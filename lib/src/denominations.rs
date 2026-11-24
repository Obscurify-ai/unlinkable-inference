//! Voucher values and how amounts split into them.

/// Voucher values in cents: 1¢ to $5,000 in 1-2-5 steps, one signing key each.
pub const DENOMINATIONS: [i64; 18] = [
    1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000,
    500000,
];

/// The only amounts an account can withdraw into a wallet at once. Fixed sizes
/// mean a withdrawal's amount says nothing about what it will be spent on.
pub const WITHDRAW_SIZES: [i64; 5] = [100, 500, 2000, 5000, 10000];

/// What a withdrawal may be: a fixed size, so most look alike, or what is left under $1, so no
/// balance is stranded.
pub fn withdrawable_amount(cents: i64) -> bool {
    WITHDRAW_SIZES.contains(&cents) || (1..100).contains(&cents)
}

/// What clients take from an account holding less than $1, one at a time: the largest that fits,
/// the rest later. (Servers take any amount under $1, for older clients.)
pub const SMALL_WITHDRAW_SIZES: [i64; 6] = [1, 2, 5, 10, 20, 50];

/// Split an amount into voucher values, largest first. With 1-2-5 steps the
/// greedy split is exact and short.
pub fn split(mut cents: i64) -> Vec<i64> {
    let mut parts = Vec::new();
    for &d in DENOMINATIONS.iter().rev() {
        while cents >= d {
            parts.push(d);
            cents -= d;
        }
    }
    parts
}

/// Denominations of blanks that can hold change of any amount up to `max_cents`:
/// the greedy split of any amount uses each value at most twice for 2s and once
/// for 1s and 5s within a power of ten, so this covers every amount.
pub fn blanks_for_any_amount_up_to(max_cents: i64) -> Vec<i64> {
    let mut out = Vec::new();
    for &d in DENOMINATIONS.iter().rev() {
        if d > max_cents {
            continue;
        }
        let mut power = 1;
        while power * 10 <= d {
            power *= 10;
        }
        let first_digit = d / power;
        let copies = if first_digit == 2 { 2 } else { 1 };
        // Large values can be needed several times (an amount over $10,000).
        let copies = if d == *DENOMINATIONS.last().unwrap() {
            (max_cents / d) as usize
        } else {
            copies
        };
        out.extend(std::iter::repeat_n(d, copies));
    }
    out
}

/// Which blanks to sign for `cents`: indexes into `blanks` (by denomination)
/// that add up to exactly the greedy split. `None` if the blanks cannot hold it.
pub fn pick_blanks(blanks: &[i64], cents: i64) -> Option<Vec<usize>> {
    pick_parts(blanks, &split(cents))
}

/// Indexes of distinct `blanks` with the values `parts`, in order. `None` if there aren't enough.
pub fn pick_parts(blanks: &[i64], parts: &[i64]) -> Option<Vec<usize>> {
    let mut used = vec![false; blanks.len()];
    let mut picked = Vec::with_capacity(parts.len());
    for &part in parts {
        let i = (0..blanks.len()).find(|&i| !used[i] && blanks[i] == part)?;
        used[i] = true;
        picked.push(i);
    }
    Some(picked)
}

/// Dust: values below a cent, in millicents (0.001¢ to 0.5¢). Change that is
/// not a whole number of cents comes back in these, rounded up in the
/// customer's favour to the next 0.001¢, so a session never costs more than
/// its tokens.
pub const DUST_MILLICENTS: [i64; 9] = [1, 2, 5, 10, 20, 50, 100, 200, 500];

/// Split millicents below a cent into dust values, largest first.
pub fn split_dust(mut millicents: i64) -> Vec<i64> {
    let mut parts = Vec::new();
    for &d in DUST_MILLICENTS.iter().rev() {
        while millicents >= d {
            parts.push(d);
            millicents -= d;
        }
    }
    parts
}

/// Dust blanks that can hold any amount from 0 to 999 millicents.
pub fn dust_blanks_for_any() -> Vec<i64> {
    vec![500, 200, 200, 100, 50, 20, 20, 10, 5, 2, 2, 1]
}

/// Like [`pick_blanks`] for dust.
pub fn pick_dust_blanks(blanks: &[i64], millicents: i64) -> Option<Vec<usize>> {
    pick_parts(blanks, &split_dust(millicents))
}

pub const MILLICENTS_PER_CENT: i64 = 1000;

/// Nanodollars (1e-9 USD) in a millicent.
pub const NANO_PER_MILLICENT: i64 = 10_000;

/// What a closing session gives back, in millicents, for a balance in nanodollars: rounded up to
/// the next millicent, so a session never costs more than its tokens, and nothing for a balance
/// of zero or less.
pub fn change_millicents(balance_nano: i64) -> i64 {
    if balance_nano <= 0 {
        return 0;
    }
    balance_nano / NANO_PER_MILLICENT + i64::from(balance_nano % NANO_PER_MILLICENT != 0)
}

/// Which of a request's blanks to sign for change of exactly `millicents`: whole cents the
/// standard way from the normal blanks, the rest from the dust blanks. `blanks` are (value, dust)
/// pairs, value in cents or, for dust, millicents. `None` if they cannot hold it.
pub fn pick_change(blanks: &[(i64, bool)], millicents: i64) -> Option<Vec<usize>> {
    if millicents < 0 {
        return None;
    }
    pick_change_parts(
        blanks,
        &split(millicents / MILLICENTS_PER_CENT),
        &split_dust(millicents % MILLICENTS_PER_CENT),
    )
}

/// [`pick_change`] for change already split: `whole` in cents, `dust` in millicents.
pub fn pick_change_parts(blanks: &[(i64, bool)], whole: &[i64], dust: &[i64]) -> Option<Vec<usize>> {
    let normal: Vec<usize> = (0..blanks.len()).filter(|&i| !blanks[i].1).collect();
    let small: Vec<usize> = (0..blanks.len()).filter(|&i| blanks[i].1).collect();
    let values = |idx: &[usize]| idx.iter().map(|&i| blanks[i].0).collect::<Vec<_>>();
    let mut picked: Vec<usize> = pick_parts(&values(&normal), whole)?.into_iter().map(|k| normal[k]).collect();
    picked.extend(pick_parts(&values(&small), dust)?.into_iter().map(|k| small[k]));
    Some(picked)
}
