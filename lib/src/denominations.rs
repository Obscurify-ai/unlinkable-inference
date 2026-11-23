//! Voucher values and how amounts split into them.

/// Voucher values in cents: 1¢ to $5,000 in 1-2-5 steps, one signing key each.
pub const DENOMINATIONS: [i64; 18] = [
    1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000,
    500000,
];

/// The only amounts an account can withdraw into a wallet at once. Fixed sizes
/// mean a withdrawal's amount says nothing about what it will be spent on.
pub const WITHDRAW_SIZES: [i64; 5] = [100, 500, 2000, 5000, 10000];

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
    let mut used = vec![false; blanks.len()];
    let mut picked = Vec::new();
    for part in split(cents) {
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
    let mut used = vec![false; blanks.len()];
    let mut picked = Vec::new();
    for part in split_dust(millicents) {
        let i = (0..blanks.len()).find(|&i| !used[i] && blanks[i] == part)?;
        used[i] = true;
        picked.push(i);
    }
    Some(picked)
}

pub const MILLICENTS_PER_CENT: i64 = 1000;
