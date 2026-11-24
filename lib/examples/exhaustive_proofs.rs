//! Proofs by exhaustion: the money rules about splitting amounts and holding change, checked
//! for every amount in the stated range, one by one. Over a finite range this proves the rule as
//! completely as a symbolic proof does. Each is listed in `spec/RULES.md`.
//!
//! `cargo run --release -p unlinkable-inference --no-default-features --example exhaustive_proofs`
//! prints one line per rule and exits 1 if any amount breaks one.

use unlinkable_inference::denominations::*;

fn sum(values: &[i64], picked: &[usize]) -> i64 {
    picked.iter().map(|&i| values[i]).sum()
}

fn distinct(picked: &[usize], len: usize) -> bool {
    let mut seen = vec![false; len];
    picked.iter().all(|&i| i < len && !std::mem::replace(&mut seen[i], true))
}

/// M7: every amount from 0 to $10,000 splits into voucher values that add up to it, largest first.
fn split_is_exact() -> Result<String, String> {
    for cents in 0..=1_000_000 {
        let parts = split(cents);
        if parts.iter().sum::<i64>() != cents
            || !parts.iter().all(|p| DENOMINATIONS.contains(p))
            || !parts.windows(2).all(|w| w[0] >= w[1])
        {
            return Err(format!("{cents}¢ splits into {parts:?}"));
        }
    }
    for mc in 0..MILLICENTS_PER_CENT {
        let parts = split_dust(mc);
        if parts.iter().sum::<i64>() != mc || !parts.iter().all(|p| DUST_MILLICENTS.contains(p)) {
            return Err(format!("{mc} millicents split into {parts:?}"));
        }
    }
    Ok("every amount from 0 to $10,000, and every amount below a cent".into())
}

/// M8: the blanks a close sends hold every change it can get.
fn change_fits() -> Result<String, String> {
    // A wallet made from an account code always sends the blanks for $1,000.
    let seeded = blanks_for_any_amount_up_to(100_000);
    for cents in 0..=100_000 {
        match pick_blanks(&seeded, cents) {
            Some(p) if distinct(&p, seeded.len()) && sum(&seeded, &p) == cents => {}
            other => return Err(format!("seeded close blanks cannot hold {cents}¢: {other:?}")),
        }
    }
    let dust = dust_blanks_for_any();
    for mc in 0..MILLICENTS_PER_CENT {
        match pick_dust_blanks(&dust, mc) {
            Some(p) if distinct(&p, dust.len()) && sum(&dust, &p) == mc => {}
            other => return Err(format!("dust blanks cannot hold {mc} millicents: {other:?}")),
        }
    }
    // Other wallets send blanks for their balance plus a cent: every limit up to $100, every amount
    // up to the limit.
    for max in 0..=10_000 {
        let blanks = blanks_for_any_amount_up_to(max);
        for cents in 0..=max {
            match pick_blanks(&blanks, cents) {
                Some(p) if sum(&blanks, &p) == cents => {}
                other => return Err(format!("blanks for up to {max}¢ cannot hold {cents}¢: {other:?}")),
            }
        }
    }
    Ok("up to $1,000 for seeded wallets, every limit up to $100 for others, every amount below a cent".into())
}

/// Every list of up to `max_len` items drawn from `options`.
fn lists<T: Copy>(options: &[T], max_len: usize) -> Vec<Vec<T>> {
    let mut all = vec![Vec::new()];
    let mut layer = vec![Vec::new()];
    for _ in 0..max_len {
        layer = layer
            .iter()
            .flat_map(|l: &Vec<T>| options.iter().map(move |&o| [l.clone(), vec![o]].concat()))
            .collect();
        all.extend(layer.iter().cloned());
    }
    all
}

/// M9: whatever blanks a client sends, the server picks, for each part of the change, a different
/// blank of exactly that value and kind. The picking only compares values for equality, so values
/// from {1, 2, 3} make every choice it can face with up to three distinct values; tried for every
/// list of up to 6 blanks against every change of up to 4 whole and 3 dust parts.
fn change_is_exactly_what_was_asked() -> Result<String, String> {
    let kinds: Vec<(i64, bool)> = [1, 2, 3].iter().flat_map(|&v| [(v, false), (v, true)]).collect();
    let blank_lists = lists(&kinds, 6);
    let wholes = lists(&[1i64, 2, 3], 4);
    let dusts = lists(&[1i64, 2, 3], 3);
    let mut cases = 0u64;
    for blanks in &blank_lists {
        for whole in &wholes {
            for dust in &dusts {
                cases += 1;
                let Some(picked) = pick_change_parts(blanks, whole, dust) else {
                    // Refusing is fine only when the blanks really can't hold it.
                    let can = |v: i64, d: bool, need: usize| blanks.iter().filter(|&&b| b == (v, d)).count() >= need;
                    let count = |l: &[i64], v: i64| l.iter().filter(|&&x| x == v).count();
                    if [1, 2, 3].iter().all(|&v| can(v, false, count(whole, v)) && can(v, true, count(dust, v))) {
                        return Err(format!("refused {whole:?} + dust {dust:?} from {blanks:?}, which hold it"));
                    }
                    continue;
                };
                let asked: Vec<(i64, bool)> = whole.iter().map(|&v| (v, false)).chain(dust.iter().map(|&v| (v, true))).collect();
                let got: Vec<(i64, bool)> = picked.iter().map(|&i| blanks[i]).collect();
                if !distinct(&picked, blanks.len()) || got != asked {
                    return Err(format!("asked {asked:?} from {blanks:?}, picked {picked:?}"));
                }
            }
        }
    }
    Ok(format!("{cases} cases: up to 6 blanks, up to 4 whole and 3 dust parts, values compared only for equality"))
}

type Check = fn() -> Result<String, String>;

fn main() {
    let mut failed = false;
    let checks: [(&str, Check); 3] =
        [("M7", split_is_exact), ("M8", change_fits), ("M9", change_is_exactly_what_was_asked)];
    for (rule, check) in checks {
        match check() {
            Ok(what) => println!("ok {rule}: {what}"),
            Err(why) => {
                println!("BROKEN {rule}: {why}");
                failed = true;
            }
        }
    }
    std::process::exit(i32::from(failed));
}
