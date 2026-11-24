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

fn main() {
    let mut failed = false;
    for (rule, check) in [("M7", split_is_exact as fn() -> Result<String, String>), ("M8", change_fits)] {
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
