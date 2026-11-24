//! Proofs about the money arithmetic, checked by Kani
//! (`cargo kani -p unlinkable-inference --no-default-features`).
//!
//! Kani does not run these on a few examples: it turns the code into a formula and checks it for
//! every input in the stated range at once. Each one is listed in `spec/RULES.md`. Rules over a
//! small finite range (splitting amounts, holding change) are proved by trying every amount
//! instead, which is quicker: `lib/examples/exhaustive_proofs.rs`.

use crate::denominations::*;

fn distinct(picked: &[usize], len: usize) -> bool {
    let mut seen = [false; 64];
    for &i in picked {
        if i >= len || seen[i] {
            return false;
        }
        seen[i] = true;
    }
    true
}

/// M9. Whatever blanks a client sends, the server signs change worth exactly the session's
/// balance, never a millicent more, and never the same blank twice.
#[kani::proof]
#[kani::unwind(25)]
fn change_signed_is_exactly_the_balance() {
    const N: usize = 4;
    let len: usize = kani::any();
    kani::assume(len <= N);
    let blanks: [(i64, bool); N] = kani::any();
    let millicents: i64 = kani::any();
    kani::assume((0..=10_000_000).contains(&millicents));
    if let Some(picked) = pick_change(&blanks[..len], millicents) {
        assert!(distinct(&picked, len));
        let total: i128 = picked
            .iter()
            .map(|&i| {
                let (v, dust) = blanks[i];
                if dust { v as i128 } else { v as i128 * MILLICENTS_PER_CENT as i128 }
            })
            .sum();
        assert_eq!(total, millicents as i128);
    }
}

/// M10. A closing session gives back its whole balance rounded up to the next millicent: never
/// less than it holds, and less than a millicent more. Nothing for an empty or overdrawn one.
/// For every 64-bit balance.
#[kani::proof]
#[kani::solver(z3)]
fn change_rounds_up_by_less_than_a_millicent() {
    let nano: i64 = kani::any();
    let mc = change_millicents(nano);
    if nano <= 0 {
        assert_eq!(mc, 0);
    } else {
        // (mc - 1) millicents fall short of the balance; mc millicents cover it.
        assert!(mc >= 1);
        let rest = nano - (mc - 1) * NANO_PER_MILLICENT;
        assert!(rest > 0 && rest <= NANO_PER_MILLICENT);
    }
}

/// M11. An account can withdraw exactly $1, $5, $20, $50 or $100, or 1¢ to 99¢, and nothing
/// else.
#[kani::proof]
fn withdrawals_come_in_fixed_sizes() {
    let cents: i64 = kani::any();
    let allowed = matches!(cents, 100 | 500 | 2000 | 5000 | 10000) || (1..=99).contains(&cents);
    assert_eq!(withdrawable_amount(cents), allowed);
}
