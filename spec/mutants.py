#!/usr/bin/env python3
"""Break the design and the code on purpose and check a proof catches each break.

Each mutant swaps one piece of text in one file (in a scratch copy of the repo),
runs the proof that should catch it, and expects that proof to FAIL. A mutant
the proofs miss means a rule is weaker than it reads: this script then exits 1.

  spec/mutants.py            every mutant
  spec/mutants.py NAME ...   only these
  spec/mutants.py --no-kani   skip the ones that need Kani (slow)
  spec/mutants.py --list
"""
import os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(ROOT, "spec")
sys.path.insert(0, SPEC)
from runners import proverif, tlc, kani, exhaustive  # noqa: E402

TIMING_PROCESS = """process
  ! ( new wa: channel; new wb: channel;
    new master_a: bitstring; new master_b: bitstring;
    new acct_a: bitstring; new acct_b: bitstring; out(c, (acct_a, acct_b));
    ( ( Withdraw(acct_a, master_a, wa)
      | in(wa, (sa: bitstring, ma: bitstring, va: bitstring));
        Chat(sa, ma, va, minute1, choice[chat1, chat2]) )
    | ( Withdraw(acct_b, master_b, wb)
      | in(wb, (sb: bitstring, mb: bitstring, vb: bitstring));
        Chat(sb, mb, vb, minute1, choice[chat2, chat1]) ) ) )
"""

P1_PROCESS = "process\n" + open(os.path.join(SPEC, "protocol", "p1_payment.pv")).read().split("\nprocess\n", 1)[1]

# (name, what it breaks, file, old text, new text, checker)
MUTANTS = [
    # --- privacy: the protocol models ---------------------------------------------------
    ("no-blinding", "P1: the client sends the voucher message unblinded",
     "spec/protocol/common.pvl",
     "  out(c, (acct, login_key(master), blind(m, r, pinned)));\n  in(c, bs: bitstring);\n  let v = unblind(bs, r, pinned) in",
     "  out(c, (acct, login_key(master), m));\n  in(c, bs: bitstring);\n  let v = bs in",
     ("proverif", "p1_payment")),
    ("blinding-from-login-key", "P1: the blinding comes from something the server sees",
     "spec/protocol/common.pvl",
     "  let r = blinding_of(s, op1) in\n  out(c, (acct,",
     "  let r = login_key(master) in\n  out(c, (acct,",
     ("proverif", "p1_payment")),
    ("key-per-account", "P1: the client takes whatever key the server hands it (no pinning)",
     "spec/protocol/common.pvl",
     "let Withdraw(acct: bitstring, master: bitstring, w: channel) =\n  let s = wallet_seed(master) in\n  let m = msg_of(s, op1) in\n  let r = blinding_of(s, op1) in\n  out(c, (acct, login_key(master), blind(m, r, pinned)));\n  in(c, bs: bitstring);\n  let v = unblind(bs, r, pinned) in\n  if checksign(v, m, pinned) = true then\n  out(w, (s, m, v)).",
     "let Withdraw(acct: bitstring, master: bitstring, w: channel) =\n  in(c, kp: pkey);\n  let s = wallet_seed(master) in\n  let m = msg_of(s, op1) in\n  let r = blinding_of(s, op1) in\n  out(c, (acct, login_key(master), blind(m, r, kp)));\n  in(c, bs: bitstring);\n  let v = unblind(bs, r, kp) in\n  if checksign(v, m, kp) = true then\n  out(w, (s, m, (v, kp))).",
     ("proverif", "p1_payment")),
    ("withdraw-just-before-chat", "P1: each device withdraws and chats at once (the timing caveat)",
     "spec/protocol/p1_payment.pv", P1_PROCESS, TIMING_PROCESS, ("proverif", "p1_payment")),
    ("seed-is-login-key", "P2/P4: the wallet seed is the login key the server sees",
     "spec/protocol/common.pvl",
     "letfun wallet_seed(master: bitstring) = hmac(master, t_wallet).",
     "letfun wallet_seed(master: bitstring) = hmac(master, t_login).",
     ("proverif", "p2_change")),
    ("change-reuses-message", "P2: change is made on the message of the voucher that paid",
     "spec/protocol/common.pvl",
     "  let m2 = msg_of(s, op2) in", "  let m2 = msg_of(s, op1) in",
     ("proverif", "p2_change")),
    ("pass-key-per-account", "P3: the pass key's metadata names the account",
     "spec/protocol/common.pvl",
     "  let key = pkd(pk(sk_pass), pass_meta(label)) in",
     "  let key = pkd(pk(sk_pass), (pass_meta(label), acct)) in",
     ("proverif", "p3_pass")),

    # --- money: the ledger model ---------------------------------------------------------
    ("partial-spend", "M1: a refused open still spends the vouchers that were unspent",
     "spec/ledger/Ledger.tla",
     "     ELSE IF vs \\cap spent # {} THEN\n       \\* 409: nothing spent; the device drops the ones that were\n       /\\ wallet' = wallet \\ (vs \\cap spent)\n       /\\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>",
     "     ELSE IF vs \\cap spent # {} THEN\n       /\\ wallet' = wallet \\ (vs \\cap spent)\n       /\\ spent' = spent \\cup vs\n       /\\ UNCHANGED <<acct, issued, sessions, answers, charged, forgiven>>",
     ("tlc", "Conservation")),
    ("no-spent-check", "M3: an open does not look at which vouchers were spent",
     "spec/ledger/Ledger.tla",
     "     ELSE IF vs \\cap spent # {} THEN\n       \\* 409",
     "     ELSE IF FALSE THEN\n       \\* 409",
     ("tlc", "Conservation")),
    ("retry-opens-again", "M1: a retried open with a taken secret opens a new session over it",
     "spec/ledger/Ledger.tla",
     "  /\\ IF sessions[s].st # \"none\" THEN",
     "  /\\ IF FALSE THEN",
     ("tlc", "Conservation")),
    ("repeat-close-mints", "M1: closing a closed session signs change again",
     "spec/ledger/Ledger.tla",
     "       /\\ wallet' = IF sessions[s].closeDigest = d THEN wallet \\cup sessions[s].change ELSE wallet\n       /\\ UNCHANGED <<acct, issued, spent, sessions, answers, charged, forgiven>>",
     "       /\\ Unused # {}\n       /\\ LET m == Mint(1, sessions[s].fam) IN /\\ issued' = m.iss /\\ wallet' = wallet \\cup m.ids\n       /\\ UNCHANGED <<acct, spent, sessions, answers, charged, forgiven>>",
     ("tlc", "Conservation")),
    ("close-keeps-a-unit", "M2: closing keeps one unit back",
     "spec/ledger/Ledger.tla",
     "m == Mint(IF b > 0 THEN b ELSE 0, f) IN",
     "m == Mint(IF b > 1 THEN b - 1 ELSE 0, f) IN",
     ("tlc", "Conservation")),
    ("overdraw-account", "M4: a withdrawal is not checked against the balance",
     "spec/ledger/Ledger.tla", "  /\\ amt <= acct\n", "", ("tlc", "AccountNonNegative")),
    ("withdraw-unrecorded", "M5: a withdrawal's answer is not kept for a retry",
     "spec/ledger/Ledger.tla",
     "     /\\ answers' = answers @@ (d :> m.ids)\n     /\\ acct' = acct - amt",
     "     /\\ answers' = answers\n     /\\ acct' = acct - amt",
     ("tlc", "Recoverable")),
    ("change-always-paid", "M6: change comes back as paid money whatever funded the session",
     "spec/ledger/Ledger.tla",
     "              f == sessions[s].fam\n", "              f == \"paid\"\n", ("tlc", "Conservation")),

    # --- money: the Rust code itself -----------------------------------------------------
    ("split-drops-the-last-cent", "M7: the split stops one step early on an exact fit",
     "lib/src/denominations.rs",
     "    for &d in DENOMINATIONS.iter().rev() {\n        while cents >= d {",
     "    for &d in DENOMINATIONS.iter().rev() {\n        while cents > d {",
     ("exhaustive", "M7")),
    ("split-skips-a-value", "M8: the split never uses the 20¢ voucher (still exact, but the change no longer fits)",
     "lib/src/denominations.rs",
     "    for &d in DENOMINATIONS.iter().rev() {\n        while cents >= d {",
     "    for &d in DENOMINATIONS.iter().rev() {\n        if d == 20 { continue; }\n        while cents >= d {",
     ("exhaustive", "M8")),
    ("one-blank-of-two", "M8: close blanks carry one 2 per power of ten instead of two",
     "lib/src/denominations.rs",
     "let copies = if first_digit == 2 { 2 } else { 1 };",
     "let copies = if first_digit == 2 { 1 } else { 1 };",
     ("exhaustive", "M8")),
    ("dust-blanks-short", "M8: the dust blanks lack one 2",
     "lib/src/denominations.rs",
     "vec![500, 200, 200, 100, 50, 20, 20, 10, 5, 2, 2, 1]",
     "vec![500, 200, 200, 100, 50, 20, 20, 10, 5, 2, 1]",
     ("exhaustive", "M8")),
    ("change-picks-whole-only", "M9: change drops the last dust part",
     "lib/src/denominations.rs",
     "    picked.extend(pick_parts(&values(&small), dust)?",
     "    picked.extend(pick_parts(&values(&small), &dust[..dust.len().saturating_sub(1)])?",
     ("exhaustive", "M9")),
    ("change-picks-a-blank-twice", "M9: the same blank can be picked twice",
     "lib/src/denominations.rs",
     "        let i = (0..blanks.len()).find(|&i| !used[i] && blanks[i] == part)?;",
     "        let i = (0..blanks.len()).find(|&i| blanks[i] == part)?;",
     ("exhaustive", "M9")),
    ("round-down", "M10: change is rounded down",
     "lib/src/denominations.rs",
     "balance_nano / NANO_PER_MILLICENT + i64::from(balance_nano % NANO_PER_MILLICENT != 0)",
     "balance_nano / NANO_PER_MILLICENT",
     ("kani", "change_rounds_up_by_less_than_a_millicent")),
    ("withdraw-a-dollar-ten", "M11: $1.10 becomes a withdrawal size",
     "lib/src/denominations.rs",
     "pub const WITHDRAW_SIZES: [i64; 5] = [100, 500, 2000, 5000, 10000];",
     "pub const WITHDRAW_SIZES: [i64; 5] = [100, 110, 2000, 5000, 10000];",
     ("kani", "withdrawals_come_in_fixed_sizes")),
]


def scratch_copy():
    tmp = tempfile.mkdtemp(prefix="mutant-")
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    for f in files:
        src = os.path.join(ROOT, f)
        if os.path.isfile(src):
            dst = os.path.join(tmp, f)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    return tmp


def run(mutant):
    name, what, path, old, new, (kind, target) = mutant
    tmp = scratch_copy()
    try:
        full = os.path.join(tmp, path)
        text = open(full).read()
        if text.count(old) != 1:
            return False, f"the text to break is not in {path} exactly once (update the mutant)"
        open(full, "w").write(text.replace(old, new))
        if kind == "proverif":
            status, detail = proverif(os.path.join(tmp, "spec"), target)
        elif kind == "tlc":
            status, detail = tlc(os.path.join(tmp, "spec"), only=target)
        elif kind == "exhaustive":
            status, detail = exhaustive(tmp, target, target_dir=os.path.join(ROOT, "target", "mutants"))
        else:
            status, detail = kani(tmp, target, target_dir=os.path.join(ROOT, "target"))
        # Caught only when the proof ran and found the break: a tool that failed to run caught nothing.
        return status == "fail", detail
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(args):
    if args[:1] == ["--list"]:
        for m in MUTANTS:
            print(f"{m[0]:28} {m[1]}")
        return 0
    skip_kani = "--no-kani" in args
    args = [a for a in args if a != "--no-kani"]
    chosen = [m for m in MUTANTS if (not args or m[0] in args) and not (skip_kani and m[5][0] == "kani")]
    missed = 0
    for m in chosen:
        caught, detail = run(m)
        print(f"{'caught' if caught else 'MISSED'}  {m[0]:28} {m[1]}\n        {detail}", flush=True)
        missed += not caught
    print(f"\n{len(chosen) - missed} of {len(chosen)} breaks caught.")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
