#!/usr/bin/env python3
"""Check every rule in spec/RULES.md, and that the rules are the ones Tony approved.

  spec/check.py              everything (Kani takes a while)
  spec/check.py --no-kani    everything but the Kani proofs (minutes instead of an hour)
  spec/check.py --mutants    also break things on purpose (spec/mutants.py)

Exit 0 only when every proof holds and nothing that states a rule changed since
it was approved.
"""
import hashlib, os, subprocess, sys

SPEC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SPEC)
sys.path.insert(0, SPEC)
from runners import proverif, tlc, kani, exhaustive  # noqa: E402

MODELS = ["p0_seed", "p1_payment", "p2_change", "p3_pass"]
HARNESSES = [
    "change_rounds_up_by_less_than_a_millicent",
    "withdrawals_come_in_fixed_sizes",
]


def locked_files():
    """Everything that states a rule or decides whether one holds."""
    out = []
    for dirpath, dirs, files in os.walk(SPEC):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in files:
            if f == "APPROVED" or f.endswith(".pyc") or f.startswith("."):
                continue
            out.append(os.path.relpath(os.path.join(dirpath, f), ROOT))
    out += ["lib/src/proofs.rs", "lib/examples/exhaustive_proofs.rs", ".github/workflows/proofs.yml"]
    return sorted(out)


def fingerprints():
    return {f: hashlib.sha256(open(os.path.join(ROOT, f), "rb").read()).hexdigest() for f in locked_files()}


def approval():
    path = os.path.join(SPEC, "APPROVED")
    if not os.path.exists(path):
        return False, "the rules have never been approved (spec/approve.py)"
    approved = {}
    for line in open(path):
        if line.strip() and not line.startswith("#"):
            digest, name = line.split(None, 1)
            approved[name.strip()] = digest
    now = fingerprints()
    changed = sorted(f for f in set(now) | set(approved) if now.get(f) != approved.get(f))
    if changed:
        return False, "changed since Tony approved them: " + ", ".join(changed)
    first = open(path).readline().strip("# \n")
    return True, first


def main(args):
    results = []
    ok, detail = approval()
    results.append(("approval", ok, detail))
    print(f"{'ok ' if ok else 'NO '} approval   {detail}", flush=True)
    for m in MODELS:
        ok, detail = proverif(SPEC, m)
        ok = ok == "pass"
        results.append((m, ok, detail))
        print(f"{'ok ' if ok else 'NO '} protocol   {detail}", flush=True)
    ok, detail = tlc(SPEC)
    ok = ok == "pass"
    results.append(("ledger", ok, detail))
    print(f"{'ok ' if ok else 'NO '} ledger     {detail}", flush=True)
    ok, detail = exhaustive(ROOT)
    ok = ok == "pass"
    results.append(("exhaustive", ok, detail))
    print(f"{'ok ' if ok else 'NO '} rust       {detail}", flush=True)
    if "--no-kani" not in args:
        for h in HARNESSES:
            ok, detail = kani(ROOT, h)
            ok = ok == "pass"
            results.append((h, ok, detail))
            print(f"{'ok ' if ok else 'NO '} rust       {detail}", flush=True)
    if "--mutants" in args:
        code = subprocess.run([sys.executable, os.path.join(SPEC, "mutants.py")]).returncode
        results.append(("mutants", code == 0, ""))
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} of {len(results)} checks pass.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
