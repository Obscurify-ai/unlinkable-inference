#!/usr/bin/env python3
"""Check every rule in spec/RULES.md, and that the rules are the ones the maintainer approved.

  spec/check.py              everything (Kani takes a while)
  spec/check.py --no-kani    everything but the Kani proofs (minutes instead of an hour)
  spec/check.py --mutants    also break things on purpose (spec/mutants.py)

Exit 0 only when every proof holds and nothing that states a rule changed since
it was approved.
"""
import hashlib, json, os, subprocess, sys, time

SPEC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SPEC)
sys.path.insert(0, SPEC)
from runners import proverif, tlc, kani, exhaustive, types  # noqa: E402

MODELS = {"p0_seed": ["P4"], "p1_payment": ["P1"], "p2_change": ["P2"], "p3_pass": ["P3"]}
LEDGER_RULES = ["M1", "M2", "M3", "M4", "M5", "M6"]
EXHAUSTIVE_RULES = ["M7", "M8", "M9"]
HARNESSES = {
    "change_rounds_up_by_less_than_a_millicent": ["M10"],
    "withdrawals_come_in_fixed_sizes": ["M11"],
}
# Where the last run's results go: outside the locked files and outside git.
STATUS_DIR = os.path.join(ROOT, "target", "spec-status")


def locked_files():
    """Everything that states a rule or decides whether one holds."""
    out = []
    for dirpath, dirs, files in os.walk(SPEC):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in files:
            if f == "APPROVED" or f.endswith(".pyc") or f.startswith("."):
                continue
            out.append(os.path.relpath(os.path.join(dirpath, f), ROOT))
    out += ["lib/src/proofs.rs", "lib/examples/exhaustive_proofs.rs", "lib/src/server/stored.rs",
            ".github/workflows/proofs.yml"]
    return sorted(out)


def fingerprints():
    return {f: hashlib.sha256(open(os.path.join(ROOT, f), "rb").read()).hexdigest() for f in locked_files()}


def digest(prints=None):
    """One fingerprint for the rules as they stand: what an approval approves."""
    prints = fingerprints() if prints is None else prints
    return hashlib.sha256(json.dumps(sorted(prints.items())).encode()).hexdigest()


def code_stamp():
    """Fingerprint of every file in the repo but the approval itself: results are current
    only while this is unchanged."""
    files = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT,
                           capture_output=True, text=True, check=True).stdout.split()
    h = hashlib.sha256()
    for f in sorted(files):
        path = os.path.join(ROOT, f)
        if f == "spec/APPROVED" or not os.path.isfile(path):
            continue
        h.update(f.encode() + b"\0" + open(path, "rb").read() + b"\0")
    return h.hexdigest()


def save_status(name, data):
    os.makedirs(STATUS_DIR, exist_ok=True)
    data = {"ran_at": int(time.time()), **data}
    path = os.path.join(STATUS_DIR, name)
    open(path + ".tmp", "w").write(json.dumps(data, indent=1))
    os.replace(path + ".tmp", path)


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
        return False, "changed since they were approved: " + ", ".join(changed)
    first = open(path).readline().strip("# \n")
    return True, first


def main(args):
    stamp = code_stamp()
    results = []

    def record(name, rules, status, detail, kind):
        ok = status == "pass"
        results.append({"name": name, "rules": rules, "status": status, "detail": detail, "kind": kind})
        print(f"{'ok ' if ok else 'NO '} {kind:10} {detail}", flush=True)

    ok, detail = approval()
    print(f"{'ok ' if ok else 'NO '} approval   {detail}", flush=True)
    for m, rules in MODELS.items():
        record(m, rules, *proverif(SPEC, m), "protocol")
    record("ledger", LEDGER_RULES, *tlc(SPEC), "ledger")
    record("exhaustive", EXHAUSTIVE_RULES, *exhaustive(ROOT), "rust")
    record("types", ["P5"], *types(ROOT), "rust")
    if "--no-kani" not in args:
        for h, rules in HARNESSES.items():
            record(h, rules, *kani(ROOT, h), "rust")
    if code_stamp() == stamp:
        save_status("check.json", {"code_stamp": stamp, "kani": "--no-kani" not in args, "checks": results})
    else:
        print("The files changed while the checks ran: results not saved.")
    failed = [r for r in results if r["status"] != "pass"] + ([] if ok else ["approval"])
    if "--mutants" in args:
        code = subprocess.run([sys.executable, os.path.join(SPEC, "mutants.py")]).returncode
        failed += [] if code == 0 else ["mutants"]
    total = len(results) + 1 + ("--mutants" in args)
    print(f"\n{total - len(failed)} of {total} checks pass.")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
