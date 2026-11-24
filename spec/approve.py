#!/usr/bin/env python3
"""Record that Tony approved the rules as they stand.

  spec/approve.py --show          what changed since the last approval (send this to Tony)
  spec/approve.py --yes "NOTE"    record his approval; NOTE says how he gave it

Only run --yes after Tony has said yes to the change himself. An agent's own
judgement is never an approval: the point of the lock is that the rules are his.
"""
import datetime, os, subprocess, sys

SPEC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SPEC)
sys.path.insert(0, SPEC)
from check import fingerprints  # noqa: E402


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout


def show():
    last = git("log", "-1", "--format=%H", "--", "spec/APPROVED").strip()
    if not last:
        print("Never approved. The rules as they stand:\n")
        print(open(os.path.join(SPEC, "RULES.md")).read())
        return
    rules = git("diff", last, "--", "spec/RULES.md")
    others = git("diff", "--stat", last, "--", "spec", "lib/src/proofs.rs", "lib/examples/exhaustive_proofs.rs", ".github/workflows/proofs.yml")
    print(rules or "RULES.md is unchanged.")
    if others.strip():
        print("\nFiles that state or check the rules, changed since the last approval:\n" + others)


def approve(note):
    date = datetime.date.today().isoformat()
    lines = [f"# Approved by Tony on {date}: {note}",
             "# SHA-256 of every file that states a rule or decides whether one holds."]
    lines += [f"{digest}  {name}" for name, digest in sorted(fingerprints().items())]
    open(os.path.join(SPEC, "APPROVED"), "w").write("\n".join(lines) + "\n")
    print(f"Recorded. Commit spec/APPROVED with the change it approves.")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--yes"] and len(sys.argv) > 2:
        approve(" ".join(sys.argv[2:]))
    elif sys.argv[1:2] == ["--show"]:
        show()
    else:
        print(__doc__)
        sys.exit(2)
