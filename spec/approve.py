#!/usr/bin/env python3
"""Record that the maintainer approved the rules as they stand.

  spec/approve.py --show          what changed since the last approval (send this to the maintainer)
  spec/approve.py --yes "NOTE"    record the approval; NOTE says how it was given
  spec/approve.py --expect DIGEST --yes "NOTE"
                                  the same, but only if the rules are still the ones
                                  that were read (DIGEST from spec/status.py, shown with them)

Only run --yes after the maintainer has said yes to the change. An agent's own
judgement is never an approval: the point of the lock is that the rules are the maintainer's.
"""
import datetime, os, subprocess, sys

SPEC = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(SPEC)
sys.path.insert(0, SPEC)
from check import digest, fingerprints  # noqa: E402


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout


def changes():
    """What changed since the last approval: (diff of RULES.md, other locked files changed),
    or None if the rules were never approved."""
    last = git("log", "-1", "--format=%H", "--", "spec/APPROVED").strip()
    if not last:
        return None
    rules = git("diff", last, "--", "spec/RULES.md")
    others = git("diff", "--stat", last, "--", "spec", "lib/src/proofs.rs", "lib/examples/exhaustive_proofs.rs", ".github/workflows/proofs.yml")
    return rules, others.strip()


def show():
    found = changes()
    if found is None:
        print("Never approved. The rules as they stand:\n")
        print(open(os.path.join(SPEC, "RULES.md")).read())
        return
    rules, others = found
    print(rules or "RULES.md is unchanged.")
    if others:
        print("\nFiles that state or check the rules, changed since the last approval:\n" + others)


def approve(note, expect=None):
    prints = fingerprints()
    if expect is not None and digest(prints) != expect:
        print("Not recorded: the rules changed since they were shown. Show them again.")
        return 3
    date = datetime.date.today().isoformat()
    lines = [f"# Approved on {date}: {note}",
             "# SHA-256 of every file that states a rule or decides whether one holds."]
    lines += [f"{d}  {name}" for name, d in sorted(prints.items())]
    open(os.path.join(SPEC, "APPROVED"), "w").write("\n".join(lines) + "\n")
    print("Recorded. Commit spec/APPROVED with the change it approves.")
    return 0


if __name__ == "__main__":
    expect = None
    if sys.argv[1:2] == ["--expect"] and len(sys.argv) > 2:
        expect = sys.argv[2]
        del sys.argv[1:3]
    if sys.argv[1:2] == ["--yes"] and len(sys.argv) > 2:
        sys.exit(approve(" ".join(sys.argv[2:]), expect))
    elif sys.argv[1:2] == ["--show"]:
        show()
    else:
        print(__doc__)
        sys.exit(2)
