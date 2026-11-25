#!/usr/bin/env python3
"""Everything a page needs to show the rules for approval, as JSON on stdout.

  spec/status.py

The rules come straight from RULES.md, every word of it, split into its sections,
rules and notes. With them: the fingerprint an approval must name (approve.py
--expect), whether and when the maintainer approved, what changed since, and the results of
the last check.py and mutants.py runs, marked stale if any file changed after them.
"""
import json, os, re, sys, time

SPEC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SPEC)
from check import STATUS_DIR, approval, code_stamp, digest  # noqa: E402
from approve import changes  # noqa: E402

RULE = re.compile(r"^\*\*([PM]\d+)\. (.+?)\*\*\s*(.*)$", re.S)
PROOF = re.compile(r"^\*(?!\*)([^*]+)\*$")
TRAILING_PROOF = re.compile(r"^(.*?)\s*\*(?!\*)([^*]+)\*$", re.S)


def blocks(lines):
    """Paragraphs and bullet lists, each list item one string."""
    out, para, items = [], [], None

    def flush():
        nonlocal para, items
        if para:
            out.append(("para", " ".join(para)))
        if items:
            out.append(("list", [" ".join(i) for i in items]))
        para, items = [], None

    for line in lines:
        if not line.strip():
            flush()
        elif line.startswith("- "):
            if para:
                out.append(("para", " ".join(para)))
                para = []
            items = (items or []) + [[line[2:].strip()]]
        elif items:
            items[-1].append(line.strip())
        else:
            para.append(line.strip())
    flush()
    return out


def parse(text):
    title, intro, sections = "", [], []
    current = None
    chunks = re.split(r"^(#{1,2}) (.+)$", text, flags=re.M)
    for kind, body in blocks(chunks[0].splitlines()):
        intro.append({"type": kind, "text": body} if kind == "para" else {"type": kind, "items": body})
    for level, heading, body in zip(chunks[1::3], chunks[2::3], chunks[3::3]):
        target = intro
        if level == "#":
            title = heading.strip()
        else:
            current = {"title": heading.strip(), "items": []}
            sections.append(current)
            target = current["items"]
        for kind, content in blocks(body.splitlines()):
            if kind == "list":
                target.append({"type": "list", "items": content})
                continue
            rule, proof = RULE.match(content), PROOF.match(content)
            if rule:
                # A rule's paragraph may end with how it is proved, in italics.
                text, proof_line = rule[3], None
                trailing = TRAILING_PROOF.match(text)
                if trailing:
                    text, proof_line = trailing[1], trailing[2]
                target.append({"type": "rule", "id": rule[1], "title": rule[2], "text": text, "proof": proof_line})
            elif proof and target and target[-1]["type"] == "rule" and target[-1]["proof"] is None:
                target[-1]["proof"] = proof[1]
            else:
                target.append({"type": "para", "text": content})
    return {"title": title, "intro": intro, "sections": sections}


def last_run(name, stamp):
    path = os.path.join(STATUS_DIR, name)
    if not os.path.exists(path):
        return None
    run = json.load(open(path))
    run["current"] = run.get("code_stamp") == stamp
    return run


def main():
    stamp = code_stamp()
    ok, detail = approval()
    found = changes()
    approved_file = os.path.exists(os.path.join(SPEC, "APPROVED"))
    state = "approved" if ok else ("changed" if approved_file else "never")
    check = last_run("check.json", stamp)
    mutants = last_run("mutants.json", stamp)
    print(json.dumps({
        "generated_at": int(time.time()),
        "digest": digest(),
        "approval": {"state": state, "detail": detail},
        "changes": None if found is None else {"rules_diff": found[0], "other_files": found[1]},
        "rules": parse(open(os.path.join(SPEC, "RULES.md")).read()),
        "check": check,
        "mutants": mutants,
    }, indent=1))


if __name__ == "__main__":
    main()
