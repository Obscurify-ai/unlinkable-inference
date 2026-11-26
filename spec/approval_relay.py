#!/usr/bin/env python3
"""Record an approval the maintainer gave on the Obscurify admin page.

  spec/approval_relay.py URL

URL answers {"digest": "<64 hex digits>"}: the fingerprint of the rules the maintainer
last approved there. It is recorded (approve.py --expect) only if it is the fingerprint
of the rules as they stand here, so an approval can only ever name the text it was given
for, and nothing else the page answers is used. Prints one line: "recorded", or why
nothing was. The approvals workflow (.github/workflows/approval.yml) runs this.
"""
import json, re, sys, urllib.request
import os

SPEC = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SPEC)
from approve import approve  # noqa: E402
from check import approval, digest  # noqa: E402

NOTE = "pressed Approve in the Obscurify admin panel"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "unlinkable-inference approval relay"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read(4096))


def main(url):
    try:
        given = fetch(url).get("digest")
    except Exception as e:  # nothing approved yet answers 404; any failure records nothing
        print(f"no approval read: {e}")
        return 0
    if not isinstance(given, str) or not re.fullmatch(r"[0-9a-f]{64}", given):
        print("no approval read: not a fingerprint")
        return 0
    if approval()[0]:
        print("already approved")
        return 0
    if given != digest():
        print("the last approval is for other rules; nothing recorded")
        return 0
    if approve(NOTE, expect=given) != 0:
        print("not recorded")
        return 1
    print("recorded")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
