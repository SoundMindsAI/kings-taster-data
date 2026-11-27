#!/usr/bin/env python3
"""Fail if any `uses:` in the workflows is not pinned to a full 40-character commit SHA."""
import os
import re
import sys

USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)")
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")


def main(d):
    bad = 0
    for name in sorted(os.listdir(d)):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(d, name), encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                m = USES.match(line)
                if m and not PINNED.match(m.group(1)):
                    print("UNPINNED %s:%d" % (name, n))
                    bad += 1
    print("pins: %s" % ("FAIL" if bad else "OK"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows"))
