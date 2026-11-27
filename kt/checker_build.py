"""Helpers for the optional checker-builder skill (SPEC.md §5).

The bot itself writes ~/.kings-taster/checker.py from skills/kings-taster-build.md. This
module only loads that skill, splits it, and extracts its reference snippets so tests can
prove they work. It is not a downloaded checker and never contacts the network.
"""
import json
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-build.md")
CASES_PATH = os.path.join(ROOT, "conformance", "cases.json")
WORD_CAP = 3000
SNIPPET_LINE_CAP = 300
SNIPPETS_START = "<!-- snippets -->"
SNIPPETS_END = "<!-- /snippets -->"
SNIPPET_NAMES = ("canonicalize_url", "match_key", "field_allowlists")


def skill_text():
    with open(SKILL_PATH, encoding="utf-8") as f:
        return f.read()


def split_skill(text=None):
    """Return (body before the snippets marker, the marked snippets block)."""
    text = text if text is not None else skill_text()
    start = text.index(SNIPPETS_START)
    end = text.index(SNIPPETS_END)
    return text[:start], text[start:end]


def word_count(body):
    return len(body.split())


def snippet_line_count(snippets):
    return len(snippets.strip().splitlines())


def snippet(name, text=None):
    """Return the code under `### name` (without its code fence)."""
    _, block = split_skill(text)
    marker = "### %s\n" % name
    i = block.index(marker)
    rest = block[i + len(marker):]
    j = rest.find("\n### ")
    rest = rest if j < 0 else rest[:j]
    lines = [ln for ln in rest.strip().splitlines() if not ln.startswith("```")]
    return "\n".join(lines) + "\n"


def load_snippet(name, text=None):
    """Compile and run one snippet in a fresh namespace and return it."""
    ns = {"__name__": "kt_snippet_" + name}
    exec(compile(snippet(name, text), "<snippet %s>" % name, "exec"), ns)
    return ns


_C_ESCAPES = {"t": 9, "r": 13, "n": 10, "\\": 92, "'": 39, '"': 34, "0": 0}


def decode_c_escapes(s):
    """Decode C-style escapes (\\t \\r \\n \\xNN \\\\) into bytes."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", s[i + 2:i + 4]):
                out.append(int(s[i + 2:i + 4], 16))
                i += 4
                continue
            if n in _C_ESCAPES:
                out.append(_C_ESCAPES[n])
                i += 2
                continue
        out += c.encode("utf-8")
        i += 1
    return bytes(out)


def canonicalization_vectors():
    with open(CASES_PATH, encoding="utf-8") as f:
        return json.load(f)["canonicalization_vectors"]["vectors"]
