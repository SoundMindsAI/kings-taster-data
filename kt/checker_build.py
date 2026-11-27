"""Helpers for the optional checker-builder skill (SPEC.md §5).

The bot itself writes ~/.kings-taster/checker.py from skills/kings-taster-build.md. This
module only loads that skill, splits it, and extracts its reference snippets so tests can
prove they work. It is not a downloaded checker and never contacts the network.
"""
import json
import os
import re
from kt import common

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


class Refused(ValueError):
    """An untrusted value was refused: the check is Unknown (injection_seen)."""


PKG_NAME = re.compile(r"^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]{1,214}$")
PKG_VER = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
REPO_PART = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
ECOSYSTEMS = ("npm", "PyPI")
CHECKER = "~/.kings-taster/checker.py"
_cache = {}


def _snip(name):
    if name not in _cache:
        _cache[name] = load_snippet(name)
    return _cache[name]


def canonical_url(url):
    """Run the skill's canonicalize_url; it raises ValueError when it refuses."""
    return _snip("canonicalize_url")["canonicalize_url"](url)


def validate_package(name, version, ecosystem):
    if ecosystem not in ECOSYSTEMS:
        raise Refused("ecosystem")
    if not isinstance(name, str) or not isinstance(version, str):
        raise Refused("type")
    if not PKG_NAME.fullmatch(name) or not PKG_VER.fullmatch(version):
        raise Refused("name or version")
    if not common.valid_package_name(ecosystem, name):
        raise Refused("package name")
    return name, version


def validate_repo(owner_repo):
    if not isinstance(owner_repo, str) or owner_repo.count("/") != 1:
        raise Refused("repo")
    owner, repo = owner_repo.split("/")
    for side in (owner, repo):
        if not REPO_PART.fullmatch(side) or side in (".", ".."):
            raise Refused("repo")
    return owner_repo


def validate_url(url):
    """Return the canonical URL, or raise Refused."""
    if not isinstance(url, str) or not re.match(r"(?i)https?://", url):
        raise Refused("scheme")
    if any(c in url for c in "'\"`") or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise Refused("quote or control character")
    try:
        return canonical_url(url)
    except ValueError as e:
        raise Refused(str(e))


def link_match_keys(url):
    """url-sha256, domain and (for an IP host) ip keys from a canonical http(s) URL."""
    canon = validate_url(url)
    mk = _snip("match_key")["match_key"]
    host = re.match(r"^https?://([^/?]*)", canon).group(1)
    keys = [mk("url", canon)]
    if re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", host):
        keys.append(mk("ip", host))
    try:
        keys.append(mk("domain", host))
    except UnicodeError:
        raise Refused("host")
    return keys


def check_argv(item_type, name=None, version=None, ecosystem=None, url=None):
    """Return the checker command as an argv list (never a shell string)."""
    base = ["python3", "-I", "-s", CHECKER, "check", "--type=" + item_type]
    if item_type == "package":
        validate_package(name, version, ecosystem)
        return base + ["--ecosystem=" + ecosystem, "--name=" + name, "--version=" + version]
    if item_type == "repo":
        return base + ["--name=" + validate_repo(name)]
    if item_type == "link":
        validate_url(url)
        return base + ["--url=" + url]
    raise Refused("type")
