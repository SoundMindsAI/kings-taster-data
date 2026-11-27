#!/usr/bin/env python3
"""Stdlib-only secret scan for the kings-taster-data tree (pre-push hook and CI).

FAIL (exit 1): private key blocks, known token formats, credential assignments, high-entropy strings.
FLAG (reported, exit 0): email addresses and phone numbers, so a person can check them.

Usage:
  secret_scan.py [PATH]                       scan the working tree (default .)
  secret_scan.py --git-range BASE [PATH]      also scan every added line in BASE..HEAD
  secret_scan.py --staged [PATH]              scan what is about to be pushed/committed (pre-push)
Findings are printed as path:line rule plus a redacted hint; the matched text is never printed.
"""
import argparse
import hashlib
import math
import os
import re
import subprocess
import sys

SKIP_DIRS = {".git", "__pycache__", "node_modules"}  # skipped at any depth
SKIP_TOP_DIRS = {"work"}  # skipped only directly under the scan root
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".pdf",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".tar", ".jar", ".whl",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".o", ".a", ".class",
}
MAX_FILE = 5 * 1024 * 1024

FAIL_RULES = [
    ("private_key_block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai_like_key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9]{20,}\b")),
    ("stripe_key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}\b")),
    ("ngrok_token", re.compile(r"\b[0-9][A-Za-z0-9]{26}_[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("credential_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|client[_-]?secret|auth)\b\s*[:=]\s*[\"']([^\"'\s$<{]{12,})[\"']")),
]
FLAG_RULES = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", re.compile(r"(?<![\w.:/-])(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w.-])")),
]
ENTROPY_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
HEX_ONLY = re.compile(r"^[0-9a-f]+$|^[0-9A-F]+$")
SSH_PUBKEY = re.compile(r"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]{48}")
ALLOWED_EMAILS = {"support@soundminds.ai"}
URLS = re.compile(r"https?://[^\s\"'<>]+")
SRI_HASH = re.compile(r"\bsha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}")
ALLOWLIST_FILE = ".secret-scan-allow"
_ALLOWED_TOKENS = set()  # sha256 of exact high-entropy tokens a person has reviewed (never the token itself)
ENTROPY_LIMIT = 4.5


def entropy(s):
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def redact(s):
    return "%s…(%d chars)" % (s[:3], len(s))


def scan_line(line):
    fails, flags = [], []
    for name, rx in FAIL_RULES:
        m = rx.search(line)
        if m:
            fails.append((name, redact(m.group(0))))
    clean = SRI_HASH.sub("", URLS.sub("", SSH_PUBKEY.sub("", line)))
    for tok in ENTROPY_TOKEN.findall(clean):
        core = tok.strip("=-_/")
        if len(core) < 32 or HEX_ONLY.match(core):
            continue  # hashes (sha256 etc.) are expected in this repo
        if re.fullmatch(r"[A-Za-z_/-]+", core) or re.fullmatch(r"[a-z0-9_/-]+", core):
            continue  # identifiers and paths
        if entropy(core) >= ENTROPY_LIMIT and hashlib.sha256(core.encode()).hexdigest() not in _ALLOWED_TOKENS:
            fails.append(("high_entropy", redact(core)))
    for name, rx in FLAG_RULES:
        for m in rx.finditer(line):
            v = m.group(0)
            if name == "email" and (v.lower() in ALLOWED_EMAILS or v.lower().endswith(("@example.com", "@example.org"))):
                continue
            flags.append((name, redact(v)))
    return fails, flags


def iter_files(root):
    for d, dirs, files in os.walk(root):
        at_root = os.path.abspath(d) == os.path.abspath(root)
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and not (at_root and x in SKIP_TOP_DIRS))
        for f in sorted(files):
            yield os.path.join(d, f)


def scan_text(label, text, out):
    for n, line in enumerate(text.splitlines(), 1):
        if "secret-scan: allow" in line:
            continue
        fails, flags = scan_line(line)
        for r, h in fails:
            out["fail"].append("%s:%d %s %s" % (label, n, r, h))
        for r, h in flags:
            out["flag"].append("%s:%d %s %s" % (label, n, r, h))


def scan_tree(root, out):
    count = 0
    for p in iter_files(root):
        try:
            # A file is skipped only when it has a binary extension and its first
            # 8192 bytes contain a NUL. That's the fail-closed choice, so a text
            # secret renamed to .png is still scanned.
            if os.path.splitext(p)[1].lower() in BINARY_EXTS:
                with open(p, "rb") as f:
                    head = f.read(8192)
                if b"\0" in head:
                    out["flag"].append("%s: skipped_binary (known binary extension, not scanned)" % os.path.relpath(p, root))
                    continue
            if os.path.getsize(p) > MAX_FILE:
                out["fail"].append("%s: skipped_large_file (over %d bytes, not scanned)" % (os.path.relpath(p, root), MAX_FILE))
                continue
            with open(p, "rb") as f:
                data = f.read()
        except OSError:
            continue
        count += 1
        scan_text(os.path.relpath(p, root), data.decode("utf-8", "replace"), out)
    return count


def scan_git(root, base, out):
    if not base or set(base) == {"0"}:
        rng = ["HEAD"]
    else:
        rng = ["%s..HEAD" % base]
    diff = subprocess.run(["git", "-C", root, "log", "-p", "--no-color", "--format=commit %H"] + rng,
                          capture_output=True, text=True, errors="replace")
    if diff.returncode != 0:
        out["fail"].append("git: could not read history for the range")
        return
    added = "\n".join(l[1:] for l in diff.stdout.splitlines() if l.startswith("+") and not l.startswith("+++"))
    scan_text("git-history(%s)" % rng[0], added, out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--git-range", metavar="BASE")
    ap.add_argument("--staged", action="store_true")
    a = ap.parse_args(argv)
    out = {"fail": [], "flag": []}
    allow = os.path.join(a.path, ALLOWLIST_FILE)
    if os.path.exists(allow):
        with open(allow, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"^sha256:([0-9a-f]{64})\s", line)
                if m:
                    _ALLOWED_TOKENS.add(m.group(1))
    n = scan_tree(a.path, out)
    if a.git_range is not None:
        scan_git(a.path, a.git_range, out)
    if a.staged:
        st = subprocess.run(["git", "-C", a.path, "diff", "--cached", "-U0", "--no-color"], capture_output=True,
                            text=True, errors="replace")
        scan_text("staged", "\n".join(l[1:] for l in st.stdout.splitlines() if l.startswith("+")), out)
    for line in out["fail"]:
        print("FAIL " + line)
    for line in out["flag"]:
        print("FLAG " + line)
    verdict = "FAIL" if out["fail"] else "PASS"
    print("secret-scan: %s (%d files, %d fail, %d flag)" % (verdict, n, len(out["fail"]), len(out["flag"])))
    return 1 if out["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
