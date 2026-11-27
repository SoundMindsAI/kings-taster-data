"""Validator for the King's Taster finding record (SPEC.md §8).

Usage: python3 -m kt.finding record.json [more.json ...]
Exit 0 if every record is valid, 1 otherwise. Prints one line per file, never the record contents.
"""
import json
import os
import re
import sys
import unicodedata
from urllib.parse import unquote, urlsplit

from . import jsonschema_lite
from .common import loads_strict, parse_time

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "schema", "finding-record.schema.json")

RESULT_RANK = {"block": 3, "unknown": 2, "caution": 1, "no_known_reports": 0}
# Reasons that mean a check could not be completed -> Unknown (Block still wins, SPEC.md §3.1).
UNKNOWN_REASONS = {"check_failed", "no_link_source", "stale_list", "unverified_list",
                   "injection_seen", "paused", "update_required", "rate_limited"}
CAUTION_REASONS = {"vulnerable_version", "new_domain", "no_rdap", "lookalike", "install_scripts",
                   "retired_entry", "source_build_required", "pending_review"}
BLOCK_REASONS = {"malicious_match"}
REQUIRED_SOURCES = {  # SPEC.md §3.1 required sources per item type
    "package": {"osv", "kings_taster_list"},
    "repo": {"github_api", "kings_taster_list"},
    "link": {"kings_taster_list", "rdap", "safe_browsing"},
}
LINK_REPUTATION = {"safe_browsing"}

# Mandated third-party notice text that may legitimately contain banned words.
GOOGLE_NOTICE = ("Google works to provide the most accurate and up-to-date information about unsafe web "
                 "resources. However, Google cannot guarantee that its information is comprehensive and "
                 "error-free: some risky sites may not be identified, and some safe sites may be identified in error.")
GOOGLE_ATTRIBUTION = "Advisory provided by Google"
BANNED = re.compile(r"\bsafe(ly|ty)?\b(?!\s+browsing)|guarantee", re.IGNORECASE)
WORDING_PREFIX = {"block": "Block.", "caution": "Caution.", "unknown": "Unknown.",
                  "no_known_reports": "No known reports."}
URL_IN_TEXT = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)
EXPLANATION_URL_HOSTS = {"osv.dev", "www.cisa.gov", "github.com", "transparencyreport.google.com",
                         "safebrowsing.google.com"}
# On github.com only advisories and this repo count as official source links.
GITHUB_OFFICIAL_PATHS = ("/advisories", "/SoundMindsAI/kings-taster-data/")
# The one fixed No-known-reports form (SPEC.md §3.1): every source carries its own date.
NKR_FORM = re.compile(r"No known reports\. Checked against [^()\n]{1,80} \(\d{4}-\d{2}-\d{2}\)"
                      r"(?:, [^()\n]{1,80} \(\d{4}-\d{2}-\d{2}\))* on \d{4}-\d{2}-\d{2}\.\Z")
INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
                       "\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]")


def _normalize_text(s):
    """NFKC-fold (fullwidth, ligatures) and drop invisible characters before word tests."""
    return INVISIBLE.sub("", unicodedata.normalize("NFKC", s))


def official_url_problem(url, allowed_hosts):
    """None if url is a plain https link on an allowed host with no dot or empty path segments."""
    if "\\" in url or re.search(r"%2e|%2f|%5c", url, re.IGNORECASE):
        return "encoded dot, slash or backslash"
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "unparsable"
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or host not in allowed_hosts or port is not None or parts.username or parts.password:
        return "not an official https host"
    path = parts.path
    decoded = path
    for _ in range(3):
        decoded = unquote(decoded)
    segs = decoded.split("/")[1:]
    if any(s in (".", "..") for s in segs) or "" in segs[:-1]:
        return "dot or empty path segment"
    if host == "github.com" and not (decoded == "/advisories" or decoded.startswith(("/advisories/",) + GITHUB_OFFICIAL_PATHS[1:])):
        return "github.com link outside advisories and the kings-taster-data repo"
    return None

PKG_IND = re.compile(r"^(npm|pypi):((?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*)(@[A-Za-z0-9.+_!~-]{1,64})?\Z")
REPO_IND = re.compile(r"^github:[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}\Z")
LINK_IND = re.compile(r"^hxxps?://[^/?#\s]+(?:[/?#][\x21-\x7e]*)?\Z")


def _load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def _check_indicator(item_type, ind, errors):
    if item_type == "package":
        if not PKG_IND.match(ind):
            errors.append("indicator_defanged: not a valid npm:/pypi: package indicator")
    elif item_type == "repo":
        if not REPO_IND.match(ind):
            errors.append("indicator_defanged: not a valid github:owner/repo indicator")
    elif item_type == "link":
        if not LINK_IND.match(ind):
            errors.append("indicator_defanged: links must start hxxp:// or hxxps://")
        else:
            host = re.match(r"^hxxps?://([^/?#]+)", ind).group(1)
            if "." in host.replace("[.]", ""):
                errors.append("indicator_defanged: every dot in the host must be written [.]")
            if "[.]" not in host and not host.startswith("["):
                errors.append("indicator_defanged: host has no defanged dot")
    if re.search(r"https?://", ind, re.IGNORECASE):
        errors.append("indicator_defanged: contains a live URL")


def _refang(ind):
    return ind.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".").replace("[://]", "://")


def check_rules(rec):
    """Cross-field rules (schema/FINDING-RULES.md). Assumes the schema already passed."""
    errors = []
    result = rec["result"]
    reasons = set(rec["reasons"])
    ca = rec["checked_against"]
    sources = [c["source"] for c in ca]
    if len(sources) != len(set(sources)):
        errors.append("checked_against: each source may appear once")

    try:
        parse_time(rec["checked_at"])
    except ValueError:
        errors.append("checked_at: not a valid time")

    _check_indicator(rec["item_type"], rec["indicator_defanged"], errors)

    # R1: required sources for this item type must be listed and marked required.
    req = REQUIRED_SOURCES[rec["item_type"]]
    by_src = {c["source"]: c for c in ca}
    for s in sorted(req):
        if s not in by_src:
            errors.append("checked_against: required source %s missing" % s)
        elif not by_src[s]["required"]:
            errors.append("checked_against: %s must be required=true for %s" % (s, rec["item_type"]))
    for c in ca:
        if c["required"] and c["source"] not in req:
            errors.append("checked_against: %s is not a required source for %s" % (c["source"], rec["item_type"]))

    # R2: a required source that is not ok forces Unknown (Block still wins).
    failed_required = [c for c in ca if c["required"] and c["status"] != "ok"]
    if failed_required and result not in ("unknown", "block"):
        errors.append("result: a required source did not succeed, so result must be unknown (or block)")
    if failed_required:
        need = set()
        for c in failed_required:
            if c["status"] == "rate_limited":
                need.add("rate_limited")
            elif c["status"] == "not_configured" and c["source"] in LINK_REPUTATION:
                need.add("no_link_source")
            elif c["source"] == "kings_taster_list":
                need |= set()  # list problems use stale_list / unverified_list / check_failed / paused
            else:
                need.add("check_failed")
        missing = [r for r in sorted(need) if r not in reasons]
        if missing:
            errors.append("reasons: missing %s for the failed required source(s)" % ",".join(missing))
        if by_src.get("kings_taster_list", {}).get("status", "ok") != "ok" and not (
                reasons & {"stale_list", "unverified_list", "check_failed", "paused", "rate_limited", "update_required"}):
            errors.append("reasons: list file failed but no list reason given")
    for c in ca:
        if c["status"] == "rate_limited" and "rate_limited" not in reasons:
            errors.append("reasons: rate_limited source without the rate_limited reason")

    # R3: reasons must be consistent with the result (precedence Block > Unknown > Caution > No known reports).
    if reasons & UNKNOWN_REASONS and result not in ("unknown", "block"):
        errors.append("result: an Unknown reason is present, so result must be unknown (or block)")
    if reasons & CAUTION_REASONS and result == "no_known_reports":
        errors.append("result: a Caution reason is present, so result can't be no_known_reports")
    if result == "block" and "malicious_match" not in reasons:
        errors.append("result: block needs the malicious_match reason")
    if "malicious_match" in reasons and result != "block":
        errors.append("result: malicious_match must give block (use pending_review for held popular names)")
    if "pending_review" in reasons and "malicious_match" in reasons:
        errors.append("reasons: pending_review and malicious_match can't both apply to one item")
    if result == "caution" and not (reasons & CAUTION_REASONS):
        errors.append("result: caution needs a Caution reason")
    if result == "unknown" and not (reasons & UNKNOWN_REASONS) and not failed_required:
        errors.append("result: unknown needs an Unknown reason or a failed required source")
    if result == "no_known_reports":
        if reasons - {"checker_failed"}:
            errors.append("result: no_known_reports allows no reasons except checker_failed")
        if rec["matched_entries"]:
            errors.append("result: no_known_reports can't have matched entries")
        if any(c["required"] and c["status"] != "ok" for c in ca):
            errors.append("result: no_known_reports needs every required source ok")

    # R4: matches.
    for m in rec["matched_entries"]:
        if official_url_problem(m["source_url"], EXPLANATION_URL_HOSTS):
            errors.append("matched_entries.source_url: not a plain official source link")
    if (result == "block" or reasons & {"vulnerable_version", "retired_entry", "pending_review"}) and not rec["matched_entries"]:
        errors.append("matched_entries: needed for block, vulnerable_version, retired_entry and pending_review")
    if "vulnerable_version" in reasons and rec["fixed_version"] is None:
        # A fix may genuinely not exist; then the explanation must say so.
        if "no fixed version" not in rec["explanation"].lower():
            errors.append("fixed_version: required with vulnerable_version (or say 'no fixed version')")
    if "vulnerable_version" not in reasons and rec["fixed_version"] is not None:
        errors.append("fixed_version: only allowed with vulnerable_version")

    # R5: mode / checker.
    if "checker_failed" in reasons and rec["mode"] != "checklist":
        errors.append("mode: checker_failed means the bot fell back to checklist mode")

    # R6: explanation wording.
    exp = rec["explanation"]
    if not exp.startswith(WORDING_PREFIX[result]):
        errors.append("explanation: must start with %r (SPEC.md §3.1 wording)" % WORDING_PREFIX[result])
    if result == "no_known_reports" and not NKR_FORM.match(exp):
        errors.append("explanation: must be 'No known reports. Checked against <source> (<date>), ... on <date>.'")
    if INVISIBLE.search(exp) or unicodedata.normalize("NFKC", exp) != exp:
        errors.append("explanation: contains invisible or compatibility characters")
    stripped = _normalize_text(exp).replace(GOOGLE_NOTICE, "")
    if BANNED.search(stripped):
        errors.append("explanation: uses a banned word (safe / guarantee)")
    sb_ok = by_src.get("safe_browsing", {}).get("status") == "ok"
    if GOOGLE_ATTRIBUTION in exp and not sb_ok:
        errors.append("explanation: Google attribution only allowed when Safe Browsing was used")
    for u in URL_IN_TEXT.findall(exp):
        if official_url_problem(u.rstrip(".,;:"), EXPLANATION_URL_HOSTS):
            errors.append("explanation: contains a URL that is not an official source link")
            break
    if rec["item_type"] == "link":
        live = _refang(rec["indicator_defanged"])
        norm = _normalize_text(exp).lower()
        host = re.match(r"^https?://([^/?#]+)", live)
        if live.lower() in norm:
            errors.append("explanation: contains the live (refanged) indicator")
        elif host and host.group(1).lower() in norm:
            errors.append("explanation: contains the live (refanged) host")
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", exp):
        errors.append("explanation: contains control characters")
    return errors


def validate_record(rec, schema=None):
    schema = schema or _load_schema()
    errs = jsonschema_lite.validate(rec, schema)
    if errs:
        return errs
    return check_rules(rec)


def main(argv):
    if not argv:
        print("usage: python3 -m kt.finding record.json [...]", file=sys.stderr)
        return 2
    schema = _load_schema()
    bad = 0
    for path in argv:
        try:
            with open(path, "rb") as f:
                rec = loads_strict(f.read())
        except (OSError, ValueError, RecursionError) as e:
            print("INVALID %s: unreadable (%s)" % (path, type(e).__name__))
            bad += 1
            continue
        try:
            errs = validate_record(rec, schema)
        except RecursionError:
            errs = ["record nested too deeply"]
        if errs:
            bad += 1
            print("INVALID %s: %d problem(s)" % (path, len(errs)))
            for e in errs:
                print("  - " + e)
        else:
            print("VALID %s" % path)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
