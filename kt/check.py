"""Checklist-mode check skill helpers (SPEC.md §4).

The bot itself follows the skill text in skills/kings-taster-check.md. This module loads
that skill, runs its extractors, and applies the fixed decision rules so tests can prove
the skill and the rules agree. It never contacts the network.
"""
import os
import re
import subprocess
import sys
import uuid

from .common import normalize_package, parse_time, sha256_file
from .finding import RESULT_RANK, validate_record, GOOGLE_ATTRIBUTION, GOOGLE_NOTICE
from . import lookalike as LK
from . import urlcheck as U
from . import verify as KV

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-check.md")
WORD_CAP = 400
COMMAND_LINE_CAP = 150
EXTRACTOR_LINE_CAP = 10
REQUIRED = {
    "package": ("osv", "kings_taster_list"),
    "repo": ("github_api", "kings_taster_list"),
    "link": ("kings_taster_list", "rdap", "safe_browsing"),
}
ALLOWED_HOSTS = frozenset({
    "api.osv.dev",
    "api.github.com",
    "github.com",
    "release-assets.githubusercontent.com",
    "data.iana.org",
    "safebrowsing.googleapis.com",
})
LIST_PATH_PREFIX = U.LIST_PATH_PREFIX
BANNED = re.compile(r"\bsafe(ly|ty)?\b(?!\s+browsing)|guarantee", re.IGNORECASE)
# The skill body may mention the ban itself; the Google notice is only in Commands.
SAFE_EXCEPTIONS = ('Never say "safe"', "Safe Browsing")


def skill_text():
    with open(SKILL_PATH, encoding="utf-8") as f:
        return f.read()


def split_skill(text=None):
    text = text if text is not None else skill_text()
    start = text.index("<!-- commands -->")
    end = text.index("<!-- /commands -->")
    return text[:start], text[start:end]


def word_count(body):
    return len(body.split())


def command_line_count(commands):
    return len(commands.strip().splitlines())


def google_notice(text=None):
    _, commands = split_skill(text)
    block = commands.split("### google-notice", 1)[1]
    lines = [ln for ln in block.strip().splitlines() if ln and not ln.startswith("<!--")]
    return lines[0], " ".join(lines[1:])


def extractor_script(name, text=None):
    """Return the python3 -I -c script for ### extract-<name>."""
    _, commands = split_skill(text)
    marker = "### extract-%s\n" % name
    i = commands.index(marker)
    rest = commands[i + len(marker):]
    start = rest.index("python3 -I -c '\n") + len("python3 -I -c '\n")
    end = rest.index("\n'", start)
    return rest[start:end]


def run_extractor(name, *paths, text=None):
    script = extractor_script(name, text)
    return subprocess.run(
        [sys.executable, "-I", "-c", script, *paths],
        capture_output=True, text=True, timeout=15, check=False,
    )


def parse_extracted(stdout):
    lines = [ln for ln in stdout.splitlines() if ln]
    data = {"lines": lines, "class": None}
    for ln in lines:
        if ln.startswith("class "):
            data["class"] = ln.split(" ", 1)[1]
        elif ln == "injection_seen":
            data["class"] = "injection_seen"
        elif ln.startswith("osv_count "):
            data["osv_count"] = int(ln.split()[1])
        elif ln.startswith("list_hits "):
            data["list_hits"] = int(ln.split()[1])
        elif ln.startswith("sb_hits "):
            data["sb_hits"] = int(ln.split()[1])
        elif ln.startswith("full_name "):
            data["full_name"] = ln.split(" ", 1)[1]
        elif ln.startswith("created_at "):
            data["created_at"] = ln.split(" ", 1)[1]
        elif ln.startswith("ldhName "):
            data["ldhName"] = ln.split(" ", 1)[1]
        elif ln.startswith("registration "):
            data["registration"] = ln.split(" ", 1)[1]
        elif ln.startswith("threat "):
            data.setdefault("threats", []).append(ln.split(" ", 1)[1])
        elif " malicious " in ln or ln.endswith(" malicious") or " vulnerable " in ln:
            parts = ln.split()
            data.setdefault("hits", []).append({
                "id": parts[0], "kind": parts[1],
                "date": parts[2] if len(parts) > 2 else "",
                "fixed": parts[3] if len(parts) > 3 else "",
            })
        elif " canary=" in ln:
            parts = ln.split()
            data.setdefault("hits", []).append({
                "id": parts[0], "type": parts[1] if len(parts) > 1 else "",
                "date": parts[2] if len(parts) > 2 else "",
                "canary": " canary=yes" in ln,
                "review_state": next((t.split("=", 1)[1] for t in parts if t.startswith("review_state=")), "auto"),
            })
    return data


def _split_host_paths(host, url_path):
    """Return (hostname, [paths]); the host is empty when the arguments are refused.

    Every argument goes through the shared parser, so a bad authority in any of
    them (userinfo, port, backslash, ...) gives an empty host. A full URL must be
    https (or a '//host' reference). Control characters, space and DEL are refused
    in every form, including a bare host with a bare path. When url_path is a full
    URL, the hostname and path come from it; a bare host or a second full URL that
    names another host is a mismatch. With two full URLs both paths are returned.
    """
    if not isinstance(host, str) or not isinstance(url_path, str):
        return "", ["/"]
    path = url_path or ""
    raw_host = host or ""
    if any(c <= " " or c == "\x7f" for c in raw_host + path):
        return "", ["/"]
    host_is_url = U.is_url(raw_host)
    path_is_url = U.is_url(path)
    try:
        host_url = U.split_url(raw_host) if host_is_url else None
        path_url = U.split_url(path) if path_is_url else None
        bare = U.bare_host(raw_host) if raw_host and not host_is_url else None
    except ValueError:
        return "", ["/"]
    if any(u is not None and u[0] not in ("https", "") for u in (host_url, path_url)):
        return "", ["/"]
    if host_url is None and path_url is None:
        return bare or "", [path.split("?", 1)[0].split("#", 1)[0]]
    # With two full URLs, every path is returned so none goes unchecked.
    paths = [u[2] for u in (host_url, path_url) if u is not None]
    hostname = (host_url or path_url)[1]
    if host_url and path_url and not U.same_host(raw_host, path):
        return "", paths
    if bare is not None and bare != hostname:
        return "", paths
    return hostname, paths


def _split_host_path(host, url_path):
    """(hostname, path) for the first path; host_allowed checks every path."""
    hostname, paths = _split_host_paths(host, url_path)
    return hostname, paths[0]


def host_allowed(host, url_path="", list_redirect=False):
    """True only for allowlisted hosts. github.com is list-download paths only (no /repos/)."""
    host, paths = _split_host_paths(host, url_path)
    host = (host or "").lower()
    if list_redirect:
        return host in U.LIST_HOSTS
    if host == "github.com":
        return all(U.list_path_ok(p) for p in paths)
    if host not in ALLOWED_HOSTS:
        return False
    if host == "release-assets.githubusercontent.com":
        return False  # only as the allowed list-file redirect
    return True


_POPULAR_FILES = {"npm": "npm.txt", "PyPI": "pypi.txt"}
_POPULAR_DEFAULT = {}  # ecosystem -> frozenset of canonical names, default ROOT only

def clear_popular_cache():
    """Forget the cached default lists so the next call re-reads config/popular/."""
    _POPULAR_DEFAULT.clear()


def _read_popular_eco(eco, root):
    """Canonical names from one ecosystem's list. OSError if unreadable, ValueError if empty."""
    names = set()
    path = os.path.join(root, "config", "popular", _POPULAR_FILES[eco])
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.add(normalize_package(eco, line))
    if not names:
        raise ValueError("popular list is empty: %s" % _POPULAR_FILES[eco])
    return frozenset(names)


def popular_for(eco, root=None):
    """Names on one ecosystem's list ("npm" or "PyPI"). Only the default ROOT is cached."""
    if root is not None:
        return _read_popular_eco(eco, root)
    if eco not in _POPULAR_DEFAULT:
        _POPULAR_DEFAULT[eco] = _read_popular_eco(eco, ROOT)
    return _POPULAR_DEFAULT[eco]


def _popular_names(root=None):
    """Union of both lists as (ecosystem, name) pairs; fails if either list fails."""
    if root is not None:
        return frozenset((eco, n) for eco in _POPULAR_FILES for n in popular_for(eco, root))
    if "union" not in _POPULAR_DEFAULT:
        _POPULAR_DEFAULT["union"] = frozenset(
            (eco, n) for eco in _POPULAR_FILES for n in popular_for(eco))
    return _POPULAR_DEFAULT["union"]


def _canonical_ecosystem(ecosystem):
    """Map ecosystem spelling to the canonical value; unknown names are None (not an error)."""
    if not ecosystem:
        return None
    key = str(ecosystem).strip()
    lowered = key.lower()
    if lowered == "npm":
        return "npm"
    if lowered == "pypi":
        return "PyPI"
    return None


def is_popular(ecosystem, name, root=None):
    """True if the name is on the top-10k list. Ecosystem spelling is case-insensitive."""
    if not ecosystem or not name:
        return False
    eco = _canonical_ecosystem(ecosystem)
    if eco is None:
        return False
    names = popular_for(eco, root)  # an unreadable or empty list raises; it is not "not popular"
    try:
        return normalize_package(eco, name) in names
    except ValueError:
        return False


def verify_list(release_dir, allowed_signers=None, state=None, now=None,
                template_version=None, require_shards=False, max_age_hours=48,
                update_state=True):
    """Run the official verifier (scripts/verify.sh / kt.verify.verify_release) on a local dir.

    That path covers keys.json, rollback state, a missing-keys refusal once pins are
    published, latest.json hash and file_type checks, and shard SHA-256 vs the manifest.
    After a successful verify, the check path writes the rollback watermark when a
    state file is given (pass update_state=False to skip the write). Never contacts
    the network. Returns a dict with ok, reason, detail, and code.
    """
    allowed = allowed_signers or os.path.join(ROOT, "config", "allowed_signers")
    now_val = parse_time(now) if isinstance(now, str) else now
    try:
        code, line = KV.verify_release(
            release_dir, allowed, state=state, update_state=update_state,
            template_version=template_version, now=now_val,
            max_age_hours=max_age_hours, require_shards=require_shards,
        )
    except KV.VerifyError as e:
        return {"ok": False, "reason": "unverified_list", "detail": str(e)[:300], "code": 1}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        return {"ok": False, "reason": "unverified_list", "detail": str(e)[:300], "code": 1}
    if code == 0:
        return {"ok": True, "reason": None, "detail": line, "code": 0}
    if code == 5:
        return {"ok": False, "reason": "stale_list", "detail": line, "code": 5}
    if code == 3:
        return {"ok": False, "reason": "paused", "detail": line, "code": 3}
    if code == 4:
        return {"ok": False, "reason": "update_required", "detail": line, "code": 4}
    return {"ok": False, "reason": "unverified_list", "detail": line, "code": code}


# Official verifier used by scripts/verify.sh.
verify_release = KV.verify_release


def _date10(value, fallback=""):
    if not value:
        return fallback
    return str(value)[:10]


def _source_display(source):
    return {
        "osv": "OSV.dev",
        "kings_taster_list": "King's Taster list",
        "github_api": "the GitHub API",
        "rdap": "RDAP",
        "safe_browsing": "Google Safe Browsing",
        "pypi_registry": "the PyPI registry",
        "npm_registry": "the npm registry",
    }.get(source, source)


def _status_of(src):
    code = src.get("http_status")
    if src.get("status") == "not_configured":
        return "not_configured"
    if code in (403, 429) or src.get("status") == "rate_limited":
        return "rate_limited"
    extracted = src.get("extracted")
    if (isinstance(extracted, dict) and extracted.get("class") == "injection_seen") or src.get("status") == "injection_seen":
        return "failed"
    if src.get("status") == "failed" or (code and not (200 <= int(code) < 300)):
        return "failed"
    # Missing evidence is failed evidence: canary_ok must be exactly True and extracted a dict.
    if src.get("canary_ok") is not True or not isinstance(extracted, dict):
        return "failed"
    if not _has_evidence(src.get("source"), extracted):
        return "failed"
    if src.get("status") not in (None, "ok"):
        return "failed"
    return "ok"


def _has_evidence(source, extracted):
    cls = extracted.get("class")
    if source == "osv":
        return cls in ("clean", "vulnerable", "malicious")
    if source == "kings_taster_list":
        hits = extracted.get("hits")
        return cls == "clean" or (isinstance(hits, list) and len(hits) > 0)
    if source == "safe_browsing":
        return cls in ("clean", "hit")
    if source == "rdap":
        return cls in ("ok", "no_rdap")
    if source == "github_api":
        name = extracted.get("full_name")
        return isinstance(name, str) and bool(name)
    return isinstance(cls, str) and bool(cls)


POPULAR_LIST_UNREADABLE_NOTE = "The popular-name list couldn't be read."


def decide(item, sources, *, now, template_version, health=None, finding_id=None,
           finding_path="~/.kings-taster/findings/example.json"):
    """Apply the fixed checklist rules and return record, explanation, and at most 5 verdict lines.

    now and template_version are required keyword-only arguments (a missing one is a TypeError).
    """
    item_type = item["item_type"]
    indicator = item["indicator_defanged"]
    # Always consult config/popular/; there is no way to bypass a listed name.
    popular_failed = False
    popular = False
    reasons = []
    try:
        if item_type == "package":
            eco, name = LK.package_parts(item)
            if eco:
                popular_for(eco)  # a package needs only its own ecosystem's list
            else:
                _popular_names()
            popular = is_popular(eco or "", name or "")
        else:
            _popular_names()  # repo, link, other: both lists must be usable
            popular = is_popular(item.get("ecosystem") or "", item.get("name") or "")
    except (OSError, ValueError):
        popular_failed = True
        reasons.append("check_failed")
    if health and health.get("status") == "failing":
        reason = health.get("reason") or "failed"
        explanation = ("Unknown. I couldn't finish the check: health check failing: %s. "
                       "Don't proceed until it can be checked." % reason)
        stubs = []
        for req in REQUIRED.get(item["item_type"], ()):
            stubs.append({
                "source": req, "required": True, "status": "failed",
                "http_status": None, "response_sha256": None, "source_date": None,
            })
        rec = _record(item, stubs, result="unknown", reasons=["check_failed"],
                      explanation=explanation, now=now, template_version=template_version,
                      finding_id=finding_id)
        lines = _verdict_lines(rec, deciding=None, finding_path=finding_path)
        return rec, lines

    checked = []
    matched = []
    list_note = POPULAR_LIST_UNREADABLE_NOTE if popular_failed else None
    fixed = None
    deciding = None  # (rank, source, date, snippet)
    no_link = False

    for src in sources:
        name = src["source"]
        # Sources in REQUIRED for this item_type stay required; required=False
        # cannot opt them out. Only extra sources may be marked optional.
        required = name in REQUIRED.get(item_type, ()) or bool(src.get("required"))
        status = _status_of(src)
        if status == "not_configured":
            entry = {
                "source": name, "required": required, "status": "not_configured",
                "http_status": None, "response_sha256": None, "source_date": None,
            }
        else:
            entry = {
                "source": name, "required": required, "status": status if status in ("ok", "failed", "rate_limited") else "failed",
                "http_status": src.get("http_status"),
                "response_sha256": src.get("response_sha256") or ("0" * 64),
                "source_date": src.get("source_date") or now,
            }
        checked.append(entry)
        extracted = src.get("extracted")
        if not isinstance(extracted, dict):
            extracted = {}
        date = _date10(src.get("source_date") or extracted.get("date") or now)

        if status == "not_configured":
            if required and name == "safe_browsing":
                reasons.append("no_link_source")
                no_link = True
            elif required:
                reasons.append("check_failed")
            continue
        if status == "rate_limited":
            reasons.append("rate_limited")
            continue
        if status == "failed":
            if extracted.get("class") == "injection_seen" or src.get("status") == "injection_seen":
                reasons.append("injection_seen")
            if name == "kings_taster_list":
                reasons.append(src.get("list_reason") or "check_failed")
            elif extracted.get("class") != "injection_seen" and src.get("status") != "injection_seen":
                reasons.append("check_failed")
            continue
        if name == "osv":
            klass = extracted.get("class")
            hits = extracted.get("hits") or []
            if klass == "malicious" or any(h.get("kind") == "malicious" for h in hits):
                hit = next((h for h in hits if h.get("kind") == "malicious"), {"id": "MAL", "date": date})
                url = "https://osv.dev/vulnerability/%s" % hit["id"]
                if popular_failed:
                    # The popular-name hold can't apply, so a live MAL- is Block. check_failed
                    # is already in reasons; keep the hit in matched and say the list couldn't be read.
                    reasons.append("malicious_match")
                    matched.append(_match(hit["id"], url, "osv"))
                    deciding = _best(deciding, RESULT_RANK["block"], "osv", date,
                        "Block. %s is listed as malicious by OpenSSF Malicious Packages via OSV.dev (%s, %s). Don't proceed."
                        % (indicator, url, date))
                elif popular:
                    reasons.append("pending_review")
                    matched.append(_match(hit["id"], url, "osv"))
                    deciding = _best(deciding, RESULT_RANK["caution"], "osv", date,
                        "Caution. Reported malicious by OSV, pending review, from OSV.dev (%s, %s)." % (url, date))
                else:
                    reasons.append("malicious_match")
                    matched.append(_match(hit["id"], url, "osv"))
                    deciding = _best(deciding, RESULT_RANK["block"], "osv", date,
                        "Block. %s is listed as malicious by OpenSSF Malicious Packages via OSV.dev (%s, %s). Don't proceed."
                        % (indicator, url, date))
            elif klass == "vulnerable" or any(h.get("kind") == "vulnerable" for h in hits):
                hit = next((h for h in hits if h.get("kind") == "vulnerable"), {"id": "OSV", "date": date, "fixed": ""})
                url = "https://osv.dev/vulnerability/%s" % hit["id"]
                reasons.append("vulnerable_version")
                matched.append(_match(hit["id"], url, "osv"))
                fx = (hit.get("fixed") or "").strip()
                fixed = fx or None
                if fx:
                    why = "Version %s has a known vulnerability; upgrade to %s or later" % (
                        item.get("version") or "this version", fx)
                else:
                    why = "Version %s has a known vulnerability; no fixed version" % (
                        item.get("version") or "this version")
                deciding = _best(deciding, RESULT_RANK["caution"], "osv", date,
                    "Caution. %s, from OSV.dev (%s, %s)." % (why, url, date))
        elif name == "kings_taster_list":
            verified = bool(src.get("verified"))
            if not verified and src.get("release_dir"):
                vr = verify_list(
                    src["release_dir"],
                    allowed_signers=src.get("allowed_signers"),
                    state=src.get("state"),
                    now=now,
                    template_version=template_version,
                    require_shards=bool(src.get("require_shards", True)),
                    max_age_hours=src.get("max_age_hours", 48),
                )
                verified = bool(vr.get("ok"))
                if not verified:
                    reasons.append(vr.get("reason") or "unverified_list")
                    entry["status"] = "failed"
                    continue
            if not verified:
                reasons.append("unverified_list")
                entry["status"] = "failed"
                continue
            # Hits are already filtered by match_key, so a build-assigned "canary:" id
            # means the item under check is that reserved list canary: it blocks like
            # any other list hit. A canary=yes flag on a real id changes nothing.
            hits = list(extracted.get("hits") or [])
            # A pending_review hit (popular name, SPEC.md §7.2) is held at Caution;
            # any other hit, including approved, auto and reserved canaries, blocks.
            firm = [h for h in hits if h.get("review_state") != "pending_review"]
            held = [h for h in hits if h.get("review_state") == "pending_review"]
            url = "https://github.com/SoundMindsAI/kings-taster-data/"
            if extracted.get("class") != "clean" and firm:
                hit = firm[0]
                reasons.append("malicious_match")
                matched.append(_match(hit["id"], url, "list"))
                deciding = _best(deciding, RESULT_RANK["block"], "kings_taster_list", date,
                    "Block. %s is listed as malicious by King's Taster list (%s, %s). Don't proceed."
                    % (indicator, url, date))
            elif extracted.get("class") != "clean" and held:
                reasons.append("pending_review")
                matched.append(_match(held[0]["id"], url, "list"))
                deciding = _best(deciding, RESULT_RANK["caution"], "kings_taster_list", date,
                    "Caution. Reported malicious by the King's Taster list, pending review, from King's Taster list (%s, %s)."
                    % (url, date))
        elif name == "rdap":
            if extracted.get("class") == "no_rdap" or not extracted.get("registration"):
                reasons.append("no_rdap")
                deciding = _best(deciding, RESULT_RANK["caution"], "rdap", date,
                    "Caution. No RDAP registration date was found, from RDAP (https://www.iana.org/help/licensing-terms, %s)." % date)
        elif name == "safe_browsing":
            if extracted.get("class") == "hit":
                reasons.append("malicious_match")
                url = "https://safebrowsing.google.com"
                deciding = _best(deciding, RESULT_RANK["block"], "safe_browsing", date,
                    "Block. %s is listed as malicious by Google Safe Browsing (%s, %s). Don't proceed. %s %s"
                    % (indicator, url, date, GOOGLE_ATTRIBUTION, GOOGLE_NOTICE))

    # Lookalike-name check (SPEC.md §3.3): Caution only; an unreadable popular list is check_failed.
    look = LK.check(item)
    if look["class"] == "check_failed":
        if "check_failed" not in reasons:
            reasons.append("check_failed")
    elif look["class"] == "lookalike":
        reasons.append("lookalike")
        deciding = _best(deciding, RESULT_RANK["caution"], "lookalike", _date10(now),
            "Caution. %s looks like the popular name %s, from the lookalike-name check (%s)."
            % (look["label"], look["match"], _date10(now)))

    # required sources missing from the list entirely
    seen = {s["source"] for s in checked}
    for req in REQUIRED.get(item_type, ()):
        if req not in seen:
            if req == "safe_browsing":
                reasons.append("no_link_source")
                no_link = True
                checked.append({
                    "source": req, "required": True, "status": "not_configured",
                    "http_status": None, "response_sha256": None, "source_date": None,
                })
            else:
                reasons.append("check_failed")
                checked.append({
                    "source": req, "required": True, "status": "failed",
                    "http_status": None, "response_sha256": None, "source_date": None,
                })

    reasons = _uniq(reasons)
    result = "no_known_reports"
    if "malicious_match" in reasons:
        result = "block"
    elif any(r in reasons for r in ("check_failed", "no_link_source", "stale_list", "unverified_list",
                                     "injection_seen", "paused", "update_required", "rate_limited")):
        result = "unknown"
    elif reasons:
        result = "caution"

    if result == "block":
        explanation = deciding[3] if deciding and deciding[0] == RESULT_RANK["block"] else (
            "Block. %s is listed as malicious by a required source (https://osv.dev/vulnerability/MAL, %s). Don't proceed."
            % (indicator, _date10(now)))
        if list_note and list_note not in explanation:
            explanation = "%s %s" % (explanation, list_note)
    elif result == "unknown" and no_link and reasons == ["no_link_source"]:
        explanation = ("Unknown. I can't check links until a link-reputation source is set up. "
                       "Don't proceed. Say 'set up link checks' to add one.")
    elif result == "unknown":
        which = _unknown_which(reasons, checked)
        explanation = ("Unknown. I couldn't finish the check: %s. Don't proceed until it can be checked." % which)
        if deciding and deciding[3].startswith("Caution."):
            explanation = "%s %s" % (explanation, deciding[3])
    elif result == "caution":
        explanation = deciding[3] if deciding else (
            "Caution. A required source reported a concern, from OSV.dev (https://osv.dev/vulnerability/OSV, %s)." % _date10(now))
    else:
        parts = []
        for s in checked:
            if s["status"] == "ok":
                parts.append("%s (%s)" % (_source_display(s["source"]), _date10(s["source_date"])))
        explanation = "No known reports. Checked against %s on %s." % (", ".join(parts), _date10(now))

    rec = _record(item, checked, result, reasons, explanation, now, template_version, finding_id,
                  matched=matched, fixed=fixed)
    lines = _verdict_lines(rec, deciding, finding_path, list_note if result == "block" else None)
    return rec, lines


def _uniq(items):
    out = []
    for i in items:
        if i not in out:
            out.append(i)
    return out


def _best(current, rank, source, date, text):
    cand = (rank, source, date, text)
    if current is None or rank > current[0]:
        return cand
    return current


def _match(eid, url, origin):
    if origin == "osv":
        return {
            "id": "osv:%s" % eid, "source_url": url,
            "upstream_origin": "ossf-malicious-packages:osv" if eid.startswith("MAL-") else "osv",
            "license": "Apache-2.0" if eid.startswith("MAL-") else "CC-BY-4.0",
            "attribution": "OpenSSF Malicious Packages via OSV.dev" if eid.startswith("MAL-") else "OSV.dev",
        }
    return {
        "id": eid, "source_url": url, "upstream_origin": "kings-taster-list",
        "license": "CC0-1.0", "attribution": "King's Taster list",
    }


def _unknown_which(reasons, checked):
    if "rate_limited" in reasons:
        src = next((s for s in checked if s["status"] == "rate_limited"), None)
        name = _source_display(src["source"]) if src else "a source"
        return "%s is rate limiting requests, try again later" % name
    if "injection_seen" in reasons:
        return "an unexpected host or a value that broke the extractor"
    if "unverified_list" in reasons:
        return "the King's Taster list signature could not be verified"
    if "stale_list" in reasons:
        return "the King's Taster list is stale"
    failed = next((s for s in checked if s["status"] == "failed"), None)
    if failed:
        return "%s failed" % _source_display(failed["source"])
    return "a required check failed"


def _record(item, sources, result, reasons, explanation, now, template_version, finding_id,
            matched=None, fixed=None):
    rec = {
        "finding_id": finding_id or str(uuid.uuid4()),
        "checked_at": now if now.endswith("Z") else now + "Z",
        "template_version": template_version,
        "mode": "checklist",
        "checker_sha256": None,
        "item_type": item["item_type"],
        "indicator_defanged": item["indicator_defanged"],
        "result": result,
        "reasons": reasons,
        "checked_against": sources,
        "matched_entries": matched or [],
        "fixed_version": fixed,
        "explanation": explanation,
    }
    return rec


def _verdict_lines(rec, deciding, finding_path, note=None):
    result = rec["result"]
    label = {"block": "Block", "caution": "Caution", "unknown": "Unknown",
             "no_known_reports": "No known reports"}[result]
    line1 = "%s. %s" % (label, rec["indicator_defanged"])
    if deciding:
        line2 = "Deciding source: %s (%s)" % (_source_display(deciding[1]), deciding[2])
    elif rec["checked_against"]:
        ok = next((s for s in rec["checked_against"] if s["status"] == "ok"), rec["checked_against"][0])
        line2 = "Deciding source: %s (%s)" % (_source_display(ok["source"]), _date10(ok["source_date"]))
    else:
        line2 = "Deciding source: none"
    others = []
    for s in rec["checked_against"]:
        others.append("%s=%s" % (s["source"], s["status"]))
    line3 = "Sources: %s" % (", ".join(others) if others else "none")
    lines = [line1, line2, line3]
    if result == "unknown" and deciding and deciding[3].startswith("Caution."):
        lines.append(deciding[3])
    elif note:
        lines.append(note)
    elif result in ("unknown", "caution") and rec["reasons"]:
        lines.append("Reason: %s" % ", ".join(rec["reasons"]))
    lines.append(finding_path)
    return lines[:5]


def body_banned_words(body):
    text = body
    for exc in SAFE_EXCEPTIONS:
        text = text.replace(exc, "")
    return bool(BANNED.search(text))
