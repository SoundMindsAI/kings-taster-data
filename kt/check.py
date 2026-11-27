"""Checklist-mode check skill helpers (SPEC.md §4).

The bot itself follows the skill text in skills/kings-taster-check.md. This module loads
that skill, runs its extractors, and applies the fixed decision rules so tests can prove
the skill and the rules agree. It never contacts the network.
"""
import hashlib
import os
import posixpath
import re
import subprocess
import sys
import uuid

from .common import normalize_package, parse_time
from .finding import RESULT_RANK, validate_record, GOOGLE_ATTRIBUTION, GOOGLE_NOTICE
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
LIST_REDIRECT_HOSTS = frozenset({"github.com", "release-assets.githubusercontent.com"})
LIST_PATH_PREFIX = "/SoundMindsAI/kings-taster-data/releases/download/"
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
                "canary": ln.endswith("canary=yes"),
            })
    return data


def _unquote_path(value, times=4):
    """Decode %XX sequences (any case) a few times, without a network library."""
    out = value or ""
    for _ in range(times):
        nxt = re.sub(r"%([0-9A-Fa-f]{2})",
                     lambda m: bytes.fromhex(m.group(1)).decode("latin-1"), out)
        if nxt == out:
            break
        out = nxt
    return out


def _has_dotdot(value):
    """True if value has a '..' path segment, including percent-encoded forms."""
    raw = value or ""
    lower = raw.lower()
    if ".." in raw:
        return True
    if "%2e%2e" in lower or "%2e." in lower or ".%2e" in lower or "%252e" in lower:
        return True
    return False


def _split_host_path(host, url_path):
    """Accept a bare host + path, or a full URL in either argument.

    When url_path is a full URL, the hostname always comes from that URL.
    A bare host that does not match it is treated as a mismatch (empty host).
    """
    path = url_path or ""
    raw_host = host or ""
    source = raw_host if ("://" in raw_host or raw_host.startswith("//")) else (
        path if ("://" in path or path.startswith("//")) else None)
    if source is not None:
        rest = source.split("://", 1)[-1] if "://" in source else source[2:]
        authority, _, remainder = rest.partition("/")
        # Query or fragment in the authority is not a host (e.g.
        # https://evil.example?x=@github.com/...). Refuse before the '@' split.
        if "?" in authority or "#" in authority:
            return "", "/"
        if "@" in authority:
            authority = authority.rsplit("@", 1)[1]
        # Strip a port, but keep IPv6 in brackets out of scope (we only allow names).
        if authority.startswith("["):
            hostname = authority[1:].split("]", 1)[0]
        else:
            hostname = authority.split(":", 1)[0]
        parsed_path = "/" + remainder if remainder or rest.endswith("/") or "/" in rest else "/"
        parsed_path = parsed_path.split("?", 1)[0].split("#", 1)[0]
        if "://" in raw_host or raw_host.startswith("//"):
            return hostname, parsed_path
        # url_path is a full URL: always use its hostname. A bare host
        # argument that disagrees is a mismatch and is refused.
        if raw_host:
            given = raw_host.split("@", 1)[-1]
            if given.startswith("["):
                given = given[1:].split("]", 1)[0]
            else:
                given = given.split(":", 1)[0]
            if given.lower() != hostname.lower():
                return "", parsed_path
        return hostname, parsed_path
    return raw_host, path.split("?", 1)[0].split("#", 1)[0]


def _list_download_path_ok(path):
    """github.com is allowed only for /SoundMindsAI/kings-taster-data/releases/download/<tag>/<file>.

    The prefix is matched on segment boundaries. Any '..' (raw or encoded, any case) is refused.
    """
    if not path or _has_dotdot(path):
        return False
    decoded = _unquote_path(path)
    if _has_dotdot(decoded):
        return False
    if "\\" in decoded:
        return False
    if not decoded.startswith("/"):
        decoded = "/" + decoded
    normalized = posixpath.normpath(decoded)
    if normalized != decoded.rstrip("/") and normalized + "/" != decoded:
        # Collapse of '.' or '//' only is ok; a changed path after '..' was already refused.
        if ".." in decoded.split("/") or ".." in normalized.split("/"):
            return False
    if not normalized.startswith(LIST_PATH_PREFIX):
        return False
    rest = normalized[len(LIST_PATH_PREFIX):]
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2:
        return False
    if any(p in (".", "..") for p in parts):
        return False
    return True


def host_allowed(host, url_path="", list_redirect=False):
    """True only for allowlisted hosts. github.com is list-download paths only (no /repos/)."""
    host, url_path = _split_host_path(host, url_path)
    host = (host or "").lower()
    if list_redirect:
        return host in LIST_REDIRECT_HOSTS
    if host == "github.com":
        return _list_download_path_ok(url_path)
    if host not in ALLOWED_HOSTS:
        return False
    if host == "release-assets.githubusercontent.com":
        return False  # only as the allowed list-file redirect
    return True


def _popular_names(root=None):
    root = root or ROOT
    names = set()
    for eco, fname in (("npm", "npm.txt"), ("PyPI", "pypi.txt")):
        path = os.path.join(root, "config", "popular", fname)
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                names.add((eco, normalize_package(eco, line)))
    return names


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
    try:
        return (eco, normalize_package(eco, name)) in _popular_names(root)
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
    extracted = src.get("extracted") or {}
    if extracted.get("class") == "injection_seen" or src.get("status") == "injection_seen":
        return "failed"
    if src.get("status") == "failed" or (code and not (200 <= int(code) < 300)):
        return "failed"
    if src.get("canary_ok") is False:
        return "failed"
    return src.get("status") or "ok"


def decide(item, sources, *, popular=None, health=None, now="2026-11-27T00:00:00Z",
           template_version="1.0.0", finding_id=None, finding_path="~/.kings-taster/findings/example.json"):
    """Apply the fixed checklist rules and return record, explanation, and at most 5 verdict lines."""
    item_type = item["item_type"]
    indicator = item["indicator_defanged"]
    # Always consult config/popular/; the popular= flag cannot bypass a listed name,
    # and cannot hold an unlisted name at Caution.
    popular = is_popular(item.get("ecosystem") or "", item.get("name") or "")
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
    reasons = []
    matched = []
    fixed = None
    deciding = None  # (rank, source, date, snippet)
    sb_ok = False
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
        extracted = src.get("extracted") or {}
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
                if popular:
                    reasons.append("pending_review")
                    matched.append(_match(hit["id"], url, "osv"))
                    deciding = max(filter(None, [deciding, (RESULT_RANK["caution"], "osv", date,
                        "Caution. Reported malicious by OSV, pending review, from OSV.dev (%s, %s)." % (url, date))]),
                        default=None, key=lambda x: x[0]) if deciding else (
                            RESULT_RANK["caution"], "osv", date,
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
            # Only the build-assigned "canary:" ids are canaries. A hit that merely
            # carries canary=yes is real list data and must still block.
            hits = [h for h in (extracted.get("hits") or [])
                    if not str(h.get("id") or "").startswith("canary:")]
            if extracted.get("class") != "clean" and hits:
                hit = hits[0]
                url = "https://github.com/SoundMindsAI/kings-taster-data/"
                reasons.append("malicious_match")
                matched.append(_match(hit["id"], url, "list"))
                deciding = _best(deciding, RESULT_RANK["block"], "kings_taster_list", date,
                    "Block. %s is listed as malicious by King's Taster list (%s, %s). Don't proceed."
                    % (indicator, url, date))
        elif name == "rdap":
            if extracted.get("class") == "no_rdap" or not extracted.get("registration"):
                reasons.append("no_rdap")
                deciding = _best(deciding, RESULT_RANK["caution"], "rdap", date,
                    "Caution. No RDAP registration date was found, from RDAP (https://www.iana.org/help/licensing-terms, %s)." % date)
        elif name == "safe_browsing":
            sb_ok = True
            if extracted.get("class") == "hit":
                reasons.append("malicious_match")
                url = "https://safebrowsing.google.com"
                deciding = _best(deciding, RESULT_RANK["block"], "safe_browsing", date,
                    "Block. %s is listed as malicious by Google Safe Browsing (%s, %s). Don't proceed. %s %s"
                    % (indicator, url, date, GOOGLE_ATTRIBUTION, GOOGLE_NOTICE))

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

    if sb_ok and GOOGLE_ATTRIBUTION not in explanation:
        # only add when SB contributed a line; block path already adds it
        pass

    rec = _record(item, checked, result, reasons, explanation, now, template_version, finding_id,
                  matched=matched, fixed=fixed)
    lines = _verdict_lines(rec, deciding, finding_path)
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


def _verdict_lines(rec, deciding, finding_path):
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
    elif result in ("unknown", "caution") and rec["reasons"]:
        lines.append("Reason: %s" % ", ".join(rec["reasons"]))
    lines.append(finding_path)
    return lines[:5]


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def body_banned_words(body):
    text = body
    for exc in SAFE_EXCEPTIONS:
        text = text.replace(exc, "")
    return bool(BANNED.search(text))
