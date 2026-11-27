"""Weekly client health skill helpers (SPEC.md §4D). Never contacts the network."""
import errno
import fcntl
import json
import os
import re
import tempfile

from .common import parse_time, sha256_file, utc_now
from .shards import gzip_size
from .validate import CANARY_TYPES, ECO_PREFIX, MAX_MANIFEST_BYTES
from . import verify as KV

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-health.md")
ROUTINE_PATH = os.path.join(ROOT, "routines", "kings-taster-health.md")
ROUTINE_LINE = "Run kings-taster-health."
WORD_CAP = 250
COMMAND_LINE_CAP = 40
STALE_HOURS = 48
FUTURE_SKEW_SECONDS = 600  # client's 10-minute window (the published verifier uses 5)
MAX_SHARD_GZIP_BYTES = 5242880
UNKNOWN_LINE = "Unknown, don't proceed (health check failing: %s)"
LINE = ("Before you or any bot downloads, installs or clicks anything new, "
        "ask King's Taster and wait for its verdict. Don't proceed on Block or Unknown.")
MISSING_NUDGE = "The King's Taster line is missing from %s. Paste it again?"
QUIET_NOTE = "%s hasn't asked me anything in 30 days."
BANNED = re.compile(r"\bsafe(ly|ty)?\b(?!\s+browsing)|guarantee", re.IGNORECASE)
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


def routine_line():
    with open(ROUTINE_PATH, encoding="utf-8") as f:
        return f.read().strip()


def body_banned_words(body):
    text = body
    for exc in SAFE_EXCEPTIONS:
        text = text.replace(exc, "")
    return bool(BANNED.search(text))


def nudge_text(name):
    return MISSING_NUDGE % name + "\n" + LINE


def default_state_path(cache_dir):
    """Default verify-state path: sibling of the cache directory."""
    return os.path.join(os.path.dirname(os.path.abspath(cache_dir)), "verify-state.json")


def default_health_path(cache_dir):
    """Default health.json path: sibling of the cache directory."""
    return os.path.join(os.path.dirname(os.path.abspath(cache_dir)), "health.json")


def week_id(now):
    year, week, _ = now.isocalendar()
    return "%d-W%02d" % (year, week)


def _path_lock(path):
    """Exclusive lock on path.lock, opened with O_NOFOLLOW."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock_path = path + ".lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError("lock path must not be a symlink") from e
        raise

    class _Lock:
        def __enter__(self):
            fcntl.flock(fd, fcntl.LOCK_EX)
            return self

        def __exit__(self, exc_type, exc, tb):
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    return _Lock()


class _null_lock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def load_health(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("health.json must be an object")
    return doc


def save_health(path, doc, *, already_locked=False):
    """Write health.json via a temp file and rename. Does not follow symlinks."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _write():
        fd, tmp = tempfile.mkstemp(
            prefix=".health.", suffix=".tmp", dir=os.path.dirname(path) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
                f.write("\n")
                f.flush()
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    if already_locked:
        _write()
        return
    with _path_lock(path):
        _write()


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _list_canaries(iocs):
    have = set()
    for e in (iocs.get("entries") or []):
        if not e.get("canary"):
            continue
        typ = e.get("type") or ""
        if typ == "package":
            have.add(typ + ":" + ECO_PREFIX.get(e.get("ecosystem"), ""))
        else:
            have.add(typ)
    return have


def _caps_ok(cache_dir, manifest):
    man_path = os.path.join(cache_dir, "manifest.json")
    if os.path.isfile(man_path) and os.path.getsize(man_path) > MAX_MANIFEST_BYTES:
        return "the manifest is over the 5 MB cap"
    for s in manifest.get("shards") or []:
        path = os.path.join(cache_dir, s.get("file") or "")
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as fh:
            raw = fh.read()
        if gzip_size(raw) > MAX_SHARD_GZIP_BYTES:
            return "a cached shard is over the 5 MB gzip cap"
    return None


def _item1(cache_dir, now, allowed, state):
    latest_path = os.path.join(cache_dir, "latest.json")
    if not os.path.isfile(latest_path):
        return False, "the list is missing", None
    try:
        latest = _read_json(latest_path)
        generated = parse_time(latest["generated_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return False, "the list date could not be read", None
    if (generated - now).total_seconds() > FUTURE_SKEW_SECONDS:
        return False, "the list date is more than 10 minutes ahead", latest.get("generated_at")
    if (now - generated).total_seconds() > STALE_HOURS * 3600:
        return False, "the list is older than 48 hours", latest.get("generated_at")
    try:
        code, line = KV.verify_release(
            cache_dir, allowed, state=state, update_state=False,
            now=now, max_age_hours=STALE_HOURS, require_shards=False,
        )
    except KV.VerifyError as e:
        return False, "the list did not verify (%s)" % str(e)[:120], latest.get("generated_at")
    except (OSError, ValueError, KeyError) as e:
        return False, "the list did not verify", latest.get("generated_at")
    if code == 5:
        return False, "the list is older than 48 hours", latest.get("generated_at")
    if code not in (0, 3):
        return False, "the list did not verify", latest.get("generated_at")
    try:
        manifest = _read_json(os.path.join(cache_dir, "manifest.json"))
    except (OSError, ValueError):
        return False, "the manifest could not be read", latest.get("generated_at")
    cap = _caps_ok(cache_dir, manifest)
    if cap:
        return False, cap, latest.get("generated_at")
    return True, "list ok", latest.get("generated_at")


def _item2(cache_dir, canaries):
    iocs_path = os.path.join(cache_dir, "iocs.json")
    if not os.path.isfile(iocs_path):
        return False, "list canaries could not be checked"
    try:
        iocs = _read_json(iocs_path)
    except (OSError, ValueError):
        return False, "list canaries could not be checked"
    missing = sorted(CANARY_TYPES - _list_canaries(iocs))
    if missing:
        return False, "list canaries are missing"
    canaries = canaries or {}
    # OSV and RDAP are required. Missing or omitted results are a failure.
    # Safe Browsing is optional when unset; only an explicit False fails.
    if canaries.get("osv") is not True:
        return False, "the OSV canary was not caught"
    if canaries.get("rdap") is not True:
        return False, "the RDAP canary was not caught"
    if canaries.get("safe_browsing") is False:
        return False, "the Safe Browsing canary was not caught"
    return True, "canaries ok"


def _item3(checker):
    """Return (ok, detail, mode). mode is checklist if the checker is unused or failed."""
    if not checker:
        return True, "checker not in use", "checklist"
    approved = checker.get("approved_sha256")
    actual = checker.get("sha256")
    if not actual and checker.get("path") and os.path.isfile(checker["path"]):
        actual = sha256_file(checker["path"])
    if not approved or not actual or actual != approved:
        return False, "the checker SHA-256 does not match", "checklist"
    if checker.get("conformance_pass") is not True:
        return False, "conformance.json did not pass 100%", "checklist"
    return True, "checker ok", "checker"


def _item4(routing):
    """Return (ok, detail, nudge, notes). Missing line is a fail; 30-day notes are not."""
    routing = routing or {}
    covered = routing.get("covered") or []
    already = set(routing.get("already_nudged") or [])
    missing = []
    notes = []
    for bot in covered:
        name = bot.get("name") or "a covered bot"
        if not bot.get("line_present"):
            missing.append(name)
        days = bot.get("days_since_ask")
        if days is not None and days >= 30:
            notes.append(QUIET_NOTE % name)
    if not missing:
        return True, "routing ok", None, notes, None
    first = next((n for n in missing if n not in already), None)
    nudge = nudge_text(first) if first else None
    return False, "the routing line is missing from %s" % ", ".join(missing), nudge, notes, first


def run(*, cache_dir, now=None, status=False, allowed_signers=None, state=None,
        canaries=None, checker=None, routing=None, health_path=None):
    """Run the four health items against a local cache. Never contacts the network."""
    now = parse_time(now) if isinstance(now, str) else (now or utc_now())
    allowed = allowed_signers or os.path.join(ROOT, "config", "allowed_signers")
    if state is None and cache_dir:
        state = default_state_path(cache_dir)
    if health_path is None and cache_dir:
        health_path = default_health_path(cache_dir)
    ok1, detail1, list_date = _item1(cache_dir, now, allowed, state)
    ok2, detail2 = _item2(cache_dir, canaries)
    ok3, detail3, mode = _item3(checker)
    week = week_id(now)
    lock = _path_lock(health_path) if health_path else _null_lock()
    with lock:
        existing = {}
        if health_path:
            try:
                existing = load_health(health_path)
            except (OSError, ValueError):
                existing = {}
        persisted = []
        if existing.get("nudge_week") == week:
            persisted = [n for n in (existing.get("nudged") or []) if isinstance(n, str)]
        routing = dict(routing or {})
        already = list(routing.get("already_nudged") or [])
        for name in persisted:
            if name not in already:
                already.append(name)
        routing["already_nudged"] = already
        ok4, detail4, nudge, notes, nudge_name = _item4(routing)
        nudged = list(persisted)
        if nudge and nudge_name and nudge_name not in nudged:
            nudged.append(nudge_name)

        failing = not (ok1 and ok2)
        reason = None
        if not ok1:
            reason = detail1
        elif not ok2:
            reason = detail2
        doc = {
            "status": "failing" if failing else "ok",
            "reason": reason,
            "list_date": list_date,
            "mode": mode,
            "nudge_week": week,
            "nudged": nudged,
            "items": {
                "list": {"ok": ok1, "detail": detail1},
                "canaries": {"ok": ok2, "detail": detail2},
                "checker": {"ok": ok3, "detail": detail3},
                "routing": {"ok": ok4, "detail": detail4},
            },
        }
        if health_path:
            save_health(health_path, doc, already_locked=True)

    failing = doc["status"] == "failing"
    reason = doc["reason"]

    unknown_line = UNKNOWN_LINE % (reason or "failed") if failing else None
    fail_lines = []
    if failing:
        which = "the list" if not ok1 else "a canary"
        fail_lines = [
            "%s failed: %s." % (which[0].upper() + which[1:], reason),
            "Since the list date: %s." % (list_date or "unknown"),
            "Refresh the list, or say 'King's Taster status' after you have fixed it.",
        ][:3]
    elif not ok3:
        fail_lines = [
            "The checker failed: %s." % detail3,
            "Switched to checklist mode.",
            "Checks can continue in checklist mode.",
        ][:3]

    weekly_lines = []
    if failing or not ok3:
        weekly_lines = list(fail_lines)
    if not ok4 and nudge:
        weekly_lines = (weekly_lines + [nudge] + notes) if (failing or not ok3) else ([nudge] + notes)
    elif notes and (status or not ok4 or failing or not ok3):
        # 30-day notes ride with a nudge, or appear on a status run.
        if status:
            pass

    status_lines = [
        "List: %s%s" % ("ok" if ok1 else "fail", "" if ok1 else " (%s)" % detail1),
        "Canaries: %s%s" % ("ok" if ok2 else "fail", "" if ok2 else " (%s)" % detail2),
        "Checker: %s%s" % ("ok" if ok3 else "fail", "" if ok3 else " (%s)" % detail3),
        "Routing: %s%s" % ("ok" if ok4 else "fail", "" if ok4 else " (%s)" % detail4),
        "List date: %s" % (list_date or "unknown"),
        "Mode: %s" % mode,
    ]
    if list_date:
        # already included
        pass
    # at most 8
    if notes and status:
        for n in notes:
            if len(status_lines) < 8:
                status_lines.append(n)

    silent = (not status) and ok1 and ok2 and ok3 and ok4 and not notes
    # A 30-day note means something changed for the user, so the weekly run is not silent.
    if (not status) and ok1 and ok2 and ok3 and ok4 and notes:
        weekly_lines = notes
        silent = False

    return {
        "health": doc,
        "silent": silent,
        "lines": status_lines[:8] if status else weekly_lines,
        "nudge": nudge,
        "notes": notes,
        "unknown_line": unknown_line,
        "mode": mode,
        "failing": failing,
    }
