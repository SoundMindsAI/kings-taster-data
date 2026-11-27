"""First-run setup (SPEC.md §4C, §4D, §10.1): plain statement, routing, then connectivity.

The bot follows skills/kings-taster-first-run.md. This module sequences those steps
for tests. It never contacts X: a poster, if provided, must be a dry-run double
passed in by the caller.
"""
import errno
import fcntl
import json
import os
import tempfile
import threading

from . import connectivity as CONN
from . import routing as R

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-first-run.md")
WORD_CAP = 250
PLAIN_STATEMENT = (
    "When you check something, your bot sends only that item (the package name and version, "
    "the repo name, or the link's domain or hash prefix) to the official sources named in the "
    "answer. It sends nothing about you, except the IP address every web request carries, and "
    "your Safe Browsing key if you add one. Your Grok Bot's AI sees what you ask it to check "
    "and what comes back, like anything else you ask it, and it also sees any key you add. A "
    "finding is shared only when you approve the exact post, each time."
)
STATE_KEY = CONN.STATE_KEY
CONNECTIVITY_ITEM = "connectivity"


def skill_text():
    with open(SKILL_PATH, encoding="utf-8") as f:
        return f.read()


def split_skill(text=None):
    text = text if text is not None else skill_text()
    a, b = text.index("<!-- fixed -->"), text.index("<!-- /fixed -->")
    return text[:a], text[a + len("<!-- fixed -->"):b].strip()


def word_count(body):
    return len(body.split())


def report_caps(limits):
    caps = limits["reports_per_install"]
    return caps["per_day"], caps["per_week"], caps["per_item_per_week"]


def reports_left(used, limits, *, item=CONNECTIVITY_ITEM):
    """How many connectivity replies may still start, given usage counts."""
    day, week, per_item = report_caps(limits)
    item_used = used.get("items", {}).get(item, 0)
    left = min(day - used.get("day", 0), week - used.get("week", 0), per_item - item_used)
    return max(0, left)


class DryRunPoster:
    """A test double. It never contacts the network or any posting tool."""

    def __init__(self, *, post_ok=True, read_ok=True, thread_url="https://example.invalid/thread"):
        self.post_ok = post_ok
        self.read_ok = read_ok
        self.thread_url = thread_url
        self.posts = []
        self.reads = 0

    def post(self, text, thread_url=None):
        self.posts.append({"text": text, "thread": thread_url or self.thread_url})
        if not self.post_ok:
            return {"ok": False, "reason": "dry-run post failed", "url": None}
        return {"ok": True, "reason": None, "url": (thread_url or self.thread_url) + "/reply"}

    def read_thread(self, thread_url=None):
        self.reads += 1
        if not self.read_ok:
            return {"ok": False, "message": "read-only check failed"}
        return {"ok": True, "message": CONN.READ_ONLY_OK}


def valid_limits(limits):
    """True if limits has usable non-negative report caps. Missing or corrupt is False."""
    if not isinstance(limits, dict):
        return False
    try:
        day, week, per_item = report_caps(limits)
    except (TypeError, KeyError, ValueError):
        return False
    return all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
               for n in (day, week, per_item))


def _empty_used():
    return {"day": 0, "week": 0, "items": {}}


def _copy_used(used):
    out = _empty_used()
    if not used:
        return out
    out["day"] = used.get("day", 0)
    out["week"] = used.get("week", 0)
    out["items"] = dict(used.get("items") or {})
    return out


def _valid_usage(used):
    if not isinstance(used, dict):
        return False
    for key in ("day", "week"):
        if key in used:
            n = used[key]
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                return False
    items = used.get("items", {})
    if items is None:
        items = {}
    if not isinstance(items, dict):
        return False
    for v in items.values():
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return False
    return True


def usage_from_state(state):
    """Return persisted usage, or None if the file has no usage fields yet."""
    if not state:
        return None
    if not any(k in state for k in ("day", "week", "items")):
        return None
    used = {
        "day": state.get("day", 0),
        "week": state.get("week", 0),
        "items": dict(state.get("items") or {}),
    }
    if not _valid_usage(used):
        raise ValueError("state.json usage is corrupt")
    return used


def merge_used(caller, persisted):
    """Take the higher count in each field so a stale caller cannot lower caps."""
    a = _copy_used(caller)
    if not persisted:
        return a
    b = _copy_used(persisted)
    items = set(a["items"]) | set(b["items"])
    return {
        "day": max(a["day"], b["day"]),
        "week": max(a["week"], b["week"]),
        "items": {k: max(a["items"].get(k, 0), b["items"].get(k, 0)) for k in items},
    }


def reserve_report(used, limits, *, item=CONNECTIVITY_ITEM):
    """Increment usage in place if a slot remains. Return True if reserved."""
    if not valid_limits(limits):
        return False
    if reports_left(used, limits, item=item) < 1:
        return False
    used["day"] = used.get("day", 0) + 1
    used["week"] = used.get("week", 0) + 1
    used.setdefault("items", {})
    used["items"][item] = used["items"].get(item, 0) + 1
    return True


def load_state(path):
    """Load and validate state.json. Missing is {}. Corrupt raises before any post."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("state.json must be an object")
    usage_from_state(doc)  # raises if usage fields are present but corrupt
    if STATE_KEY in doc and doc[STATE_KEY] not in (True, False):
        raise ValueError("state.json connectivity_done is corrupt")
    return doc


def save_state(path, doc):
    """Write state.json via a temp file and rename so a crash cannot leave a half-write."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".state.", suffix=".tmp", dir=os.path.dirname(path) or ".")
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


def _state_lock(path):
    """Exclusive lock on path.lock, held for the reservation/write.

    The lock file is opened with O_NOFOLLOW so a symlink cannot redirect
    the open (or file creation) outside the state directory.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock_path = path + ".lock"
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError("state lock path must not be a symlink") from e
        raise

    class _Lock:
        def __enter__(self):
            fcntl.flock(fd, fcntl.LOCK_EX)
            return self

        def __exit__(self, exc_type, exc, tb):
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    return _Lock()


# One in-process lock for cap reservations. The file lock covers cross-process
# access; this covers concurrent threads (including ones that passed distinct
# used dicts). A single lock also avoids a growing map keyed by id(used).
_CAP_LOCK = threading.Lock()


class _null_lock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def package_version():
    """Return this package's running version, or None if it is missing."""
    import kt as pkg
    return getattr(pkg, "__version__", None)


def run(trigger, *, already_done=False, offer_answer="none", send_answer="none",
        routing_choice="just_this_bot", chief_name=None, ticked=None, delivery="paste",
        running_version=None, used=None, limits=None, poster=None, state_path=None,
        post_ok=True):
    """One first-run (or later user-requested) setup attempt.

    `poster` must be a DryRunPoster (or any object with post/read_thread). Tests
    must not pass a live posting client. If poster is omitted, nothing is posted
    and a failed post is treated as the read-only fallback when the flow would
    have posted.

    `running_version` must be an ASCII x.y.z string. If omitted, the package
    version (`kt.__version__`) is used. A missing or invalid version fails
    closed before any post. The already_done flag can only add to a persisted
    connectivity_done value, never clear it. Caps fail closed: missing or
    corrupt limits, or a missing state path when usage cannot be reserved
    safely, means no post (a private read-only check may still run). State is
    loaded and validated before any post. Usage is reserved atomically (lock
    file and temp+rename, plus one in-process cap lock) at the yes, before the
    post, so two concurrent yeses get at most one post.
    """
    # Refuse a bad version before any post or state write. No silent default.
    if running_version is None:
        running_version = package_version()
    if not CONN.SEMVER.match(running_version if isinstance(running_version, str) else ""):
        raise ValueError("running version is not x.y.z")

    # Load and validate state BEFORE any post. A corrupt file raises.
    if state_path:
        load_state(state_path)

    caller_used = used if used is not None else _empty_used()
    if not _valid_usage(caller_used):
        raise ValueError("usage counts are corrupt")
    # Keep a reference so a shared used dict is updated in place under the cap lock.
    if used is None:
        used = caller_used

    shown = {"plain_statement": PLAIN_STATEMENT, "routing_ask": R.ASK}
    routing_doc, actions, just_this = R.apply_choice(
        routing_choice, chief_name=chief_name, ticked=ticked, delivery=delivery)
    shown["routing"] = {"doc": routing_doc, "actions": actions, "just_this_bot": just_this}

    # Limits missing or corrupt: no post (private check only).
    caps_ok = valid_limits(limits)
    reserved = False
    effective_done = bool(already_done)
    used_now = _copy_used(caller_used)

    file_lock = _state_lock(state_path) if state_path else _null_lock()
    with file_lock, _CAP_LOCK:
        state = load_state(state_path) if state_path else {}
        # Flag can only add, never clear a persisted connectivity_done.
        effective_done = bool(already_done) or bool(state.get(STATE_KEY))
        persisted = usage_from_state(state)
        used_now = merge_used(used, persisted)
        used["day"] = used_now["day"]
        used["week"] = used_now["week"]
        used["items"] = dict(used_now["items"])

        would_count = (
            trigger in ("first_run", "user_request")
            and not (trigger == "first_run" and effective_done)
            and offer_answer == "yes" and send_answer == "yes"
            and caps_ok
        )
        if would_count:
            reserved = reserve_report(used, limits)
            used_now = _copy_used(used)
            if reserved and state_path:
                state[STATE_KEY] = True if trigger == "first_run" else state.get(STATE_KEY, False)
                state["day"] = used_now["day"]
                state["week"] = used_now["week"]
                state["items"] = dict(used_now["items"])
                save_state(state_path, state)

        left = 0
        if caps_ok:
            # If we reserved, a slot was taken; flow still sees a remaining slot of 1
            # for this yes. If we did not reserve, either we are over cap or this is
            # not a counting yes: pass the current remaining count.
            left = 1 if reserved else reports_left(used_now, limits)
        # Persist connectivity_done for a first-run offer (including declines) before return.
        will_offer = trigger in ("first_run", "user_request") and not (
            trigger == "first_run" and effective_done)
        if state_path and will_offer and trigger == "first_run":
            state = load_state(state_path) if os.path.exists(state_path) else state
            state[STATE_KEY] = True
            # Keep decline-only state as done, without inventing usage if none exists.
            if "day" in state or persisted is not None or reserved:
                state["day"] = used_now["day"]
                state["week"] = used_now["week"]
                state["items"] = dict(used_now["items"])
            save_state(state_path, state)

    flow = CONN.flow(trigger, effective_done, offer_answer, send_answer,
                     post_ok=post_ok, reports_left=left)
    # If we reserved a cap slot, this yes counts even if the post later fails.
    if reserved:
        flow = dict(flow)
        flow["counts_as_report"] = True
        if not post_ok:
            flow["posted"] = False
            flow["read_only_check"] = True

    posted = None
    read_only = None
    live_link = None
    not_sent = None
    if flow["draft_shown"]:
        draft = CONN.draft(running_version)
        shown["draft"] = draft
        shown["approval_notice"] = CONN.APPROVAL_NOTICE
        shown["asked_ok_to_send"] = True
        if not CONN.draft_allowed(draft, running_version):
            flow = dict(flow)
            flow["posted"] = False
            flow["read_only_check"] = True
            # A reserved slot already counted; keep counts_as_report.
            shown["pre_send"] = "refused"
        elif flow["posted"]:
            if poster is None:
                not_sent = "Not sent: no poster configured"
                flow = dict(flow)
                flow["posted"] = False
                flow["read_only_check"] = True
            else:
                result = poster.post(draft)
                if result.get("ok"):
                    posted = draft
                    live_link = result.get("url")
                else:
                    not_sent = "Not sent: %s" % (result.get("reason") or "post failed")
                    flow = dict(flow)
                    flow["posted"] = False
                    flow["read_only_check"] = True
        elif send_answer == "yes" and not post_ok:
            not_sent = "Not sent: post failed"
    if flow["read_only_check"]:
        if poster is None:
            read_only = {"ok": False, "message": "read-only check skipped (no poster)"}
        else:
            read_only = poster.read_thread()

    return {
        "shown": shown,
        "routing": routing_doc,
        "actions": actions,
        "flow": flow,
        "posted": posted,
        "live_link": live_link,
        "not_sent": not_sent,
        "read_only": read_only,
        "counts_as_report": flow["counts_as_report"],
        "counts_as_threat_report": False,
        "used": _copy_used(used_now),
    }
