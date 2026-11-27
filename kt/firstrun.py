"""First-run setup (SPEC.md §4C, §4D, §10.1): plain statement, routing, then connectivity.

The bot follows skills/kings-taster-first-run.md. This module sequences those steps
for tests. It never contacts X: a poster, if provided, must be a dry-run double
passed in by the caller.
"""
import json
import os

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


def load_state(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise ValueError("state.json must be an object")
    return doc


def save_state(path, doc):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def run(trigger, *, already_done=False, offer_answer="none", send_answer="none",
        routing_choice="just_this_bot", chief_name=None, ticked=None, delivery="paste",
        running_version="1.0.0", used=None, limits=None, poster=None, state_path=None,
        post_ok=True):
    """One first-run (or later user-requested) setup attempt.

    `poster` must be a DryRunPoster (or any object with post/read_thread). Tests
    must not pass a live posting client. If poster is omitted, nothing is posted
    and a failed post is treated as the read-only fallback when the flow would
    have posted.
    """
    used = used or {"day": 0, "week": 0, "items": {}}
    left = 1
    if limits is not None:
        left = reports_left(used, limits)
    shown = {"plain_statement": PLAIN_STATEMENT, "routing_ask": R.ASK}
    routing_doc, actions, just_this = R.apply_choice(
        routing_choice, chief_name=chief_name, ticked=ticked, delivery=delivery)
    shown["routing"] = {"doc": routing_doc, "actions": actions, "just_this_bot": just_this}
    flow = CONN.flow(trigger, already_done, offer_answer, send_answer,
                     post_ok=post_ok, reports_left=left)
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
            flow["counts_as_report"] = False
            shown["pre_send"] = "refused"
        elif flow["posted"]:
            if poster is None:
                # No poster: do not post. Treat as a failed send, then read-only.
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
    if flow["marks_done"] and state_path:
        state = load_state(state_path)
        state[STATE_KEY] = True
        save_state(state_path, state)
    used_after = dict(used)
    used_after["items"] = dict(used.get("items") or {})
    if flow["counts_as_report"]:
        used_after["day"] = used.get("day", 0) + 1
        used_after["week"] = used.get("week", 0) + 1
        used_after["items"][CONNECTIVITY_ITEM] = used_after["items"].get(CONNECTIVITY_ITEM, 0) + 1
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
        "used": used_after,
    }
