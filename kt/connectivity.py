"""First-run connectivity reply (SPEC.md §4D and §10.1): the fixed rules, as reference code.

The bot itself runs from the template's text; this module is the reference the conformance data in
conformance/cases.json ("connectivity") is checked against, so the two can't drift apart.
"""
import re

TEMPLATE = "KT %s is live and checking"
PATTERN = re.compile(r"^KT \d{1,3}\.\d{1,3}\.\d{1,3} is live and checking\Z", re.ASCII)
SEMVER = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\Z", re.ASCII)
OFFER = "Want to post a one-time reply to the King's Taster X thread to confirm your setup works?"
APPROVAL_NOTICE = "This posts publicly from your X account, so anyone can see that this account uses King's Taster."
READ_ONLY_OK = "X connection works (read-only check)"
STATE_KEY = "connectivity_done"
TRIGGERS = ("first_run", "user_request", "routine", "health_check", "bot_message")
ANSWERS = ("yes", "no", "not_now", "none")


def draft(running_version):
    if not SEMVER.match(running_version):
        raise ValueError("running version is not x.y.z")
    return TEMPLATE % running_version


def draft_allowed(text, running_version):
    """The pre-send rule for this post: exactly the template, with the running version. No override."""
    return bool(SEMVER.match(running_version)) and isinstance(text, str) and bool(PATTERN.match(text)) \
        and text == TEMPLATE % running_version


def flow(trigger, already_done, offer_answer, send_answer="none", post_ok=True, reports_left=1):
    """What happens for one connectivity attempt. Returns a dict of fixed outcomes:
    offered, draft_shown, asked_ok_to_send, posted, read_only_check, marks_done, counts_as_report."""
    out = {"offered": False, "draft_shown": False, "asked_ok_to_send": False, "posted": False,
           "read_only_check": False, "marks_done": False, "counts_as_report": False}
    if trigger not in ("first_run", "user_request"):
        return out  # routines, health checks and other bots can never start it
    if trigger == "first_run" and already_done:
        return out  # offered once per install, never again by itself
    out["offered"] = True
    out["marks_done"] = True
    if offer_answer != "yes":
        out["read_only_check"] = True  # a decline (or "not now", or no answer) posts nothing
        return out
    if reports_left < 1:
        return out  # over the report cap: nothing is drafted
    out["draft_shown"] = True
    out["asked_ok_to_send"] = True
    if send_answer != "yes":
        out["read_only_check"] = True
        return out
    out["counts_as_report"] = True
    if post_ok:
        out["posted"] = True
    else:
        out["read_only_check"] = True  # "Not sent", with the reason, then the read-only check
    return out
