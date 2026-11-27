"""First-run routing (SPEC.md §4C): the fixed line, the three paths, and the weekly check.

The bot itself follows skills/kings-taster-routing.md. This module is the reference the
tests check against so the skill and the rules cannot drift apart. It never edits another
bot and never saves a bot's instructions.
"""
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
SKILL_PATH = os.path.join(ROOT, "skills", "kings-taster-routing.md")
WORD_CAP = 250
LINE_WORD_CAP = 30
LINE = ("Before you or any bot downloads, installs or clicks anything new, "
        "ask King's Taster and wait for its verdict. Don't proceed on Block or Unknown.")
ASK = "Who routes your work?"
JUST_THIS_BOT = "Ask me before you download, install or click something new."
MISSING_NUDGE = "The King's Taster line is missing from %s. Paste it again?"
QUIET_NOTE = "%s hasn't asked me anything in 30 days."
CHOICES = ("chief_of_staff", "no_chief", "just_this_bot")
DELIVERIES = ("paste", "ask_to_add")
FILTER_TERMS = ("code", "repo", "package", "install", "download", "browsing", "link")
# Fields that must never appear in routing.json (instructions and other bot text).
FORBIDDEN_KEYS = ("instructions", "description", "message", "prompt", "system", "profile")


def skill_text():
    with open(SKILL_PATH, encoding="utf-8") as f:
        return f.read()


def split_skill(text=None):
    text = text if text is not None else skill_text()
    line_start, line_end = "<!-- line -->", "<!-- /line -->"
    a, b = text.index(line_start), text.index(line_end)
    body = text[:a]
    line = text[a + len(line_start):b].strip()
    fixed = ""
    if "<!-- fixed -->" in text:
        fa, fb = text.index("<!-- fixed -->"), text.index("<!-- /fixed -->")
        fixed = text[fa + len("<!-- fixed -->"):fb].strip()
    return body, line, fixed


def word_count(body):
    return len(body.split())


def bot_is_candidate(description):
    """True if a bot description mentions the §4C filter terms. The description is never saved."""
    if not isinstance(description, str) or not description.strip():
        return False
    text = description.lower()
    return any(term in text for term in FILTER_TERMS)


def filter_candidates(bots):
    """bots is a list of {name, description}. Returns names only, in the given order."""
    out = []
    seen = set()
    for bot in bots or []:
        name = bot.get("name") if isinstance(bot, dict) else None
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        if name in seen:
            continue
        if bot_is_candidate(bot.get("description") or ""):
            out.append(name)
            seen.add(name)
    return out


def apply_choice(choice, *, chief_name=None, ticked=None, delivery="paste"):
    """Build a routing.json document and the delivery actions. Never returns an edit action."""
    if choice not in CHOICES:
        raise ValueError("unknown routing choice")
    if delivery not in DELIVERIES:
        raise ValueError("unknown delivery")
    if choice == "just_this_bot":
        doc = {"choice": choice, "covered": []}
        return doc, [], JUST_THIS_BOT
    if choice == "chief_of_staff":
        if not isinstance(chief_name, str) or not chief_name.strip():
            raise ValueError("chief-of-staff bot name is required")
        names = [chief_name.strip()]
    else:
        names = []
        for n in ticked or []:
            if not isinstance(n, str) or not n.strip():
                raise ValueError("covered bot names must be non-empty strings")
            n = n.strip()
            if n not in names:
                names.append(n)
        if not names:
            raise ValueError("no chief of staff requires at least one covered bot")
    covered = [{"name": n, "message_approved": delivery == "ask_to_add"} for n in names]
    actions = [{"bot": n, "method": delivery} for n in names]
    doc = {"choice": choice, "covered": covered}
    return doc, actions, None


def validate_routing(doc):
    """Return a list of problems; an empty list means the document is safe to save."""
    errors = []
    if not isinstance(doc, dict):
        return ["routing.json must be an object"]
    extra = [k for k in doc if k not in ("choice", "covered")]
    if extra:
        errors.append("unexpected fields: %s" % ", ".join(extra))
    for key in doc:
        if key.lower() in FORBIDDEN_KEYS:
            errors.append("forbidden field %s" % key)
    if doc.get("choice") not in CHOICES:
        errors.append("choice must be one of %s" % ", ".join(CHOICES))
    covered = doc.get("covered")
    if not isinstance(covered, list):
        errors.append("covered must be a list")
        return errors
    if doc.get("choice") == "just_this_bot" and covered:
        errors.append("just_this_bot must not list covered bots")
    seen = set()
    for i, item in enumerate(covered):
        if not isinstance(item, dict):
            errors.append("covered[%d] must be an object" % i)
            continue
        extra = [k for k in item if k not in ("name", "message_approved")]
        if extra:
            errors.append("covered[%d] unexpected fields: %s" % (i, ", ".join(extra)))
        for key in item:
            if key.lower() in FORBIDDEN_KEYS:
                errors.append("covered[%d] forbidden field %s" % (i, key))
        name = item.get("name")
        if not isinstance(name, str) or not name.strip() or "\n" in name:
            errors.append("covered[%d] needs a single-line name" % i)
        elif name in seen:
            errors.append("duplicate name %s" % name)
        else:
            seen.add(name)
        if "message_approved" in item and not isinstance(item["message_approved"], bool):
            errors.append("covered[%d] message_approved must be true or false" % i)
    return errors


def save_routing(path, doc):
    errors = validate_routing(doc)
    if errors:
        raise ValueError("; ".join(errors))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")


def load_routing(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    errors = validate_routing(doc)
    if errors:
        raise ValueError("; ".join(errors))
    return doc


def weekly_method(*, can_read, message_approved, can_message):
    """First method that works: read, then ask the bot, then ask the user."""
    if can_read:
        return "read"
    if message_approved and can_message:
        return "ask_bot"
    return "ask_user"


def weekly_check(name, *, line_present, can_read=False, message_approved=False,
                 can_message=False, days_since_ask=None, already_nudged_this_week=False):
    """What the weekly routing check does for one covered bot.

    Returns a dict: method, silent, nudge (or None), note (or None). It never
    re-adds the line and never edits the other bot.
    """
    method = weekly_method(can_read=can_read, message_approved=message_approved,
                           can_message=can_message)
    out = {"method": method, "silent": True, "nudge": None, "note": None, "readd": False}
    if not line_present:
        out["silent"] = False
        if not already_nudged_this_week:
            out["nudge"] = nudge_text(name)
    if days_since_ask is not None and days_since_ask >= 30:
        # The 30-day note is added to that week's message (the nudge, or a
        # standalone note if the line is still in place).
        out["note"] = QUIET_NOTE % name
        if line_present:
            out["silent"] = False
    return out


def nudge_text(name, include_line=True):
    text = MISSING_NUDGE % name
    if include_line:
        text = text + "\n" + LINE
    return text
