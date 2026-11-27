"""Load the public licensing table (sources/licensing.json) and list the feeds it allows."""
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
TABLE = os.path.join(ROOT, "sources", "licensing.json")
REQUIRED = ("id", "source", "use", "in_list_file", "license", "commercial_use",
            "redistribution", "attribution", "key_needed", "rate_limit", "terms_url")
USES = ("list_file", "live_lookup", "test_data", "documented_only")
# Fetcher ids used in kt/sources.py and the pipeline, mapped to table rows.
LIST_FETCHER_IDS = {
    "cisa-kev": "cisa-kev",
    "osv-npm": "osv-mal-npm",
    "osv-pypi": "osv-mal-pypi",
}


def load_table(path=None):
    with open(path or TABLE, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or not isinstance(doc.get("sources"), list) or not doc["sources"]:
        raise ValueError("licensing table is missing or empty")
    return doc


def problems(doc):
    """Return a list of problems in the table. An empty list means the table is well-formed."""
    errors = []
    if doc.get("checked_on") and not isinstance(doc["checked_on"], str):
        errors.append("checked_on must be a string")
    seen = set()
    for i, row in enumerate(doc.get("sources") or []):
        if not isinstance(row, dict):
            errors.append("row %d is not an object" % i); continue
        missing = [k for k in REQUIRED if k not in row]
        if missing:
            errors.append("row %s is missing %s" % (row.get("id", i), ", ".join(missing)))
            continue
        extra = [k for k in row if k not in REQUIRED + ("feed_url",)]
        if extra:
            errors.append("row %s has unexpected fields: %s" % (row["id"], ", ".join(extra)))
        if row["id"] in seen:
            errors.append("duplicate id %s" % row["id"])
        seen.add(row["id"])
        if row["use"] not in USES:
            errors.append("row %s has an unknown use" % row["id"])
        if not isinstance(row["in_list_file"], bool):
            errors.append("row %s in_list_file must be true or false" % row["id"])
        if row["use"] == "list_file" and not row["in_list_file"]:
            errors.append("row %s is a list-file source but in_list_file is false" % row["id"])
        if row["in_list_file"] and row["use"] not in ("list_file",):
            errors.append("row %s is in the list file but use is %s" % (row["id"], row["use"]))
        if row["use"] == "list_file" and row["id"] != "ghsa-malware" and not row.get("feed_url"):
            errors.append("list-file row %s needs a feed_url" % row["id"])
        for k in REQUIRED:
            if k in ("in_list_file",):
                continue
            if not isinstance(row[k], str) or not row[k].strip():
                errors.append("row %s field %s must be a non-empty string" % (row["id"], k))
    for fid, rid in LIST_FETCHER_IDS.items():
        if rid not in seen:
            errors.append("pipeline fetcher %s has no licensing row %s" % (fid, rid))
    return errors


def list_file_rows(doc=None):
    doc = doc or load_table()
    return [s for s in doc["sources"] if s["in_list_file"] and s["use"] == "list_file"]


def feed_urls(doc=None):
    return [s["feed_url"] for s in list_file_rows(doc) if s.get("feed_url")]
