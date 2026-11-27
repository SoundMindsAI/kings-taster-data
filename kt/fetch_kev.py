"""Fetch and parse the CISA KEV catalog into list-file entries.

Only allowlisted fields are kept: cveID, vendorProject, product, dateAdded,
knownRansomwareCampaignUse. Free-text fields (vulnerabilityName,
shortDescription, requiredAction, notes) are never copied.
CISA terms: CC0 1.0; no CISA logo or DHS seal; no claim of endorsement.
"""
import argparse
import json
import os
import sys
import tempfile

from . import sources
from .common import CVE_ID, FetchError, clean_label, fetch, fmt_time, parse_time, utc_now, write_json, read_json, match_key

LIMITS = os.path.join(os.path.dirname(__file__), "..", "config", "limits.json")
CANARIES = os.path.join(os.path.dirname(__file__), "..", "config", "canaries.json")


def parse(raw_bytes, evidence, limits, canaries):
    """Return the normalized source document. Raises ValueError if the feed can't be trusted."""
    doc = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise ValueError("KEV: unexpected top-level shape")
    released = doc.get("dateReleased")
    source_date = fmt_time(parse_time(released)) if isinstance(released, str) else None
    entries, rejected = [], []
    for v in doc["vulnerabilities"]:
        cve = v.get("cveID") if isinstance(v, dict) else None
        if not isinstance(cve, str) or not CVE_ID.match(cve):
            rejected.append({"id": None, "why": "bad_cve_id"})
            continue
        try:
            added = parse_time(v.get("dateAdded"))
        except ValueError:
            rejected.append({"id": cve, "why": "bad_date"})
            continue
        ransomware = {"Known": True, "Unknown": None}.get(v.get("knownRansomwareCampaignUse"), None)
        entries.append({
            "id": "kev:" + cve,
            "type": "cve",
            "value": cve,
            "match_key": match_key("cve", cve),
            "kind": "vulnerable",
            "ecosystem": None,
            "affected_versions": None,
            "fixed_version": None,
            "vendor": clean_label(v.get("vendorProject")),
            "product": clean_label(v.get("product")),
            "known_ransomware_use": ransomware,
            "aliases": [],
            "origins": ["cisa-kev"],
            "confidence": "high",
            "upstream_origin": sources.KEV["upstream_origin"],
            "source_url": sources.KEV["source_url_base"] + "?search_api_fulltext=" + cve,
            "license": sources.KEV["license"],
            "attribution": sources.KEV["attribution"],
            "published": fmt_time(added),
        })
    ids = {e["value"] for e in entries}
    if len({e["id"] for e in entries}) != len(entries):
        # KEV ids are unique upstream; duplicates mean the feed is malformed.
        raise ValueError("KEV: duplicate cveID")
    minimum = limits["min_entries"]["cisa-kev"]
    if len(entries) < minimum:
        raise ValueError("KEV: only %d entries (minimum %d)" % (len(entries), minimum))
    missing = [c for c in canaries["upstream"]["cisa-kev"] if c not in ids]
    if missing:
        raise ValueError("KEV: upstream canary missing")
    return {
        "source": sources.KEV["id"],
        "status": "ok",
        "evidence": evidence,
        "source_date": source_date,
        "catalog_version": doc.get("catalogVersion") if isinstance(doc.get("catalogVersion"), str) and len(doc.get("catalogVersion")) <= 20 else None,
        "entries": sorted(entries, key=lambda e: e["id"]),
        "rejected": rejected,
    }


def failed_doc(evidence, why):
    return {"source": sources.KEV["id"], "status": "failed", "evidence": evidence, "failure": why,
            "source_date": None, "entries": [], "rejected": []}


def run(out_path, input_path=None, limits=None, canaries=None):
    limits = limits or read_json(LIMITS)
    canaries = canaries or read_json(CANARIES)
    with tempfile.TemporaryDirectory() as td:
        if input_path:  # recorded fixture (tests / offline)
            with open(input_path, "rb") as f:
                raw = f.read()
            from .common import sha256_bytes
            evidence = {"url": sources.KEV["url"], "http_status": 200, "response_sha256": sha256_bytes(raw),
                        "bytes": len(raw), "last_modified": None, "fetched_at": fmt_time(utc_now()),
                        "recorded_fixture": True}
        else:
            dest = os.path.join(td, "kev.json")
            try:
                evidence = fetch(sources.KEV["url"], dest, limits["max_download_bytes"]["cisa-kev"])
            except FetchError as e:
                doc = failed_doc(e.evidence, str(e))
                write_json(out_path, doc)
                return doc
            with open(dest, "rb") as f:
                raw = f.read()
        try:
            doc = parse(raw, evidence, limits, canaries)
        except (ValueError, UnicodeDecodeError) as e:
            doc = failed_doc(evidence, str(e)[:200])
    write_json(out_path, doc)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--input", help="parse a saved response instead of fetching")
    a = ap.parse_args(argv)
    doc = run(a.out, a.input)
    print("cisa-kev: %s, %d entries, http %s" % (doc["status"], len(doc["entries"]), doc["evidence"].get("http_status")))
    return 0 if doc["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
