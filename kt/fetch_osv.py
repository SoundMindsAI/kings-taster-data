"""Fetch OSV per-ecosystem exports and keep only OpenSSF malicious-packages (MAL-) entries.

Reads https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip (OSV's official
GCS export, fetched over HTTPS; nothing is cloned). Only allowlisted, validated fields are
kept: id, package name, versions/ranges, aliases (ID pattern only), published, modified,
and the origin source names. summary, details, references, credits are never copied.
License: OpenSSF Malicious Packages data is Apache-2.0; entries whose origins include
GitHub's malware advisories also carry CC-BY-4.0 attribution.
"""
import argparse
import json
import os
import sys
import tempfile
import zipfile

from . import sources
from .common import (ALIAS_ID, MAL_ID, ORIGIN_SOURCE, VERSION, FetchError, fetch, fmt_time, match_key,
                     parse_time, read_json, sha256_file, utc_now, valid_package_name, write_json, defang)

LIMITS = os.path.join(os.path.dirname(__file__), "..", "config", "limits.json")
CANARIES = os.path.join(os.path.dirname(__file__), "..", "config", "canaries.json")


def _affected(aff, limits):
    """Return (affected_versions dict, problem or None)."""
    versions = aff.get("versions") or []
    if not isinstance(versions, list):
        return None, "bad_versions"
    good = [v for v in versions if isinstance(v, str) and VERSION.match(v)]
    if len(good) != len(versions):
        return None, "bad_version_string"
    ranges_out = []
    all_versions = False
    for r in aff.get("ranges") or []:
        if not isinstance(r, dict) or r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            return None, "unsupported_range"
        ev_out = []
        for ev in r.get("events") or []:
            if not isinstance(ev, dict) or len(ev) != 1:
                return None, "bad_event"
            (k, v), = ev.items()
            if k not in ("introduced", "fixed", "last_affected") or not isinstance(v, str) or not (v == "0" or VERSION.match(v)):
                return None, "bad_event"
            ev_out.append({k: v})
        if ev_out == [{"introduced": "0"}]:
            all_versions = True
        ranges_out.append({"type": r["type"], "events": ev_out})
    if not good and not ranges_out:
        return None, "no_versions"
    truncated = len(good) > limits["max_versions_per_entry"]
    if truncated:
        # Too many to list: treat as all versions, which is the conservative reading for malware.
        all_versions, good = True, []
    return {"all_versions": all_versions, "versions": sorted(set(good)), "ranges": ranges_out}, None


def parse_record(rec, ecosystem, limits):
    """Return (entries, withdrawn_id or None, rejects)."""
    rid = rec.get("id") if isinstance(rec, dict) else None
    if not isinstance(rid, str) or not MAL_ID.match(rid):
        return [], None, [{"id": None, "why": "bad_id"}]
    if rec.get("withdrawn"):
        return [], rid, []
    try:
        published = fmt_time(parse_time(rec.get("published")))
        modified = fmt_time(parse_time(rec.get("modified")))
    except ValueError:
        return [], None, [{"id": rid, "why": "bad_time"}]
    aliases = sorted({a for a in rec.get("aliases") or [] if isinstance(a, str) and ALIAS_ID.match(a)})
    origins = []
    ds = rec.get("database_specific") or {}
    for o in (ds.get("malicious-packages-origins") or []) if isinstance(ds, dict) else []:
        s = o.get("source") if isinstance(o, dict) else None
        if isinstance(s, str) and ORIGIN_SOURCE.match(s):
            origins.append(s)
    origins = sorted(set(origins)) or ["unspecified"]
    license_ = sources.OSV_MAL_LICENSE
    attribution = sources.OSV_MAL_ATTRIBUTION
    if sources.GHSA_ORIGIN in origins:
        license_ += sources.GHSA_LICENSE_SUFFIX
        attribution += sources.GHSA_ATTRIBUTION_SUFFIX
    entries, rejects = [], []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") if isinstance(aff, dict) else None
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != ecosystem:
            continue
        name = pkg.get("name")
        if not valid_package_name(ecosystem, name):
            rejects.append({"id": rid, "why": "bad_package_name"})
            continue
        av, problem = _affected(aff, limits)
        if problem:
            rejects.append({"id": rid, "why": problem})
            continue
        mk = match_key("package", name, ecosystem)
        entries.append({
            "id": "osv:%s:%s" % (rid, mk),
            "type": "package",
            "value": defang("package", name, ecosystem),
            "match_key": mk,
            "kind": "malicious",
            "ecosystem": ecosystem,
            "affected_versions": av,
            "fixed_version": None,
            "vendor": None,
            "product": None,
            "known_ransomware_use": None,
            "aliases": aliases,
            "origins": origins,
            "confidence": "high" if len(origins) >= 2 else "medium",
            "upstream_origin": "ossf-malicious-packages:" + "+".join(origins),
            "source_url": sources.OSV_SOURCE_URL + rid,
            "license": license_,
            "attribution": attribution,
            "published": published,
            "modified": modified,
        })
    return entries, None, rejects


def parse_zip(zip_path, ecosystem, limits):
    entries, withdrawn, rejects, seen_ids = [], [], [], set()
    total = 0
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            base = os.path.basename(info.filename)
            if info.is_dir() or not base.startswith("MAL-") or not base.endswith(".json"):
                continue
            if "/" in info.filename.strip("/") or ".." in info.filename:
                rejects.append({"id": None, "why": "nested_member"})
                continue
            if info.file_size > limits["max_zip_member_bytes"]:
                rejects.append({"id": base[:-5][:40], "why": "member_too_large"})
                continue
            total += info.file_size
            if total > limits["max_zip_total_uncompressed_bytes"]:
                raise ValueError("zip expands past the uncompressed cap")
            with z.open(info) as f:
                data = f.read(limits["max_zip_member_bytes"] + 1)
            try:
                rec = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                rejects.append({"id": base[:-5][:40], "why": "bad_json"})
                continue
            if isinstance(rec, dict) and rec.get("id") != base[:-5]:
                rejects.append({"id": None, "why": "id_filename_mismatch"})
                continue
            e, w, r = parse_record(rec, ecosystem, limits)
            if isinstance(rec, dict) and isinstance(rec.get("id"), str):
                seen_ids.add(rec["id"])
            entries += e
            rejects += r
            if w:
                withdrawn.append(w)
    return entries, sorted(withdrawn), rejects, seen_ids


def run(ecosystem, out_path, input_path=None, limits=None, canaries=None):
    limits = limits or read_json(LIMITS)
    canaries = canaries or read_json(CANARIES)
    meta = sources.OSV[ecosystem]
    sid = meta["id"]
    with tempfile.TemporaryDirectory() as td:
        if input_path:
            zpath = input_path
            evidence = {"url": meta["url"], "http_status": 200, "response_sha256": sha256_file(zpath),
                        "bytes": os.path.getsize(zpath), "last_modified": None,
                        "fetched_at": fmt_time(utc_now()), "recorded_fixture": True}
        else:
            zpath = os.path.join(td, "all.zip")
            try:
                evidence = fetch(meta["url"], zpath, limits["max_download_bytes"][sid])
            except FetchError as e:
                doc = {"source": sid, "status": "failed", "evidence": e.evidence, "failure": str(e),
                       "source_date": None, "entries": [], "withdrawn": [], "rejected": []}
                write_json(out_path, doc)
                return doc
        try:
            entries, withdrawn, rejects, seen = parse_zip(zpath, ecosystem, limits)
            failure = None
            if len(entries) < limits["min_entries"][sid]:
                failure = "only %d entries (minimum %d)" % (len(entries), limits["min_entries"][sid])
            elif [c for c in canaries["upstream"][sid] if c not in seen]:
                failure = "upstream canary missing"
            ids = [e["id"] for e in entries]
            if len(ids) != len(set(ids)):
                failure = "duplicate entry ids"
        except (zipfile.BadZipFile, ValueError, OSError) as e:
            entries, withdrawn, rejects, failure = [], [], [], "unreadable export: %s" % type(e).__name__
    source_date = max((e["modified"] for e in entries), default=None)
    doc = {"source": sid, "status": "failed" if failure else "ok", "evidence": evidence,
           "source_date": source_date, "entries": sorted(entries, key=lambda e: e["id"]) if not failure else [],
           "withdrawn": withdrawn, "rejected": rejects}
    if failure:
        doc["failure"] = failure
    write_json(out_path, doc)
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ecosystem", required=True, choices=sorted(sources.OSV))
    ap.add_argument("--out", required=True)
    ap.add_argument("--input", help="parse a saved all.zip instead of fetching")
    a = ap.parse_args(argv)
    doc = run(a.ecosystem, a.out, a.input)
    print("%s: %s, %d entries, %d withdrawn, %d rejected, http %s" % (
        doc["source"], doc["status"], len(doc["entries"]), len(doc["withdrawn"]), len(doc["rejected"]),
        doc["evidence"].get("http_status")))
    return 0 if doc["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
