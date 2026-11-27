"""Validators for the release files: iocs.json, latest.json, stats.json, conformance.json.

Usage: python3 -m kt.validate <dir> [--previous <dir>]
Checks schemas, cross-field rules, latest.json hashes, and (with --previous) monotonicity.
Prints counts and rule names only, never entry values.
"""
import argparse
import json
import os
import re
import sys

from . import jsonschema_lite
from .common import canonical_json, match_key, normalize_package, parse_time, sha256_bytes, ECO_PREFIX
from .finding import RESULT_RANK, UNKNOWN_REASONS, CAUTION_REASONS, BLOCK_REASONS

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCHEMAS = {name: os.path.join(ROOT, "schema", name + ".schema.json") for name in ("iocs", "latest", "stats")}
ALL_REASONS = UNKNOWN_REASONS | CAUTION_REASONS | BLOCK_REASONS | {"checker_failed"}
REQUIRED_SOURCE_IDS = {"cisa-kev", "osv-npm", "osv-pypi", "kings-taster-canary"}
CANARY_TYPES = {"package:npm", "package:pypi", "domain", "url", "ip", "hash", "repo_owner", "cve"}
RELEASE_FILES = ("iocs.json", "conformance.json", "stats.json")


def _schema(name):
    with open(SCHEMAS[name], encoding="utf-8") as f:
        return json.load(f)


def _semver(s):
    return tuple(int(x) for x in s.split("."))


def validate_iocs(doc, fast_entries=False):
    schema = _schema("iocs")
    errors = []
    if fast_entries:
        shallow = dict(doc, entries=[])
        errors += jsonschema_lite.validate(shallow, schema)
        entry_schema = schema["$defs"]["entry"]
        for i, e in enumerate(doc.get("entries", [])):
            errs = jsonschema_lite.validate(e, entry_schema, schema, "$.entries[%d]" % i)
            if errs:
                errors += errs[:3]
                if len(errors) > 50:
                    return errors
    else:
        errors += jsonschema_lite.validate(doc, schema)
    if errors:
        return errors
    ids = [e["id"] for e in doc["entries"]]
    if len(ids) != len(set(ids)):
        errors.append("entries: duplicate id")
    revoked = {r["id"] for r in doc["revoked_entries"]}
    if len(revoked) != len(doc["revoked_entries"]):
        errors.append("revoked_entries: duplicate id")
    if revoked & set(ids):
        errors.append("entries: a revoked id is still listed")
    src_ids = [s["id"] for s in doc["sources"]]
    if set(src_ids) != REQUIRED_SOURCE_IDS or len(src_ids) != len(set(src_ids)):
        errors.append("sources: must list exactly %s" % sorted(REQUIRED_SOURCE_IDS))
    if doc["paused"] != (doc["paused_reason"] is not None):
        errors.append("paused_reason: set if and only if paused")
    canaries = set()
    for e in doc["entries"]:
        t = e["type"]
        if t == "package":
            if e["ecosystem"] not in ECO_PREFIX:
                errors.append("entry %s: package without npm/PyPI ecosystem" % e["id"][:60]); continue
            name = e["value"].split(":", 1)[1] if ":" in e["value"] else ""
            if e["value"] != "%s:%s" % (ECO_PREFIX[e["ecosystem"]], name) or e["match_key"] != match_key("package", name, e["ecosystem"]):
                errors.append("entry %s: value/match_key mismatch" % e["id"][:60])
            if e["affected_versions"] is None:
                errors.append("entry %s: package needs affected_versions" % e["id"][:60])
        elif e["ecosystem"] is not None:
            errors.append("entry %s: ecosystem only for packages" % e["id"][:60])
        if t == "cve" and e["match_key"] != match_key("cve", e["value"]):
            errors.append("entry %s: cve match_key mismatch" % e["id"][:60])
        if t in ("domain", "ip") and "." in e["value"].replace("[.]", ""):
            errors.append("entry %s: value not defanged" % e["id"][:60])
        if t == "url" and (not e["value"].startswith(("hxxp://", "hxxps://")) or re.search(r"https?://", e["value"])):
            errors.append("entry %s: url not defanged" % e["id"][:60])
        if e["review_state"] != "auto" and not (e["kind"] == "malicious" and t == "package"):
            errors.append("entry %s: review_state only applies to malicious packages" % e["id"][:60])
        if e["review_state"] == "approved" and len(e["origins"]) < 2:
            errors.append("entry %s: approved block needs two upstream origins" % e["id"][:60])
        if e["kind"] == "vulnerable" and e["type"] == "package" and e["review_state"] != "auto":
            errors.append("entry %s: vulnerable entries are never held or blocked" % e["id"][:60])
        if e["canary"]:
            canaries.add(t + (":" + ECO_PREFIX[e["ecosystem"]] if t == "package" else ""))
            if e["kind"] != "malicious":
                errors.append("entry %s: canaries are malicious entries" % e["id"][:60])
        try:
            if parse_time(e["first_seen"]) > parse_time(doc["generated_at"]):
                errors.append("entry %s: first_seen after generated_at" % e["id"][:60])
        except ValueError:
            errors.append("entry %s: bad time" % e["id"][:60])
    if canaries != CANARY_TYPES:
        errors.append("entries: canary set incomplete (%s missing)" % sorted(CANARY_TYPES - canaries))
    by_src = {}
    for e in doc["entries"]:
        k = "kings-taster-canary" if e["canary"] else ("cisa-kev" if e["id"].startswith("kev:") else
                                                        "osv-npm" if e["ecosystem"] == "npm" else "osv-pypi")
        by_src[k] = by_src.get(k, 0) + 1
    for s in doc["sources"]:
        if s["entry_count"] != by_src.get(s["id"], 0):
            errors.append("sources: entry_count mismatch for %s" % s["id"])
        if s["status"] == "ok" and (s["http_status"] != 200 or s["response_sha256"] is None) and s["id"] != "kings-taster-canary":
            errors.append("sources: %s ok without evidence" % s["id"])
    return errors


def validate_stats(doc):
    return jsonschema_lite.validate(doc, _schema("stats"))


def validate_conformance(doc):
    errors = []
    if doc.get("file_type") != "conformance" or doc.get("schema_version") != 1:
        errors.append("conformance: wrong file_type/schema_version")
    allowed_top = {"file_type", "schema_version", "generated_at", "tag", "comment", "global_expectations", "cases",
                   "canonicalization_vectors"}
    if set(doc) - allowed_top:
        errors.append("conformance: unexpected top-level fields")
    cases = doc.get("cases") or []
    if len(cases) < 30:
        errors.append("conformance: too few cases")
    seen = set()
    cats = set()
    for c in cases:
        cid = c.get("id")
        if not isinstance(cid, str) or not re.fullmatch(r"[a-z0-9-]{3,60}", cid) or cid in seen:
            errors.append("conformance: bad or duplicate case id"); continue
        seen.add(cid)
        cats.add(c.get("category"))
        exp = c.get("expected", {})
        if exp.get("result") not in RESULT_RANK:
            errors.append("case %s: bad result" % cid)
        for r in exp.get("reasons_include", []) + exp.get("reasons_exclude", []):
            if r not in ALL_REASONS:
                errors.append("case %s: unknown reason code" % cid)
        if set(exp.get("reasons_include", [])) & set(exp.get("reasons_exclude", [])):
            errors.append("case %s: reason both included and excluded" % cid)
        if c.get("category") == "token_budget":
            b = exp.get("budget") or {}
            if not (isinstance(b.get("max_words_loaded"), int) and b["max_words_loaded"] <= 2000
                    and b.get("max_verdict_lines") == 5 and "kings-taster-build" in b.get("forbidden_skills", [])):
                errors.append("case %s: token budget must cap words at 2000, lines at 5, and forbid kings-taster-build" % cid)
        if c.get("item", {}).get("item_type") not in ("package", "repo", "link"):
            errors.append("case %s: bad item_type" % cid)
    need = {"canary", "injection", "build_canary", "list_state", "required_source", "precedence", "checker",
            "token_budget"}
    if not need <= cats:
        errors.append("conformance: missing categories %s" % sorted(need - cats))
    vec = (doc.get("canonicalization_vectors") or {}).get("vectors") or []
    if len(vec) < 30:
        errors.append("conformance: canonicalization vectors missing")
    return errors


def validate_latest(latest, release_dir):
    errors = jsonschema_lite.validate(latest, _schema("latest"))
    if errors:
        return errors
    if latest["release_base_url"] != "https://github.com/SoundMindsAI/kings-taster-data/releases/download/%s/" % latest["tag"]:
        errors.append("latest: release_base_url doesn't match tag")
    for name in RELEASE_FILES:
        p = os.path.join(release_dir, name)
        if not os.path.exists(p):
            errors.append("latest: %s missing" % name); continue
        with open(p, "rb") as f:
            b = f.read()
        if sha256_bytes(b) != latest["assets"][name]["sha256"] or len(b) != latest["assets"][name]["bytes"]:
            errors.append("latest: %s hash/size mismatch" % name)
        try:
            d = json.loads(b.decode("utf-8"))
        except ValueError:
            errors.append("latest: %s not JSON" % name); continue
        if d.get("generated_at") != latest["generated_at"] or d.get("tag") != latest["tag"]:
            errors.append("latest: %s generated_at/tag differ from latest.json" % name)
        if b != canonical_json(d):
            errors.append("latest: %s is not in canonical form" % name)
    return errors


def check_monotonic(prev_iocs, new_iocs):
    """SPEC.md §7.4: reject rollback. prev/new are parsed iocs.json docs."""
    errors = []
    if parse_time(new_iocs["generated_at"]) <= parse_time(prev_iocs["generated_at"]):
        errors.append("monotonic: generated_at is not newer than the previous release")
    if new_iocs["schema_version"] < prev_iocs["schema_version"]:
        errors.append("monotonic: schema_version went down")
    if _semver(new_iocs["min_template_version"]) < _semver(prev_iocs["min_template_version"]):
        errors.append("monotonic: min_template_version went down")
    prev_rev = {r["id"] for r in prev_iocs["revoked_entries"]}
    new_rev = {r["id"] for r in new_iocs["revoked_entries"]}
    if not prev_rev <= new_rev:
        errors.append("monotonic: a previously revoked entry is no longer revoked")
    return errors


def validate_release_dir(d, previous_dir=None, fast_entries=True):
    errors = []
    docs = {}
    for name in RELEASE_FILES + ("latest.json",):
        p = os.path.join(d, name)
        try:
            with open(p, "rb") as f:
                docs[name] = json.loads(f.read().decode("utf-8"))
        except (OSError, ValueError):
            errors.append("%s: missing or not JSON" % name)
    if errors:
        return errors
    for name, ft in (("iocs.json", "iocs"), ("conformance.json", "conformance"), ("stats.json", "stats"),
                     ("latest.json", "latest")):
        if docs[name].get("file_type") != ft:
            errors.append("%s: file_type must be %s" % (name, ft))
    errors += ["iocs.json: " + e for e in validate_iocs(docs["iocs.json"], fast_entries)]
    errors += ["stats.json: " + e for e in validate_stats(docs["stats.json"])]
    errors += ["conformance.json: " + e for e in validate_conformance(docs["conformance.json"])]
    errors += validate_latest(docs["latest.json"], d)
    if docs["latest.json"].get("paused") != docs["iocs.json"].get("paused"):
        errors.append("latest/iocs paused flags differ")
    if previous_dir:
        with open(os.path.join(previous_dir, "iocs.json"), "rb") as f:
            prev = json.loads(f.read().decode("utf-8"))
        errors += check_monotonic(prev, docs["iocs.json"])
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dir")
    ap.add_argument("--previous")
    a = ap.parse_args(argv)
    errs = validate_release_dir(a.dir, a.previous)
    if errs:
        print("INVALID: %d problem(s)" % len(errs))
        for e in errs[:100]:
            print("  - " + e)
        return 1
    print("VALID: release files in %s" % a.dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
