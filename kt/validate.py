"""Validators for the release files: iocs.json, latest.json, stats.json, conformance.json, manifest.json and
the shard-*.json files it lists.

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
from . import connectivity as CONN
from . import shards as SH
from .common import (canonical_json, loads_strict, match_key, normalize_package, parse_time, read_json,
                     sha256_bytes, utc_now, ECO_PREFIX)
from .finding import RESULT_RANK, UNKNOWN_REASONS, CAUTION_REASONS, BLOCK_REASONS

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCHEMAS = {name: os.path.join(ROOT, "schema", name + ".schema.json") for name in ("iocs", "latest", "stats", "manifest")}
ALL_REASONS = UNKNOWN_REASONS | CAUTION_REASONS | BLOCK_REASONS | {"checker_failed"}
REQUIRED_SOURCE_IDS = {"cisa-kev", "osv-npm", "osv-pypi", "kings-taster-canary"}
CANARY_TYPES = {"package:npm", "package:pypi", "domain", "url", "ip", "hash", "repo_owner", "cve"}
RELEASE_FILES = ("iocs.json", "conformance.json", "stats.json", "manifest.json")
# Signed files (latest.json + RELEASE_FILES, each with a .sig) plus LICENSES.md and Apache-2.0.txt.
RELEASE_ASSET_OVERHEAD = 2 * (1 + len(RELEASE_FILES)) + 2
MAX_RELEASE_ASSETS = 1000  # GitHub's per-release asset limit
MAX_MANIFEST_BYTES = 5 * 1024 * 1024


def _schema(name):
    with open(SCHEMAS[name], encoding="utf-8") as f:
        return json.load(f)


def _semver(s):
    return tuple(int(x) for x in s.split("."))


def list_canary_keys(root=None):
    """Sorted match_key values (with multiplicity) of the fixed list canaries in
    config/canaries.json, or None when the file is missing, unreadable, malformed
    or lists no canaries. Callers must treat None as a failure, never as "nothing
    expected"."""
    path = os.path.join(root or ROOT, "config", "canaries.json")
    try:
        doc = read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("list"), list):
        return None
    keys = []
    for e in doc["list"]:
        if not isinstance(e, dict) or "type" not in e or "value" not in e:
            return None
        try:
            keys.append(match_key(e["type"], e["value"], e.get("ecosystem")))
        except (KeyError, ValueError, TypeError):
            return None
    return sorted(keys) or None


def validate_iocs(doc, fast_entries=False, root=None):
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
    canary_keys = []
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
            canary_keys.append(e["match_key"])
            if e["kind"] != "malicious":
                errors.append("entry %s: canaries are malicious entries" % e["id"][:60])
            if not e["id"].startswith("canary:"):
                # The canary flag must never let real data skip matching (SPEC.md §4).
                errors.append("entry %s: canary flag on a non-canary id" % e["id"][:60])
        elif e["id"].startswith("canary:"):
            errors.append("entry %s: canary id without the canary flag" % e["id"][:60])
        try:
            if parse_time(e["first_seen"]) > parse_time(doc["generated_at"]):
                errors.append("entry %s: first_seen after generated_at" % e["id"][:60])
        except ValueError:
            errors.append("entry %s: bad time" % e["id"][:60])
    if canaries != CANARY_TYPES:
        errors.append("entries: canary set incomplete (%s missing)" % sorted(CANARY_TYPES - canaries))
    expected_keys = list_canary_keys(root)
    if expected_keys is None:
        errors.append("canaries: config/canaries.json is missing, unreadable or lists no canaries")
    elif sorted(canary_keys) != expected_keys:
        # Exact multiset match: no missing, extra or duplicated canary match_key.
        errors.append("entries: canary match_keys differ from config/canaries.json")
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


def validate_manifest(doc):
    errors = jsonschema_lite.validate(doc, _schema("manifest"))
    if not errors and doc["counts"]["shards"] + RELEASE_ASSET_OVERHEAD > MAX_RELEASE_ASSETS:
        errors.append("manifest: too many shards for one release")
    return errors


def validate_stats(doc):
    return jsonschema_lite.validate(doc, _schema("stats"))


def validate_conformance(doc):
    errors = []
    if doc.get("file_type") != "conformance" or doc.get("schema_version") != 1:
        errors.append("conformance: wrong file_type/schema_version")
    allowed_top = {"file_type", "schema_version", "generated_at", "tag", "comment", "global_expectations", "cases",
                   "canonicalization_vectors", "connectivity"}
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
    errors += validate_connectivity(doc.get("connectivity"))
    return errors


CONN_FIXED = {"template": "KT {version} is live and checking",
              "pattern": "^KT \\d{1,3}\\.\\d{1,3}\\.\\d{1,3} is live and checking\\Z",
              "offer": CONN.OFFER, "approval_notice": CONN.APPROVAL_NOTICE, "read_only_ok": CONN.READ_ONLY_OK,
              "default_answer": "no", "state_key": CONN.STATE_KEY, "counts_toward_report_caps": True,
              "counts_as_threat_report": False, "override_allowed": False}
CONN_OUTCOMES = ("offered", "draft_shown", "asked_ok_to_send", "posted", "read_only_check", "marks_done",
                 "counts_as_report")


def validate_connectivity(c):
    """SPEC.md §4D/§10.1: the connectivity cases must carry the fixed texts and agree with kt/connectivity.py."""
    if not isinstance(c, dict):
        return ["conformance: connectivity cases missing"]
    errors = []
    if set(c) != set(CONN_FIXED) | {"comment", "draft_cases", "flow_cases"}:
        errors.append("connectivity: unexpected or missing fields")
    for k, v in CONN_FIXED.items():
        if c.get(k) != v:
            errors.append("connectivity: %s must be the fixed value" % k)
    ids = set()
    drafts = c.get("draft_cases") or []
    flows = c.get("flow_cases") or []
    if sum(1 for d in drafts if d.get("expected") == "allow") < 1 or sum(1 for d in drafts if d.get("expected") == "refuse") < 8:
        errors.append("connectivity: need at least 1 allowed and 8 refused drafts")
    for d in drafts:
        cid = d.get("id")
        if set(d) != {"id", "running_version", "draft", "expected"} or not isinstance(cid, str) \
                or not re.fullmatch(r"conn-[a-z0-9-]{3,55}", cid) or cid in ids:
            errors.append("connectivity: bad draft case"); continue
        ids.add(cid)
        if d["expected"] not in ("allow", "refuse") or \
                CONN.draft_allowed(d["draft"], d["running_version"]) != (d["expected"] == "allow"):
            errors.append("connectivity: draft case %s disagrees with the rule" % cid)
    triggers = set()
    for f in flows:
        cid = f.get("id")
        keys = {"id", "trigger", "already_done", "offer_answer", "send_answer", "post_ok", "reports_left", "expected"}
        if set(f) != keys or not isinstance(cid, str) or not re.fullmatch(r"conn-[a-z0-9-]{3,55}", cid) or cid in ids \
                or f["trigger"] not in CONN.TRIGGERS or f["offer_answer"] not in CONN.ANSWERS \
                or f["send_answer"] not in CONN.ANSWERS or set(f["expected"]) != set(CONN_OUTCOMES):
            errors.append("connectivity: bad flow case"); continue
        ids.add(cid)
        triggers.add(f["trigger"])
        got = CONN.flow(f["trigger"], f["already_done"], f["offer_answer"], f["send_answer"], f["post_ok"],
                        f["reports_left"])
        if got != f["expected"]:
            errors.append("connectivity: flow case %s disagrees with the rule" % cid)
    if triggers != set(CONN.TRIGGERS):
        errors.append("connectivity: flow cases must cover every trigger")
    return errors


FUTURE_SKEW_SECONDS = 300  # a signed file dated more than 5 minutes ahead is refused (rollback-state poisoning)


def check_not_future(generated_at, now=None):
    now = now or utc_now()
    if (parse_time(generated_at) - now).total_seconds() > FUTURE_SKEW_SECONDS:
        return ["latest: generated_at is in the future"]
    return []


def validate_latest(latest, release_dir, raw=None):
    """raw: the exact latest.json bytes; when given they must be the canonical form (no duplicate keys)."""
    if not isinstance(latest, dict):
        return ["latest: not a JSON object"]
    errors = jsonschema_lite.validate(latest, _schema("latest"))
    if errors:
        return errors
    if raw is not None and raw != canonical_json(latest):
        errors.append("latest: latest.json is not in canonical form")
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
            d = loads_strict(b)
        except ValueError:
            errors.append("latest: %s not JSON or has duplicate keys" % name); continue
        if not isinstance(d, dict):
            errors.append("latest: %s is not a JSON object" % name); continue
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


def validate_release_dir(d, previous_dir=None, fast_entries=True, now=None, root=None):
    errors = []
    docs, raws = {}, {}
    for name in RELEASE_FILES + ("latest.json",):
        p = os.path.join(d, name)
        try:
            with open(p, "rb") as f:
                raws[name] = f.read()
            docs[name] = loads_strict(raws[name])
        except (OSError, ValueError):
            errors.append("%s: missing, not JSON, or has duplicate keys" % name)
            continue
        if not isinstance(docs[name], dict):
            errors.append("%s: not a JSON object" % name)
    if errors:
        return errors
    if len(raws["manifest.json"]) > MAX_MANIFEST_BYTES:
        return errors + ["manifest.json: over the 5 MB cap"]
    for name, ft in (("iocs.json", "iocs"), ("conformance.json", "conformance"), ("stats.json", "stats"),
                     ("manifest.json", "manifest"), ("latest.json", "latest")):
        if docs[name].get("file_type") != ft:
            errors.append("%s: file_type must be %s" % (name, ft))
    errors += ["iocs.json: " + e for e in validate_iocs(docs["iocs.json"], fast_entries, root=root)]
    errors += ["stats.json: " + e for e in validate_stats(docs["stats.json"])]
    errors += ["conformance.json: " + e for e in validate_conformance(docs["conformance.json"])]
    m_errs = validate_manifest(docs["manifest.json"])
    errors += ["manifest.json: " + e for e in m_errs]
    if not m_errs and not errors:
        errors += SH.validate_shards(d, docs["manifest.json"], iocs=docs["iocs.json"], require_all=True)
    errors += validate_latest(docs["latest.json"], d, raw=raws["latest.json"])
    if not errors:
        errors += check_not_future(docs["latest.json"]["generated_at"], now)
    if docs["latest.json"].get("paused") != docs["iocs.json"].get("paused"):
        errors.append("latest/iocs paused flags differ")
    if previous_dir:
        prev = read_json(os.path.join(previous_dir, "iocs.json"))
        errors += check_monotonic(prev, docs["iocs.json"])
    return errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dir")
    ap.add_argument("--previous")
    ap.add_argument("--now", help="ISO time to judge 'not in the future' against (default: now)")
    a = ap.parse_args(argv)
    try:
        errs = validate_release_dir(a.dir, a.previous, now=parse_time(a.now) if a.now else None)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        errs = ["unexpected %s while validating" % type(e).__name__]
    if errs:
        print("INVALID: %d problem(s)" % len(errs))
        for e in errs[:100]:
            print("  - " + e)
        return 1
    print("VALID: release files in %s" % a.dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
