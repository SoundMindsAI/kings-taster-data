"""Build the unsigned release files from fetched source documents.

python3 -m kt.build --sources <dir> --out <dir> [--previous <dir> | --bootstrap] [--force-pause]

Writes iocs.json, conformance.json, stats.json, manifest.json, one shard-*.json per shard, latest.json
(canonical JSON) and build-report.json (not released: circuit breaker, hold queue, rejects).
Exit codes: 0 built; 1 refused (validation, monotonicity, missing source with no previous).
"""
import argparse
import datetime as dt
import os
import re
import statistics
import sys

from . import sources as S
from . import shards as SH
from .common import (CVE_ID, ECO_PREFIX, canonical_json, defang, fmt_time, match_key, normalize_package,
                     parse_time, read_json, sha256_bytes, utc_now, write_json)
from .validate import (RELEASE_ASSET_OVERHEAD, check_monotonic, validate_conformance, validate_iocs, validate_latest,
                       validate_manifest, validate_stats)

ROOT = os.path.join(os.path.dirname(__file__), "..")
SOURCE_FILES = {"cisa-kev": "kev.json", "osv-npm": "osv-npm.json", "osv-pypi": "osv-pypi.json"}
TERMS = {
    "cisa-kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "osv-npm": "https://github.com/ossf/malicious-packages/blob/main/LICENSE",
    "osv-pypi": "https://github.com/ossf/malicious-packages/blob/main/LICENSE",
    "kings-taster-canary": "https://github.com/SoundMindsAI/kings-taster-data/blob/main/LICENSE",
}
RETENTION_DAYS = {"ip": 30, "url": 90, "domain": 180}  # package, hash, cve: never (SPEC.md §6.3)
REVOKE_REASONS = {"dispute_upheld", "false_positive", "withdrawn_upstream", "pipeline_error"}
PAUSE_REASONS = {"qa_bar_missed", "incident", "maintenance", "manual"}
RELEASE_BASE = "https://github.com/SoundMindsAI/kings-taster-data/releases/download/%s/"


class BuildError(Exception):
    pass


def _src_prefix(entry_id):
    if entry_id.startswith("kev:"):
        return "cisa-kev"
    if entry_id.startswith("canary:"):
        return "kings-taster-canary"
    return "osv-npm" if ":npm:" in entry_id else "osv-pypi"


def load_popular(path):
    names = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                names.add(line)
    return names


def canary_entries(cfg, now):
    out = []
    for c in cfg["list"]:
        t = c["type"]
        eco = c.get("ecosystem")
        val = c["value"]
        if t == "url":
            mk = match_key("url", val)  # canonical form already (Google rules leave it unchanged)
        else:
            mk = match_key(t, val, eco)
        cid = "canary:" + t + (":" + ECO_PREFIX[eco] if eco else "")
        out.append({
            "id": cid, "type": t, "value": defang(t, val, eco), "match_key": mk, "kind": "malicious",
            "ecosystem": eco,
            "affected_versions": {"all_versions": True, "versions": [], "ranges": []} if t == "package" else None,
            "fixed_version": None, "vendor": None, "product": None, "known_ransomware_use": None,
            "aliases": [], "origins": ["kings-taster-canary"], "confidence": "high",
            "upstream_origin": S.KT_LIST["upstream_origin"], "source_url": S.KT_LIST["source_url"],
            "license": S.KT_LIST["license"], "attribution": S.KT_LIST["attribution"],
            "published": "2026-11-26T00:00:00Z", "modified": None, "canary": True,
        })
    return out


def _week_bins(times, now, weeks=12):
    bins = [0] * weeks
    for t in times:
        age = (now - t).total_seconds() / 86400.0
        if 0 <= age < weeks * 7:
            bins[weeks - 1 - int(age // 7)] += 1
    return bins


def build(sources_dir, out_dir, previous_dir=None, bootstrap=False, force_pause=False, now=None, root=ROOT):
    now = now or utc_now()
    generated_at = fmt_time(now)
    tag = "kt-" + now.strftime("%Y%m%dT%H%M%SZ")
    cfg = lambda *p: read_json(os.path.join(root, *p))
    limits, canaries = cfg("config", "limits.json"), cfg("config", "canaries.json")
    control, approvals, revoked_cfg = cfg("review", "control.json"), cfg("review", "popular-approvals.json"), cfg("review", "revoked.json")
    popular = {"npm": {normalize_package("npm", n) for n in load_popular(os.path.join(root, "config", "popular", "npm.txt"))},
               "PyPI": {normalize_package("PyPI", n) for n in load_popular(os.path.join(root, "config", "popular", "pypi.txt"))}}
    if len(popular["npm"]) < 10 or len(popular["PyPI"]) < 10:
        raise BuildError("popular-name lists missing or too short; refusing to build without a hold queue")

    prev = None
    if previous_dir:
        prev = read_json(os.path.join(previous_dir, "iocs.json"))
        if parse_time(prev["generated_at"]) >= now:
            raise BuildError("monotonic: now is not after the previous generated_at")
    elif not bootstrap:
        raise BuildError("no previous release given; use --bootstrap only for the very first release")
    prev_entries = {e["id"]: e for e in prev["entries"]} if prev else {}
    prev_sources = {s["id"]: s for s in prev["sources"]} if prev else {}

    # 1. sources
    src_records, entries, withdrawn, rejected = [], [], set(), {}
    for sid, fname in SOURCE_FILES.items():
        doc = read_json(os.path.join(sources_dir, fname))
        if doc.get("source") != sid:
            raise BuildError("%s: wrong source document" % fname)
        lic, attr = (S.KEV["license"], S.KEV["attribution"]) if sid == "cisa-kev" else (S.OSV_MAL_LICENSE, S.OSV_MAL_ATTRIBUTION)
        if doc["status"] == "ok":
            ev = doc["evidence"]
            sd = doc.get("source_date")
            src_records.append({"id": sid, "status": "ok", "http_status": ev["http_status"],
                                "response_sha256": ev["response_sha256"],
                                "source_date": fmt_time(parse_time(sd)) if sd else None,
                                "fetched_at": ev["fetched_at"], "license": lic, "attribution": attr,
                                "terms_url": TERMS[sid], "entry_count": 0})
            entries += doc["entries"]
            withdrawn |= set(doc.get("withdrawn", []))
            rejected[sid] = len(doc.get("rejected", []))
        elif prev and sid in prev_sources:
            carried = dict(prev_sources[sid], status="carried_over", entry_count=0)
            src_records.append(carried)
            entries += [{k: v for k, v in e.items() if k not in ("first_seen", "status", "expires", "review_state")}
                        for e in prev["entries"] if not e["canary"] and _src_prefix(e["id"]) == sid]
            rejected[sid] = 0
        else:
            raise BuildError("%s failed and there is no previous release to carry over" % sid)
    entries += canary_entries(canaries, now)
    src_records.append({"id": "kings-taster-canary", "status": "ok", "http_status": None, "response_sha256": None,
                        "source_date": "2026-11-26T00:00:00Z", "fetched_at": None,
                        "license": S.KT_LIST["license"], "attribution": S.KT_LIST["attribution"],
                        "terms_url": TERMS["kings-taster-canary"], "entry_count": 0})

    # 2. revocations (review file + previous + withdrawn upstream)
    revoked = {}
    for r in (prev["revoked_entries"] if prev else []):
        revoked[r["id"]] = r
    for r in revoked_cfg.get("revoked", []):
        if set(r) != {"id", "match_key", "revoked_at", "reason"} or r["reason"] not in REVOKE_REASONS:
            raise BuildError("review/revoked.json: bad row")
        parse_time(r["revoked_at"])
        revoked.setdefault(r["id"], r)
    new_ids = {e["id"] for e in entries}
    for pid, pe in prev_entries.items():
        mal = pid.split(":")[1] if pid.startswith("osv:") else None
        if mal and mal in withdrawn and pid not in revoked:
            revoked[pid] = {"id": pid, "match_key": pe["match_key"], "revoked_at": generated_at,
                            "reason": "withdrawn_upstream"}
    newly_revoked = [i for i in revoked if not prev or i not in {r["id"] for r in prev["revoked_entries"]}]

    # 3. per-entry state
    appr = {}
    for a in approvals.get("approvals", []):
        if set(a) != {"entry_id", "approved_by", "approved_at", "ref"} or a["approved_by"] != "owner" \
                or not re.fullmatch(r"[A-Za-z0-9#/._-]{1,80}", a["ref"]):
            raise BuildError("review/popular-approvals.json: bad row")
        parse_time(a["approved_at"])
        appr[a["entry_id"]] = a
    final, seen, hold = [], set(), []
    for e in entries:
        if e["id"] in revoked:
            continue
        if e["id"] in seen:
            raise BuildError("duplicate entry id across sources")
        seen.add(e["id"])
        e = dict(e)
        e.setdefault("modified", None)
        e.setdefault("canary", False)
        e["first_seen"] = prev_entries[e["id"]]["first_seen"] if e["id"] in prev_entries else generated_at
        days = RETENTION_DAYS.get(e["type"]) if not e["canary"] else None
        if days:
            base = parse_time(e["modified"] or e["published"])
            exp = base + dt.timedelta(days=days)
            e["expires"], e["status"] = fmt_time(exp), ("retired" if exp <= now else "active")
        else:
            e["expires"], e["status"] = None, "active"
        e["review_state"] = "auto"
        if e["kind"] == "malicious" and e["type"] == "package" and not e["canary"]:
            name = e["match_key"].split(":", 1)[1]
            if name in popular[e["ecosystem"]]:
                if e["id"] in appr and len(e["origins"]) >= 2:
                    e["review_state"] = "approved"
                else:
                    e["review_state"] = "pending_review"
                    hold.append({"id": e["id"], "match_key": e["match_key"], "origins": e["origins"],
                                 "source_url": e["source_url"], "published": e["published"],
                                 "approved_but_single_origin": e["id"] in appr,
                                 "new_this_run": e["id"] not in prev_entries})
        final.append(e)
    final.sort(key=lambda e: e["id"])
    counts = {}
    for e in final:
        counts[_src_prefix(e["id"])] = counts.get(_src_prefix(e["id"]), 0) + 1
    for s in src_records:
        s["entry_count"] = counts.get(s["id"], 0)

    paused = bool(control.get("paused")) or force_pause
    reason = control.get("paused_reason") if control.get("paused") else ("manual" if force_pause else None)
    if paused and reason not in PAUSE_REASONS:
        reason = "manual"
    mtv = control["min_template_version"]
    if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", mtv):
        raise BuildError("review/control.json: bad min_template_version")

    iocs = {"file_type": "iocs", "schema_version": 1, "generated_at": generated_at, "tag": tag,
            "min_template_version": mtv, "paused": paused, "paused_reason": reason,
            "sources": sorted(src_records, key=lambda s: s["id"]),
            "revoked_entries": sorted(revoked.values(), key=lambda r: r["id"]),
            "entries": final,
            "counts": {"entries": len(final), "revoked": len(revoked), "pending_review": len(hold),
                       "rejected_upstream_records": sum(rejected.values())}}
    errs = validate_iocs(iocs, fast_entries=True, root=root)
    if prev:
        errs += check_monotonic(prev, iocs)
    if errs:
        raise BuildError("iocs.json failed validation: " + "; ".join(errs[:10]))

    # 4. diff + circuit breaker
    added = [i for i in seen - set(revoked) if i not in prev_entries] if prev else sorted(seen)
    removed = [i for i in prev_entries if i not in seen and i not in revoked]
    breaker = []
    if prev:
        if len(added) > limits["max_added_per_run"]:
            breaker.append("added_%d_over_%d" % (len(added), limits["max_added_per_run"]))
        if len(removed) > limits["max_removed_per_run"]:
            breaker.append("removed_%d_over_%d" % (len(removed), limits["max_removed_per_run"]))
        if len(newly_revoked) > limits["max_revoked_per_run"]:
            breaker.append("revoked_%d_over_%d" % (len(newly_revoked), limits["max_revoked_per_run"]))
    else:
        breaker.append("bootstrap_first_release")
    if any(h["new_this_run"] for h in hold):
        breaker.append("new_popular_name_hit")
    if any(s["status"] == "carried_over" for s in src_records):
        breaker.append("source_carried_over")

    # 5. stats
    week = lambda t: (now - parse_time(t)).total_seconds() < 7 * 86400
    mal = [e for e in final if e["kind"] == "malicious" and e["type"] == "package" and not e["canary"]]
    kev = [e for e in final if e["type"] == "cve" and not e["canary"]]
    lat = []
    if prev:
        for e in mal + kev:
            if e["id"] not in prev_entries and week(e["first_seen"]):
                h = (parse_time(e["first_seen"]) - parse_time(e["published"])).total_seconds() / 3600.0
                if h >= 0:
                    lat.append(h)
    stats = {
        "file_type": "stats", "schema_version": 1, "generated_at": generated_at, "tag": tag,
        "data_as_of": generated_at, "window_days": 7, "paused": paused,
        "official": {
            "malicious_packages_this_week": {"npm": sum(1 for e in mal if e["ecosystem"] == "npm" and week(e["published"])),
                                             "pypi": sum(1 for e in mal if e["ecosystem"] == "PyPI" and week(e["published"]))},
            "malicious_packages_weekly_12w": {
                "npm": _week_bins([parse_time(e["published"]) for e in mal if e["ecosystem"] == "npm"], now),
                "pypi": _week_bins([parse_time(e["published"]) for e in mal if e["ecosystem"] == "PyPI"], now)},
            "kev_added_this_week": sum(1 for e in kev if week(e["published"])),
            "kev_added_weekly_12w": _week_bins([parse_time(e["published"]) for e in kev], now),
            "named_campaigns_this_week": [],
        },
        "list": {"entries_total": len(final), "entries_by_source": counts, "added_this_run": len(added),
                 "retired_this_week": sum(1 for e in final if e["status"] == "retired" and e["expires"] and week(e["expires"])),
                 "revoked_total": len(revoked), "pending_review_total": len(hold)},
        "freshness": {"median_hours_listing_to_list": round(statistics.median(lat), 1) if lat else None,
                      "sample_size": len(lat),
                      "source_dates": {s["id"]: s["source_date"] for s in src_records}},
        "qa": {"status": "not_measured"}, "disputes": {"status": "not_measured"},
        "user_reports": {"status": "not_available"},
    }
    errs = validate_stats(stats)
    if errs:
        raise BuildError("stats.json failed validation: " + "; ".join(errs[:10]))

    # 6. conformance
    cases = read_json(os.path.join(root, "conformance", "cases.json"))
    conf = dict(cases, file_type="conformance", schema_version=1, generated_at=generated_at, tag=tag)
    errs = validate_conformance(conf)
    if errs:
        raise BuildError("conformance.json failed validation: " + "; ".join(errs[:10]))

    # 7. shards + manifest (SPEC.md §6.5)
    try:
        manifest, shard_files = SH.build_shards(iocs, limits)
    except SH.ShardError as e:
        raise BuildError(str(e))
    errs = validate_manifest(manifest)
    max_assets = limits["shards"]["max_release_assets"]
    if len(shard_files) + RELEASE_ASSET_OVERHEAD > max_assets:
        errs.append("%d shards would exceed the %d-asset release limit" % (len(shard_files), max_assets))
    if errs:
        raise BuildError("manifest.json failed validation: " + "; ".join(errs[:10]))

    # 8. write + latest
    os.makedirs(out_dir, exist_ok=True)
    for name in os.listdir(out_dir):
        if name.startswith("shard-") and name.endswith(".json"):
            os.remove(os.path.join(out_dir, name))  # never leave a stale shard from an older build
    for name, b in shard_files.items():
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(b)
    assets = {}
    for name, doc in (("iocs.json", iocs), ("conformance.json", conf), ("stats.json", stats),
                      ("manifest.json", manifest)):
        b = canonical_json(doc)
        with open(os.path.join(out_dir, name), "wb") as f:
            f.write(b)
        assets[name] = {"sha256": sha256_bytes(b), "bytes": len(b)}
    latest = {"file_type": "latest", "schema_version": 1, "generated_at": generated_at, "tag": tag,
              "release_base_url": RELEASE_BASE % tag, "assets": assets, "paused": paused,
              "paused_reason": reason, "min_template_version": mtv}
    with open(os.path.join(out_dir, "latest.json"), "wb") as f:
        f.write(canonical_json(latest))
    errs = validate_latest(latest, out_dir)
    if errs:
        raise BuildError("latest.json failed validation: " + "; ".join(errs))
    report = {"generated_at": generated_at, "tag": tag, "bootstrap": prev is None,
              "previous_generated_at": prev["generated_at"] if prev else None,
              "needs_human": bool(breaker), "breaker": breaker,
              "added": len(added), "removed": len(removed), "newly_revoked": len(newly_revoked),
              "hold_queue": hold, "rejected_upstream_records": rejected,
              "sources": {s["id"]: s["status"] for s in src_records}, "assets": assets,
              "shards": {"count": len(shard_files), "max_gzip_bytes": max(r["gzip_bytes"] for r in manifest["shards"]),
                         "total_gzip_bytes": sum(r["gzip_bytes"] for r in manifest["shards"])}}
    write_json(os.path.join(out_dir, "build-report.json"), report)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sources", required=True)
    ap.add_argument("--out", required=True)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--previous")
    g.add_argument("--bootstrap", action="store_true")
    ap.add_argument("--force-pause", action="store_true")
    a = ap.parse_args(argv)
    try:
        r = build(a.sources, a.out, a.previous, a.bootstrap, a.force_pause)
    except (BuildError, KeyError, ValueError, OSError) as e:
        print("BUILD REFUSED: %s" % str(e)[:500])
        return 1
    print("built %s: +%d -%d revoked+%d hold=%d needs_human=%s %s" % (
        r["tag"], r["added"], r["removed"], r["newly_revoked"], len(r["hold_queue"]), r["needs_human"],
        ",".join(r["breaker"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
