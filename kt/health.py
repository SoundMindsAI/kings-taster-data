"""Daily pipeline health check (SPEC.md §7.5).

Checks a local release directory (unsigned after a build, or signed before
publish). It never contacts the network. A failing check means that day's
release must not be published; a size jump over the configured ratio is a
hold for review.
"""
import argparse
import json
import os
import sys
import tempfile

from .common import ECO_PREFIX, parse_time, read_json, sha256_bytes, utc_now
from .shards import looks_like_shard_filename
from .validate import CANARY_TYPES, FUTURE_SKEW_SECONDS, list_canary_pairs, validate_release_dir

ROOT = os.path.join(os.path.dirname(__file__), "..")
SILENT_SOURCES = ("cisa-kev", "osv-npm", "osv-pypi")
DEFAULT_GAPS = {"cisa-kev": 14, "osv-npm": 3, "osv-pypi": 3}
SIZE_JUMP_RATIO = 0.5
MAX_ALERT_AFTER_HOURS = 72
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_HOLD = 10  # distinct from argparse's usage-error status (2)


def source_of(entry_id):
    if entry_id.startswith("kev:"):
        return "cisa-kev"
    if entry_id.startswith("canary:"):
        return "kings-taster-canary"
    return "osv-npm" if ":npm:" in entry_id else "osv-pypi"


def load_limits(root=None):
    path = os.path.join(root or ROOT, "config", "limits.json")
    doc = read_json(path)
    return doc.get("pipeline_health") or {}


def _shard_paths(release_dir):
    names = []
    for name in sorted(os.listdir(release_dir)):
        if looks_like_shard_filename(name) and os.path.isfile(os.path.join(release_dir, name)):
            names.append(name)
    return names


def _add(report, name, status, detail):
    report["checks"].append({"name": name, "status": status, "detail": detail})
    if status == "fail":
        report["failed"].append("%s: %s" % (name, detail))
    elif status == "hold":
        report["holds"].append("%s: %s" % (name, detail))


def check_release(release_dir, previous_dir=None, *, now=None, signed=False,
                  require_shards=True, allowed_signers=None, limits=None, root=None,
                  pre_sign=False):
    """Return a health report for a local release directory. Never uses the network."""
    root = root or ROOT
    now = now or utc_now()
    if isinstance(now, str):
        now = parse_time(now)
    cfg = limits if limits is not None else load_limits(root)
    gaps = {
        "cisa-kev": int(cfg.get("cisa_kev_gap_days", DEFAULT_GAPS["cisa-kev"])),
        "osv-npm": int(cfg.get("osv_mal_gap_days", DEFAULT_GAPS["osv-npm"])),
        "osv-pypi": int(cfg.get("osv_mal_gap_days", DEFAULT_GAPS["osv-pypi"])),
    }
    ratio = float(cfg.get("size_jump_hold_ratio", SIZE_JUMP_RATIO))
    report = {
        "status": "ok",
        "signed": bool(signed),
        "require_shards": bool(require_shards),
        "generated_at": None,
        "tag": None,
        "checks": [],
        "failed": [],
        "holds": [],
    }
    latest_path = os.path.join(release_dir, "latest.json")
    manifest_path = os.path.join(release_dir, "manifest.json")
    iocs_path = os.path.join(release_dir, "iocs.json")
    for path, label in ((latest_path, "latest.json"), (manifest_path, "manifest.json"),
                        (iocs_path, "iocs.json")):
        if not os.path.isfile(path):
            _add(report, "build", "fail", "%s is missing" % label)
            return _finalize(report)

    latest = read_json(latest_path)
    manifest = read_json(manifest_path)
    iocs = read_json(iocs_path)
    report["generated_at"] = latest.get("generated_at")
    report["tag"] = latest.get("tag")

    # --- Build: shards present and hashes match the manifest ---
    if require_shards:
        listed = [s["file"] for s in manifest.get("shards") or []]
        on_disk = _shard_paths(release_dir)
        missing = [n for n in listed if n not in on_disk]
        extra = [n for n in on_disk if n not in listed]
        if missing:
            _add(report, "build", "fail", "missing shards: %s" % ", ".join(missing[:8]))
        elif extra:
            _add(report, "build", "fail", "unlisted shard files: %s" % ", ".join(extra[:8]))
        else:
            mismatch = []
            for s in manifest["shards"]:
                path = os.path.join(release_dir, s["file"])
                with open(path, "rb") as fh:
                    raw = fh.read()
                digest = sha256_bytes(raw)
                if digest != s.get("sha256") or len(raw) != s.get("bytes"):
                    mismatch.append(s["name"])
            if mismatch:
                _add(report, "build", "fail", "hash/size mismatch: %s" % ", ".join(mismatch[:8]))
            else:
                _add(report, "build", "ok", "%d shards match the manifest" % len(listed))
    else:
        _add(report, "build", "ok", "shard files not required for this run")

    # --- Dates ---
    try:
        generated = parse_time(latest["generated_at"])
    except (KeyError, ValueError, TypeError):
        _add(report, "dates", "fail", "generated_at is missing or not a UTC time")
        generated = None
    if generated is not None:
        date_ok = False
        if (generated - now).total_seconds() > FUTURE_SKEW_SECONDS:
            _add(report, "dates", "fail", "generated_at is in the future")
        elif require_shards and not signed and not pre_sign and generated.date() != now.date():
            # Strict "today" only for the daily (unsigned) build, as SPEC.md §7.5 says.
            _add(report, "dates", "fail", "generated_at is not today's date")
        elif signed or pre_sign:
            hours = cfg.get("alert_after_hours", 26)
            if isinstance(hours, bool) or not isinstance(hours, int) or not 1 <= hours <= MAX_ALERT_AFTER_HOURS:
                _add(report, "dates", "fail", "alert_after_hours must be a whole number from 1 to %d" % MAX_ALERT_AFTER_HOURS)
            elif (now - generated).total_seconds() > hours * 3600:
                _add(report, "dates", "fail", "generated_at is older than %d hours" % hours)
            else:
                date_ok = True
        else:
            date_ok = True
        if date_ok:
            stale = []
            for e in iocs.get("entries") or []:
                try:
                    if parse_time(e["first_seen"]) > generated:
                        stale.append(e["id"])
                except (KeyError, ValueError, TypeError):
                    stale.append(e.get("id") or "?")
                if len(stale) >= 8:
                    break
            if stale:
                _add(report, "dates", "fail", "first_seen after generated_at: %s" % ", ".join(stale[:8]))
            else:
                _add(report, "dates", "ok", "generated_at %s, first_seen on or before it" % latest["generated_at"])

    # --- Canaries ---
    # The canary flag must never let real data skip matching: every flagged entry
    # must carry a build-assigned "canary:" id, and the flagged match_keys must be
    # exactly the configured list canaries (same keys, same counts).
    have = set()
    flagged_keys = []
    bad_ids = []
    unflagged_ids = []
    for e in iocs.get("entries") or []:
        eid = e.get("id")
        if not e.get("canary"):
            if isinstance(eid, str) and eid.startswith("canary:"):
                unflagged_ids.append(eid[:60])
            continue
        if not (isinstance(eid, str) and eid.startswith("canary:")):
            bad_ids.append(str(eid)[:60] if eid is not None else "?")
        typ = e.get("type") or ""
        if typ == "package":
            have.add(typ + ":" + ECO_PREFIX.get(e.get("ecosystem"), ""))
        else:
            have.add(typ)
        mk = e.get("match_key")
        flagged_keys.append((typ, mk if isinstance(mk, str) else "?"))
    missing_c = sorted(CANARY_TYPES - have)
    expected_keys = _expected_canary_keys(root)
    if missing_c:
        _add(report, "canaries", "fail", "missing canary types: %s" % ", ".join(missing_c))
    elif bad_ids:
        _add(report, "canaries", "fail", "canary flag on non-canary ids: %s" % ", ".join(bad_ids[:8]))
    elif unflagged_ids:
        _add(report, "canaries", "fail", "canary id without the canary flag: %s" % ", ".join(unflagged_ids[:8]))
    elif expected_keys is None:
        _add(report, "canaries", "fail", "config/canaries.json is missing, unreadable or lists no canaries")
    elif sorted(flagged_keys) != expected_keys:
        _add(report, "canaries", "fail", "canary match_key mismatch")
    else:
        _add(report, "canaries", "ok", "list canaries present for %s" % ", ".join(sorted(have)))

    # --- Signing (only when asked, against local .sig files) ---
    if signed:
        from . import verify as V
        signers = allowed_signers or os.path.join(root, "config", "allowed_signers")
        try:
            V.verify_release(release_dir, allowed=signers, now=now,
                             require_shards=require_shards, max_age_hours=87600)
            _add(report, "signing", "ok", "signatures verify")
        except V.VerifyError as e:
            _add(report, "signing", "fail", str(e))
        except Exception as e:
            _add(report, "signing", "fail", "verify failed (%s)" % type(e).__name__)
    else:
        _add(report, "signing", "ok", "unsigned build; signatures are checked at sign-and-release")

    # --- Silent sources ---
    src_status = {s["id"]: s for s in (iocs.get("sources") or []) if isinstance(s, dict) and "id" in s}
    newest = {sid: None for sid in SILENT_SOURCES}
    counts = {sid: 0 for sid in SILENT_SOURCES}
    for e in iocs.get("entries") or []:
        if e.get("canary"):
            continue
        sid = source_of(e["id"])
        if sid not in newest:
            continue
        counts[sid] += 1
        try:
            seen = parse_time(e["first_seen"])
        except (KeyError, ValueError, TypeError):
            continue
        if newest[sid] is None or seen > newest[sid]:
            newest[sid] = seen
    silent = []
    for sid in SILENT_SOURCES:
        rec = src_status.get(sid)
        if rec is None:
            silent.append("%s is missing from the source list" % sid)
            continue
        if rec.get("status") == "carried_over":
            silent.append("%s fetch failed (carried over)" % sid)
            continue
        if counts[sid] == 0:
            silent.append("%s returned no list entries" % sid)
            continue
        gap = gaps[sid]
        last = newest[sid]
        if last is not None and (now - last).total_seconds() > gap * 86400:
            silent.append("%s added nothing for more than %d days (last new entry %s)"
                          % (sid, gap, last.strftime("%Y-%m-%d")))
    if silent:
        _add(report, "sources", "fail", "; ".join(silent))
    else:
        _add(report, "sources", "ok", "required sources are present and within their gaps")

    # --- Size jump vs the previous release ---
    if previous_dir and require_shards and os.path.isdir(previous_dir):
        prev_manifest_path = os.path.join(previous_dir, "manifest.json")
        if os.path.isfile(prev_manifest_path):
            prev_manifest = read_json(prev_manifest_path)
            jumps = _size_jumps(release_dir, manifest, previous_dir, prev_manifest, ratio)
            if jumps:
                _add(report, "size", "hold", "; ".join(jumps[:8]))
            else:
                _add(report, "size", "ok", "no shard or total size jumped more than %.0f%%" % (ratio * 100))
        else:
            _add(report, "size", "ok", "previous release has no manifest to compare")
    else:
        _add(report, "size", "ok", "no previous release; size jump not checked")

    # Structural validation (local, no network). The daily pipeline already ran a full
    # validate; this uses the fast path as a second check. The hourly watchdog skips
    # it because the pointer files have no shards.
    if require_shards:
        errs = validate_release_dir(release_dir, previous_dir=previous_dir,
                                    fast_entries=True, now=now, root=root)
        if errs:
            _add(report, "validate", "fail", errs[0])
        else:
            _add(report, "validate", "ok", "release directory validates")

    return _finalize(report)


def _expected_canary_keys(root):
    """Sorted match_key values of the fixed list canaries in config/canaries.json,
    or None when the file is missing, unreadable or empty (the check must fail)."""
    return list_canary_pairs(root)


def _size_jumps(release_dir, manifest, previous_dir, prev_manifest, ratio):
    """Compare gzip_bytes from the manifests. Shard files need not be on disk
    (the production previous dir holds only the signed pointer files)."""
    def totals(mani):
        files = {}
        for s in mani.get("shards") or []:
            if not isinstance(s, dict):
                continue
            name, gz = s.get("name"), s.get("gzip_bytes")
            if name and isinstance(gz, int):
                files[name] = gz
        return files, sum(files.values())

    cur_files, cur_total = totals(manifest)
    prev_files, prev_total = totals(prev_manifest)
    jumps = []
    if prev_total > 0 and cur_total > prev_total * (1 + ratio):
        jumps.append("total gzip size jumped from %d to %d" % (prev_total, cur_total))
    for name, prev_sz in prev_files.items():
        cur_sz = cur_files.get(name)
        if prev_sz > 0 and cur_sz is not None and cur_sz > prev_sz * (1 + ratio):
            jumps.append("shard %s gzip size jumped from %d to %d" % (name, prev_sz, cur_sz))
    return jumps


def _finalize(report):
    if report["failed"]:
        report["status"] = "fail"
    elif report["holds"]:
        report["status"] = "hold"
    else:
        report["status"] = "ok"
    return report


def write_report(path, report):
    """Write the report via a temp file and rename. Does not follow a symlink at path."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".health.", suffix=".tmp",
                               dir=os.path.dirname(os.path.abspath(path)) or ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument("release_dir")
    ap.add_argument("--previous")
    ap.add_argument("--signed", action="store_true")
    ap.add_argument("--pre-sign", action="store_true",
                    help="use the signed-path age bound without requiring signatures")
    ap.add_argument("--no-shards", action="store_true",
                    help="skip shard-file checks (hourly watchdog of the pointer files)")
    ap.add_argument("--now", help="UTC time for date and gap checks (tests and KT_NOW)")
    ap.add_argument("--out", help="write pipeline-health.json here")
    ap.add_argument("--allowed-signers")
    ap.add_argument("--root", default=ROOT)
    out = None
    signed, require_shards = False, True
    try:
        try:
            a = ap.parse_args(argv)
        except SystemExit as e:
            # argparse uses status 2 for usage errors; that must not mean "hold".
            return EXIT_OK if e.code in (0, None) else EXIT_FAIL
        signed, require_shards = bool(a.signed), not a.no_shards
        out = a.out or os.path.join(a.release_dir, "pipeline-health.json")
        report = check_release(
            a.release_dir, a.previous, now=a.now, signed=a.signed,
            require_shards=not a.no_shards, allowed_signers=a.allowed_signers,
            root=a.root, pre_sign=a.pre_sign,
        )
        write_report(out, report)
        sys.stdout.write("%s\n" % report["status"])
        for line in report["failed"] + report["holds"]:
            sys.stdout.write("%s\n" % line)
        if report["status"] == "fail":
            return EXIT_FAIL
        if report["status"] == "hold":
            return EXIT_HOLD
        return EXIT_OK
    except Exception:
        if out:
            try:
                write_report(out, {
                    "status": "fail", "signed": signed, "require_shards": require_shards,
                    "generated_at": None, "tag": None, "checks": [],
                    "failed": ["health check crashed"], "holds": [],
                })
            except Exception:
                pass
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
