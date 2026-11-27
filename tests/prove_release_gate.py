"""Harness-only proof that a health FAIL or HOLD stops sign-and-release
before any signature or publish. Used by unit tests and by the default-off
workflow_dispatch job on tests.yml. No network, no live keys, stub gh only.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sys

from kt.common import canonical_json, sha256_bytes
from tests.helpers import T0, fetch_all, load
from tests.test_sign_verify import FILES, SignAndReleaseBase, sign_dir
from kt import build as B


def write_canonical(path, doc):
    with open(path, "wb") as f:
        f.write(canonical_json(doc))


def reset_logs(harness):
    for path in (harness.sig_log, harness.log):
        if os.path.exists(path):
            os.remove(path)


def signed(harness):
    if not os.path.exists(harness.sig_log):
        return False
    with open(harness.sig_log, encoding="utf-8") as f:
        return any("-Y sign" in line for line in f)


def published(harness):
    for call in _gh_calls(harness):
        if call[:2] in (["release", "create"], ["release", "edit"], ["release", "upload"]):
            return True
    return False


def posted_to_x(harness):
    needles = ("tweet", "twitter", "x.com", "create_post")
    for call in _gh_calls(harness):
        blob = " ".join(call).lower()
        if any(n in blob for n in needles):
            return True
    return False


def artifact_extracted(harness):
    """True when stub gh was asked to download the unsigned artifact into a --dir."""
    for call in _gh_calls(harness):
        if call[:2] == ["run", "download"] and "--dir" in call and "kt-release-unsigned" in call:
            return True
    return False


def _gh_calls(harness):
    if not os.path.exists(harness.log):
        return []
    calls = []
    with open(harness.log, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                calls.append(json.loads(line))
    return calls


def _copy_unsigned_artifact(harness, dest):
    os.makedirs(dest, exist_ok=True)
    for name in os.listdir(harness.unsigned):
        src = os.path.join(harness.unsigned, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(dest, name))
    with open(os.path.join(dest, "pipeline-health.json"), "w", encoding="utf-8") as f:
        f.write("{}\n")
    return dest


def prove_fail(harness):
    """Stale generated_at via --run-id: health FAIL, no sign, no publish."""
    reset_logs(harness)
    art = _copy_unsigned_artifact(harness, os.path.join(harness.tmp, "fail-artifact"))
    rc, out = harness.run_script(
        "--run-id", "1", "--dry-run", "--accept-breaker", "--bootstrap",
        env_extra={"STUB_GH_ARTIFACT": art, "KT_NOW": "2026-11-29T06:17:00Z"},
    )
    return _result("fail", rc, out, harness, expect_hold=False)


def prove_hold(harness):
    """Size-jump HOLD via --run-id plus a signed pointer-only previous release."""
    reset_logs(harness)
    root = os.path.join(harness.tmp, "root")
    src = fetch_all(harness.tmp, root)
    prev_full = os.path.join(harness.tmp, "hold-prev-full")
    B.build(src, prev_full, bootstrap=True, now=T0, root=root)
    later = T0 + dt.timedelta(hours=1)
    later_iso = later.strftime("%Y-%m-%dT%H:%M:%SZ")
    art = os.path.join(harness.tmp, "hold-artifact")
    B.build(src, art, previous_dir=prev_full, bootstrap=False, now=later, root=root)
    with open(os.path.join(art, "pipeline-health.json"), "w", encoding="utf-8") as f:
        f.write("{}\n")
    prev = os.path.join(harness.tmp, "hold-prev")
    os.makedirs(prev)
    for name in FILES:
        shutil.copy(os.path.join(prev_full, name), os.path.join(prev, name))
    man = load(os.path.join(prev, "manifest.json"))
    for shard in man.get("shards") or []:
        shard["gzip_bytes"] = 1
    man_path = os.path.join(prev, "manifest.json")
    write_canonical(man_path, man)
    with open(man_path, "rb") as fh:
        raw = fh.read()
    latest_path = os.path.join(prev, "latest.json")
    latest = load(latest_path)
    latest["assets"]["manifest.json"] = {"sha256": sha256_bytes(raw), "bytes": len(raw)}
    write_canonical(latest_path, latest)
    sign_dir(prev, harness.key)
    rc, out = harness.run_script(
        "--run-id", "1", "--dry-run", "--accept-breaker",
        env_extra={"STUB_GH_ARTIFACT": art, "STUB_GH_PREV": prev, "KT_NOW": later_iso},
    )
    return _result("hold", rc, out, harness, expect_hold=True)


def _result(case, rc, out, harness, expect_hold):
    did_sign = signed(harness)
    did_pub = published(harness)
    did_x = posted_to_x(harness)
    extracted = artifact_extracted(harness)
    if expect_hold:
        blocked = rc != 0 and "pipeline health hold" in out and "DRY RUN OK" not in out
    else:
        blocked = rc != 0 and "pipeline health check failed" in out and "DRY RUN OK" not in out
    ok = blocked and not did_sign and not did_pub and not did_x and extracted
    return {
        "case": case,
        "ok": ok,
        "blocked": blocked,
        "signed": did_sign,
        "published": did_pub,
        "x_post": did_x,
        "artifact_extracted": extracted,
        "rc": rc,
        "out": out,
    }


def format_line(result):
    return (
        "RELEASE_GATE_PROVE case=%s result=%s sign=%s publish=%s x_post=%s artifact_extracted=%s"
        % (
            result["case"],
            "blocked" if result["ok"] else "LEAK",
            "yes" if result["signed"] else "no",
            "yes" if result["published"] else "no",
            "yes" if result["x_post"] else "no",
            "yes" if result["artifact_extracted"] else "no",
        )
    )


def main(argv):
    case = (argv[1] if len(argv) > 1 else os.environ.get("PROVE_CASE", "fail")).strip().lower()
    if case not in ("fail", "hold"):
        sys.stderr.write("prove_release_gate: case must be fail or hold\n")
        return 2
    harness = SignAndReleaseBase("setUp")
    harness.setUp()
    try:
        result = prove_fail(harness) if case == "fail" else prove_hold(harness)
        print(format_line(result))
        if not result["ok"]:
            sys.stderr.write(result["out"] + "\n")
            return 1
        return 0
    finally:
        harness.doCleanups()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
