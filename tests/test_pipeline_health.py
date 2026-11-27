"""Daily pipeline health check (SPEC.md §7.5). All checks are local; no network."""
import datetime as dt
import io
import contextlib
import os
import shutil
import unittest

from kt import build as B
from kt import health as H
from kt.common import canonical_json, sha256_bytes
from tests.helpers import REPO, T0, T0_ISO, fetch_all, load, make_root, tmpdir

T1 = T0 + dt.timedelta(days=1)
T1_ISO = "2026-11-28T06:17:00Z"


def write_canonical(path, doc):
    with open(path, "wb") as f:
        f.write(canonical_json(doc))


class HealthCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.root = make_root(self.tmp)
        self.src = fetch_all(self.tmp, self.root)

    def build(self, name="r1", now=T0, previous=None):
        out = os.path.join(self.tmp, name)
        B.build(self.src, out, previous_dir=previous, bootstrap=previous is None, now=now, root=self.root)
        return out

    def check(self, release, previous=None, now=T0, **kw):
        return H.check_release(release, previous, now=now, root=self.root, **kw)


class TestHealthPassAndHolds(HealthCase):
    def test_fresh_bootstrap_is_ok(self):
        out = self.build()
        report = self.check(out)
        self.assertEqual(report["status"], "ok", report["failed"] + report["holds"])
        names = [c["name"] for c in report["checks"]]
        self.assertIn("build", names)
        self.assertIn("canaries", names)
        self.assertIn("sources", names)
        self.assertIn("dates", names)
        self.assertIn("size", names)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main([out, "--now", T0_ISO, "--out", os.path.join(out, "pipeline-health.json"),
                                     "--root", self.root]), 0)
        self.assertTrue(os.path.isfile(os.path.join(out, "pipeline-health.json")))

    def test_missing_shard_is_fail(self):
        out = self.build()
        m = load(os.path.join(out, "manifest.json"))
        target = next(s["file"] for s in m["shards"])
        os.remove(os.path.join(out, target))
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("missing shards" in x for x in report["failed"]))

    def test_shard_hash_mismatch_is_fail(self):
        out = self.build()
        m = load(os.path.join(out, "manifest.json"))
        path = os.path.join(out, m["shards"][0]["file"])
        with open(path, "ab") as f:
            f.write(b"\n")
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("hash/size mismatch" in x for x in report["failed"]))

    def test_generated_at_not_today_is_fail(self):
        out = self.build()
        report = self.check(out, now=T0 + dt.timedelta(days=1))
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("not today's date" in x for x in report["failed"]))

    def test_generated_at_in_the_future_is_fail(self):
        out = self.build(now=T0 + dt.timedelta(hours=2))
        report = self.check(out, now=T0)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("in the future" in x for x in report["failed"]))

    def test_first_seen_after_generated_at_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        victim = next(e for e in iocs["entries"] if not e["canary"])
        victim["first_seen"] = "2026-11-28T00:00:00Z"
        write_canonical(iocs_path, iocs)
        # latest still points at the old iocs hash; health dates check reads iocs first
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("first_seen after generated_at" in x or "validate" in x
                            for x in report["failed"]))

    def test_missing_canary_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        for e in iocs["entries"]:
            if e["canary"]:
                e["canary"] = False
                break
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("canaries" in x or "canary" in x.lower() for x in report["failed"]))

    def test_carried_over_source_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        for s in iocs["sources"]:
            if s["id"] == "cisa-kev":
                s["status"] = "carried_over"
                break
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("carried over" in x for x in report["failed"]))

    def test_source_with_no_entries_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        iocs["entries"] = [e for e in iocs["entries"] if e.get("canary") or not e["id"].startswith("kev:")]
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("no list entries" in x for x in report["failed"]))

    def test_silent_osv_gap_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        old = "2026-11-20T00:00:00Z"  # 7 days before T0; OSV gap is 3 days
        for e in iocs["entries"]:
            if (not e["canary"]) and ":npm:" in e["id"]:
                e["first_seen"] = old
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("osv-npm added nothing" in x for x in report["failed"]))

    def test_silent_kev_gap_is_fourteen_days(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        # 10 days old: still within the 14-day KEV gap
        mid = "2026-11-17T00:00:00Z"
        for e in iocs["entries"]:
            if (not e["canary"]) and e["id"].startswith("kev:"):
                e["first_seen"] = mid
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertFalse(any("cisa-kev added nothing" in x for x in report["failed"]), report["failed"])
        # 16 days old: over the gap
        old = "2026-11-11T00:00:00Z"
        iocs = load(iocs_path)
        for e in iocs["entries"]:
            if (not e["canary"]) and e["id"].startswith("kev:"):
                e["first_seen"] = old
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("cisa-kev added nothing" in x for x in report["failed"]))

    def test_size_jump_is_a_hold(self):
        prev = self.build("prev")
        cur = self.build("cur", now=T1, previous=prev)
        ok = self.check(cur, previous=prev, now=T1)
        self.assertEqual(ok["status"], "ok", ok["failed"] + ok["holds"])
        # Shrink the previous shard files so today's gzip sizes look like a jump.
        for name in os.listdir(prev):
            if name.startswith("shard-") and name.endswith(".json"):
                with open(os.path.join(prev, name), "wb") as f:
                    f.write(b"{}\n")
        report = self.check(cur, previous=prev, now=T1)
        self.assertEqual(report["status"], "hold", report)
        self.assertTrue(report["holds"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main([cur, "--previous", prev, "--now", T1_ISO, "--root", self.root]), 2)

    def test_unsigned_signed_flag_without_sigs_is_fail(self):
        out = self.build()
        report = self.check(out, signed=True,
                            allowed_signers=os.path.join(self.root, "config", "allowed_signers"))
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any(x.startswith("signing:") for x in report["failed"]))

    def test_no_shards_mode_skips_missing_shards(self):
        out = self.build()
        for name in os.listdir(out):
            if name.startswith("shard-"):
                os.remove(os.path.join(out, name))
        report = self.check(out, require_shards=False)
        self.assertEqual(report["status"], "ok", report["failed"])

    def test_module_does_not_touch_the_network(self):
        path = os.path.join(REPO, "kt", "health.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        for needle in ("urllib", "http.client", "requests", "socket", "gh ", "github.com"):
            self.assertNotIn(needle, src, needle)



@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class TestHealthSigned(HealthCase):
    def test_signed_release_passes(self):
        from tests.test_sign_verify import keygen, sign_dir
        keys = os.path.join(self.tmp, "keys")
        os.makedirs(keys)
        key, pub = keygen(keys, "cur")
        allowed = os.path.join(self.tmp, "allowed")
        with open(allowed, "w") as f:
            f.write('kings-taster-current namespaces="kings-taster" %s\n' % pub)
        out = self.build()
        sign_dir(out, key)
        report = self.check(out, signed=True, allowed_signers=allowed)
        self.assertEqual(report["status"], "ok", report["failed"] + report["holds"])


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class TestHealthSignAndRelease(unittest.TestCase):
    def setUp(self):
        from tests.test_sign_verify import SignAndReleaseBase
        self.harness = SignAndReleaseBase("setUp")
        self.harness.setUp()

    def test_sign_and_release_refuses_stale_generated_at(self):
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra={"KT_NOW": "2026-11-29T06:17:00Z"})
        self.assertEqual(rc, 1, out)
        self.assertIn("pipeline health check failed", out)

    def test_same_day_dry_run_still_publishes_nothing_and_passes(self):
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker")
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)
