"""Daily pipeline health check (SPEC.md §7.5). All checks are local; no network."""
import datetime as dt
import io
import json
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

    def test_pre_sign_uses_age_bound_not_calendar_day(self):
        out = self.build()
        morning = T0 + dt.timedelta(hours=18)
        report = self.check(out, now=morning, pre_sign=True)
        self.assertEqual(report["status"], "ok", report["failed"] + report["holds"])
        stale = T0 + dt.timedelta(hours=27)
        report = self.check(out, now=stale, pre_sign=True)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("older than" in x for x in report["failed"]), report["failed"])

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

    def _shrink_prev_manifest(self, prev):
        man = load(os.path.join(prev, "manifest.json"))
        for s in man["shards"]:
            s["gzip_bytes"] = 1
        write_canonical(os.path.join(prev, "manifest.json"), man)

    def test_size_jump_is_a_hold(self):
        prev = self.build("prev")
        cur = self.build("cur", now=T1, previous=prev)
        ok = self.check(cur, previous=prev, now=T1)
        self.assertEqual(ok["status"], "ok", ok["failed"] + ok["holds"])
        # Compare gzip_bytes from the signed manifests, not on-disk shards.
        self._shrink_prev_manifest(prev)
        report = self.check(cur, previous=prev, now=T1)
        self.assertEqual(report["status"], "hold", report)
        self.assertTrue(report["holds"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main([cur, "--previous", prev, "--now", T1_ISO, "--root", self.root]), H.EXIT_HOLD)

    def test_size_jump_holds_when_previous_has_only_pointer_files(self):
        prev = self.build("prev")
        cur = self.build("cur", now=T1, previous=prev)
        prev_ptr = os.path.join(self.tmp, "prev-ptr")
        os.makedirs(prev_ptr)
        for name in ("latest.json", "iocs.json", "conformance.json", "stats.json", "manifest.json"):
            shutil.copyfile(os.path.join(prev, name), os.path.join(prev_ptr, name))
        self._shrink_prev_manifest(prev_ptr)
        report = self.check(cur, previous=prev_ptr, now=T1)
        self.assertEqual(report["status"], "hold", report)
        self.assertTrue(any("gzip size jumped" in x for x in report["holds"]))

    def test_canary_wrong_match_key_is_fail(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        for e in iocs["entries"]:
            if e.get("canary"):
                e["match_key"] = "npm:not-a-canary"
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertTrue(any("match_key" in x for x in report["failed"]), report["failed"])

    def _canary_check(self, report):
        return next(c for c in report["checks"] if c["name"] == "canaries")

    def test_canary_flag_on_a_real_entry_is_fail(self):
        # N1: canary:true on a real OSV/KEV entry (own id, own match_key) must not pass
        # health or validate; otherwise the checker would skip it as a canary.
        from kt import validate as V
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        victim = next(e for e in iocs["entries"] if not e["canary"] and e["type"] == "package")
        self.assertFalse(victim["id"].startswith("canary:"))
        victim["canary"] = True
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])
        self.assertTrue(any(x.startswith("canaries:") for x in report["failed"]), report["failed"])
        errs = V.validate_iocs(iocs, root=self.root)
        self.assertTrue(any("canary" in e for e in errs), errs)
        self.assertTrue(any("canary" in e for e in V.validate_release_dir(out, now=T0, root=self.root)))

    def test_canary_flag_on_real_entry_with_canary_key_is_fail(self):
        # Same as above but the flagged real entry copies a canary's match_key, so a
        # subset check on keys alone would pass; counts must match exactly.
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        canary = next(e for e in iocs["entries"] if e["canary"] and e["type"] == "package")
        victim = next(e for e in iocs["entries"] if not e["canary"] and e["type"] == "package"
                      and e["ecosystem"] == canary["ecosystem"])
        victim["canary"] = True
        victim["match_key"] = canary["match_key"]
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])

    def test_duplicate_configured_canary_key_is_fail(self):
        # N1 counts: an extra flagged entry whose id starts with canary: and whose
        # match_key copies a configured canary must fail (a set-subset check would pass).
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        canary = next(e for e in iocs["entries"] if e["canary"])
        extra = dict(canary)
        extra["id"] = canary["id"] + "-dup"
        self.assertTrue(extra["id"].startswith("canary:"))
        iocs["entries"].append(extra)
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])
        self.assertTrue(any("match_key" in x for x in report["failed"]), report["failed"])

    def test_missing_canary_config_is_fail(self):
        # N2: no config/canaries.json must fail the check, not mean "no expected keys".
        out = self.build()
        os.remove(os.path.join(self.root, "config", "canaries.json"))
        report = self.check(out)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main([out, "--now", T0_ISO, "--out", os.path.join(self.tmp, "h.json"),
                                     "--root", self.root]), H.EXIT_FAIL)

    def test_corrupt_canary_config_is_fail(self):
        out = self.build()
        path = os.path.join(self.root, "config", "canaries.json")
        for raw in ("{not-json", '{"list": []}', '{"list": "x"}', "[]"):
            with open(path, "w", encoding="utf-8") as f:
                f.write(raw)
            report = self.check(out)
            self.assertEqual(report["status"], "fail", raw)
            self.assertEqual(self._canary_check(report)["status"], "fail", (raw, report["checks"]))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main([out, "--now", T0_ISO, "--out", os.path.join(self.tmp, "h.json"),
                                     "--root", self.root]), H.EXIT_FAIL)

    def test_unflagged_canary_id_is_fail_even_without_shards(self):
        # N8: a real entry with a canary: id but no canary flag must fail health
        # (watchdog shape: no shards required), as validate already does.
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        extra = next(dict(e) for e in iocs["entries"] if not e["canary"])
        extra["id"] = "canary:sneaky"
        extra["canary"] = False
        iocs["entries"].append(extra)
        write_canonical(iocs_path, iocs)
        report = self.check(out, require_shards=False)
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])
        self.assertTrue(any(x.startswith("canaries:") for x in report["failed"]), report["failed"])

    def test_swapped_domain_and_ip_canary_keys_fail_health_and_validate(self):
        # N9: the key list alone is a multiset; keys must be bound to their types.
        from kt import validate as V
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        dom = next(e for e in iocs["entries"] if e["canary"] and e["type"] == "domain")
        ip = next(e for e in iocs["entries"] if e["canary"] and e["type"] == "ip")
        dom["match_key"], ip["match_key"] = ip["match_key"], dom["match_key"]
        write_canonical(iocs_path, iocs)
        report = self.check(out)
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])
        errs = V.validate_iocs(iocs, root=self.root)
        self.assertTrue(any("canary match_keys differ" in e for e in errs), errs)

    def test_non_string_canary_value_returns_none(self):
        # N7: AttributeError from match_key must not escape list_canary_keys.
        from kt import validate as V
        out = self.build()
        path = os.path.join(self.root, "config", "canaries.json")
        doc = load(path)
        doc["list"][2]["value"] = 5
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        self.assertIsNone(V.list_canary_keys(self.root))
        report = self.check(out)
        self.assertEqual(self._canary_check(report)["status"], "fail", report["checks"])

    def test_alert_after_hours_must_be_a_sane_positive_int(self):
        # N13: a huge value must not let an old artifact pass the pre-sign date check.
        out = self.build()
        stale = T0 + dt.timedelta(days=30)
        for bad in (10 ** 30, 73, 0, -1, "26", 26.0, True, None):
            with self.subTest(bad=bad):
                report = self.check(out, now=stale, pre_sign=True, limits={"alert_after_hours": bad})
                self.assertEqual(report["status"], "fail", report["checks"])
                dates = next(c for c in report["checks"] if c["name"] == "dates")
                self.assertEqual(dates["status"], "fail")
        ok_now = T0 + dt.timedelta(hours=70)
        report = self.check(out, now=ok_now, pre_sign=True, limits={"alert_after_hours": 72})
        dates = next(c for c in report["checks"] if c["name"] == "dates")
        self.assertEqual(dates["status"], "ok", dates)

    def test_abbreviated_flags_are_refused_and_full_flags_work(self):
        out = self.build()
        h = os.path.join(self.tmp, "h.json")
        for flag in (["--o", h], ["--r", self.root], ["--allowed", "x"], ["--prev", out], ["--pre"]):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                # main() maps argparse's status 2 to EXIT_FAIL, not a hold.
                self.assertEqual(H.main([out, "--now", T0_ISO] + flag), H.EXIT_FAIL)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(H.main([out, "--now", T0_ISO, "--out", h, "--root", self.root,
                                     "--pre-sign"]), H.EXIT_OK)
            self.assertEqual(H.main(["--help"]), H.EXIT_OK)

    def test_crash_report_keeps_parsed_flags(self):
        # N6: a crash after parse_args records the flags that were actually given.
        import json
        out = self.build()
        with open(os.path.join(out, "latest.json"), "w") as f:
            f.write("{not-json")
        dest = os.path.join(self.tmp, "pipeline-health.json")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = H.main([out, "--now", T0_ISO, "--out", dest, "--root", self.root, "--signed", "--no-shards"])
        self.assertEqual(rc, H.EXIT_FAIL)
        with open(dest, encoding="utf-8") as f:
            doc = json.loads(f.read())
        self.assertEqual(doc["status"], "fail")
        self.assertIs(doc["signed"], True)
        self.assertIs(doc["require_shards"], False)

    def test_silent_gap_uses_full_elapsed_seconds(self):
        out = self.build()
        iocs_path = os.path.join(out, "iocs.json")
        iocs = load(iocs_path)
        # 3 days + 1 hour before T0: .days would be 3 (not a fail); total_seconds is.
        almost = "2026-11-24T05:17:00Z"
        for e in iocs["entries"]:
            if (not e["canary"]) and e["id"].startswith("kev:"):
                e["first_seen"] = almost
        write_canonical(iocs_path, iocs)
        report = self.check(out, now=T0, limits={"cisa_kev_gap_days": 3, "osv_mal_gap_days": 3})
        self.assertEqual(report["status"], "fail", report)
        self.assertTrue(any("cisa-kev added nothing" in x for x in report["failed"]))

    def test_usage_error_is_fail_not_hold(self):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(H.main(["--not-a-flag"]), H.EXIT_FAIL)
            self.assertNotEqual(H.main(["--not-a-flag"]), H.EXIT_HOLD)

    def test_corrupt_latest_writes_fail_report(self):
        out = self.build()
        with open(os.path.join(out, "latest.json"), "w") as f:
            f.write("{not-json")
        dest = os.path.join(self.tmp, "pipeline-health.json")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = H.main([out, "--now", T0_ISO, "--out", dest, "--root", self.root])
        self.assertEqual(rc, H.EXIT_FAIL)
        self.assertTrue(os.path.isfile(dest))
        import json
        with open(dest, encoding="utf-8") as f:
            doc = json.loads(f.read())
        self.assertEqual(doc["status"], "fail")
        self.assertTrue(doc["failed"])

    def test_write_report_replaces_a_symlink_at_the_path(self):
        dest = os.path.join(self.tmp, "pipeline-health.json")
        target = os.path.join(self.tmp, "elsewhere.json")
        with open(target, "w") as f:
            f.write("old\n")
        os.symlink(target, dest)
        H.write_report(dest, {"status": "ok", "failed": [], "holds": []})
        self.assertFalse(os.path.islink(dest))
        with open(target, encoding="utf-8") as f:
            self.assertEqual(f.read(), "old\n")

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

    def tearDown(self):
        self.harness.doCleanups()

    def test_sign_and_release_refuses_stale_generated_at(self):
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra={"KT_NOW": "2026-11-29T06:17:00Z"})
        self.assertEqual(rc, 1, out)
        self.assertIn("pipeline health check failed", out)
        self.assertNotIn("DRY RUN OK", out)
        from tests.prove_release_gate import signed, published
        self.assertFalse(signed(self.harness), out)
        self.assertFalse(published(self.harness), out)

    def test_same_day_dry_run_still_publishes_nothing_and_passes(self):
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker")
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)

    def test_sign_and_release_allows_next_utc_morning_within_age_bound(self):
        # Built at 2026-11-27T06:17Z; signed the next UTC morning (~18 hours later).
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra={"KT_NOW": "2026-11-28T00:30:00Z"})
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)

    def test_run_id_accepts_pipeline_health_json_in_the_artifact(self):
        art = os.path.join(self.harness.tmp, "artifact")
        os.makedirs(art)
        for name in os.listdir(self.harness.unsigned):
            src = os.path.join(self.harness.unsigned, name)
            if os.path.isfile(src):
                shutil.copy(src, os.path.join(art, name))
        with open(os.path.join(art, "pipeline-health.json"), "w") as f:
            f.write("{}\n")
        rc, out = self.harness.run_script(
            "--run-id", "1", "--dry-run", "--accept-breaker", "--bootstrap",
            env_extra={"STUB_GH_ARTIFACT": art})
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)
        self.assertNotIn("unexpected file", out)

    def _stub_health_exit(self, code):
        path = os.path.join(self.harness.repo, "kt", "health.py")
        with open(path, "w") as f:
            f.write("import os, sys\n"
                    "if __name__ == \"__main__\":\n"
                    "    sys.exit(int(os.environ[\"KT_HEALTH_EXIT\"]))\n")
        return {"KT_HEALTH_EXIT": str(code)}

    def test_unexpected_health_exit_refuses_to_sign(self):
        env = self._stub_health_exit(137)
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra=env)
        self.assertEqual(rc, 1, out)
        self.assertIn("pipeline health check failed (exit 137)", out)
        self.assertNotIn("DRY RUN OK", out)
        from tests.prove_release_gate import signed, published
        self.assertFalse(signed(self.harness), out)
        self.assertFalse(published(self.harness), out)

    def test_health_exit_two_is_not_a_hold(self):
        env = self._stub_health_exit(2)
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra=env)
        self.assertEqual(rc, 1, out)
        self.assertIn("pipeline health check failed (exit 2)", out)
        self.assertNotIn("health hold", out)
        self.assertNotIn("DRY RUN OK", out)

    def test_accept_health_allows_hold_exit(self):
        env = self._stub_health_exit(10)
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            env_extra=env)
        self.assertEqual(rc, 1, out)
        self.assertIn("pipeline health hold", out)
        rc, out = self.harness.run_script(
            "--from-dir", self.harness.unsigned, "--dry-run", "--accept-breaker",
            "--accept-health", env_extra=env)
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)
        self.assertIn("health hold accepted by operator", out)

    def test_fail_dry_run_does_not_sign_or_publish(self):
        from tests.prove_release_gate import format_line, prove_fail
        result = prove_fail(self.harness)
        self.assertTrue(result["ok"], format_line(result) + "\n" + result["out"])
        self.assertFalse(result["signed"])
        self.assertFalse(result["published"])
        self.assertFalse(result["x_post"])
        self.assertTrue(result["artifact_extracted"])

    def test_hold_dry_run_does_not_sign_or_publish(self):
        from tests.prove_release_gate import format_line, prove_hold
        result = prove_hold(self.harness)
        self.assertTrue(result["ok"], format_line(result) + "\n" + result["out"])
        self.assertFalse(result["signed"])
        self.assertFalse(result["published"])
        self.assertFalse(result["x_post"])
        self.assertTrue(result["artifact_extracted"])
