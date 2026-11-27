"""List-refresh and weekly health skills (SPEC.md §4B, §4D). No network."""
import datetime as dt
import os
import re
import shutil
import unittest

from kt import build as B
from kt import client_health as H
from kt import refresh as R
from tests.helpers import REPO, T0, T0_ISO, fetch_all, load, make_root, tmpdir

UNCLEARED = re.compile(
    r"abuse\.ch|feodo|ssl blacklist|urlhaus|threatfox|safedep|stepsecurity",
    re.IGNORECASE,
)
T1 = T0 + dt.timedelta(days=1)
T1_ISO = "2026-11-28T06:17:00Z"


def _write(path, body):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    mode = "wb" if isinstance(body, bytes) else "w"
    with open(path, mode, encoding=None if isinstance(body, bytes) else "utf-8") as f:
        f.write(body)


class TestSkillAndRoutineCaps(unittest.TestCase):
    def test_refresh_caps_and_routine(self):
        body, cmd = R.split_skill()
        self.assertLessEqual(R.word_count(body), R.WORD_CAP)
        self.assertGreater(R.word_count(body), 80)
        self.assertLessEqual(R.command_line_count(cmd), R.COMMAND_LINE_CAP)
        self.assertEqual(R.routine_line(), R.ROUTINE_LINE)
        self.assertEqual(R.routine_line(), "Run kings-taster-list-refresh.")
        self.assertFalse(R.body_banned_words(body))
        text = R.skill_text()
        for needle in ("scripts/verify.sh", "--update-state", "date -u",
                       "github.com/SoundMindsAI/kings-taster-data/releases/download",
                       "release-assets.githubusercontent.com", "injection_seen",
                       "48 hours", "~/.kings-taster/list/"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("is live and checking", text)

    def test_health_caps_and_routine(self):
        body, cmd = H.split_skill()
        self.assertLessEqual(H.word_count(body), H.WORD_CAP)
        self.assertGreater(H.word_count(body), 80)
        self.assertLessEqual(H.command_line_count(cmd), H.COMMAND_LINE_CAP)
        self.assertEqual(H.routine_line(), H.ROUTINE_LINE)
        self.assertEqual(H.routine_line(), "Run kings-taster-health.")
        self.assertFalse(H.body_banned_words(body))
        text = H.skill_text()
        for needle in ("scripts/verify.sh", "date -u", "health.json", "status: failing",
                       "Unknown, don't proceed (health check failing:",
                       "10 minutes", "48 hours", "conformance.json"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("Want to post", text)
        self.assertNotIn("is live and checking", text)
        self.assertEqual(len(H.LINE.split()), 25)
        self.assertIn(H.LINE, H.nudge_text("Installer"))

    def test_no_uncleared_wording(self):
        for text in (R.skill_text(), H.skill_text(), R.routine_line(), H.routine_line()):
            self.assertIsNone(UNCLEARED.search(text))

    def test_modules_have_no_network_or_live_poster(self):
        for path in (R.__file__, H.__file__):
            with open(path, encoding="utf-8") as f:
                src = f.read()
            for banned in ("import socket", "import urllib", "from urllib", "import http",
                           "urlopen", "import requests", "tweepy", "create_posts"):
                self.assertNotIn(banned, src, banned)


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class SignedCacheCase(unittest.TestCase):
    def setUp(self):
        from tests.test_sign_verify import keygen, sign_dir
        self.tmp = tmpdir(self)
        keys = os.path.join(self.tmp, "keys")
        os.makedirs(keys)
        self.key, pub = keygen(keys, "cur")
        self.allowed = os.path.join(self.tmp, "allowed")
        with open(self.allowed, "w") as f:
            f.write('kings-taster-current namespaces="kings-taster" %s\n' % pub)
        self.root = make_root(self.tmp)
        self.src = fetch_all(self.tmp, self.root)
        self.release = os.path.join(self.tmp, "rel")
        B.build(self.src, self.release, bootstrap=True, now=T0, root=self.root)
        sign_dir(self.release, self.key)
        self.cache = os.path.join(self.tmp, "cache")
        self.state = os.path.join(self.tmp, "verify-state.json")

    def seed_cache(self, release=None, shards=1):
        release = release or self.release
        os.makedirs(self.cache, exist_ok=True)
        for name in os.listdir(release):
            if name.startswith("shard-") and name.endswith(".json"):
                continue
            src = os.path.join(release, name)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(self.cache, name))
        chosen = [n for n in os.listdir(release)
                  if n.startswith("shard-") and n.endswith(".json")][:shards]
        for name in chosen:
            shutil.copyfile(os.path.join(release, name), os.path.join(self.cache, name))
        return chosen


class TestRefresh(SignedCacheCase):
    def test_unchanged_release_is_silent_and_does_not_refetch_shards(self):
        cached = self.seed_cache(shards=2)
        fetcher = R.LocalFetcher(self.release)
        out = R.refresh(self.cache, self.release, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["silent"])
        self.assertFalse(out["changed"])
        self.assertEqual(out["lines"], [])
        self.assertFalse(any(n in "".join(fetcher.gets) for n in cached))

    def test_empty_cache_fetches_signed_files_but_not_every_shard(self):
        fetcher = R.LocalFetcher(self.release)
        out = R.refresh(self.cache, self.release, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["silent"])
        fetched = set(out["fetched"])
        self.assertIn("latest.json", fetched)
        self.assertIn("manifest.json", fetched)
        self.assertFalse(any(n.startswith("shard-") for n in fetched))
        self.assertTrue(os.path.isfile(os.path.join(self.cache, "latest.json")))
        self.assertTrue(os.path.isfile(self.state))  # watermark written

    def test_only_changed_cached_shards_are_refetched(self):
        cached = self.seed_cache(shards=2)
        # A later release: refetch only if that shard's digest changed.
        later = os.path.join(self.tmp, "later")
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        fetcher = R.LocalFetcher(later)
        out = R.refresh(self.cache, later, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertTrue(out["ok"], out)
        shard_fetches = [u for u in fetcher.gets if "/shard-" in u]
        # At most the shards we already cached, never the whole set.
        self.assertLessEqual(len(shard_fetches), len(cached))
        self.assertLess(len(shard_fetches), 50)

    def test_failed_verify_keeps_the_last_good_cache(self):
        self.seed_cache(shards=1)
        before = load(os.path.join(self.cache, "latest.json"))
        bad = os.path.join(self.tmp, "bad")
        shutil.copytree(self.release, bad)
        with open(os.path.join(bad, "latest.json"), "ab") as f:
            f.write(b"\n")
        fetcher = R.LocalFetcher(bad)
        out = R.refresh(self.cache, bad, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertFalse(out["ok"])
        self.assertTrue(out["lines"])
        self.assertLessEqual(len(out["lines"]), 3)
        self.assertEqual(load(os.path.join(self.cache, "latest.json")), before)

    def test_stale_cached_list_is_reported(self):
        self.seed_cache(shards=0)
        later = T0 + dt.timedelta(hours=49)
        fetcher = R.LocalFetcher(self.release)
        out = R.refresh(self.cache, self.release, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state,
                        now=later.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertFalse(out["ok"])
        self.assertEqual(out["failed"], "stale_list")

    def test_disallowed_host_is_injection(self):
        self.assertFalse(R.list_url_allowed("https://evil.example/latest.json"))
        self.assertFalse(R.list_url_allowed(
            "https://github.com/SoundMindsAI/kings-taster-data/releases/download/../../evil/x"))
        self.assertTrue(R.list_url_allowed(
            "https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"))

    def test_promotion_crash_does_not_leave_a_mixed_cache(self):
        self.seed_cache(shards=1)
        before = load(os.path.join(self.cache, "latest.json"))
        later = os.path.join(self.tmp, "later")
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        real = os.rename
        def crash_before_install(src, dst):
            if os.path.abspath(dst) == os.path.abspath(self.cache):
                raise OSError("simulated crash before the new cache was installed")
            return real(src, dst)
        os.rename = crash_before_install
        try:
            with self.assertRaises(OSError):
                R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                          allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        finally:
            os.rename = real
        # Live cache is either absent (recovered on the next call) or still the old list.
        bak = R._bak_dir(self.cache)
        if os.path.isdir(self.cache) and os.path.isfile(os.path.join(self.cache, "latest.json")):
            after = load(os.path.join(self.cache, "latest.json"))
            self.assertEqual(after["generated_at"], before["generated_at"])
        elif os.path.isdir(bak):
            after = load(os.path.join(bak, "latest.json"))
            self.assertEqual(after["generated_at"], before["generated_at"])
        else:
            self.fail("expected the old cache in place or in the bak directory")
        # A later refresh recovers and installs one complete tree, never a mix.
        out = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertTrue(out["ok"], out)
        latest = load(os.path.join(self.cache, "latest.json"))
        manifest = load(os.path.join(self.cache, "manifest.json"))
        self.assertEqual(latest["generated_at"], manifest["generated_at"])
        self.assertEqual(latest["generated_at"], load(os.path.join(later, "latest.json"))["generated_at"])

    def test_leftover_shard_does_not_block_a_later_refresh(self):
        self.seed_cache(shards=1)
        orphan = os.path.join(self.cache, "shard-orphan-not-in-manifest.json")
        with open(orphan, "w", encoding="utf-8") as f:
            f.write('{}\n')
        later = os.path.join(self.tmp, "later")
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        out = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertTrue(out["ok"], out)
        self.assertFalse(os.path.isfile(os.path.join(self.cache, "shard-orphan-not-in-manifest.json")))
        self.assertEqual(load(os.path.join(self.cache, "latest.json"))["generated_at"],
                         load(os.path.join(later, "latest.json"))["generated_at"])

    def test_unchanged_path_re_verifies_and_does_not_accept_a_mixed_cache(self):
        self.seed_cache(shards=1)
        first = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                          allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(first["ok"], first)
        with open(os.path.join(self.cache, "shard-orphan-not-in-manifest.json"), "w", encoding="utf-8") as f:
            f.write('{}\n')
        out = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(out["ok"], out)
        self.assertTrue(out["silent"])
        self.assertFalse(os.path.isfile(os.path.join(self.cache, "shard-orphan-not-in-manifest.json")))

    def test_unchanged_path_and_default_state_write_the_watermark(self):
        self.seed_cache(shards=0)
        default = R.default_state_path(self.cache)
        self.assertFalse(os.path.exists(self.state))
        out = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                        allowed_signers=self.allowed, now=T0_ISO)  # state omitted
        self.assertTrue(out["ok"], out)
        self.assertTrue(os.path.isfile(default))
        # A second call on the unchanged list still writes/keeps the watermark.
        out2 = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                         allowed_signers=self.allowed, state=default, now=T0_ISO)
        self.assertTrue(out2["ok"], out2)
        self.assertTrue(os.path.isfile(default))
        # An older signed list is refused against that watermark (and the newer cache).
        later = os.path.join(self.tmp, "later")
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        newer = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                          allowed_signers=self.allowed, now=T1_ISO)
        self.assertTrue(newer["ok"], newer)
        before = load(os.path.join(self.cache, "latest.json"))
        back = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                         allowed_signers=self.allowed, now=T1_ISO)
        self.assertFalse(back["ok"], back)
        self.assertEqual(load(os.path.join(self.cache, "latest.json")), before)

    def test_cache_symlink_is_not_followed(self):
        victim_dir = os.path.join(self.tmp, "outside")
        os.makedirs(victim_dir)
        victim = os.path.join(victim_dir, "latest-victim")
        os.makedirs(self.cache, exist_ok=True)
        os.symlink(victim, os.path.join(self.cache, "latest.json"))
        out = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(out["ok"], out)
        self.assertFalse(os.path.exists(victim))
        self.assertTrue(os.path.isfile(os.path.join(self.cache, "latest.json")))
        self.assertFalse(os.path.islink(os.path.join(self.cache, "latest.json")))


class TestClientHealth(SignedCacheCase):
    def _health(self, **kw):
        kw.setdefault("cache_dir", self.cache)
        kw.setdefault("allowed_signers", self.allowed)
        kw.setdefault("state", self.state)
        kw.setdefault("now", T0_ISO)
        kw.setdefault("canaries", {"osv": True, "rdap": True})
        kw.setdefault("health_path", os.path.join(self.tmp, "health.json"))
        return H.run(**kw)

    def test_passing_weekly_run_is_silent(self):
        self.seed_cache(shards=1)
        out = self._health()
        self.assertTrue(out["silent"], out)
        self.assertEqual(out["lines"], [])
        self.assertFalse(out["failing"])
        self.assertEqual(out["health"]["status"], "ok")
        self.assertEqual(out["mode"], "checklist")
        self.assertIsNone(out["unknown_line"])

    def test_status_is_at_most_eight_lines(self):
        self.seed_cache(shards=1)
        out = self._health(status=True)
        self.assertFalse(out["silent"])
        self.assertLessEqual(len(out["lines"]), 8)
        self.assertGreaterEqual(len(out["lines"]), 6)
        blob = "\n".join(out["lines"])
        self.assertIn("List:", blob)
        self.assertIn("Canaries:", blob)
        self.assertIn("Checker:", blob)
        self.assertIn("Routing:", blob)
        self.assertIn("List date:", blob)
        self.assertIn("Mode:", blob)

    def test_stale_list_is_item1_failing(self):
        self.seed_cache(shards=1)
        later = T0 + dt.timedelta(hours=49)
        out = self._health(now=later.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertTrue(out["failing"])
        self.assertFalse(out["silent"])
        self.assertLessEqual(len(out["lines"]), 3)
        self.assertIn("older than 48 hours", out["health"]["items"]["list"]["detail"])
        self.assertTrue(out["unknown_line"].startswith("Unknown, don't proceed (health check failing:"))

    def test_future_date_is_item1_failing(self):
        self.seed_cache(shards=1)
        earlier = T0 - dt.timedelta(minutes=11)
        out = self._health(now=earlier.strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.assertTrue(out["failing"])
        self.assertIn("10 minutes ahead", out["health"]["items"]["list"]["detail"])

    def test_bad_signature_is_item1_failing(self):
        self.seed_cache(shards=1)
        with open(os.path.join(self.cache, "latest.json"), "ab") as f:
            f.write(b"\n")
        out = self._health()
        self.assertTrue(out["failing"])
        self.assertIn("did not verify", out["health"]["items"]["list"]["detail"])

    def test_oversized_shard_is_item1_failing(self):
        self.seed_cache(shards=1)
        import kt.verify as KV
        orig = KV.verify_release
        KV.verify_release = lambda *a, **k: (0, "VERIFIED")
        try:
            man = load(os.path.join(self.cache, "manifest.json"))
            name = man["shards"][0]["file"]
            path = os.path.join(self.cache, name)
            with open(path, "wb") as f:
                f.write(os.urandom(6 * 1024 * 1024))
            out = self._health()
        finally:
            KV.verify_release = orig
        self.assertTrue(out["failing"])
        self.assertIn("5 MB", out["health"]["items"]["list"]["detail"])

    def test_missing_list_canary_is_item2_failing(self):
        self.seed_cache(shards=1)
        iocs_path = os.path.join(self.cache, "iocs.json")
        iocs = load(iocs_path)
        for e in iocs["entries"]:
            if e.get("canary"):
                e["canary"] = False
        with open(iocs_path, "w", encoding="utf-8") as f:
            json_dump = __import__("json").dump
            json_dump(iocs, f)
        # Signature will fail because iocs changed; this test injects canaries= after
        # we need item 2 specifically. Tampering iocs breaks verify (item 1).
        # Use a verify stub so item 1 passes and item 2 can fail on its own.
        import kt.verify as KV
        orig = KV.verify_release
        KV.verify_release = lambda *a, **k: (0, "VERIFIED")
        try:
            out = self._health()
        finally:
            KV.verify_release = orig
        self.assertTrue(out["failing"])
        self.assertTrue(out["health"]["items"]["list"]["ok"])
        self.assertFalse(out["health"]["items"]["canaries"]["ok"])
        self.assertIn("canaries", out["health"]["items"]["canaries"]["detail"])

    def test_osv_canary_failure_is_item2(self):
        self.seed_cache(shards=1)
        out = self._health(canaries={"osv": False, "rdap": True})
        self.assertTrue(out["failing"])
        self.assertIn("OSV canary", out["health"]["items"]["canaries"]["detail"])

    def test_unset_safe_browsing_is_not_a_failure(self):
        self.seed_cache(shards=1)
        out = self._health(canaries={"osv": True, "rdap": True})  # sb omitted
        self.assertFalse(out["failing"])
        self.assertTrue(out["health"]["items"]["canaries"]["ok"])

    def test_changed_checker_switches_to_checklist_not_unknown(self):
        self.seed_cache(shards=1)
        out = self._health(checker={"sha256": "a" * 64, "approved_sha256": "b" * 64,
                                    "conformance_pass": True})
        self.assertFalse(out["failing"])
        self.assertIsNone(out["unknown_line"])
        self.assertEqual(out["mode"], "checklist")
        self.assertFalse(out["health"]["items"]["checker"]["ok"])
        self.assertFalse(out["silent"])
        self.assertLessEqual(len(out["lines"]), 3)
        self.assertTrue(any("checklist" in ln.lower() for ln in out["lines"]))

    def test_removed_routing_line_nudges_without_failing_checks(self):
        self.seed_cache(shards=1)
        out = self._health(routing={"covered": [{"name": "Installer", "line_present": False}]})
        self.assertFalse(out["failing"])
        self.assertIsNone(out["unknown_line"])
        self.assertIn(H.LINE, out["nudge"])
        self.assertIn("Installer", out["nudge"])
        self.assertFalse(out["silent"])

    def test_thirty_day_note_and_one_nudge_per_week(self):
        self.seed_cache(shards=1)
        out = self._health(routing={"covered": [
            {"name": "Installer", "line_present": False, "days_since_ask": 30},
        ], "already_nudged": ["Installer"]})
        self.assertIsNone(out["nudge"])  # already nudged this week
        self.assertTrue(any("30 days" in n for n in out["notes"]))

    def test_passing_status_clears_failing(self):
        self.seed_cache(shards=1)
        path = os.path.join(self.tmp, "health.json")
        failed = self._health(canaries={"osv": False, "rdap": True}, health_path=path)
        self.assertEqual(failed["health"]["status"], "failing")
        ok = self._health(canaries={"osv": True, "rdap": True}, health_path=path, status=True)
        self.assertEqual(ok["health"]["status"], "ok")
        self.assertIsNone(ok["unknown_line"])
        self.assertEqual(load(path)["status"], "ok")

    def test_missing_osv_or_rdap_canary_result_fails(self):
        self.seed_cache(shards=1)
        path = os.path.join(self.tmp, "health.json")
        for canaries in (None, {}, {"osv": True}, {"rdap": True}):
            out = self._health(canaries=canaries, health_path=path)
            self.assertTrue(out["failing"], canaries)
            self.assertFalse(out["health"]["items"]["canaries"]["ok"], canaries)
            self.assertFalse(out["silent"], canaries)

    def test_health_tmp_symlink_does_not_write_outside_the_state_dir(self):
        self.seed_cache(shards=1)
        victim_dir = os.path.join(self.tmp, "outside")
        os.makedirs(victim_dir)
        victim = os.path.join(victim_dir, "victim")
        health = os.path.join(self.tmp, "health.json")
        os.symlink(victim, health + ".tmp")
        out = self._health(health_path=health)
        self.assertFalse(out["failing"], out)
        self.assertFalse(os.path.exists(victim))
        self.assertTrue(os.path.isfile(health))
        self.assertFalse(os.path.islink(health))

    def test_weekly_nudge_is_persisted_and_locked(self):
        self.seed_cache(shards=1)
        path = os.path.join(self.tmp, "health.json")
        routing = {"covered": [{"name": "Installer", "line_present": False}]}
        first = self._health(routing=routing, health_path=path)
        self.assertIsNotNone(first["nudge"])
        self.assertIn(H.LINE, first["nudge"])
        self.assertTrue(os.path.isfile(path + ".lock"))
        doc = load(path)
        self.assertIn("Installer", doc.get("nudged") or [])
        second = self._health(routing=routing, health_path=path)
        self.assertIsNone(second["nudge"])
