"""List-refresh and weekly health skills (SPEC.md §4B, §4D). No network."""
import datetime as dt
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import threading
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
        official = "https://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"
        self.assertTrue(R.list_url_allowed(official))
        self.assertTrue(R.list_url_allowed(official + ".sig"))
        self.assertFalse(R.list_url_allowed("https://evil.example/latest.json"))
        self.assertFalse(R.list_url_allowed(
            "https://github.com/SoundMindsAI/kings-taster-data/releases/download/../../evil/x"))
        self.assertFalse(R.list_url_allowed(official.replace("https://", "http://")))
        self.assertFalse(R.list_url_allowed("http://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json.sig"))
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

    def _patch_watermark_verify_to_fail(self):
        """Make R._verify fail only when update_state is true. Returns the original."""
        real = R._verify

        def fake(dir_path, allowed, state, now, require_shards, update_state):
            if update_state:
                return 1, "simulated watermark write failure"
            return real(dir_path, allowed, state, now, require_shards, update_state)

        R._verify = fake
        return real

    def _assert_no_incoming_leftovers(self):
        parent = R._incoming_parent(self.cache)
        self.assertEqual([n for n in os.listdir(parent) if n.startswith(".incoming-")], [])

    def test_watermark_failure_after_promote_restores_the_previous_cache(self):
        self.seed_cache(shards=1)
        before = load(os.path.join(self.cache, "latest.json"))
        later = os.path.join(self.tmp, "later")
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        real = self._patch_watermark_verify_to_fail()
        try:
            out = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                            allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        finally:
            R._verify = real
        self.assertFalse(out["ok"], out)
        self.assertFalse(out["silent"])
        self.assertEqual(out["failed"], "unverified_list")
        self.assertIn("The last good cache was kept.", out["lines"])
        # The live cache is the T0 list again, as one complete tree.
        after = load(os.path.join(self.cache, "latest.json"))
        self.assertEqual(after["generated_at"], before["generated_at"])
        self.assertEqual(load(os.path.join(self.cache, "manifest.json"))["generated_at"],
                         before["generated_at"])
        self.assertFalse(os.path.exists(R._bak_dir(self.cache)))
        self._assert_no_incoming_leftovers()
        # With the watermark writable again, the later release installs normally.
        out2 = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                         allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertTrue(out2["ok"], out2)
        self.assertEqual(load(os.path.join(self.cache, "latest.json"))["generated_at"],
                         load(os.path.join(later, "latest.json"))["generated_at"])
        self.assertFalse(os.path.exists(R._bak_dir(self.cache)))

    def test_watermark_failure_on_unchanged_list_is_not_ok(self):
        self.seed_cache(shards=1)
        before = load(os.path.join(self.cache, "latest.json"))
        real = self._patch_watermark_verify_to_fail()
        try:
            out = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                            allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        finally:
            R._verify = real
        self.assertFalse(out["ok"], out)
        self.assertFalse(out["silent"])
        self.assertEqual(out["failed"], "unverified_list")
        self.assertIn("The last good cache was kept.", out["lines"])
        self.assertEqual(load(os.path.join(self.cache, "latest.json")), before)
        self.assertFalse(os.path.exists(R._bak_dir(self.cache)))
        self._assert_no_incoming_leftovers()

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


    def _later(self):
        later = os.path.join(self.tmp, "later-" + str(len(os.listdir(self.tmp))))
        B.build(self.src, later, previous_dir=self.release, bootstrap=False, now=T1, root=self.root)
        from tests.test_sign_verify import sign_dir
        sign_dir(later, self.key)
        return later

    def test_http_url_is_not_allowed(self):
        self.assertFalse(R.list_url_allowed(
            "http://github.com/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"))

    def test_disallowed_sig_url_is_injection(self):
        dest = os.path.join(self.tmp, "out.sig")
        fetcher = R.LocalFetcher(self.release)
        with self.assertRaises(ValueError) as ctx:
            fetcher.fetch("https://evil.example/latest.json.sig", dest)
        self.assertIn("injection", str(ctx.exception))
        self.assertFalse(os.path.exists(dest))

    def test_hostile_tag_is_refused_before_fetch(self):
        from tests.test_sign_verify import sign_dir
        bad = os.path.join(self.tmp, "hostile-tag")
        shutil.copytree(self.release, bad)
        latest_path = os.path.join(bad, "latest.json")
        latest = load(latest_path)
        latest["tag"] = "kt-../../evil"
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump(latest, f)
            f.write("\n")
        sign_dir(bad, self.key)
        fetcher = R.LocalFetcher(bad)
        out = R.refresh(self.cache, bad, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["failed"], "unverified_list")
        for url in fetcher.gets:
            self.assertNotIn("..", url)
            self.assertNotIn("/evil", url)

    def test_unverified_latest_is_refused_before_the_tag_is_used(self):
        bad = os.path.join(self.tmp, "unsigned-latest")
        shutil.copytree(self.release, bad)
        latest_path = os.path.join(bad, "latest.json")
        latest = load(latest_path)
        latest["tag"] = "kt-20990101T000000Z"
        with open(latest_path, "w", encoding="utf-8") as f:
            json.dump(latest, f)
            f.write("\n")
        # leave the old signature in place so verify_file fails
        fetcher = R.LocalFetcher(bad)
        out = R.refresh(self.cache, bad, fetcher=fetcher,
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["failed"], "unverified_list")
        self.assertFalse(any("20990101" in u for u in fetcher.gets), fetcher.gets)

    def test_lock_is_held_across_fetch_and_promote(self):
        later = self._later()
        self.seed_cache(shards=0)
        cache = self.cache
        held = {"fetch": [], "promote": [], "work": []}

        def lock_held():
            lock_path = os.path.abspath(cache) + ".lock"
            if not os.path.exists(lock_path):
                return False
            r = subprocess.run(
                [sys.executable, "-c",
                 "import fcntl,os,sys\n"
                 "fd=os.open(sys.argv[1], os.O_RDWR)\n"
                 "try:\n"
                 "    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
                 "    sys.exit(0)\n"
                 "except BlockingIOError:\n"
                 "    sys.exit(2)\n"
                 "finally:\n"
                 "    os.close(fd)\n",
                 lock_path],
                capture_output=True, timeout=10)
            return r.returncode == 2

        class Probe(R.LocalFetcher):
            def fetch(self, url, dest):
                held["fetch"].append(lock_held())
                work = os.path.dirname(os.path.abspath(dest))
                held["work"].append(work)
                return super().fetch(url, dest)

        orig = R._promote

        def probe_promote(work, cache_dir):
            held["promote"].append(lock_held())
            self.assertTrue(os.path.basename(work).startswith(".incoming-"))
            return orig(work, cache_dir)

        R._promote = probe_promote
        try:
            out = R.refresh(cache, later, fetcher=Probe(later),
                            allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        finally:
            R._promote = orig
        self.assertTrue(out["ok"], out)
        self.assertTrue(held["fetch"] and all(held["fetch"]), held)
        self.assertTrue(held["promote"] and all(held["promote"]), held)
        for work in held["work"]:
            self.assertNotEqual(work, os.path.abspath(cache) + ".incoming")
            self.assertTrue(os.path.basename(work).startswith(".incoming-"), work)

    def test_concurrent_refresh_keeps_a_verified_cache(self):
        from kt import verify as KV
        first = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                          allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(first["ok"], first)
        later = self._later()
        bad = os.path.join(self.tmp, "unverified-tree")
        shutil.copytree(later, bad)
        with open(os.path.join(bad, "latest.json"), "ab") as f:
            f.write(b"\n")
        errors = []
        outs = []

        def run(src, now):
            try:
                outs.append(R.refresh(self.cache, src, fetcher=R.LocalFetcher(src),
                                      allowed_signers=self.allowed, state=self.state, now=now))
            except Exception as e:
                errors.append(e)

        t_good = threading.Thread(target=run, args=(later, T1_ISO))
        t_bad = threading.Thread(target=run, args=(bad, T1_ISO))
        t_good.start()
        t_bad.start()
        t_good.join(timeout=60)
        t_bad.join(timeout=60)
        self.assertFalse(errors, errors)
        code, line = KV.verify_release(
            self.cache, self.allowed, state=self.state, now=T1,
            max_age_hours=48, require_shards=False)
        self.assertIn(code, (0, 3), line)

    def test_fetch_failure_on_latest_keeps_the_cache(self):
        first = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                          allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(first["ok"], first)
        before = load(os.path.join(self.cache, "latest.json"))

        class Boom(R.LocalFetcher):
            def fetch(self, url, dest):
                if url.endswith("latest.json") and not url.endswith(".sig"):
                    raise OSError("nope")
                return super().fetch(url, dest)

        later = self._later()
        out = R.refresh(self.cache, later, fetcher=Boom(later),
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertFalse(out["ok"])
        self.assertEqual(out["failed"], "check_failed")
        self.assertEqual(load(os.path.join(self.cache, "latest.json")), before)

    def test_fetch_failure_on_a_shard_keeps_the_cache(self):
        cached = self.seed_cache(shards=2)
        later = self._later()
        before = load(os.path.join(self.cache, "latest.json"))

        class Boom(R.LocalFetcher):
            def fetch(self, url, dest):
                if "/shard-" in url:
                    raise OSError("nope")
                return super().fetch(url, dest)

        out = R.refresh(self.cache, later, fetcher=Boom(later),
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        # If no cached shard digest changed, the fetch may not be attempted.
        if any(n.startswith("shard-") for n in (out.get("fetched") or [])) or out["failed"] == "check_failed":
            self.assertFalse(out["ok"])
            self.assertEqual(out["failed"], "check_failed")
            self.assertEqual(load(os.path.join(self.cache, "latest.json")), before)
        else:
            # No refetch was needed; still must leave a verified cache.
            self.assertTrue(out["ok"] or out["failed"] == "check_failed", out)

    def test_corrupt_verify_state_is_unverified(self):
        with open(self.state, "w", encoding="utf-8") as f:
            f.write("[]\n")
        out = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["failed"], "unverified_list")

    def test_manifest_array_is_unverified(self):
        class Swap(R.LocalFetcher):
            def fetch(self, url, dest):
                super().fetch(url, dest)
                if url.endswith("manifest.json") and not url.endswith(".sig"):
                    with open(dest, "w", encoding="utf-8") as f:
                        f.write("[]\n")

        out = R.refresh(self.cache, self.release, fetcher=Swap(self.release),
                        allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertFalse(out["ok"], out)
        self.assertEqual(out["failed"], "unverified_list")

    def test_bak_symlink_does_not_block_promote(self):
        first = R.refresh(self.cache, self.release, fetcher=R.LocalFetcher(self.release),
                          allowed_signers=self.allowed, state=self.state, now=T0_ISO)
        self.assertTrue(first["ok"], first)
        bak = R._bak_dir(self.cache)
        os.symlink(os.path.join(self.tmp, "nowhere"), bak)
        later = self._later()
        out = R.refresh(self.cache, later, fetcher=R.LocalFetcher(later),
                        allowed_signers=self.allowed, state=self.state, now=T1_ISO)
        self.assertTrue(out["ok"], out)
        self.assertFalse(os.path.islink(bak))
        self.assertFalse(os.path.exists(bak))
        from kt import verify as KV
        code, line = KV.verify_release(
            self.cache, self.allowed, state=self.state, now=T1,
            max_age_hours=48, require_shards=False)
        self.assertIn(code, (0, 3), line)


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
        # After verify has passed, item 1 reads the signed manifest's gzip_bytes
        # rather than recompressing. The manifest here honestly records the
        # oversized shard, so the verified path must still fail on the cap.
        from kt.shards import gzip_size
        self.seed_cache(shards=1)
        import kt.verify as KV
        orig = KV.verify_release
        KV.verify_release = lambda *a, **k: (0, "VERIFIED")
        try:
            man_path = os.path.join(self.cache, "manifest.json")
            man = load(man_path)
            name = man["shards"][0]["file"]
            raw = os.urandom(6 * 1024 * 1024)
            _write(os.path.join(self.cache, name), raw)
            man["shards"][0]["gzip_bytes"] = gzip_size(raw)
            self.assertGreater(man["shards"][0]["gzip_bytes"], H.MAX_SHARD_GZIP_BYTES)
            _write(man_path, json.dumps(man))
            out = self._health()
        finally:
            KV.verify_release = orig
        self.assertTrue(out["failing"])
        self.assertIn("5 MB", out["health"]["items"]["list"]["detail"])

    def test_verified_manifest_gzip_bytes_over_cap_fails_even_with_a_small_shard(self):
        self.seed_cache(shards=1)
        import kt.verify as KV
        orig = KV.verify_release
        KV.verify_release = lambda *a, **k: (0, "VERIFIED")
        try:
            man_path = os.path.join(self.cache, "manifest.json")
            man = load(man_path)
            # Pick a shard that is actually cached; seed_cache copies by directory order.
            entry = next(s for s in man["shards"]
                         if os.path.isfile(os.path.join(self.cache, s["file"])))
            shard = os.path.join(self.cache, entry["file"])
            self.assertLess(os.path.getsize(shard), H.MAX_SHARD_GZIP_BYTES)
            entry["gzip_bytes"] = H.MAX_SHARD_GZIP_BYTES + 1
            _write(man_path, json.dumps(man))
            out = self._health()
        finally:
            KV.verify_release = orig
        self.assertTrue(out["failing"])
        self.assertFalse(out["health"]["items"]["list"]["ok"])
        self.assertIn("5 MB", out["health"]["items"]["list"]["detail"])

    def test_verified_caps_do_not_trust_a_missing_or_bad_gzip_bytes(self):
        self.seed_cache(shards=1)
        man = load(os.path.join(self.cache, "manifest.json"))
        self.assertIsNone(H._caps_ok(self.cache, man, verified=True))
        for bad in (None, "4096", 4096.0, True):
            doc = json.loads(json.dumps(man))
            if bad is None:
                del doc["shards"][0]["gzip_bytes"]
            else:
                doc["shards"][0]["gzip_bytes"] = bad
            self.assertIsNotNone(H._caps_ok(self.cache, doc, verified=True), repr(bad))

    def test_unverified_caps_still_recompress_the_shard_file(self):
        self.seed_cache(shards=1)
        man = load(os.path.join(self.cache, "manifest.json"))
        name = man["shards"][0]["file"]
        self.assertLessEqual(man["shards"][0]["gzip_bytes"], H.MAX_SHARD_GZIP_BYTES)
        _write(os.path.join(self.cache, name), os.urandom(6 * 1024 * 1024))
        # Not verified (default and explicit): the file on disk decides.
        self.assertIn("5 MB", H._caps_ok(self.cache, man))
        self.assertIn("5 MB", H._caps_ok(self.cache, man, verified=False))
        # Verified: the signed manifest's under-cap gzip_bytes is used instead.
        self.assertIsNone(H._caps_ok(self.cache, man, verified=True))

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

    def test_status_run_does_not_consume_the_nudge(self):
        self.seed_cache(shards=1)
        path = os.path.join(self.tmp, "health.json")
        routing = {"covered": [{"name": "Installer", "line_present": False}]}
        status = self._health(routing=routing, health_path=path, status=True)
        self.assertTrue(status["nudge"] is None or "Installer" in (status.get("nudge") or ""), status)
        doc = load(path)
        self.assertNotIn("Installer", doc.get("nudged") or [])
        weekly = self._health(routing=routing, health_path=path, status=False)
        self.assertIsNotNone(weekly["nudge"])
        self.assertIn(H.LINE, weekly["nudge"])
        self.assertIn("Installer", weekly["nudge"])

    def test_health_json_and_lock_symlinks(self):
        self.seed_cache(shards=1)
        victim_dir = os.path.join(self.tmp, "outside")
        os.makedirs(victim_dir)
        victim = os.path.join(victim_dir, "health-victim")
        with open(victim, "w") as f:
            f.write("secret\n")
        health = os.path.join(self.tmp, "health.json")
        os.symlink(victim, health)
        out = self._health(health_path=health)
        self.assertFalse(out["failing"], out)
        self.assertFalse(os.path.islink(health))
        self.assertTrue(os.path.isfile(health))
        with open(victim, encoding="utf-8") as f:
            self.assertEqual(f.read(), "secret\n")

        health2 = os.path.join(self.tmp, "health2.json")
        os.symlink(os.path.join(self.tmp, "dangling-lock"), health2 + ".lock")
        with self.assertRaises(ValueError):
            self._health(health_path=health2)

