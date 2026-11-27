"""Sharded list (SPEC.md §6.5) and the first-run connectivity reply rules (SPEC.md §4D, §10.1)."""
import copy
import json
import os
import re
import shutil
import unittest

from kt import build as B
from kt import connectivity as CONN
from kt import shards as SH
from kt import validate as V
from kt.common import canonical_json, sha256_bytes
from tests.helpers import REPO, T0, fetch_all, load, make_root, readb, save, tmpdir


def write_canonical(path, doc):
    with open(path, "wb") as f:
        f.write(canonical_json(doc))


class ShardCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.root = make_root(self.tmp)
        self.src = fetch_all(self.tmp, self.root)

    def build(self, name="r1", **kw):
        out = os.path.join(self.tmp, name)
        B.build(self.src, out, bootstrap=True, now=T0, root=self.root, **kw)
        return out

    def set_limits(self, **shards):
        p = os.path.join(self.root, "config", "limits.json")
        lim = load(p)
        lim["shards"].update(shards)
        save(p, lim)

    def relink(self, out, manifest):
        """Rewrite manifest.json and fix latest.json's pointer to it (as a signer would)."""
        write_canonical(os.path.join(out, "manifest.json"), manifest)
        latest = load(os.path.join(out, "latest.json"))
        b = readb(os.path.join(out, "manifest.json"))
        latest["assets"]["manifest.json"] = {"sha256": sha256_bytes(b), "bytes": len(b)}
        write_canonical(os.path.join(out, "latest.json"), latest)


class TestShardBuild(ShardCase):
    def test_layout_and_valid(self):
        out = self.build()
        self.assertEqual(V.validate_release_dir(out, fast_entries=False, now=T0), [])
        m = load(os.path.join(out, "manifest.json"))
        self.assertEqual(m["groups"]["npm"], {"prefix_bytes": 1})
        self.assertEqual(m["groups"]["pypi"], {"prefix_bytes": 1})
        self.assertEqual(m["groups"]["kev"], {"prefix_bytes": 0})
        names = [s["name"] for s in m["shards"]]
        self.assertEqual(len(names), 256 + 256 + 6)
        self.assertIn("kev", names)
        self.assertIn("npm-00", names)
        self.assertIn("pypi-ff", names)
        self.assertEqual(len([n for n in os.listdir(out) if n.startswith("shard-")]), len(names))
        self.assertLessEqual(len(names) + V.RELEASE_ASSET_OVERHEAD, 1000)
        latest = load(os.path.join(out, "latest.json"))
        self.assertIn("manifest.json", latest["assets"])

    def test_every_entry_is_in_the_shard_a_client_would_pick(self):
        out = self.build()
        m = load(os.path.join(out, "manifest.json"))
        iocs = load(os.path.join(out, "iocs.json"))
        for e in iocs["entries"]:
            shard = load(os.path.join(out, SH.shard_for(e["match_key"], m["groups"])))
            self.assertIn(e, shard["entries"])
        canaries = [e for e in iocs["entries"] if e["canary"]]
        self.assertEqual(len(canaries), 8)
        self.assertEqual(m["counts"]["entries"], len(iocs["entries"]))
        self.assertEqual(sum(m["counts"]["by_type"].values()), len(iocs["entries"]))

    def test_shard_key_is_first_byte_of_sha256(self):
        import hashlib
        mk = "npm:left-pad"
        want = "shard-npm-%s.json" % hashlib.sha256(mk.encode()).hexdigest()[:2]
        self.assertEqual(SH.shard_for(mk, {g: {"prefix_bytes": SH.DEFAULT_PREFIX_BYTES.get(g, 0)} for g in SH.GROUPS}), want)
        self.assertEqual(SH.group_of("cve:cve-2021-44228"), "kev")
        self.assertEqual(SH.group_of("github:owner"), "repo_owner")
        with self.assertRaises(SH.ShardError):
            SH.group_of("weird:thing")

    def test_build_is_deterministic(self):
        a, b = self.build("a"), self.build("b")
        for n in os.listdir(a):
            if n != "build-report.json":
                self.assertEqual(readb(os.path.join(a, n)), readb(os.path.join(b, n)), n)

    def test_prefix_config(self):
        self.set_limits(prefix_bytes={"npm": 1, "pypi": 0})
        out = self.build()
        m = load(os.path.join(out, "manifest.json"))
        self.assertEqual(len(m["shards"]), 256 + 7)
        self.assertEqual(V.validate_release_dir(out, now=T0), [])
        self.set_limits(prefix_bytes={"npm": 2})
        with self.assertRaisesRegex(B.BuildError, "prefix_bytes"):
            self.build("x")
        self.set_limits(prefix_bytes={"nuget": 1})
        with self.assertRaisesRegex(B.BuildError, "unknown group"):
            self.build("y")

    def test_shard_over_gzip_cap_fails_build(self):
        self.set_limits(max_shard_gzip_bytes=300)
        with self.assertRaisesRegex(B.BuildError, "raise its prefix length"):
            self.build()

    def test_manifest_over_cap_fails_build(self):
        self.set_limits(max_manifest_bytes=1000)
        with self.assertRaisesRegex(B.BuildError, "manifest.json is .* over the 1000 cap"):
            self.build()

    def test_no_stale_shards_left_behind(self):
        out = self.build()
        open(os.path.join(out, "shard-npm-zz.json"), "w").close()
        self.build()  # same out dir
        self.assertFalse(os.path.exists(os.path.join(out, "shard-npm-zz.json")))


class TestShardValidation(ShardCase):
    def setUp(self):
        super().setUp()
        self.out = self.build()
        self.m = load(os.path.join(self.out, "manifest.json"))

    def errs(self):
        return V.validate_release_dir(self.out, now=T0)

    def test_tampered_shard_refused(self):
        p = os.path.join(self.out, "shard-kev.json")
        with open(p, "ab") as f:
            f.write(b" ")
        self.assertTrue(any("hash/size mismatch" in e for e in self.errs()))

    def test_missing_shard_refused(self):
        os.remove(os.path.join(self.out, "shard-npm-7f.json"))
        self.assertTrue(any("shard npm-7f missing" in e for e in self.errs()))

    def test_unlisted_shard_refused(self):
        shutil.copy(os.path.join(self.out, "shard-kev.json"), os.path.join(self.out, "shard-npm-zz.json"))
        self.assertTrue(any("doesn't list" in e for e in self.errs()))

    def test_unlisted_hidden_and_case_variant_shard_files_refused(self):
        src = os.path.join(self.out, "shard-kev.json")
        for name in (".shard-kev.json", "SHARD-kev.json", "Shard-kev.json", ".SHARD-npm-aa.json"):
            shutil.copy(src, os.path.join(self.out, name))
            self.assertTrue(any("doesn't list" in e for e in self.errs()), name)
            os.remove(os.path.join(self.out, name))
        for name in ("notes.txt", "shardlog.json", "not-shard-kev.json", "foo-shard-kev.json", "latest.json.bak"):
            with open(os.path.join(self.out, name), "w") as f:
                f.write("x")
            self.assertFalse(any("doesn't list" in e for e in self.errs()), name)
            os.remove(os.path.join(self.out, name))

    def test_entry_in_wrong_shard_refused(self):
        # Move one entry into another shard and re-pin both in the manifest: still refused.
        src = next(s for s in self.m["shards"] if s["group"] == "npm" and s["entries"])
        dst = next(s for s in self.m["shards"] if s["group"] == "npm" and s["name"] != src["name"])
        a, b = (load(os.path.join(self.out, s["file"])) for s in (src, dst))
        e = a["entries"].pop(0)
        b["entries"] = sorted(b["entries"] + [e], key=lambda x: x["id"])
        for s, doc in ((src, a), (dst, b)):
            write_canonical(os.path.join(self.out, s["file"]), doc)
            raw = readb(os.path.join(self.out, s["file"]))
            s.update(sha256=sha256_bytes(raw), bytes=len(raw), gzip_bytes=SH.gzip_size(raw), entries=len(doc["entries"]),
                     by_type={"package": len(doc["entries"])} if doc["entries"] else {})
        self.relink(self.out, self.m)
        self.assertTrue(any("belongs in another shard" in e for e in self.errs()))

    def test_count_mismatch_refused(self):
        self.m["counts"]["entries"] += 1
        self.relink(self.out, self.m)
        self.assertTrue(any("totals" in e for e in self.errs()))

    def test_dropped_shard_from_manifest_refused(self):
        self.m["shards"] = [s for s in self.m["shards"] if s["name"] != "pypi-00"]
        self.m["counts"]["shards"] -= 1
        self.relink(self.out, self.m)
        self.assertTrue(any("shard list does not match" in e for e in self.errs()))

    def test_entry_missing_from_shards_refused(self):
        s = next(s for s in self.m["shards"] if s["name"] == "kev")
        doc = load(os.path.join(self.out, s["file"]))
        doc["entries"] = [e for e in doc["entries"] if not e["canary"]]
        write_canonical(os.path.join(self.out, s["file"]), doc)
        raw = readb(os.path.join(self.out, s["file"]))
        s.update(sha256=sha256_bytes(raw), bytes=len(raw), gzip_bytes=SH.gzip_size(raw), entries=len(doc["entries"]),
                 by_type={"cve": len(doc["entries"])})
        self.m["counts"]["entries"] -= 1
        self.m["counts"]["by_group"]["kev"] -= 1
        self.m["counts"]["by_type"]["cve"] -= 1
        self.relink(self.out, self.m)
        self.assertTrue(any("differ from iocs.json" in e for e in self.errs()))

    def test_manifest_schema_and_asset_limit(self):
        bad = copy.deepcopy(self.m)
        bad["caps"]["shard_gzip_bytes"] = 6 * 1024 * 1024
        self.assertTrue(V.validate_manifest(bad))
        bad = copy.deepcopy(self.m)
        bad["groups"]["npm"]["prefix_bytes"] = 2
        self.assertTrue(V.validate_manifest(bad))
        bad = copy.deepcopy(self.m)
        bad["shards"][0]["note"] = "extra"
        self.assertTrue(V.validate_manifest(bad))
        bad = copy.deepcopy(self.m)
        bad["counts"]["shards"] = 989
        self.assertTrue(V.validate_manifest(bad))

    def test_oversized_manifest_refused(self):
        with open(os.path.join(self.out, "manifest.json"), "ab") as f:
            f.write(b" " * (5 * 1024 * 1024))
        self.assertTrue(any("over the 5 MB cap" in e for e in self.errs()))


class TestConnectivity(unittest.TestCase):
    def test_draft_rule(self):
        self.assertEqual(CONN.draft("1.4.0"), "KT 1.4.0 is live and checking")
        self.assertTrue(CONN.draft_allowed("KT 1.4.0 is live and checking", "1.4.0"))
        for bad in ("KT 1.4.1 is live and checking", "KT 1.4.0 is live and checking.", " KT 1.4.0 is live and checking",
                    "KT 1.4.0 is live and checking\n", "KT 1.4.0 is live and checking 🎉", None):
            self.assertFalse(CONN.draft_allowed(bad, "1.4.0"), bad)
        self.assertFalse(CONN.draft_allowed("KT x is live and checking", "x"))
        with self.assertRaises(ValueError):
            CONN.draft("1.4")

    def test_flow_never_posts_without_two_yeses(self):
        for offer in CONN.ANSWERS:
            for send in CONN.ANSWERS:
                r = CONN.flow("first_run", False, offer, send)
                self.assertEqual(r["posted"], offer == "yes" and send == "yes")
                if not r["posted"]:
                    self.assertTrue(r["read_only_check"])

    def test_only_first_run_or_the_user_can_start_it(self):
        for t in ("routine", "health_check", "bot_message"):
            self.assertFalse(any(CONN.flow(t, False, "yes", "yes").values()))
        self.assertFalse(CONN.flow("first_run", True, "yes", "yes")["offered"])
        self.assertTrue(CONN.flow("user_request", True, "yes", "yes")["posted"])

    def test_conformance_section_matches_rules(self):
        conf = load(os.path.join(REPO, "conformance", "cases.json"))
        self.assertEqual(V.validate_connectivity(conf["connectivity"]), [])
        c = conf["connectivity"]
        self.assertTrue(re.match(c["pattern"], "KT 1.4.0 is live and checking"))
        self.assertIsNone(re.match(c["pattern"], "KT 1.4.0 is live and checking\n"))
        for change in (("offer", "Post a reply?"), ("override_allowed", True), ("counts_toward_report_caps", False),
                       ("approval_notice", "This posts.")):
            bad = copy.deepcopy(c)
            bad[change[0]] = change[1]
            self.assertTrue(V.validate_connectivity(bad), change)
        bad = copy.deepcopy(c)
        bad["draft_cases"][1]["expected"] = "allow"
        self.assertTrue(any("disagrees" in e for e in V.validate_connectivity(bad)))
        bad = copy.deepcopy(c)
        bad["flow_cases"][-1]["expected"]["posted"] = True
        self.assertTrue(any("disagrees" in e for e in V.validate_connectivity(bad)))
        bad = copy.deepcopy(c)
        bad["flow_cases"] = [f for f in bad["flow_cases"] if f["trigger"] != "bot_message"]
        self.assertTrue(any("every trigger" in e for e in V.validate_connectivity(bad)))


class TestDocs(unittest.TestCase):
    def test_plain_statement_identical_in_readme_and_spec(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        with open(os.path.join(REPO, "SPEC.md"), encoding="utf-8") as f:
            spec = f.read()
        quote = re.search(r"\*\*The plain statement,\*\*[^\n]*\n\n> (.+)\n", spec).group(1)
        self.assertIn("\n" + quote + "\n", readme)

    def test_report_caps_in_spec_match_limits(self):
        caps = load(os.path.join(REPO, "config", "limits.json"))["reports_per_install"]
        day, week, item = caps["per_day"], caps["per_week"], caps["per_item_per_week"]
        with open(os.path.join(REPO, "SPEC.md"), encoding="utf-8") as f:
            spec = " ".join(f.read().split())
        self.assertIn("%d a day, %d a week, and %d per item per week" % (day, week, item), spec)


class TestShardFilename(unittest.TestCase):
    def test_hidden_and_case_variants(self):
        for name in ("shard-kev.json", "shard-npm-00.json", ".shard-kev.json", "SHARD-kev.json",
                     "Shard-npm-aa.json", ".SHARD-x", "shard-foo.txt"):
            self.assertTrue(SH.looks_like_shard_filename(name), name)
        for name in ("notes.txt", "shardlog.json", "not-shard-kev.json", "foo-shard-kev.json",
                     "latest.json.bak", "README.md", ".", "..", "", ".gitignore"):
            self.assertFalse(SH.looks_like_shard_filename(name), name)
