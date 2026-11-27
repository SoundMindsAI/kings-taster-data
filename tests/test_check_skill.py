"""Checklist skill (SPEC.md §4): caps, extractors, and fixed decision rules. No network."""
import json
import os
import subprocess
import re
import unittest

from kt import check as C
from kt.finding import validate_record, GOOGLE_ATTRIBUTION, GOOGLE_NOTICE
from tests.helpers import REPO

FIX = os.path.join(REPO, "tests", "fixtures", "check")
UNCLEARED = re.compile(
    r"abuse\.ch|feodo|ssl blacklist|urlhaus|threatfox|safedep|stepsecurity",
    re.IGNORECASE,
)
# A planted UUID v4 used in records we validate.
FID = "0f8fad5b-d9cb-469f-a165-70867728950e"
NOW = "2026-11-26T23:40:00Z"
SHA = "abababababababababababababababababababababababababababababababab"


def _src(name, extracted, *, required=True, status="ok", http_status=200,
         source_date="2026-11-26T10:00:00Z", canary_ok=True, verified=None,
         release_dir=None, allowed_signers=None, state=None):
    rec = {
        "source": name, "required": required, "status": status,
        "http_status": http_status, "response_sha256": SHA,
        "source_date": source_date, "extracted": extracted, "canary_ok": canary_ok,
    }
    if verified is not None:
        rec["verified"] = verified
    if release_dir is not None:
        rec["release_dir"] = release_dir
    if allowed_signers is not None:
        rec["allowed_signers"] = allowed_signers
    if state is not None:
        rec["state"] = state
    return rec


def _extract(name, *files):
    paths = []
    for f in files:
        candidate = os.path.join(FIX, f)
        paths.append(candidate if os.path.exists(candidate) else f)
    r = C.run_extractor(name, *paths)
    return r, C.parse_extracted(r.stdout)


class TestSkillCaps(unittest.TestCase):
    def setUp(self):
        self.body, self.commands = C.split_skill()

    def test_word_and_line_caps(self):
        self.assertLessEqual(C.word_count(self.body), C.WORD_CAP)
        self.assertLessEqual(C.command_line_count(self.commands), C.COMMAND_LINE_CAP)
        self.assertGreater(C.word_count(self.body), 200)

    def test_required_fragments(self):
        text = C.skill_text()
        for needle in (
            "curl --proto =https --max-redirs 0",
            "curl --proto =https --max-redirs 1",
            "python3 -I -c",
            "date -u",
            "api.osv.dev",
            "api.github.com",
            "data.iana.org",
            "safebrowsing.googleapis.com",
            "release-assets.githubusercontent.com",
            "github.com/SoundMindsAI/kings-taster-data/releases/download",
            "ssh-keygen -Y verify",
            "-s FILE.sig",
            "scripts/verify.sh",
            "keys.json",
            "root_pins",
            "--state",
            "--update-state",
            "SHA-256",
            "config/popular/",
            "~/.kings-taster/keys.env",
            "Never say \"safe\"",
            "rate_limited",
            "injection_seen",
            "health check failing",
        ):
            self.assertIn(needle, text, needle)
        # The connectivity reply belongs to first-run, not this skill.
        self.assertNotIn("is live and checking", text)
        self.assertIn("--max-redirs 1", self.commands)
        self.assertIn("Do not contact the item's own URL", self.commands)

    def test_body_does_not_say_safe_except_the_ban_and_the_product_name(self):
        self.assertFalse(C.body_banned_words(self.body))

    def test_google_notice_is_the_required_text(self):
        attr, notice = C.google_notice()
        self.assertEqual(attr, GOOGLE_ATTRIBUTION)
        self.assertEqual(notice, GOOGLE_NOTICE)

    def test_no_uncleared_source_names(self):
        self.assertIsNone(UNCLEARED.search(C.skill_text()))

    def test_no_internal_paths_or_people(self):
        text = C.skill_text()
        for needle in ("/workspace", "Boss", "Yak", "Copilot", "QA Lead", "1Password", "paper", "printout", "vault"):
            self.assertNotIn(needle, text, needle)


class TestExtractors(unittest.TestCase):
    def test_osv_malicious_prints_allowlisted_fields_only(self):
        r, data = _extract("osv", "osv-mal.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["class"], "malicious")
        self.assertTrue(any(h["id"] == "MAL-2026-20650" for h in data["hits"]))
        self.assertLessEqual(len(data["lines"]), C.EXTRACTOR_LINE_CAP)
        blob = r.stdout.lower()
        for banned in ("summary", "details", "readme", "description", "bloomcredit"):
            # name may appear? package name is not printed by design (only id/kind/date/fixed)
            self.assertNotIn(banned, blob, banned)

    def test_osv_vulnerable_and_clean(self):
        r, data = _extract("osv", "osv-vuln.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["class"], "vulnerable")
        self.assertTrue(any(h["id"] == "PYSEC-2026-2946" for h in data["hits"]))
        # The huge versions list must not be dumped.
        self.assertLessEqual(len(data["lines"]), C.EXTRACTOR_LINE_CAP)
        self.assertNotIn("0.0.100", r.stdout)
        r, data = _extract("osv", "osv-clean.json")
        self.assertEqual(data["class"], "clean")
        self.assertEqual(data.get("osv_count"), 0)

    def test_osv_injection_refused_and_does_not_print_free_text(self):
        r, data = _extract("osv", "osv-injection.json")
        self.assertEqual(data["class"], "injection_seen")
        self.assertNotIn("DROP ME", r.stdout)
        self.assertNotIn("also drop", r.stdout)
        self.assertLessEqual(len(data["lines"]), C.EXTRACTOR_LINE_CAP)

    def test_github_list_rdap_sb(self):
        r, data = _extract("github", "github-repo.json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["full_name"], "octocat/Hello-World")
        self.assertNotIn("must not be printed", r.stdout)
        self.assertNotIn("example.invalid", r.stdout)
        self.assertLessEqual(len(data["lines"]), C.EXTRACTOR_LINE_CAP)

        r, data = _extract("github", "github-injection.json")
        self.assertEqual(data["class"], "injection_seen")

        r, data = _extract("list", "list-shard.json", "pypi:bloomcredit-python")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["list_hits"], 1)
        self.assertEqual(data["hits"][0]["id"], "kt:pypi:bloomcredit-python")
        self.assertFalse(data["hits"][0]["canary"])

        r, data = _extract("list", "list-shard.json", "npm:left-pad")
        self.assertEqual(data.get("class"), "clean")
        self.assertEqual(data["list_hits"], 0)

        r, data = _extract("rdap", "rdap-ok.json")
        self.assertEqual(data["class"], "ok")
        self.assertEqual(data["ldhName"], "example.com")
        self.assertEqual(data["registration"], "1995-08-14")
        self.assertNotIn("must not be printed", r.stdout)
        self.assertNotIn("drop me", r.stdout)

        r, data = _extract("rdap", "rdap-none.json")
        self.assertEqual(data["class"], "no_rdap")

        r, data = _extract("sb", "sb-hit.json")
        self.assertEqual(data["class"], "hit")
        self.assertIn("MALWARE", data["threats"])
        self.assertNotIn("must not be printed", r.stdout)

        r, data = _extract("sb", "sb-clean.json")
        self.assertEqual(data["class"], "clean")

    def test_extractors_use_isolated_python(self):
        body, commands = C.split_skill()
        self.assertEqual(commands.count("python3 -I -c"), 5)


class TestDecisions(unittest.TestCase):
    def _package(self, name="bloomcredit-python", version="99.2.0", eco="PyPI"):
        return {
            "item_type": "package",
            "indicator_defanged": "%s:%s@%s" % (eco.lower(), name, version),
            "ecosystem": eco, "name": name, "version": version,
        }

    def _decide(self, item, sources, **kw):
        kw.setdefault("now", NOW)
        kw.setdefault("template_version", "1.0.0")
        rec, lines = C.decide(item, sources, finding_id=FID,
                              finding_path="~/.kings-taster/findings/%s.json" % FID, **kw)
        errs = validate_record(rec)
        self.assertEqual(errs, [], errs)
        self.assertLessEqual(len(lines), 5)
        return rec, lines

    def test_malicious_osv_is_block(self):
        r, data = _extract("osv", "osv-mal.json")
        rec, lines = self._decide(self._package(), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertTrue(rec["explanation"].startswith("Block."))
        self.assertIn("Don't proceed.", rec["explanation"])
        self.assertTrue(lines[0].startswith("Block."))

    def test_vulnerable_osv_is_caution(self):
        r, data = _extract("osv", "osv-vuln.json")
        rec, lines = self._decide(self._package("praisonaiagents", "1.0.0"), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "caution")
        self.assertIn("vulnerable_version", rec["reasons"])
        self.assertIn("upgrade to", rec["explanation"])
        self.assertTrue(lines[0].startswith("Caution."))
        self.assertTrue(any(l.startswith("Reason:") for l in lines))

    def test_clean_is_no_known_reports(self):
        rec, lines = self._decide(self._package("left-pad", "1.0.0", "npm"), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "no_known_reports")
        self.assertEqual(rec["reasons"], [])
        self.assertTrue(rec["explanation"].startswith("No known reports. Checked against"))
        self.assertFalse(any(l.startswith("Reason:") for l in lines))

    def test_popular_malicious_is_pending_review(self):
        r, data = _extract("osv", "osv-popular-mal.json")
        self.assertTrue(C.is_popular("npm", "lodash"))
        rec, lines = self._decide(self._package("lodash", "4.0.0", "npm"), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])  # decide() reads config/popular/ itself; there is no flag to bypass it
        self.assertEqual(rec["result"], "caution")
        self.assertIn("pending_review", rec["reasons"])
        self.assertNotIn("malicious_match", rec["reasons"])
        self.assertIn("pending review", rec["explanation"])

    def test_popular_flag_is_gone(self):
        with self.assertRaises(TypeError):
            C.decide(self._package(), [], now=NOW, template_version="1.0.0", popular=False)

    def test_now_and_template_version_are_required(self):
        item = self._package()
        with self.assertRaises(TypeError):
            C.decide(item, [], template_version="1.0.0")
        with self.assertRaises(TypeError):
            C.decide(item, [], now=NOW)

    def test_popular_names_are_cached_and_clearable(self):
        C.clear_popular_cache()
        first = C._popular_names()
        self.assertIs(C._popular_names(), first)
        C.clear_popular_cache()
        self.assertEqual(C._popular_names(), first)

    def test_is_popular_ecosystem_spelling_is_case_insensitive(self):
        self.assertTrue(C.is_popular("npm", "lodash"))
        self.assertTrue(C.is_popular("NPM", "lodash"))
        self.assertFalse(C.is_popular("pypi", "not-a-real-package-xxxxxx"))
        self.assertFalse(C.is_popular("NPM", "not-a-real-package-xxxxxx"))
        # Must not raise for pypi / NPM (L-PR7-3).
        self.assertIsInstance(C.is_popular("pypi", "requests"), bool)
        self.assertIsInstance(C.is_popular("PyPI", "requests"), bool)

    def test_unverified_list_is_unknown_even_when_extracted_clean(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("unverified_list", rec["reasons"])

    def test_osv_caution_is_shown_when_list_is_unverified(self):
        r, data = _extract("osv", "osv-vuln.json")
        rec, lines = self._decide(self._package("praisonaiagents", "1.0.0", "PyPI"), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "injection_seen"}, status="failed", http_status=200),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("vulnerable_version", rec["reasons"])
        self.assertTrue(rec["explanation"].startswith("Unknown."))
        self.assertIn("upgrade to", rec["explanation"])
        self.assertTrue(any(l.startswith("Caution.") for l in lines), lines)
        self.assertLessEqual(len(lines), 5)

    def test_block_wins_over_unknown(self):
        r, data = _extract("osv", "osv-mal.json")
        rec, _ = self._decide(self._package(), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "injection_seen"}, status="failed", http_status=200),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertIn("injection_seen", rec["reasons"])

    def test_rate_limited_is_unknown(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {}, status="rate_limited", http_status=429),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("rate_limited", rec["reasons"])
        self.assertIn("try again later", rec["explanation"])

    def test_missing_evidence_is_unknown(self):
        clean = {"class": "clean", "hits": [], "osv_count": 0}
        no_canary = _src("osv", clean)
        del no_canary["canary_ok"]
        no_extracted = _src("osv", clean)
        del no_extracted["extracted"]
        cases = {
            "canary_ok omitted": no_canary,
            "canary_ok none": _src("osv", clean, canary_ok=None),
            "canary_ok non-boolean": _src("osv", clean, canary_ok="yes"),
            "extracted omitted": no_extracted,
            "extracted none": _src("osv", None),
            "extracted not a dict": _src("osv", ["clean"]),
            "empty extraction": _src("osv", C.parse_extracted("")),
            "empty dict": _src("osv", {}),
            "hits only empty": _src("osv", {"hits": []}),
            "garbage class": _src("osv", {"class": "garbage", "hits": []}),
            "bogus status": _src("osv", clean, status="weird"),
            "non-string status": _src("osv", clean, status=5),
        }
        for name, osv in cases.items():
            with self.subTest(case=name):
                rec, _ = self._decide(self._package(), [
                    osv,
                    _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
                ])
                self.assertEqual(rec["result"], "unknown")
                self.assertIn("check_failed", rec["reasons"])

    def test_missing_required_source_is_unknown(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("check_failed", rec["reasons"])
        self.assertTrue(any(s["source"] == "kings_taster_list" and s["required"] for s in rec["checked_against"]))

    def test_required_source_cannot_be_marked_optional(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {}, required=False, status="not_configured", http_status=None),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("check_failed", rec["reasons"])
        osv = next(s for s in rec["checked_against"] if s["source"] == "osv")
        self.assertTrue(osv["required"])

    def test_no_link_source_wording(self):
        rec, _ = self._decide({
            "item_type": "link",
            "indicator_defanged": "hxxps://example[.]invalid/x",
        }, [
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
            _src("rdap", {"class": "ok", "registration": "1995-08-14", "ldhName": "example.invalid"}),
            _src("safe_browsing", {}, status="not_configured", http_status=None, required=True),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertEqual(rec["reasons"], ["no_link_source"])
        self.assertIn("set up link checks", rec["explanation"])

    def test_health_failing_short_circuits(self):
        rec, lines = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": []}),
            _src("kings_taster_list", {"class": "clean", "hits": []}, verified=True),
        ], health={"status": "failing", "reason": "stale list"})
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("health check failing: stale list", rec["explanation"])
        self.assertTrue(rec["explanation"].startswith("Unknown."))
        self.assertLessEqual(len(lines), 5)

    def test_list_hit_is_block(self):
        r, data = _extract("list", "list-shard.json", "pypi:bloomcredit-python")
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", data, verified=True),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])

    def test_list_hit_with_canary_flag_but_real_id_still_blocks(self):
        # N1: a real entry mislabelled canary=yes is still a list match.
        real = {"id": "kt:pypi:bloomcredit-python", "type": "package", "date": "2026-11-26", "canary": True}
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", {"class": "malicious", "hits": [real], "list_hits": 1}, verified=True),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertTrue(any(m["id"] == real["id"] for m in rec["matched_entries"]), rec["matched_entries"])

    def test_reserved_canary_item_blocks(self):
        # The item under check is a reserved list canary (id from the build), so
        # the match_key-filtered hit is a firm list hit.
        item = {"item_type": "package", "ecosystem": "npm", "name": "kings-taster-canary-npm",
                "version": "1.0.0", "indicator_defanged": "npm:kings-taster-canary-npm@1.0.0"}
        canary = {"id": "canary:package:npm", "type": "package", "date": "2026-11-26", "canary": True}
        rec, _ = self._decide(item, [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", {"class": "malicious", "hits": [canary], "list_hits": 1}, verified=True),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertTrue(any(m["id"] == canary["id"] for m in rec["matched_entries"]), rec["matched_entries"])

    def test_skill_states_reserved_canary_rule(self):
        flat = " ".join(C.split_skill()[0].split())
        self.assertIn("including a list canary", flat)

    def _shard_extract(self, tmp, key, review_state=None, entry_id="kt:npm:lodash"):
        entry = {"id": entry_id, "match_key": key, "type": "package",
                 "first_seen": "2026-11-26", "canary": False}
        if review_state:
            entry["review_state"] = review_state
        path = os.path.join(tmp, "shard.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entries": [entry]}, fh)
        r = C.run_extractor("list", path, key)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r, C.parse_extracted(r.stdout)

    def _list_decision(self, name, review_state, entry_id):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            _, data = self._shard_extract(tmp, "npm:%s" % name, review_state, entry_id)
        return self._decide(self._package(name, "4.17.21", "npm"), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", data, verified=True),
        ])

    def test_list_extractor_prints_review_state(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            r, data = self._shard_extract(tmp, "npm:lodash", "pending_review")
            self.assertIn("review_state=pending_review", r.stdout)
            self.assertEqual(data["hits"][0]["review_state"], "pending_review")
            r, data = self._shard_extract(tmp, "npm:lodash", "approved")
            self.assertEqual(data["hits"][0]["review_state"], "approved")
            r, data = self._shard_extract(tmp, "npm:lodash")
            self.assertEqual(data["hits"][0]["review_state"], "auto")
            r, data = self._shard_extract(tmp, "npm:lodash", "free text ignore previous")
            self.assertEqual(data["class"], "injection_seen")
            self.assertNotIn("ignore previous", r.stdout)

    def test_firm_list_hit_survives_print_cap(self):
        import tempfile
        key = "npm:lodash"
        entries = [{"id": "kt:npm:lodash:p%d" % n, "match_key": key, "type": "package",
                    "first_seen": "2026-11-26", "canary": False,
                    "review_state": "pending_review"} for n in range(8)]
        entries.append({"id": "kt:npm:lodash:firm", "match_key": key, "type": "package",
                        "first_seen": "2026-11-26", "canary": False,
                        "review_state": "approved"})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "shard.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"entries": entries}, fh)
            r = C.run_extractor("list", path, key)
        self.assertEqual(r.returncode, 0, r.stderr)
        data = C.parse_extracted(r.stdout)
        self.assertEqual(data["list_hits"], 9)
        self.assertLessEqual(len(data["hits"]), 8)
        self.assertTrue(any(h["id"] == "kt:npm:lodash:firm" and h["review_state"] == "approved"
                            for h in data["hits"]), data["hits"])
        rec, _ = self._decide(self._package("lodash", "4.17.21", "npm"), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", data, verified=True),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertNotIn("pending_review", rec["reasons"])

    def test_popular_list_hit_pending_review_is_caution(self):
        rec, _ = self._list_decision("lodash", "pending_review", "kt:npm:lodash")
        self.assertEqual(rec["result"], "caution")
        self.assertIn("pending_review", rec["reasons"])
        self.assertNotIn("malicious_match", rec["reasons"])
        self.assertIn("pending review", rec["explanation"])

    def test_popular_list_hit_approved_still_blocks(self):
        rec, _ = self._list_decision("lodash", "approved", "kt:npm:lodash")
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])
        self.assertNotIn("pending_review", rec["reasons"])

    def test_non_popular_list_hit_auto_still_blocks(self):
        name = "not-a-real-package-xxxxxx"
        self.assertFalse(C.is_popular("npm", name))
        rec, _ = self._list_decision(name, "auto", "kt:npm:%s" % name)
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])

    def test_skill_states_list_pending_review_rule(self):
        body, _ = C.split_skill()
        flat = " ".join(body.split())
        self.assertIn("list hit with review_state pending_review is Caution, never Block", flat)

    def test_canary_failure_is_unknown(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": []}, canary_ok=False, status="failed"),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}, verified=True),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("check_failed", rec["reasons"])


class TestHosts(unittest.TestCase):
    LIST_OK = "/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"

    def test_allowlist(self):
        self.assertTrue(C.host_allowed("api.osv.dev"))
        self.assertTrue(C.host_allowed("api.github.com", "/repos/octocat/Hello-World"))
        self.assertTrue(C.host_allowed("github.com", self.LIST_OK))
        self.assertTrue(C.host_allowed("release-assets.githubusercontent.com", list_redirect=True))
        self.assertFalse(C.host_allowed("release-assets.githubusercontent.com"))
        self.assertFalse(C.host_allowed("evil.example"))
        self.assertFalse(C.host_allowed("github.com", "/evil/repo/archive/main.zip"))
        self.assertFalse(C.host_allowed("example.com"))  # the item's own site

    def test_github_com_repos_is_refused(self):
        # Skill: github.com only for the list download path; API calls go to api.github.com.
        self.assertFalse(C.host_allowed("github.com", "/repos/octocat/Hello-World"))
        self.assertFalse(C.host_allowed("github.com", "/repos/SoundMindsAI/kings-taster-data"))

    def test_dotdot_in_list_path_is_refused(self):
        path = "/SoundMindsAI/kings-taster-data/releases/download/../../../../other/releases/download/x/y"
        self.assertFalse(C.host_allowed("github.com", path))

    def test_encoded_dotdot_any_case_is_refused(self):
        prefix = "/SoundMindsAI/kings-taster-data/releases/download/"
        for enc in ("%2e%2e", "%2E%2E", "%2e%2E", "%2E%2e", "%2e%2e", "%252e%252e"):
            self.assertFalse(C.host_allowed("github.com", prefix + enc + "/other/x"), enc)
            self.assertFalse(C.host_allowed("github.com", prefix + enc.upper() + "/other/x"), enc)

    def test_list_prefix_is_matched_on_segment_boundaries(self):
        # A longer first segment must not match just because it starts with the prefix.
        self.assertFalse(C.host_allowed(
            "github.com",
            "/SoundMindsAI/kings-taster-data/releases/download-evil/kt-latest/latest.json"))
        self.assertFalse(C.host_allowed(
            "github.com",
            "/SoundMindsAI/kings-taster-data/releases/download"))
        self.assertFalse(C.host_allowed(
            "github.com",
            "/SoundMindsai/kings-taster-data/releases/download/kt-latest/latest.json"))

    def test_full_url_is_parsed(self):
        url = "https://github.com" + self.LIST_OK
        self.assertTrue(C.host_allowed(url))
        self.assertTrue(C.host_allowed("github.com", url))
        self.assertFalse(C.host_allowed(
            "https://github.com/SoundMindsAI/kings-taster-data/releases/download/../../evil/x"))
        self.assertFalse(C.host_allowed("https://evil.example/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"))

    def test_host_plus_full_url_mismatch_is_refused(self):
        # github.com + https://evil.example/<allowed-path> must not keep the
        # allowlisted host and the path from the other URL.
        evil = "https://evil.example" + self.LIST_OK
        self.assertFalse(C.host_allowed("github.com", evil))
        host, path = C._split_host_path("github.com", evil)
        self.assertNotEqual((host or "").lower(), "github.com")
        # Matching host + same-host URL still works.
        self.assertTrue(C.host_allowed("github.com", "https://github.com" + self.LIST_OK))

    def test_query_or_fragment_in_authority_is_refused(self):
        # N10: '?' or '#' in the authority must not let '@github.com' become the host.
        allowed = "https://github.com" + self.LIST_OK
        self.assertTrue(C.host_allowed(allowed))
        self.assertFalse(C.host_allowed("https://evil.example?x=@" + "github.com" + self.LIST_OK))
        self.assertFalse(C.host_allowed("https://evil.example#x=@" + "github.com" + self.LIST_OK))
        host_q, _ = C._split_host_path("https://evil.example?x=@github.com" + self.LIST_OK, "")
        host_h, _ = C._split_host_path("https://evil.example#x=@github.com" + self.LIST_OK, "")
        self.assertNotEqual((host_q or "").lower(), "github.com")
        self.assertNotEqual((host_h or "").lower(), "github.com")

    def test_two_full_urls_must_name_the_same_host(self):
        # N3: both arguments full URLs: the second must not be ignored.
        good = "https://github.com" + self.LIST_OK
        evil = "https://evil.example" + self.LIST_OK
        self.assertFalse(C.host_allowed(good, evil))
        self.assertFalse(C.host_allowed(evil, good))
        host, _ = C._split_host_path(good, evil)
        self.assertEqual(host, "")
        self.assertTrue(C.host_allowed(good, "https://GitHub.com" + self.LIST_OK))

    def test_backslash_semicolon_tab_or_userinfo_in_authority_is_refused(self):
        # N12: WHATWG parsers read '\' as a path separator, so these name another host.
        for sep in ("\\", ";", "\t"):
            with self.subTest(sep=repr(sep)):
                self.assertFalse(C.host_allowed("https://evil.example" + sep + "@" + "github.com" + self.LIST_OK))
        self.assertFalse(C.host_allowed("https://user@" + "github.com" + self.LIST_OK))
        self.assertTrue(C.host_allowed("https://github.com" + self.LIST_OK))

    def test_l1_authority_refusals_apply_to_every_argument(self):
        official = "https://github.com" + self.LIST_OK
        # Second URL: github.com:x plus userinfo at evil.example must not read as host github.com.
        tricky = "https://github.com:x" + "@" + "evil.example" + self.LIST_OK
        self.assertFalse(C.host_allowed("https://github.com" + self.LIST_OK, tricky))
        self.assertFalse(C.host_allowed(tricky, official))
        # Bare host with userinfo must not be reduced to its last '@' part.
        self.assertFalse(C.host_allowed("evil" + "@" + "github.com", official))
        self.assertTrue(C.host_allowed("github.com", official))

    def test_l3_explicit_port_is_refused(self):
        self.assertFalse(C.host_allowed("https://github.com:8443" + self.LIST_OK))
        self.assertFalse(C.host_allowed("github.com", "https://github.com:8443" + self.LIST_OK))
        self.assertFalse(C.host_allowed("github.com:8443", self.LIST_OK))
        self.assertFalse(C.host_allowed("https://api.osv.dev:443/v1/query"))
        self.assertTrue(C.host_allowed("https://github.com" + self.LIST_OK))


@unittest.skipUnless(__import__("shutil").which("ssh-keygen"), "ssh-keygen not installed")
class TestListVerify(unittest.TestCase):
    """decide() and verify_list() must use the official verifier (scripts/verify.sh / verify_release)."""

    def setUp(self):
        import shutil
        from tests.helpers import T0, fetch_all, make_root, tmpdir
        from tests.test_sign_verify import keygen, sign_dir
        from kt import build as B

        self.tmp = tmpdir(self)
        keys = os.path.join(self.tmp, "keys")
        os.makedirs(keys)
        self.key, pub = keygen(keys, "cur")
        self.allowed = os.path.join(self.tmp, "allowed")
        with open(self.allowed, "w") as f:
            f.write('kings-taster-current namespaces="kings-taster" %s\n' % pub)
        self.root = make_root(self.tmp)
        self.src = fetch_all(self.tmp, self.root)
        self.out = os.path.join(self.tmp, "rel")
        B.build(self.src, self.out, bootstrap=True, now=T0, root=self.root)
        sign_dir(self.out, self.key)

    def _vr(self, d=None, **kw):
        kw.setdefault("allowed_signers", self.allowed)
        kw.setdefault("now", "2026-11-27T06:17:00Z")
        return C.verify_list(d or self.out, **kw)

    def test_signed_release_verifies_and_decide_accepts_it(self):
        vr = self._vr()
        self.assertTrue(vr["ok"], vr)
        self.assertTrue(hasattr(C, "verify_release"))
        rec, _ = C.decide(
            {"item_type": "package", "indicator_defanged": "pypi:bloomcredit-python@99.3.0",
             "ecosystem": "PyPI", "name": "bloomcredit-python", "version": "99.3.0"},
            [
                _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
                _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0},
                     release_dir=self.out, allowed_signers=self.allowed),
            ],
            now="2026-11-27T06:17:00Z", template_version="1.0.0", finding_id=FID,
            finding_path="~/.kings-taster/findings/%s.json" % FID,
        )
        self.assertEqual(validate_record(rec), [])
        self.assertEqual(rec["result"], "no_known_reports")
        self.assertNotIn("unverified_list", rec["reasons"])

    def test_shard_mismatch_is_unverified(self):
        shards = [n for n in os.listdir(self.out) if n.startswith("shard-") and n.endswith(".json")]
        path = os.path.join(self.out, shards[0])
        with open(path, "ab") as f:
            f.write(b"\n")
        vr = self._vr()
        self.assertFalse(vr["ok"])
        self.assertEqual(vr["reason"], "unverified_list")
        self.assertTrue("shard" in vr["detail"].lower() or "hash" in vr["detail"].lower() or vr["detail"])

    def test_latest_json_hash_mismatch_is_unverified(self):
        iocs = os.path.join(self.out, "iocs.json")
        with open(iocs, "ab") as f:
            f.write(b"\n")
        vr = self._vr()
        self.assertFalse(vr["ok"])
        self.assertEqual(vr["reason"], "unverified_list")

    def test_rollback_state_is_refused(self):
        state = os.path.join(self.tmp, "state.json")
        # A later generated_at in state makes this release look rolled back.
        with open(state, "w") as f:
            f.write('{"generated_at": "2026-11-28T00:00:00Z", "latest_sha256": "%s", "tag": "kt-future"}\n' % ("a" * 64))
        vr = self._vr(state=state)
        self.assertFalse(vr["ok"])
        self.assertEqual(vr["reason"], "unverified_list")
        self.assertIn("rollback", vr["detail"].lower())

    def test_missing_keys_json_refused_when_pins_published(self):
        # Drive the official verifier's missing-keys path without publishing real pins.
        from tests.test_keys import keygen as kgen, write_pins
        import kt.keys as K
        _priv, root_pub = kgen(self.tmp, "master")
        _b, bak_pub = kgen(self.tmp, "master-backup")
        pins = os.path.join(self.tmp, "root_pins")
        write_pins(pins, root_pub, bak_pub)
        orig = K.DEFAULT_PINS
        K.DEFAULT_PINS = pins
        try:
            vr = self._vr()
        finally:
            K.DEFAULT_PINS = orig
        self.assertFalse(vr["ok"], vr)
        self.assertEqual(vr["reason"], "unverified_list")
        self.assertIn("keys.json", vr["detail"].lower())

    def test_skill_verify_command_writes_watermark_and_refuses_older_release(self):
        """Following the skill's exact verify command writes the watermark; a replay is refused."""
        import datetime as dt
        from tests.helpers import T0
        from tests.test_sign_verify import sign_dir
        from kt import build as B

        newer_now = T0 + dt.timedelta(days=1)
        newer = os.path.join(self.tmp, "newer")
        B.build(self.src, newer, previous_dir=self.out, bootstrap=False, now=newer_now, root=self.root)
        sign_dir(newer, self.key)

        documented = ("scripts/verify.sh DIR --allowed-signers allowed_signers "
                      "--state ~/.kings-taster/verify-state.json --update-state")
        self.assertIn(documented, C.skill_text())

        state = os.path.join(self.tmp, "verify-state.json")
        script = os.path.join(REPO, "scripts", "verify.sh")
        now_iso = "2026-11-28T06:17:00Z"
        # Skill command with only test paths (and --now to pin the fixture clock) substituted.
        cmd = [script, "DIR", "--allowed-signers", "allowed_signers",
               "--state", "~/.kings-taster/verify-state.json", "--update-state"]
        self.assertEqual(cmd[0], script)
        self.assertEqual(cmd[1:], documented.split()[1:])  # DIR ... --update-state
        run_cmd = [script, newer, "--allowed-signers", self.allowed,
                   "--state", state, "--update-state", "--now", now_iso]
        first = subprocess.run(run_cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertTrue(os.path.isfile(state), "watermark was not written")

        replay = subprocess.run(
            [script, self.out, "--allowed-signers", self.allowed,
             "--state", state, "--update-state", "--now", now_iso],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(replay.returncode, 0, replay.stdout + replay.stderr)
        self.assertIn("rollback", (replay.stdout + replay.stderr).lower())

        # The Python check path defaults to writing the watermark too.
        vr = C.verify_list(self.out, allowed_signers=self.allowed, state=state, now=now_iso)
        self.assertFalse(vr["ok"])
        self.assertIn("rollback", vr["detail"].lower())

    def test_verify_list_default_writes_watermark(self):
        state = os.path.join(self.tmp, "watermark.json")
        vr = C.verify_list(self.out, allowed_signers=self.allowed, state=state,
                           now="2026-11-27T06:17:00Z")
        self.assertTrue(vr["ok"], vr)
        self.assertTrue(os.path.isfile(state))

    def test_module_names_the_official_verifier(self):
        path = os.path.join(REPO, "kt", "check.py")
        with open(path, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("verify_release", src)
        self.assertIn("scripts/verify.sh", src)
        self.assertIn("keys.json", src)
        self.assertIn("from . import verify", src)
