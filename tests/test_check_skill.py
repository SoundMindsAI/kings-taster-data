"""Checklist skill (SPEC.md §4): caps, extractors, and fixed decision rules. No network."""
import json
import os
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
         source_date="2026-11-26T10:00:00Z", canary_ok=True):
    return {
        "source": name, "required": required, "status": status,
        "http_status": http_status, "response_sha256": SHA,
        "source_date": source_date, "extracted": extracted, "canary_ok": canary_ok,
    }


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
        rec, lines = C.decide(item, sources, now=NOW, finding_id=FID,
                              finding_path="~/.kings-taster/findings/%s.json" % FID, **kw)
        errs = validate_record(rec)
        self.assertEqual(errs, [], errs)
        self.assertLessEqual(len(lines), 5)
        return rec, lines

    def test_malicious_osv_is_block(self):
        r, data = _extract("osv", "osv-mal.json")
        rec, lines = self._decide(self._package(), [
            _src("osv", data),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
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
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
        ])
        self.assertEqual(rec["result"], "caution")
        self.assertIn("vulnerable_version", rec["reasons"])
        self.assertIn("upgrade to", rec["explanation"])
        self.assertTrue(lines[0].startswith("Caution."))
        self.assertTrue(any(l.startswith("Reason:") for l in lines))

    def test_clean_is_no_known_reports(self):
        rec, lines = self._decide(self._package("left-pad", "1.0.0", "npm"), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
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
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
        ], popular=True)
        self.assertEqual(rec["result"], "caution")
        self.assertIn("pending_review", rec["reasons"])
        self.assertNotIn("malicious_match", rec["reasons"])
        self.assertIn("pending review", rec["explanation"])

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
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("rate_limited", rec["reasons"])
        self.assertIn("try again later", rec["explanation"])

    def test_missing_required_source_is_unknown(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("check_failed", rec["reasons"])
        self.assertTrue(any(s["source"] == "kings_taster_list" and s["required"] for s in rec["checked_against"]))

    def test_no_link_source_wording(self):
        rec, _ = self._decide({
            "item_type": "link",
            "indicator_defanged": "hxxps://example[.]invalid/x",
        }, [
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
            _src("rdap", {"class": "ok", "registration": "1995-08-14", "ldhName": "example.invalid"}),
            _src("safe_browsing", {}, status="not_configured", http_status=None, required=True),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertEqual(rec["reasons"], ["no_link_source"])
        self.assertIn("set up link checks", rec["explanation"])

    def test_health_failing_short_circuits(self):
        rec, lines = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": []}),
            _src("kings_taster_list", {"class": "clean", "hits": []}),
        ], health={"status": "failing", "reason": "stale list"})
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("health check failing: stale list", rec["explanation"])
        self.assertTrue(rec["explanation"].startswith("Unknown."))
        self.assertLessEqual(len(lines), 5)

    def test_list_hit_is_block(self):
        r, data = _extract("list", "list-shard.json", "pypi:bloomcredit-python")
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": [], "osv_count": 0}),
            _src("kings_taster_list", data),
        ])
        self.assertEqual(rec["result"], "block")
        self.assertIn("malicious_match", rec["reasons"])

    def test_canary_failure_is_unknown(self):
        rec, _ = self._decide(self._package(), [
            _src("osv", {"class": "clean", "hits": []}, canary_ok=False, status="failed"),
            _src("kings_taster_list", {"class": "clean", "hits": [], "list_hits": 0}),
        ])
        self.assertEqual(rec["result"], "unknown")
        self.assertIn("check_failed", rec["reasons"])


class TestHosts(unittest.TestCase):
    def test_allowlist(self):
        self.assertTrue(C.host_allowed("api.osv.dev"))
        self.assertTrue(C.host_allowed("api.github.com", "/repos/octocat/Hello-World"))
        self.assertTrue(C.host_allowed("github.com", "/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"))
        self.assertTrue(C.host_allowed("release-assets.githubusercontent.com", list_redirect=True))
        self.assertFalse(C.host_allowed("release-assets.githubusercontent.com"))
        self.assertFalse(C.host_allowed("evil.example"))
        self.assertFalse(C.host_allowed("github.com", "/evil/repo/archive/main.zip"))
        self.assertFalse(C.host_allowed("example.com"))  # the item's own site
