import glob
import json
import os
import unittest

from kt import finding
from tests.helpers import FIX, load


class TestFindingRecord(unittest.TestCase):
    def test_valid_fixtures(self):
        files = sorted(glob.glob(os.path.join(FIX, "findings", "valid", "*.json")))
        self.assertGreaterEqual(len(files), 10)
        for f in files:
            with self.subTest(f=os.path.basename(f)):
                self.assertEqual(finding.validate_record(load(f)), [])

    def test_invalid_fixtures(self):
        expected = load(os.path.join(FIX, "findings", "invalid", "EXPECTED.json"))
        self.assertGreaterEqual(len(expected), 20)
        for name, needle in expected.items():
            with self.subTest(case=name):
                errs = finding.validate_record(load(os.path.join(FIX, "findings", "invalid", name + ".json")))
                self.assertTrue(errs, "should be invalid")
                self.assertTrue(any(needle in e for e in errs), errs)

    def test_v4_changes_present(self):
        s = load(finding.SCHEMA_PATH)
        cs = s["$defs"]["checked_source"]
        self.assertEqual(set(cs["required"]), {"source", "required", "status", "http_status", "response_sha256", "source_date"})
        self.assertEqual(set(cs["properties"]["status"]["enum"]), {"ok", "failed", "not_configured", "rate_limited"})
        self.assertEqual(s["properties"]["mode"]["enum"], ["checklist", "checker"])
        self.assertIn("checker_sha256", s["required"])
        reasons = set(s["$defs"]["reason"]["enum"])
        for r in ("rate_limited", "source_build_required", "pending_review", "checker_failed"):
            self.assertIn(r, reasons)
        v3 = {"malicious_match", "vulnerable_version", "new_domain", "no_rdap", "lookalike", "install_scripts",
              "retired_entry", "check_failed", "no_link_source", "stale_list", "unverified_list", "injection_seen",
              "paused", "update_required"}
        self.assertEqual(reasons, v3 | {"rate_limited", "source_build_required", "pending_review", "checker_failed"})

    def test_no_free_text_or_handle_fields(self):
        s = load(finding.SCHEMA_PATH)
        self.assertFalse(s["additionalProperties"])
        for d in ("checked_source", "matched_entry"):
            self.assertFalse(s["$defs"][d]["additionalProperties"])
        names = set(s["properties"]) | set(s["$defs"]["checked_source"]["properties"]) | set(s["$defs"]["matched_entry"]["properties"])
        for bad in ("handle", "reporter", "user", "username", "location", "notes", "comment", "x_handle"):
            self.assertFalse(any(bad in n for n in names), bad)

    def test_google_notice_allowed_only_verbatim(self):
        rec = load(os.path.join(FIX, "findings", "valid", "block-package.json"))
        rec["explanation"] = rec["explanation"] + " " + finding.GOOGLE_NOTICE
        self.assertEqual(finding.validate_record(rec), [])
        rec["explanation"] = rec["explanation"].replace("comprehensive", "complete")
        self.assertTrue(any("banned word" in e for e in finding.validate_record(rec)))

    def test_cli(self):
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = finding.main([os.path.join(FIX, "findings", "invalid", "says-safe.json")])
        self.assertEqual(rc, 1)
        self.assertNotIn("safe to install", buf.getvalue())  # never echoes record contents
