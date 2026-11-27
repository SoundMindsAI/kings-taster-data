"""Licensing table: well-formed, matches LICENSES.md, and is the only allowlist for list-file feeds."""
import os
import re
import unittest

from kt import licensing as L
from kt import sources
from tests.helpers import REPO

class TestLicensingTable(unittest.TestCase):
    def setUp(self):
        self.doc = L.load_table()
        with open(os.path.join(REPO, "sources", "LICENSES.md"), encoding="utf-8") as f:
            self.md = f.read()

    def _norm(self, s):
        return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()

    def test_table_is_well_formed(self):
        self.assertEqual(L.problems(self.doc), [])

    def test_required_columns_in_markdown(self):
        found = next(l for l in self.md.splitlines() if l.startswith("| Source |"))
        for col in ("Source", "Commercial use", "Redistribution", "Attribution", "Key", "Rate limit"):
            self.assertIn(col, found, col)

    def test_every_row_appears_in_markdown(self):
        body = self._norm(self.md)
        for row in self.doc["sources"]:
            self.assertIn(self._norm(row["source"]), body, row["id"])
            self.assertIn(row["terms_url"], self.md, row["id"])

    def test_markdown_does_not_name_sources_missing_from_json(self):
        names = {row["source"] for row in self.doc["sources"]}
        in_table = False
        named = 0
        for line in self.md.splitlines():
            if line.startswith("| Source |"):
                in_table = True
                continue
            if in_table and line.startswith("|---"):
                continue
            if in_table and not line.startswith("|"):
                break
            if in_table and line.startswith("|"):
                named += 1
                self.assertTrue(any(n in line or self._norm(n) in self._norm(line) for n in names), line[:80])
        self.assertEqual(named, len(self.doc["sources"]))

    def test_pipeline_fetchers_are_list_file_rows(self):
        self.assertEqual(tuple(sources.LIST_FETCHERS), ("cisa-kev", "osv-npm", "osv-pypi"))
        by_id = {s["id"]: s for s in self.doc["sources"]}
        self.assertEqual(sources.KEV["url"], by_id["cisa-kev"]["feed_url"])
        self.assertEqual(sources.OSV["npm"]["url"], by_id["osv-mal-npm"]["feed_url"])
        self.assertEqual(sources.OSV["PyPI"]["url"], by_id["osv-mal-pypi"]["feed_url"])
        for fid, rid in L.LIST_FETCHER_IDS.items():
            row = by_id[rid]
            self.assertTrue(row["in_list_file"], fid)
            self.assertEqual(row["use"], "list_file")

    def test_no_fetcher_url_outside_the_table(self):
        allowed = set(L.feed_urls(self.doc))
        self.assertEqual(allowed, {sources.KEV["url"], sources.OSV["npm"]["url"], sources.OSV["PyPI"]["url"]})

