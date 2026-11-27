"""Feed conformance/cases.json into decide(). Offline: extractors run on local fixtures only."""
import json
import os
import re
import tempfile
import unittest

from kt import build as B
from kt import check as C
from tests.helpers import REPO

FIX = os.path.join(REPO, "tests", "fixtures", "check")
NOW = "2026-11-26T23:40:00Z"
FID = "0f8fad5b-d9cb-469f-a165-70867728950e"
SHA = "ab" * 32

with open(os.path.join(REPO, "conformance", "cases.json"), encoding="utf-8") as _fh:
    CASES = json.load(_fh)["cases"]

SKIP = {}
SKIP.update({
    "canary-safe-browsing-test-url": "needs a live Safe Browsing response for Google's test URL",
    "inject-npm-readme": "needs the npm registry extractor, which decide() has no source for",
    "inject-pypi-description": "needs the PyPI registry extractor, which decide() has no source for",
    "inject-rdap-remarks": "case body has no ldhName, so the real RDAP extractor rejects it as written",
    "inject-package-name": "item validation happens before decide(); decide() takes parsed items",
    "build-time-canary": "needs a real source build; the file-must-never-exist check is a side effect",
    "list-retired-entry": "decide() has no retired_entry input",
    "req-link-new-domain": "decide() has no new_domain input",
    "checker-tampered": "needs the optional checker binary",
    "checker-crash": "needs the optional checker binary",
    "budget-cached-verdict": "needs the verdict cache, which is not part of decide()",
    "budget-block-not-cached": "needs the verdict cache, which is not part of decide()",
    "budget-link-never-cached": "needs the verdict cache, which is not part of decide()",
})

LIST_FAIL_REASON = {
    "stale_49h": "stale_list", "paused": "paused", "min_template_version_above_current": "update_required",
    "bad_signature": "unverified_list", "signed_by_unlisted_key": "unverified_list",
    "older_generated_at": "unverified_list", "conformance_file_served_as_iocs": "unverified_list",
    "verified_with_injected_value": "unverified_list",
}
CLEAN_LIST = {"class": "clean", "hits": [], "list_hits": 0}


def _item(spec):
    ind = spec["indicator_defanged"]
    item = dict(spec)
    m = re.match(r"^(npm|pypi):([^@]+)@(.+)$", ind)
    if m:
        item.update(ecosystem="npm" if m.group(1) == "npm" else "PyPI", name=m.group(2), version=m.group(3))
    return item


def _extract_file(name, fixture, *args):
    r = C.run_extractor(name, os.path.join(FIX, fixture), *args)
    assert r.returncode == 0, r.stderr
    return C.parse_extracted(r.stdout)


def _list_hit(item, review_state):
    """Run the real list extractor over a one-entry shard for the item's name."""
    key = "%s:%s" % (item["ecosystem"].lower(), item["name"])
    entry = {"id": "kt:" + key, "match_key": key, "type": "package",
             "first_seen": "2026-11-26", "canary": False, "review_state": review_state}
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "shard.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entries": [entry]}, fh)
        r = C.run_extractor("list", path, key)
    assert r.returncode == 0, r.stderr
    return C.parse_extracted(r.stdout)


def _canary_for(item):
    """The reserved list canary entry the item under check is, or None."""
    with open(os.path.join(REPO, "config", "canaries.json"), encoding="utf-8") as fh:
        entries = B.canary_entries(json.load(fh), None)
    ind = item["indicator_defanged"]
    if item["item_type"] == "package":
        keys = {"%s:%s" % ("npm" if item["ecosystem"] == "npm" else "pypi", item["name"])}
    elif item["item_type"] == "repo":
        keys = {"github:" + ind.split(":", 1)[1].split("/")[0].lower()}
    else:
        url = ind.replace("hxxp", "http").replace("[.]", ".")
        host = url.split("://", 1)[1].split("/", 1)[0]
        keys = {"domain:" + host, "ip:" + host}
        if not url.endswith("%s/" % host):
            keys.add(B.match_key("url", url))
    matches = [e for e in entries if e["match_key"] in keys]
    # A URL canary also shares the domain host; prefer the more specific type.
    rank = {"url": 0, "ip": 1, "domain": 2}
    matches.sort(key=lambda e: rank.get(e["type"], 9))
    return matches[0] if matches else None


def _canary_hit(entry):
    """Run the real list extractor over a one-entry shard carrying the canary."""
    shard = {"id": entry["id"], "match_key": entry["match_key"], "type": entry["type"],
             "first_seen": "2026-11-26", "canary": True, "review_state": "auto"}
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "shard.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"entries": [shard]}, fh)
        r = C.run_extractor("list", path, entry["match_key"])
    assert r.returncode == 0, r.stderr
    return C.parse_extracted(r.stdout)


def _src(name, extracted, status="ok", http_status=200, **extra):
    rec = {"source": name, "required": True, "status": status, "http_status": http_status,
           "response_sha256": SHA, "source_date": "2026-11-26T10:00:00Z",
           "extracted": extracted, "canary_ok": True}
    rec.update(extra)
    return rec


def _failure(token):
    status = token.get("status")
    if status == "redirect":
        return _src("x", {}, status="injection_seen", http_status=None)
    return _src("x", {}, status=status, http_status=token.get("http_status"))


def _build_source(name, token, item):
    """Map one setup token onto a decide() source. Returns None for sources decide() ignores."""
    if name == "iana_rdap_bootstrap":
        return None
    if isinstance(token, dict):
        if token.get("body") is not None and token.get("status") == "ok" and name == "osv":
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "raw.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(token["body"], fh)
                r = C.run_extractor("osv", path)
            return _src(name, C.parse_extracted(r.stdout))
        if token.get("status") == "ok" and name == "rdap":
            if token.get("http_status") == 404:
                return _src(name, {"class": "no_rdap"})
            raise unittest.SkipTest("rdap setup %r not expressible" % (token,))
        if token.get("status") in ("failed", "rate_limited", "redirect"):
            src = _failure(token)
            src["source"] = name
            if token.get("status") == "redirect":
                src["extracted"] = {"class": "injection_seen"}
            return src
        raise unittest.SkipTest("setup %s=%r not expressible" % (name, token))
    if name == "osv":
        if token == "ok":
            return _src(name, _extract_file("osv", "osv-clean.json"))
        if token in ("ok_mal_hit", "ok_mal_hit_popular_name"):
            return _src(name, _extract_file("osv", "osv-mal.json"))
        if token == "ok_vulnerable_hit":
            return _src(name, _extract_file("osv", "osv-vuln.json"))
        if token == "ok_but_canary_missing":
            return _src(name, _extract_file("osv", "osv-clean.json"), canary_ok=False)
    elif name == "github_api":
        if token == "ok":
            return _src(name, _extract_file("github", "github-repo.json"))
    elif name == "rdap":
        if token == "ok":
            return _src(name, _extract_file("rdap", "rdap-ok.json"))
    elif name == "safe_browsing":
        if token == "ok":
            return _src(name, _extract_file("sb", "sb-clean.json"))
        if token == "not_configured":
            return _src(name, {}, status="not_configured", http_status=None)
    elif name == "kings_taster_list":
        if token == "verified":
            # A real verified list always carries the reserved canary entries.
            canary = _canary_for(item)
            if canary:
                return _src(name, _canary_hit(canary), verified=True)
            return _src(name, dict(CLEAN_LIST), verified=True)
        if token == "verified_entry_revoked":
            return _src(name, dict(CLEAN_LIST), verified=True)  # revoked entries are absent from shards
        if token == "verified_entry_pending_review":
            return _src(name, _list_hit(item, "pending_review"), verified=True)
        if token == "verified_entry_approved":
            return _src(name, _list_hit(item, "approved"), verified=True)
        if token == "verified_but_canary_missing":
            return _src(name, dict(CLEAN_LIST), verified=True, canary_ok=False)
        if token in LIST_FAIL_REASON:
            # The verifier's own outcome is covered in the sign/verify tests; here it is the input.
            return _src(name, {}, status="failed", http_status=None, list_reason=LIST_FAIL_REASON[token])
    raise unittest.SkipTest("setup %s=%r not expressible" % (name, token))


def _run_case(case):
    item = _item(case["item"])
    sources = []
    for name, token in case["setup"].items():
        if name in ("npm_registry", "pypi_registry", "cache", "checker"):
            raise unittest.SkipTest("setup %s not expressible" % name)
        src = _build_source(name, token, item)
        if src is not None:
            src["source"] = name
            sources.append(src)
    return C.decide(item, sources, now=NOW, finding_id=FID,
                    finding_path="~/.kings-taster/findings/%s.json" % FID)


class TestConformanceCases(unittest.TestCase):
    def test_every_case_is_run_or_skipped_by_name(self):
        ids = {c["id"] for c in CASES}
        self.assertLessEqual(set(SKIP), ids)

    def test_cases(self):
        ran = 0
        for case in CASES:
            with self.subTest(case=case["id"]):
                if case["id"] in SKIP:
                    continue
                try:
                    rec, lines = _run_case(case)
                except unittest.SkipTest as exc:
                    self.fail("case %s has no mapping and no SKIP entry: %s" % (case["id"], exc))
                exp = case["expected"]
                self.assertEqual(rec["result"], exp["result"], rec["explanation"])
                for reason in exp["reasons_include"]:
                    self.assertIn(reason, rec["reasons"])
                for reason in exp["reasons_exclude"]:
                    self.assertNotIn(reason, rec["reasons"])
                if "budget" in exp:
                    self.assertLessEqual(len(lines), exp["budget"]["max_verdict_lines"])
                ran += 1
        self.assertGreater(ran, 20)


class TestPopularListRuleAgreement(unittest.TestCase):
    """SPEC.md §7.2: skill text, extractor output, and decide() agree on list pending_review."""

    def test_skill_extractor_and_decide_agree(self):
        body, commands = C.split_skill()
        flat = " ".join(body.split())
        self.assertIn("list hit with review_state pending_review is Caution, never Block", flat)
        self.assertIn("review_state=%s", commands)
        self.assertIn("Classify the item (package, repo, or link). Run every required source.", flat)
        by_id = {c["id"]: c for c in CASES}
        for cid, hold in (("prec-popular-list-pending", True), ("prec-popular-list-approved", False)):
            rec, _ = _run_case(by_id[cid])
            self.assertEqual(rec["result"], "caution" if hold else "block")
            self.assertIn("pending_review" if hold else "malicious_match", rec["reasons"])
            self.assertNotIn("malicious_match" if hold else "pending_review", rec["reasons"])


if __name__ == "__main__":
    unittest.main()
