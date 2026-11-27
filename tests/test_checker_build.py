"""Checker-builder skill (SPEC.md §5): caps, wording, snippets and the Google vectors. No network.

Wording note: the repo-wide grep for the banned-word list may only hit the popular-name line in
config/popular/npm.txt and the needle list in tests/test_check_skill.py. Don't add those words here.
"""
import re
import unittest

from kt import checker_build as B
from kt import common
from kt.check import body_banned_words

UNCLEARED = re.compile(
    r"abuse\.ch|feodo|ssl blacklist|urlhaus|threatfox|safedep|stepsecurity",
    re.IGNORECASE,
)
BANNED_NEEDLES = ("/workspace", "/home/box", "Boss", "Yak", "Copilot", "QA Lead", "XBot", "Planner")
BANNED_WORDS = re.compile("|".join(("1pass" + "word", "pa" + "per", "print" + "out", "vau" + "lt", "sy" + "nc", "u" + "sb")), re.IGNORECASE)


class TestCaps(unittest.TestCase):
    def setUp(self):
        self.body, self.snippets = B.split_skill()

    def test_caps_and_non_trivial(self):
        self.assertLessEqual(B.word_count(self.body), B.WORD_CAP)
        self.assertGreater(B.word_count(self.body), 500)
        self.assertLessEqual(B.snippet_line_count(self.snippets), B.SNIPPET_LINE_CAP)

    def test_title_and_layout(self):
        self.assertTrue(self.body.startswith("# kings-taster-build\n"))
        self.assertTrue(self.snippets.startswith("<!-- snippets -->\n## Snippets\n"))
        for name in B.SNIPPET_NAMES:
            self.assertIn("### %s\n" % name, self.snippets)


class TestWording(unittest.TestCase):
    def test_required_needles(self):
        text = B.skill_text()
        for needle in (
            "~/.kings-taster/checker.py", "standard library", "100%", "conformance.json",
            "Use this checker?", "SHA-256", "api.osv.dev", "api.github.com", "github.com",
            "release-assets.githubusercontent.com", "data.iana.org",
            "safebrowsing.googleapis.com", "ssh-keygen -Y verify", "keys.env",
            "checklist mode", "Never load this skill on a normal check",
            "Never run a package manager's install or build", "date -u",
            "finding record", '`mode`', '"checker"', "checker_sha256", "never on by default",
            "first-run offer", "--max-redirs 0", "--max-redirs 1", "injection_seen",
            "rate_limited", "checker_failed", "check_failed", "canary_ok", "tamper-proof",
            "Never say \"safe\"", "~/.kings-taster/findings/", "~/.kings-taster/state.json",
            "SPEC.md §10.1", "weekly",
            "next_page_token", "the list file and RDAP still run",
            "source_build_required", "lookalike", "health.json",
        ):
            self.assertIn(needle, text, needle)

    def test_no_banned_words(self):
        body, _ = B.split_skill()
        self.assertFalse(body_banned_words(body))

    def test_hygiene(self):
        for path in (B.SKILL_PATH, B.__file__):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertIsNone(UNCLEARED.search(text), path)
            self.assertIsNone(BANNED_WORDS.search(text), path)
            for needle in BANNED_NEEDLES:
                self.assertNotIn(needle, text, (path, needle))


class TestCanonicalize(unittest.TestCase):
    def test_every_google_vector(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        vectors = B.canonicalization_vectors()
        self.assertEqual(len(vectors), 33)
        for v in vectors:
            got = canon(B.decode_c_escapes(v["input"]))
            self.assertEqual(got.encode("latin-1"), B.decode_c_escapes(v["expected"]), v["input"])

    def test_credits_google(self):
        code = B.snippet("canonicalize_url")
        self.assertIn("CC-BY 4.0", code)
        self.assertIn("https://developers.google.com/safe-browsing/v4/urls-hashing", code)

    def test_userinfo_is_removed(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        self.assertEqual(canon("http://user:pass@example.com/a"), "http://example.com/a")
        self.assertEqual(canon("https://user:pass@192.0.2.1:443/x"), "https://192.0.2.1/x")


class TestMatchKey(unittest.TestCase):
    def test_agrees_with_common(self):
        mk = B.load_snippet("match_key")["match_key"]
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        cases = [
            ("package", "Left_Pad", "npm"), ("package", "@Scope/Pkg", "npm"),
            ("package", "Foo.Bar_baz--Qux", "PyPI"), ("domain", "BÜCHER.example.", None),
            ("domain", "Evil.COM", None), ("ip", "192.0.2.1", None), ("hash", "ABCDEF0123", None),
            ("repo_owner", "SomeOwner", None), ("cve", "CVE-2024-12345", None),
            ("url", canon("HTTP://Evil.com:80/a/../b#f"), None),
        ]
        for t, v, eco in cases:
            self.assertEqual(mk(t, v, eco), common.match_key(t, v, eco), (t, v))
        self.assertEqual(mk("package", "Foo_Bar", "PyPI"), "pypi:" + common.normalize_package("PyPI", "Foo_Bar"))
        with self.assertRaises(ValueError):
            mk("nope", "x")


class TestAllowlists(unittest.TestCase):
    def test_fields(self):
        ns = B.load_snippet("field_allowlists")
        allowed = ns["ALLOWED_FIELDS"]
        self.assertEqual(ns["MAX_EXTRACT_LINES"], 10)
        expect = {
            "osv": {"osv_count", "id", "kind", "date", "fixed", "class"},
            "github": {"full_name", "created_at", "pushed_at", "private", "fork", "archived"},
            "list": {"list_hits", "id", "type", "date", "canary", "review_state", "class"},
            "rdap": {"ldhName", "registration", "expiration", "status", "class"},
            "safe_browsing": {"sb_hits", "threat", "class"},
        }
        for src, fields in expect.items():
            self.assertTrue(fields <= set(allowed[src]), src)
        free_text = {"readme", "description", "details", "remarks", "scripts"}
        for src, fields in allowed.items():
            self.assertFalse(free_text & set(fields), src)
        self.assertTrue(free_text <= set(ns["NEVER_KEEP"]))
        self.assertEqual(set(ns["CLASSES"]["osv"]), {"malicious", "vulnerable", "clean", "injection_seen"})
        self.assertEqual(set(ns["CLASSES"]["rdap"]), {"ok", "no_rdap", "injection_seen"})
        self.assertEqual(set(ns["CLASSES"]["safe_browsing"]), {"hit", "clean", "injection_seen"})


class TestHelper(unittest.TestCase):
    def test_snippet_extraction_and_compile(self):
        for name in B.SNIPPET_NAMES:
            code = B.snippet(name)
            self.assertNotIn("```", code)
            compile(code, name, "exec")
            self.assertTrue(B.load_snippet(name))
        with self.assertRaises(ValueError):
            B.snippet("missing")

    def test_snippets_are_stdlib_only(self):
        for name in B.SNIPPET_NAMES:
            mods = re.findall(r"^\s*(?:import|from)\s+(\w+)", B.snippet(name), re.M)
            self.assertTrue(set(mods) <= {"re", "hashlib"}, (name, mods))

    def test_decode_c_escapes(self):
        self.assertEqual(B.decode_c_escapes("a\\tb\\r\\n\\x01\\x80"), b"a\tb\r\n\x01\x80")


if __name__ == "__main__":
    unittest.main()
