"""The shared URL parser and its call sites must agree. Local only, no network."""
import unittest

from kt import check as C
from kt import finding
from kt import refresh as R
from kt import urlcheck as U

LP = "/SoundMindsAI/kings-taster-data/releases/download/kt-latest/latest.json"
OFFICIAL = "https://github.com" + LP
AT = "@"

# (label, url, expected). expected is whether the list-download URL is accepted.
LIST_CASES = [
    ("official", OFFICIAL, True),
    ("official sig", OFFICIAL + ".sig", True),
    ("mixed-case host", "https://GitHub.com" + LP, True),
    ("http scheme", "http://github.com" + LP, False),
    ("other host", "https://evil.example" + LP, False),
    ("L3 port", "https://github.com:8443" + LP, False),
    ("port 443", "https://github.com:443" + LP, False),
    ("bad port", "https://github.com:-0" + LP, False),
    ("empty port", "https://github.com:" + LP, False),
    ("L1 userinfo with colon", "https://github.com:x" + AT + "evil.example" + LP, False),
    ("userinfo", "https://user" + AT + "github.com" + LP, False),
    ("userinfo, real host last", "https://evil.example" + AT + "github.com" + LP, False),
    ("N10 query", "https://evil.example?x=" + AT + "github.com" + LP, False),
    ("N10 fragment", "https://evil.example#x=" + AT + "github.com" + LP, False),
    ("N12 backslash", "https://evil.example\\" + AT + "github.com" + LP, False),
    ("N12 semicolon", "https://evil.example;" + AT + "github.com" + LP, False),
    ("N12 tab", "https://evil.example\t" + AT + "github.com" + LP, False),
    ("L2 space", "https://github.com /x" + LP, False),
    ("L2 CR", "https://github.com\r" + LP, False),
    ("L2 LF", "https://github.com\n" + LP, False),
    ("L-R2-1 tab in path", "https://github.com/SoundMindsAI/kings-taster-data/releases/down\tload/kt-latest/latest.json", False),
    ("L-R2-1 CR in path", "https://github.com/SoundMindsAI/kings-taster-data/releases/down\rload/kt-latest/latest.json", False),
    ("L-R2-1 LF in path", "https://github.com/SoundMindsAI/kings-taster-data/releases/down\nload/kt-latest/latest.json", False),
    ("L-R2-1 DEL in path", "https://github.com/SoundMindsAI/kings-taster-data/releases/down\x7fload/kt-latest/latest.json", False),
    ("leading space", " " + OFFICIAL, False),
    ("dotdot", "https://github.com/SoundMindsAI/kings-taster-data/releases/download/../../evil/x", False),
]


class TestSharedUrlParser(unittest.TestCase):
    def test_list_download_url_ok_and_list_url_allowed_agree(self):
        for label, url, expected in LIST_CASES:
            with self.subTest(label):
                self.assertEqual(U.list_download_url_ok(url), expected)
                self.assertEqual(R.list_url_allowed(url), expected)
                if url.startswith("https://") and expected:
                    self.assertTrue(C.host_allowed(url))

    def test_host_allowed_refuses_what_the_parser_refuses(self):
        for label, url, expected in LIST_CASES:
            if url.startswith("http://") or label == "dotdot":
                continue
            with self.subTest(label):
                self.assertEqual(C.host_allowed(url), expected)
                self.assertEqual(C.host_allowed("github.com", url), expected)
                self.assertEqual(C.host_allowed(OFFICIAL, url), expected)
                self.assertEqual(C.host_allowed(url, OFFICIAL), expected)

    def test_redirect_hosts(self):
        redirect = "https://release-assets.githubusercontent.com/x/y"
        self.assertTrue(U.list_download_url_ok(redirect, list_redirect=True))
        self.assertTrue(R.list_url_allowed(redirect, list_redirect=True))
        self.assertFalse(U.list_download_url_ok(redirect))
        self.assertFalse(U.list_download_url_ok(
            "https://release-assets.githubusercontent.com:8443/x/y", list_redirect=True))

    def test_same_host_n3(self):
        self.assertTrue(U.same_host(OFFICIAL, "https://GITHUB.com/other"))
        self.assertFalse(U.same_host(OFFICIAL, "https://evil.example" + LP))
        self.assertFalse(U.same_host(OFFICIAL, "https://github.com:8443" + LP))

    def test_official_link_ok_matches_official_url_problem(self):
        hosts = finding.EXPLANATION_URL_HOSTS
        cases = [
            ("https://osv.dev/vulnerability/MAL-2026-1", None),
            ("https://github.com/advisories/GHSA-abcd-efgh-ijkm", None),
            ("https://github.com" + LP, None),
            ("https://osv.dev:-0/vulnerability/X", "unparsable"),
            ("https://osv.dev:443/vulnerability/X", "not an official https host"),
            ("https://osv.dev:0/vulnerability/X", "not an official https host"),
            ("https://user" + AT + "osv.dev/vulnerability/X", "not an official https host"),
            ("https://osv.dev?x=1/vulnerability/X", "not an official https host"),
            ("https://osv.dev/vulnerability/X Y", "whitespace or control character"),
            ("https://osv.dev/vulnerability/X\rY", "whitespace or control character"),
            ("https://osv.dev/vulnerability/X\nY", "whitespace or control character"),
            ("https://osv.dev/vulnerability/X\tY", "whitespace or control character"),
            ("https://osv.dev/vulnerability/..%2fx", "encoded dot, slash or backslash"),
            ("https://github.com/evil/repo", "github.com link outside advisories and the kings-taster-data repo"),
        ]
        for url, expected in cases:
            with self.subTest(url=url):
                self.assertEqual(finding.official_url_problem(url, hosts), expected)
                self.assertEqual(U.official_link_ok(url, hosts)[0] is None, expected is None
                                 or expected.startswith("github.com"))

    def test_l2_whitespace_is_a_problem_not_a_crash(self):
        hosts = finding.EXPLANATION_URL_HOSTS
        for bad in (" ", "\r", "\n"):
            self.assertIsNotNone(finding.official_url_problem("https://osv.dev/vulnerability/X" + bad, hosts))
            self.assertIsNotNone(finding.official_url_problem("https://osv.dev" + bad + "/vulnerability/X", hosts))

    def test_bare_host_refusals(self):
        for bad in ("evil" + AT + "github.com", "github.com:443", "github.com\\x", "a b", ""):
            with self.assertRaises(ValueError, msg=bad):
                U.bare_host(bad)
        self.assertEqual(U.bare_host("GitHub.com"), "github.com")


if __name__ == "__main__":
    unittest.main()
