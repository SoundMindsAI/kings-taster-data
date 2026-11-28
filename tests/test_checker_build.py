"""Checker-builder skill (SPEC.md §5): caps, wording, snippets and the Google vectors. No network.

Wording note: the repo-wide grep for the banned-word list may only hit the popular-name line in
config/popular/npm.txt and the needle list in tests/test_check_skill.py. Don't add those words here.
"""
import os
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
            "next_page_token", "partial page set", "the list file and RDAP still run",
            "a link-reputation source", "Checklist mode still verifies", "https://api.osv.dev/v1/query",
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
            got = canon(B.decode_c_escapes(v["input"]), strict=False)
            self.assertEqual(got.encode("latin-1"), B.decode_c_escapes(v["expected"]), v["input"])

    def test_credits_google(self):
        code = B.snippet("canonicalize_url")
        self.assertIn("CC-BY 4.0", code)
        self.assertIn("https://developers.google.com/safe-browsing/v4/urls-hashing", code)

    def test_vectors_strict_default(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        refused = 0
        pct = 0
        space_control = 0
        for v in B.canonicalization_vectors():
            raw = B.decode_c_escapes(v["input"])
            try:
                got = canon(raw)
            except ValueError:
                refused += 1
                auth = re.split(rb"[/?]", raw.split(b"://", 1)[-1], maxsplit=1)[0]
                # Classify % in the host first; the remaining refusals are space/control.
                if b"%" in auth:
                    pct += 1
                else:
                    self.assertTrue(re.search(rb"[\x00-\x20]", raw), v["input"])
                    space_control += 1
                continue
            self.assertEqual(got.encode("latin-1"), B.decode_c_escapes(v["expected"]), v["input"])
        # The 6 strict refusals are 4 with % in the host and 2 with space/control.
        self.assertEqual((pct, space_control, refused), (4, 2, 6))

    def test_vectors_pass_non_strict(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for v in B.canonicalization_vectors():
            got = canon(B.decode_c_escapes(v["input"]), strict=False)
            self.assertEqual(got.encode("latin-1"), B.decode_c_escapes(v["expected"]), v["input"])

    def test_qa_host_confusion_is_refused(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for bad in (
            "http://evil.com\\@192.0.2.1/", "http://evil.com%5c@192.0.2.1/", "http://evil.com%5C@192.0.2.1/",
            "http://evil.com%255c@192.0.2.1/", "javascript:alert(1)", "http:/evil.com/x",
            "http:evil.com/x", "https:///evil.com/x", "http:///", "ftp://example.com/",
            "http://exa\x01mple.com/", "http://exa mple.com/", "http://evil.com%2f@192.0.2.1/",
            "http://evil.com%253f@192.0.2.1/", "http://évil.com/", "http://[::1]/", "http://1.2.3.256/",
        ):
            with self.assertRaises(ValueError, msg=bad):
                canon(bad)

    def test_strict_refuses_percent_in_authority(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for bad in ("http://good.com%252f@192.0.2.1/", "http://good.com%253f@192.0.2.1/",
                    "http://good.com%25252f@192.0.2.1/", "http://good.com%2540192.0.2.1/",
                    "http://good.com%41/", "http://good.com%2e%63om:80/"):
            with self.assertRaises(ValueError, msg=bad):
                canon(bad)
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_url(bad)
            with self.assertRaises(B.Refused, msg=bad):
                B.check_argv("link", url=bad)
        self.assertEqual(canon("http://example.com/a%2Fb"), "http://example.com/a/b")
        canon("http://example.com/?q=%252f")

    def test_strict_refuses_non_ascii_host(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for bad in ("http://evil\u3002com/", "http://evil\uff0ecom/", "http://evil\uff61com/",
                    "http://\uff25\uff36\uff29\uff2c.com/", "http://\u00e9vil.com/"):
            with self.assertRaises(ValueError, msg=bad):
                canon(bad)
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_url(bad)

    def test_strict_refuses_bad_numeric_and_bracket_hosts(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for bad in ("http://0x/", "http://4294967296/", "http://[evil.com]/", "http://1.2.3.256/",
                    "http://[::1]/", "http://1.2.3.4.5/"):
            with self.assertRaises(ValueError, msg=bad):
                canon(bad)
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_url(bad)
        self.assertEqual(canon("http://3279880203/blah"), "http://195.127.0.11/blah")
        self.assertEqual(canon("http://0x7f.1/"), "http://127.0.0.1/")

    def test_dots_follow_google_rules(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        self.assertEqual(canon("http://evil.com./"), "http://evil.com/")
        self.assertEqual(canon("http://evil.com../"), "http://evil.com/")
        self.assertEqual(canon("http://www.google.com.../"), "http://www.google.com/")
        for u in ("http://.evil.com/", "http://evil..com/", "http://.1.2.3.4/", "http://1..2/"):
            with self.assertRaises(ValueError, msg=u):
                canon(u)
            self.assertEqual(canon(u, strict=False), canon(u.replace("..", ".").replace("//.", "//")), u)

    def test_strict_refuses_numeric_tld_but_keeps_ips(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        for bad in ("http://evil.123/", "http://.1.2.3.4/", "http://1..2/"):
            with self.assertRaises(ValueError, msg=bad):
                canon(bad)
        self.assertEqual(canon("http://1.2.3.4/"), "http://1.2.3.4/")
        self.assertEqual(canon("http://127.1/"), "http://127.0.0.1/")

    def test_strict_false_keeps_percent_authority_vectors(self):
        canon = B.load_snippet("canonicalize_url")["canonicalize_url"]
        self.assertEqual(canon("http://host%23.com/", strict=False), "http://host%23.com/")

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


class TestArgvAndValidation(unittest.TestCase):
    def test_shell_probes_never_reach_a_shell(self):
        url = "http://x.example/a;echo INJECTED-RAN;#"
        with self.assertRaises(B.Refused):
            B.check_argv("link", url=url)
        for ok in (url.replace(" ", "%20"), "http://x.example/a;echo;#"):
            argv = B.check_argv("link", url=ok)
            self.assertIsInstance(argv, list)
            self.assertEqual(argv.count("--url=" + ok), 1)
        for bad in ("left-pad$(echo SUBST-RAN)", "a;b", "a b", "`x`", "a|b", "../x"):
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_package(bad, "1.0.0", "npm")
            with self.assertRaises(B.Refused, msg=bad):
                B.check_argv("package", name=bad, version="1.0.0", ecosystem="npm")

    def test_package_rules(self):
        self.assertEqual(B.validate_package("left-pad", "1.3.0", "npm"), ("left-pad", "1.3.0"))
        self.assertEqual(B.validate_package("@scope/pkg", "1.0", "npm")[0], "@scope/pkg")
        self.assertEqual(B.validate_package("Foo_Bar", "2.0+x", "PyPI")[1], "2.0+x")
        for name, ver, eco in (("x", "1;2", "npm"), ("x", "", "npm"), ("x", "$(id)", "npm"),
                               ("x", "1", "gem"), ("-x", "1", "PyPI"), ("x" * 215, "1", "npm")):
            with self.assertRaises(B.Refused, msg=(name, ver, eco)):
                B.validate_package(name, ver, eco)
        argv = B.check_argv("package", name="left-pad", version="1.3.0", ecosystem="npm")
        self.assertEqual(argv[:5], ["python3", "-I", "-s", B.CHECKER, "check"])
        self.assertIn("--name=left-pad", argv)
        self.assertNotIn("~", B.CHECKER)
        self.assertTrue(os.path.isabs(argv[3]), argv[3])
        self.assertNotIn("~", argv[3])

    def test_snippets_have_no_tilde_paths(self):
        _, snippets = B.split_skill()
        self.assertNotIn("~", snippets)

    def test_repo_rules(self):
        self.assertEqual(B.validate_repo("Owner/re.po_1"), "Owner/re.po_1")
        for bad in ("a", "a/b/c", "a/", "/b", "a/b;c", "a/$(x)", "../b", "a/..", "a/" + "b" * 101, 5):
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_repo(bad)
        self.assertEqual(B.check_argv("repo", name="o/r")[-1], "--name=o/r")

    def test_url_rules(self):
        self.assertEqual(B.validate_url("HTTP://Evil.com:80/a/../b#f"), "http://evil.com/b")
        for bad in ("ftp://x.example/", "javascript:alert(1)", "http://x.example/'a", 'http://x.example/"',
                    "http://x.example/a\x01", "http://x.example/a b", "http://x.example/\n",
                    "http://evil.com\\@192.0.2.1/", "http://evil.com%5c@192.0.2.1/", "https:///evil.com/x",
                    "http:/evil.com/x", "http:evil.com/x", 7):
            with self.assertRaises(B.Refused, msg=bad):
                B.validate_url(bad)
            with self.assertRaises(B.Refused, msg=bad):
                B.check_argv("link", url=bad)
        with self.assertRaises(B.Refused):
            B.check_argv("other")

    def test_skill_states_the_rules(self):
        text = B.skill_text()
        for needle in ("valid_package_name", "as an argv list with no shell", "Never put them into a shell string",
                       "^[A-Za-z0-9._-]{1,100}$", "^(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]{1,214}$",
                       "^[A-Za-z0-9._+-]{1,64}$", "If `canonicalize_url` refuses, the check is Unknown (`injection_seen`).",
                       "If that list can't be read or is empty, the hold doesn't apply: a live MAL- is Block, "
                       "and the answer says the list couldn't be read."):
            self.assertIn(needle, text, needle)


class TestKeys(unittest.TestCase):
    def test_domain_and_ip_keys(self):
        self.assertEqual(B.link_match_keys("http://Example.COM/a"),
                         [common.match_key("url", "http://example.com/a"), common.match_key("domain", "example.com")])
        keys = B.link_match_keys("http://3279880203/blah")
        self.assertEqual(keys, [common.match_key("url", "http://195.127.0.11/blah"),
                                common.match_key("ip", "195.127.0.11"), common.match_key("domain", "195.127.0.11")])

    def test_skill_requires_domain_and_ip(self):
        text = B.skill_text()
        for needle in ("`url-sha256:`, the `domain:` key", "`ip:` key", "SPEC.md §3.3 also requires a lookalike-name check",
                       "Apply the same rule `kings-taster-check` states, offline, with `python3 -E -s -m kt.lookalike`",
                       "Don't write a second algorithm"):
            self.assertIn(needle, text, needle)
        self.assertNotIn("Leave it out", text)


class TestRegexParityAndKeys(unittest.TestCase):
    def test_patterns_match_check_skill(self):
        with open(os.path.join(B.ROOT, "skills", "kings-taster-check.md"), encoding="utf-8") as f:
            check = f.read()
        name = re.search(r'NAME=re\.compile\(r"(\^\(@[^"]*)"\)', check).group(1)
        ver = re.search(r'VER=re\.compile\(r"([^"]*)"\)', check).group(1)
        repo = re.search(r'NAME=re\.compile\(r"(\^\[A-Za-z0-9\._-\]\{1,100\}\$)"\)', check).group(1)
        self.assertEqual(B.PKG_NAME.pattern.encode(), name.encode())
        self.assertEqual(B.PKG_VER.pattern.encode(), ver.encode())
        self.assertEqual(B.REPO_PART.pattern.encode(), repo.encode())

    def test_same_rule_as_valid_package_name(self):
        self.assertIn(
            "NAME must also pass the same rule as `kt.common.valid_package_name` for the ecosystem (npm, or PEP 508 for PyPI).",
            B.skill_text(),
        )

    def test_google_attribution_sentence(self):
        self.assertIn("A Safe Browsing hit must add Google's attribution and notice, with the exact text in the "
                      "`google-notice` block of `kings-taster-check` (`GOOGLE_ATTRIBUTION` and `GOOGLE_NOTICE` "
                      "in `kt.finding`).", B.skill_text())

    def test_safe_browsing_key_in_header(self):
        for name in ("kings-taster-check.md", "kings-taster-build.md"):
            with open(os.path.join(B.ROOT, "skills", name), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("x-goog-api-key", text, name)
            self.assertNotIn("?key=$SAFE_BROWSING_KEY", text, name)
            self.assertNotIn("urls:search?key=", text, name)
        self.assertIn(r"printf 'x-goog-api-key: %s\n'", text_of("kings-taster-check.md"))
        self.assertIn(r"printf 'x-goog-api-key: %s\n'", B.skill_text())
        self.assertIn("| curl -H @-", text_of("kings-taster-check.md"))
        self.assertIn("| curl -H @-", B.skill_text())
        self.assertIn("never appears in argv", text_of("kings-taster-check.md"))
        self.assertIn("never appears in argv", B.skill_text())
        self.assertIn("never appears in argv or the URL", B.skill_text())

    def test_skills_state_key_rules(self):
        for name in ("kings-taster-check.md", "kings-taster-build.md"):
            text = text_of(name)
            for needle in ("^[A-Za-z0-9_-]{1,128}$", "If it doesn't, that source has failed.",
                           "Never print the key", "re.fullmatch", "never grep",
                           "--data @FILE", "`-H @-` uses stdin", "the POST body must be `--data @FILE`"):
                self.assertIn(needle, text, (name, needle))
            self.assertIn("[[ $", text)
            self.assertRegex(text, r"\[\[ \$[A-Z_]+ =~ \^\[A-Za-z0-9_-\]\{1,128\}\$ \]\]")

    def test_skill_states_strict_refusals(self):
        text = B.skill_text()
        for needle in ("authority contains `%`", "never convert an IDN host to Punycode", "0x80",
                       "`[` or `]`", "not a valid IPv4 address", "leading dot or an empty label",
                       "last label is all digits",
                       "two or more trailing dots", "differs from Node.js behavior and is harmless"):
            self.assertIn(needle, text, needle)


def text_of(name):
    with open(os.path.join(B.ROOT, "skills", name), encoding="utf-8") as f:
        return f.read()


class TestOsvPin(unittest.TestCase):
    def test_pinned_endpoint_and_fail_closed(self):
        text = B.skill_text()
        for needle in ("`POST https://api.osv.dev/v1/query` only", "Never use querybatch",
                       "Require HTTP 200 and the exact effective URL `https://api.osv.dev/v1/query`",
                       "Accept `{}` as zero vulns (clean) only when that status and URL are confirmed.",
                       "A missing, unreadable or unconfirmed status file, a non-200, or a wrong URL "
                       "(including `/v1/querybatch`) is `injection_seen`.",
                       "`http_status` and `response_sha256`", "at most 20 pages", "^[A-Za-z0-9_-]{1,256}$",
                       "A 403 or 429 is `rate_limited`", "A non-2xx response is a failed source."):
            self.assertIn(needle, text, needle)
        self.assertNotIn("OSV batch", text)


class TestVerifierAndFetch(unittest.TestCase):
    def test_verifier_exception_and_steps(self):
        text = B.skill_text()
        self.assertNotIn("openssl", text.lower())
        self.assertIn("except the official list verifier already in this repo: `scripts/verify.sh` or "
                      "`python3 -E -s -m kt.verify`", text)
        for needle in ("-I kings-taster-current", "-I kings-taster-next", "`file_type`", "`keys.json`",
                       "`root_pins`", "64 KiB", "`--state`", "`--update-state`"):
            self.assertIn(needle, text, needle)

    def test_no_redirect_and_effective_host(self):
        text = B.skill_text()
        for needle in ("must refuse redirects", "check the host allowlist", "as an argv list with no shell",
                       "exactly one redirect", "require the effective host to be `github.com` or "
                       "`release-assets.githubusercontent.com`", "is `injection_seen` (Unknown)."):
            self.assertIn(needle, text, needle)

    def test_full_sentences(self):
        text = B.skill_text()
        for s in ("A canary passes only when `canary_ok` is exactly True; a missing result is not a pass.",
                  "Never treat a partial page set as clean.",
                  "Checklist mode still verifies the list with the same verifier.",
                  "An unverifiable list is Unknown (`unverified_list`)."):
            self.assertIn(s, text, s)
        self.assertNotIn("same verifier; an unverifiable", text)

    def test_lows(self):
        text = B.skill_text()
        for needle in ("`GOOGLE_ATTRIBUTION` and `GOOGLE_NOTICE`", "`google-notice` block",
                       "`kt.common.defang`", "`schema/finding-record.schema.json`",
                       "`conformance.json`; `conformance/cases.json` is the in-repo development copy",
                       "local directory of saved fixture files", "discard any partial verdict",
                       "mode 0o600"):
            self.assertIn(needle, text, needle)
        code = B.snippet("canonicalize_url")
        self.assertIn('"URLs and Hashing"', code)
        self.assertIn("(Safe Browsing APIs (v4)), CC-BY 4.0", code)
        self.assertIn("The live lookup is v5", code)


if __name__ == "__main__":
    unittest.main()
