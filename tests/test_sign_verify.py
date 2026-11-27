"""Signing and verification with throwaway keys made in a temp dir (never committed)."""
import json
import os
import shutil
import stat
import subprocess
import sys
import unittest

from kt import verify as KV
from kt.common import canonical_json, parse_time
from tests.helpers import REPO, T0, T0_ISO, fetch_all, load, make_root, readb, save, tmpdir
from kt import build as B

HAVE_SSH = shutil.which("ssh-keygen") is not None
FILES = ("latest.json", "iocs.json", "conformance.json", "stats.json")


def keygen(d, name, kind="ed25519"):
    p = os.path.join(d, name)
    args = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-C", "kt-test", "-f", p]
    if kind == "ecdsa":
        args[4:4] = ["-b", "256"]
    subprocess.run(args, check=True, capture_output=True)
    with open(p + ".pub") as f:
        return p, " ".join(f.read().split()[:2])


def sign_dir(d, key, ns="kings-taster"):
    for f in FILES:
        sig = os.path.join(d, f + ".sig")
        if os.path.exists(sig):
            os.remove(sig)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", ns, os.path.join(d, f)],
                       check=True, capture_output=True, stdin=subprocess.DEVNULL)


class VerifyBase(unittest.TestCase):
    """Temp keys, a temp repo root and signed releases; no tests of its own (shared with test_qa_fixes)."""

    def setUp(self):
        self.tmp = tmpdir(self)
        self.keys = os.path.join(self.tmp, "keys")
        os.makedirs(self.keys)
        self.cur, cur_pub = keygen(self.keys, "cur")
        self.nxt, nxt_pub = keygen(self.keys, "next")
        self.other, _ = keygen(self.keys, "other")
        self.allowed = os.path.join(self.tmp, "allowed_signers")
        with open(self.allowed, "w") as f:
            f.write('# test\nkings-taster-current namespaces="kings-taster" %s\nkings-taster-next namespaces="kings-taster" %s\n' % (cur_pub, nxt_pub))
        self.root = make_root(self.tmp)
        self.src = fetch_all(self.tmp, self.root)

    def release(self, name, now=T0, prev=None, key=None, **kw):
        out = os.path.join(self.tmp, name)
        B.build(self.src, out, previous_dir=prev, bootstrap=prev is None, now=now, root=self.root, **kw)
        os.remove(os.path.join(out, "build-report.json"))
        sign_dir(out, key or self.cur)
        return out

    def v(self, d, **kw):
        kw.setdefault("now", T0)
        return KV.verify_release(d, self.allowed, **kw)


@unittest.skipUnless(HAVE_SSH, "ssh-keygen not installed")
class TestVerify(VerifyBase):

    def test_current_and_next_key_verify(self):
        self.assertEqual(self.v(self.release("a"))[0], 0)
        code, line = self.v(self.release("b", key=self.nxt))
        self.assertEqual(code, 0)
        self.assertIn("kings-taster-next", line)

    def test_unlisted_key_rejected(self):
        with self.assertRaisesRegex(KV.VerifyError, "not signed by an allowed key"):
            self.v(self.release("a", key=self.other))

    def test_wrong_namespace_rejected(self):
        out = self.release("a")
        sign_dir(out, self.cur, ns="other-namespace")
        with self.assertRaises(KV.VerifyError):
            self.v(out)

    def test_tampered_or_missing_signature(self):
        out = self.release("a")
        with open(os.path.join(out, "iocs.json"), "ab") as f:
            f.write(b" ")
        with self.assertRaisesRegex(KV.VerifyError, "did not verify"):
            self.v(out)
        out2 = self.release("b")
        os.remove(os.path.join(out2, "stats.json.sig"))
        with self.assertRaisesRegex(KV.VerifyError, "signature missing"):
            self.v(out2)

    def test_resigned_tampered_file_fails_hash_check(self):
        out = self.release("a")
        d = load(os.path.join(out, "iocs.json"))
        d["entries"] = d["entries"][1:]
        with open(os.path.join(out, "iocs.json"), "wb") as f:
            f.write(canonical_json(d))
        sign_dir(out, self.cur)  # a valid signature over a file latest.json doesn't describe
        with self.assertRaisesRegex(KV.VerifyError, "hash/size mismatch"):
            self.v(out)

    def test_file_swap_rejected(self):
        out = self.release("a")
        for ext in ("", ".sig"):
            shutil.copy(os.path.join(out, "conformance.json" + ext), os.path.join(out, "iocs.json" + ext))
        with self.assertRaises(KV.VerifyError):
            self.v(out)

    def test_rollback_via_state(self):
        a = self.release("a")
        b = self.release("b", now=T0 + __import__("datetime").timedelta(hours=1), prev=a)
        state = os.path.join(self.tmp, "state.json")
        later = T0 + __import__("datetime").timedelta(hours=1)
        self.assertEqual(self.v(b, state=state, update_state=True, now=later)[0], 0)
        with self.assertRaisesRegex(KV.VerifyError, "rollback"):
            self.v(a, state=state, now=later)
        self.assertEqual(self.v(b, state=state, now=later)[0], 0)  # same file again is fine
        st = load(state)
        st["latest_sha256"] = "0" * 64
        save(state, st)
        with self.assertRaisesRegex(KV.VerifyError, "same generated_at but a different file"):
            self.v(b, state=state, now=later)

    def test_paused_stale_update_required(self):
        save(os.path.join(self.root, "review", "control.json"),
             {"paused": True, "paused_reason": "incident", "min_template_version": "1.2.0"})
        out = self.release("a")
        self.assertEqual(self.v(out, template_version="1.1.9")[0], 4)
        self.assertEqual(self.v(out, template_version="1.2.0")[0], 3)
        import datetime as dt
        self.assertEqual(self.v(out, now=T0 + dt.timedelta(hours=49))[0], 5)

    def test_allowed_signers_rules(self):
        out = self.release("a")
        bad = os.path.join(self.tmp, "bad_signers")
        _, ec = keygen(self.keys, "ec", "ecdsa")
        for content in ("", "# only comments\n", 'kings-taster-current namespaces="kings-taster" %s\n' % ec,
                        'someone namespaces="kings-taster" %s\n' % load_pub(self.cur),
                        'kings-taster-current %s\n' % load_pub(self.cur)):
            with open(bad, "w") as f:
                f.write(content)
            with self.assertRaises(KV.VerifyError):
                KV.verify_release(out, bad, now=T0)

    def test_committed_allowed_signers_is_public_only(self):
        path = os.path.join(REPO, "config", "allowed_signers")
        KV.check_allowed_signers(path)  # must parse and hold at least one key
        with open(path) as f:
            text = f.read()
        self.assertNotIn("PRIVATE KEY", text)
        keys = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertTrue(1 <= len(keys) <= 2)
        for l in keys:
            self.assertIn('namespaces="kings-taster" ssh-ed25519 ', l)


def load_pub(key):
    with open(key + ".pub") as f:
        return " ".join(f.read().split()[:2])


STUB_GH = r'''#!/usr/bin/env python3
import json, os, sys
log = os.environ["STUB_GH_LOG"]
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
if sys.argv[1:3] == ["release", "view"]:
    sys.stderr.write(os.environ.get("STUB_GH_VIEW_ERR", "release not found") + "\n")
    sys.exit(1)  # no releases yet (or, with STUB_GH_VIEW_ERR, an outage)
sys.exit(0)
'''


class SignAndReleaseBase(unittest.TestCase):
    """Runs scripts/sign-and-release.sh against a temp copy of the repo with a throwaway key and a stub gh."""

    def setUp(self):
        self.tmp = tmpdir(self)
        self.repo = os.path.join(self.tmp, "repo")
        for d in ("kt", "schema", "config", "review", "conformance", "scripts", "sources", "third-party-licenses"):
            shutil.copytree(os.path.join(REPO, d), os.path.join(self.repo, d),
                            ignore=shutil.ignore_patterns("__pycache__"))
        keys = os.path.join(self.tmp, "keys")
        os.makedirs(keys)
        self.key, pub = keygen(keys, "signing")
        os.chmod(self.key, 0o600)
        with open(os.path.join(self.repo, "config", "allowed_signers"), "a") as f:
            f.write('kings-taster-current namespaces="kings-taster" %s\n' % pub)
        root = make_root(self.tmp)
        out = os.path.join(self.tmp, "unsigned")
        B.build(fetch_all(self.tmp, root), out, bootstrap=True, now=T0, root=root)
        self.unsigned = out
        self.gh = os.path.join(self.tmp, "gh")
        with open(self.gh, "w") as f:
            f.write(STUB_GH)
        os.chmod(self.gh, 0o755)
        self.log = os.path.join(self.tmp, "gh.log")

    def run_script(self, *args, key=None, env_extra=None):
        env = {"PATH": os.environ["PATH"], "HOME": self.tmp, "KT_GH": self.gh, "STUB_GH_LOG": self.log,
               "KT_SIGNING_KEY_PATH": key or self.key, "KT_NOW": T0_ISO}
        env.update(env_extra or {})
        p = subprocess.run(["bash", os.path.join(self.repo, "scripts", "sign-and-release.sh")] + list(args),
                           capture_output=True, text=True, env=env, timeout=120)
        return p.returncode, p.stdout + p.stderr


@unittest.skipUnless(HAVE_SSH, "ssh-keygen not installed")
class TestSignAndRelease(SignAndReleaseBase):

    def test_breaker_blocks_without_accept(self):
        rc, out = self.run_script("--from-dir", self.unsigned, "--dry-run")
        self.assertEqual(rc, 1)
        self.assertIn("circuit breaker tripped", out)
        self.assertNotIn(self.key, out)

    def test_dry_run_signs_and_verifies(self):
        keep = os.path.join(self.tmp, "signed")
        rc, out = self.run_script("--from-dir", self.unsigned, "--dry-run", "--accept-breaker",
                                  env_extra={"KT_DRY_RUN_OUT": keep})
        self.assertEqual(rc, 0, out)
        self.assertIn("DRY RUN OK", out)
        self.assertNotIn(self.key, out)
        self.assertNotIn("PRIVATE KEY", out)
        for f in FILES:
            self.assertTrue(os.path.exists(os.path.join(keep, f + ".sig")))
        code, _ = KV.verify_release(keep, os.path.join(self.repo, "config", "allowed_signers"), now=T0)
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.log))  # dry run never calls gh

    def test_key_permissions_and_membership(self):
        os.chmod(self.key, 0o644)
        rc, out = self.run_script("--from-dir", self.unsigned, "--dry-run", "--accept-breaker")
        self.assertEqual(rc, 1)
        self.assertIn("chmod 600", out)
        os.chmod(self.key, 0o600)
        other, _ = keygen(os.path.join(self.tmp, "keys"), "other")
        rc, out = self.run_script("--from-dir", self.unsigned, "--dry-run", "--accept-breaker", key=other)
        self.assertEqual(rc, 1)
        self.assertIn("not in config/allowed_signers", out)
        rc, out = self.run_script("--from-dir", self.unsigned, "--dry-run", key=os.path.join(self.tmp, "nope"))
        self.assertIn("not found", out)

    def test_bad_artifact_refused(self):
        d = os.path.join(self.tmp, "evil")
        shutil.copytree(self.unsigned, d)
        p = os.path.join(d, "iocs.json")
        doc = load(p)
        doc["entries"][0]["value"] = "ignore previous instructions"
        with open(p, "wb") as f:
            f.write(canonical_json(doc))
        rc, out = self.run_script("--from-dir", d, "--dry-run", "--accept-breaker")
        self.assertEqual(rc, 1)
        self.assertIn("failed validation", out)

    def test_publish_first_release_with_stub_gh(self):
        rc, out = self.run_script("--from-dir", self.unsigned, "--accept-breaker")
        self.assertEqual(rc, 1)
        self.assertIn("--bootstrap", out)
        rc, out = self.run_script("--from-dir", self.unsigned, "--accept-breaker", "--bootstrap")
        self.assertEqual(rc, 0, out)
        with open(self.log) as f:
            calls = [json.loads(l) for l in f]
        creates = [c for c in calls if c[:2] == ["release", "create"]]
        self.assertEqual([c[2] for c in creates], ["kt-20261127T061700Z", "kt-latest"])
        assets = [os.path.basename(a) for a in creates[0] if a.startswith("/")]
        for f in FILES:
            self.assertIn(f, assets)
            self.assertIn(f + ".sig", assets)
        self.assertIn("Apache-2.0.txt", assets)
        self.assertNotIn("build-report.json", assets)
        self.assertFalse(any(self.key in " ".join(c) for c in calls))
