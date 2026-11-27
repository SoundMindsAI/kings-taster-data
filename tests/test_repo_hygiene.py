import ast
import glob
import os
import subprocess
import sys
import unittest

from tests.helpers import REPO, load, tmpdir

sys.path.insert(0, os.path.join(REPO, "scripts"))
import secret_scan  # noqa: E402

# Fake secrets are assembled at runtime so the tree itself never contains one.
import base64
import hashlib


def _rand(n, seed):
    out = ""
    i = 0
    while len(out) < n:
        out += "".join(c for c in base64.b64encode(hashlib.sha256((seed + str(i)).encode()).digest()).decode() if c.isalnum())
        i += 1
    return out[:n]


FAKE = {
    "private_key_block": "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "github_token": "gh" + "p_" + _rand(36, "gh"),
    "aws_access_key": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    "jwt": "eyJ" + _rand(20, "a") + ".eyJ" + _rand(24, "b") + "." + _rand(43, "c"),
    "high_entropy": _rand(40, "entropy"),
    "credential_assignment": "api_key = " + '"' + _rand(20, "cred") + '"',
}
EMAIL = "someone" + "@" + "corp.example.net"
PHONE = "+1 555" + "-123-" + "4567"


class TestSecretScan(unittest.TestCase):
    def test_each_rule_fires(self):
        for rule, text in FAKE.items():
            with self.subTest(rule=rule):
                fails, _ = secret_scan.scan_line("x " + text + " y")
                self.assertIn(rule, [r for r, _ in fails])

    def test_never_prints_the_secret(self):
        fails, _ = secret_scan.scan_line(FAKE["github_token"])
        for _, hint in fails:
            self.assertNotIn(FAKE["github_token"][5:], hint)

    def test_hashes_pubkeys_urls_not_flagged(self):
        ok = ["c3be89b9aff55946faee6eff6e0e082e75dcc9de8090ad8ea7fe0d50a0c35fdb",
              "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGmPZsVmpRn5J3kyd8b1v1tfPh6rC4s7dmB0B4lGv9bQ",
              "https://github.com/pypa/advisory-database/blob/main/vulns/praisonaiagents/PYSEC-2026-2946",
              "sha512-mwmuZxEx0xI9CC8bjxJKSZORQBN6ZH0ow0XX+h0dEpaKfr8U1Op8daRgXrmBpbbdzQr/PXeaonjBiV2zgBRKhQ=="]
        for line in ok:
            self.assertEqual(secret_scan.scan_line(line)[0], [], line[:20])

    def test_emails_and_phones_flag_only(self):
        fails, flags = secret_scan.scan_line("mail %s or call %s" % (EMAIL, PHONE))
        self.assertEqual(fails, [])
        self.assertEqual(sorted(r for r, _ in flags), ["email", "phone"])
        self.assertEqual(secret_scan.scan_line("support@soundminds.ai")[1], [])

    def test_tree_scan_and_exit_code(self):
        d = tmpdir(self)
        with open(os.path.join(d, "ok.txt"), "w") as f:
            f.write("nothing here\n")
        self.assertEqual(secret_scan.main([d]), 0)
        with open(os.path.join(d, "bad.txt"), "w") as f:
            f.write(FAKE["aws_access_key"] + "\n")
        self.assertEqual(secret_scan.main([d]), 1)

    def test_whole_repo_is_clean(self):
        self.assertEqual(secret_scan.main([REPO]), 0)


class TestRepoRules(unittest.TestCase):
    def py_files(self):
        return [p for p in glob.glob(os.path.join(REPO, "**", "*.py"), recursive=True) if "/.git/" not in p]

    def test_stdlib_only(self):
        allowed = set(sys.stdlib_module_names) | {"kt", "tests", "secret_scan"}
        for p in self.py_files():
            with open(p, encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mods = [node.module]
                for m in mods:
                    self.assertIn(m.split(".")[0], allowed, "%s imports %s" % (os.path.relpath(p, REPO), m))

    def test_no_dependency_manifests(self):
        for name in ("requirements.txt", "package.json", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"):
            self.assertFalse(os.path.exists(os.path.join(REPO, name)), name)

    def test_workflows_pinned_and_keyless(self):
        r = subprocess.run([sys.executable, os.path.join(REPO, "scripts", "check_pins.py"),
                            os.path.join(REPO, ".github", "workflows")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        for p in glob.glob(os.path.join(REPO, ".github", "workflows", "*.yml")):
            with open(p) as f:
                txt = f.read()
            self.assertNotIn("KT_SIGNING_KEY", txt)
            self.assertNotIn("secrets.", txt)
            self.assertNotIn("ssh-keygen -Y sign", txt)
            self.assertIn("permissions:\n  contents: read", txt)
            for line in txt.splitlines():  # expressions only as env/with values, never inside run scripts
                if "${{" in line:
                    self.assertRegex(line, r"^\s+[A-Za-z_-]+:\s*\$\{\{[^}]*\}\}\s*$", line)
                    self.assertNotRegex(line, r"^\s+run:")

    def test_no_key_material_committed(self):
        for p in glob.glob(os.path.join(REPO, "**", "*"), recursive=True):
            if "/.git/" in p or "__pycache__" in p or not os.path.isfile(p):
                continue
            with open(p, "rb") as f:
                self.assertNotRegex(f.read(), rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY", os.path.relpath(p, REPO))

    def test_schemas_have_no_handle_or_free_text_fields(self):
        bad = ("handle", "reporter", "username", "location", "comment_text", "free_text", "screen_name")
        for p in glob.glob(os.path.join(REPO, "schema", "*.json")):
            def walk(node):
                if isinstance(node, dict):
                    if node.get("type") == "object" and "properties" in node:
                        self.assertFalse(node.get("additionalProperties", True), p)
                    for k, v in node.get("properties", {}).items() if isinstance(node.get("properties"), dict) else []:
                        for b in bad:
                            self.assertNotIn(b, k, "%s: %s" % (os.path.basename(p), k))
                    for v in node.values():
                        walk(v)
                elif isinstance(node, list):
                    for v in node:
                        walk(v)
            walk(load(p))
