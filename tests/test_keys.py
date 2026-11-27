"""keys.json format and verification. Throwaway keys are made in a temp dir and never committed."""
import datetime as dt
import os
import shutil
import subprocess
import unittest

from kt import keys as K
from kt.common import canonical_json, fmt_time, sha256_bytes
from tests.helpers import REPO, T0, tmpdir

HAVE_SSH = shutil.which("ssh-keygen") is not None


def keygen(d, name):
    p = os.path.join(d, name)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kt-test", "-f", p],
                   check=True, capture_output=True)
    with open(p + ".pub") as f:
        return p, " ".join(f.read().split()[:2])


def blob(pub):
    return pub.split()[1]


def sign_file(path, key, ns=K.NAMESPACE):
    sig = path + ".sig"
    if os.path.exists(sig):
        os.remove(sig)
    subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", key, "-n", ns, path],
                   check=True, capture_output=True, stdin=subprocess.DEVNULL)


def write_pins(path, root_pub, backup_pub=None):
    lines = ['# test pins', 'kings-taster-root namespaces="kings-taster-keys" %s' % root_pub]
    if backup_pub:
        lines.append('kings-taster-root-backup namespaces="kings-taster-keys" %s' % backup_pub)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def keys_doc(current_pub, now=T0, next_pub=None, revoked=None, days=90, start=None):
    start = start or now
    end = start + dt.timedelta(days=days)
    def entry(role, pub):
        b = blob(pub)
        return {"role": role, "principal": K.ROLE_PRINCIPAL[role], "algorithm": "ssh-ed25519",
                "public_key": b, "fingerprint": K.fingerprint_of(b),
                "valid_after": fmt_time(start), "valid_before": fmt_time(end)}
    doc = {"file_type": "keys", "schema_version": 1, "generated_at": fmt_time(now),
           "signing_keys": [entry("current", current_pub)], "revoked_keys": list(revoked or [])}
    if next_pub:
        doc["signing_keys"].append(entry("next", next_pub))
    return doc


def write_keys(d, doc):
    path = os.path.join(d, "keys.json")
    with open(path, "wb") as f:
        f.write(canonical_json(doc))
    return path


@unittest.skipUnless(HAVE_SSH, "ssh-keygen not installed")
class TestKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir(self)
        self.root_priv, self.root_pub = keygen(self.tmp, "root")
        self.bak_priv, self.bak_pub = keygen(self.tmp, "backup")
        self.cur_priv, self.cur_pub = keygen(self.tmp, "current")
        self.nxt_priv, self.nxt_pub = keygen(self.tmp, "next")
        self.other_priv, self.other_pub = keygen(self.tmp, "other")
        self.pins = os.path.join(self.tmp, "root_pins")
        write_pins(self.pins, self.root_pub, self.bak_pub)

    def signed(self, doc=None, key=None):
        path = write_keys(self.tmp, doc or keys_doc(self.cur_pub))
        sign_file(path, key or self.root_priv)
        return path

    def test_fingerprint_matches_ssh_keygen(self):
        pub_path = self.cur_priv + ".pub"
        out = subprocess.run(["ssh-keygen", "-lf", pub_path, "-E", "sha256"],
                             check=True, capture_output=True, text=True).stdout
        ssh_fp = out.split()[1]  # SHA256:...
        self.assertEqual(K.fingerprint_of(blob(self.cur_pub)), ssh_fp)

    def test_committed_pins_are_empty_placeholder(self):
        pins = K.load_root_pins(os.path.join(REPO, "config", "root_pins"))
        self.assertEqual(pins, [])
        path = self.signed()
        with self.assertRaisesRegex(K.KeysError, "not published yet"):
            K.verify_keys_file(path, os.path.join(REPO, "config", "root_pins"), now=T0)

    def test_valid_keys_signed_by_root_accepted(self):
        path = self.signed()
        doc, raw, signer = K.verify_keys_file(path, self.pins, now=T0)
        self.assertEqual(signer, "kings-taster-root")
        self.assertTrue(K.signing_key_usable(doc, now=T0, principal="kings-taster-current"))
        text = K.allowed_signers_text(doc, now=T0)
        self.assertIn("kings-taster-current", text)
        self.assertEqual(raw, canonical_json(doc))

    def test_rotation_signed_by_backup_root_accepted(self):
        old_fp = K.fingerprint_of(blob(self.cur_pub))
        new_priv, new_pub = keygen(self.tmp, "current2")
        doc = keys_doc(new_pub, now=T0 + dt.timedelta(days=1))
        doc["revoked_keys"] = [{"fingerprint": old_fp, "principal": "kings-taster-current",
                                "revoked_at": fmt_time(T0 + dt.timedelta(days=1)), "reason": "rotated"}]
        path = self.signed(doc, key=self.bak_priv)
        got, _, signer = K.verify_keys_file(path, self.pins, now=T0 + dt.timedelta(days=1))
        self.assertEqual(signer, "kings-taster-root-backup")
        self.assertTrue(K.signing_key_usable(got, now=T0 + dt.timedelta(days=1), fingerprint=K.fingerprint_of(blob(new_pub))))
        self.assertFalse(K.signing_key_usable(got, now=T0 + dt.timedelta(days=1), fingerprint=old_fp))

    def test_unsigned_keys_refused(self):
        path = write_keys(self.tmp, keys_doc(self.cur_pub))
        with self.assertRaisesRegex(K.VerifyError, "signature missing"):
            K.verify_keys_file(path, self.pins, now=T0)

    def test_unknown_signer_refused(self):
        path = self.signed(key=self.other_priv)
        with self.assertRaisesRegex(K.VerifyError, "not signed by an allowed key"):
            K.verify_keys_file(path, self.pins, now=T0)

    def test_expired_current_key_refused(self):
        start = T0 - dt.timedelta(days=91)
        doc = keys_doc(self.cur_pub, now=T0, start=start, days=90)
        # generated_at is T0, which is after valid_before
        path = self.signed(doc)
        with self.assertRaisesRegex(K.KeysError, "no current signing key that is valid now"):
            K.verify_keys_file(path, self.pins, now=T0)

    def test_revoked_key_not_usable(self):
        fp = K.fingerprint_of(blob(self.cur_pub))
        new_priv, new_pub = keygen(self.tmp, "current3")
        doc = keys_doc(new_pub)
        doc["revoked_keys"] = [{"fingerprint": fp, "principal": "kings-taster-current",
                                "revoked_at": fmt_time(T0), "reason": "compromised"}]
        self.assertFalse(K.signing_key_usable(doc, now=T0, fingerprint=fp))
        path = self.signed(doc)
        got, _, _ = K.verify_keys_file(path, self.pins, now=T0)
        self.assertFalse(K.signing_key_usable(got, now=T0, fingerprint=fp))

    def test_signing_key_also_revoked_refused(self):
        fp = K.fingerprint_of(blob(self.cur_pub))
        doc = keys_doc(self.cur_pub)
        doc["revoked_keys"] = [{"fingerprint": fp, "principal": "kings-taster-current",
                                "revoked_at": fmt_time(T0), "reason": "rotated"}]
        self.assertTrue(any("also listed as revoked" in e for e in K.validate_keys(doc, raw=canonical_json(doc), now=T0)))

    def test_window_over_90_days_refused(self):
        doc = keys_doc(self.cur_pub, days=91)
        self.assertTrue(any("over 90 days" in e for e in K.validate_keys(doc, raw=canonical_json(doc), now=T0)))

    def test_exact_90_day_window_ok(self):
        doc = keys_doc(self.cur_pub, days=90)
        self.assertEqual(K.validate_keys(doc, raw=canonical_json(doc), now=T0), [])

    def test_fingerprint_mismatch_refused(self):
        doc = keys_doc(self.cur_pub)
        doc["signing_keys"][0]["fingerprint"] = K.fingerprint_of(blob(self.nxt_pub))
        self.assertTrue(any("does not match" in e for e in K.validate_keys(doc, raw=canonical_json(doc), now=T0)))

    def test_extra_field_refused(self):
        doc = keys_doc(self.cur_pub)
        doc["note"] = "no"
        self.assertTrue(K.validate_keys(doc, now=T0))

    def test_non_canonical_refused(self):
        path = write_keys(self.tmp, keys_doc(self.cur_pub))
        pretty = os.path.join(self.tmp, "keys.json")
        with open(pretty, "wb") as f:
            f.write(b'{\n  "file_type": "keys"\n}\n')  # will fail schema too; use pretty of a valid doc
        doc = keys_doc(self.cur_pub)
        pretty_bytes = (__import__("json").dumps(doc, indent=2) + "\n").encode()
        with open(pretty, "wb") as f:
            f.write(pretty_bytes)
        sign_file(pretty, self.root_priv)
        with self.assertRaisesRegex(K.KeysError, "canonical"):
            K.verify_keys_file(pretty, self.pins, now=T0)

    def test_rollback_refused(self):
        path = self.signed(keys_doc(self.cur_pub, now=T0))
        with open(path, "rb") as f:
            raw = f.read()
        later = T0 + dt.timedelta(days=1)
        with self.assertRaisesRegex(K.KeysError, "rollback"):
            K.verify_keys_file(path, self.pins, now=T0, previous_generated_at=fmt_time(later))
        # same time, different bytes
        other = keys_doc(self.nxt_pub, now=T0)
        other_path = write_keys(self.tmp, other)
        sign_file(other_path, self.root_priv)
        with self.assertRaisesRegex(K.KeysError, "rollback"):
            K.verify_keys_file(other_path, self.pins, now=T0,
                               previous_generated_at=fmt_time(T0), previous_sha256=sha256_bytes(raw))

    def test_future_generated_at_refused(self):
        doc = keys_doc(self.cur_pub, now=T0 + dt.timedelta(minutes=10))
        self.assertTrue(any("in the future" in e for e in K.validate_keys(doc, raw=canonical_json(doc), now=T0)))

    def test_missing_keys_file_refused(self):
        with self.assertRaisesRegex(K.KeysError, "missing"):
            K.verify_keys_file(os.path.join(self.tmp, "nope.json"), self.pins, now=T0)

    def test_empty_pins_refuse_even_a_good_signature(self):
        empty = os.path.join(self.tmp, "empty_pins")
        with open(empty, "w") as f:
            f.write("# no keys yet\n")
        path = self.signed()
        with self.assertRaisesRegex(K.KeysError, "not published yet"):
            K.verify_keys_file(path, empty, now=T0)

    def test_no_private_key_material_in_module_or_pins(self):
        for path in (os.path.join(REPO, "kt", "keys.py"), os.path.join(REPO, "config", "root_pins"),
                     os.path.join(REPO, "schema", "keys.schema.json")):
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn("PRIVATE KEY", text)
            self.assertNotIn("BEGIN OPENSSH", text)
