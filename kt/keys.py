"""Root-signed keys.json (SPEC.md §7.3A): format, validation and verification.

The first signed keys.json has not been published yet. config/root_pins holds no
master public keys yet. This module refuses a missing, unsigned or unverifiable
keys.json. Tests generate throwaway keys in a temporary directory; those keys are
never committed. This module never generates a master key.
"""
import base64
import hashlib
import json
import os
import re

from .common import canonical_json, loads_strict, parse_time, utc_now
from . import jsonschema_lite
from .validate import FUTURE_SKEW_SECONDS
from .verify import PRINCIPALS as DAILY_PRINCIPALS, VerifyError, verify_file

NAMESPACE = "kings-taster-keys"
ROOT_PRINCIPALS = ("kings-taster-root", "kings-taster-root-backup")
ROLE_PRINCIPAL = {"current": "kings-taster-current", "next": "kings-taster-next"}
REASONS = ("rotated", "compromised", "retired")
MAX_BYTES = 65536
MAX_SIGNING_KEYS = 2
MAX_REVOKED = 64
MAX_VALIDITY_SECONDS = 90 * 24 * 3600
FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
PUB_RE = re.compile(r"^[A-Za-z0-9+/]{68}(?:==|=)?\Z")
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z", re.ASCII)
_VALID_TIME = r'"\d{8}(?:\d{4,6})?Z?"'
_OPTION = re.compile(r'namespaces="kings-taster-keys"|valid-after=' + _VALID_TIME + r'|valid-before=' + _VALID_TIME)
PIN_LINE = re.compile(
    r'^(kings-taster-root|kings-taster-root-backup) '
    r'((?:namespaces="kings-taster-keys"|valid-(?:after|before)=' + _VALID_TIME + r')'
    r'(?:,(?:namespaces="kings-taster-keys"|valid-(?:after|before)=' + _VALID_TIME + r'))*) '
    r'ssh-ed25519 [A-Za-z0-9+/]{68}(?:==|=)?(?: [A-Za-z0-9@._-]{0,64})?\Z')
ROOT = os.path.join(os.path.dirname(__file__), "..")
SCHEMA = os.path.join(ROOT, "schema", "keys.schema.json")
DEFAULT_PINS = os.path.join(ROOT, "config", "root_pins")


class KeysError(Exception):
    pass


def _schema_doc():
    with open(SCHEMA, encoding="utf-8") as f:
        return json.load(f)


def fingerprint_of(public_key):
    """OpenSSH SHA256 fingerprint of an ssh-ed25519 public-key blob (base64)."""
    if not isinstance(public_key, str) or not PUB_RE.match(public_key):
        raise KeysError("public key is not an ssh-ed25519 blob")
    pad = "=" * ((4 - len(public_key) % 4) % 4)
    raw = base64.b64decode(public_key + pad)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def _options_ok(options):
    names = [o.split("=", 1)[0] for o in options.split(",")]
    return (names.count("namespaces") == 1 and names.count("valid-after") <= 1
            and names.count("valid-before") <= 1 and all(_OPTION.fullmatch(o) for o in options.split(",")))


def load_root_pins(path):
    """Return the pin lines as (principal, public key, fingerprint) tuples. Empty if only comments, which is the unpublished state."""
    keys = []
    seen = set()
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = PIN_LINE.match(line)
            if not m or not _options_ok(m.group(2)):
                raise KeysError("root_pins line %d is not an Ed25519 kings-taster-keys pin line" % n)
            principal = m.group(1)
            if principal in seen:
                raise KeysError("root_pins repeats principal %s" % principal)
            seen.add(principal)
            pub = line.split()[3]
            keys.append((principal, pub, fingerprint_of(pub)))
    if len(keys) > 2:
        raise KeysError("root_pins may hold only the two master public keys")
    return keys


def validate_keys(doc, raw=None, now=None):
    """Schema and cross-field rules. Returns a list of problem strings."""
    if not isinstance(doc, dict):
        return ["keys.json: not a JSON object"]
    errors = jsonschema_lite.validate(doc, _schema_doc())
    if errors:
        return ["keys.json: " + e for e in errors]
    if raw is not None and raw != canonical_json(doc):
        return ["keys.json: not in canonical form"]
    now = now or utc_now()
    try:
        issued = parse_time(doc["generated_at"])
    except ValueError:
        return ["keys.json: generated_at is not an ISO UTC time"]
    if (issued - now).total_seconds() > FUTURE_SKEW_SECONDS:
        errors.append("keys.json: generated_at is in the future")
    roles, fps, principals = [], set(), set()
    for k in doc["signing_keys"]:
        role, princ = k["role"], k["principal"]
        if ROLE_PRINCIPAL.get(role) != princ:
            errors.append("keys.json: signing key role %s must use principal %s" % (role, ROLE_PRINCIPAL.get(role)))
        if role in roles or princ in principals:
            errors.append("keys.json: duplicate signing key role or principal")
        roles.append(role); principals.add(princ)
        if k["algorithm"] != "ssh-ed25519":
            errors.append("keys.json: signing keys must be ssh-ed25519")
        try:
            fp = fingerprint_of(k["public_key"])
        except KeysError:
            errors.append("keys.json: signing key %s has a bad public key" % princ); continue
        if k["fingerprint"] != fp:
            errors.append("keys.json: signing key %s fingerprint does not match the public key" % princ)
        if fp in fps:
            errors.append("keys.json: signing key fingerprint repeated")
        fps.add(fp)
        try:
            start, end = parse_time(k["valid_after"]), parse_time(k["valid_before"])
        except ValueError:
            errors.append("keys.json: signing key %s has a bad validity window" % princ); continue
        if end <= start:
            errors.append("keys.json: signing key %s valid_before must be after valid_after" % princ)
        elif (end - start).total_seconds() > MAX_VALIDITY_SECONDS:
            errors.append("keys.json: signing key %s validity window is over 90 days" % princ)
    if "current" not in roles:
        errors.append("keys.json: a current signing key is required")
    revoked_fps = set()
    for r in doc["revoked_keys"]:
        fp = r.get("fingerprint")
        if not isinstance(fp, str) or not FINGERPRINT_RE.match(fp) or fp in revoked_fps:
            errors.append("keys.json: revoked_keys has a bad or repeated fingerprint"); continue
        revoked_fps.add(fp)
        if r.get("reason") not in REASONS:
            errors.append("keys.json: revoked reason must be rotated, compromised or retired")
        try:
            parse_time(r["revoked_at"])
        except (ValueError, KeyError):
            errors.append("keys.json: revoked_at is not an ISO UTC time")
        if r.get("principal") not in DAILY_PRINCIPALS:
            errors.append("keys.json: revoked principal is not a daily signing principal")
    overlap = fps & revoked_fps
    if overlap:
        errors.append("keys.json: a signing key is also listed as revoked")
    return errors


def signing_key_usable(doc, now=None, fingerprint=None, principal=None):
    """True if a listed signing key is unexpired, not revoked, and matches fingerprint or principal."""
    now = now or utc_now()
    revoked = {r["fingerprint"] for r in doc.get("revoked_keys") or []}
    for k in doc["signing_keys"]:
        if fingerprint is not None and k["fingerprint"] != fingerprint:
            continue
        if principal is not None and k["principal"] != principal:
            continue
        if k["fingerprint"] in revoked:
            continue
        start, end = parse_time(k["valid_after"]), parse_time(k["valid_before"])
        if start <= now < end:
            return True
    return False


def allowed_signers_text(doc, now=None):
    """OpenSSH allowed_signers body for daily files, from the usable keys in keys.json."""
    now = now or utc_now()
    lines = []
    for k in doc["signing_keys"]:
        if not signing_key_usable(doc, now=now, fingerprint=k["fingerprint"]):
            continue
        lines.append('%s namespaces="kings-taster" ssh-ed25519 %s' % (k["principal"], k["public_key"]))
    return "\n".join(lines) + ("\n" if lines else "")


def verify_keys_file(path, pins_path, now=None, previous_generated_at=None, previous_sha256=None):
    """Verify keys.json against the master public-key pins. Raises KeysError or VerifyError on refusal.

    Returns (doc, raw, signer_principal). A pins file with no keys is the unpublished
    placeholder: every keys.json is refused.
    """
    now = now or utc_now()
    try:
        pins = load_root_pins(pins_path)
    except OSError as e:
        raise KeysError("root_pins could not be read: %s" % e)
    if not pins:
        raise KeysError("master public keys are not published yet; keys.json is refused")
    if not os.path.exists(path):
        raise KeysError("keys.json is missing")
    with open(path, "rb") as f:
        raw = f.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise KeysError("keys.json is over the size cap")
    try:
        doc = loads_strict(raw)
    except ValueError:
        raise KeysError("keys.json is not JSON or has duplicate keys")
    errs = validate_keys(doc, raw=raw, now=now)
    if errs:
        raise KeysError(errs[0])
    signer = verify_file(path, pins_path, namespace=NAMESPACE, principals=ROOT_PRINCIPALS, data=raw)
    if previous_generated_at:
        gen = parse_time(doc["generated_at"])
        last = parse_time(previous_generated_at)
        if gen < last:
            raise KeysError("keys.json rollback: generated_at is older than the last accepted file")
        if gen == last and previous_sha256 and hashlib.sha256(raw).hexdigest() != previous_sha256:
            raise KeysError("keys.json rollback: same generated_at but a different file")
    if not signing_key_usable(doc, now=now, principal="kings-taster-current"):
        raise KeysError("keys.json has no current signing key that is valid now")
    return doc, raw, signer
