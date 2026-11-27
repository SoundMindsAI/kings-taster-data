"""Verify a King's Taster release with `ssh-keygen -Y verify` (OpenSSH signatures, Ed25519).

python3 -m kt.verify <dir> --allowed-signers config/allowed_signers
       [--state FILE [--update-state]] [--template-version X.Y.Z] [--now ISO] [--max-age-hours 48]
       [--require-shards]

<dir> holds latest.json, iocs.json, conformance.json, stats.json, manifest.json and a .sig for each.
Any shard-*.json files in <dir> are checked against the signed manifest (SHA-256, size, gzip cap, counts).
Shard files the manifest does not list are refused. With --require-shards every shard the manifest lists must
be present.
Prints one verdict line. Exit codes:
  0 VERIFIED   1 UNVERIFIED (bad/missing signature, wrong key, hash mismatch, bad file, rollback)
  3 PAUSED     4 UPDATE_REQUIRED   5 STALE
Never prints file contents or key material beyond the signer name.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .common import loads_strict, parse_time, sha256_bytes, sha256_file, utc_now, write_json, read_json
from . import shards as SH
from .validate import MAX_MANIFEST_BYTES, RELEASE_FILES, check_not_future, validate_latest, validate_manifest

NAMESPACE = "kings-taster"
PRINCIPALS = ("kings-taster-current", "kings-taster-next")
SIG_MAX_BYTES = 65536
_VALID_TIME = r'"\d{8}(?:\d{4,6})?Z?"'
# OpenSSH accepts these options in any order; each may appear once. Unknown options are refused.
_OPTION = re.compile(r'namespaces="kings-taster"|valid-after=' + _VALID_TIME + r'|valid-before=' + _VALID_TIME)
SIGNER_LINE = re.compile(
    r'^(kings-taster-current|kings-taster-next) '
    r'((?:namespaces="kings-taster"|valid-(?:after|before)=' + _VALID_TIME + r')'
    r'(?:,(?:namespaces="kings-taster"|valid-(?:after|before)=' + _VALID_TIME + r'))*) '
    r'ssh-ed25519 [A-Za-z0-9+/]{68}(?:==|=)?(?: [A-Za-z0-9@._-]{0,64})?\Z')


def _options_ok(options):
    names = [o.split("=", 1)[0] for o in options.split(",")]
    return (names.count("namespaces") == 1 and names.count("valid-after") <= 1
            and names.count("valid-before") <= 1 and all(_OPTION.fullmatch(o) for o in options.split(",")))


FILES = ("latest.json",) + RELEASE_FILES


class VerifyError(Exception):
    pass


def check_allowed_signers(path):
    keys = 0
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = SIGNER_LINE.match(line)
            if not m or not _options_ok(m.group(2)):
                raise VerifyError("allowed_signers line %d is not an Ed25519 kings-taster key line" % n)
            keys += 1
    if keys == 0:
        raise VerifyError("allowed_signers has no keys")
    if keys > 2:
        raise VerifyError("allowed_signers may hold only the current and next key")
    return keys


def _ssh_keygen():
    exe = shutil.which("ssh-keygen")
    if not exe:
        raise VerifyError("ssh-keygen not installed")
    return exe


def verify_file(path, allowed, namespace=NAMESPACE, principals=PRINCIPALS, data=None):
    sig = path + ".sig"
    if not os.path.exists(sig):
        raise VerifyError("%s: signature missing" % os.path.basename(path))
    with open(sig, "rb") as f:
        sig_bytes = f.read(SIG_MAX_BYTES + 1)
    if len(sig_bytes) > SIG_MAX_BYTES:
        raise VerifyError("%s: signature file is too large" % os.path.basename(path))
    if sig_bytes.count(b"-----BEGIN SSH SIGNATURE-----") != 1 or sig_bytes.count(b"-----END SSH SIGNATURE-----") != 1:
        raise VerifyError("%s: signature file must hold exactly one signature" % os.path.basename(path))
    exe = _ssh_keygen()
    fp = subprocess.run([exe, "-Y", "find-principals", "-s", sig, "-f", allowed, "-n", namespace],
                        capture_output=True, text=True, timeout=30)
    found = [p for p in fp.stdout.split() if p in principals]
    if fp.returncode != 0 or len(found) != 1:
        raise VerifyError("%s: not signed by an allowed key" % os.path.basename(path))
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    v = subprocess.run([exe, "-Y", "verify", "-f", allowed, "-I", found[0], "-n", namespace, "-s", sig],
                       input=data, capture_output=True, timeout=60)
    out = ((v.stdout or b"") + (v.stderr or b"")).decode("utf-8", "replace")
    if v.returncode != 0 or "Good \"%s\" signature for %s with ED25519 key" % (namespace, found[0]) not in out:
        raise VerifyError("%s: signature did not verify" % os.path.basename(path))
    return found[0]


def _keys_state(state):
    """Last accepted keys.json time and hash, if the state file has them."""
    if not state or not os.path.exists(state):
        return None, None
    st = read_json(state)
    if not isinstance(st, dict):
        raise VerifyError("state file is not valid")
    prev_at, prev_sha = st.get("keys_generated_at"), st.get("keys_sha256")
    if prev_at is not None and not isinstance(prev_at, str):
        raise VerifyError("state file is not valid")
    if prev_sha is not None and not isinstance(prev_sha, str):
        raise VerifyError("state file is not valid")
    return prev_at, prev_sha


def verify_release(d, allowed, state=None, update_state=False, template_version=None, now=None,
                   max_age_hours=48, require_shards=False):
    check_allowed_signers(allowed)
    now = now or utc_now()
    keys_doc = keys_raw = None
    daily_allowed = allowed
    tmp_allowed = None
    try:
        from . import keys as K
        try:
            pins = K.load_root_pins(K.DEFAULT_PINS)
        except (K.KeysError, OSError, ValueError) as e:
            raise VerifyError("root_pins: %s" % e)
        keys_path = os.path.join(d, "keys.json")
        keys_present = os.path.exists(keys_path) or os.path.exists(keys_path + ".sig")
        if pins and not keys_present:
            raise VerifyError("keys.json is missing")
        if keys_present:
            prev_at, prev_sha = _keys_state(state)
            try:
                keys_doc, keys_raw, _ = K.verify_keys_file(
                    keys_path, K.DEFAULT_PINS, now=now,
                    previous_generated_at=prev_at, previous_sha256=prev_sha)
            except (K.KeysError, VerifyError, OSError, ValueError) as e:
                raise VerifyError("keys.json: %s" % e)
            text = K.allowed_signers_text(keys_doc, now=now)
            if not text.strip():
                raise VerifyError("keys.json has no usable signing key")
            tmp_allowed = tempfile.mkdtemp(prefix="kt-allowed-")
            daily_allowed = os.path.join(tmp_allowed, "allowed_signers")
            with open(daily_allowed, "w", encoding="utf-8") as f:
                f.write(text)
            check_allowed_signers(daily_allowed)
        signers = {name: verify_file(os.path.join(d, name), daily_allowed) for name in FILES}
        if keys_doc is not None:
            from . import keys as K
            for name, principal in signers.items():
                fp = next((k["fingerprint"] for k in keys_doc["signing_keys"] if k["principal"] == principal), None)
                if not fp or not K.signing_key_usable(keys_doc, now=now, fingerprint=fp, principal=principal):
                    raise VerifyError("%s: signed by a key that keys.json does not allow" % name)
    finally:
        if tmp_allowed:
            shutil.rmtree(tmp_allowed, ignore_errors=True)

    with open(os.path.join(d, "latest.json"), "rb") as f:
        raw = f.read()
    try:
        latest = loads_strict(raw)
    except ValueError:
        raise VerifyError("latest.json is not JSON or has duplicate keys")
    if not isinstance(latest, dict) or latest.get("file_type") != "latest":
        raise VerifyError("latest.json has the wrong file_type")
    errs = validate_latest(latest, d, raw=raw)
    if errs:
        raise VerifyError("latest.json check failed: " + errs[0])
    for name, ft in (("iocs.json", "iocs"), ("conformance.json", "conformance"), ("stats.json", "stats")):
        doc = read_json(os.path.join(d, name))
        if not isinstance(doc, dict) or doc.get("file_type") != ft:
            raise VerifyError("%s has the wrong file_type" % name)
    if os.path.getsize(os.path.join(d, "manifest.json")) > MAX_MANIFEST_BYTES:
        raise VerifyError("manifest.json is over the 5 MB cap")
    manifest = read_json(os.path.join(d, "manifest.json"))
    if not isinstance(manifest, dict) or manifest.get("file_type") != "manifest" or validate_manifest(manifest):
        raise VerifyError("manifest.json has the wrong file_type or fails its schema")
    errs = SH.validate_shards(d, manifest, require_all=require_shards)
    if errs:
        raise VerifyError("shard check failed: " + errs[0])
    errs = check_not_future(latest["generated_at"], now)
    if errs:
        raise VerifyError(errs[0])
    gen = parse_time(latest["generated_at"])
    sha = sha256_file(os.path.join(d, "latest.json"))
    if state and os.path.exists(state):
        st = read_json(state)
        if not isinstance(st, dict) or not isinstance(st.get("generated_at"), str):
            raise VerifyError("state file is not valid")
        last = parse_time(st["generated_at"])
        if gen < last:
            raise VerifyError("rollback: generated_at is older than the last accepted file")
        if gen == last and st.get("latest_sha256") != sha:
            raise VerifyError("rollback: same generated_at but a different file")
    if template_version:
        tv = tuple(int(x) for x in template_version.split("."))
        if tv < tuple(int(x) for x in latest["min_template_version"].split(".")):
            return 4, "UPDATE_REQUIRED: template %s is below min_template_version %s" % (
                template_version, latest["min_template_version"])
    if (now - gen).total_seconds() > max_age_hours * 3600:
        return 5, "STALE: generated_at %s is older than %d hours" % (latest["generated_at"], max_age_hours)
    if state and update_state:
        st = {"generated_at": latest["generated_at"], "latest_sha256": sha, "tag": latest["tag"]}
        if keys_doc is not None:
            st["keys_generated_at"] = keys_doc["generated_at"]
            st["keys_sha256"] = sha256_bytes(keys_raw)
        elif os.path.exists(state):
            prev = read_json(state)
            if isinstance(prev, dict) and isinstance(prev.get("keys_generated_at"), str):
                st["keys_generated_at"] = prev["keys_generated_at"]
                if isinstance(prev.get("keys_sha256"), str):
                    st["keys_sha256"] = prev["keys_sha256"]
        write_json(state, st)
    if latest["paused"]:
        return 3, "PAUSED: King's Taster is paused (%s), tag %s" % (latest["paused_reason"], latest["tag"])
    return 0, "VERIFIED: tag %s generated_at %s signed by %s" % (
        latest["tag"], latest["generated_at"], ",".join(sorted(set(signers.values()))))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dir")
    ap.add_argument("--allowed-signers", required=True)
    ap.add_argument("--state")
    ap.add_argument("--update-state", action="store_true")
    ap.add_argument("--template-version")
    ap.add_argument("--now")
    ap.add_argument("--max-age-hours", type=int, default=48)
    ap.add_argument("--require-shards", action="store_true")
    a = ap.parse_args(argv)
    try:
        code, line = verify_release(a.dir, a.allowed_signers, a.state, a.update_state, a.template_version,
                                    parse_time(a.now) if a.now else None, a.max_age_hours, a.require_shards)
    except (VerifyError, OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        print("UNVERIFIED: %s" % str(e)[:300])
        return 1
    except Exception as e:  # fail closed with the same one-line format for any odd signed input
        print("UNVERIFIED: unexpected %s while checking the release" % type(e).__name__)
        return 1
    print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
