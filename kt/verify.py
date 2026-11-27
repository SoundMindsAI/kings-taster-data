"""Verify a King's Taster release with `ssh-keygen -Y verify` (OpenSSH signatures, Ed25519).

python3 -m kt.verify <dir> --allowed-signers config/allowed_signers
       [--state FILE [--update-state]] [--template-version X.Y.Z] [--now ISO] [--max-age-hours 48]
       [--require-shards]

<dir> holds latest.json, iocs.json, conformance.json, stats.json, manifest.json and a .sig for each.
Any shard-*.json files in <dir> are checked against the signed manifest (SHA-256, size, gzip cap, counts);
with --require-shards every shard the manifest lists must be present.
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

from .common import loads_strict, parse_time, sha256_file, utc_now, write_json, read_json
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


def verify_file(path, allowed):
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
    fp = subprocess.run([exe, "-Y", "find-principals", "-s", sig, "-f", allowed, "-n", NAMESPACE],
                        capture_output=True, text=True, timeout=30)
    principals = [p for p in fp.stdout.split() if p in PRINCIPALS]
    if fp.returncode != 0 or len(principals) != 1:
        raise VerifyError("%s: not signed by an allowed key" % os.path.basename(path))
    with open(path, "rb") as data:
        v = subprocess.run([exe, "-Y", "verify", "-f", allowed, "-I", principals[0], "-n", NAMESPACE, "-s", sig],
                           stdin=data, capture_output=True, text=True, timeout=60)
    out = v.stdout + v.stderr
    if v.returncode != 0 or "Good \"%s\" signature for %s with ED25519 key" % (NAMESPACE, principals[0]) not in out:
        raise VerifyError("%s: signature did not verify" % os.path.basename(path))
    return principals[0]


def verify_release(d, allowed, state=None, update_state=False, template_version=None, now=None,
                   max_age_hours=48, require_shards=False):
    check_allowed_signers(allowed)
    signers = {name: verify_file(os.path.join(d, name), allowed) for name in FILES}
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
    now = now or utc_now()
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
        write_json(state, {"generated_at": latest["generated_at"], "latest_sha256": sha, "tag": latest["tag"]})
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
