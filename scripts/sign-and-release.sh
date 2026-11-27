#!/usr/bin/env bash
# sign-and-release.sh: owner-side signing and release for King's Taster.
# The private key never leaves the owner's machine; CI only builds unsigned files.
#
# Usage:
#   scripts/sign-and-release.sh --run-id <id>   [--key PATH] [--accept-breaker] [--bootstrap] [--dry-run]
#   scripts/sign-and-release.sh --from-dir DIR  [--key PATH] [--accept-breaker] [--bootstrap] [--dry-run]
#
# Key: --key PATH or env KT_SIGNING_KEY_PATH. The path and the key are never printed.
# Steps: get the unsigned artifact -> validate -> check against the live release (signature +
# monotonic generated_at + revocations) -> circuit breaker -> sign with ssh-keygen -Y sign ->
# verify our own signatures -> create the dated release -> update the kt-latest pointer.
# --dry-run stops after verification and creates nothing on GitHub.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${KT_REPO:-SoundMindsAI/kings-taster-data}"
NS="kings-taster"
ARTIFACT="kt-release-unsigned"
POINTER_TAG="kt-latest"
GH="${KT_GH:-gh}"
FILES=(latest.json iocs.json conformance.json stats.json)

RUN_ID="" FROM_DIR="" KEY="${KT_SIGNING_KEY_PATH:-}" ACCEPT_BREAKER=0 BOOTSTRAP=0 DRY_RUN=0
die() { echo "sign-and-release: REFUSED: $*" >&2; exit 1; }

# Prints "present" or "absent". Only gh's explicit "release not found" counts as absent; any other failure
# (network, auth, 5xx) returns 1 so the caller refuses instead of treating the live release as missing.
release_state() {
  local err rc=0
  err="$("$GH" release view "$1" --repo "$REPO" 2>&1 >/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then echo present; return 0; fi
  if printf '%s\n' "$err" | grep -qx 'release not found'; then echo absent; return 0; fi
  return 1
}
while [ $# -gt 0 ]; do
  case "$1" in
    --run-id) RUN_ID="${2:?}"; shift 2 ;;
    --from-dir) FROM_DIR="${2:?}"; shift 2 ;;
    --key) KEY="${2:?}"; shift 2 ;;
    --accept-breaker) ACCEPT_BREAKER=1; shift ;;
    --bootstrap) BOOTSTRAP=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) die "unknown argument" ;;
  esac
done
[ -n "$RUN_ID" ] || [ -n "$FROM_DIR" ] || die "need --run-id or --from-dir"
[ -z "$RUN_ID" ] || [ -z "$FROM_DIR" ] || die "use only one of --run-id / --from-dir"
[ -z "$RUN_ID" ] || [[ "$RUN_ID" =~ ^[0-9]{1,20}$ ]] || die "bad run id"
[ -n "$KEY" ] || die "no signing key path (use --key or KT_SIGNING_KEY_PATH)"
[ -f "$KEY" ] || die "signing key file not found"
command -v ssh-keygen >/dev/null || die "ssh-keygen not installed"

# Key checks (nothing about the key is printed).
# GNU stat uses -c; macOS/BSD stat uses -f.
perm="$(stat -c '%a' "$KEY" 2>/dev/null || stat -f '%Lp' "$KEY")" || die "can't read the signing key's permissions"
[[ "$perm" =~ ^[0-7]00$ ]] || die "signing key must not be readable by group/others (chmod 600)"
ssh-keygen -l -f "$KEY" 2>/dev/null | grep -q '(ED25519)$' || die "signing key is not Ed25519"
PUB="$(ssh-keygen -y -f "$KEY" 2>/dev/null | cut -d' ' -f1,2)" || die "can't read the public half of the key"
ALLOWED="$ROOT/config/allowed_signers"
grep -v '^#' "$ALLOWED" | grep -qF -- "$PUB" || die "this key is not in config/allowed_signers"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ART="$WORK/art"; PREV="$WORK/prev"; mkdir -p "$ART" "$PREV"
PY=(python3 -E -s)
# Tests only: KT_NOW pins the clock used for the "not dated in the future" checks.
NOW_ARGS=()
if [ -n "${KT_NOW:-}" ]; then NOW_ARGS=(--now "$KT_NOW"); fi
cd "$ROOT"

# 1. Get the unsigned artifact.
if [ -n "$RUN_ID" ]; then
  meta="$("$GH" run view "$RUN_ID" --repo "$REPO" --json headBranch,conclusion,event,workflowName)"
  echo "$meta" | "${PY[@]}" -c 'import json,sys
m=json.load(sys.stdin)
ok = m.get("headBranch")=="main" and m.get("conclusion")=="success" and m.get("workflowName")=="pipeline" and m.get("event") in ("schedule","workflow_dispatch")
sys.exit(0 if ok else 1)' || die "run is not a successful 'pipeline' run on main"
  "$GH" run download "$RUN_ID" --repo "$REPO" --name "$ARTIFACT" --dir "$ART"
else
  for f in "${FILES[@]}" build-report.json; do
    [ -f "$FROM_DIR/$f" ] || die "missing $f in --from-dir"
    cp "$FROM_DIR/$f" "$ART/$f"
  done
fi
for f in "${FILES[@]}" build-report.json; do [ -f "$ART/$f" ] || die "artifact is missing $f"; done
for f in "$ART"/*; do
  case "$(basename "$f")" in latest.json|iocs.json|conformance.json|stats.json|build-report.json) ;; *) die "unexpected file in artifact" ;; esac
done

# 2. Validate the unsigned files.
"${PY[@]}" -m kt.validate "$ART" "${NOW_ARGS[@]}" >/dev/null || { "${PY[@]}" -m kt.validate "$ART" "${NOW_ARGS[@]}" | head -20 >&2 || true; die "artifact failed validation"; }
TAG="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1]))["tag"])' "$ART/latest.json")"
[[ "$TAG" =~ ^kt-[0-9]{8}T[0-9]{6}Z$ ]] || die "bad tag"

# 3. Compare with the live release: verify its signature, then require monotonic generated_at.
HAVE_PREV=0
if [ "$DRY_RUN" -eq 0 ] || [ -n "$RUN_ID" ]; then
  PSTATE="$(release_state "$POINTER_TAG")" || die "could not check the live release (gh failed); not treating it as absent"
  if [ "$PSTATE" = present ]; then
    "$GH" release download "$POINTER_TAG" --repo "$REPO" --pattern 'latest.json' --pattern 'latest.json.sig' --dir "$PREV"
    PTAG="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1]))["tag"])' "$PREV/latest.json")"
    [[ "$PTAG" =~ ^kt-[0-9]{8}T[0-9]{6}Z$ ]] || die "live pointer has a bad tag"
    for f in iocs.json conformance.json stats.json; do
      "$GH" release download "$PTAG" --repo "$REPO" --pattern "$f" --pattern "$f.sig" --dir "$PREV"
    done
    "${PY[@]}" -m kt.verify "$PREV" --allowed-signers "$ALLOWED" --max-age-hours 87600 "${NOW_ARGS[@]}" >/dev/null \
      || [ $? -eq 3 ] || die "the live release does not verify; fix that first"
    HAVE_PREV=1
  fi
fi
if [ "$HAVE_PREV" -eq 1 ]; then
  "${PY[@]}" -m kt.validate "$ART" --previous "$PREV" "${NOW_ARGS[@]}" >/dev/null || die "not newer than the live release, or a revocation was dropped (rollback refused)"
  "${PY[@]}" -c 'import json,sys
r=json.load(open(sys.argv[1])); p=json.load(open(sys.argv[2]))
sys.exit(0 if r.get("previous_generated_at")==p["generated_at"] else 1)' "$ART/build-report.json" "$PREV/iocs.json" \
    || die "the build was not made from the current live release"
elif [ "$BOOTSTRAP" -ne 1 ]; then
  [ "$DRY_RUN" -eq 1 ] && [ -n "$FROM_DIR" ] || die "no live release found; pass --bootstrap only for the very first release"
fi

# 4. Circuit breaker (big changes, new popular-name hits, carried-over sources, first release).
if "${PY[@]}" -c 'import json,sys;sys.exit(0 if json.load(open(sys.argv[1]))["needs_human"] else 1)' "$ART/build-report.json"; then
  reasons="$("${PY[@]}" -c 'import json,sys;r=json.load(open(sys.argv[1]));print(",".join(r["breaker"]), "hold_queue=%d" % len(r["hold_queue"]))' "$ART/build-report.json")"
  [ "$ACCEPT_BREAKER" -eq 1 ] || die "circuit breaker tripped ($reasons); a person must review, then rerun with --accept-breaker"
  echo "sign-and-release: breaker tripped ($reasons), accepted by operator"
fi

# 5. Sign, then verify our own signatures.
for f in "${FILES[@]}"; do
  [ ! -e "$ART/$f.sig" ] || die "unexpected existing signature"
  ssh-keygen -Y sign -q -f "$KEY" -n "$NS" "$ART/$f" </dev/null || die "signing failed"
done
"${PY[@]}" -m kt.verify "$ART" --allowed-signers "$ALLOWED" --max-age-hours 87600 "${NOW_ARGS[@]}" >/dev/null || [ $? -eq 3 ] \
  || die "our own signatures did not verify"

if [ "$DRY_RUN" -eq 1 ]; then
  OUT="${KT_DRY_RUN_OUT:-}"
  if [ -n "$OUT" ]; then mkdir -p "$OUT"; cp "$ART"/*.json "$ART"/*.sig "$OUT"/; fi
  echo "sign-and-release: DRY RUN OK, $TAG signed and verified, nothing published"
  exit 0
fi

# 6. Publish: dated release first, then move the pointer.
NOTES="$WORK/notes.md"
cat > "$NOTES" <<NOTES_EOF
King's Taster list file $TAG. Verify with ssh-keygen -Y verify (namespace "$NS"); see config/allowed_signers.

Data notice: CISA KEV (CC0 1.0; no endorsement by CISA or DHS is implied, and no CISA logo or DHS seal is used).
OpenSSF Malicious Packages via OSV.dev (Apache-2.0; entries with GitHub malware advisory origins also CC-BY 4.0).
"No known reports" means nothing was found, not that something is safe.
NOTES_EOF
cp "$ROOT/sources/LICENSES.md" "$ART/LICENSES.md"
TPL_DIR="$ROOT/third-party-licenses"
OSSF_LICENSE="OpenSSF-Malicious-Packages-Apache-2.0.txt"
cp "$TPL_DIR/$OSSF_LICENSE" "$ART/Apache-2.0.txt"
assets=()
for f in "${FILES[@]}"; do assets+=("$ART/$f" "$ART/$f.sig"); done
"$GH" release create "$TAG" "${assets[@]}" "$ART/LICENSES.md" "$ART/Apache-2.0.txt" \
  --repo "$REPO" --target main --title "$TAG" --notes-file "$NOTES" --latest=false
PSTATE="$(release_state "$POINTER_TAG")" || die "could not check the pointer release (gh failed) after creating $TAG; move $POINTER_TAG by hand"
if [ "$PSTATE" = present ]; then
  "$GH" release upload "$POINTER_TAG" "$ART/latest.json" "$ART/latest.json.sig" --repo "$REPO" --clobber
else
  "$GH" release create "$POINTER_TAG" "$ART/latest.json" "$ART/latest.json.sig" --repo "$REPO" --target main \
    --title "kt-latest pointer" --notes "Signed pointer to the current King's Taster release. Do not edit by hand." --latest=false
fi
echo "sign-and-release: PUBLISHED $TAG and moved $POINTER_TAG"
