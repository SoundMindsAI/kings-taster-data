#!/usr/bin/env bash
# Install the pre-push secret scan into this clone's .git/hooks (local only, not pushed).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK="$ROOT/.git/hooks/pre-push"
cat > "$HOOK" <<'HOOK_EOF'
#!/usr/bin/env bash
# King's Taster pre-push: scan the tree and every commit being pushed. Blocks the push on FAIL.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
z40=0000000000000000000000000000000000000000
while read -r _local_ref local_sha _remote_ref remote_sha; do
  [ "$local_sha" = "$z40" ] && continue
  base="$remote_sha"; [ "$base" = "$z40" ] && base=""
  python3 -E -s "$ROOT/scripts/secret_scan.py" --git-range "$base" "$ROOT"
done
python3 -E -s "$ROOT/scripts/secret_scan.py" "$ROOT"
HOOK_EOF
chmod +x "$HOOK"
echo "installed $HOOK"
