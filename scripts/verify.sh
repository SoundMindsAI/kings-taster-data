#!/usr/bin/env bash
# Verify a downloaded King's Taster release directory. See kt/verify.py for exit codes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python3 -E -s -m kt.verify "$@"
