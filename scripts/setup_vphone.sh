#!/usr/bin/env bash
# Bootstrap vphone-cli for Peekaboo dynamic iOS validation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> Peekaboo vphone-cli setup"
peekaboo vphone setup "$@" || true

echo ""
echo "==> Status"
peekaboo vphone status || true

echo ""
echo "When SIP/AMFI are configured and IPSW download completes:"
echo "  peekaboo vphone provision --cve CVE-2026-43818 --variant exp"
