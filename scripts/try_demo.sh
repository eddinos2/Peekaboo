#!/usr/bin/env bash
# Quick end-to-end demo — no IPSW or Ghidra required.
# Needs: OPENROUTER__API_KEY in .env (see .env.example)
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

# Load .env if present
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export RE__BACKEND=simple

echo "=== Peekaboo demo (artifacts + simple RE backend) ==="
peekaboo health-check || true

peekaboo artifacts CVE-DEMO-0001 \
  --platform ios \
  --pre demo/artifacts/pre \
  --post demo/artifacts/post

echo ""
echo "Reports:"
ls -la ~/.local/share/peekaboo/reports/ 2>/dev/null | tail -5 || true
peekaboo cached --cve CVE-DEMO-0001
