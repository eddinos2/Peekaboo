#!/usr/bin/env bash
# Demo script for real-case iOS CVE analysis.
# Prerequisites: OPENROUTER__API_KEY, ipsw CLI, Ghidra 11+
set -euo pipefail

CVE="${1:-CVE-2024-23208}"
DEVICE="${2:-iPhone16,1}"

echo "=== Peekaboo iOS real-case demo ==="
echo "CVE:    $CVE"
echo "Device: $DEVICE"
echo ""

peekaboo health-check
peekaboo ios health-check

echo ""
echo "Starting analysis (this may take 30-90 min for IPSW download)..."
peekaboo ios cve "$CVE" --device "$DEVICE"

echo ""
echo "Cached reports:"
peekaboo cached --cve "$CVE"

echo ""
echo "Reports directory: ~/.local/share/peekaboo/reports/"
