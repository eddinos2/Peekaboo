#!/usr/bin/env bash
# Monitor CVE-2026-43818 IPSW download + pipeline progress.
PRE_TOTAL=11118099013
POST_TOTAL=11252535908
TOTAL=$((PRE_TOTAL + POST_TOTAL))
PRE_DIR="${HOME}/.local/share/peekaboo/_temp/CVE-2026-43818/ios/pre"
POST_DIR="${HOME}/.local/share/peekaboo/_temp/CVE-2026-43818/ios/post"
LOG="/tmp/peekaboo-cve-run.log"

dir_bytes() {
  du -sk "$1" 2>/dev/null | awk '{print $1 * 1024}'
}

while true; do
  pre=$(dir_bytes "$PRE_DIR")
  post=$(dir_bytes "$POST_DIR")
  done=$((pre + post))
  pct=$((done * 100 / TOTAL))
  remaining=$((TOTAL - done))
  # Re-sample speed every loop from partial file growth (handled externally)
  echo "$(date '+%H:%M:%S') download ${pct}% ($((done / 1024 / 1024))MB / $((TOTAL / 1024 / 1024))MB) pre=$((pre / 1024 / 1024))MB post=$((post / 1024 / 1024))MB"
  if tail -3 "$LOG" 2>/dev/null | grep -q "cve_run_complete"; then
    tail -5 "$LOG"
    break
  fi
  if ! pgrep -f "peekaboo.*CVE-2026-43818" >/dev/null 2>&1; then
    if tail -5 "$LOG" 2>/dev/null | grep -q "gather_failed\|cve_run_complete"; then
      echo "WARN: peekaboo exited — check log"
      tail -8 "$LOG"
      break
    fi
  fi
  sleep 120
done
