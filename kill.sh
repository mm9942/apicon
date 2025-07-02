#!/usr/bin/env bash
#
# soft-then-hard.sh ── gently ask a process to leave, then insist if it lingers
# usage:  soft-then-hard.sh <process-name-or-pattern>
# example: ./soft-then-hard.sh apicon
#

set -euo pipefail

# ── 1. anchor intent ───────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <process_name_or_pattern>" >&2
  exit 1
fi
pattern="$1"

# ── 2. find all matching PIDs (pgrep -f respects full command line) ───────────
readarray -t pids < <(pgrep -f "$pattern" || true)

if [[ ${#pids[@]} -eq 0 ]]; then
  echo "✧ No process found matching pattern: '$pattern'" >&2
  exit 2
fi

echo "✧ Targeting PIDs: ${pids[*]}"

# ── 3. softly request shutdown (SIGQUIT) ──────────────────────────────────────
for pid in "${pids[@]}"; do
  echo "→ sending SIGQUIT to $pid"
  sudo kill -QUIT "$pid"
done

sleep 5  # allow time for graceful tear-down

# ── 4. verify and, if needed, escalate to SIGKILL ─────────────────────────────
for pid in "${pids[@]}"; do
  if kill -0 "$pid" 2>/dev/null; then
    echo "→ $pid ignored SIGQUIT; sending SIGKILL"
    sudo kill -9 "$pid"
  else
    echo "✓ $pid exited gracefully"
  fi
done

echo "◎ Done."
