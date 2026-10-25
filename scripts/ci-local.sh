#!/usr/bin/env bash
# Local mirror of .github/workflows/lint.yml — same steps, same order.
# Runs every step (no stop at first failure) and prints a pass/fail summary.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
LOG_DIR="${CI_LOG_DIR:-${TMPDIR:-/tmp}/vol-analyze-ci}"
mkdir -p "$LOG_DIR"
STEPS=("lint:make lint" "check:make check" "test:make test")
FAILED=0

for step in "${STEPS[@]}"; do
    name="${step%%:*}" cmd="${step#*:}"
    log="${LOG_DIR}/${name}.log"
    if bash -c "$cmd" > "$log" 2>&1; then
        printf '  PASS  %-6s %s\n' "$name" "$log"
    else
        printf '  FAIL  %-6s %s\n' "$name" "$log"
        FAILED=$(( FAILED + 1 ))
    fi
done

echo "  NOTE  the macos-latest test leg is not mirrored here — run make ci on a Mac to cover it"
(( FAILED == 0 )) || { echo "${FAILED} CI step(s) failed — see logs above"; exit 1; }
echo "All CI steps passed"
