#!/usr/bin/env bash
# Run the full test suite with -race detection enabled.
# Requires CGO (gcc) — install mingw-w64 on Windows:
#   winget install BrechtSanders.WinLibs.POSIX.UCRT
#
# Usage:
#   bash scripts/race-test.sh              # all packages
#   bash scripts/race-test.sh ./pkg/core/  # specific package

set -euo pipefail

if ! command -v gcc &> /dev/null; then
    echo "ERROR: gcc not found. -race requires CGO."
    echo ""
    echo "Install mingw-w64:"
    echo "  winget install BrechtSanders.WinLibs.POSIX.UCRT"
    echo ""
    exit 1
fi

PACKAGES="${@:-./...}"

echo "Running tests with -race on: $PACKAGES"
echo "---"

CGO_ENABLED=1 go test -race -count=1 -timeout 10m $PACKAGES

echo "---"
echo "✓ Race tests passed"