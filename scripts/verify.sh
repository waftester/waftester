#!/usr/bin/env bash
# Full quality gate for WAFtester: build, test (-race), lint.
# Single command that replaces the 3-step verification pattern.
#
# Usage:
#   bash scripts/verify.sh              # all packages
#   bash scripts/verify.sh ./pkg/core/  # specific package(s)
#
# Requires CGO (gcc) for -race. Install mingw-w64 on Windows:
#   winget install BrechtSanders.WinLibs.POSIX.UCRT

set -euo pipefail

PACKAGES="${@:-./...}"

if ! command -v gcc &> /dev/null; then
    echo "WARNING: gcc not found. -race requires CGO."
    echo "Install: winget install BrechtSanders.WinLibs.POSIX.UCRT"
    echo "Falling back to tests without -race."
    echo ""
    RACE_FLAG=""
else
    RACE_FLAG="-race"
fi

echo "=== go build ==="
go build $PACKAGES
echo "  ✓ build passed"

echo ""
echo "=== go test ==="
CGO_ENABLED=${RACE_FLAG:+1} go test -v ${RACE_FLAG} -count=1 -timeout 10m $PACKAGES
echo "  ✓ tests passed"

echo ""
echo "=== golangci-lint ==="
golangci-lint run
echo "  ✓ lint passed"

echo ""
echo "=== All gates passed ==="