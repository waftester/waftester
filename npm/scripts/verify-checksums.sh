#!/usr/bin/env bash
# verify-checksums.sh — Verify GoReleaser archive checksums
#
# Usage:
#   ./npm/scripts/verify-checksums.sh <archives-dir>
#
# Verifies all archives listed in checksums.txt match their SHA-256 hashes.
# Exits non-zero on ANY mismatch.

set -euo pipefail

ARCHIVES_DIR="${1:?Usage: $0 <archives-dir>}"

if [[ ! -f "${ARCHIVES_DIR}/checksums.txt" ]]; then
  echo "ERROR: checksums.txt not found in ${ARCHIVES_DIR}" >&2
  exit 1
fi

echo "==> Verifying checksums in ${ARCHIVES_DIR}/checksums.txt" >&2

cd "${ARCHIVES_DIR}"

# sha256sum --check verifies each line: <hash>  <filename>
if sha256sum --check checksums.txt; then
  echo "==> All checksums verified ✓" >&2
  exit 0
else
  echo "ERROR: Checksum verification FAILED" >&2
  echo "One or more archives have been tampered with or corrupted." >&2
  echo "Do NOT publish these packages." >&2
  exit 1
fi
