#!/usr/bin/env bash
# test-build-mock.sh — Create mock GoReleaser archives and test build script
#
# Usage:
#   bash npm/scripts/test-build-mock.sh
#
# Creates fake archives mimicking GoReleaser's layout (nested directory),
# runs build-npm-packages.sh, and validates the output structure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MOCK_DIR="${REPO_ROOT}/npm-mock-test"
ARCHIVES_DIR="${MOCK_DIR}/archives"
OUTPUT_DIR="${MOCK_DIR}/staging"
VERSION="99.0.0-test.1"

log() { echo "==> $*" >&2; }
err() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "  PASS: $*" >&2; }

cleanup() {
  log "Cleaning up ${MOCK_DIR}..."
  rm -rf "${MOCK_DIR}"
}
trap cleanup EXIT

# ============================================================================
# Step 1: Create mock archives mimicking GoReleaser layout
# ============================================================================

log "Creating mock GoReleaser archives..."
rm -rf "${MOCK_DIR}"
mkdir -p "${ARCHIVES_DIR}"

# GoReleaser wraps files in a directory: waftester_Os_Arch/waf-tester
PLATFORMS=(
  "waftester_Darwin_x86_64|tar.gz|waf-tester"
  "waftester_Darwin_arm64|tar.gz|waf-tester"
  "waftester_Linux_x86_64|tar.gz|waf-tester"
  "waftester_Linux_arm64|tar.gz|waf-tester"
  "waftester_Windows_x86_64|zip|waf-tester.exe"
  "waftester_Windows_arm64|zip|waf-tester.exe"
)

for entry in "${PLATFORMS[@]}"; do
  IFS='|' read -r dirname fmt binary <<< "${entry}"
  tmpdir="${MOCK_DIR}/tmp/${dirname}"
  mkdir -p "${tmpdir}"

  # Create a mock binary (just an echo script or dummy file)
  if [[ "${binary}" == *.exe ]]; then
    echo "mock-binary-${dirname}" > "${tmpdir}/${binary}"
  else
    # Create a proper shell script that outputs version
    cat > "${tmpdir}/${binary}" << 'MOCKEOF'
#!/bin/sh
echo "waf-tester v99.0.0-test.1"
MOCKEOF
    chmod +x "${tmpdir}/${binary}"
  fi

  # Also add the files GoReleaser normally includes
  echo "Mock README" > "${tmpdir}/README.md"
  echo "Mock LICENSE" > "${tmpdir}/LICENSE"
  echo "Mock LICENSE-COMMUNITY" > "${tmpdir}/LICENSE-COMMUNITY"

  # Create the archive
  archive_name="${dirname}"
  if [[ "${fmt}" == "tar.gz" ]]; then
    (cd "${MOCK_DIR}/tmp" && tar czf "${ARCHIVES_DIR}/${archive_name}.tar.gz" "${dirname}/")
  else
    # Use PowerShell's Compress-Archive since zip may not be in Git Bash
    win_src="$(cygpath -w "${MOCK_DIR}/tmp/${dirname}")"
    win_dst="$(cygpath -w "${ARCHIVES_DIR}/${archive_name}.zip")"
    powershell.exe -NoProfile -Command "Compress-Archive -Path '${win_src}' -DestinationPath '${win_dst}' -Force" \
      || err "Failed to create zip: ${archive_name}.zip"
  fi
done

# Create checksums.txt (GoReleaser format)
(cd "${ARCHIVES_DIR}" && sha256sum *.tar.gz *.zip > checksums.txt)

log "Mock archives created:"
ls -la "${ARCHIVES_DIR}/" >&2

# ============================================================================
# Step 2: Run build script
# ============================================================================

log "Running build-npm-packages.sh..."
chmod +x "${SCRIPT_DIR}/build-npm-packages.sh"
"${SCRIPT_DIR}/build-npm-packages.sh" "${VERSION}" "${ARCHIVES_DIR}" "${OUTPUT_DIR}"

# ============================================================================
# Step 3: Validate output structure
# ============================================================================

log ""
log "═══ VALIDATION ═══"

errors=0

# Check all 7 packages exist
for pkg in darwin-x64 darwin-arm64 linux-x64 linux-arm64 win32-x64 win32-arm64; do
  pkg_dir="${OUTPUT_DIR}/@waftester/${pkg}"
  if [[ -d "${pkg_dir}" ]]; then
    pass "@waftester/${pkg} directory exists"
  else
    err "@waftester/${pkg} directory missing"
    errors=$((errors + 1))
  fi

  # Check binary exists
  if [[ "${pkg}" == win32-* ]]; then
    bin="${pkg_dir}/bin/waf-tester.exe"
  else
    bin="${pkg_dir}/bin/waf-tester"
  fi
  if [[ -f "${bin}" ]]; then
    pass "@waftester/${pkg}/bin/ has binary"
  else
    echo "  FAIL: @waftester/${pkg}/bin/ missing binary" >&2
    errors=$((errors + 1))
  fi

  # Check package.json was rendered (no more template placeholders)
  pj="${pkg_dir}/package.json"
  if [[ -f "${pj}" ]]; then
    if grep -q '{{' "${pj}"; then
      echo "  FAIL: @waftester/${pkg}/package.json has unresolved placeholders" >&2
      errors=$((errors + 1))
    else
      pass "@waftester/${pkg}/package.json rendered (no placeholders)"
    fi

    # Verify version is correct
    if grep -q "\"${VERSION}\"" "${pj}"; then
      pass "@waftester/${pkg}/package.json has version ${VERSION}"
    else
      echo "  FAIL: @waftester/${pkg}/package.json version mismatch" >&2
      errors=$((errors + 1))
    fi

    # Verify os/cpu fields
    if grep -q '"os"' "${pj}" && grep -q '"cpu"' "${pj}"; then
      pass "@waftester/${pkg}/package.json has os/cpu fields"
    else
      echo "  FAIL: @waftester/${pkg}/package.json missing os/cpu" >&2
      errors=$((errors + 1))
    fi
  else
    echo "  FAIL: @waftester/${pkg}/package.json missing" >&2
    errors=$((errors + 1))
  fi

  # Check README exists
  if [[ -f "${pkg_dir}/README.md" ]]; then
    pass "@waftester/${pkg}/README.md exists"
  else
    echo "  FAIL: @waftester/${pkg}/README.md missing" >&2
    errors=$((errors + 1))
  fi

  # Check LICENSE exists
  if [[ -f "${pkg_dir}/LICENSE" ]]; then
    pass "@waftester/${pkg}/LICENSE exists"
  else
    echo "  FAIL: @waftester/${pkg}/LICENSE missing" >&2
    errors=$((errors + 1))
  fi
done

# Check main package
cli_dir="${OUTPUT_DIR}/@waftester/cli"
if [[ -d "${cli_dir}" ]]; then
  pass "@waftester/cli directory exists"
else
  err "@waftester/cli directory missing"
fi

# Check cli.js exists and has shebang
if [[ -f "${cli_dir}/bin/cli.js" ]]; then
  if head -1 "${cli_dir}/bin/cli.js" | grep -q '#!/usr/bin/env node'; then
    pass "@waftester/cli/bin/cli.js has correct shebang"
  else
    echo "  FAIL: cli.js missing shebang" >&2
    errors=$((errors + 1))
  fi
else
  echo "  FAIL: @waftester/cli/bin/cli.js missing" >&2
  errors=$((errors + 1))
fi

# Check version was substituted in main package.json
main_pj="${cli_dir}/package.json"
if [[ -f "${main_pj}" ]]; then
  # Should have the test version, not the source version from package.json
  source_ver=$(grep -oP '"version":\s*"\K[^"]+' "${REPO_ROOT}/npm/cli/package.json" | head -1)
  source_count=$(grep -c "\"${source_ver}\"" "${main_pj}" || true)
  test_count=$(grep -c "\"${VERSION}\"" "${main_pj}" || true)
  if [[ "${source_count}" -eq 0 && "${test_count}" -ge 7 ]]; then
    pass "@waftester/cli/package.json version replaced (${test_count} occurrences)"
  else
    echo "  FAIL: version substitution incomplete (${source_ver}: ${source_count}, ${VERSION}: ${test_count})" >&2
    errors=$((errors + 1))
  fi
else
  echo "  FAIL: @waftester/cli/package.json missing" >&2
  errors=$((errors + 1))
fi

# Check payloads copied
if [[ -d "${cli_dir}/payloads" ]]; then
  payload_count=$(find "${cli_dir}/payloads" -type f | wc -l)
  if (( payload_count > 5 )); then
    pass "@waftester/cli/payloads has ${payload_count} files"
  else
    echo "  FAIL: payloads too few files (${payload_count})" >&2
    errors=$((errors + 1))
  fi
else
  echo "  FAIL: @waftester/cli/payloads/ missing" >&2
  errors=$((errors + 1))
fi

# Check templates copied
if [[ -d "${cli_dir}/templates" ]]; then
  tmpl_count=$(find "${cli_dir}/templates" -type f | wc -l)
  if (( tmpl_count > 5 )); then
    pass "@waftester/cli/templates has ${tmpl_count} files"
  else
    echo "  FAIL: templates too few files (${tmpl_count})" >&2
    errors=$((errors + 1))
  fi
else
  echo "  FAIL: @waftester/cli/templates/ missing" >&2
  errors=$((errors + 1))
fi

# Check .cache and premium directories were removed
if [[ -d "${cli_dir}/payloads/.cache" ]]; then
  echo "  FAIL: payloads/.cache should have been removed" >&2
  errors=$((errors + 1))
else
  pass "payloads/.cache removed"
fi
if [[ -d "${cli_dir}/payloads/premium" ]]; then
  echo "  FAIL: payloads/premium should have been removed" >&2
  errors=$((errors + 1))
else
  pass "payloads/premium removed"
fi

# Check LICENSE files
for f in LICENSE LICENSE-COMMUNITY; do
  if [[ -f "${cli_dir}/${f}" ]]; then
    pass "@waftester/cli/${f} exists"
  else
    echo "  FAIL: @waftester/cli/${f} missing" >&2
    errors=$((errors + 1))
  fi
done

# ============================================================================
# Summary
# ============================================================================

log ""
if (( errors == 0 )); then
  log "═══ ALL CHECKS PASSED ═══"
  exit 0
else
  log "═══ ${errors} CHECK(S) FAILED ═══"
  exit 1
fi
