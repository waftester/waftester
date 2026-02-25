#!/usr/bin/env bash
# build-npm-packages.sh — Extract GoReleaser archives and build npm packages
#
# Usage:
#   ./npm/scripts/build-npm-packages.sh <version> <archives-dir> <output-dir>
#
# Example:
#   ./npm/scripts/build-npm-packages.sh 2.8.0 ./dist ./npm-staging
#
# Produces:
#   <output-dir>/@waftester/cli/          — main package
#   <output-dir>/@waftester/darwin-x64/   — platform packages (×6)
#   ...
#
# Prerequisites:
#   - GoReleaser archives + checksums.txt in <archives-dir>
#   - npm/cli/ directory with bin/cli.js, package.json, README.md
#   - npm/platform-template/ with package.json.tmpl, README.md

set -euo pipefail

# ============================================================================
# Arguments
# ============================================================================

VERSION="${1:?Usage: $0 <version> <archives-dir> <output-dir>}"
ARCHIVES_DIR="${2:?Usage: $0 <version> <archives-dir> <output-dir>}"
OUTPUT_DIR="${3:?Usage: $0 <version> <archives-dir> <output-dir>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
NPM_DIR="${REPO_ROOT}/npm"

# ============================================================================
# Platform mapping: npm-name → GoReleaser archive info
# ============================================================================
# Format: NPM_NAME|OS|CPU|PLATFORM_LABEL|ARCHIVE_NAME|BINARY_NAME
#
# GoReleaser archives are flat (no wrapper directory) — binary is at root.

PLATFORMS=(
  "darwin-x64|darwin|x64|macOS x64|waftester_Darwin_x86_64.tar.gz|waf-tester"
  "darwin-arm64|darwin|arm64|macOS arm64|waftester_Darwin_arm64.tar.gz|waf-tester"
  "linux-x64|linux|x64|Linux x64|waftester_Linux_x86_64.tar.gz|waf-tester"
  "linux-arm64|linux|arm64|Linux arm64|waftester_Linux_arm64.tar.gz|waf-tester"
  "win32-x64|win32|x64|Windows x64|waftester_Windows_x86_64.zip|waf-tester.exe"
  "win32-arm64|win32|arm64|Windows arm64|waftester_Windows_arm64.zip|waf-tester.exe"
)

# ============================================================================
# Helpers
# ============================================================================

log() { echo "==> $*" >&2; }
err() { echo "ERROR: $*" >&2; exit 1; }

# Verify checksums before doing anything
verify_checksums() {
  log "Verifying checksums..."
  if [[ ! -f "${ARCHIVES_DIR}/checksums.txt" ]]; then
    err "checksums.txt not found in ${ARCHIVES_DIR}"
  fi
  cd "${ARCHIVES_DIR}"
  sha256sum --check checksums.txt --quiet \
    || err "Checksum verification failed! Aborting."
  cd - > /dev/null
  log "All checksums verified ✓"
}

# Generate platform package.json from template
render_platform_package_json() {
  local pkg_name="$1" version="$2" os="$3" cpu="$4" label="$5"
  sed \
    -e "s|{{PACKAGE_NAME}}|${pkg_name}|g" \
    -e "s|{{VERSION}}|${version}|g" \
    -e "s|{{OS}}|${os}|g" \
    -e "s|{{CPU}}|${cpu}|g" \
    -e "s|{{PLATFORM_LABEL}}|${label}|g" \
    "${NPM_DIR}/platform-template/package.json.tmpl"
}

# ============================================================================
# Main
# ============================================================================

log "Building npm packages for WAFtester v${VERSION}"
log "Archives: ${ARCHIVES_DIR}"
log "Output:   ${OUTPUT_DIR}"

# Verify first
verify_checksums

# Clean output
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# ============================================================================
# Build platform packages (×6)
# ============================================================================

for entry in "${PLATFORMS[@]}"; do
  IFS='|' read -r npm_name os cpu label archive binary <<< "${entry}"
  pkg_name="@waftester/${npm_name}"
  pkg_dir="${OUTPUT_DIR}/@waftester/${npm_name}"
  archive_path="${ARCHIVES_DIR}/${archive}"

  log "Building ${pkg_name}..."

  if [[ ! -f "${archive_path}" ]]; then
    err "Archive not found: ${archive_path}"
  fi

  mkdir -p "${pkg_dir}/bin"

  # Extract binary from archive (GoReleaser archives are flat — binary at root)
  if [[ "${archive}" == *.zip ]]; then
    unzip -j -o "${archive_path}" "${binary}" -d "${pkg_dir}/bin/" \
      || err "Failed to extract ${binary} from ${archive}"
  else
    tar xzf "${archive_path}" -C "${pkg_dir}/bin/" "${binary}" \
      || err "Failed to extract ${binary} from ${archive}"
  fi

  # Set executable permission (critical for Unix platforms)
  chmod +x "${pkg_dir}/bin/${binary}"

  # Smoke test: verify binary runs (skip cross-platform)
  if [[ "${binary}" != *.exe ]] && [[ "$(uname -s | tr '[:upper:]' '[:lower:]')" == "${os}" ]]; then
    local_arch="$(uname -m)"
    expected_arch=""
    case "${cpu}" in
      x64)   expected_arch="x86_64" ;;
      arm64) expected_arch="aarch64" ;;
    esac
    if [[ "${local_arch}" == "${expected_arch}" ]]; then
      log "  Smoke testing ${pkg_name}..."
      "${pkg_dir}/bin/${binary}" version > /dev/null 2>&1 \
        || err "Smoke test failed for ${pkg_name}"
      log "  Smoke test passed ✓"
    fi
  fi

  # Generate package.json
  render_platform_package_json "${pkg_name}" "${VERSION}" "${os}" "${cpu}" "${label}" \
    > "${pkg_dir}/package.json"

  # Copy LICENSE and README
  cp "${REPO_ROOT}/LICENSE" "${pkg_dir}/"
  cp "${NPM_DIR}/platform-template/README.md" "${pkg_dir}/"

  log "  ${pkg_name} ready"
done

# ============================================================================
# Build main package (@waftester/cli)
# ============================================================================

log "Building @waftester/cli..."

cli_dir="${OUTPUT_DIR}/@waftester/cli"
mkdir -p "${cli_dir}/bin"

# Copy bin shim
cp "${NPM_DIR}/cli/bin/cli.js" "${cli_dir}/bin/"

# Copy payloads, presets, and templates from repo root
cp -r "${REPO_ROOT}/payloads" "${cli_dir}/"
cp -r "${REPO_ROOT}/presets" "${cli_dir}/"
cp -r "${REPO_ROOT}/templates" "${cli_dir}/"

# Remove any .cache or premium dirs that shouldn't be published
rm -rf "${cli_dir}/payloads/.cache" "${cli_dir}/payloads/premium"

# Copy LICENSE files
cp "${REPO_ROOT}/LICENSE" "${cli_dir}/"
cp "${REPO_ROOT}/LICENSE-COMMUNITY" "${cli_dir}/"

# Copy npm README
cp "${NPM_DIR}/cli/README.md" "${cli_dir}/"

# Generate package.json with version and pinned optionalDependencies.
# Extract the source version dynamically so the script survives version bumps.
SOURCE_VERSION=$(grep -oP '"version":\s*"\K[^"]+' "${NPM_DIR}/cli/package.json" | head -1)
if [[ "${SOURCE_VERSION}" == "${VERSION}" ]]; then
  log "  Source version matches target (${VERSION}) — copying as-is"
  cp "${NPM_DIR}/cli/package.json" "${cli_dir}/package.json"
else
  log "  Replacing version ${SOURCE_VERSION} → ${VERSION}"
  sed "s/\"${SOURCE_VERSION}\"/\"${VERSION}\"/g" "${NPM_DIR}/cli/package.json" \
    > "${cli_dir}/package.json"

  # Sanity check: verify substitution worked
  if grep -q "\"${SOURCE_VERSION}\"" "${cli_dir}/package.json" 2>/dev/null; then
    err "Version substitution failed — source version ${SOURCE_VERSION} still present in output"
  fi
fi

# Verify target version appears at least 7 times (version + 6 optionalDeps)
target_count=$(grep -c "\"${VERSION}\"" "${cli_dir}/package.json" || true)
if (( target_count < 7 )); then
  err "Version check failed — expected at least 7 occurrences of ${VERSION}, found ${target_count}"
fi

log "  @waftester/cli ready"

# ============================================================================
# Summary
# ============================================================================

log ""
log "All 7 npm packages built successfully:"
for entry in "${PLATFORMS[@]}"; do
  IFS='|' read -r npm_name _ _ _ _ _ _ <<< "${entry}"
  pkg_size=$(du -sh "${OUTPUT_DIR}/@waftester/${npm_name}/bin/" 2>/dev/null | cut -f1)
  log "  @waftester/${npm_name} (${pkg_size})"
done
cli_size=$(du -sh "${cli_dir}" 2>/dev/null | cut -f1)
log "  @waftester/cli (${cli_size})"
log ""
log "Output directory: ${OUTPUT_DIR}"
log "Next: run publish-npm-packages.sh"
