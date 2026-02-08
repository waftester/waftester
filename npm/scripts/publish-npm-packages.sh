#!/usr/bin/env bash
# publish-npm-packages.sh — Publish all 7 npm packages with provenance
#
# Usage:
#   ./npm/scripts/publish-npm-packages.sh <version> <staging-dir> [--dry-run]
#
# Example:
#   ./npm/scripts/publish-npm-packages.sh 2.8.0 ./npm-staging
#   ./npm/scripts/publish-npm-packages.sh 2.8.0 ./npm-staging --dry-run
#
# Environment:
#   NPM_TOKEN — required (set by GitHub Actions secret)
#
# The script:
#   1. Publishes all 6 platform packages (with idempotency check)
#   2. Waits for all 6 to appear on the registry
#   3. Publishes the main @waftester/cli package
#   4. Runs smoke test: npx -y @waftester/cli@<version> version

set -euo pipefail

# ============================================================================
# Arguments & Configuration
# ============================================================================

VERSION="${1:?Usage: $0 <version> <staging-dir> [--dry-run]}"
STAGING_DIR="${2:?Usage: $0 <version> <staging-dir> [--dry-run]}"
DRY_RUN="${3:-}"

# Pre-release detection: version contains '-' (e.g., 2.8.0-rc.1)
TAG_ARGS=""
if [[ "${VERSION}" == *-* ]]; then
  TAG_ARGS="--tag next"
  echo "==> Pre-release detected (${VERSION}), using --tag next" >&2
fi

# Dry-run mode
PUBLISH_EXTRA=""
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  PUBLISH_EXTRA="--dry-run"
  echo "==> DRY RUN MODE — nothing will be published" >&2
fi

# Platform packages (must match build script)
PLATFORM_PACKAGES=(
  "@waftester/darwin-x64"
  "@waftester/darwin-arm64"
  "@waftester/linux-x64"
  "@waftester/linux-arm64"
  "@waftester/win32-x64"
  "@waftester/win32-arm64"
)

# ============================================================================
# Helpers
# ============================================================================

log() { echo "==> $*" >&2; }
err() { echo "ERROR: $*" >&2; exit 1; }

# Check if a package@version already exists on npm
pkg_exists() {
  local pkg="$1" ver="$2"
  npm view "${pkg}@${ver}" version > /dev/null 2>&1
}

# Publish a single package with retries
publish_pkg() {
  local pkg_dir="$1" pkg_name="$2"
  local max_retries=3 attempt=0

  while (( attempt < max_retries )); do
    attempt=$((attempt + 1))
    log "  Publishing ${pkg_name} (attempt ${attempt}/${max_retries})..."

    # shellcheck disable=SC2086
    if (cd "${pkg_dir}" && npm publish \
        --provenance \
        --access public \
        ${TAG_ARGS} \
        ${PUBLISH_EXTRA} \
      ); then
      log "  ${pkg_name}@${VERSION} published ✓"
      return 0
    fi

    if (( attempt < max_retries )); then
      local wait=$((attempt * 5))
      log "  Retrying in ${wait}s..."
      sleep "${wait}"
    fi
  done

  err "Failed to publish ${pkg_name} after ${max_retries} attempts"
}

# Wait for a package version to appear on the registry (npm CDN propagation)
wait_for_pkg() {
  local pkg="$1" ver="$2"
  local max_wait=120 interval=5 elapsed=0

  log "  Waiting for ${pkg}@${ver} on registry..."
  while (( elapsed < max_wait )); do
    if pkg_exists "${pkg}" "${ver}"; then
      log "  ${pkg}@${ver} available ✓"
      return 0
    fi
    sleep "${interval}"
    elapsed=$((elapsed + interval))
  done
  err "${pkg}@${ver} not found on registry after ${max_wait}s"
}

# ============================================================================
# Validation
# ============================================================================

if [[ "${DRY_RUN}" != "--dry-run" ]]; then
  if [[ -z "${NPM_TOKEN:-}" ]]; then
    err "NPM_TOKEN environment variable is not set"
  fi
  # Configure npm auth (CI-friendly, no .npmrc file in repo)
  export NPM_CONFIG_TOKEN="${NPM_TOKEN}"
fi

# Verify staging directory exists with expected packages
for pkg in "${PLATFORM_PACKAGES[@]}"; do
  pkg_subdir="${pkg#@waftester/}"
  if [[ ! -d "${STAGING_DIR}/@waftester/${pkg_subdir}" ]]; then
    err "Missing staging directory: ${STAGING_DIR}/@waftester/${pkg_subdir}"
  fi
done
if [[ ! -d "${STAGING_DIR}/@waftester/cli" ]]; then
  err "Missing staging directory: ${STAGING_DIR}/@waftester/cli"
fi

# ============================================================================
# Step 1: Publish platform packages
# ============================================================================

log "Publishing 6 platform packages..."

published=0
skipped=0

for pkg in "${PLATFORM_PACKAGES[@]}"; do
  pkg_subdir="${pkg#@waftester/}"
  pkg_dir="${STAGING_DIR}/@waftester/${pkg_subdir}"

  if [[ "${DRY_RUN}" != "--dry-run" ]] && pkg_exists "${pkg}" "${VERSION}"; then
    log "  ${pkg}@${VERSION} already exists, skipping"
    skipped=$((skipped + 1))
    continue
  fi

  publish_pkg "${pkg_dir}" "${pkg}"
  published=$((published + 1))
done

log "Platform packages: ${published} published, ${skipped} skipped"

# ============================================================================
# Step 2: Wait for all platform packages to be on registry
# ============================================================================

if [[ "${DRY_RUN}" != "--dry-run" ]]; then
  log "Waiting for platform packages on registry..."
  for pkg in "${PLATFORM_PACKAGES[@]}"; do
    wait_for_pkg "${pkg}" "${VERSION}"
  done
  log "All 6 platform packages available on registry ✓"
fi

# ============================================================================
# Step 3: Publish main package
# ============================================================================

log "Publishing @waftester/cli..."

if [[ "${DRY_RUN}" != "--dry-run" ]] && pkg_exists "@waftester/cli" "${VERSION}"; then
  log "  @waftester/cli@${VERSION} already exists, skipping"
else
  publish_pkg "${STAGING_DIR}/@waftester/cli" "@waftester/cli"
fi

# ============================================================================
# Step 4: Wait + smoke test
# ============================================================================

if [[ "${DRY_RUN}" != "--dry-run" ]]; then
  wait_for_pkg "@waftester/cli" "${VERSION}"

  log "Running smoke test..."

  tag_suffix=""
  if [[ -n "${TAG_ARGS}" ]]; then
    tag_suffix="@next"
  else
    tag_suffix="@${VERSION}"
  fi

  smoke_output=$(npx -y "@waftester/cli${tag_suffix}" version 2>&1) \
    || err "Smoke test failed: npx @waftester/cli${tag_suffix} version"

  log "Smoke test output: ${smoke_output}"
  log "Smoke test passed ✓"
fi

# ============================================================================
# Summary
# ============================================================================

log ""
log "═══════════════════════════════════════════════════════════"
if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  log "DRY RUN COMPLETE — no packages were published"
else
  log "All 7 packages published successfully!"
  log ""
  log "  npm install -g @waftester/cli@${VERSION}"
  log "  npx -y @waftester/cli@${VERSION} version"
  if [[ -n "${TAG_ARGS}" ]]; then
    log ""
    log "  (pre-release: tagged as 'next', not 'latest')"
  fi
fi
log "═══════════════════════════════════════════════════════════"
