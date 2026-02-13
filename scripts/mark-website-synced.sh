#!/usr/bin/env bash
# Updates .website-sync after the developer has synced the website.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CHANGELOG_VERSION=$(grep -oP '## \[\K[0-9]+\.[0-9]+\.[0-9]+' "$REPO_ROOT/CHANGELOG.md" | head -1)

cat > "$REPO_ROOT/.website-sync" << EOF
# Last synced state between waftester repo and waftester.com website.
# Updated after syncing website content. Checked by tests + pre-push.
# Run: ./scripts/mark-website-synced.sh

changelog_version=${CHANGELOG_VERSION}
EOF

echo "Updated .website-sync: changelog_version=${CHANGELOG_VERSION}"
echo "Now commit: git add .website-sync && git commit -m 'chore: mark website synced to ${CHANGELOG_VERSION}'"
