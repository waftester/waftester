#!/usr/bin/env bash
# Install git hooks for WAFtester development.
# Run once after cloning: ./scripts/install-hooks.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

echo "Installing git hooks..."

# Install pre-commit hook
cp "$REPO_ROOT/scripts/hooks/pre-commit" "$HOOKS_DIR/pre-commit"
chmod +x "$HOOKS_DIR/pre-commit"
echo "  ✓ pre-commit hook installed"

# Install pre-push hook
cp "$REPO_ROOT/scripts/hooks/pre-push" "$HOOKS_DIR/pre-push"
chmod +x "$HOOKS_DIR/pre-push"
echo "  ✓ pre-push hook installed"

echo "Done. Hooks are active."
