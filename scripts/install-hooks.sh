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

# Install commit-msg hook
cp "$REPO_ROOT/scripts/hooks/commit-msg" "$HOOKS_DIR/commit-msg"
chmod +x "$HOOKS_DIR/commit-msg"
echo "  ✓ commit-msg hook installed"

# Install pre-push hook
cp "$REPO_ROOT/scripts/hooks/pre-push" "$HOOKS_DIR/pre-push"
chmod +x "$HOOKS_DIR/pre-push"
echo "  ✓ pre-push hook installed"

# Mark scripts as executable
chmod +x "$REPO_ROOT/scripts/race-test.sh" 2>/dev/null || true
chmod +x "$REPO_ROOT/scripts/verify.sh" 2>/dev/null || true

echo "Done. Hooks are active."
echo ""
echo "Run the full quality gate:"
echo "  bash scripts/verify.sh"
