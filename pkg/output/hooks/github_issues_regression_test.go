// Regression tests for GitHub Issues hook input validation (from 85-fix adversarial review).
//
// Bug: NewGitHubIssuesHook accepted any string for Owner/Repo, allowing
//      path traversal or API URL manipulation (e.g., "../../admin").
// Fix: Validate with regex ^[a-zA-Z0-9._-]+$ and return an error.
package hooks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGitHubIssuesHook_RejectsInvalidOwner verifies that malicious owner
// names are rejected with an error.
// Regression: no validation was performed, enabling path traversal.
func TestNewGitHubIssuesHook_RejectsInvalidOwner(t *testing.T) {
	t.Parallel()

	invalidOwners := []string{
		"",                  // empty
		"../../admin",       // path traversal
		"owner/repo",        // slash in owner
		"owner name",        // space
		"owner\tname",       // tab
		"<script>",          // XSS attempt
		"owner%00",          // null byte in encoding
		"a b",               // whitespace
		"user\n",            // newline
	}

	for _, owner := range invalidOwners {
		t.Run("owner_"+owner, func(t *testing.T) {
			_, err := NewGitHubIssuesHook(GitHubIssuesOptions{
				Token: "test-token",
				Owner: owner,
				Repo:  "valid-repo",
			})
			assert.Error(t, err, "owner %q must be rejected", owner)
		})
	}
}

// TestNewGitHubIssuesHook_RejectsInvalidRepo verifies that malicious repo
// names are rejected.
func TestNewGitHubIssuesHook_RejectsInvalidRepo(t *testing.T) {
	t.Parallel()

	invalidRepos := []string{
		"",                  // empty
		"../../etc/passwd",  // traversal
		"repo name",         // space
		"repo/sub",          // slash
		"<script>alert(1)</script>",
	}

	for _, repo := range invalidRepos {
		t.Run("repo_"+repo, func(t *testing.T) {
			_, err := NewGitHubIssuesHook(GitHubIssuesOptions{
				Token: "test-token",
				Owner: "valid-owner",
				Repo:  repo,
			})
			assert.Error(t, err, "repo %q must be rejected", repo)
		})
	}
}

// TestNewGitHubIssuesHook_AcceptsValidNames verifies legitimate GitHub names
// are accepted.
func TestNewGitHubIssuesHook_AcceptsValidNames(t *testing.T) {
	t.Parallel()

	validNames := []struct {
		owner string
		repo  string
	}{
		{"octocat", "Hello-World"},
		{"my.org", "my_repo"},
		{"user-name", "repo.name"},
		{"UPPER", "lower"},
		{"a", "b"},
		{"123", "456"},
		{"my-org.name", "repo-name_v2.0"},
	}

	for _, tt := range validNames {
		t.Run(tt.owner+"/"+tt.repo, func(t *testing.T) {
			hook, err := NewGitHubIssuesHook(GitHubIssuesOptions{
				Token: "test-token",
				Owner: tt.owner,
				Repo:  tt.repo,
			})
			require.NoError(t, err, "%s/%s must be accepted", tt.owner, tt.repo)
			assert.NotNil(t, hook)
		})
	}
}
