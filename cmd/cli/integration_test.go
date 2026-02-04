package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// skipIfNotIntegration skips the test if WAFTESTER_INTEGRATION is not set.
// Integration tests run actual CLI commands which may be slow.
func skipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("WAFTESTER_INTEGRATION") != "1" {
		t.Skip("Skipping integration test (set WAFTESTER_INTEGRATION=1 to run)")
	}
}

// runCLI runs the CLI with the given arguments using "go run ."
// Returns stdout, stderr, and any error from execution.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	// Get the cmd/cli directory - tests run from this directory
	cliDir := getCLIDir(t)

	cmdArgs := append([]string{"run", "."}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = cliDir

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	return stdoutBuf.String(), stderrBuf.String(), err
}

// getCLIDir returns the absolute path to the cmd/cli directory.
func getCLIDir(t *testing.T) string {
	t.Helper()

	// First try the working directory (normal test execution)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Check if we're already in cmd/cli
	if filepath.Base(wd) == "cli" && filepath.Base(filepath.Dir(wd)) == "cmd" {
		return wd
	}

	// Try to find cmd/cli relative to working directory
	cliDir := filepath.Join(wd, "cmd", "cli")
	if _, err := os.Stat(filepath.Join(cliDir, "main.go")); err == nil {
		return cliDir
	}

	// Already in the right place
	return wd
}

// getPayloadsDir returns the absolute path to the payloads directory.
func getPayloadsDir(t *testing.T) string {
	t.Helper()

	cliDir := getCLIDir(t)

	// payloads is at the repo root, two levels up from cmd/cli
	payloadsDir := filepath.Join(cliDir, "..", "..", "payloads")

	// Normalize path
	payloadsDir, err := filepath.Abs(payloadsDir)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	return payloadsDir
}

// TestCLI_Help_ShowsCommands verifies that running with -h or help
// shows the COMMANDS section in the output.
func TestCLI_Help_ShowsCommands(t *testing.T) {
	skipIfNotIntegration(t)

	testCases := []struct {
		name string
		args []string
	}{
		{"help flag", []string{"-h"}},
		{"help command", []string{"help"}},
		{"double-dash help", []string{"--help"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runCLI(t, tc.args...)
			// Help should exit with code 0
			if err != nil {
				// Some shells return exit code 0 for help, others might not
				// Check if we got output at least
				if stdout == "" && stderr == "" {
					t.Fatalf("CLI help failed with no output: %v", err)
				}
			}

			// Check combined output (help may go to stdout or stderr)
			combined := stdout + stderr
			if !strings.Contains(combined, "COMMANDS") {
				t.Errorf("Help output should contain 'COMMANDS' section.\nGot stdout:\n%s\nGot stderr:\n%s", stdout, stderr)
			}
		})
	}
}

// TestCLI_InvalidCommand_ShowsHelp verifies that an invalid command
// shows usage information (or at least doesn't crash silently).
func TestCLI_InvalidCommand_ShowsHelp(t *testing.T) {
	skipIfNotIntegration(t)

	stdout, stderr, err := runCLI(t, "nonexistent-command-xyz")

	// Invalid command should either:
	// 1. Show help/usage
	// 2. Return an error
	// 3. Fall through to default run behavior

	// At minimum, we should get some output or an error
	combined := stdout + stderr
	if err == nil && combined == "" {
		t.Error("Invalid command should produce output or error")
	}

	// The default behavior may try to run tests or show help
	// Either is acceptable - we just verify it doesn't crash silently
	t.Logf("Output for invalid command: stdout=%d bytes, stderr=%d bytes, err=%v",
		len(stdout), len(stderr), err)
}

// TestCLI_Version_ShowsVersion verifies that version command works.
func TestCLI_Version_ShowsVersion(t *testing.T) {
	skipIfNotIntegration(t)

	testCases := []struct {
		name string
		args []string
	}{
		{"version flag", []string{"-v"}},
		{"version command", []string{"version"}},
		{"double-dash version", []string{"--version"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, err := runCLI(t, tc.args...)
			if err != nil {
				// Version should exit cleanly, but check for output
				if stdout == "" && stderr == "" {
					t.Fatalf("CLI version failed with no output: %v", err)
				}
			}

			// Version output typically contains "waf" or version info
			combined := stdout + stderr
			// The banner should appear (contains WAF or similar)
			if len(combined) == 0 {
				t.Error("Version command should produce output")
			}
		})
	}
}

// TestCLI_Validate_ValidPayloadFile tests the validate command with a real payload file.
func TestCLI_Validate_ValidPayloadFile(t *testing.T) {
	skipIfNotIntegration(t)

	// Find a real payload file from the payloads directory
	payloadsDir := getPayloadsDir(t)

	// Check if payloads directory exists
	if _, err := os.Stat(payloadsDir); os.IsNotExist(err) {
		t.Skip("Payloads directory not found, skipping validate test")
	}

	// Run validate command with the payloads directory
	stdout, stderr, err := runCLI(t, "validate", "-payloads", payloadsDir)

	// Validate command should work with valid payload files
	combined := stdout + stderr
	t.Logf("Validate output: %s", combined)

	// The command should produce output indicating validation
	// Even if there are warnings, it shouldn't crash
	if err != nil {
		// Check if there's meaningful output
		if combined == "" {
			t.Errorf("Validate command failed with no output: %v", err)
		}
	}

	// Look for validation-related output
	hasValidationOutput := strings.Contains(combined, "Validation") ||
		strings.Contains(combined, "Payload") ||
		strings.Contains(combined, "valid") ||
		strings.Contains(combined, "Invalid") ||
		strings.Contains(combined, "error")

	if !hasValidationOutput && combined != "" {
		t.Logf("Note: Validate output didn't contain expected keywords, got: %s", combined)
	}
}

// TestCLI_Validate_InvalidFile tests the validate command with a non-existent file.
func TestCLI_Validate_InvalidFile(t *testing.T) {
	skipIfNotIntegration(t)

	// Use a path that definitely doesn't exist
	nonExistentPath := filepath.Join(os.TempDir(), "waftester-test-nonexistent-payloads-xyz123")

	stdout, stderr, err := runCLI(t, "validate", "-payloads", nonExistentPath)

	combined := stdout + stderr
	t.Logf("Validate with invalid path output: %s", combined)

	// The command should handle missing files gracefully
	// It may exit with error or print error message
	if err == nil && !strings.Contains(combined, "error") && !strings.Contains(combined, "not found") && !strings.Contains(combined, "no such") {
		// If no error and no error message, check if it at least didn't crash
		t.Logf("Note: Command succeeded with non-existent path. Output: %s", combined)
	}
}

// TestCLI_Docs_ShowsDocumentation tests the docs command.
func TestCLI_Docs_ShowsDocumentation(t *testing.T) {
	skipIfNotIntegration(t)

	stdout, stderr, err := runCLI(t, "docs")

	// Docs should exit cleanly
	if err != nil {
		if stdout == "" && stderr == "" {
			t.Fatalf("CLI docs failed with no output: %v", err)
		}
	}

	combined := stdout + stderr

	// Docs should show documentation content
	hasDocsContent := strings.Contains(combined, "COMMAND") ||
		strings.Contains(combined, "DOCUMENTATION") ||
		strings.Contains(combined, "waf-tester")

	if !hasDocsContent {
		t.Errorf("Docs command should show documentation content.\nGot:\n%s", combined)
	}
}

// TestCLI_NoArgs_ShowsUsage tests that running without arguments shows usage.
func TestCLI_NoArgs_ShowsUsage(t *testing.T) {
	skipIfNotIntegration(t)

	stdout, stderr, err := runCLI(t)

	// No args should show usage and exit with error (code 1)
	combined := stdout + stderr

	// Should show usage info
	hasUsageInfo := strings.Contains(combined, "USAGE") ||
		strings.Contains(combined, "COMMANDS") ||
		strings.Contains(combined, "waf-tester")

	if !hasUsageInfo && combined == "" {
		t.Error("Running without args should show usage information")
	}

	// Typically exits with non-zero code when no args provided
	if err == nil {
		t.Logf("Note: CLI exited successfully with no args (may show usage)")
	}
}

// TestCLI_CommandAliases tests that command aliases work correctly.
func TestCLI_CommandAliases(t *testing.T) {
	skipIfNotIntegration(t)

	// Test that common aliases are recognized
	aliasGroups := []struct {
		name    string
		aliases []string
	}{
		{"auto", []string{"auto", "superpower", "sp"}},
		{"help", []string{"help", "-h", "--help"}},
		{"version", []string{"version", "-v", "--version"}},
		{"docs", []string{"docs", "doc", "man", "manual"}},
	}

	for _, group := range aliasGroups {
		t.Run(group.name, func(t *testing.T) {
			// Run first alias to get baseline
			baseStdout, baseStderr, baseErr := runCLI(t, group.aliases[0])
			baseOutput := baseStdout + baseStderr
			baseHasError := baseErr != nil

			// Other aliases should behave similarly
			for _, alias := range group.aliases[1:] {
				stdout, stderr, err := runCLI(t, alias)
				output := stdout + stderr
				hasError := err != nil

				// Both should succeed or both should fail
				if baseHasError != hasError {
					// Allow some variance in exit codes for help/version
					if !strings.Contains(group.name, "help") && !strings.Contains(group.name, "version") {
						t.Logf("Alias '%s' error state differs from '%s': %v vs %v",
							alias, group.aliases[0], err, baseErr)
					}
				}

				// Both should produce output
				if len(output) == 0 && len(baseOutput) > 0 {
					t.Errorf("Alias '%s' produced no output while '%s' did",
						alias, group.aliases[0])
				}
			}
		})
	}
}
