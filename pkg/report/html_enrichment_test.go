// Regression tests for command injection and escaping in reproduction commands.
package report

import (
	"strings"
	"testing"
)

// TestGenerateCurlCommand_EndpointEscaping verifies that endpoints with shell
// metacharacters are properly escaped in curl commands.
// Regression: unescaped endpoint allowed shell injection via single quotes.
func TestGenerateCurlCommand_EndpointEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		endpoint        string
		wantEscapedQuot bool   // expect single-quote escaping applied
		wantContains    string // substring that should appear in escaped form
	}{
		{
			name:            "single_quote_injection",
			endpoint:        "https://example.com/path'; rm -rf /; echo '",
			wantEscapedQuot: true,
			wantContains:    `'\''`, // bash single-quote escape pattern
		},
		{
			name:     "backtick_safe_in_single_quotes",
			endpoint: "https://example.com/`whoami`",
			// backticks are safe inside bash single-quoted strings — no escaping needed
		},
		{
			name:     "dollar_safe_in_single_quotes",
			endpoint: "https://example.com/$(id)",
			// $() is safe inside bash single-quoted strings
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			finding := &BypassFinding{
				Endpoint: tt.endpoint,
				Method:   "GET",
			}
			cmd := GenerateCurlCommand(finding)

			if cmd == "" {
				t.Fatal("expected command, got empty string")
			}

			// If the endpoint contains single quotes, they MUST be escaped
			if tt.wantEscapedQuot {
				if !strings.Contains(cmd, `'\''`) {
					t.Errorf("single quotes not escaped with '\\'' pattern:\n%s", cmd)
				}
			}

			if tt.wantContains != "" && !strings.Contains(cmd, tt.wantContains) {
				t.Errorf("expected output to contain %q:\n%s", tt.wantContains, cmd)
			}
		})
	}
}

// TestGeneratePowerShellCommand_EndpointEscaping verifies that endpoints
// containing single quotes are escaped for PowerShell.
// Regression: finding.Endpoint was written raw into single-quoted PowerShell string,
// allowing command injection via embedded single quotes.
func TestGeneratePowerShellCommand_EndpointEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		payload  string
		method   string
		contains string // must appear in output (escaped form)
	}{
		{
			name:     "single_quote_in_endpoint",
			endpoint: "https://example.com/path'; Invoke-Expression 'malicious",
			method:   "GET",
			contains: "path''", // PowerShell escaping: ' → ''
		},
		{
			name:     "single_quote_in_payload",
			endpoint: "https://example.com/api",
			payload:  "'; Drop-Database; '",
			method:   "POST",
			contains: "''", // Payload single quotes escaped
		},
		{
			name:     "backtick_in_payload",
			endpoint: "https://example.com/api",
			payload:  "`$(calc.exe)`",
			method:   "POST",
			contains: "``", // PowerShell escaping: ` → ``
		},
		{
			name:     "clean_endpoint",
			endpoint: "https://example.com/api/v1",
			method:   "GET",
			contains: "https://example.com/api/v1",
		},
		{
			name:     "empty_endpoint",
			endpoint: "",
			method:   "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			finding := &BypassFinding{
				Endpoint: tt.endpoint,
				Payload:  tt.payload,
				Method:   tt.method,
			}
			cmd := GeneratePowerShellCommand(finding)

			if tt.endpoint == "" {
				if cmd != "" {
					t.Errorf("expected empty for empty endpoint, got: %s", cmd)
				}
				return
			}

			if cmd == "" {
				t.Fatal("expected command, got empty string")
			}

			if tt.contains != "" && !strings.Contains(cmd, tt.contains) {
				t.Errorf("expected output to contain %q:\n%s", tt.contains, cmd)
			}

			// Structural: endpoint must be inside single quotes
			if !strings.Contains(cmd, "-Uri '") {
				t.Errorf("endpoint not inside single-quoted -Uri:\n%s", cmd)
			}
		})
	}
}

// TestGeneratePowerShellCommand_SingleQuoteNotRaw verifies the critical regression:
// a single quote in the endpoint must not appear as a raw unescaped single quote.
// In PowerShell, ' inside '...' is escaped by doubling: ”
func TestGeneratePowerShellCommand_SingleQuoteNotRaw(t *testing.T) {
	t.Parallel()

	finding := &BypassFinding{
		Endpoint: "https://evil.com/x'; Invoke-Expression 'calc",
		Method:   "GET",
	}
	cmd := GeneratePowerShellCommand(finding)

	// After escaping, the endpoint inside the -Uri should have '' instead of raw '
	uriIdx := strings.Index(cmd, "-Uri '")
	if uriIdx == -1 {
		t.Fatal("no -Uri found")
	}
	uriContent := cmd[uriIdx+len("-Uri '"):]

	// The escaped endpoint should contain '' where the original had '
	if !strings.Contains(uriContent, "''") {
		t.Errorf("single quotes in endpoint not doubled:\n%s", cmd)
	}

	// The original raw injection pattern must be broken by escaping
	// Original: x'; Invoke-Expression 'calc
	// Escaped:  x''; Invoke-Expression ''calc
	if !strings.Contains(uriContent, "x''") {
		t.Errorf("expected x'' (escaped single quote) in URI:\n%s", cmd)
	}
}

// TestGeneratePythonCode_EndpointEscaping verifies that endpoints with Python
// string metacharacters are properly escaped.
// Regression: unescaped endpoints allowed Python string breakout.
func TestGeneratePythonCode_EndpointEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		endpoint string
		contains string // expected escaped form
	}{
		{
			name:     "double_quote_injection",
			endpoint: `https://example.com/"; import os; os.system("id"); x="`,
			contains: `\"`, // double quotes must be escaped
		},
		{
			name:     "backslash_injection",
			endpoint: `https://example.com/\path`,
			contains: `\\path`, // backslash must be doubled
		},
		{
			name:     "clean_endpoint",
			endpoint: "https://example.com/api/v1",
			contains: "https://example.com/api/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			finding := &BypassFinding{
				Endpoint: tt.endpoint,
				Method:   "GET",
			}
			code := GeneratePythonCode(finding)

			if code == "" {
				t.Fatal("expected code, got empty string")
			}

			if tt.contains != "" && !strings.Contains(code, tt.contains) {
				t.Errorf("expected code to contain %q:\n%s", tt.contains, code)
			}

			// Structural: URL must be inside double-quoted Python string
			if !strings.Contains(code, `url = "`) {
				t.Errorf("endpoint not inside double-quoted Python string:\n%s", code)
			}
		})
	}
}

// TestGeneratePythonCode_DoubleQuoteNotRaw verifies the critical regression:
// a double quote in the endpoint must be escaped so it cannot break the Python string.
func TestGeneratePythonCode_DoubleQuoteNotRaw(t *testing.T) {
	t.Parallel()

	finding := &BypassFinding{
		Endpoint: `https://evil.com/"; import os; #`,
		Method:   "GET",
	}
	code := GeneratePythonCode(finding)

	// Extract the url = "..." line
	urlLine := ""
	for _, line := range strings.Split(code, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "url = ") {
			urlLine = line
			break
		}
	}
	if urlLine == "" {
		t.Fatal("url = line not found in output")
	}

	// The escaped form should contain \" (escaped double quote)
	if !strings.Contains(urlLine, `\"`) {
		t.Errorf("double quote not escaped in URL line: %s", urlLine)
	}
}

// TestGeneratePowerShellCommand_DefaultMethod verifies GET default when method is empty.
func TestGeneratePowerShellCommand_DefaultMethod(t *testing.T) {
	finding := &BypassFinding{
		Endpoint: "https://example.com/api",
	}
	cmd := GeneratePowerShellCommand(finding)

	if !strings.Contains(cmd, "-Method GET") {
		t.Errorf("expected default method GET, got: %s", cmd)
	}
}

// TestGeneratePowerShellCommand_BodyMethods verifies POST/PUT/PATCH include body.
func TestGeneratePowerShellCommand_BodyMethods(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"POST", "PUT", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			finding := &BypassFinding{
				Endpoint: "https://example.com/api",
				Payload:  "test=value",
				Method:   method,
			}
			cmd := GeneratePowerShellCommand(finding)

			if !strings.Contains(cmd, "-Body ") {
				t.Errorf("%s should include -Body, got: %s", method, cmd)
			}
		})
	}
}

// TestGeneratePowerShellCommand_GETNoBody verifies GET/DELETE/HEAD omit body.
func TestGeneratePowerShellCommand_GETNoBody(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"GET", "DELETE", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			finding := &BypassFinding{
				Endpoint: "https://example.com/api",
				Payload:  "test=value",
				Method:   method,
			}
			cmd := GeneratePowerShellCommand(finding)

			if strings.Contains(cmd, "-Body ") {
				t.Errorf("%s should NOT include -Body, got: %s", method, cmd)
			}
		})
	}
}
