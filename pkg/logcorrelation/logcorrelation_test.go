package logcorrelation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleModSecLog = `--a1234567-A--
[28/Jan/2026:10:15:30 +0000] 192.168.1.1 - - [28/Jan/2026:10:15:30 +0000] "GET /test?id=1 HTTP/1.1" 403
X-WAF-Test-Marker: abc123

--a1234567-B--
GET /test?id=1' UNION SELECT 1,2,3-- HTTP/1.1
Host: example.com
X-WAF-Test-Marker: abc123

--a1234567-H--
Message: Warning. Matched "Operator ` + "`" + `Rx' with parameter ` + "`" + `(?i:union.*select)' against variable ` + "`" + `ARGS:id' (Value: ` + "`" + `1' UNION SELECT 1,2,3--') [file "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "100"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]

--a1234567-Z--

--b7654321-A--
[28/Jan/2026:10:15:31 +0000] 192.168.1.2 - - [28/Jan/2026:10:15:31 +0000] "GET /search?q=test HTTP/1.1" 403
X-WAF-Test-Marker: def456

--b7654321-B--
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
X-WAF-Test-Marker: def456

--b7654321-H--
Message: Warning. Matched "Operator ` + "`" + `Rx' with parameter ` + "`" + `<script' against variable ` + "`" + `ARGS:q' (Value: ` + "`" + `<script>alert(1)</script>') [file "/etc/modsecurity/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "200"] [id "941100"] [msg "XSS Attack Detected via libinjection"] [severity "CRITICAL"]
Message: Warning. [id "941110"] [msg "XSS Filter - Category 1"] [severity "WARNING"]

--b7654321-Z--
`

func TestModSecLogParser(t *testing.T) {
	// Create temp log file
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	parser, err := NewModSecParser(logFile)
	require.NoError(t, err)
	defer parser.Close()

	// Find entries for marker abc123
	entries, err := parser.FindByMarker("abc123")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].TriggeredRules, uint(942100))
	assert.Equal(t, "abc123", entries[0].Marker)
}

func TestModSecLogParserMultipleRules(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	parser, err := NewModSecParser(logFile)
	require.NoError(t, err)
	defer parser.Close()

	// Find entries for marker def456 (has 2 rules)
	entries, err := parser.FindByMarker("def456")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].TriggeredRules, uint(941100))
	assert.Contains(t, entries[0].TriggeredRules, uint(941110))
}

func TestRuleIDExtraction(t *testing.T) {
	parser := &ModSecParser{}

	ruleIDs := parser.extractRuleIDs(`[id "942100"] [id "941100"]`)
	assert.Contains(t, ruleIDs, uint(942100))
	assert.Contains(t, ruleIDs, uint(941100))
}

func TestRuleIDExtractionNoQuotes(t *testing.T) {
	parser := &ModSecParser{}

	ruleIDs := parser.extractRuleIDs(`[id 942100] [id 941100]`)
	assert.Contains(t, ruleIDs, uint(942100))
	assert.Contains(t, ruleIDs, uint(941100))
}

func TestCorrelator(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "X-WAF-Test-Marker")
	require.NoError(t, err)
	defer c.Close()

	// Check expected rules
	result, err := c.Verify("abc123", []uint{942100}, nil)
	require.NoError(t, err)
	assert.True(t, result.ExpectedRulesMatched)
	assert.Empty(t, result.MissingExpectedRules)
	assert.True(t, result.Success)
}

func TestCorrelatorMissingExpectedRule(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "X-WAF-Test-Marker")
	require.NoError(t, err)
	defer c.Close()

	// Check for a rule that didn't trigger
	result, err := c.Verify("abc123", []uint{942100, 999999}, nil)
	require.NoError(t, err)
	assert.False(t, result.ExpectedRulesMatched)
	assert.Contains(t, result.MissingExpectedRules, uint(999999))
	assert.False(t, result.Success)
}

func TestCorrelatorUnexpectedRules(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "X-WAF-Test-Marker")
	require.NoError(t, err)
	defer c.Close()

	// Check that rule 941100 is NOT expected
	result, err := c.Verify("def456", nil, []uint{941100})
	require.NoError(t, err)
	assert.False(t, result.NoUnexpectedRulesTriggered)
	assert.Contains(t, result.UnexpectedRulesTriggered, uint(941100))
}

func TestCorrelatorVerifyBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "X-WAF-Test-Marker")
	require.NoError(t, err)
	defer c.Close()

	// Verify blocked
	result, err := c.VerifyBlocked("abc123")
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.Greater(t, len(result.TriggeredRules), 0)
}

func TestCorrelatorNotBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "X-WAF-Test-Marker")
	require.NoError(t, err)
	defer c.Close()

	// Verify with non-existent marker
	result, err := c.VerifyBlocked("nonexistent")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Empty(t, result.TriggeredRules)
}

func TestMarkerGeneration(t *testing.T) {
	marker1 := GenerateMarker()
	marker2 := GenerateMarker()

	assert.NotEqual(t, marker1, marker2)
	assert.Len(t, marker1, 32) // UUID without dashes
}

func TestMarkerHeader(t *testing.T) {
	assert.Equal(t, "X-WAF-Test-Marker", MarkerHeader)
}

func TestCorrelatorGetMarkerHeader(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(""), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "Custom-Header")
	require.NoError(t, err)
	defer c.Close()

	assert.Equal(t, "Custom-Header", c.GetMarkerHeader())
}

func TestCorrelatorDefaultHeader(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(""), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "")
	require.NoError(t, err)
	defer c.Close()

	assert.Equal(t, MarkerHeader, c.GetMarkerHeader())
}

func TestModSecParserCache(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	parser, err := NewModSecParser(logFile)
	require.NoError(t, err)
	defer parser.Close()

	// First call
	entries1, err := parser.FindByMarker("abc123")
	require.NoError(t, err)

	// Second call should use cache
	entries2, err := parser.FindByMarker("abc123")
	require.NoError(t, err)

	assert.Equal(t, len(entries1), len(entries2))

	// Clear cache
	parser.ClearCache()

	// Third call should re-parse
	entries3, err := parser.FindByMarker("abc123")
	require.NoError(t, err)
	assert.Equal(t, len(entries1), len(entries3))
}

func TestModSecParserMessages(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	parser, err := NewModSecParser(logFile)
	require.NoError(t, err)
	defer parser.Close()

	entries, err := parser.FindByMarker("abc123")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Greater(t, len(entries[0].Messages), 0)
	assert.Contains(t, entries[0].Messages[0], "SQL Injection")
}

func TestModSecParserSeverity(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	parser, err := NewModSecParser(logFile)
	require.NoError(t, err)
	defer parser.Close()

	entries, err := parser.FindByMarker("abc123")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "CRITICAL", entries[0].Severity)
}

func TestNewCorrelatorFileNotFound(t *testing.T) {
	_, err := NewCorrelator("/nonexistent/path/file.log", "")
	assert.Error(t, err)
}

func TestBatchVerify(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "modsec_audit.log")
	err := os.WriteFile(logFile, []byte(sampleModSecLog), 0644)
	require.NoError(t, err)

	c, err := NewCorrelator(logFile, "")
	require.NoError(t, err)
	defer c.Close()

	tests := []struct {
		Marker      string
		ExpectRules []uint
	}{
		{Marker: "abc123", ExpectRules: []uint{942100}},
		{Marker: "def456", ExpectRules: []uint{941100}},
	}

	results, err := c.BatchVerify(tests)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.True(t, results[0].Success)
	assert.True(t, results[1].Success)
}
