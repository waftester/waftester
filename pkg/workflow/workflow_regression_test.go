// Regression test for bug: command injection via external workflow commands
package workflow

import (
"testing"
)

// TestAllowlist_ExcludesScriptingLanguages verifies dangerous scripting
// interpreters are NOT in the command allowlist.
// Regression test for bug: arbitrary command execution from workflow files
func TestAllowlist_ExcludesScriptingLanguages(t *testing.T) {
denied := []string{
"python", "python3", "ruby", "perl", "php",
"node", "bash", "sh", "lua", "powershell",
}
for _, cmd := range denied {
if isAllowedExternalCommand(cmd) {
t.Errorf("SECURITY: %q should NOT be in the command allowlist", cmd)
}
}
}

// TestAllowlist_IncludesSafeUtilities verifies that safe utilities
// ARE allowed in the command allowlist.
// Regression test for bug: overly restrictive allowlist blocking safe commands
func TestAllowlist_IncludesSafeUtilities(t *testing.T) {
allowed := []string{
"echo", "grep", "jq", "curl", "wget",
"sort", "uniq", "nuclei",
}
for _, cmd := range allowed {
if !isAllowedExternalCommand(cmd) {
t.Errorf("%q should be in the command allowlist", cmd)
}
}
}

// TestAllowlist_HandlesPathPrefixes verifies that full paths like
// /usr/bin/echo are resolved to their base name via filepath.Base.
// Regression test for bug: full paths bypassing allowlist check
func TestAllowlist_HandlesPathPrefixes(t *testing.T) {
tests := []struct {
path    string
allowed bool
}{
{"/usr/bin/echo", true},
{"/usr/local/bin/jq", true},
{"/usr/bin/curl", true},
{"/usr/bin/python3", false},
{"/usr/bin/ruby", false},

{"/usr/bin/node", false},
}

for _, tt := range tests {
t.Run(tt.path, func(t *testing.T) {
got := isAllowedExternalCommand(tt.path)
if got != tt.allowed {
t.Errorf("isAllowedExternalCommand(%q) = %v, want %v", tt.path, got, tt.allowed)
}
})
}
}

// TestValidateFilePath_PreventTraversal verifies that path traversal
// attempts are blocked by validateFilePath.
// Regression test for bug: path traversal in workflow file inputs
func TestValidateFilePath_PreventTraversal(t *testing.T) {
engine := NewEngine()
engine.WorkDir = "/opt/waftester/workdir"

badPaths := []struct {
name string
path string
}{
{"parent_traversal", "../../etc/passwd"},
{"deep_traversal", "../../../etc/shadow"},
{"windows_traversal", "..\\..\\windows\\system32\\config\\sam"},
{"mid_traversal", "subdir/../../etc/passwd"},
}

for _, tt := range badPaths {
t.Run(tt.name, func(t *testing.T) {
err := engine.validateFilePath(tt.path)
if err == nil {
t.Errorf("SECURITY: validateFilePath(%q) should have returned error for traversal", tt.path)
}
})
}
}

// TestValidateFilePath_AllowsValidPaths verifies that valid relative paths
// within the working directory are permitted.
func TestValidateFilePath_AllowsValidPaths(t *testing.T) {
engine := NewEngine()

validPaths := []string{
"results.json",
"output/report.html",
"data/payloads/sqli.json",
}

for _, p := range validPaths {
t.Run(p, func(t *testing.T) {
err := engine.validateFilePath(p)
if err != nil {
t.Errorf("validateFilePath(%q) returned unexpected error: %v", p, err)
}
})
}
}

// TestIsWafTesterCommand_Regression verifies internal command detection.
// Regression test for bug: missing command in internal command list
func TestIsWafTesterCommand_Regression(t *testing.T) {
tests := []struct {
cmd  string
want bool
}{
{"scan", true},
{"discover", true},
{"probe", true},
{"fuzz", true},
{"report", true},
{"wafdetect", true},
{"echo", false},
{"python", false},
{"rm", false},
}

for _, tt := range tests {
t.Run(tt.cmd, func(t *testing.T) {
if got := isWafTesterCommand(tt.cmd); got != tt.want {
t.Errorf("isWafTesterCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
}
})
}
}
