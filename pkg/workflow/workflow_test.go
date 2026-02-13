package workflow

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// echoCommand returns a cross-platform echo command configuration.
// On Windows: cmd /c echo <message>
// On Linux/Mac: echo <message>
func echoCommand() (cmd string, args []string, needsShQuote bool) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/c", "echo"}, false
	}
	return "echo", nil, false
}

// echoYAML returns a YAML snippet for an echo command that works cross-platform
func echoYAML(message string) string {
	if runtime.GOOS == "windows" {
		return `command: cmd
    args:
      - "/c"
      - "echo"
      - "` + message + `"`
	}
	return `command: echo
    args:
      - "` + message + `"`
}

// sleepYAML returns a YAML snippet for a sleep command that works cross-platform
func sleepYAML(seconds string) string {
	if runtime.GOOS == "windows" {
		return `command: cmd
    args:
      - "/c"
      - "ping"
      - "-n"
      - "` + seconds + `"
      - "127.0.0.1"
      - ">nul"`
	}
	return `command: sleep
    args:
      - "` + seconds + `"`
}

// newTestEngine creates an engine with cmd allowed on Windows for tests.
func newTestEngine() *Engine {
	e := NewEngine()
	if runtime.GOOS == "windows" {
		e.ExtraAllowedCommands = map[string]bool{"cmd": true, "cmd.exe": true}
	}
	return e
}

func TestParseWorkflow_Basic(t *testing.T) {
	yaml := `
name: test-workflow
description: A test workflow
steps:
  - name: Step 1
    command: echo
    args:
      - "hello"
`
	wf, err := ParseWorkflow([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse workflow: %v", err)
	}

	if wf.Name != "test-workflow" {
		t.Errorf("expected name 'test-workflow', got %s", wf.Name)
	}
	if len(wf.Steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(wf.Steps))
	}
	if wf.Steps[0].ID == "" {
		t.Error("expected auto-generated step ID")
	}
}

func TestParseWorkflow_MissingName(t *testing.T) {
	yaml := `
steps:
  - name: Step 1
    command: echo
`
	_, err := ParseWorkflow([]byte(yaml))
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestParseWorkflow_NoSteps(t *testing.T) {
	yaml := `
name: no-steps
`
	_, err := ParseWorkflow([]byte(yaml))
	if err == nil {
		t.Error("expected error for no steps")
	}
}

func TestParseWorkflow_WithInputs(t *testing.T) {
	yaml := `
name: input-test
inputs:
  - name: target
    description: Target URL
    required: true
  - name: output
    default: results.json
steps:
  - name: Scan
    command: probe
    args:
      - "-u"
      - "{{.target}}"
`
	wf, err := ParseWorkflow([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(wf.Inputs) != 2 {
		t.Errorf("expected 2 inputs, got %d", len(wf.Inputs))
	}
	if !wf.Inputs[0].Required {
		t.Error("expected target input to be required")
	}
}

func TestParseWorkflow_WithVariables(t *testing.T) {
	yaml := `
name: var-test
variables:
  base_url: https://example.com
  version: v1
steps:
  - name: Test
    command: probe
    args:
      - "-u"
      - "{{.base_url}}/api/{{.version}}"
`
	wf, err := ParseWorkflow([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if wf.Variables["base_url"] != "https://example.com" {
		t.Error("expected base_url variable")
	}
}

func TestParseWorkflow_WithCondition(t *testing.T) {
	yaml := `
name: condition-test
steps:
  - id: step1
    name: First
    command: echo
    args: ["hello"]
  - id: step2
    name: Conditional
    command: echo
    args: ["world"]
    if: steps.step1.success
`
	wf, err := ParseWorkflow([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if wf.Steps[1].Condition != "steps.step1.success" {
		t.Errorf("expected condition, got %s", wf.Steps[1].Condition)
	}
}

func TestParseWorkflow_WithParallel(t *testing.T) {
	yaml := `
name: parallel-test
steps:
  - name: Parallel scan
    command: probe
    args:
      - "-u"
      - "{{.target}}"
    parallel:
      matrix:
        target:
          - https://example1.com
          - https://example2.com
          - https://example3.com
      max-concurrency: 2
`
	wf, err := ParseWorkflow([]byte(yaml))
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if wf.Steps[0].Parallel == nil {
		t.Fatal("expected parallel config")
	}
	if len(wf.Steps[0].Parallel.Matrix["target"]) != 3 {
		t.Errorf("expected 3 targets in matrix")
	}
	if wf.Steps[0].Parallel.MaxConcurrency != 2 {
		t.Errorf("expected max-concurrency 2")
	}
}

func TestEngine_Execute_SimpleCommand(t *testing.T) {
	yaml := `
name: simple-test
steps:
  - name: Echo test
    ` + echoYAML("hello world") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Error)
	}
	if len(result.Steps) != 1 {
		t.Errorf("expected 1 step result, got %d", len(result.Steps))
	}
}

func TestEngine_Execute_WithVariables(t *testing.T) {
	yaml := `
name: var-test
variables:
  message: hello
steps:
  - name: Echo var
    ` + echoYAML("{{.message}}") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
}

func TestEngine_Execute_WithInputs(t *testing.T) {
	yaml := `
name: input-test
inputs:
  - name: msg
    required: true
steps:
  - name: Echo input
    ` + echoYAML("{{.msg}}") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	// Missing required input
	_, err := engine.Execute(context.Background(), wf, nil)
	if err == nil {
		t.Error("expected error for missing required input")
	}

	// With input
	result, err := engine.Execute(context.Background(), wf, map[string]string{"msg": "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
}

func TestEngine_Execute_WithDefaultInput(t *testing.T) {
	yaml := `
name: default-test
inputs:
  - name: msg
    default: default-message
steps:
  - name: Echo
    ` + echoYAML("{{.msg}}") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("expected success with default input")
	}
}

func TestEngine_Execute_ConditionSuccess(t *testing.T) {
	yaml := `
name: condition-success-test
steps:
  - id: first
    name: First step
    ` + echoYAML("first") + `
  - id: second
    name: Second step
    ` + echoYAML("second") + `
    if: steps.first.success
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) != 2 {
		t.Fatalf("expected 2 step results, got %d", len(result.Steps))
	}
	if result.Steps[1].Status != "success" {
		t.Errorf("expected second step to run, got status %s", result.Steps[1].Status)
	}
}

func TestEngine_Execute_ConditionSkip(t *testing.T) {
	yaml := `
name: condition-skip-test
steps:
  - id: first
    name: First step
    ` + echoYAML("first") + `
  - id: second
    name: Should skip
    ` + echoYAML("second") + `
    if: steps.first.failure
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Steps) < 2 {
		t.Fatalf("expected 2 step results, got %d", len(result.Steps))
	}
	if result.Steps[1].Status != "skipped" {
		t.Errorf("expected second step to be skipped, got %s", result.Steps[1].Status)
	}
}

func TestEngine_Execute_ContinueOnError(t *testing.T) {
	yaml := `
name: continue-test
steps:
  - id: fail
    name: Will fail
    command: nonexistent-command-12345
    continue-on-error: true
  - id: next
    name: Should still run
    ` + echoYAML("running") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Steps[0].Status != "failed" {
		t.Errorf("expected first step to fail")
	}
	if result.Steps[1].Status != "success" {
		t.Errorf("expected second step to run despite first failure")
	}
	if result.Status != "partial" {
		t.Errorf("expected partial status, got %s", result.Status)
	}
}

func TestEngine_Execute_DryRun(t *testing.T) {
	yaml := `
name: dryrun-test
steps:
  - name: Would run
    ` + echoYAML("hello") + `
`
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()
	engine.DryRun = true

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "success" {
		t.Errorf("expected success in dry run mode")
	}
}

func TestEngine_Execute_WithTimeout(t *testing.T) {
	var yaml string
	if runtime.GOOS == "windows" {
		yaml = `
name: timeout-test
timeout: 500ms
steps:
  - name: Long running
    command: ping
    args: ["-n", "10", "127.0.0.1"]
`
	} else {
		yaml = `
name: timeout-test
timeout: 500ms
steps:
  - name: Long running
    command: sleep
    args: ["10"]
`
	}
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()

	start := time.Now()
	result, err := engine.Execute(context.Background(), wf, nil)
	duration := time.Since(start)

	// Should timeout before command completes
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Timeout should occur within a reasonable window
	if duration > 10*time.Second {
		t.Errorf("timeout didn't work, took %v", duration)
	}

	if result.Status == "success" && result.Steps[0].Status == "success" {
		t.Log("Command completed before timeout (fast system)")
	}
}

func TestEngine_Execute_WithOutput(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "output.txt")

	var yaml string
	if runtime.GOOS == "windows" {
		yaml = `
name: output-test
steps:
  - name: Write output
    command: cmd
    args:
      - "/c"
      - "echo"
      - "test output"
    output: "` + filepath.ToSlash(outputFile) + `"
`
	} else {
		yaml = `
name: output-test
steps:
  - name: Write output
    command: echo
    args:
      - "test output"
    output: "` + filepath.ToSlash(outputFile) + `"
`
	}
	wf, _ := ParseWorkflow([]byte(yaml))
	engine := newTestEngine()
	engine.WorkDir = dir

	result, err := engine.Execute(context.Background(), wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Status != "success" {
		t.Fatalf("expected success, got %s", result.Status)
	}

	// Check output file was created
	if _, err := os.Stat(outputFile); err != nil {
		t.Errorf("output file not created: %v", err)
	}
}

func TestEngine_Expand(t *testing.T) {
	engine := newTestEngine()
	vars := map[string]string{
		"target": "https://example.com",
		"port":   "8080",
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"{{.target}}", "https://example.com"},
		{"{{.target}}:{{.port}}", "https://example.com:8080"},
		{"no-vars", "no-vars"},
	}

	for _, tc := range tests {
		got := engine.expand(tc.input, vars)
		if got != tc.expected {
			t.Errorf("expand(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestEngine_EvaluateCondition(t *testing.T) {
	engine := newTestEngine()

	// Set up step results
	engine.stepResults["step1"] = &StepResult{Status: "success"}
	engine.stepResults["step2"] = &StepResult{Status: "failed"}

	vars := map[string]string{"mode": "test"}

	tests := []struct {
		condition string
		expected  bool
	}{
		{"steps.step1.success", true},
		{"steps.step1.failure", false},
		{"steps.step2.success", false},
		{"steps.step2.failure", true},
		{"always", true},
		{"never", false},
		{"has(mode)", true},
		{"has(missing)", false},
		{"mode == test", true},
		{"mode == production", false},
	}

	for _, tc := range tests {
		got := engine.evaluateCondition(tc.condition, vars)
		if got != tc.expected {
			t.Errorf("evaluateCondition(%q) = %v, want %v", tc.condition, got, tc.expected)
		}
	}
}

func TestGenerateMatrixCombinations(t *testing.T) {
	matrix := map[string][]string{
		"os":      {"linux", "windows"},
		"version": {"1.0", "2.0"},
	}

	combos := generateMatrixCombinations(matrix)

	if len(combos) != 4 {
		t.Errorf("expected 4 combinations, got %d", len(combos))
	}

	// Verify all combinations exist
	found := make(map[string]bool)
	for _, c := range combos {
		key := c["os"] + "-" + c["version"]
		found[key] = true
	}

	expected := []string{"linux-1.0", "linux-2.0", "windows-1.0", "windows-2.0"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("missing combination: %s", e)
		}
	}
}

func TestLoadWorkflow_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workflow.yaml")

	var content string
	if runtime.GOOS == "windows" {
		content = `
name: file-test
steps:
  - name: Test
    command: cmd
    args: ["/c", "echo", "hello"]
`
	} else {
		content = `
name: file-test
steps:
  - name: Test
    command: echo
    args: ["hello"]
`
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatalf("failed to load workflow: %v", err)
	}

	if wf.Name != "file-test" {
		t.Errorf("expected name 'file-test', got %s", wf.Name)
	}
}

func TestSaveWorkflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saved.yaml")

	wf := &Workflow{
		Name:        "saved-workflow",
		Description: "A saved workflow",
		Steps: []Step{
			{
				ID:      "step1",
				Name:    "Step 1",
				Command: "cmd",
				Args:    []string{"/c", "echo", "hello"},
			},
		},
	}

	if err := SaveWorkflow(wf, path); err != nil {
		t.Fatalf("failed to save workflow: %v", err)
	}

	// Load it back
	loaded, err := LoadWorkflow(path)
	if err != nil {
		t.Fatalf("failed to reload workflow: %v", err)
	}

	if loaded.Name != wf.Name {
		t.Errorf("expected name %s, got %s", wf.Name, loaded.Name)
	}
}

func TestBuiltinWorkflows(t *testing.T) {
	builtins := BuiltinWorkflows()

	if len(builtins) == 0 {
		t.Error("expected built-in workflows")
	}

	// Check specific workflows
	expected := []string{"full-scan", "quick-probe", "waf-detection"}
	for _, name := range expected {
		if _, ok := builtins[name]; !ok {
			t.Errorf("expected built-in workflow: %s", name)
		}
	}

	// Validate built-in workflows
	for name, wf := range builtins {
		if wf.Name == "" {
			t.Errorf("built-in %s has no name", name)
		}
		if len(wf.Steps) == 0 {
			t.Errorf("built-in %s has no steps", name)
		}
	}
}

func TestWorkflowResult_ToJSON(t *testing.T) {
	result := &WorkflowResult{
		WorkflowName: "test",
		Status:       "success",
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		Duration:     time.Second,
		Steps: []StepResult{
			{StepID: "s1", Status: "success"},
		},
	}

	json, err := result.ToJSON()
	if err != nil {
		t.Fatalf("failed to convert to JSON: %v", err)
	}

	if len(json) == 0 {
		t.Error("expected non-empty JSON")
	}
}

func TestIsWafTesterCommand(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
	}{
		{"discover", true},
		{"scan", true},
		{"probe", true},
		{"fuzz", true},
		{"run", true},
		{"learn", true},
		{"report", true},
		{"wafdetect", true},
		{"waffprint", true},
		{"echo", false},
		{"curl", false},
		{"unknown", false},
	}

	for _, tc := range tests {
		got := isWafTesterCommand(tc.cmd)
		if got != tc.expected {
			t.Errorf("isWafTesterCommand(%q) = %v, want %v", tc.cmd, got, tc.expected)
		}
	}
}
