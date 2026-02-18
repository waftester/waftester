// Package workflow provides workflow automation for chaining commands
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/retry"
	"gopkg.in/yaml.v3"
)

// Workflow represents an automated workflow
type Workflow struct {
	// Name of the workflow
	Name string `yaml:"name" json:"name"`

	// Description of the workflow
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Author
	Author string `yaml:"author,omitempty" json:"author,omitempty"`

	// Version
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// Tags for categorization
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Variables available to all steps
	Variables map[string]string `yaml:"variables,omitempty" json:"variables,omitempty"`

	// Input definitions
	Inputs []Input `yaml:"inputs,omitempty" json:"inputs,omitempty"`

	// Steps to execute
	Steps []Step `yaml:"steps" json:"steps"`

	// Outputs to produce
	Outputs []Output `yaml:"outputs,omitempty" json:"outputs,omitempty"`

	// OnError defines error handling behavior
	OnError string `yaml:"on-error,omitempty" json:"on_error,omitempty"` // stop, continue, retry

	// Timeout for the entire workflow
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// Input defines a workflow input
type Input struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Type        string `yaml:"type,omitempty" json:"type,omitempty"` // string, file, list
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Default     string `yaml:"default,omitempty" json:"default,omitempty"`
}

// Output defines a workflow output
type Output struct {
	Name   string `yaml:"name" json:"name"`
	Source string `yaml:"source" json:"source"` // step.output, file path, etc.
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
}

// Step represents a workflow step
type Step struct {
	// ID for referencing this step
	ID string `yaml:"id,omitempty" json:"id,omitempty"`

	// Name of the step
	Name string `yaml:"name" json:"name"`

	// Command to run (waf-tester command or external)
	Command string `yaml:"command" json:"command"`

	// Args for the command
	Args []string `yaml:"args,omitempty" json:"args,omitempty"`

	// Input from previous steps or files
	Input string `yaml:"input,omitempty" json:"input,omitempty"`

	// Output file path
	Output string `yaml:"output,omitempty" json:"output,omitempty"`

	// WorkDir working directory
	WorkDir string `yaml:"workdir,omitempty" json:"workdir,omitempty"`

	// Condition for running this step
	Condition string `yaml:"if,omitempty" json:"if,omitempty"`

	// Environment variables
	Env map[string]string `yaml:"env,omitempty" json:"env,omitempty"`

	// Timeout for this step
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retries on failure
	Retries int `yaml:"retries,omitempty" json:"retries,omitempty"`

	// ContinueOnError whether to continue if this step fails
	ContinueOnError bool `yaml:"continue-on-error,omitempty" json:"continue_on_error,omitempty"`

	// Parallel run multiple instances
	Parallel *ParallelConfig `yaml:"parallel,omitempty" json:"parallel,omitempty"`
}

// ParallelConfig for parallel execution
type ParallelConfig struct {
	// Matrix of values to iterate
	Matrix map[string][]string `yaml:"matrix,omitempty" json:"matrix,omitempty"`

	// MaxConcurrency limits parallel instances
	MaxConcurrency int `yaml:"max-concurrency,omitempty" json:"max_concurrency,omitempty"`
}

// StepResult represents the result of a step execution
type StepResult struct {
	StepID     string        `json:"step_id"`
	StepName   string        `json:"step_name"`
	Status     string        `json:"status"` // success, failed, skipped
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Duration   time.Duration `json:"duration"`
	Output     string        `json:"output,omitempty"`
	OutputFile string        `json:"output_file,omitempty"`
	Error      string        `json:"error,omitempty"`
	ExitCode   int           `json:"exit_code"`
}

// WorkflowResult represents the result of a workflow execution
type WorkflowResult struct {
	WorkflowName string            `json:"workflow_name"`
	Status       string            `json:"status"` // success, failed, partial
	StartTime    time.Time         `json:"start_time"`
	EndTime      time.Time         `json:"end_time"`
	Duration     time.Duration     `json:"duration"`
	Steps        []StepResult      `json:"steps"`
	Outputs      map[string]string `json:"outputs,omitempty"`
	Error        string            `json:"error,omitempty"`
}

// Engine executes workflows
type Engine struct {
	// WafTesterPath path to waf-tester binary
	WafTesterPath string

	// Variables for template expansion
	Variables map[string]string

	// WorkDir working directory
	WorkDir string

	// Verbose output
	Verbose bool

	// DryRun mode
	DryRun bool

	// ExtraAllowedCommands extends the built-in command allowlist.
	// Use for testing or when a controlled environment needs shell access.
	ExtraAllowedCommands map[string]bool

	// StepResults from previous steps
	stepResults map[string]*StepResult
	stepMu      sync.RWMutex
}

// NewEngine creates a new workflow engine
func NewEngine() *Engine {
	return &Engine{
		WafTesterPath: "waf-tester",
		Variables:     make(map[string]string),
		stepResults:   make(map[string]*StepResult),
	}
}

// LoadWorkflow loads a workflow from a file
func LoadWorkflow(path string) (*Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read workflow: %w", err)
	}

	return ParseWorkflow(data)
}

// ParseWorkflow parses a workflow from YAML data
func ParseWorkflow(data []byte) (*Workflow, error) {
	var wf Workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("failed to parse workflow: %w", err)
	}

	// Validate
	if wf.Name == "" {
		return nil, fmt.Errorf("workflow missing required field: name")
	}
	if len(wf.Steps) == 0 {
		return nil, fmt.Errorf("workflow has no steps")
	}

	// Generate IDs for steps without them
	for i := range wf.Steps {
		if wf.Steps[i].ID == "" {
			wf.Steps[i].ID = fmt.Sprintf("step-%d", i+1)
		}
	}

	return &wf, nil
}

// Execute runs a workflow
func (e *Engine) Execute(ctx context.Context, wf *Workflow, inputs map[string]string) (*WorkflowResult, error) {
	result := &WorkflowResult{
		WorkflowName: wf.Name,
		StartTime:    time.Now(),
		Steps:        make([]StepResult, 0, len(wf.Steps)),
		Outputs:      make(map[string]string),
	}

	// Merge variables
	vars := make(map[string]string)
	for k, v := range e.Variables {
		vars[k] = v
	}
	for k, v := range wf.Variables {
		vars[k] = v
	}
	for k, v := range inputs {
		vars[k] = v
	}

	// Check required inputs
	for _, input := range wf.Inputs {
		if _, ok := vars[input.Name]; !ok {
			if input.Required {
				return nil, fmt.Errorf("missing required input: %s", input.Name)
			}
			if input.Default != "" {
				vars[input.Name] = input.Default
			}
		}
	}

	// Parse workflow timeout
	var timeout time.Duration
	if wf.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(wf.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid workflow timeout: %w", err)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute steps
	var lastError error
	for i := range wf.Steps {
		step := &wf.Steps[i]

		// Check condition
		if step.Condition != "" {
			if !e.evaluateCondition(step.Condition, vars) {
				stepResult := StepResult{
					StepID:   step.ID,
					StepName: step.Name,
					Status:   "skipped",
				}
				result.Steps = append(result.Steps, stepResult)
				continue
			}
		}

		// Check parallel execution
		if step.Parallel != nil && len(step.Parallel.Matrix) > 0 {
			parallelResults := e.executeParallel(ctx, step, vars)
			result.Steps = append(result.Steps, parallelResults...)
			continue
		}

		// Execute step
		stepResult := e.executeStep(ctx, step, vars)
		result.Steps = append(result.Steps, stepResult)

		// Store result for later reference
		e.stepMu.Lock()
		e.stepResults[step.ID] = &stepResult
		e.stepMu.Unlock()

		// Handle errors
		if stepResult.Status == "failed" {
			lastError = fmt.Errorf("step %s failed: %s", step.Name, stepResult.Error)

			if !step.ContinueOnError {
				if wf.OnError == "continue" {
					continue
				}
				break
			}
		}

		// Update variables with step output
		if stepResult.Output != "" {
			vars[step.ID+".output"] = stepResult.Output
		}
		if stepResult.OutputFile != "" {
			vars[step.ID+".output_file"] = stepResult.OutputFile
		}
	}

	// Collect outputs
	for _, output := range wf.Outputs {
		if val, ok := vars[output.Source]; ok {
			result.Outputs[output.Name] = val
		}
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Determine status
	hasFailures := false
	hasSuccesses := false
	for _, s := range result.Steps {
		if s.Status == "failed" {
			hasFailures = true
		} else if s.Status == "success" {
			hasSuccesses = true
		}
	}

	if hasFailures && hasSuccesses {
		result.Status = "partial"
	} else if hasFailures {
		result.Status = "failed"
		result.Error = lastError.Error()
	} else {
		result.Status = "success"
	}

	return result, nil
}

func (e *Engine) executeStep(ctx context.Context, step *Step, vars map[string]string) StepResult {
	result := StepResult{
		StepID:    step.ID,
		StepName:  step.Name,
		StartTime: time.Now(),
	}

	// Parse timeout
	var timeout time.Duration
	if step.Timeout != "" {
		var err error
		timeout, err = time.ParseDuration(step.Timeout)
		if err == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
	}

	// Expand variables in command and args
	command := e.expand(step.Command, vars)
	args := make([]string, len(step.Args))
	for i, arg := range step.Args {
		args[i] = e.expand(arg, vars)
	}

	// Handle input from previous step
	var inputData string
	if step.Input != "" {
		expanded := e.expand(step.Input, vars)
		if strings.HasPrefix(expanded, "file:") {
			filePath := strings.TrimPrefix(expanded, "file:")
			// Security: Validate path to prevent path traversal attacks
			if err := e.validateFilePath(filePath); err != nil {
				result.Status = "failed"
				result.Error = fmt.Sprintf("security: %v", err)
				result.EndTime = time.Now()
				result.Duration = result.EndTime.Sub(result.StartTime)
				return result
			}
			data, err := os.ReadFile(filePath)
			if err == nil {
				inputData = string(data)
			}
		} else {
			inputData = expanded
		}
	}

	// Expand output path
	outputPath := ""
	if step.Output != "" {
		outputPath = e.expand(step.Output, vars)
	}

	// Dry run mode
	if e.DryRun {
		result.Status = "success"
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		return result
	}

	// Build command factory — exec.Cmd cannot be reused after CombinedOutput,
	// so we recreate it on each retry attempt.
	buildCmd := func() *exec.Cmd {
		var c *exec.Cmd
		if isWafTesterCommand(command) {
			cmdArgs := append([]string{command}, args...)
			c = exec.CommandContext(ctx, e.WafTesterPath, cmdArgs...)
		} else {
			c = exec.CommandContext(ctx, command, args...)
		}

		// Set working directory
		if step.WorkDir != "" {
			c.Dir = e.expand(step.WorkDir, vars)
		} else if e.WorkDir != "" {
			c.Dir = e.WorkDir
		}

		// Set environment
		c.Env = os.Environ()
		for k, v := range step.Env {
			c.Env = append(c.Env, fmt.Sprintf("%s=%s", k, e.expand(v, vars)))
		}

		// Handle input
		if inputData != "" {
			c.Stdin = strings.NewReader(inputData)
		}
		return c
	}

	// Validate external command allowlist before building
	if !isWafTesterCommand(command) {
		if !e.isAllowedExternalCommand(command) {
			result.Status = "failed"
			result.Error = fmt.Sprintf("security: command %q is not in the allowed command list", command)
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)
			return result
		}
	}

	// Execute with retries
	var output []byte
	var err error
	maxAttempts := step.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	err = retry.Do(ctx, retry.Config{
		MaxAttempts: maxAttempts,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    retry.Linear,
	}, func() error {
		cmd := buildCmd()
		var cmdErr error
		output, cmdErr = cmd.CombinedOutput()
		return cmdErr
	})

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Output = string(output)

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
	} else {
		result.Status = "success"

		// Write output to file if specified
		if outputPath != "" {
			if verr := e.validateFilePath(outputPath); verr != nil {
				result.Status = "failed"
				result.Error = fmt.Sprintf("security: output path: %v", verr)
			} else if err := os.WriteFile(outputPath, output, 0644); err == nil {
				result.OutputFile = outputPath
			}
		}
	}

	return result
}

func (e *Engine) executeParallel(ctx context.Context, step *Step, vars map[string]string) []StepResult {
	// Generate combinations from matrix
	combinations := generateMatrixCombinations(step.Parallel.Matrix)

	maxConcurrency := step.Parallel.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = len(combinations)
	}

	results := make([]StepResult, len(combinations))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, combo := range combinations {
		wg.Add(1)
		go func(idx int, comboVars map[string]string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Merge combo vars with parent vars
			stepVars := make(map[string]string)
			for k, v := range vars {
				stepVars[k] = v
			}
			for k, v := range comboVars {
				stepVars[k] = v
			}

			// Create a copy of the step with updated ID
			stepCopy := *step
			stepCopy.ID = fmt.Sprintf("%s-%d", step.ID, idx)
			stepCopy.Parallel = nil

			results[idx] = e.executeStep(ctx, &stepCopy, stepVars)
		}(i, combo)
	}

	wg.Wait()
	return results
}

func generateMatrixCombinations(matrix map[string][]string) []map[string]string {
	if len(matrix) == 0 {
		return nil
	}

	// Get keys in consistent order
	keys := make([]string, 0, len(matrix))
	for k := range matrix {
		keys = append(keys, k)
	}

	// Generate all combinations
	var result []map[string]string
	var generate func(int, map[string]string)
	generate = func(keyIdx int, current map[string]string) {
		if keyIdx >= len(keys) {
			combo := make(map[string]string)
			for k, v := range current {
				combo[k] = v
			}
			result = append(result, combo)
			return
		}

		key := keys[keyIdx]
		for _, val := range matrix[key] {
			current[key] = val
			generate(keyIdx+1, current)
		}
	}

	generate(0, make(map[string]string))
	return result
}

// expand performs simple string variable substitution on input.
// Uses plain string replacement instead of text/template to avoid
// template injection from untrusted workflow YAML files.
func (e *Engine) expand(input string, vars map[string]string) string {
	result := input
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{"+k+"}}", v)
		result = strings.ReplaceAll(result, "{{."+k+"}}", v)
	}
	return result
}

func (e *Engine) evaluateCondition(condition string, vars map[string]string) bool {
	// Simple condition evaluation
	condition = strings.TrimSpace(condition)

	// Check for step success/failure conditions
	if strings.HasPrefix(condition, "steps.") {
		parts := strings.Split(condition, ".")
		if len(parts) >= 3 {
			stepID := parts[1]
			property := parts[2]

			e.stepMu.RLock()
			stepResult, ok := e.stepResults[stepID]
			e.stepMu.RUnlock()

			if !ok {
				return false
			}

			switch property {
			case "success":
				return stepResult.Status == "success"
			case "failure", "failed":
				return stepResult.Status == "failed"
			case "skipped":
				return stepResult.Status == "skipped"
			}
		}
	}

	// Check for variable existence
	if strings.HasPrefix(condition, "has(") {
		varName := strings.TrimPrefix(condition, "has(")
		varName = strings.TrimSuffix(varName, ")")
		_, ok := vars[varName]
		return ok
	}

	// Check for always/never
	if condition == "always" {
		return true
	}
	if condition == "never" {
		return false
	}

	// Check for variable equality
	if strings.Contains(condition, "==") {
		parts := strings.SplitN(condition, "==", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSpace(parts[1])
		right = strings.Trim(right, "\"'")

		if val, ok := vars[left]; ok {
			return val == right
		}
	}

	return true
}

func isWafTesterCommand(cmd string) bool {
	wafCommands := []string{
		"discover", "scan", "probe", "fuzz", "run",
		"learn", "report", "wafdetect", "waffprint",
	}
	for _, c := range wafCommands {
		if cmd == c {
			return true
		}
	}
	return false
}

// isAllowedExternalCommand validates external commands against a security allowlist.
// This prevents arbitrary command execution from user-controlled workflow files.
//
// Security: awk/sed/xargs are excluded because they support shell execution
// (awk system(), sed e, xargs sh). curl/wget are excluded because they enable
// data exfiltration. Only read-only, non-executing utilities are allowed.
func (e *Engine) isAllowedExternalCommand(cmd string) bool {
	// Allowlist of safe external commands that can be executed from workflows.
	// Each command here must be read-only and unable to spawn subprocesses.
	allowedCommands := map[string]bool{
		// Read-only text utilities (no exec capability)
		"echo":   true,
		"cat":    true,
		"grep":   true,
		"jq":     true,
		"head":   true,
		"tail":   true,
		"sort":   true,
		"uniq":   true,
		"wc":     true,
		"tr":     true,
		"cut":    true,
		"base64": true,
		"sleep":  true,
		// Nuclei integration
		"nuclei": true,
	}

	// Extract base command name (handle paths like /usr/bin/echo)
	baseName := filepath.Base(cmd)
	if allowedCommands[baseName] {
		return true
	}
	return e.ExtraAllowedCommands[baseName]
}

// validateFilePath checks for path traversal attacks.
// It ensures the file path doesn't escape the workflow working directory.
func (e *Engine) validateFilePath(path string) error {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(path)

	// Check for absolute paths that try to escape
	if filepath.IsAbs(cleanPath) {
		workDir := e.WorkDir
		if workDir == "" {
			var wdErr error
			workDir, wdErr = os.Getwd()
			if wdErr != nil {
				return fmt.Errorf("cannot determine working directory: %w", wdErr)
			}
		}
		absWorkDir, err := filepath.Abs(workDir)
		if err != nil {
			return fmt.Errorf("invalid working directory: %w", err)
		}
		// Use filepath.Rel instead of HasPrefix to avoid prefix-matching
		// siblings like /tmp/workdir-evil when workDir is /tmp/workdir.
		rel, err := filepath.Rel(absWorkDir, cleanPath)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("path %q escapes working directory", path)
		}
		return nil
	}

	// For relative paths, check for traversal attempts
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, string(filepath.Separator)+"..") {
		return fmt.Errorf("path traversal detected in %q", path)
	}

	return nil
}

// SaveWorkflow saves a workflow to a file
func SaveWorkflow(wf *Workflow, path string) error {
	data, err := yaml.Marshal(wf)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ToJSON converts workflow result to JSON
func (r *WorkflowResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// BuiltinWorkflows returns pre-defined workflow templates
func BuiltinWorkflows() map[string]*Workflow {
	return map[string]*Workflow{
		"full-scan": {
			Name:        "full-scan",
			Description: "Complete security scan: discover → learn → scan → report",
			Version:     "1.0.0",
			Tags:        []string{"security", "complete"},
			Inputs: []Input{
				{Name: "target", Description: "Target URL", Required: true},
				{Name: "output_dir", Description: "Output directory", Default: "./results"},
			},
			Steps: []Step{
				{
					ID:      "discover",
					Name:    "Discover endpoints",
					Command: "discover",
					Args:    []string{"-u", "{{.target}}", "-o", "{{.output_dir}}/endpoints.json"},
				},
				{
					ID:      "learn",
					Name:    "Learn WAF behavior",
					Command: "learn",
					Args:    []string{"-u", "{{.target}}", "-o", "{{.output_dir}}/waf-profile.json"},
				},
				{
					ID:        "scan",
					Name:      "Run security scan",
					Command:   "run",
					Args:      []string{"-u", "{{.target}}", "-o", "{{.output_dir}}/scan-results.json"},
					Condition: "steps.discover.success",
				},
				{
					ID:      "report",
					Name:    "Generate report",
					Command: "report",
					Args:    []string{"-i", "{{.output_dir}}/scan-results.json", "-o", "{{.output_dir}}/report.html", "-f", "html"},
				},
			},
		},
		"quick-probe": {
			Name:        "quick-probe",
			Description: "Quick target enumeration and probing",
			Version:     "1.0.0",
			Tags:        []string{"probe", "quick"},
			Inputs: []Input{
				{Name: "targets", Description: "File with target URLs", Required: true},
			},
			Steps: []Step{
				{
					ID:      "probe",
					Name:    "Probe targets",
					Command: "probe",
					Args:    []string{"-l", "{{.targets}}", "-jsonl", "-o", "alive.json"},
				},
			},
		},
		"waf-detection": {
			Name:        "waf-detection",
			Description: "Detect and fingerprint WAF",
			Version:     "1.0.0",
			Tags:        []string{"waf", "detection"},
			Inputs: []Input{
				{Name: "target", Description: "Target URL", Required: true},
			},
			Steps: []Step{
				{
					ID:      "detect",
					Name:    "Detect WAF presence",
					Command: "wafdetect",
					Args:    []string{"-u", "{{.target}}"},
				},
				{
					ID:      "fingerprint",
					Name:    "Fingerprint WAF",
					Command: "waffprint",
					Args:    []string{"-u", "{{.target}}"},
				},
			},
		},
	}
}
