// Package ftw provides go-ftw compatibility for test format migration
package ftw

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
	"gopkg.in/yaml.v3"
)

// FTWTest represents a go-ftw test file format
type FTWTest struct {
	Meta  Meta    `yaml:"meta" json:"meta"`
	Tests []Stage `yaml:"tests" json:"tests"`
}

// Meta contains test metadata
type Meta struct {
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Stage represents a test stage
type Stage struct {
	TestTitle   string  `yaml:"test_title" json:"test_title"`
	Description string  `yaml:"description,omitempty" json:"description,omitempty"`
	Stages      []Input `yaml:"stages" json:"stages"`
}

// Input represents a single test input
type Input struct {
	Stage StageData `yaml:"stage" json:"stage"`
}

// StageData contains the actual test data
type StageData struct {
	Input  StageInput  `yaml:"input" json:"input"`
	Output StageOutput `yaml:"output" json:"output"`
}

// StageInput defines the HTTP request
type StageInput struct {
	DestAddr            string            `yaml:"dest_addr,omitempty" json:"dest_addr,omitempty"`
	Port                int               `yaml:"port,omitempty" json:"port,omitempty"`
	Protocol            string            `yaml:"protocol,omitempty" json:"protocol,omitempty"`
	URI                 string            `yaml:"uri,omitempty" json:"uri,omitempty"`
	Version             string            `yaml:"version,omitempty" json:"version,omitempty"`
	Method              string            `yaml:"method,omitempty" json:"method,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Data                string            `yaml:"data,omitempty" json:"data,omitempty"`
	EncodedRequest      string            `yaml:"encoded_request,omitempty" json:"encoded_request,omitempty"`
	RawRequest          string            `yaml:"raw_request,omitempty" json:"raw_request,omitempty"`
	SaveCookie          bool              `yaml:"save_cookie,omitempty" json:"save_cookie,omitempty"`
	StopMagic           bool              `yaml:"stop_magic,omitempty" json:"stop_magic,omitempty"`
	AutocompleteHeaders bool              `yaml:"autocomplete_headers,omitempty" json:"autocomplete_headers,omitempty"`
}

// StageOutput defines expected response
type StageOutput struct {
	Status           interface{} `yaml:"status,omitempty" json:"status,omitempty"`
	ResponseContains string      `yaml:"response_contains,omitempty" json:"response_contains,omitempty"`
	LogContains      string      `yaml:"log_contains,omitempty" json:"log_contains,omitempty"`
	NoLogContains    string      `yaml:"no_log_contains,omitempty" json:"no_log_contains,omitempty"`
	ExpectError      bool        `yaml:"expect_error,omitempty" json:"expect_error,omitempty"`
}

// TestCase represents our internal test format
type TestCase struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
	Method      string            `json:"method" yaml:"method"`
	Path        string            `json:"path" yaml:"path"`
	Headers     map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Body        string            `json:"body,omitempty" yaml:"body,omitempty"`
	ExpectBlock bool              `json:"expect_block" yaml:"expect_block"`
	ExpectCode  int               `json:"expect_code,omitempty" yaml:"expect_code,omitempty"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	RuleID      string            `json:"rule_id,omitempty" yaml:"rule_id,omitempty"`
}

// Converter converts between FTW and internal formats
type Converter struct {
	DefaultHost string
	DefaultPort int
}

// NewConverter creates a new converter
func NewConverter() *Converter {
	return &Converter{
		DefaultHost: "localhost",
		DefaultPort: 80,
	}
}

// WithHost sets the default host
func (c *Converter) WithHost(host string) *Converter {
	c.DefaultHost = host
	return c
}

// WithPort sets the default port
func (c *Converter) WithPort(port int) *Converter {
	c.DefaultPort = port
	return c
}

// FromFTW converts an FTW test to internal format
func (c *Converter) FromFTW(ftw *FTWTest) ([]*TestCase, error) {
	var tests []*TestCase

	if !ftw.Meta.Enabled {
		return tests, nil
	}

	for _, test := range ftw.Tests {
		for i, stage := range test.Stages {
			tc := &TestCase{
				ID:          fmt.Sprintf("%s-%d", sanitizeID(test.TestTitle), i+1),
				Name:        test.TestTitle,
				Description: test.Description,
				Enabled:     ftw.Meta.Enabled,
				Method:      stage.Stage.Input.Method,
				Path:        stage.Stage.Input.URI,
				Headers:     stage.Stage.Input.Headers,
				Body:        stage.Stage.Input.Data,
			}

			if tc.Method == "" {
				tc.Method = "GET"
			}
			if tc.Path == "" {
				tc.Path = "/"
			}

			// Determine expected behavior from output
			tc.ExpectBlock = c.determineExpectBlock(stage.Stage.Output)
			tc.ExpectCode = c.parseStatusCode(stage.Stage.Output.Status)

			// Extract rule ID from log_contains if present
			tc.RuleID = c.extractRuleID(stage.Stage.Output.LogContains)

			tests = append(tests, tc)
		}
	}

	return tests, nil
}

// ToFTW converts internal test cases to FTW format
func (c *Converter) ToFTW(tests []*TestCase, meta Meta) *FTWTest {
	ftw := &FTWTest{
		Meta:  meta,
		Tests: make([]Stage, 0),
	}

	// Group by name
	groups := make(map[string][]*TestCase)
	var order []string
	for _, tc := range tests {
		if _, exists := groups[tc.Name]; !exists {
			order = append(order, tc.Name)
		}
		groups[tc.Name] = append(groups[tc.Name], tc)
	}

	for _, name := range order {
		groupTests := groups[name]
		stage := Stage{
			TestTitle:   name,
			Description: groupTests[0].Description,
			Stages:      make([]Input, 0),
		}

		for _, tc := range groupTests {
			input := Input{
				Stage: StageData{
					Input: StageInput{
						Method:  tc.Method,
						URI:     tc.Path,
						Headers: tc.Headers,
						Data:    tc.Body,
					},
					Output: StageOutput{},
				},
			}

			if tc.ExpectBlock {
				input.Stage.Output.Status = []int{403}
				if tc.RuleID != "" {
					input.Stage.Output.LogContains = fmt.Sprintf("id \"%s\"", tc.RuleID)
				}
			} else {
				input.Stage.Output.Status = []int{200}
			}

			stage.Stages = append(stage.Stages, input)
		}

		ftw.Tests = append(ftw.Tests, stage)
	}

	return ftw
}

// determineExpectBlock determines if the test expects blocking
func (c *Converter) determineExpectBlock(output StageOutput) bool {
	// Check status codes
	codes := c.parseStatusCodes(output.Status)
	for _, code := range codes {
		if code == 403 || code == 400 || code == 500 {
			return true
		}
	}

	// Check log_contains for rule IDs
	if output.LogContains != "" {
		return true
	}

	return false
}

// parseStatusCode parses the first status code
func (c *Converter) parseStatusCode(status interface{}) int {
	codes := c.parseStatusCodes(status)
	if len(codes) > 0 {
		return codes[0]
	}
	return 0
}

// parseStatusCodes parses status codes from various formats
func (c *Converter) parseStatusCodes(status interface{}) []int {
	var codes []int

	switch v := status.(type) {
	case int:
		codes = append(codes, v)
	case float64:
		codes = append(codes, int(v))
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			codes = append(codes, i)
		}
	case []interface{}:
		for _, item := range v {
			codes = append(codes, c.parseStatusCodes(item)...)
		}
	case []int:
		codes = v
	}

	return codes
}

// extractRuleID extracts a rule ID from log_contains
func (c *Converter) extractRuleID(logContains string) string {
	if logContains == "" {
		return ""
	}

	// Match patterns like 'id "920420"' or 'id:920420'
	patterns := []string{
		`id\s*"(\d+)"`,
		`id\s*:\s*(\d+)`,
		`id=(\d+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(logContains); len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// LoadFTWFile loads an FTW test file
func LoadFTWFile(path string) (*FTWTest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var ftw FTWTest
	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(data, &ftw)
	} else {
		err = yaml.Unmarshal(data, &ftw)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	return &ftw, nil
}

// SaveFTWFile saves an FTW test file
func SaveFTWFile(ftw *FTWTest, path string) error {
	var data []byte
	var err error

	if strings.HasSuffix(path, ".json") {
		data, err = json.MarshalIndent(ftw, "", "  ")
	} else {
		data, err = yaml.Marshal(ftw)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// LoadTestCaseFile loads internal test cases from file
func LoadTestCaseFile(path string) ([]*TestCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var tests []*TestCase
	if strings.HasSuffix(path, ".json") {
		err = json.Unmarshal(data, &tests)
	} else {
		err = yaml.Unmarshal(data, &tests)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}

	return tests, nil
}

// SaveTestCaseFile saves internal test cases to file
func SaveTestCaseFile(tests []*TestCase, path string) error {
	var data []byte
	var err error

	if strings.HasSuffix(path, ".json") {
		data, err = json.MarshalIndent(tests, "", "  ")
	} else {
		data, err = yaml.Marshal(tests)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// sanitizeID creates a safe ID from a test title
func sanitizeID(title string) string {
	// Replace spaces and special characters
	re := regexcache.MustGet(`[^a-zA-Z0-9-_]`)
	id := re.ReplaceAllString(title, "-")

	// Remove consecutive hyphens
	re = regexcache.MustGet(`-+`)
	id = re.ReplaceAllString(id, "-")

	// Trim hyphens from start/end
	id = strings.Trim(id, "-")

	// Convert to lowercase
	return strings.ToLower(id)
}

// Importer imports FTW test directories
type Importer struct {
	converter *Converter
}

// NewImporter creates a new importer
func NewImporter() *Importer {
	return &Importer{
		converter: NewConverter(),
	}
}

// ImportDirectory imports all FTW test files from a directory
func (i *Importer) ImportDirectory(dir string) ([]*TestCase, error) {
	var allTests []*TestCase

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		ftw, err := LoadFTWFile(path)
		if err != nil { //nolint:nilerr // intentional: skip files that aren't FTW format
			return nil
		}

		tests, err := i.converter.FromFTW(ftw)
		if err != nil {
			return fmt.Errorf("failed to convert %s: %w", path, err)
		}

		allTests = append(allTests, tests...)
		return nil
	})

	return allTests, err
}

// Exporter exports internal test cases to FTW format
type Exporter struct {
	converter *Converter
}

// NewExporter creates a new exporter
func NewExporter() *Exporter {
	return &Exporter{
		converter: NewConverter(),
	}
}

// ExportToFile exports test cases to a single FTW file
func (e *Exporter) ExportToFile(tests []*TestCase, path string, meta Meta) error {
	ftw := e.converter.ToFTW(tests, meta)
	return SaveFTWFile(ftw, path)
}

// ExportByCategory exports test cases to separate files by category
func (e *Exporter) ExportByCategory(tests []*TestCase, dir string, author string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Group by tags (use first tag as category)
	groups := make(map[string][]*TestCase)
	for _, tc := range tests {
		cat := "uncategorized"
		if len(tc.Tags) > 0 {
			cat = tc.Tags[0]
		}
		groups[cat] = append(groups[cat], tc)
	}

	for cat, catTests := range groups {
		meta := Meta{
			Author:  author,
			Enabled: true,
			Name:    fmt.Sprintf("%s Tests", cat),
		}

		filename := filepath.Join(dir, fmt.Sprintf("%s.yaml", sanitizeID(cat)))
		if err := e.ExportToFile(catTests, filename, meta); err != nil {
			return fmt.Errorf("failed to export %s: %w", cat, err)
		}
	}

	return nil
}

// Validator validates FTW test files
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid    bool
	Errors   []string
	Warnings []string
}

// Validate validates an FTW test file
func (v *Validator) Validate(ftw *FTWTest) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// Check meta
	if ftw.Meta.Name == "" {
		result.Errors = append(result.Errors, "meta.name is required")
		result.Valid = false
	}

	// Check tests
	if len(ftw.Tests) == 0 {
		result.Warnings = append(result.Warnings, "no tests defined")
	}

	for i, test := range ftw.Tests {
		if test.TestTitle == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("test[%d].test_title is required", i))
			result.Valid = false
		}

		if len(test.Stages) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("test[%d] has no stages", i))
		}

		for j, stage := range test.Stages {
			// Validate input
			if stage.Stage.Input.Method == "" && stage.Stage.Input.RawRequest == "" && stage.Stage.Input.EncodedRequest == "" {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("test[%d].stages[%d].input has no method (defaults to GET)", i, j))
			}

			// Validate output
			if stage.Stage.Output.Status == nil &&
				stage.Stage.Output.LogContains == "" &&
				stage.Stage.Output.ResponseContains == "" &&
				!stage.Stage.Output.ExpectError {
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("test[%d].stages[%d].output has no assertions", i, j))
			}
		}
	}

	return result
}

// ValidateFile validates an FTW test file
func (v *Validator) ValidateFile(path string) (*ValidationResult, error) {
	ftw, err := LoadFTWFile(path)
	if err != nil {
		return nil, err
	}

	return v.Validate(ftw), nil
}

// Runner provides FTW-compatible test execution
type Runner struct {
	BaseURL   string
	converter *Converter
}

// NewRunner creates a new FTW runner
func NewRunner(baseURL string) *Runner {
	return &Runner{
		BaseURL:   baseURL,
		converter: NewConverter(),
	}
}

// RunResult represents a test run result
type RunResult struct {
	Test       *TestCase
	Passed     bool
	StatusCode int
	Blocked    bool
	Message    string
	LogMatch   bool
}

// RunSummary contains run summary
type RunSummary struct {
	TotalTests int
	Passed     int
	Failed     int
	Skipped    int
	Results    []*RunResult
}

// Note: Actual HTTP execution would be done by integrating with the HTTP client
// This provides the compatibility layer for FTW test format
