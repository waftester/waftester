package ftw

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFTWStructs(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{
			Author:      "test",
			Enabled:     true,
			Name:        "Test Suite",
			Description: "Test description",
		},
		Tests: []Stage{
			{
				TestTitle:   "SQL Injection Test",
				Description: "Tests SQL injection detection",
				Stages: []Input{
					{
						Stage: StageData{
							Input: StageInput{
								DestAddr: "localhost",
								Port:     80,
								Protocol: "http",
								URI:      "/search?q=1' OR '1'='1",
								Method:   "GET",
								Headers:  map[string]string{"User-Agent": "test"},
							},
							Output: StageOutput{
								Status:      []int{403},
								LogContains: "id \"942100\"",
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, "test", ftw.Meta.Author)
	assert.True(t, ftw.Meta.Enabled)
	assert.Equal(t, "Test Suite", ftw.Meta.Name)
	assert.Len(t, ftw.Tests, 1)
	assert.Equal(t, "SQL Injection Test", ftw.Tests[0].TestTitle)
}

func TestNewConverter(t *testing.T) {
	c := NewConverter()
	assert.NotNil(t, c)
	assert.Equal(t, "localhost", c.DefaultHost)
	assert.Equal(t, 80, c.DefaultPort)
}

func TestConverterWithHost(t *testing.T) {
	c := NewConverter().WithHost("example.com")
	assert.Equal(t, "example.com", c.DefaultHost)
}

func TestConverterWithPort(t *testing.T) {
	c := NewConverter().WithPort(8080)
	assert.Equal(t, 8080, c.DefaultPort)
}

func TestConverterFromFTW(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{
			Enabled: true,
			Name:    "Test Suite",
		},
		Tests: []Stage{
			{
				TestTitle:   "SQLi Test",
				Description: "SQL Injection",
				Stages: []Input{
					{
						Stage: StageData{
							Input: StageInput{
								URI:    "/test?id=1' OR '1'='1",
								Method: "GET",
								Headers: map[string]string{
									"Host": "example.com",
								},
							},
							Output: StageOutput{
								Status:      []int{403},
								LogContains: "id \"942100\"",
							},
						},
					},
				},
			},
		},
	}

	c := NewConverter()
	tests, err := c.FromFTW(ftw)
	require.NoError(t, err)
	require.Len(t, tests, 1)

	tc := tests[0]
	assert.Equal(t, "sqli-test-1", tc.ID)
	assert.Equal(t, "SQLi Test", tc.Name)
	assert.Equal(t, "GET", tc.Method)
	assert.Equal(t, "/test?id=1' OR '1'='1", tc.Path)
	assert.True(t, tc.ExpectBlock)
	assert.Equal(t, "942100", tc.RuleID)
}

func TestConverterFromFTWDisabled(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{
			Enabled: false,
			Name:    "Disabled Suite",
		},
		Tests: []Stage{
			{TestTitle: "Test"},
		},
	}

	c := NewConverter()
	tests, err := c.FromFTW(ftw)
	require.NoError(t, err)
	assert.Len(t, tests, 0) // Disabled tests should not be converted
}

func TestConverterToFTW(t *testing.T) {
	tests := []*TestCase{
		{
			ID:          "test-1",
			Name:        "Test Group",
			Description: "Test description",
			Method:      "POST",
			Path:        "/api/login",
			Headers:     map[string]string{"Content-Type": "application/json"},
			Body:        `{"user":"admin","pass":"' OR '1'='1"}`,
			ExpectBlock: true,
			RuleID:      "942100",
		},
		{
			ID:          "test-2",
			Name:        "Test Group",
			Method:      "GET",
			Path:        "/safe",
			ExpectBlock: false,
		},
	}

	meta := Meta{
		Author:  "tester",
		Enabled: true,
		Name:    "Converted Tests",
	}

	c := NewConverter()
	ftw := c.ToFTW(tests, meta)

	assert.Equal(t, "tester", ftw.Meta.Author)
	assert.True(t, ftw.Meta.Enabled)
	assert.Len(t, ftw.Tests, 1) // Grouped by name
	assert.Equal(t, "Test Group", ftw.Tests[0].TestTitle)
	assert.Len(t, ftw.Tests[0].Stages, 2)
}

func TestConverterDetermineExpectBlock(t *testing.T) {
	c := NewConverter()

	tests := []struct {
		name     string
		output   StageOutput
		expected bool
	}{
		{
			name:     "403 status",
			output:   StageOutput{Status: []int{403}},
			expected: true,
		},
		{
			name:     "400 status",
			output:   StageOutput{Status: []int{400}},
			expected: true,
		},
		{
			name:     "200 status",
			output:   StageOutput{Status: []int{200}},
			expected: false,
		},
		{
			name:     "log_contains",
			output:   StageOutput{LogContains: "id \"942100\""},
			expected: true,
		},
		{
			name:     "empty output",
			output:   StageOutput{},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := c.determineExpectBlock(tc.output)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConverterParseStatusCodes(t *testing.T) {
	c := NewConverter()

	tests := []struct {
		name     string
		input    interface{}
		expected []int
	}{
		{"int", 403, []int{403}},
		{"float64", float64(200), []int{200}},
		{"string", "500", []int{500}},
		{"slice", []interface{}{200, 201}, []int{200, 201}},
		{"nil", nil, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := c.parseStatusCodes(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConverterExtractRuleID(t *testing.T) {
	c := NewConverter()

	tests := []struct {
		input    string
		expected string
	}{
		{`id "942100"`, "942100"},
		{`id:942100`, "942100"},
		{`id=942100`, "942100"},
		{`matched id "920420"`, "920420"},
		{"no rule id", ""},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := c.extractRuleID(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Simple Test", "simple-test"},
		{"Test-123", "test-123"},
		{"Test_Case", "test_case"},
		{"Test@#$Special", "test-special"},
		{"  Spaces  ", "spaces"},
		{"Multiple---Hyphens", "multiple-hyphens"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeID(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNewImporter(t *testing.T) {
	i := NewImporter()
	assert.NotNil(t, i)
	assert.NotNil(t, i.converter)
}

func TestNewExporter(t *testing.T) {
	e := NewExporter()
	assert.NotNil(t, e)
	assert.NotNil(t, e.converter)
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	assert.NotNil(t, v)
}

func TestValidatorValidate(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name         string
		ftw          *FTWTest
		expectValid  bool
		expectErrors int
	}{
		{
			name: "valid test",
			ftw: &FTWTest{
				Meta: Meta{Name: "Valid Test", Enabled: true},
				Tests: []Stage{
					{
						TestTitle: "Test 1",
						Stages: []Input{
							{
								Stage: StageData{
									Input:  StageInput{Method: "GET", URI: "/"},
									Output: StageOutput{Status: []int{200}},
								},
							},
						},
					},
				},
			},
			expectValid:  true,
			expectErrors: 0,
		},
		{
			name: "missing meta name",
			ftw: &FTWTest{
				Meta:  Meta{Enabled: true},
				Tests: []Stage{},
			},
			expectValid:  false,
			expectErrors: 1,
		},
		{
			name: "missing test title",
			ftw: &FTWTest{
				Meta: Meta{Name: "Test", Enabled: true},
				Tests: []Stage{
					{TestTitle: ""},
				},
			},
			expectValid:  false,
			expectErrors: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := v.Validate(tc.ftw)
			assert.Equal(t, tc.expectValid, result.Valid)
			assert.Len(t, result.Errors, tc.expectErrors)
		})
	}
}

func TestValidatorWarnings(t *testing.T) {
	v := NewValidator()

	ftw := &FTWTest{
		Meta:  Meta{Name: "Test", Enabled: true},
		Tests: []Stage{}, // No tests - should warn
	}

	result := v.Validate(ftw)
	assert.True(t, result.Valid) // Warnings don't fail validation
	assert.Contains(t, result.Warnings, "no tests defined")
}

func TestNewRunner(t *testing.T) {
	r := NewRunner("http://localhost:8080")
	assert.NotNil(t, r)
	assert.Equal(t, "http://localhost:8080", r.BaseURL)
	assert.NotNil(t, r.converter)
}

func TestLoadAndSaveFTWFile(t *testing.T) {
	tmpDir := t.TempDir()

	ftw := &FTWTest{
		Meta: Meta{
			Author:  "tester",
			Enabled: true,
			Name:    "Test Suite",
		},
		Tests: []Stage{
			{
				TestTitle: "Test",
				Stages: []Input{
					{
						Stage: StageData{
							Input:  StageInput{Method: "GET", URI: "/"},
							Output: StageOutput{Status: []int{200}},
						},
					},
				},
			},
		},
	}

	// Test YAML
	yamlPath := filepath.Join(tmpDir, "test.yaml")
	err := SaveFTWFile(ftw, yamlPath)
	require.NoError(t, err)

	loaded, err := LoadFTWFile(yamlPath)
	require.NoError(t, err)
	assert.Equal(t, ftw.Meta.Name, loaded.Meta.Name)
	assert.Len(t, loaded.Tests, 1)

	// Test JSON
	jsonPath := filepath.Join(tmpDir, "test.json")
	err = SaveFTWFile(ftw, jsonPath)
	require.NoError(t, err)

	loaded, err = LoadFTWFile(jsonPath)
	require.NoError(t, err)
	assert.Equal(t, ftw.Meta.Name, loaded.Meta.Name)
}

func TestLoadAndSaveTestCaseFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []*TestCase{
		{
			ID:          "test-1",
			Name:        "Test 1",
			Method:      "GET",
			Path:        "/",
			ExpectBlock: false,
		},
		{
			ID:          "test-2",
			Name:        "Test 2",
			Method:      "POST",
			Path:        "/api",
			ExpectBlock: true,
		},
	}

	// Test YAML
	yamlPath := filepath.Join(tmpDir, "tests.yaml")
	err := SaveTestCaseFile(tests, yamlPath)
	require.NoError(t, err)

	loaded, err := LoadTestCaseFile(yamlPath)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, "test-1", loaded[0].ID)

	// Test JSON
	jsonPath := filepath.Join(tmpDir, "tests.json")
	err = SaveTestCaseFile(tests, jsonPath)
	require.NoError(t, err)

	loaded, err = LoadTestCaseFile(jsonPath)
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
}

func TestLoadFTWFileNotFound(t *testing.T) {
	_, err := LoadFTWFile("/nonexistent/file.yaml")
	assert.Error(t, err)
}

func TestLoadTestCaseFileNotFound(t *testing.T) {
	_, err := LoadTestCaseFile("/nonexistent/file.yaml")
	assert.Error(t, err)
}

func TestImporterImportDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid FTW file
	ftw := &FTWTest{
		Meta: Meta{
			Enabled: true,
			Name:    "SQLi Tests",
		},
		Tests: []Stage{
			{
				TestTitle: "Test 1",
				Stages: []Input{
					{
						Stage: StageData{
							Input:  StageInput{Method: "GET", URI: "/test"},
							Output: StageOutput{Status: []int{200}},
						},
					},
				},
			},
		},
	}
	err := SaveFTWFile(ftw, filepath.Join(tmpDir, "sqli.yaml"))
	require.NoError(t, err)

	// Create another file
	ftw.Meta.Name = "XSS Tests"
	ftw.Tests[0].TestTitle = "Test 2"
	err = SaveFTWFile(ftw, filepath.Join(tmpDir, "xss.yaml"))
	require.NoError(t, err)

	// Create non-FTW file (should be skipped)
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not yaml"), 0644)
	require.NoError(t, err)

	// Import directory
	i := NewImporter()
	tests, err := i.ImportDirectory(tmpDir)
	require.NoError(t, err)
	assert.Len(t, tests, 2) // Two valid FTW files with one test each
}

func TestExporterExportToFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []*TestCase{
		{ID: "test-1", Name: "Test", Method: "GET", Path: "/"},
	}

	meta := Meta{
		Author:  "tester",
		Enabled: true,
		Name:    "Export Test",
	}

	e := NewExporter()
	path := filepath.Join(tmpDir, "export.yaml")
	err := e.ExportToFile(tests, path, meta)
	require.NoError(t, err)

	// Verify file was created
	_, err = os.Stat(path)
	require.NoError(t, err)

	// Load and verify
	ftw, err := LoadFTWFile(path)
	require.NoError(t, err)
	assert.Equal(t, "Export Test", ftw.Meta.Name)
}

func TestExporterExportByCategory(t *testing.T) {
	tmpDir := t.TempDir()
	exportDir := filepath.Join(tmpDir, "export")

	tests := []*TestCase{
		{ID: "sqli-1", Name: "SQLi Test", Method: "GET", Path: "/", Tags: []string{"sqli"}},
		{ID: "sqli-2", Name: "SQLi Test 2", Method: "POST", Path: "/api", Tags: []string{"sqli"}},
		{ID: "xss-1", Name: "XSS Test", Method: "GET", Path: "/", Tags: []string{"xss"}},
		{ID: "uncategorized-1", Name: "Uncategorized", Method: "GET", Path: "/"},
	}

	e := NewExporter()
	err := e.ExportByCategory(tests, exportDir, "tester")
	require.NoError(t, err)

	// Verify files were created
	files, err := os.ReadDir(exportDir)
	require.NoError(t, err)
	assert.Len(t, files, 3) // sqli.yaml, xss.yaml, uncategorized.yaml
}

func TestValidatorValidateFile(t *testing.T) {
	tmpDir := t.TempDir()

	ftw := &FTWTest{
		Meta: Meta{
			Enabled: true,
			Name:    "Test",
		},
		Tests: []Stage{
			{TestTitle: "Test"},
		},
	}

	path := filepath.Join(tmpDir, "test.yaml")
	err := SaveFTWFile(ftw, path)
	require.NoError(t, err)

	v := NewValidator()
	result, err := v.ValidateFile(path)
	require.NoError(t, err)
	assert.True(t, result.Valid)
}

func TestValidatorValidateFileNotFound(t *testing.T) {
	v := NewValidator()
	_, err := v.ValidateFile("/nonexistent/file.yaml")
	assert.Error(t, err)
}

func TestTestCaseStruct(t *testing.T) {
	tc := &TestCase{
		ID:          "test-001",
		Name:        "SQL Injection Test",
		Description: "Tests for SQL injection",
		Enabled:     true,
		Method:      "GET",
		Path:        "/search?q=1' OR '1'='1",
		Headers:     map[string]string{"User-Agent": "test"},
		Body:        "",
		ExpectBlock: true,
		ExpectCode:  403,
		Tags:        []string{"sqli", "owasp"},
		RuleID:      "942100",
	}

	assert.Equal(t, "test-001", tc.ID)
	assert.Equal(t, "SQL Injection Test", tc.Name)
	assert.True(t, tc.Enabled)
	assert.True(t, tc.ExpectBlock)
	assert.Equal(t, 403, tc.ExpectCode)
	assert.Contains(t, tc.Tags, "sqli")
}

func TestStageInputFields(t *testing.T) {
	input := StageInput{
		DestAddr:            "localhost",
		Port:                8080,
		Protocol:            "https",
		URI:                 "/api/test",
		Version:             "HTTP/1.1",
		Method:              "POST",
		Headers:             map[string]string{"Content-Type": "application/json"},
		Data:                `{"test": true}`,
		EncodedRequest:      "",
		RawRequest:          "",
		SaveCookie:          true,
		StopMagic:           false,
		AutocompleteHeaders: true,
	}

	assert.Equal(t, "localhost", input.DestAddr)
	assert.Equal(t, 8080, input.Port)
	assert.Equal(t, "https", input.Protocol)
	assert.Equal(t, "/api/test", input.URI)
	assert.Equal(t, "POST", input.Method)
	assert.True(t, input.SaveCookie)
	assert.True(t, input.AutocompleteHeaders)
}

func TestStageOutputFields(t *testing.T) {
	output := StageOutput{
		Status:           []int{403, 400},
		ResponseContains: "blocked",
		LogContains:      "id \"942100\"",
		NoLogContains:    "error",
		ExpectError:      false,
	}

	assert.Equal(t, []int{403, 400}, output.Status)
	assert.Equal(t, "blocked", output.ResponseContains)
	assert.Equal(t, "id \"942100\"", output.LogContains)
	assert.Equal(t, "error", output.NoLogContains)
	assert.False(t, output.ExpectError)
}

func TestRunResultStruct(t *testing.T) {
	tc := &TestCase{ID: "test-1"}
	result := &RunResult{
		Test:       tc,
		Passed:     true,
		StatusCode: 403,
		Blocked:    true,
		Message:    "Blocked by WAF",
		LogMatch:   true,
	}

	assert.Equal(t, tc, result.Test)
	assert.True(t, result.Passed)
	assert.Equal(t, 403, result.StatusCode)
	assert.True(t, result.Blocked)
	assert.True(t, result.LogMatch)
}

func TestRunSummaryStruct(t *testing.T) {
	summary := &RunSummary{
		TotalTests: 100,
		Passed:     90,
		Failed:     8,
		Skipped:    2,
		Results:    make([]*RunResult, 0),
	}

	assert.Equal(t, 100, summary.TotalTests)
	assert.Equal(t, 90, summary.Passed)
	assert.Equal(t, 8, summary.Failed)
	assert.Equal(t, 2, summary.Skipped)
}

func TestValidationResultStruct(t *testing.T) {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []string{},
		Warnings: []string{"minor warning"},
	}

	assert.True(t, result.Valid)
	assert.Empty(t, result.Errors)
	assert.Len(t, result.Warnings, 1)
}

func TestConverterDefaultMethod(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{Enabled: true, Name: "Test"},
		Tests: []Stage{
			{
				TestTitle: "No Method",
				Stages: []Input{
					{
						Stage: StageData{
							Input:  StageInput{URI: "/test"}, // No method
							Output: StageOutput{Status: []int{200}},
						},
					},
				},
			},
		},
	}

	c := NewConverter()
	tests, err := c.FromFTW(ftw)
	require.NoError(t, err)
	assert.Equal(t, "GET", tests[0].Method) // Defaults to GET
}

func TestConverterDefaultPath(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{Enabled: true, Name: "Test"},
		Tests: []Stage{
			{
				TestTitle: "No Path",
				Stages: []Input{
					{
						Stage: StageData{
							Input:  StageInput{Method: "GET"}, // No URI
							Output: StageOutput{Status: []int{200}},
						},
					},
				},
			},
		},
	}

	c := NewConverter()
	tests, err := c.FromFTW(ftw)
	require.NoError(t, err)
	assert.Equal(t, "/", tests[0].Path) // Defaults to /
}

func TestMultipleStagesInTest(t *testing.T) {
	ftw := &FTWTest{
		Meta: Meta{Enabled: true, Name: "Test"},
		Tests: []Stage{
			{
				TestTitle: "Multi-Stage",
				Stages: []Input{
					{
						Stage: StageData{
							Input:  StageInput{Method: "GET", URI: "/step1"},
							Output: StageOutput{Status: []int{200}},
						},
					},
					{
						Stage: StageData{
							Input:  StageInput{Method: "POST", URI: "/step2"},
							Output: StageOutput{Status: []int{403}},
						},
					},
					{
						Stage: StageData{
							Input:  StageInput{Method: "DELETE", URI: "/step3"},
							Output: StageOutput{Status: []int{200}},
						},
					},
				},
			},
		},
	}

	c := NewConverter()
	tests, err := c.FromFTW(ftw)
	require.NoError(t, err)
	assert.Len(t, tests, 3)
	assert.Equal(t, "multi-stage-1", tests[0].ID)
	assert.Equal(t, "multi-stage-2", tests[1].ID)
	assert.Equal(t, "multi-stage-3", tests[2].ID)
}
