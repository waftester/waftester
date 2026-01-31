// Package templatevalidator provides validation for Nuclei-compatible YAML templates
package templatevalidator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidationResult holds the result of validating a template
type ValidationResult struct {
	File     string   `json:"file"`
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ValidationSummary holds the overall validation summary
type ValidationSummary struct {
	TotalFiles    int                 `json:"total_files"`
	ValidFiles    int                 `json:"valid_files"`
	InvalidFiles  int                 `json:"invalid_files"`
	TotalErrors   int                 `json:"total_errors"`
	TotalWarnings int                 `json:"total_warnings"`
	Results       []*ValidationResult `json:"results"`
}

// Template represents the structure of a Nuclei-compatible template
type Template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string   `yaml:"name"`
		Author         string   `yaml:"author"`
		Severity       string   `yaml:"severity"`
		Description    string   `yaml:"description"`
		Reference      []string `yaml:"reference"`
		Tags           string   `yaml:"tags"`
		Classification struct {
			CVEID       string      `yaml:"cve-id"`
			CWEID       interface{} `yaml:"cwe-id"` // Can be string or []string
			CVSSMetrics string      `yaml:"cvss-metrics"`
			CVSSScore   float64     `yaml:"cvss-score"`
		} `yaml:"classification"`
		Metadata map[string]interface{} `yaml:"metadata"`
	} `yaml:"info"`
	HTTP []struct {
		Method   string            `yaml:"method"`
		Path     []string          `yaml:"path"`
		Raw      []string          `yaml:"raw"`
		Headers  map[string]string `yaml:"headers"`
		Body     string            `yaml:"body"`
		Matchers []struct {
			Type      string   `yaml:"type"`
			Words     []string `yaml:"words"`
			Regex     []string `yaml:"regex"`
			Status    []int    `yaml:"status"`
			Condition string   `yaml:"condition"`
		} `yaml:"matchers"`
		MatchersCondition string `yaml:"matchers-condition"`
	} `yaml:"http"`
	Variables map[string]string `yaml:"variables"`
}

// ValidSeverities defines valid severity levels
var ValidSeverities = []string{"critical", "high", "medium", "low", "info", "unknown"}

// Validator validates Nuclei-compatible templates
type Validator struct {
	StrictMode bool
}

// NewValidator creates a new template validator
func NewValidator(strict bool) *Validator {
	return &Validator{StrictMode: strict}
}

// ValidateFile validates a single template file
func (v *Validator) ValidateFile(filePath string) *ValidationResult {
	result := &ValidationResult{
		File:  filePath,
		Valid: true,
	}

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("cannot read file: %v", err))
		return result
	}

	// Parse YAML
	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid YAML: %v", err))
		return result
	}

	// Validate required fields
	if tmpl.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required field: id")
	} else if !isValidID(tmpl.ID) {
		result.Errors = append(result.Errors, fmt.Sprintf("invalid id format: %s (should be lowercase with hyphens)", tmpl.ID))
		result.Valid = false
	}

	if tmpl.Info.Name == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required field: info.name")
	}

	if tmpl.Info.Author == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required field: info.author")
	}

	if tmpl.Info.Severity == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "missing required field: info.severity")
	} else if !isValidSeverity(tmpl.Info.Severity) {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("invalid severity: %s (must be one of: %s)",
			tmpl.Info.Severity, strings.Join(ValidSeverities, ", ")))
	}

	// Validate HTTP requests if present
	if len(tmpl.HTTP) == 0 {
		result.Warnings = append(result.Warnings, "no http requests defined")
	}

	for i, req := range tmpl.HTTP {
		if len(req.Path) == 0 && len(req.Raw) == 0 {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("http[%d]: must have path or raw request", i))
		}

		if len(req.Matchers) == 0 {
			result.Warnings = append(result.Warnings, fmt.Sprintf("http[%d]: no matchers defined", i))
		}

		for j, matcher := range req.Matchers {
			if matcher.Type == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("http[%d].matchers[%d]: missing type", i, j))
			}
		}
	}

	// Warnings (non-fatal)
	if tmpl.Info.Description == "" {
		result.Warnings = append(result.Warnings, "missing description")
	}

	if len(tmpl.Info.Reference) == 0 {
		result.Warnings = append(result.Warnings, "no references provided")
	}

	if tmpl.Info.Tags == "" {
		result.Warnings = append(result.Warnings, "no tags provided")
	}

	// Strict mode additional checks
	if v.StrictMode {
		if tmpl.Info.Classification.CVEID == "" && strings.HasPrefix(strings.ToLower(tmpl.ID), "cve-") {
			result.Warnings = append(result.Warnings, "CVE template missing classification.cve-id")
		}
	}

	return result
}

// ValidateDirectory validates all templates in a directory
func (v *Validator) ValidateDirectory(dirPath string) (*ValidationSummary, error) {
	summary := &ValidationSummary{}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(path), ".yaml") && !strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		result := v.ValidateFile(path)
		summary.Results = append(summary.Results, result)
		summary.TotalFiles++

		if result.Valid {
			summary.ValidFiles++
		} else {
			summary.InvalidFiles++
		}

		summary.TotalErrors += len(result.Errors)
		summary.TotalWarnings += len(result.Warnings)

		return nil
	})

	return summary, err
}

// isValidID checks if the template ID follows naming conventions
func isValidID(id string) bool {
	// Allow CVE IDs in uppercase
	if strings.HasPrefix(id, "CVE-") {
		return regexp.MustCompile(`^CVE-\d{4}-\d+$`).MatchString(id)
	}
	// Otherwise should be lowercase with hyphens
	return regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$`).MatchString(id) ||
		regexp.MustCompile(`^[a-z0-9]$`).MatchString(id)
}

// isValidSeverity checks if the severity is valid
func isValidSeverity(severity string) bool {
	severity = strings.ToLower(severity)
	for _, valid := range ValidSeverities {
		if severity == valid {
			return true
		}
	}
	return false
}
