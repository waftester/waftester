// Package validate provides payload validation functionality
package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/payloadprovider"
	"github.com/waftester/waftester/pkg/ui"
)

// ValidationResult holds the results of payload validation
type ValidationResult struct {
	TotalFiles        int      `json:"total_files"`
	TotalPayloads     int      `json:"total_payloads"`
	Errors            []string `json:"errors"`
	Warnings          []string `json:"warnings"`
	DuplicateIDs      []string `json:"duplicate_ids"`
	MissingFields     []string `json:"missing_fields"`
	InvalidSeverities []string `json:"invalid_severities"`
	Valid             bool     `json:"valid"`
}

// PayloadSchema represents the expected structure of a payload
type PayloadSchema struct {
	ID           string   `json:"id"`
	Payload      string   `json:"payload"`
	Category     string   `json:"category"`
	SeverityHint string   `json:"severity_hint"`
	Tags         []string `json:"tags"`
	Notes        string   `json:"notes"`
	// Optional fields
	Method        string `json:"method,omitempty"`
	Body          string `json:"body,omitempty"`
	ExpectedBlock bool   `json:"expected_block,omitempty"`
	Service       string `json:"service,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
}

var (
	// validSeverities is built from finding.TitleCaseStrings to stay in sync.
	// Payloads use Critical/High/Medium/Low (not Info).
	validSeverities = func() map[string]bool {
		titles := finding.TitleCaseStrings()
		m := make(map[string]bool, len(titles)*2)
		for _, s := range titles {
			m[s] = true                  // title case ("Critical")
			m[strings.ToLower(s)] = true // lowercase ("critical")
		}
		return m
	}()

	validCategories = payloadprovider.NewCategoryMapper().ValidCategories()

	requiredFields = []string{"id", "payload", "category", "severity_hint", "tags", "notes"}

	// Validation constants
	maxIDLength = 256

	green = func(a ...interface{}) string {
		s := fmt.Sprint(a...)
		if !ui.StdoutIsTerminal() {
			return s
		}
		return "\033[32m" + s + "\033[0m"
	}
	red = func(a ...interface{}) string {
		s := fmt.Sprint(a...)
		if !ui.StdoutIsTerminal() {
			return s
		}
		return "\033[31m" + s + "\033[0m"
	}
	yellow = func(a ...interface{}) string {
		s := fmt.Sprint(a...)
		if !ui.StdoutIsTerminal() {
			return s
		}
		return "\033[33m" + s + "\033[0m"
	}
	cyan = func(a ...interface{}) string {
		s := fmt.Sprint(a...)
		if !ui.StdoutIsTerminal() {
			return s
		}
		return "\033[36m" + s + "\033[0m"
	}
)

// ValidatePayloads validates all payload files in the given directory
func ValidatePayloads(payloadDir string, failFast bool, verbose bool) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid: true,
	}

	if ui.UnicodeTerminal() {
		fmt.Println(cyan("╔════════════════════════════════════════════════════════════════╗"))
		fmt.Println(cyan("║                                                                ║"))
		fmt.Println(cyan("║    " + ui.Icon("🔍", ">") + " Security Test Harness Validator                         ║"))
		fmt.Println(cyan("║                                                                ║"))
		fmt.Println(cyan("╚════════════════════════════════════════════════════════════════╝"))
	} else {
		fmt.Println(cyan("+================================================================+"))
		fmt.Println(cyan("|                                                                |"))
		fmt.Println(cyan("|    " + ui.Icon("🔍", ">") + " Security Test Harness Validator                         |"))
		fmt.Println(cyan("|                                                                |"))
		fmt.Println(cyan("+================================================================+"))
	}
	fmt.Println()

	allTestIDs := make(map[string]string) // ID -> file path

	// Check ids-map.json exists
	idsMapPath := filepath.Join(payloadDir, "ids-map.json")
	if _, err := os.Stat(idsMapPath); os.IsNotExist(err) {
		result.Errors = append(result.Errors, "Critical: ids-map.json not found")
		result.Valid = false
		if failFast {
			return result, fmt.Errorf("ids-map.json not found at %s", idsMapPath)
		}
	} else {
		fmt.Printf("   %s Found ids-map.json\n", green(ui.Icon("✓", "+")))
		// Validate it's valid JSON
		data, err := os.ReadFile(idsMapPath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Cannot read ids-map.json: %v", err))
			result.Valid = false
		} else {
			var idsMap interface{}
			if err := json.Unmarshal(data, &idsMap); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("ids-map.json parse error: %v", err))
				result.Valid = false
			} else {
				fmt.Printf("   %s ids-map.json is valid JSON\n", green(ui.Icon("✓", "+")))
			}
		}
	}

	// Find all JSON payload files
	var payloadFiles []string
	err := filepath.Walk(payloadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			basename := filepath.Base(path)
			if basename != "ids-map.json" && basename != "version.json" {
				payloadFiles = append(payloadFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error scanning payload directory: %w", err)
	}

	result.TotalFiles = len(payloadFiles)
	fmt.Printf("   Found %d payload files\n", result.TotalFiles)
	fmt.Println()

	// Validate each file
	for _, filePath := range payloadFiles {
		relPath, _ := filepath.Rel(payloadDir, filePath)
		if verbose {
			fmt.Printf("   Validating %s...\n", relPath)
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: cannot read file: %v", relPath, err))
			result.Valid = false
			continue
		}

		var payloads []map[string]interface{}
		if err := json.Unmarshal(data, &payloads); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: JSON parse error: %v", relPath, err))
			result.Valid = false
			continue
		}

		for i, p := range payloads {
			result.TotalPayloads++

			// Check required fields
			for _, field := range requiredFields {
				val, ok := p[field]
				if !ok || val == nil {
					msg := fmt.Sprintf("%s[%d]: missing required field '%s'", relPath, i, field)
					result.MissingFields = append(result.MissingFields, msg)
					result.Valid = false
					if failFast {
						return result, errors.New(msg)
					}
				}
			}

			// Check ID uniqueness and validity
			if id, ok := p["id"].(string); ok {
				// Check for empty ID
				if id == "" {
					msg := fmt.Sprintf("%s[%d]: ID cannot be empty", relPath, i)
					result.Errors = append(result.Errors, msg)
					result.Valid = false
					if failFast {
						return result, errors.New(msg)
					}
					continue
				}

				// Check for whitespace in ID
				trimmedID := strings.TrimSpace(id)
				if trimmedID != id || strings.ContainsAny(id, "\t\n\r") {
					msg := fmt.Sprintf("%s[%d]: ID '%s' contains invalid whitespace", relPath, i, id)
					result.Errors = append(result.Errors, msg)
					result.Valid = false
					if failFast {
						return result, errors.New(msg)
					}
					continue
				}

				// Check for very long ID
				if len(id) > maxIDLength {
					msg := fmt.Sprintf("%s[%d]: ID too long (%d chars, max %d)", relPath, i, len(id), maxIDLength)
					result.Errors = append(result.Errors, msg)
					result.Valid = false
					if failFast {
						return result, errors.New(msg)
					}
					continue
				}

				if existingFile, exists := allTestIDs[id]; exists {
					msg := fmt.Sprintf("Duplicate ID '%s' in %s (first seen in %s)", id, relPath, existingFile)
					result.DuplicateIDs = append(result.DuplicateIDs, msg)
					result.Valid = false
					if failFast {
						return result, errors.New(msg)
					}
				} else {
					allTestIDs[id] = relPath
				}
			}

			// Validate severity
			if severity, ok := p["severity_hint"].(string); ok {
				if !validSeverities[severity] {
					msg := fmt.Sprintf("%s[%d]: invalid severity '%s' (expected: %s)", relPath, i, severity, strings.Join(finding.TitleCaseStrings(), ", "))
					result.InvalidSeverities = append(result.InvalidSeverities, msg)
					result.Valid = false
				}
			}

			// Validate category
			if category, ok := p["category"].(string); ok {
				if !validCategories[strings.ToLower(category)] {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("%s[%d]: non-standard category '%s'", relPath, i, category))
				}
			}
		}
	}

	// Print summary
	fmt.Println()
	if ui.UnicodeTerminal() {
		fmt.Println(cyan("════════════════════════════════════════════════════════════════"))
		fmt.Println(cyan("                     VALIDATION SUMMARY"))
		fmt.Println(cyan("════════════════════════════════════════════════════════════════"))
	} else {
		fmt.Println(cyan("================================================================"))
		fmt.Println(cyan("                     VALIDATION SUMMARY"))
		fmt.Println(cyan("================================================================"))
	}
	fmt.Printf("   Files validated:    %d\n", result.TotalFiles)
	fmt.Printf("   Total payloads:     %d\n", result.TotalPayloads)
	fmt.Printf("   Unique test IDs:    %d\n", len(allTestIDs))
	fmt.Println()

	if len(result.Errors) > 0 {
		fmt.Printf("   %s Errors: %d\n", red(ui.Icon("✗", "x")), len(result.Errors))
		for _, e := range result.Errors {
			fmt.Printf("      %s %s\n", red(ui.Icon("•", "-")), e)
		}
	}

	if len(result.DuplicateIDs) > 0 {
		fmt.Printf("   %s Duplicate IDs: %d\n", red(ui.Icon("✗", "x")), len(result.DuplicateIDs))
		for _, d := range result.DuplicateIDs {
			fmt.Printf("      %s %s\n", red(ui.Icon("•", "-")), d)
		}
	}

	if len(result.MissingFields) > 0 {
		fmt.Printf("   %s Missing fields: %d\n", red(ui.Icon("✗", "x")), len(result.MissingFields))
		for _, m := range result.MissingFields {
			fmt.Printf("      %s %s\n", red(ui.Icon("•", "-")), m)
		}
	}

	if len(result.InvalidSeverities) > 0 {
		fmt.Printf("   %s Invalid severities: %d\n", red(ui.Icon("✗", "x")), len(result.InvalidSeverities))
		for _, s := range result.InvalidSeverities {
			fmt.Printf("      %s %s\n", red(ui.Icon("•", "-")), s)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Printf("   %s Warnings: %d\n", yellow(ui.Icon("⚠", "!")), len(result.Warnings))
		if verbose {
			for _, w := range result.Warnings {
				fmt.Printf("      %s %s\n", yellow(ui.Icon("•", "-")), w)
			}
		}
	}

	fmt.Println()
	if result.Valid {
		fmt.Printf("   %s All validations passed!\n", green(ui.Icon("✓", "+")))
	} else {
		fmt.Printf("   %s Validation failed with %d error(s)\n", red(ui.Icon("✗", "x")),
			len(result.Errors)+len(result.DuplicateIDs)+len(result.MissingFields)+len(result.InvalidSeverities))
	}

	return result, nil
}
