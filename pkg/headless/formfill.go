package headless

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/waftester/waftester/pkg/regexcache"
)

// FormFiller handles automatic form detection and filling
// Based on katana's form fill functionality
type FormFiller struct {
	defaults    map[string]string
	patterns    map[string]string // regex pattern -> value
	customRules map[string]string // field name -> custom value
}

// DefaultFormValues provides intelligent defaults for common form fields
var DefaultFormValues = map[string]string{
	// Identity fields
	"email":      "test@example.com",
	"e-mail":     "test@example.com",
	"mail":       "test@example.com",
	"username":   "testuser",
	"user":       "testuser",
	"login":      "testuser",
	"name":       "Test User",
	"firstname":  "Test",
	"first_name": "Test",
	"first-name": "Test",
	"lastName":   "User",
	"last_name":  "User",
	"last-name":  "User",
	"fullname":   "Test User",
	"full_name":  "Test User",

	// Authentication
	"password":         "TestPassword123!",
	"pass":             "TestPassword123!",
	"pwd":              "TestPassword123!",
	"passwd":           "TestPassword123!",
	"confirm_password": "TestPassword123!",
	"password_confirm": "TestPassword123!",
	"confirmPassword":  "TestPassword123!",
	"new_password":     "NewPassword123!",
	"old_password":     "OldPassword123!",

	// Contact
	"phone":       "1234567890",
	"telephone":   "1234567890",
	"tel":         "1234567890",
	"mobile":      "1234567890",
	"cell":        "1234567890",
	"address":     "123 Test Street",
	"address1":    "123 Test Street",
	"address2":    "Suite 100",
	"city":        "Test City",
	"state":       "CA",
	"zip":         "12345",
	"zipcode":     "12345",
	"postal":      "12345",
	"postal_code": "12345",
	"country":     "US",

	// Search and query
	"q":        "test query",
	"search":   "test search",
	"query":    "test query",
	"keyword":  "test",
	"keywords": "test keywords",
	"s":        "search term",

	// Text areas and comments
	"comment":     "This is a test comment.",
	"comments":    "This is a test comment.",
	"message":     "This is a test message.",
	"body":        "This is test body content.",
	"text":        "This is test text.",
	"content":     "This is test content.",
	"description": "This is a test description.",

	// Numbers
	"age":      "25",
	"quantity": "1",
	"qty":      "1",
	"amount":   "100",
	"price":    "99.99",

	// URLs
	"url":      "https://example.com",
	"website":  "https://example.com",
	"homepage": "https://example.com",
	"link":     "https://example.com",

	// Dates
	"date":       "2024-01-15",
	"dob":        "1990-01-01",
	"birthdate":  "1990-01-01",
	"birth_date": "1990-01-01",

	// Company/Business
	"company":      "Test Company",
	"organization": "Test Organization",
	"title":        "Test Title",
	"subject":      "Test Subject",

	// Security
	"captcha":      "1234",
	"code":         "1234",
	"verification": "1234",
	"otp":          "123456",
	"token":        "test-token",

	// File uploads (placeholder text)
	"file":       "test.txt",
	"attachment": "test.txt",
	"document":   "test.pdf",
	"image":      "test.png",
}

// FieldPatterns maps regex patterns to values
var FieldPatterns = map[string]string{
	`(?i)email`:    "test@example.com",
	`(?i)e-?mail`:  "test@example.com",
	`(?i)password`: "TestPassword123!",
	`(?i)pass`:     "TestPassword123!",
	`(?i)phone`:    "1234567890",
	`(?i)tel`:      "1234567890",
	`(?i)name`:     "Test User",
	`(?i)search`:   "test",
	`(?i)query`:    "test query",
	`(?i)q$`:       "test",
	`(?i)url`:      "https://example.com",
	`(?i)address`:  "123 Test Street",
	`(?i)city`:     "Test City",
	`(?i)zip`:      "12345",
	`(?i)country`:  "US",
	`(?i)comment`:  "Test comment",
	`(?i)message`:  "Test message",
	`(?i)date`:     "2024-01-15",
}

// NewFormFiller creates a new form filler with optional custom values
func NewFormFiller(customValues map[string]string) *FormFiller {
	// Defensive copy of global FieldPatterns to prevent mutation via LoadFormConfig
	patternsCopy := make(map[string]string, len(FieldPatterns))
	for k, v := range FieldPatterns {
		patternsCopy[k] = v
	}
	filler := &FormFiller{
		defaults:    make(map[string]string),
		patterns:    patternsCopy,
		customRules: make(map[string]string),
	}

	// Copy defaults
	for k, v := range DefaultFormValues {
		filler.defaults[k] = v
	}

	// Apply custom values
	for k, v := range customValues {
		filler.customRules[k] = v
	}

	return filler
}

// LoadFormConfig loads form fill configuration from a JSON file
func (f *FormFiller) LoadFormConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read form config %s: %w", path, err)
	}

	var config struct {
		Defaults map[string]string `json:"defaults"`
		Patterns map[string]string `json:"patterns"`
		Custom   map[string]string `json:"custom"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse form config: %w", err)
	}

	for k, v := range config.Defaults {
		f.defaults[k] = v
	}
	for k, v := range config.Patterns {
		f.patterns[k] = v
	}
	for k, v := range config.Custom {
		f.customRules[k] = v
	}

	return nil
}

// GetValueForField determines the appropriate value for a form field
func (f *FormFiller) GetValueForField(field FormField) string {
	// 1. Check custom rules first (highest priority)
	if val, ok := f.customRules[field.Name]; ok {
		return val
	}
	if val, ok := f.customRules[field.ID]; ok {
		return val
	}

	// 2. Check exact match in defaults
	name := strings.ToLower(field.Name)
	if val, ok := f.defaults[name]; ok {
		return val
	}

	// 3. Check patterns
	for pattern, value := range f.patterns {
		re, err := regexcache.Get(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(field.Name) || re.MatchString(field.ID) {
			return value
		}
		if field.Placeholder != "" && re.MatchString(field.Placeholder) {
			return value
		}
	}

	// 4. Default based on input type
	switch strings.ToLower(field.Type) {
	case "email":
		return "test@example.com"
	case "password":
		return "TestPassword123!"
	case "tel", "phone":
		return "1234567890"
	case "url":
		return "https://example.com"
	case "number":
		return "1"
	case "date":
		return "2024-01-15"
	case "datetime-local":
		return "2024-01-15T10:00"
	case "time":
		return "10:00"
	case "color":
		return "#000000"
	case "range":
		return "50"
	case "checkbox":
		return "true"
	case "radio":
		if len(field.Options) > 0 {
			return field.Options[0]
		}
		return "1"
	case "select":
		if len(field.Options) > 0 {
			return field.Options[0]
		}
		return ""
	case "textarea":
		return "This is a test message for the textarea field."
	case "hidden":
		// Don't change hidden fields
		return field.Value
	}

	// 5. Generic fallback
	return "test"
}

// FillForm generates filled form data for a form
func (f *FormFiller) FillForm(form FormInfo) map[string]string {
	result := make(map[string]string)

	for _, field := range form.Fields {
		// Skip hidden fields with values and submit buttons
		if field.Type == "hidden" && field.Value != "" {
			result[field.Name] = field.Value
			continue
		}
		if field.Type == "submit" || field.Type == "button" || field.Type == "reset" {
			continue
		}

		value := f.GetValueForField(field)
		if value != "" {
			result[field.Name] = value
		}
	}

	return result
}

// DetectFormType tries to identify what type of form this is
func DetectFormType(form FormInfo) string {
	// Analyze field names to determine form type
	fieldNames := make([]string, len(form.Fields))
	for i, f := range form.Fields {
		fieldNames[i] = strings.ToLower(f.Name)
	}
	combined := strings.Join(fieldNames, " ")

	// Registration form (check first - has confirm password)
	if strings.Contains(combined, "password") && strings.Contains(combined, "confirm") {
		return "registration"
	}

	// Login form detection
	if strings.Contains(combined, "password") &&
		(strings.Contains(combined, "email") || strings.Contains(combined, "username") || strings.Contains(combined, "login")) {
		return "login"
	}

	// Search form
	if strings.Contains(combined, "search") || strings.Contains(combined, "query") ||
		(len(form.Fields) == 1 && form.Method == "GET") {
		return "search"
	}

	// Contact form
	if strings.Contains(combined, "message") || strings.Contains(combined, "comment") ||
		strings.Contains(combined, "contact") {
		return "contact"
	}

	// Password reset
	if strings.Contains(combined, "email") && strings.Contains(combined, "reset") {
		return "password_reset"
	}

	// File upload
	for _, f := range form.Fields {
		if f.Type == "file" {
			return "upload"
		}
	}

	return "unknown"
}

// FormToURLEncoded converts form data to URL-encoded string
func FormToURLEncoded(data map[string]string) string {
	vals := make(url.Values, len(data))
	for k, v := range data {
		vals.Set(k, v)
	}
	return vals.Encode()
}

// FormToJSON converts form data to JSON string
func FormToJSON(data map[string]string) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("marshal form data: %w", err)
	}
	return string(b), nil
}
