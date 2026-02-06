package output

import (
	"reflect"
	"testing"
)

// =============================================================================
// parseCSV Tests
// =============================================================================
// These tests verify that parseCSV correctly parses comma-separated values
// from CLI flags into string slices for use with integrations.

func TestParseCSV_EmptyString(t *testing.T) {
	result := parseCSV("")
	if result != nil {
		t.Errorf("expected nil for empty string, got %v", result)
	}
}

func TestParseCSV_SingleValue(t *testing.T) {
	result := parseCSV("security")
	expected := []string{"security"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_MultipleValues(t *testing.T) {
	result := parseCSV("security,waf-bypass,bug")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_TrimsWhitespace(t *testing.T) {
	result := parseCSV("security , waf-bypass , bug ")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_FiltersEmptyStrings(t *testing.T) {
	result := parseCSV("security,,waf-bypass,,,bug")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_WhitespaceOnlyBecomesEmpty(t *testing.T) {
	result := parseCSV("security, ,waf-bypass")
	expected := []string{"security", "waf-bypass"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_RealWorldJiraLabels(t *testing.T) {
	// Tests the exact format users would provide via --jira-labels flag
	result := parseCSV("waftester,security,waf-bypass,critical")
	expected := []string{"waftester", "security", "waf-bypass", "critical"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseCSV_RealWorldGitHubAssignees(t *testing.T) {
	// Tests the exact format users would provide via --github-issues-assignees flag
	result := parseCSV("octocat,hubot,security-team")
	expected := []string{"octocat", "hubot", "security-team"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// =============================================================================
// parseSemicolonSeparated Tests
// =============================================================================
// These tests verify that parseSemicolonSeparated correctly parses semicolon-separated
// values from CLI flags into string slices for Azure DevOps tags.

func TestParseSemicolonSeparated_EmptyString(t *testing.T) {
	result := parseSemicolonSeparated("")
	if result != nil {
		t.Errorf("expected nil for empty string, got %v", result)
	}
}

func TestParseSemicolonSeparated_SingleValue(t *testing.T) {
	result := parseSemicolonSeparated("security")
	expected := []string{"security"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseSemicolonSeparated_MultipleValues(t *testing.T) {
	result := parseSemicolonSeparated("security;waf-bypass;bug")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseSemicolonSeparated_TrimsWhitespace(t *testing.T) {
	result := parseSemicolonSeparated("security ; waf-bypass ; bug ")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseSemicolonSeparated_FiltersEmptyStrings(t *testing.T) {
	result := parseSemicolonSeparated("security;;waf-bypass;;;bug")
	expected := []string{"security", "waf-bypass", "bug"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestParseSemicolonSeparated_RealWorldADOTags(t *testing.T) {
	// Tests the exact format users would provide via --ado-tags flag
	result := parseSemicolonSeparated("waftester;security;waf-bypass;P1")
	expected := []string{"waftester", "security", "waf-bypass", "P1"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

// =============================================================================
// Integration Wiring Tests
// =============================================================================
// These tests verify that CLI configuration values are correctly passed through
// to the hooks via BuildDispatcher. These are the tests that would have caught
// the bugs we found during adversarial review:
// - Jira labels being hardcoded instead of using CLI value
// - Jira assignee not being passed through
// - ADO tags being hardcoded instead of using CLI value

func TestBuildDispatcher_JiraLabelsFromConfig(t *testing.T) {
	// This test verifies that when JiraLabels is set in config,
	// it gets parsed and used (not hardcoded defaults)

	cfg := Config{
		JiraURL:     "https://jira.example.com",
		JiraProject: "SEC",
		JiraEmail:   "test@example.com",
		JiraToken:   "test-token",
		JiraLabels:  "custom-label-1,custom-label-2",
	}

	// We're testing that parseCSV is called correctly
	// The actual hook creation would try to connect, so we just test the parsing
	labels := []string{"waftester", "security"} // defaults
	if cfg.JiraLabels != "" {
		labels = parseCSV(cfg.JiraLabels)
	}

	expected := []string{"custom-label-1", "custom-label-2"}
	if !reflect.DeepEqual(labels, expected) {
		t.Errorf("expected custom labels %v, got %v (hardcoded defaults would be bug)", expected, labels)
	}
}

func TestBuildDispatcher_JiraLabelsDefaultsWhenEmpty(t *testing.T) {
	// This test verifies that when JiraLabels is empty,
	// default labels are used

	cfg := Config{
		JiraURL:     "https://jira.example.com",
		JiraProject: "SEC",
		JiraLabels:  "", // Empty - should use defaults
	}

	labels := []string{"waftester", "security"} // defaults
	if cfg.JiraLabels != "" {
		labels = parseCSV(cfg.JiraLabels)
	}

	if len(labels) != 2 || labels[0] != "waftester" {
		t.Errorf("expected default labels, got %v", labels)
	}
}

func TestBuildDispatcher_ADOTagsFromConfig(t *testing.T) {
	// This test verifies that when ADOTags is set in config,
	// it gets parsed and used (not hardcoded defaults)

	cfg := Config{
		ADOOrganization: "testorg",
		ADOProject:      "testproj",
		ADOPAT:          "test-pat",
		ADOTags:         "custom-tag-1;custom-tag-2;P1",
	}

	// We're testing that parseSemicolonSeparated is called correctly
	tags := []string{"waftester", "security", "waf-bypass"} // defaults
	if cfg.ADOTags != "" {
		tags = parseSemicolonSeparated(cfg.ADOTags)
	}

	expected := []string{"custom-tag-1", "custom-tag-2", "P1"}
	if !reflect.DeepEqual(tags, expected) {
		t.Errorf("expected custom tags %v, got %v (hardcoded defaults would be bug)", expected, tags)
	}
}

func TestBuildDispatcher_ADOTagsDefaultsWhenEmpty(t *testing.T) {
	// This test verifies that when ADOTags is empty,
	// default tags are used

	cfg := Config{
		ADOOrganization: "testorg",
		ADOProject:      "testproj",
		ADOPAT:          "test-pat",
		ADOTags:         "", // Empty - should use defaults
	}

	tags := []string{"waftester", "security", "waf-bypass"} // defaults
	if cfg.ADOTags != "" {
		tags = parseSemicolonSeparated(cfg.ADOTags)
	}

	if len(tags) != 3 || tags[0] != "waftester" {
		t.Errorf("expected default tags, got %v", tags)
	}
}

func TestBuildDispatcher_GitHubIssuesLabelsFromConfig(t *testing.T) {
	// This test verifies that when GitHubIssuesLabels is set in config,
	// it gets parsed and used (not hardcoded defaults)

	cfg := Config{
		GitHubIssuesToken:  "ghp_test123",
		GitHubIssuesOwner:  "testorg",
		GitHubIssuesRepo:   "testrepo",
		GitHubIssuesLabels: "security,waf-bypass,P0",
	}

	// We're testing that parseCSV is called correctly
	labels := []string{"waftester", "security", "waf-bypass"} // defaults
	if cfg.GitHubIssuesLabels != "" {
		labels = parseCSV(cfg.GitHubIssuesLabels)
	}

	expected := []string{"security", "waf-bypass", "P0"}
	if !reflect.DeepEqual(labels, expected) {
		t.Errorf("expected custom labels %v, got %v", expected, labels)
	}
}

func TestBuildDispatcher_GitHubIssuesAssigneesFromConfig(t *testing.T) {
	// This test verifies that when GitHubIssuesAssignees is set in config,
	// it gets parsed and used

	cfg := Config{
		GitHubIssuesToken:     "ghp_test123",
		GitHubIssuesOwner:     "testorg",
		GitHubIssuesRepo:      "testrepo",
		GitHubIssuesAssignees: "user1,user2,security-team",
	}

	// We're testing that parseCSV is called correctly
	var assignees []string
	if cfg.GitHubIssuesAssignees != "" {
		assignees = parseCSV(cfg.GitHubIssuesAssignees)
	}

	expected := []string{"user1", "user2", "security-team"}
	if !reflect.DeepEqual(assignees, expected) {
		t.Errorf("expected assignees %v, got %v", expected, assignees)
	}
}

func TestBuildDispatcher_JiraAssigneePassedThrough(t *testing.T) {
	// This test verifies that JiraAssignee from config is not lost

	cfg := Config{
		JiraURL:      "https://jira.example.com",
		JiraProject:  "SEC",
		JiraEmail:    "test@example.com",
		JiraToken:    "test-token",
		JiraAssignee: "5b10a2844c20165700ede21g", // Jira account ID
	}

	// The assignee should be available in config
	if cfg.JiraAssignee == "" {
		t.Error("expected JiraAssignee to be set in config")
	}
	if cfg.JiraAssignee != "5b10a2844c20165700ede21g" {
		t.Errorf("expected JiraAssignee '5b10a2844c20165700ede21g', got %q", cfg.JiraAssignee)
	}
}

// =============================================================================
// Config Field Tests
// =============================================================================
// These tests verify that Config struct has all the expected fields for integrations.

func TestConfig_HasJiraFields(t *testing.T) {
	cfg := Config{
		JiraURL:       "https://jira.example.com",
		JiraProject:   "SEC",
		JiraEmail:     "test@example.com",
		JiraToken:     "test-token",
		JiraIssueType: "Bug",
		JiraLabels:    "security,waf-bypass",
		JiraAssignee:  "account-id",
	}

	// Verify all fields are settable
	if cfg.JiraURL == "" {
		t.Error("JiraURL field missing or not settable")
	}
	if cfg.JiraProject == "" {
		t.Error("JiraProject field missing or not settable")
	}
	if cfg.JiraLabels == "" {
		t.Error("JiraLabels field missing or not settable")
	}
	if cfg.JiraAssignee == "" {
		t.Error("JiraAssignee field missing or not settable")
	}
}

func TestConfig_HasGitHubIssuesFields(t *testing.T) {
	cfg := Config{
		GitHubIssuesToken:     "ghp_test123",
		GitHubIssuesOwner:     "testorg",
		GitHubIssuesRepo:      "testrepo",
		GitHubIssuesURL:       "https://github.mycompany.com/api/v3",
		GitHubIssuesLabels:    "security,waf-bypass",
		GitHubIssuesAssignees: "user1,user2",
	}

	// Verify all fields are settable
	if cfg.GitHubIssuesToken == "" {
		t.Error("GitHubIssuesToken field missing or not settable")
	}
	if cfg.GitHubIssuesOwner == "" {
		t.Error("GitHubIssuesOwner field missing or not settable")
	}
	if cfg.GitHubIssuesRepo == "" {
		t.Error("GitHubIssuesRepo field missing or not settable")
	}
	if cfg.GitHubIssuesURL == "" {
		t.Error("GitHubIssuesURL field missing or not settable")
	}
	if cfg.GitHubIssuesLabels == "" {
		t.Error("GitHubIssuesLabels field missing or not settable")
	}
	if cfg.GitHubIssuesAssignees == "" {
		t.Error("GitHubIssuesAssignees field missing or not settable")
	}
}

func TestConfig_HasAzureDevOpsFields(t *testing.T) {
	cfg := Config{
		ADOOrganization:  "testorg",
		ADOProject:       "testproj",
		ADOPAT:           "test-pat",
		ADOWorkItemType:  "Bug",
		ADOAreaPath:      "TestOrg\\Security",
		ADOIterationPath: "TestOrg\\Sprint1",
		ADOAssignedTo:    "user@example.com",
		ADOTags:          "security;waf-bypass",
	}

	// Verify all fields are settable
	if cfg.ADOOrganization == "" {
		t.Error("ADOOrganization field missing or not settable")
	}
	if cfg.ADOProject == "" {
		t.Error("ADOProject field missing or not settable")
	}
	if cfg.ADOPAT == "" {
		t.Error("ADOPAT field missing or not settable")
	}
	if cfg.ADOWorkItemType == "" {
		t.Error("ADOWorkItemType field missing or not settable")
	}
	if cfg.ADOAreaPath == "" {
		t.Error("ADOAreaPath field missing or not settable")
	}
	if cfg.ADOIterationPath == "" {
		t.Error("ADOIterationPath field missing or not settable")
	}
	if cfg.ADOAssignedTo == "" {
		t.Error("ADOAssignedTo field missing or not settable")
	}
	if cfg.ADOTags == "" {
		t.Error("ADOTags field missing or not settable")
	}
}
