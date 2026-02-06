package main

import (
	"flag"
	"testing"
)

// =============================================================================
// CLI Integration Flag Registration Tests
// =============================================================================
// These tests verify that all integration flags (Jira, GitHub Issues, ADO)
// are properly registered in all RegisterFlags variants. This would have
// caught the bug where flags were only added to RegisterFlags() but missing
// from the 5 enterprise variants.

// TestOutputFlags_JiraFlagsRegistered verifies all Jira flags are registered
func TestOutputFlags_JiraFlagsRegistered(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterFlags(fs)

	requiredFlags := []string{
		"jira-url",
		"jira-project",
		"jira-email",
		"jira-token",
		"jira-issue-type",
		"jira-labels",
		"jira-assignee",
	}

	for _, flagName := range requiredFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("missing Jira flag: --%s", flagName)
		}
	}
}

// TestOutputFlags_GitHubIssuesFlagsRegistered verifies all GitHub Issues flags are registered
func TestOutputFlags_GitHubIssuesFlagsRegistered(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterFlags(fs)

	requiredFlags := []string{
		"github-issues-token",
		"github-issues-owner",
		"github-issues-repo",
		"github-issues-url",
		"github-issues-labels",
		"github-issues-assignees",
	}

	for _, flagName := range requiredFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("missing GitHub Issues flag: --%s", flagName)
		}
	}
}

// TestOutputFlags_AzureDevOpsFlagsRegistered verifies all Azure DevOps flags are registered
func TestOutputFlags_AzureDevOpsFlagsRegistered(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterFlags(fs)

	requiredFlags := []string{
		"ado-org",
		"ado-project",
		"ado-pat",
		"ado-work-item-type",
		"ado-area-path",
		"ado-iteration-path",
		"ado-assigned-to",
		"ado-tags",
	}

	for _, flagName := range requiredFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("missing Azure DevOps flag: --%s", flagName)
		}
	}
}

// TestOutputFlags_EnterpriseFlagsHaveNewIntegrations verifies RegisterEnterpriseFlags
// includes the new integration flags (jira-labels, jira-assignee, ado-tags)
func TestOutputFlags_EnterpriseFlagsHaveNewIntegrations(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterEnterpriseFlags(fs)

	// These are the flags that were missing and caused bugs
	criticalFlags := []string{
		"jira-labels",
		"jira-assignee",
		"ado-tags",
	}

	for _, flagName := range criticalFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("critical: --%s missing from RegisterEnterpriseFlags (this caused a bug!)", flagName)
		}
	}
}

// TestOutputFlags_RunEnterpriseFlagsHaveNewIntegrations verifies RegisterRunEnterpriseFlags
func TestOutputFlags_RunEnterpriseFlagsHaveNewIntegrations(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterRunEnterpriseFlags(fs)

	criticalFlags := []string{
		"jira-labels",
		"jira-assignee",
		"ado-tags",
	}

	for _, flagName := range criticalFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("critical: --%s missing from RegisterRunEnterpriseFlags", flagName)
		}
	}
}

// TestOutputFlags_ProbeEnterpriseFlagsHaveNewIntegrations verifies RegisterProbeEnterpriseFlags
func TestOutputFlags_ProbeEnterpriseFlagsHaveNewIntegrations(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterProbeEnterpriseFlags(fs)

	criticalFlags := []string{
		"jira-labels",
		"jira-assignee",
		"ado-tags",
	}

	for _, flagName := range criticalFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("critical: --%s missing from RegisterProbeEnterpriseFlags", flagName)
		}
	}
}

// TestOutputFlags_FuzzEnterpriseFlagsHaveNewIntegrations verifies RegisterFuzzEnterpriseFlags
func TestOutputFlags_FuzzEnterpriseFlagsHaveNewIntegrations(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterFuzzEnterpriseFlags(fs)

	criticalFlags := []string{
		"jira-labels",
		"jira-assignee",
		"ado-tags",
	}

	for _, flagName := range criticalFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("critical: --%s missing from RegisterFuzzEnterpriseFlags", flagName)
		}
	}
}

// TestOutputFlags_BypassEnterpriseFlagsHaveNewIntegrations verifies RegisterBypassEnterpriseFlags
func TestOutputFlags_BypassEnterpriseFlagsHaveNewIntegrations(t *testing.T) {
	flags := &OutputFlags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.RegisterBypassEnterpriseFlags(fs)

	criticalFlags := []string{
		"jira-labels",
		"jira-assignee",
		"ado-tags",
	}

	for _, flagName := range criticalFlags {
		f := fs.Lookup(flagName)
		if f == nil {
			t.Errorf("critical: --%s missing from RegisterBypassEnterpriseFlags", flagName)
		}
	}
}

// =============================================================================
// Stats Flag Exclusion Tests
// =============================================================================
// These tests verify that stats-json (and stats/stats-interval) are correctly
// included or excluded per Register* variant. This guards against future
// refactors accidentally adding stats flags to variants where the calling
// command already defines them (which would cause a flag redefinition panic).

func TestOutputFlags_StatsFlagPresenceByVariant(t *testing.T) {
	statsFlags := []string{"stats", "stats-json", "stats-interval"}

	// These variants SHOULD register stats flags
	shouldHave := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterEnterpriseFlags":       (*OutputFlags).RegisterEnterpriseFlags,
		"RegisterFuzzEnterpriseFlags":   (*OutputFlags).RegisterFuzzEnterpriseFlags,
		"RegisterBypassEnterpriseFlags": (*OutputFlags).RegisterBypassEnterpriseFlags,
	}

	// These variants must NOT register stats flags (caller already defines them)
	shouldNotHave := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterRunEnterpriseFlags":   (*OutputFlags).RegisterRunEnterpriseFlags,
		"RegisterProbeEnterpriseFlags": (*OutputFlags).RegisterProbeEnterpriseFlags,
	}

	for name, reg := range shouldHave {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		for _, flagName := range statsFlags {
			if fs.Lookup(flagName) == nil {
				t.Errorf("%s: --%s should be registered but is missing", name, flagName)
			}
		}
	}

	for name, reg := range shouldNotHave {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		for _, flagName := range statsFlags {
			if fs.Lookup(flagName) != nil {
				t.Errorf("%s: --%s should NOT be registered (caller already defines it)", name, flagName)
			}
		}
	}
}

// =============================================================================
// ToConfig() Integration Tests
// =============================================================================
// These tests verify that ToConfig() correctly passes all values to output.Config

func TestOutputFlags_ToConfig_PassesJiraValues(t *testing.T) {
	flags := &OutputFlags{
		JiraURL:       "https://jira.example.com",
		JiraProject:   "SEC",
		JiraEmail:     "test@example.com",
		JiraToken:     "test-token",
		JiraIssueType: "Task",
		JiraLabels:    "security,waf-bypass",
		JiraAssignee:  "account-id-123",
		Version:       "test",
	}

	cfg := flags.ToConfig()

	if cfg.JiraURL != flags.JiraURL {
		t.Errorf("JiraURL not passed: expected %q, got %q", flags.JiraURL, cfg.JiraURL)
	}
	if cfg.JiraProject != flags.JiraProject {
		t.Errorf("JiraProject not passed: expected %q, got %q", flags.JiraProject, cfg.JiraProject)
	}
	if cfg.JiraEmail != flags.JiraEmail {
		t.Errorf("JiraEmail not passed: expected %q, got %q", flags.JiraEmail, cfg.JiraEmail)
	}
	if cfg.JiraToken != flags.JiraToken {
		t.Errorf("JiraToken not passed: expected %q, got %q", flags.JiraToken, cfg.JiraToken)
	}
	if cfg.JiraIssueType != flags.JiraIssueType {
		t.Errorf("JiraIssueType not passed: expected %q, got %q", flags.JiraIssueType, cfg.JiraIssueType)
	}
	if cfg.JiraLabels != flags.JiraLabels {
		t.Errorf("JiraLabels not passed: expected %q, got %q", flags.JiraLabels, cfg.JiraLabels)
	}
	if cfg.JiraAssignee != flags.JiraAssignee {
		t.Errorf("JiraAssignee not passed: expected %q, got %q", flags.JiraAssignee, cfg.JiraAssignee)
	}
}

func TestOutputFlags_ToConfig_PassesGitHubIssuesValues(t *testing.T) {
	flags := &OutputFlags{
		GitHubIssuesToken:     "ghp_test123",
		GitHubIssuesOwner:     "testorg",
		GitHubIssuesRepo:      "testrepo",
		GitHubIssuesURL:       "https://github.mycompany.com/api/v3",
		GitHubIssuesLabels:    "security,waf-bypass",
		GitHubIssuesAssignees: "user1,user2",
		Version:               "test",
	}

	cfg := flags.ToConfig()

	if cfg.GitHubIssuesToken != flags.GitHubIssuesToken {
		t.Errorf("GitHubIssuesToken not passed: expected %q, got %q", flags.GitHubIssuesToken, cfg.GitHubIssuesToken)
	}
	if cfg.GitHubIssuesOwner != flags.GitHubIssuesOwner {
		t.Errorf("GitHubIssuesOwner not passed: expected %q, got %q", flags.GitHubIssuesOwner, cfg.GitHubIssuesOwner)
	}
	if cfg.GitHubIssuesRepo != flags.GitHubIssuesRepo {
		t.Errorf("GitHubIssuesRepo not passed: expected %q, got %q", flags.GitHubIssuesRepo, cfg.GitHubIssuesRepo)
	}
	if cfg.GitHubIssuesURL != flags.GitHubIssuesURL {
		t.Errorf("GitHubIssuesURL not passed: expected %q, got %q", flags.GitHubIssuesURL, cfg.GitHubIssuesURL)
	}
	if cfg.GitHubIssuesLabels != flags.GitHubIssuesLabels {
		t.Errorf("GitHubIssuesLabels not passed: expected %q, got %q", flags.GitHubIssuesLabels, cfg.GitHubIssuesLabels)
	}
	if cfg.GitHubIssuesAssignees != flags.GitHubIssuesAssignees {
		t.Errorf("GitHubIssuesAssignees not passed: expected %q, got %q", flags.GitHubIssuesAssignees, cfg.GitHubIssuesAssignees)
	}
}

func TestOutputFlags_ToConfig_PassesAzureDevOpsValues(t *testing.T) {
	flags := &OutputFlags{
		ADOOrganization:  "testorg",
		ADOProject:       "testproj",
		ADOPAT:           "test-pat-123",
		ADOWorkItemType:  "Task",
		ADOAreaPath:      "TestOrg\\Security",
		ADOIterationPath: "TestOrg\\Sprint1",
		ADOAssignedTo:    "user@example.com",
		ADOTags:          "security;waf-bypass;P1",
		Version:          "test",
	}

	cfg := flags.ToConfig()

	if cfg.ADOOrganization != flags.ADOOrganization {
		t.Errorf("ADOOrganization not passed: expected %q, got %q", flags.ADOOrganization, cfg.ADOOrganization)
	}
	if cfg.ADOProject != flags.ADOProject {
		t.Errorf("ADOProject not passed: expected %q, got %q", flags.ADOProject, cfg.ADOProject)
	}
	if cfg.ADOPAT != flags.ADOPAT {
		t.Errorf("ADOPAT not passed: expected %q, got %q", flags.ADOPAT, cfg.ADOPAT)
	}
	if cfg.ADOWorkItemType != flags.ADOWorkItemType {
		t.Errorf("ADOWorkItemType not passed: expected %q, got %q", flags.ADOWorkItemType, cfg.ADOWorkItemType)
	}
	if cfg.ADOAreaPath != flags.ADOAreaPath {
		t.Errorf("ADOAreaPath not passed: expected %q, got %q", flags.ADOAreaPath, cfg.ADOAreaPath)
	}
	if cfg.ADOIterationPath != flags.ADOIterationPath {
		t.Errorf("ADOIterationPath not passed: expected %q, got %q", flags.ADOIterationPath, cfg.ADOIterationPath)
	}
	if cfg.ADOAssignedTo != flags.ADOAssignedTo {
		t.Errorf("ADOAssignedTo not passed: expected %q, got %q", flags.ADOAssignedTo, cfg.ADOAssignedTo)
	}
	if cfg.ADOTags != flags.ADOTags {
		t.Errorf("ADOTags not passed: expected %q, got %q", flags.ADOTags, cfg.ADOTags)
	}
}

// =============================================================================
// OutputFlags Struct Field Tests
// =============================================================================
// These tests verify that OutputFlags struct has all the required fields

func TestOutputFlags_HasJiraFields(t *testing.T) {
	flags := OutputFlags{
		JiraURL:       "https://jira.example.com",
		JiraProject:   "SEC",
		JiraEmail:     "test@example.com",
		JiraToken:     "test-token",
		JiraIssueType: "Bug",
		JiraLabels:    "security,waf-bypass",
		JiraAssignee:  "account-id",
	}

	// Verify all fields are settable
	if flags.JiraURL == "" {
		t.Error("JiraURL field missing")
	}
	if flags.JiraProject == "" {
		t.Error("JiraProject field missing")
	}
	if flags.JiraLabels == "" {
		t.Error("JiraLabels field missing")
	}
	if flags.JiraAssignee == "" {
		t.Error("JiraAssignee field missing")
	}
}

func TestOutputFlags_HasGitHubIssuesFields(t *testing.T) {
	flags := OutputFlags{
		GitHubIssuesToken:     "ghp_test123",
		GitHubIssuesOwner:     "testorg",
		GitHubIssuesRepo:      "testrepo",
		GitHubIssuesURL:       "https://github.mycompany.com/api/v3",
		GitHubIssuesLabels:    "security,waf-bypass",
		GitHubIssuesAssignees: "user1,user2",
	}

	if flags.GitHubIssuesToken == "" {
		t.Error("GitHubIssuesToken field missing")
	}
	if flags.GitHubIssuesOwner == "" {
		t.Error("GitHubIssuesOwner field missing")
	}
	if flags.GitHubIssuesRepo == "" {
		t.Error("GitHubIssuesRepo field missing")
	}
	if flags.GitHubIssuesURL == "" {
		t.Error("GitHubIssuesURL field missing")
	}
	if flags.GitHubIssuesLabels == "" {
		t.Error("GitHubIssuesLabels field missing")
	}
	if flags.GitHubIssuesAssignees == "" {
		t.Error("GitHubIssuesAssignees field missing")
	}
}

func TestOutputFlags_HasAzureDevOpsFields(t *testing.T) {
	flags := OutputFlags{
		ADOOrganization:  "testorg",
		ADOProject:       "testproj",
		ADOPAT:           "test-pat",
		ADOWorkItemType:  "Bug",
		ADOAreaPath:      "TestOrg\\Security",
		ADOIterationPath: "TestOrg\\Sprint1",
		ADOAssignedTo:    "user@example.com",
		ADOTags:          "security;waf-bypass",
	}

	if flags.ADOOrganization == "" {
		t.Error("ADOOrganization field missing")
	}
	if flags.ADOProject == "" {
		t.Error("ADOProject field missing")
	}
	if flags.ADOPAT == "" {
		t.Error("ADOPAT field missing")
	}
	if flags.ADOWorkItemType == "" {
		t.Error("ADOWorkItemType field missing")
	}
	if flags.ADOAreaPath == "" {
		t.Error("ADOAreaPath field missing")
	}
	if flags.ADOIterationPath == "" {
		t.Error("ADOIterationPath field missing")
	}
	if flags.ADOAssignedTo == "" {
		t.Error("ADOAssignedTo field missing")
	}
	if flags.ADOTags == "" {
		t.Error("ADOTags field missing")
	}
}

// =============================================================================
// New Feature Flag Registration Tests
// =============================================================================
// These tests verify that XML, Elasticsearch, History, and TemplateConfig
// flags are properly wired into all RegisterFlags variants.

func TestOutputFlags_XMLExportFlagRegistered(t *testing.T) {
	variants := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterFlags":                 (*OutputFlags).RegisterFlags,
		"RegisterEnterpriseFlags":       (*OutputFlags).RegisterEnterpriseFlags,
		"RegisterRunEnterpriseFlags":    (*OutputFlags).RegisterRunEnterpriseFlags,
		"RegisterProbeEnterpriseFlags":  (*OutputFlags).RegisterProbeEnterpriseFlags,
		"RegisterFuzzEnterpriseFlags":   (*OutputFlags).RegisterFuzzEnterpriseFlags,
		"RegisterBypassEnterpriseFlags": (*OutputFlags).RegisterBypassEnterpriseFlags,
	}

	for name, reg := range variants {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		if fs.Lookup("xml-export") == nil {
			t.Errorf("%s: --xml-export flag missing", name)
		}
	}
}

func TestOutputFlags_ElasticsearchFlagsRegistered(t *testing.T) {
	esFlags := []string{
		"elasticsearch-url",
		"elasticsearch-api-key",
		"elasticsearch-username",
		"elasticsearch-password",
		"elasticsearch-index",
		"elasticsearch-insecure",
	}

	variants := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterFlags":                 (*OutputFlags).RegisterFlags,
		"RegisterEnterpriseFlags":       (*OutputFlags).RegisterEnterpriseFlags,
		"RegisterRunEnterpriseFlags":    (*OutputFlags).RegisterRunEnterpriseFlags,
		"RegisterProbeEnterpriseFlags":  (*OutputFlags).RegisterProbeEnterpriseFlags,
		"RegisterFuzzEnterpriseFlags":   (*OutputFlags).RegisterFuzzEnterpriseFlags,
		"RegisterBypassEnterpriseFlags": (*OutputFlags).RegisterBypassEnterpriseFlags,
	}

	for name, reg := range variants {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		for _, flagName := range esFlags {
			if fs.Lookup(flagName) == nil {
				t.Errorf("%s: --%s flag missing", name, flagName)
			}
		}
	}
}

func TestOutputFlags_HistoryFlagsRegistered(t *testing.T) {
	historyFlags := []string{"history-path", "history-tags"}

	variants := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterFlags":                 (*OutputFlags).RegisterFlags,
		"RegisterEnterpriseFlags":       (*OutputFlags).RegisterEnterpriseFlags,
		"RegisterRunEnterpriseFlags":    (*OutputFlags).RegisterRunEnterpriseFlags,
		"RegisterProbeEnterpriseFlags":  (*OutputFlags).RegisterProbeEnterpriseFlags,
		"RegisterFuzzEnterpriseFlags":   (*OutputFlags).RegisterFuzzEnterpriseFlags,
		"RegisterBypassEnterpriseFlags": (*OutputFlags).RegisterBypassEnterpriseFlags,
	}

	for name, reg := range variants {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		for _, flagName := range historyFlags {
			if fs.Lookup(flagName) == nil {
				t.Errorf("%s: --%s flag missing", name, flagName)
			}
		}
	}
}

func TestOutputFlags_TemplateConfigFlagRegistered(t *testing.T) {
	variants := map[string]func(*OutputFlags, *flag.FlagSet){
		"RegisterFlags":                 (*OutputFlags).RegisterFlags,
		"RegisterEnterpriseFlags":       (*OutputFlags).RegisterEnterpriseFlags,
		"RegisterRunEnterpriseFlags":    (*OutputFlags).RegisterRunEnterpriseFlags,
		"RegisterProbeEnterpriseFlags":  (*OutputFlags).RegisterProbeEnterpriseFlags,
		"RegisterFuzzEnterpriseFlags":   (*OutputFlags).RegisterFuzzEnterpriseFlags,
		"RegisterBypassEnterpriseFlags": (*OutputFlags).RegisterBypassEnterpriseFlags,
	}

	for name, reg := range variants {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		reg(&OutputFlags{}, fs)
		if fs.Lookup("template-config") == nil {
			t.Errorf("%s: --template-config flag missing", name)
		}
	}
}

func TestOutputFlags_ToConfig_PassesNewFeatureValues(t *testing.T) {
	flags := &OutputFlags{
		XMLExport:             "/tmp/report.xml",
		ElasticsearchURL:      "http://localhost:9200",
		ElasticsearchAPIKey:   "test-api-key",
		ElasticsearchUsername: "elastic",
		ElasticsearchPassword: "secret",
		ElasticsearchIndex:    "waftester-test",
		ElasticsearchInsecure: true,
		HistoryPath:           "/tmp/history",
		HistoryTags:           "tag1,tag2,tag3",
		TemplateConfigPath:    "/tmp/template.yaml",
		Version:               "test",
	}

	cfg := flags.ToConfig()

	if cfg.XMLExport != flags.XMLExport {
		t.Errorf("XMLExport not passed: expected %q, got %q", flags.XMLExport, cfg.XMLExport)
	}
	if cfg.ElasticsearchURL != flags.ElasticsearchURL {
		t.Errorf("ElasticsearchURL not passed: expected %q, got %q", flags.ElasticsearchURL, cfg.ElasticsearchURL)
	}
	if cfg.ElasticsearchAPIKey != flags.ElasticsearchAPIKey {
		t.Errorf("ElasticsearchAPIKey not passed")
	}
	if cfg.ElasticsearchUsername != flags.ElasticsearchUsername {
		t.Errorf("ElasticsearchUsername not passed")
	}
	if cfg.ElasticsearchPassword != flags.ElasticsearchPassword {
		t.Errorf("ElasticsearchPassword not passed")
	}
	if cfg.ElasticsearchIndex != flags.ElasticsearchIndex {
		t.Errorf("ElasticsearchIndex not passed")
	}
	if !cfg.ElasticsearchInsecure {
		t.Error("ElasticsearchInsecure not passed")
	}
	if cfg.HistoryPath != flags.HistoryPath {
		t.Errorf("HistoryPath not passed: expected %q, got %q", flags.HistoryPath, cfg.HistoryPath)
	}
	if len(cfg.HistoryTags) != 3 || cfg.HistoryTags[0] != "tag1" || cfg.HistoryTags[1] != "tag2" || cfg.HistoryTags[2] != "tag3" {
		t.Errorf("HistoryTags not parsed correctly: got %v", cfg.HistoryTags)
	}
	if cfg.TemplateConfigPath != flags.TemplateConfigPath {
		t.Errorf("TemplateConfigPath not passed: expected %q, got %q", flags.TemplateConfigPath, cfg.TemplateConfigPath)
	}
}
