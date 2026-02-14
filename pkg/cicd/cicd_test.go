package cicd

import (
	"strings"
	"testing"
)

func TestPlatforms(t *testing.T) {
	if PlatformGitHubActions != "github-actions" {
		t.Error("unexpected GitHub Actions platform value")
	}
	if PlatformGitLabCI != "gitlab-ci" {
		t.Error("unexpected GitLab CI platform value")
	}
	if PlatformJenkins != "jenkins" {
		t.Error("unexpected Jenkins platform value")
	}
	if PlatformAzureDevOps != "azure-devops" {
		t.Error("unexpected Azure DevOps platform value")
	}
	if PlatformCircleCI != "circleci" {
		t.Error("unexpected CircleCI platform value")
	}
	if PlatformBitbucket != "bitbucket" {
		t.Error("unexpected Bitbucket platform value")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")

	if config.Platform != PlatformGitHubActions {
		t.Errorf("expected github-actions, got %s", config.Platform)
	}
	if config.TargetURL != "https://example.com" {
		t.Errorf("expected https://example.com, got %s", config.TargetURL)
	}
	if len(config.Scanners) != 1 || config.Scanners[0] != "all" {
		t.Error("expected default scanners to be ['all']")
	}
	if !config.FailOnHigh {
		t.Error("expected FailOnHigh to be true by default")
	}
	if config.FailOnMedium {
		t.Error("expected FailOnMedium to be false by default")
	}
	if !config.OnPush {
		t.Error("expected OnPush to be true by default")
	}
	if !config.OnPullRequest {
		t.Error("expected OnPullRequest to be true by default")
	}
	if config.OutputFormat != "sarif" {
		t.Errorf("expected sarif format, got %s", config.OutputFormat)
	}
}

func TestNewGenerator(t *testing.T) {
	g := NewGenerator()
	if g == nil {
		t.Fatal("expected non-nil generator")
	}
}

func TestGenerator_ListPlatforms(t *testing.T) {
	g := NewGenerator()
	platforms := g.ListPlatforms()

	if len(platforms) != 6 {
		t.Errorf("expected 6 platforms, got %d", len(platforms))
	}
}

func TestGenerator_HasPlatform(t *testing.T) {
	g := NewGenerator()

	if !g.HasPlatform(PlatformGitHubActions) {
		t.Error("expected to have GitHub Actions")
	}
	if !g.HasPlatform(PlatformGitLabCI) {
		t.Error("expected to have GitLab CI")
	}
	if g.HasPlatform("unknown-platform") {
		t.Error("should not have unknown platform")
	}
}

func TestGenerator_Generate_GitHubActions(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check key elements
	if !strings.Contains(output, "name: WAF Security Scan") {
		t.Error("missing workflow name")
	}
	if !strings.Contains(output, "waf-tester run") {
		t.Error("missing waf-tester command")
	}
	if !strings.Contains(output, "https://example.com") {
		t.Error("missing target URL")
	}
	if !strings.Contains(output, "ubuntu-latest") {
		t.Error("missing runner")
	}
}

func TestGenerator_Generate_GitLabCI(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitLabCI, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "stages:") {
		t.Error("missing stages")
	}
	if !strings.Contains(output, "waf-tester run") {
		t.Error("missing waf-tester command")
	}
}

func TestGenerator_Generate_Jenkins(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformJenkins, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "pipeline {") {
		t.Error("missing pipeline block")
	}
	if !strings.Contains(output, "stages {") {
		t.Error("missing stages block")
	}
}

func TestGenerator_Generate_AzureDevOps(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformAzureDevOps, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "trigger:") {
		t.Error("missing trigger")
	}
	if !strings.Contains(output, "stages:") {
		t.Error("missing stages")
	}
}

func TestGenerator_Generate_CircleCI(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformCircleCI, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "version: 2.1") {
		t.Error("missing version")
	}
	if !strings.Contains(output, "jobs:") {
		t.Error("missing jobs")
	}
}

func TestGenerator_Generate_Bitbucket(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformBitbucket, "https://example.com")

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "image: alpine:3") {
		t.Error("missing image")
	}
	if !strings.Contains(output, "pipelines:") {
		t.Error("missing pipelines")
	}
}

func TestGenerator_Generate_InstallPattern(t *testing.T) {
	g := NewGenerator()

	// Every platform must use the curl binary download pattern with the correct
	// GoReleaser archive name — NOT go install.
	for _, platform := range g.ListPlatforms() {
		config := DefaultConfig(platform, "https://example.com")
		output, err := g.Generate(config)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", platform, err)
		}

		if strings.Contains(output, "go install") {
			t.Errorf("%s: template still contains 'go install' — must use binary download", platform)
		}
		if !strings.Contains(output, "waftester_Linux_x86_64.tar.gz") {
			t.Errorf("%s: missing correct GoReleaser archive name (waftester_Linux_x86_64.tar.gz)", platform)
		}
		if !strings.Contains(output, "releases/latest/download/") {
			t.Errorf("%s: missing GitHub Releases latest download URL", platform)
		}
		if !strings.Contains(output, "install -m 755 waf-tester") {
			t.Errorf("%s: missing 'install -m 755 waf-tester' command", platform)
		}
	}
}

func TestGenerator_Generate_NoGoImages(t *testing.T) {
	g := NewGenerator()

	// Templates should not reference Go Docker images since Go is no longer needed.
	for _, platform := range g.ListPlatforms() {
		config := DefaultConfig(platform, "https://example.com")
		output, err := g.Generate(config)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", platform, err)
		}

		for _, img := range []string{"golang:", "cimg/go:"} {
			if strings.Contains(output, img) {
				t.Errorf("%s: template still references Go Docker image %q — Go is not needed for binary download", platform, img)
			}
		}
	}
}

func TestGenerator_Generate_VersionedDownload(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")
	config.WafTesterVersion = "v2.8.8"

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "releases/download/v2.8.8/waftester_Linux_x86_64.tar.gz") {
		t.Error("versioned download URL not correctly templated")
	}
}

func TestGenerator_Generate_UnsupportedPlatform(t *testing.T) {
	g := NewGenerator()
	config := &TemplateConfig{Platform: "unsupported"}

	_, err := g.Generate(config)
	if err == nil {
		t.Error("expected error for unsupported platform")
	}
}

func TestGenerator_Generate_WithSchedule(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")
	config.OnSchedule = true
	config.ScheduleCron = "0 0 * * *"

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "schedule:") {
		t.Error("missing schedule trigger")
	}
	if !strings.Contains(output, "0 0 * * *") {
		t.Error("missing cron expression")
	}
}

func TestGenerator_Generate_WithSlackNotification(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")
	config.NotifySlack = true
	config.SlackWebhook = "SLACK_WEBHOOK"

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Notify Slack") {
		t.Error("missing Slack notification step")
	}
}

func TestGenerator_Generate_WithPrePostCommands(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")
	config.PreCommands = []string{"echo 'Starting scan'"}
	config.PostCommands = []string{"echo 'Scan complete'"}

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Pre-scan command") {
		t.Error("missing pre-scan step")
	}
	if !strings.Contains(output, "Post-scan command") {
		t.Error("missing post-scan step")
	}
}

func TestGenerator_Generate_WithEnvVar(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "")
	config.TargetEnvVar = "secrets.TARGET_URL"

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "secrets.TARGET_URL") {
		t.Error("missing env var reference")
	}
}

func TestGenerator_Generate_MultipleScanners(t *testing.T) {
	g := NewGenerator()
	config := DefaultConfig(PlatformGitHubActions, "https://example.com")
	config.Scanners = []string{"sqli", "xss", "lfi"}

	output, err := g.Generate(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "sqli,xss,lfi") {
		t.Error("missing comma-separated scanners")
	}
}

func TestNewPipelineValidator(t *testing.T) {
	v := NewPipelineValidator()
	if v == nil {
		t.Fatal("expected non-nil validator")
	}
}

func TestPipelineValidator_Validate_Valid(t *testing.T) {
	v := NewPipelineValidator()
	g := NewGenerator()

	for _, platform := range g.ListPlatforms() {
		config := DefaultConfig(platform, "https://example.com")
		content, _ := g.Generate(config)

		err := v.Validate(platform, content)
		if err != nil {
			t.Errorf("validation failed for %s: %v", platform, err)
		}
	}
}

func TestPipelineValidator_Validate_Empty(t *testing.T) {
	v := NewPipelineValidator()

	err := v.Validate(PlatformGitHubActions, "")
	if err == nil {
		t.Error("expected error for empty content")
	}
}

func TestPipelineValidator_Validate_MissingCommand(t *testing.T) {
	v := NewPipelineValidator()

	err := v.Validate(PlatformGitHubActions, "name: Test\njobs:\n  test:\n    steps: []")
	if err == nil {
		t.Error("expected error for missing waf-tester command")
	}
}

func TestPipelineValidator_Validate_UnknownPlatform(t *testing.T) {
	v := NewPipelineValidator()

	err := v.Validate("unknown", "content")
	if err == nil {
		t.Error("expected error for unknown platform")
	}
}

func TestContainsString(t *testing.T) {
	if !containsString("hello world", "world") {
		t.Error("expected to find 'world'")
	}
	if containsString("hello", "world") {
		t.Error("should not find 'world'")
	}
	if !containsString("test", "test") {
		t.Error("expected to find exact match")
	}
	if containsString("", "test") {
		t.Error("should not find in empty string")
	}
}

func TestTemplateConfig_Fields(t *testing.T) {
	config := &TemplateConfig{
		Platform:         PlatformGitHubActions,
		TargetURL:        "https://target.com",
		TargetEnvVar:     "secrets.URL",
		Scanners:         []string{"sqli", "xss"},
		FailOnHigh:       true,
		FailOnMedium:     true,
		ScheduleCron:     "0 2 * * *",
		OnPush:           true,
		OnPullRequest:    true,
		OnSchedule:       true,
		Branches:         []string{"main", "develop"},
		OutputFormat:     "json",
		UploadArtifacts:  true,
		NotifySlack:      true,
		SlackWebhook:     "SLACK_HOOK",
		Timeout:          "1h",
		ConcurrencyLimit: 100,
		RateLimit:        20,
		CustomArgs:       "--debug",
		WafTesterVersion: "v2.5.0",
		DockerImage:      "custom/image:latest",
		PreCommands:      []string{"setup.sh"},
		PostCommands:     []string{"cleanup.sh"},
	}

	if config.Platform != PlatformGitHubActions {
		t.Error("unexpected platform")
	}
	if config.Timeout != "1h" {
		t.Error("unexpected timeout")
	}
	if config.ConcurrencyLimit != 100 {
		t.Error("unexpected concurrency")
	}
}
