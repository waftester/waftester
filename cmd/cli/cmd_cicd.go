package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/waftester/waftester/pkg/cicd"
	"github.com/waftester/waftester/pkg/ui"
)

// =============================================================================
// CICD COMMAND - CI/CD Pipeline Generator
// =============================================================================

func runCICD() {
	ui.PrintCompactBanner()
	ui.PrintSection("CI/CD Pipeline Generator")

	cicdFlags := flag.NewFlagSet("cicd", flag.ExitOnError)

	// Platform options
	platform := cicdFlags.String("platform", "", "CI/CD platform: github-actions, gitlab-ci, jenkins, azure-devops, circleci, bitbucket")
	platformShort := cicdFlags.String("p", "", "Platform (shorthand)")
	listPlatforms := cicdFlags.Bool("list", false, "List supported platforms")

	// Target options
	targetURL := cicdFlags.String("target", "", "Target URL or environment variable (e.g., ${{ secrets.TARGET_URL }})")
	targetShort := cicdFlags.String("u", "", "Target URL (shorthand)")

	// Scan configuration
	scanners := cicdFlags.String("scanners", "all", "Scanners to run: all, sqli, xss, injection, bypass")
	failOnHigh := cicdFlags.Bool("fail-high", true, "Fail build on high severity findings")
	failOnMedium := cicdFlags.Bool("fail-medium", false, "Fail build on medium severity findings")

	// Trigger options
	onPush := cicdFlags.Bool("on-push", true, "Trigger on push")
	onPR := cicdFlags.Bool("on-pr", true, "Trigger on pull request")
	onSchedule := cicdFlags.Bool("on-schedule", false, "Trigger on schedule")
	scheduleCron := cicdFlags.String("cron", "0 0 * * *", "Cron schedule (when --on-schedule)")
	branches := cicdFlags.String("branches", "main,master", "Branches to trigger on (comma-separated)")

	// Execution options
	timeout := cicdFlags.String("timeout", "30m", "Job timeout")
	concurrency := cicdFlags.Int("concurrency", 50, "Request concurrency")
	rateLimit := cicdFlags.Int("rate-limit", 10, "Requests per second")

	// Output options
	outputFormat := cicdFlags.String("output-format", "sarif", "Output format: sarif, json, csv")
	uploadArtifacts := cicdFlags.Bool("upload-artifacts", true, "Upload scan results as artifacts")

	// Notifications
	slackNotify := cicdFlags.Bool("slack", false, "Enable Slack notifications")
	slackWebhook := cicdFlags.String("slack-webhook", "SLACK_WEBHOOK_URL", "Slack webhook env var name")

	// Output file
	outputFile := cicdFlags.String("o", "", "Output file (default: stdout)")

	// Docker options
	dockerImage := cicdFlags.String("docker-image", "", "Custom Docker image")
	wafTesterVersion := cicdFlags.String("version", "latest", "WAFtester version to use")

	cicdFlags.Parse(os.Args[2:])

	generator := cicd.NewGenerator()

	// List platforms
	if *listPlatforms {
		ui.PrintSection("Supported CI/CD Platforms")
		for _, p := range generator.ListPlatforms() {
			fmt.Printf("  %s %s\n", ui.Icon("•", "-"), p)
		}
		fmt.Println()
		fmt.Println("Usage: waf-tester cicd -p <platform> -u <target>")
		return
	}

	// Get platform
	platformName := *platform
	if platformName == "" {
		platformName = *platformShort
	}
	if platformName == "" {
		ui.PrintError("Platform required. Use --list to see supported platforms.")
		os.Exit(1)
	}

	// Normalize platform name
	platformName = strings.ToLower(platformName)
	platformName = strings.ReplaceAll(platformName, "_", "-")

	// Map shortcuts
	switch platformName {
	case "github", "gh", "gha":
		platformName = "github-actions"
	case "gitlab", "gl":
		platformName = "gitlab-ci"
	case "azure", "ado":
		platformName = "azure-devops"
	case "circle":
		platformName = "circleci"
	case "bb":
		platformName = "bitbucket"
	}

	p := cicd.Platform(platformName)
	if !generator.HasPlatform(p) {
		ui.PrintError(fmt.Sprintf("Unsupported platform: %s", platformName))
		fmt.Println("Use --list to see supported platforms")
		os.Exit(1)
	}

	// Get target
	target := *targetURL
	if target == "" {
		target = *targetShort
	}
	if target == "" {
		// Use platform-specific env var syntax
		switch p {
		case cicd.PlatformGitHubActions:
			target = "${{ secrets.TARGET_URL }}"
		case cicd.PlatformGitLabCI:
			target = "$TARGET_URL"
		case cicd.PlatformJenkins:
			target = "${TARGET_URL}"
		case cicd.PlatformAzureDevOps:
			target = "$(TARGET_URL)"
		default:
			target = "$TARGET_URL"
		}
	}

	ui.PrintConfigLine("Platform", string(p))
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Scanners", *scanners)
	fmt.Println()

	// Build configuration
	config := &cicd.TemplateConfig{
		Platform:         p,
		TargetURL:        target,
		Scanners:         strings.Split(*scanners, ","),
		FailOnHigh:       *failOnHigh,
		FailOnMedium:     *failOnMedium,
		OnPush:           *onPush,
		OnPullRequest:    *onPR,
		OnSchedule:       *onSchedule,
		ScheduleCron:     *scheduleCron,
		Branches:         strings.Split(*branches, ","),
		OutputFormat:     *outputFormat,
		UploadArtifacts:  *uploadArtifacts,
		NotifySlack:      *slackNotify,
		SlackWebhook:     *slackWebhook,
		Timeout:          *timeout,
		ConcurrencyLimit: *concurrency,
		RateLimit:        *rateLimit,
		WafTesterVersion: *wafTesterVersion,
		DockerImage:      *dockerImage,
	}

	// Generate template
	output, err := generator.Generate(config)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to generate template: %v", err))
		os.Exit(1)
	}

	// Output
	if *outputFile != "" {
		// Create directory if needed
		dir := filepath.Dir(*outputFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create directory: %v", err))
			os.Exit(1)
		}

		if err := os.WriteFile(*outputFile, []byte(output), 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to write file: %v", err))
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Pipeline written to %s", *outputFile))
	} else {
		fmt.Println(output)
	}

	// Print suggested file location
	if *outputFile == "" {
		fmt.Println()
		ui.PrintSection("Suggested File Location")
		switch p {
		case cicd.PlatformGitHubActions:
			fmt.Println("  .github/workflows/waf-security.yml")
		case cicd.PlatformGitLabCI:
			fmt.Println("  .gitlab-ci.yml (merge with existing)")
		case cicd.PlatformJenkins:
			fmt.Println("  Jenkinsfile")
		case cicd.PlatformAzureDevOps:
			fmt.Println("  azure-pipelines.yml")
		case cicd.PlatformCircleCI:
			fmt.Println("  .circleci/config.yml")
		case cicd.PlatformBitbucket:
			fmt.Println("  bitbucket-pipelines.yml")
		}
	}
}
