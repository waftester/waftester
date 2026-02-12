package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ═══════════════════════════════════════════════════════════════════════════
// generate_cicd — CI/CD Pipeline Generation
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) addGenerateCICDTool() {
	s.mcp.AddTool(
		&mcp.Tool{
			Name:  "generate_cicd",
			Title: "Generate CI/CD Pipeline",
			Description: `Generate a ready-to-use CI/CD pipeline config for automated WAF testing. Copy-paste output into your repo.

USE THIS TOOL WHEN:
• The user says "set up CI/CD for WAF testing" or "GitHub Actions for WAF" or "automate this"
• Creating recurring WAF regression tests that run on push/schedule
• Integrating WAF checks into an existing deployment pipeline

DO NOT USE THIS TOOL WHEN:
• You want to run a scan right now — use 'scan' or 'assess' instead
• You want to detect the WAF — use 'detect_waf' instead
• You need discovery or recon — use 'discover' instead

This is OFFLINE code generation. No network requests to any target. Produces a complete, ready-to-commit YAML/Groovy pipeline file for the chosen platform.

EXAMPLE INPUTS:
• GitHub Actions: {"platform": "github", "target": "https://staging.example.com", "scan_types": ["sqli", "xss"]}
• GitLab CI: {"platform": "gitlab", "target": "https://app.example.com"}
• Jenkins: {"platform": "jenkins", "target": "https://internal.app"}
• Azure DevOps: {"platform": "azure-devops", "target": "https://myapp.azurewebsites.net"}
• CircleCI: {"platform": "circleci", "target": "https://api.example.com", "scan_types": ["sqli"]}
• Bitbucket: {"platform": "bitbucket", "target": "https://example.com"}
• With schedule: {"platform": "github", "target": "https://example.com", "schedule": "0 2 * * 1"}

PLATFORMS: github, gitlab, jenkins, azure-devops, circleci, bitbucket

Returns: complete pipeline YAML/Groovy, ready to paste into your repo and commit.`,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"platform": map[string]any{
						"type":        "string",
						"description": "CI/CD platform to generate config for.",
						"enum":        []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"},
					},
					"target": map[string]any{
						"type":        "string",
						"description": "Target URL for WAF testing (can use environment variable like $TARGET_URL).",
					},
					"scan_types": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Vulnerability scan types to include. Example: [\"sqli\", \"xss\"].",
					},
					"schedule": map[string]any{
						"type":        "string",
						"description": "Cron schedule for automated runs (e.g. '0 2 * * 1' for weekly Monday 2am).",
					},
				},
				"required": []string{"platform", "target"},
			},
			Annotations: &mcp.ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				Title:          "Generate CI/CD Pipeline",
			},
		},
		loggedTool("generate_cicd", s.handleGenerateCICD),
	)
}

type cicdArgs struct {
	Platform  string   `json:"platform"`
	Target    string   `json:"target"`
	ScanTypes []string `json:"scan_types"`
	Schedule  string   `json:"schedule"`
}

func (s *Server) handleGenerateCICD(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	var args cicdArgs
	if err := parseArgs(req, &args); err != nil {
		return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
	}

	if args.Platform == "" {
		return errorResult("platform is required. Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket"), nil
	}
	validPlatforms := map[string]bool{
		"github": true, "gitlab": true, "jenkins": true,
		"azure-devops": true, "circleci": true, "bitbucket": true,
	}
	if !validPlatforms[args.Platform] {
		return errorResult(fmt.Sprintf("unsupported platform %q. Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket", args.Platform)), nil
	}
	if args.Target == "" {
		return errorResult("target URL is required."), nil
	}

	pipeline := generateCICDConfig(args)

	// Build structured response with the same envelope as all other tools.
	resp := buildCICDResponse(pipeline, args)
	return jsonResult(resp)
}

// cicdResponse wraps generated CI/CD pipeline config with structured metadata
// and actionable next steps for AI agent consumption.
type cicdResponse struct {
	Summary   string   `json:"summary"`
	Platform  string   `json:"platform"`
	FileName  string   `json:"file_name"`
	Pipeline  string   `json:"pipeline"`
	NextSteps []string `json:"next_steps"`
}

func buildCICDResponse(pipeline string, args cicdArgs) *cicdResponse {
	fileNames := map[string]string{
		"github":       ".github/workflows/waf-test.yml",
		"gitlab":       ".gitlab-ci.yml",
		"jenkins":      "Jenkinsfile",
		"azure-devops": "azure-pipelines.yml",
		"circleci":     ".circleci/config.yml",
		"bitbucket":    "bitbucket-pipelines.yml",
	}

	fileName := fileNames[args.Platform]
	if fileName == "" {
		fileName = "pipeline-config"
	}

	scanTypes := "sqli,xss"
	if len(args.ScanTypes) > 0 {
		scanTypes = strings.Join(args.ScanTypes, ",")
	}

	summary := fmt.Sprintf("Generated %s CI/CD pipeline targeting %s with scan types [%s]. Save as %s in your repository.",
		args.Platform, args.Target, scanTypes, fileName)

	nextSteps := []string{
		fmt.Sprintf("Save the 'pipeline' content as %s in your repository and commit.", fileName),
		"SECURITY: Replace the hardcoded target URL with a secret/environment variable before deploying to production.",
		"Adjust concurrency and rate_limit values for your target environment (conservative for production, aggressive for staging).",
		"Set up notifications (Slack, email, PagerDuty) for failed WAF tests so security regressions are caught immediately.",
		"Use 'assess' instead of 'scan' in the pipeline for formal enterprise grading with F1 score and letter grade.",
	}
	if args.Schedule != "" {
		nextSteps = append(nextSteps,
			fmt.Sprintf("Scheduled scans configured with cron '%s'. Verify the schedule matches your maintenance window.", args.Schedule))
	}

	return &cicdResponse{
		Summary:   summary,
		Platform:  args.Platform,
		FileName:  fileName,
		Pipeline:  pipeline,
		NextSteps: nextSteps,
	}
}

func generateCICDConfig(args cicdArgs) string {
	scanTypes := "sqli,xss"
	if len(args.ScanTypes) > 0 {
		scanTypes = strings.Join(args.ScanTypes, ",")
	}

	switch args.Platform {
	case "github":
		return generateGitHubActions(args.Target, scanTypes, args.Schedule)
	case "gitlab":
		return generateGitLabCI(args.Target, scanTypes, args.Schedule)
	case "jenkins":
		return generateJenkinsfile(args.Target, scanTypes)
	case "azure-devops":
		return generateAzureDevOps(args.Target, scanTypes)
	case "circleci":
		return generateCircleCI(args.Target, scanTypes)
	case "bitbucket":
		return generateBitbucket(args.Target, scanTypes)
	default:
		return fmt.Sprintf("# Unsupported platform: %s\n# Supported: github, gitlab, jenkins, azure-devops, circleci, bitbucket", args.Platform)
	}
}

func generateGitHubActions(target, scanTypes, schedule string) string {
	cron := ""
	if schedule != "" {
		cron = fmt.Sprintf("\n  schedule:\n    - cron: '%s'", schedule)
	}
	return fmt.Sprintf(`name: WAF Security Testing
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]%s

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install waf-tester
        run: |
          curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          chmod +x waf-tester

      - name: Run WAF Security Scan
        run: |
          ./waf-tester scan -u %s -types %s \
            -format sarif -o results.sarif \
            -c 10 -rl 50

      - name: Upload SARIF Results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
`, cron, target, scanTypes)
}

func generateGitLabCI(target, scanTypes, schedule string) string {
	scheduleNote := ""
	if schedule != "" {
		scheduleNote = fmt.Sprintf("\n# Schedule: %s (configure in GitLab CI/CD > Schedules)", schedule)
	}
	return fmt.Sprintf(`%s
waf-security-test:
  stage: test
  image: golang:1.24
  script:
    - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
    - chmod +x waf-tester
    - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
  artifacts:
    paths:
      - results.json
    expire_in: 30 days
`, scheduleNote, target, scanTypes)
}

func generateJenkinsfile(target, scanTypes string) string {
	return fmt.Sprintf(`pipeline {
    agent any
    stages {
        stage('WAF Security Test') {
            steps {
                sh '''
                    curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
                    chmod +x waf-tester
                    ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.json'
                }
            }
        }
    }
}
`, target, scanTypes)
}

func generateAzureDevOps(target, scanTypes string) string {
	return fmt.Sprintf(`trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
      chmod +x waf-tester
      ./waf-tester scan -u %s -types %s -format json -o $(Build.ArtifactStagingDirectory)/results.json -c 10 -rl 50
    displayName: 'Run WAF Security Scan'

  - publish: $(Build.ArtifactStagingDirectory)/results.json
    artifact: waf-test-results
`, target, scanTypes)
}

func generateCircleCI(target, scanTypes string) string {
	return fmt.Sprintf(`version: 2.1
jobs:
  waf-test:
    docker:
      - image: cimg/go:1.24
    steps:
      - checkout
      - run:
          name: Install waf-tester
          command: |
            curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
            chmod +x waf-tester
      - run:
          name: Run WAF Security Scan
          command: ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
      - store_artifacts:
          path: results.json

workflows:
  security:
    jobs:
      - waf-test
`, target, scanTypes)
}

func generateBitbucket(target, scanTypes string) string {
	return fmt.Sprintf(`pipelines:
  default:
    - step:
        name: WAF Security Test
        image: golang:1.24
        script:
          - curl -sL https://github.com/waftester/waftester/releases/latest/download/waf-tester_linux_amd64 -o waf-tester
          - chmod +x waf-tester
          - ./waf-tester scan -u %s -types %s -format json -o results.json -c 10 -rl 50
        artifacts:
          - results.json
`, target, scanTypes)
}
