// Package cicd provides CI/CD pipeline templates for security testing
package cicd

import (
	"bytes"
	"fmt"
	"text/template"
)

// Platform represents a CI/CD platform
type Platform string

const (
	PlatformGitHubActions Platform = "github-actions"
	PlatformGitLabCI      Platform = "gitlab-ci"
	PlatformJenkins       Platform = "jenkins"
	PlatformAzureDevOps   Platform = "azure-devops"
	PlatformCircleCI      Platform = "circleci"
	PlatformBitbucket     Platform = "bitbucket"
)

// TemplateConfig configures the generated CI/CD template
type TemplateConfig struct {
	Platform         Platform `json:"platform"`
	TargetURL        string   `json:"target_url"`
	TargetEnvVar     string   `json:"target_env_var"`     // e.g., ${{ secrets.TARGET_URL }}
	Scanners         []string `json:"scanners"`           // Which scanners to run
	FailOnHigh       bool     `json:"fail_on_high"`       // Fail build on high severity
	FailOnMedium     bool     `json:"fail_on_medium"`     // Fail build on medium severity
	ScheduleCron     string   `json:"schedule_cron"`      // e.g., "0 0 * * *"
	OnPush           bool     `json:"on_push"`            // Trigger on push
	OnPullRequest    bool     `json:"on_pull_request"`    // Trigger on PR
	OnSchedule       bool     `json:"on_schedule"`        // Trigger on schedule
	Branches         []string `json:"branches"`           // Branch filter
	OutputFormat     string   `json:"output_format"`      // json, sarif, csv
	UploadArtifacts  bool     `json:"upload_artifacts"`   // Upload scan results
	NotifySlack      bool     `json:"notify_slack"`       // Slack notifications
	SlackWebhook     string   `json:"slack_webhook"`      // Slack webhook env var
	Timeout          string   `json:"timeout"`            // Job timeout
	ConcurrencyLimit int      `json:"concurrency_limit"`  // Parallel requests
	RateLimit        int      `json:"rate_limit"`         // Requests per second
	CustomArgs       string   `json:"custom_args"`        // Additional CLI args
	WafTesterVersion string   `json:"waf_tester_version"` // Version to install
	DockerImage      string   `json:"docker_image"`       // Custom Docker image
	PreCommands      []string `json:"pre_commands"`       // Commands before scan
	PostCommands     []string `json:"post_commands"`      // Commands after scan
}

// DefaultConfig returns a default template configuration
func DefaultConfig(platform Platform, targetURL string) *TemplateConfig {
	return &TemplateConfig{
		Platform:         platform,
		TargetURL:        targetURL,
		Scanners:         []string{"all"},
		FailOnHigh:       true,
		FailOnMedium:     false,
		OnPush:           true,
		OnPullRequest:    true,
		Branches:         []string{"main", "master"},
		OutputFormat:     "sarif",
		UploadArtifacts:  true,
		Timeout:          "30m",
		ConcurrencyLimit: 50,
		RateLimit:        10,
		WafTesterVersion: "latest",
	}
}

// Generator generates CI/CD templates
type Generator struct {
	templates map[Platform]*template.Template
}

// NewGenerator creates a new template generator
func NewGenerator() *Generator {
	g := &Generator{
		templates: make(map[Platform]*template.Template),
	}
	g.registerTemplates()
	return g
}

// registerTemplates registers all built-in templates
func (g *Generator) registerTemplates() {
	g.templates[PlatformGitHubActions] = template.Must(template.New("github-actions").Parse(githubActionsTemplate))
	g.templates[PlatformGitLabCI] = template.Must(template.New("gitlab-ci").Parse(gitlabCITemplate))
	g.templates[PlatformJenkins] = template.Must(template.New("jenkins").Parse(jenkinsTemplate))
	g.templates[PlatformAzureDevOps] = template.Must(template.New("azure-devops").Parse(azureDevOpsTemplate))
	g.templates[PlatformCircleCI] = template.Must(template.New("circleci").Parse(circleCITemplate))
	g.templates[PlatformBitbucket] = template.Must(template.New("bitbucket").Parse(bitbucketTemplate))
}

// Generate creates a CI/CD template from the configuration
func (g *Generator) Generate(config *TemplateConfig) (string, error) {
	tmpl, ok := g.templates[config.Platform]
	if !ok {
		return "", fmt.Errorf("unsupported platform: %s", config.Platform)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return buf.String(), nil
}

// ListPlatforms returns all supported platforms
func (g *Generator) ListPlatforms() []Platform {
	return []Platform{
		PlatformGitHubActions,
		PlatformGitLabCI,
		PlatformJenkins,
		PlatformAzureDevOps,
		PlatformCircleCI,
		PlatformBitbucket,
	}
}

// HasPlatform checks if a platform is supported
func (g *Generator) HasPlatform(platform Platform) bool {
	_, ok := g.templates[platform]
	return ok
}

// GitHub Actions template
const githubActionsTemplate = `# WAF Security Testing with waf-tester
# Auto-generated CI/CD template

name: WAF Security Scan

on:
{{- if .OnPush }}
  push:
    branches:
{{- range .Branches }}
      - {{ . }}
{{- end }}
{{- end }}
{{- if .OnPullRequest }}
  pull_request:
    branches:
{{- range .Branches }}
      - {{ . }}
{{- end }}
{{- end }}
{{- if .OnSchedule }}
  schedule:
    - cron: '{{ .ScheduleCron }}'
{{- end }}
  workflow_dispatch:

env:
  WAF_TESTER_VERSION: {{ .WafTesterVersion }}

jobs:
  security-scan:
    name: WAF Security Scan
    runs-on: ubuntu-latest
    timeout-minutes: {{ .Timeout }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install waf-tester
        run: |
          if [ "{{ .WafTesterVersion }}" = "latest" ]; then
            go install github.com/waftester/waftester/cmd/waf-tester@latest
          else
            go install github.com/waftester/waftester/cmd/waf-tester@{{ .WafTesterVersion }}
          fi

{{- range .PreCommands }}
      - name: Pre-scan command
        run: {{ . }}
{{- end }}

      - name: Run WAF Security Scan
        id: scan
        run: |
          TARGET_URL="{{ if .TargetEnvVar }}${{ "{{" }} {{ .TargetEnvVar }} {{ "}}" }}{{ else }}{{ .TargetURL }}{{ end }}"
          waf-tester run \
            -u "$TARGET_URL" \
            -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
            -o {{ .OutputFormat }} \
            -c {{ .ConcurrencyLimit }} \
            --rate-limit {{ .RateLimit }} \
            {{ .CustomArgs }} \
            --output-file results.{{ .OutputFormat }}
        continue-on-error: {{ not .FailOnHigh }}

{{- range .PostCommands }}
      - name: Post-scan command
        run: {{ . }}
{{- end }}

{{- if .UploadArtifacts }}
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: waf-tester-results
          path: results.{{ .OutputFormat }}
          retention-days: 30
{{- end }}

{{- if eq .OutputFormat "sarif" }}
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
        continue-on-error: true
{{- end }}

{{- if .NotifySlack }}
      - name: Notify Slack
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          webhook-url: ${{ "{{" }} secrets.{{ .SlackWebhook }} {{ "}}" }}
          payload: |
            {
              "text": "WAF Security Scan Failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": ":warning: WAF Security scan failed for *${{ "{{" }} github.repository {{ "}}" }}*"
                  }
                }
              ]
            }
{{- end }}
`

// GitLab CI template
const gitlabCITemplate = `# WAF Security Testing with waf-tester
# Auto-generated CI/CD template

stages:
  - security

variables:
  WAF_TESTER_VERSION: {{ .WafTesterVersion }}

waf-security-scan:
  stage: security
  image: golang:1.21
  timeout: {{ .Timeout }}
{{- if .OnPush }}
  rules:
    - if: $CI_COMMIT_BRANCH
      when: always
{{- end }}
{{- if .OnPullRequest }}
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      when: always
{{- end }}
{{- if .OnSchedule }}
    - if: $CI_PIPELINE_SOURCE == "schedule"
      when: always
{{- end }}
  
  before_script:
    - go install github.com/waftester/waftester/cmd/waf-tester@{{ .WafTesterVersion }}
{{- range .PreCommands }}
    - {{ . }}
{{- end }}
  
  script:
    - |
      TARGET_URL="{{ if .TargetEnvVar }}${{ .TargetEnvVar }}{{ else }}{{ .TargetURL }}{{ end }}"
      waf-tester run \
        -u "$TARGET_URL" \
        -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
        -o {{ .OutputFormat }} \
        -c {{ .ConcurrencyLimit }} \
        --rate-limit {{ .RateLimit }} \
        {{ .CustomArgs }} \
        --output-file results.{{ .OutputFormat }}
  
  after_script:
{{- range .PostCommands }}
    - {{ . }}
{{- end }}

{{- if .UploadArtifacts }}
  artifacts:
    paths:
      - results.{{ .OutputFormat }}
    expire_in: 30 days
{{- if eq .OutputFormat "sarif" }}
    reports:
      sast: results.sarif
{{- end }}
{{- end }}

{{- if .FailOnHigh }}
  allow_failure: false
{{- else }}
  allow_failure: true
{{- end }}
`

// Jenkins template
const jenkinsTemplate = `// WAF Security Testing with waf-tester
// Auto-generated CI/CD template (Jenkinsfile)

pipeline {
    agent any
    
    environment {
        WAF_TESTER_VERSION = '{{ .WafTesterVersion }}'
        TARGET_URL = {{ if .TargetEnvVar }}credentials('{{ .TargetEnvVar }}'){{ else }}'{{ .TargetURL }}'{{ end }}
    }
    
    options {
        timeout(time: {{ .Timeout }}, unit: 'MINUTES')
        disableConcurrentBuilds()
    }
    
{{- if .OnSchedule }}
    triggers {
        cron('{{ .ScheduleCron }}')
    }
{{- end }}
    
    stages {
        stage('Install waf-tester') {
            steps {
                sh 'go install github.com/waftester/waftester/cmd/waf-tester@${WAF_TESTER_VERSION}'
            }
        }
        
{{- if .PreCommands }}
        stage('Pre-scan') {
            steps {
{{- range .PreCommands }}
                sh '{{ . }}'
{{- end }}
            }
        }
{{- end }}
        
        stage('WAF Security Scan') {
            steps {
                sh '''
                    waf-tester run \
                        -u "${TARGET_URL}" \
                        -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
                        -o {{ .OutputFormat }} \
                        -c {{ .ConcurrencyLimit }} \
                        --rate-limit {{ .RateLimit }} \
                        {{ .CustomArgs }} \
                        --output-file results.{{ .OutputFormat }}
                '''
            }
        }
        
{{- if .PostCommands }}
        stage('Post-scan') {
            steps {
{{- range .PostCommands }}
                sh '{{ . }}'
{{- end }}
            }
        }
{{- end }}
    }
    
    post {
{{- if .UploadArtifacts }}
        always {
            archiveArtifacts artifacts: 'results.{{ .OutputFormat }}', fingerprint: true
        }
{{- end }}
{{- if .NotifySlack }}
        failure {
            slackSend channel: '#security', color: 'danger', message: "WAF Security scan failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
{{- end }}
    }
}
`

// Azure DevOps template
const azureDevOpsTemplate = `# WAF Security Testing with waf-tester
# Auto-generated CI/CD template (azure-pipelines.yml)

trigger:
{{- if .OnPush }}
  branches:
    include:
{{- range .Branches }}
      - {{ . }}
{{- end }}
{{- end }}

{{- if .OnPullRequest }}
pr:
  branches:
    include:
{{- range .Branches }}
      - {{ . }}
{{- end }}
{{- end }}

{{- if .OnSchedule }}
schedules:
  - cron: '{{ .ScheduleCron }}'
    displayName: Scheduled security scan
    branches:
      include:
{{- range .Branches }}
        - {{ . }}
{{- end }}
    always: true
{{- end }}

pool:
  vmImage: 'ubuntu-latest'

variables:
  WAF_TESTER_VERSION: '{{ .WafTesterVersion }}'

stages:
  - stage: SecurityScan
    displayName: 'WAF Security Scan'
    jobs:
      - job: WafTesterScan
        displayName: 'Run waf-tester'
        timeoutInMinutes: {{ .Timeout }}
        steps:
          - task: GoTool@0
            displayName: 'Install Go'
            inputs:
              version: '1.21'

          - script: |
              go install github.com/waftester/waftester/cmd/waf-tester@$(WAF_TESTER_VERSION)
            displayName: 'Install waf-tester'

{{- range .PreCommands }}
          - script: {{ . }}
            displayName: 'Pre-scan command'
{{- end }}

          - script: |
              TARGET_URL="{{ if .TargetEnvVar }}$({{ .TargetEnvVar }}){{ else }}{{ .TargetURL }}{{ end }}"
              waf-tester run \
                -u "$TARGET_URL" \
                -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
                -o {{ .OutputFormat }} \
                -c {{ .ConcurrencyLimit }} \
                --rate-limit {{ .RateLimit }} \
                {{ .CustomArgs }} \
                --output-file results.{{ .OutputFormat }}
            displayName: 'Run WAF Security Scan'
{{- if not .FailOnHigh }}
            continueOnError: true
{{- end }}

{{- range .PostCommands }}
          - script: {{ . }}
            displayName: 'Post-scan command'
{{- end }}

{{- if .UploadArtifacts }}
          - task: PublishBuildArtifacts@1
            displayName: 'Publish Results'
            inputs:
              pathToPublish: 'results.{{ .OutputFormat }}'
              artifactName: 'waf-tester-results'
{{- end }}
`

// CircleCI template
const circleCITemplate = `# WAF Security Testing with waf-tester
# Auto-generated CI/CD template (.circleci/config.yml)

version: 2.1

executors:
  go-executor:
    docker:
      - image: cimg/go:1.21

jobs:
  waf-security-scan:
    executor: go-executor
    steps:
      - checkout
      
      - run:
          name: Install waf-tester
          command: go install github.com/waftester/waftester/cmd/waf-tester@{{ .WafTesterVersion }}

{{- range .PreCommands }}
      - run:
          name: Pre-scan command
          command: {{ . }}
{{- end }}

      - run:
          name: Run WAF Security Scan
          command: |
            TARGET_URL="{{ if .TargetEnvVar }}${{ .TargetEnvVar }}{{ else }}{{ .TargetURL }}{{ end }}"
            waf-tester run \
              -u "$TARGET_URL" \
              -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
              -o {{ .OutputFormat }} \
              -c {{ .ConcurrencyLimit }} \
              --rate-limit {{ .RateLimit }} \
              {{ .CustomArgs }} \
              --output-file results.{{ .OutputFormat }}
{{- if not .FailOnHigh }}
          no_output_timeout: {{ .Timeout }}
          when: always
{{- end }}

{{- range .PostCommands }}
      - run:
          name: Post-scan command
          command: {{ . }}
{{- end }}

{{- if .UploadArtifacts }}
      - store_artifacts:
          path: results.{{ .OutputFormat }}
          destination: waf-tester-results
{{- end }}

workflows:
  version: 2
  security-scan:
    jobs:
      - waf-security-scan:
{{- if .OnPush }}
          filters:
            branches:
              only:
{{- range .Branches }}
                - {{ . }}
{{- end }}
{{- end }}

{{- if .OnSchedule }}
  scheduled-scan:
    triggers:
      - schedule:
          cron: "{{ .ScheduleCron }}"
          filters:
            branches:
              only:
{{- range .Branches }}
                - {{ . }}
{{- end }}
    jobs:
      - waf-security-scan
{{- end }}
`

// Bitbucket template
const bitbucketTemplate = `# WAF Security Testing with waf-tester
# Auto-generated CI/CD template (bitbucket-pipelines.yml)

image: golang:1.21

pipelines:
{{- if .OnPush }}
  branches:
{{- range .Branches }}
    '{{ . }}':
      - step:
          name: WAF Security Scan
          script:
            - go install github.com/waftester/waftester/cmd/waf-tester@{{ $.WafTesterVersion }}
{{- range $.PreCommands }}
            - {{ . }}
{{- end }}
            - |
              TARGET_URL="{{ if $.TargetEnvVar }}${{ $.TargetEnvVar }}{{ else }}{{ $.TargetURL }}{{ end }}"
              waf-tester run \
                -u "$TARGET_URL" \
                -s {{ range $i, $s := $.Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
                -o {{ $.OutputFormat }} \
                -c {{ $.ConcurrencyLimit }} \
                --rate-limit {{ $.RateLimit }} \
                {{ $.CustomArgs }} \
                --output-file results.{{ $.OutputFormat }}
{{- range $.PostCommands }}
            - {{ . }}
{{- end }}
{{- if $.UploadArtifacts }}
          artifacts:
            - results.{{ $.OutputFormat }}
{{- end }}
{{- end }}
{{- end }}

{{- if .OnPullRequest }}
  pull-requests:
    '**':
      - step:
          name: WAF Security Scan (PR)
          script:
            - go install github.com/waftester/waftester/cmd/waf-tester@{{ .WafTesterVersion }}
{{- range .PreCommands }}
            - {{ . }}
{{- end }}
            - |
              TARGET_URL="{{ if .TargetEnvVar }}${{ .TargetEnvVar }}{{ else }}{{ .TargetURL }}{{ end }}"
              waf-tester run \
                -u "$TARGET_URL" \
                -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
                -o {{ .OutputFormat }} \
                -c {{ .ConcurrencyLimit }} \
                --rate-limit {{ .RateLimit }} \
                {{ .CustomArgs }} \
                --output-file results.{{ .OutputFormat }}
{{- range .PostCommands }}
            - {{ . }}
{{- end }}
{{- if .UploadArtifacts }}
          artifacts:
            - results.{{ .OutputFormat }}
{{- end }}
{{- end }}

{{- if .OnSchedule }}
  custom:
    scheduled-scan:
      - step:
          name: Scheduled WAF Security Scan
          script:
            - go install github.com/waftester/waftester/cmd/waf-tester@{{ .WafTesterVersion }}
            - |
              TARGET_URL="{{ if .TargetEnvVar }}${{ .TargetEnvVar }}{{ else }}{{ .TargetURL }}{{ end }}"
              waf-tester run \
                -u "$TARGET_URL" \
                -s {{ range $i, $s := .Scanners }}{{ if $i }},{{ end }}{{ $s }}{{ end }} \
                -o {{ .OutputFormat }} \
                -c {{ .ConcurrencyLimit }} \
                --rate-limit {{ .RateLimit }} \
                {{ .CustomArgs }} \
                --output-file results.{{ .OutputFormat }}
{{- if .UploadArtifacts }}
          artifacts:
            - results.{{ .OutputFormat }}
{{- end }}
{{- end }}
`

// PipelineValidator validates generated templates
type PipelineValidator struct{}

// NewPipelineValidator creates a new validator
func NewPipelineValidator() *PipelineValidator {
	return &PipelineValidator{}
}

// Validate checks if a generated template is syntactically valid
func (v *PipelineValidator) Validate(platform Platform, content string) error {
	if content == "" {
		return fmt.Errorf("empty template")
	}

	switch platform {
	case PlatformGitHubActions, PlatformGitLabCI, PlatformAzureDevOps, PlatformCircleCI, PlatformBitbucket:
		// YAML-based - basic validation
		if !containsString(content, "waf-tester") {
			return fmt.Errorf("template missing waf-tester command")
		}
	case PlatformJenkins:
		// Groovy-based
		if !containsString(content, "pipeline") {
			return fmt.Errorf("Jenkins template missing pipeline block")
		}
	default:
		return fmt.Errorf("unknown platform: %s", platform)
	}

	return nil
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
