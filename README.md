# WAFtester

The most comprehensive Web Application Firewall testing platform for security professionals and enterprise teams. Detect, fingerprint, and assess WAF security posture with quantitative metrics.

[![License](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/waftester/waftester)](https://github.com/waftester/waftester/releases)
[![npm](https://img.shields.io/npm/v/@waftester/cli)](https://www.npmjs.com/package/@waftester/cli)
[![Website](https://img.shields.io/badge/website-waftester.com-3b82f6)](https://waftester.com)

---

## Overview

WAFtester provides enterprise-grade WAF security assessment through a single, unified platform. Unlike fragmented toolchains that require manual correlation between detection, bypass, and reporting phases, WAFtester delivers end-to-end automated testing with statistical validation.

```bash
waf-tester auto -u https://target.com --smart
```

This command executes a complete security assessment: endpoint discovery, WAF vendor identification, optimal bypass technique selection, 2,800+ payload testing, and quantitative report generation.

---

## The Problem WAFtester Solves

Modern security teams face three critical challenges when assessing WAF effectiveness:

**Fragmented Tooling.** Traditional assessments require chaining multiple tools (wafw00f, sqlmap, nuclei, custom scripts), manual correlation of results, and significant expertise to interpret findings.

**No Quantitative Metrics.** Most tools report binary pass/fail results. Security teams need statistical measures (False Positive Rate, F1 Score, MCC) to make informed decisions about WAF configuration and vendor selection.

**WAF-Agnostic Testing.** Generic payloads waste time against well-configured WAFs. Effective testing requires WAF-specific bypass techniques selected based on the detected vendor and configuration.

WAFtester addresses these challenges with an integrated platform that automates the entire assessment lifecycle.

---

## Core Capabilities

### WAF Detection and Fingerprinting

Identify WAF vendors with high confidence using 197 vendor signatures.

```
$ waf-tester vendor -u https://protected.example.com

WAF Detection Results
--------------------------------------------------------------------------
  Vendor         Cloudflare
  Confidence     98%
  Evidence       cf-ray header, __cfduid cookie, 1020 error page
  
Recommended tampers for Cloudflare:
  charunicodeencode, space2morecomment, randomcase
```

Detection covers major commercial and open-source WAFs including Cloudflare, AWS WAF, Akamai, Imperva, Azure WAF, F5, Fortinet, ModSecurity, Barracuda, Sucuri, Radware, Citrix ADC, Palo Alto, Sophos, and Wallarm.

### Automated Bypass Discovery

Discover WAF bypass techniques using 70+ tamper scripts with automatic selection based on detected vendor.

```
$ waf-tester bypass -u https://target.com --smart --tamper-auto

Bypass Discovery
--------------------------------------------------------------------------
  Payload Variants Tested     2,847
  Blocked by WAF              2,728 (95.8%)
  Bypassed WAF                119 (4.2%)
  
Top Bypass Chains:
  1. charunicodeencode + space2morecomment    (42 bypasses)
  2. modsecurityversioned + randomcase        (31 bypasses)  
  3. between + equaltolike                    (19 bypasses)
```

The mutation engine combines 49 mutator functions with base payloads to generate comprehensive coverage across encoding, evasion, and injection location variations.

### Enterprise Assessment with Statistical Metrics

Generate quantitative WAF assessments with industry-standard statistical measures.

```
$ waf-tester assess -u https://target.com -fp -o assessment.json

Enterprise WAF Assessment
--------------------------------------------------------------------------
  Metric                  Score
  ---------------------------------
  Detection Rate (TPR)    94.2%
  False Positive Rate     0.3%
  Precision               99.7%
  Recall                  94.2%
  F1 Score                0.969
  MCC                     0.942
```

Assessment includes testing against benign traffic corpora (Leipzig corpus integration) to measure false positive rates, enabling data-driven WAF configuration decisions.

### Multi-Protocol Support

Native support for modern API protocols beyond HTTP.

```bash
# GraphQL introspection and injection testing
waf-tester scan -u https://api.example.com/graphql -types graphql

# gRPC reflection and message fuzzing  
waf-tester scan -u grpc://service:50051 -types grpc

# SOAP/WSDL enumeration and XXE testing
waf-tester scan -u https://api.example.com/service.wsdl -types soap

# WebSocket message injection
waf-tester scan -u wss://api.example.com/socket -types websocket
```

---

## Comparison with Existing Tools

### Workflow Consolidation

| Traditional Approach | WAFtester Approach |
|---------------------|-------------------|
| Run wafw00f for WAF detection | Integrated: 197 vendor signatures |
| Manually select sqlmap tampers | Auto-selects from 70+ tampers based on detected WAF |
| Write nuclei templates per vulnerability | 2,800+ payloads across 50+ categories included |
| Parse outputs and correlate manually | Unified JSON/SARIF/HTML with metrics |
| Separate tools for GraphQL, gRPC, WebSocket | Native multi-protocol support |

### Feature Comparison

| Capability | sqlmap | nuclei | Burp Suite | WAFtester |
|------------|--------|--------|------------|-----------|
| WAF-aware tamper selection | Manual | N/A | Manual | Automatic |
| False positive measurement | No | No | Limited | Full (FPR, precision) |
| Statistical metrics (MCC, F1) | No | No | No | Yes |
| Multi-protocol (GraphQL, gRPC) | No | Limited | Yes | Native |
| Mutation engine | 60 tampers | N/A | Intruder | 49 mutators x payloads |
| CI/CD native (SARIF, streaming) | No | Yes | No | Yes |

---

## Installation

### npm / npx (Recommended)

Zero-dependency install — downloads the correct platform binary automatically.

```bash
# Run directly (no install needed)
npx -y @waftester/cli scan -u https://target.com

# Or install globally
npm install -g @waftester/cli
waf-tester version
```

Works on macOS, Linux, and Windows (x64 and arm64). Requires Node.js >= 16.

### Go Install

Requires Go 1.24 or later. The binary will be named `cli`;
rename to `waf-tester` after install.

```bash
go install github.com/waftester/waftester/cmd/cli@latest
```

### Docker

Multi-architecture images (`linux/amd64`, `linux/arm64`)
are published to GHCR and Docker Hub.

```bash
# Pull the latest image
docker pull ghcr.io/waftester/waftester:latest

# Run the MCP server on port 8080
docker run -p 8080:8080 ghcr.io/waftester/waftester

# Run a scan directly
docker run --rm ghcr.io/waftester/waftester scan -u https://example.com

# Docker Compose (local build)
docker compose up --build
```

Available image tags:

| Tag | Description |
|-----|-------------|
| `latest` | Latest stable release |
| `1.2.3` | Exact version |
| `1.2`, `1` | Minor/major aliases |
| `edge` | Latest `main` branch build |
| `sha-abc1234` | Specific commit |

The image runs as non-root on a read-only distroless base (~5 MB). See [docs/INSTALLATION.md](docs/INSTALLATION.md#docker) for Docker Compose, Kubernetes, and environment variable configuration.

### Package Managers

```bash
# macOS / Linux
brew tap waftester/tap
brew install waftester

# Windows
scoop bucket add waftester https://github.com/waftester/scoop-waftester
scoop install waftester

# Arch Linux (AUR)
yay -S waftester-bin
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/waftester/waftester/releases).

For detailed installation instructions, see [docs/INSTALLATION.md](docs/INSTALLATION.md).

---

## Usage

### Automated Assessment

The `auto` command provides complete automated assessment including discovery, analysis, testing, and reporting.

```bash
# Full automated assessment with WAF-aware optimization
waf-tester auto -u https://example.com --smart

# With automatic tamper selection based on detected WAF
waf-tester auto -u https://example.com --smart --tamper-auto

# Service-specific presets for CMS and framework detection
waf-tester auto -u https://example.com -service wordpress
```

### Targeted Scanning

The `scan` command provides focused vulnerability testing across 50+ attack categories.

```bash
# SQL injection and XSS testing
waf-tester scan -u https://target.com -types sqli,xss

# All attack categories
waf-tester scan -u https://target.com -types all

# With WAF-aware tamper selection
waf-tester scan -u https://target.com --smart --tamper-auto

# With custom payload and template directories
waf-tester scan -u https://target.com --payloads ./custom-payloads --template-dir ./my-templates
```

### WAF Intelligence

The `tampers` command provides vendor-specific bypass recommendations.

```bash
# Show tampers ranked by effectiveness for specific WAF
waf-tester tampers --for-waf=cloudflare

Tampers Ranked by Effectiveness for Cloudflare
--------------------------------------------------------------------------
  Rank  Tamper                    Success Rate
  1     charunicodeencode         85%
  2     space2morecomment         82%
  3     randomcase                75%
  4     between                   68%
  5     modsecurityversioned      55%
```

---

## Output Formats and Integrations

WAFtester supports multiple output formats for integration with security workflows and CI/CD pipelines.

### Supported Formats

| Format | Use Case | Flag |
|--------|----------|------|
| JSON | Automation, APIs, scripting | `-format json` |
| JSONL | Streaming, real-time processing | `-stream -json` |
| SARIF | GitHub/GitLab Security, VS Code | `-format sarif` |
| HTML | Reports for stakeholders | `-format html` |
| PDF | Executive reports | `-format pdf` |
| JUnit | CI/CD test frameworks | `-format junit` |
| CycloneDX | SBOM vulnerability exchange | `-format cyclonedx` |
| XML | Legacy SIEM/vulnerability platforms | `--xml` |

### Enterprise Integrations

| Integration | Format | Flag |
|------------|--------|------|
| SonarQube | Generic Issue Import | `-format sonarqube` |
| GitLab SAST | gl-sast-report.json | `-format gitlab-sast` |
| DefectDojo | Findings import | `-format defectdojo` |
| Elasticsearch | SIEM streaming | `--elasticsearch-url` |
| GitHub Issues | Auto-create issues | `--github-issues-token` |
| Azure DevOps | Work item creation | `--ado-org`, `--ado-project`, `--ado-pat` |

### Real-time Alerting

```bash
# Slack notifications
waf-tester scan -u $TARGET --slack-webhook=$WEBHOOK_URL

# Microsoft Teams notifications  
waf-tester scan -u $TARGET --teams-webhook=$WEBHOOK_URL

# PagerDuty escalation
waf-tester scan -u $TARGET --pagerduty-key=$ROUTING_KEY

# Jira ticket creation
waf-tester scan -u $TARGET --jira-url=$JIRA_URL --jira-project=SEC --jira-email=$EMAIL --jira-token=$TOKEN

# GitHub Issues integration
waf-tester scan -u $TARGET --github-issues-token=$TOKEN --github-issues-owner=myorg --github-issues-repo=security-issues

# Azure DevOps work item creation
waf-tester scan -u $TARGET --ado-org=myorg --ado-project=SecurityTests --ado-pat=$ADO_PAT

# OpenTelemetry tracing
waf-tester scan -u $TARGET --otel-endpoint=$OTEL_ENDPOINT
```

---

## CI/CD Integration

### GitHub Actions (Recommended)

```yaml
- uses: waftester/waftester-action@v1
  with:
    target: https://app.example.com
```

Results appear in **Security → Code scanning**. See [WAFtester Action](https://github.com/marketplace/actions/waftester-waf-security-testing) for all options.

### Alternative: CLI in GitHub Actions

```yaml
- name: WAF Security Assessment
  run: |
    waf-tester scan -u ${{ env.TARGET_URL }} \
      -format sarif -o results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pipeline Quality Gates

```bash
# Fail pipeline on critical findings
waf-tester scan -u $TARGET -json | \
  jq -e '[.vulnerabilities[] | select(.severity=="Critical")] | length == 0'

# Extract metrics for dashboards
waf-tester assess -u $TARGET -json | \
  jq '{tpr: .metrics.detection_rate, fpr: .metrics.false_positive_rate, f1: .metrics.f1_score}'
```

For additional CI/CD examples (GitLab, Azure DevOps, Jenkins, CircleCI, Tekton), see [docs/EXAMPLES.md](docs/EXAMPLES.md#cicd-integration).

---

## MCP Server — AI Agent Integration

WAFtester includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that enables AI assistants (Claude, GPT, Copilot) and automation platforms (n8n, Langflow) to control WAFtester programmatically.

### Why MCP?

Instead of parsing CLI output or building custom integrations, AI agents interact with WAFtester through a structured protocol with typed tool schemas, progress notifications, and domain-knowledge resources. The server guides agents through optimal tool selection and workflow orchestration.

### Transports

| Transport | Use Case | Command |
|-----------|----------|---------|
| Stdio | IDE integrations (VS Code, Claude Desktop, Cursor) | `waf-tester mcp` |
| HTTP | Remote/Docker deployments, n8n, web UIs | `waf-tester mcp --http :8080` |

The HTTP transport exposes:
- `/mcp` — Streamable HTTP (2025-03-26 spec)
- `/sse` — Legacy SSE for n8n and older MCP clients
- `/health` — Readiness probe for container orchestrators

All endpoints include CORS headers for browser-based clients.

### Quick Start

```bash
# Stdio mode (for Claude Desktop, VS Code, Cursor)
waf-tester mcp

# HTTP mode (for n8n, Docker, remote access)
waf-tester mcp --http :8080

# Docker
docker run -p 8080:8080 ghcr.io/waftester/waftester mcp --http :8080
```

### Claude Desktop Configuration

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

Alternatively, if installed via Go or binary:

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "waf-tester",
      "args": ["mcp"]
    }
  }
}
```

### n8n Integration

1. Add an **MCP Client** node in n8n
2. Set transport to **SSE Endpoint**
3. Enter the URL: `http://your-server:8080/sse`
4. Connect to an AI Agent node
5. WAFtester tools appear automatically for the agent to use

### Available Tools

| Tool | What It Does |
|------|--------------|
| `list_payloads` | Browse attack payload catalog with filtering |
| `detect_waf` | Fingerprint WAF vendor, confidence, bypass tips |
| `discover` | Map attack surface (robots, sitemap, JS, Wayback) — **async** |
| `learn` | Generate intelligent test plans from discovery |
| `scan` | Execute WAF bypass tests with progress tracking — **async** |
| `assess` | Enterprise assessment with F1, precision, MCC, FPR — **async** |
| `mutate` | Apply encoding/evasion transformations |
| `bypass` | Systematic bypass with mutation matrix — **async** |
| `probe` | TLS, HTTP/2, technology fingerprinting |
| `generate_cicd` | Generate CI/CD YAML for 6 platforms |
| `get_task_status` | Poll async task progress and retrieve results |
| `cancel_task` | Stop a running async task |
| `list_tasks` | View all running/completed/failed tasks |

> **Async tools** return a `task_id` immediately. Poll with `get_task_status` to retrieve results. This prevents timeout errors with n8n and other MCP clients.

### Domain Knowledge Resources

AI agents can read these resources for context without making network requests:

| Resource | Content |
|----------|---------|
| `waftester://guide` | WAF testing methodology guide |
| `waftester://waf-signatures` | WAF vendor signatures and bypass tips |
| `waftester://evasion-techniques` | Evasion encoding catalog |
| `waftester://owasp-mappings` | OWASP Top 10 2021 mappings |
| `waftester://payloads` | Full payload catalog |
| `waftester://payloads/unified` | Unified view (JSON + Nuclei template payloads) |
| `waftester://payloads/{category}` | Category-filtered payloads |
| `waftester://templates` | Nuclei template library listing |
| `waftester://version` | Server version, capabilities, and resource counts |
| `waftester://config` | Default configuration values |

For complete MCP examples, see [docs/EXAMPLES.md](docs/EXAMPLES.md#mcp-server-integration).

---

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `auto` | Complete automated assessment | `waf-tester auto -u https://target.com` |
| `scan` | Vulnerability scanning (50+ categories) | `waf-tester scan -u https://target.com -types sqli,xss` |
| `bypass` | WAF bypass discovery | `waf-tester bypass -u https://target.com --smart` |
| `assess` | Enterprise metrics (F1, MCC, FPR) | `waf-tester assess -u https://target.com -fp` |
| `tampers` | List/test/recommend tampers | `waf-tester tampers --for-waf=cloudflare` |
| `vendor` | WAF fingerprinting (197 signatures) | `waf-tester vendor -u https://target.com` |
| `probe` | Protocol detection | `waf-tester probe -l urls.txt` |
| `fuzz` | Directory/content fuzzing | `waf-tester fuzz -u https://target.com/FUZZ` |
| `smuggle` | HTTP request smuggling detection | `waf-tester smuggle -u https://target.com` |
| `race` | Race condition testing | `waf-tester race -u https://target.com/checkout` |
| `discover` | Endpoint crawling | `waf-tester discover -u https://target.com` |
| `workflow` | YAML workflow execution | `waf-tester workflow -f recon.yaml` |
| `template` | Nuclei-compatible template scanner | `waf-tester template -u https://target.com -t templates/` |
| `grpc` | gRPC service testing | `waf-tester grpc -u localhost:50051 --list` |
| `soap` | SOAP/WSDL service testing | `waf-tester soap --wsdl https://api.example.com?wsdl` |
| `openapi` | OpenAPI specification fuzzing | `waf-tester openapi -spec openapi.yaml --fuzz` |
| `cloud` | Cloud resource discovery | `waf-tester cloud -d example.com --providers aws,azure` |
| `mcp` | MCP server for AI agents | `waf-tester mcp` or `waf-tester mcp --http :8080` |

---

## Key Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | Target URL | Required |
| `-l` | File with targets (one per line) | - |
| `-c` | Concurrent workers | 25 |
| `-rl` | Rate limit (requests/second) | 150 |
| `--smart` | WAF-aware adaptive mode | false |
| `--tamper` | Tamper list (comma-separated) | - |
| `--tamper-auto` | Auto-select for detected WAF | false |
| `--tamper-profile` | Preset: stealth, standard, aggressive, bypass | - |
| `-format` | Output format | json |
| `-o` | Output file | - |
| `-x` | Proxy (HTTP/HTTPS/SOCKS4/SOCKS5) | - |
| `--sni` | Override TLS SNI for CDN bypass | - |
| `--burp` | Burp Suite proxy shortcut | false |
| `--zap` | OWASP ZAP proxy shortcut | false |
| `--payloads` | Custom payload directory | `./payloads` |
| `--template-dir` | Custom Nuclei template directory | `./templates/nuclei` |
| `--stream` | Real-time streaming output | false |

---

## Platform Statistics

| Metric | Value |
|--------|-------|
| CLI Commands | 33 |
| WAF Signatures | 197 vendors |
| Attack Payloads | 2,800+ |
| Tamper Scripts | 70+ |
| Mutator Functions | 49 |
| Attack Categories | 50+ |
| Protocols | HTTP, GraphQL, gRPC, SOAP, WebSocket, OpenAPI |
| Output Formats | 16 |
| CI/CD Platforms | 9 |
| MCP Tools | 10 |
| MCP Resources | 10 |
| MCP Prompts | 6 |
| npm Platforms | macOS, Linux, Windows (x64 + arm64) |
| Docker Architectures | linux/amd64, linux/arm64 |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Examples Guide](docs/EXAMPLES.md) | Comprehensive usage examples |
| [Installation](docs/INSTALLATION.md) | Installation methods (Go, Docker, binary) |
| [MCP Server](docs/EXAMPLES.md#mcp-server-integration) | AI agent integration guide |
| [Docker](docs/INSTALLATION.md#docker) | Container deployment guide |
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history |
| [Security](SECURITY.md) | Security policy |

---

## License

**Core:** [Business Source License 1.1](LICENSE) - Converts to Apache 2.0 on January 31, 2030

**Community Payloads:** [MIT](LICENSE-COMMUNITY)
