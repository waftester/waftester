# WAFtester Examples Guide

This guide provides comprehensive usage examples for WAFtester, organized by use case and command category. Each example includes context on when to use the command, what value it provides, and expected output formats.

**Document Version:** 2.7.0  
**Last Updated:** February 2026

---

> **What's New in v2.7.0**
>
> - **MCP Server** — AI-native interface for Claude, GPT, n8n, and automation platforms ([details](#mcp-server-integration))
> - **SSE Transport** — Legacy SSE support for n8n compatibility ([details](#n8n-workflow-automation))
> - **Health Endpoint** — Container readiness probes for Docker/Kubernetes ([details](#docker-deployment))

## Table of Contents

- [Quick Start](#quick-start)
  - [Choose Your Path](#choose-your-path)
- [Why WAFtester?](#why-waftester)
  - [Coming from Another Tool?](#coming-from-another-tool)
- [Core Commands](#core-commands)
  - [Automated Scanning (auto)](#automated-scanning-auto)
  - [Enterprise Assessment (assess)](#enterprise-assessment-assess)
  - [Vulnerability Scanning (scan)](#vulnerability-scanning-scan)
  - [WAF Detection (vendor)](#waf-detection-vendor)
  - [Protocol Detection (protocol)](#protocol-detection-protocol)
  - [Bypass Hunting (bypass)](#bypass-hunting-bypass)
  - [Mutation Testing (mutate)](#mutation-testing-mutate)
  - [False Positive Testing (fp)](#false-positive-testing-fp)
  - [Content Fuzzing (fuzz)](#content-fuzzing-fuzz)
  - [Protocol Probing (probe)](#protocol-probing-probe)
  - [HTTP Smuggling (smuggle)](#http-smuggling-smuggle)
  - [Race Condition Testing (race)](#race-condition-testing-race)
  - [Web Crawling (crawl)](#web-crawling-crawl)
  - [JavaScript Analysis (analyze)](#javascript-analysis-analyze)
  - [Headless Browser Testing (headless)](#headless-browser-testing-headless)
- [Workflow Commands](#workflow-commands)
  - [Discovery and Planning (discover / learn)](#discovery-and-planning-discover--learn)
  - [Test Execution (run)](#test-execution-run)
  - [Workflow Orchestration (workflow)](#workflow-orchestration-workflow)
- [Protocol Testing](#protocol-testing)
  - [GraphQL Security Testing](#graphql-security-testing)
  - [gRPC Security Testing](#grpc-security-testing)
  - [SOAP/WSDL Security Testing](#soapwsdl-security-testing)
- [Tamper Scripts](#tamper-scripts)
- [Mutation Engine](#mutation-engine)
  - [Encoders](#encoders)
  - [Evasion Techniques](#evasion-techniques)
  - [Injection Locations](#injection-locations)
  - [Protocol Mutations](#protocol-mutations)
- [Smart Mode](#smart-mode)
- [Intelligence Engine (v2.6.5)](#intelligence-engine-v265)
- [Integration Overview (v2.5.0+)](#integration-overview-v250)
- [Output Formats](#output-formats)
  - [HTML Reports with Themes](#html-reports-with-themes-v250)
  - [Markdown with Enhanced Features](#markdown-with-enhanced-features-v250)
  - [Colorized Console Output](#colorized-console-output-v250)
  - [Custom Templates](#custom-templates-v250)
  - [PDF Reports](#pdf-reports-v250)
  - [Enterprise Integrations](#enterprise-integrations-v250)
  - [JUnit XML Reports](#junit-xml-reports-v250)
  - [CycloneDX VEX Reports](#cyclonedx-vex-reports-v250)
  - [XML Export](#xml-export-v268)
  - [Elasticsearch SIEM Integration](#elasticsearch-siem-integration-v268)
  - [GitHub Issues Integration](#github-issues-integration-v268)
  - [Azure DevOps Integration](#azure-devops-integration-v268)
  - [Historical Trend Analysis](#historical-trend-analysis-v268)
  - [Template Configuration](#template-configuration-v268)
  - [Real-time Alerting Hooks](#real-time-alerting-hooks-v250)
  - [GitHub Actions Integration](#github-actions-integration-v250)
  - [OpenTelemetry Tracing](#opentelemetry-tracing-v250)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions](#github-actions)
  - [GitLab CI](#gitlab-ci)
  - [Azure DevOps](#azure-devops)
  - [Jenkins Pipeline](#jenkins-pipeline-v250)
  - [CircleCI](#circleci-v250)
  - [Drone CI](#drone-ci-v250)
  - [Tekton Pipeline](#tekton-pipeline-v250)
  - [ArgoCD Pre-Sync Hook](#argocd-pre-sync-hook-v250)
  - [Harness CI](#harness-ci-v250)
  - [AWS CodePipeline](#aws-codepipeline-v250)
  - [Prometheus Metrics](#prometheus-metrics-integration-v250)
- [Advanced Options](#advanced-options)
  - [Headers and Authentication](#headers-and-authentication)
  - [Proxies](#proxies)
  - [Rate Limiting](#rate-limiting)
  - [Response Filtering](#response-filtering)
  - [Realistic Mode](#realistic-mode)
  - [Resume and Checkpoints](#resume-and-checkpoints)
  - [JA3 Fingerprint Rotation](#ja3-fingerprint-rotation)
  - [Connection Drop & Silent Ban Detection](#connection-drop--silent-ban-detection-v252)
- [Browser Scanning](#browser-scanning)
- [Multiple Targets](#multiple-targets)
- [Utility Commands](#utility-commands)
- [MCP Server Integration](#mcp-server-integration)
  - [Stdio Mode (IDE)](#stdio-mode-ide)
  - [HTTP Mode (Remote)](#http-mode-remote)
  - [Claude Desktop Setup](#claude-desktop-setup)
  - [n8n Workflow Automation](#n8n-workflow-automation)
  - [Docker Deployment](#docker-deployment)
  - [MCP Resources and Prompts](#mcp-resources-and-prompts)
  - [Enterprise Report Generation](#enterprise-report-generation-report)
- [API & Protocol Commands (v2.6.2)](#api--protocol-commands-v262)
  - [Template Scanner (template)](#template-scanner-template)
  - [gRPC Testing (grpc)](#grpc-testing-grpc)
  - [SOAP/WSDL Testing (soap)](#soapwsdl-testing-soap)
  - [OpenAPI Fuzzing (openapi)](#openapi-fuzzing-openapi)
  - [CI/CD Generator (cicd)](#cicd-generator-cicd)
  - [Plugin Manager (plugin)](#plugin-manager-plugin)
  - [Cloud Discovery (cloud)](#cloud-discovery-cloud)
- [Troubleshooting](#troubleshooting)
- [Attack Categories Reference](#attack-categories-reference)
- [Real-World Playbooks](#real-world-playbooks)
  - [Playbook 1: New Client Assessment](#playbook-1-new-client--first-waf-assessment)
  - [Playbook 2: CI/CD Pipeline](#playbook-2-cicd-pipeline--block-deploys-on-waf-regression)
  - [Playbook 3: WAF Vendor Comparison](#playbook-3-waf-vendor-comparison--cloudflare-vs-aws-waf)
  - [Playbook 4: WordPress Site](#playbook-4-wordpress-site-behind-waf)
  - [Playbook 5: API-First Application](#playbook-5-api-first-application-graphql--rest)
  - [Playbook 6: Post-Incident Verification](#playbook-6-post-incident--verify-waf-rule-fix)
  - [Playbook 7: Bug Bounty](#playbook-7-bug-bounty--quick-waf-bypass-discovery)
  - [Playbook 8: Production Monitoring](#playbook-8-production-monitoring--continuous-waf-health)
  - [Playbook 9: Compliance Audit](#playbook-9-compliance-audit--pci-dss--soc-2)
  - [Playbook 10: Multi-Region Assessment](#playbook-10-multi-region--multi-cdn-assessment)
- [Getting Help](#getting-help)

---

## Quick Start

This section provides the fastest path to running a WAF security assessment. These commands are designed for immediate value with minimal configuration.

### Prerequisites

Before running any WAFtester command, ensure:

| Requirement | Details |
|-------------|---------|
| **Network Access** | Outbound HTTPS to target (ports 80/443). Verify with `curl -I https://target.com` |
| **Permissions** | Written authorization to test the target. WAFtester sends attack payloads. |
| **Resources** | ~500MB RAM, stable internet connection (50+ req/sec capability) |
| **Target State** | Target must be accessible and responding. Test with `waf-tester probe -u URL` first. |

### Choose Your Path

Not sure where to start? Pick your role for a curated workflow.

<details>
<summary><strong>🔧 DevSecOps / CI/CD Engineer</strong> — Integrate WAF testing into pipelines</summary>

| Step | Command | Time | Purpose |
|------|---------|------|---------|
| 1 | `waf-tester probe -u $TARGET` | 10s | Verify target is reachable |
| 2 | `waf-tester scan -u $TARGET -category sqli,xss --stream -format sarif -o results.sarif` | 3-5m | SARIF output for GitHub/GitLab Security tab |
| 3 | Check exit code: non-zero = bypasses found | — | Gate deployment on WAF effectiveness |

**Jump to:** [CI/CD Integration](#cicd-integration) · [Output Formats](#output-formats) · [Playbook: CI/CD Pipeline](#playbook-2-cicd-pipeline--block-deploys-on-waf-regression)

</details>

<details>
<summary><strong>🔴 Penetration Tester / Red Team</strong> — Find WAF bypasses and prove exploitability</summary>

| Step | Command | Time | Purpose |
|------|---------|------|---------|
| 1 | `waf-tester vendor -u $TARGET` | 15s | Identify WAF vendor + bypass hints |
| 2 | `waf-tester bypass -u $TARGET --smart --tamper-auto` | 10-20m | Automated bypass discovery |
| 3 | `waf-tester mutate -u $TARGET -mutation full -chain` | 15-30m | Full mutation matrix for manual deepdive |
| 4 | `waf-tester scan -u $TARGET --smart -format html -ie -ir` | 5m | Evidence collection for report |

**Jump to:** [Bypass Hunting](#bypass-hunting-bypass) · [Mutation Engine](#mutation-engine) · [Tamper Scripts](#tamper-scripts) · [Playbook: Bug Bounty](#playbook-7-bug-bounty--quick-waf-bypass-discovery)

</details>

<details>
<summary><strong>🏢 Security Architect / CISO</strong> — Vendor comparison and compliance metrics</summary>

| Step | Command | Time | Purpose |
|------|---------|------|---------|
| 1 | `waf-tester assess -u $TARGET -fp -corpus builtin,leipzig` | 5-10m | Quantitative WAF metrics (TPR, FPR, F1, MCC) |
| 2 | `waf-tester report -workspace ./workspace -format pdf` | 1m | Board-ready PDF report |
| 3 | Schedule with `--metrics-port=9090` + Grafana | Ongoing | Track WAF effectiveness trends |

**Jump to:** [Enterprise Assessment](#enterprise-assessment-assess) · [Prometheus Metrics](#prometheus-metrics-integration-v250) · [Playbook: Vendor Comparison](#playbook-3-waf-vendor-comparison--cloudflare-vs-aws-waf)

</details>

<details>
<summary><strong>🧪 QA / AppSec Engineer</strong> — Validate WAF rules, measure false positives, regression test</summary>

| Step | Command | Time | Purpose |
|------|---------|------|---------|
| 1 | `waf-tester fp -u $TARGET -corpus builtin` | 2-3m | Baseline false positive rate |
| 2 | `waf-tester scan -u $TARGET -category sqli -ip "/api/v2"` | 2m | Targeted regression test |
| 3 | Compare JSON outputs with `jq` | — | Quantify WAF rule change impact |

**Jump to:** [False Positive Testing](#false-positive-testing-fp) · [Vulnerability Scanning](#vulnerability-scanning-scan) · [Playbook: Post-Incident Verify](#playbook-6-post-incident--verify-waf-rule-fix)

</details>

<details>
<summary><strong>🔍 Bug Bounty Hunter</strong> — Quick recon and WAF evasion for finding bypasses fast</summary>

| Step | Command | Time | Purpose |
|------|---------|------|---------|
| 1 | `waf-tester auto -u $TARGET --smart -c 50 -rl 100` | 5-15m | Full automated assessment |
| 2 | `waf-tester analyze -u $TARGET` | 1-2m | Find hidden endpoints and secrets in JS |
| 3 | `waf-tester bypass -u $TARGET --smart --tamper-auto -category sqli,xss` | 10m | Focused bypass hunting |

**Jump to:** [Automated Scanning](#automated-scanning-auto) · [JavaScript Analysis](#javascript-analysis-analyze) · [Playbook: Bug Bounty](#playbook-7-bug-bounty--quick-waf-bypass-discovery)

</details>

### One-Command Assessment

Execute a complete security assessment with a single command. This is the recommended starting point for most assessments.

**TL;DR:** `waf-tester auto -u https://example.com` — Complete WAF assessment in ~5 minutes

```bash
waf-tester auto -u https://example.com
```

#### What Happens (Detailed)

| Phase | Duration | Actions | Network Impact |
|-------|----------|---------|----------------|
| **1. Connection** | 2-5 sec | TLS handshake, HTTP/2 negotiation, initial response analysis | 3-5 requests |
| **2. WAF Detection** | 5-10 sec | Sends probe requests, matches against 197 vendor signatures, identifies block patterns | 10-20 requests |
| **3. Discovery** | 30-90 sec | Crawls site (3 levels deep), parses robots.txt/sitemap.xml, extracts forms, analyzes JavaScript for API endpoints | 100-500 requests |
| **4. Planning** | 2-5 sec | Generates optimized test plan based on discovered endpoints and WAF type | 0 requests (local) |
| **5. Testing** | 2-8 min | Executes 2,800+ attack payloads across 50+ categories, records WAF responses | 2,800-10,000 requests |
| **6. Analysis** | 5-15 sec | Correlates responses, calculates bypass rates, ranks findings by severity | 0 requests (local) |
| **7. Reporting** | 2-5 sec | Generates HTML/JSON reports in workspace directory | 0 requests (local) |

**Total Duration:** 3-10 minutes depending on target size and response times

#### Sample Output

```
$ waf-tester auto -u https://example.com

WAFtester v2.6.5 - WAF Security Assessment Tool

🔍 Phase 1: WAF Detection
   ├─ Probing target...
   ├─ Detected: Cloudflare (confidence: 94%)
   ├─ Block patterns: 403 Forbidden, "cf-ray" header
   └─ Strategy: Adaptive with challenge detection

📡 Phase 2: Discovery
   ├─ Crawling https://example.com (depth: 3)
   ├─ Parsing robots.txt, sitemap.xml
   ├─ Analyzing 23 JavaScript files
   ├─ Endpoints found: 847
   ├─ Parameters discovered: 2,341
   └─ Forms extracted: 12

📋 Phase 3: Test Planning
   ├─ Generated test plan: 8,234 test cases
   ├─ Categories: sqli, xss, traversal, rce, ssrf (+45 more)
   └─ Estimated time: 4-6 minutes

🧪 Phase 4: Testing
   [████████████████████████████████████████] 100% (8,234/8,234)
   ├─ Duration: 4m 32s
   ├─ Requests sent: 8,234
   ├─ Rate: 30.2 req/sec
   ├─ Blocked: 7,891 (95.8%)
   └─ Bypassed: 343 (4.2%)

📊 Phase 5: Results Summary
   ┌─────────────┬───────┬─────────────────────────────────────┐
   │ Severity    │ Count │ Categories                          │
   ├─────────────┼───────┼─────────────────────────────────────┤
   │ 🔴 Critical │     3 │ rce (2), sqli (1)                   │
   │ 🟠 High     │    12 │ sqli (5), xss (4), ssrf (3)         │
   │ 🟡 Medium   │    41 │ traversal (15), redirect (12), ...  │
   │ 🔵 Low      │   110 │ info-disclosure (45), headers (35)  │
   │ ⚪ Info     │   177 │ tech-detect (89), misc (88)         │
   └─────────────┴───────┴─────────────────────────────────────┘

📁 Workspace: ./waf-assessment-20260205-143022/
   ├─ discovery.json      (endpoint data)
   ├─ testplan.json       (test configuration)
   ├─ results.json        (raw findings)
   ├─ report.html         (formatted report)
   └─ summary.txt         (executive summary)

✅ Assessment complete. Open report.html for detailed findings.
```

#### Decision Guide

| Your Scenario | Recommended Command | Why |
|---------------|---------------------|-----|
| First-time assessment of new target | `waf-tester auto -u URL` | Comprehensive baseline with zero config |
| Testing application behind WAF | `waf-tester auto -u URL --smart` | Optimizes for specific WAF vendor |
| Red team / bypass hunting | `waf-tester auto -u URL --smart --tamper-auto` | Maximum evasion techniques |
| CI/CD pipeline integration | `waf-tester auto -u URL --stream -format json` | Machine-readable streaming output |
| Production with rate limits | `waf-tester auto -u URL -rl 10 -c 5` | Reduced request rate |
| Quick validation after WAF change | `waf-tester scan -u URL -category sqli,xss` | Faster targeted test (use `scan` not `auto`) |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `connection refused` | Target unreachable | Check firewall, VPN, DNS. Test with `curl -I URL` |
| `0 endpoints found` | JavaScript SPA without crawlable links | Add `--browser` flag for headless browser discovery |
| `rate limited` or scan stalls at ~10% | WAF blocking scanner | Reduce rate with `-rl 20 -c 5`, add `--smart` |
| `SSL certificate error` | Self-signed or expired cert | Add `-k` flag to skip verification |
| `403 on all requests` | IP blocked or auth required | Use `-H "Authorization: Bearer TOKEN"` or `--browser` |
| Scan takes >30 minutes | Large target or slow network | Increase parallelism `-c 100`, or use `scan` for specific categories |
| `workspace already exists` | Previous scan same day | Delete old workspace or use `-workspace-dir custom-name` |

---

### Three-Step Workflow

For assessments requiring manual review between phases, use the three-step workflow. This approach provides control points for scope validation and test plan customization.

**TL;DR:** Discover → Review → Test — For regulated environments or large applications

```bash
# Step 1: Discover endpoints and attack surface (~1-2 min)
waf-tester discover -u https://example.com

# Step 2: Generate test plan from discovered endpoints (~5 sec)
waf-tester learn -discovery discovery.json

# Step 3: Execute tests and generate report (~3-8 min)
waf-tester run -plan testplan.json -format html -o report.html
```

#### What Happens at Each Step

| Step | Command | Duration | Output | What You Can Review |
|------|---------|----------|--------|---------------------|
| **1. Discover** | `discover` | 1-2 min | `discovery.json` | Endpoints, parameters, forms — remove out-of-scope items |
| **2. Plan** | `learn` | 5 sec | `testplan.json` | Test cases, categories — adjust severity filters, add custom payloads |
| **3. Execute** | `run` | 3-8 min | `report.html` | Final report — analyze findings, export to ticketing systems |

#### Sample Discovery Output

```json
{
  "target": "https://example.com",
  "discovered_at": "2026-02-05T14:30:22Z",
  "endpoints": [
    {"path": "/api/users", "methods": ["GET", "POST"], "params": ["id", "name"]},
    {"path": "/search", "methods": ["GET"], "params": ["q", "page", "sort"]},
    {"path": "/admin/login", "methods": ["GET", "POST"], "params": ["username", "password"]}
  ],
  "forms": [
    {"action": "/contact", "method": "POST", "fields": ["email", "message"]}
  ],
  "javascript_files": 23,
  "api_endpoints_from_js": 47
}
```

#### When to Use Three-Step Workflow

| Scenario | Why Three-Step Works Better |
|----------|----------------------------|
| Regulated environments (PCI, HIPAA) | Explicit approval of test scope before execution |
| Large applications (1000+ endpoints) | Filter discovery results to reduce test time |
| Custom payload requirements | Edit testplan.json to add organization-specific tests |
| Network constraints | Run discovery from one location, tests from another |
| Team collaboration | Security lead reviews plan before junior executes |
| Incremental testing | Reuse discovery, generate new plans for different categories |

---

## Why WAFtester?

| Capability | WAFtester | Nuclei | FFUF | sqlmap | Burp Suite |
|-----------|:---------:|:------:|:----:|:------:|:----------:|
| WAF Detection (197+ vendors) | ✅ | ❌ | ❌ | ❌ | Partial |
| Smart Mode (WAF-aware testing) | ✅ | ❌ | ❌ | Partial | ✅ |
| Mutation Matrix (16×13×10 = 2,080 variants) | ✅ | ❌ | ❌ | ❌ | ❌ |
| False Positive Measurement | ✅ | ❌ | ❌ | ❌ | ❌ |
| Quantitative Metrics (TPR/FPR/F1/MCC) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Bypass Hunting with Chaining | ✅ | ❌ | ❌ | Partial | ✅ |
| Intelligence Engine / Brain Mode | ✅ | Partial | ❌ | ❌ | ❌ |
| Tamper Scripts (75+) | ✅ | ❌ | ❌ | ✅ | Partial |
| CI/CD Integration (10+ platforms) | ✅ | ✅ | ❌ | ❌ | ✅ |
| Protocol Testing (GraphQL/gRPC/SOAP) | ✅ | ✅ | ❌ | ❌ | ✅ |
| Enterprise Reporting (PDF/HTML/SARIF) | ✅ | Partial | ❌ | ❌ | ✅ |
| Open Source / CLI-first | ✅ | ✅ | ✅ | ✅ | ❌ |
| One-command full assessment | ✅ | ❌ | ❌ | ❌ | ❌ |

### Coming from Another Tool?

<details>
<summary><strong>Coming from sqlmap?</strong></summary>

sqlmap focuses on SQL injection exploitation. WAFtester focuses on WAF testing across all attack categories.

| sqlmap Command | WAFtester Equivalent | What's Different |
|---------------|---------------------|-----------------|
| `sqlmap -u URL` | `waf-tester scan -u URL -category sqli` | Tests WAF detection, not DB exploitation |
| `sqlmap --tamper=space2comment` | `waf-tester scan --tamper=space2comment` | Same syntax! Plus 75+ tamper scripts |
| `sqlmap --level 5 --risk 3` | `waf-tester bypass --smart -mutation full` | Full mutation matrix (2,080 variants) |
| `sqlmap --batch --crawl=3` | `waf-tester auto -u URL --smart` | Full pipeline: crawl + scan + report |
| `sqlmap --dbs --dump` | N/A | WAFtester tests the WAF, not the database |

**Key difference:** sqlmap exploits SQL injection through WAFs. WAFtester measures WAF effectiveness across 50+ attack categories and finds bypasses in all of them.

</details>

<details>
<summary><strong>Coming from Nuclei?</strong></summary>

Nuclei focuses on known vulnerability detection via templates. WAFtester focuses on WAF bypass and effectiveness.

| Nuclei Command | WAFtester Equivalent | What's Different |
|---------------|---------------------|-----------------|
| `nuclei -u URL` | `waf-tester auto -u URL --smart` | WAF-aware, adapts to detected WAF |
| `nuclei -t cves/` | `waf-tester template -t templates/` | Compatible YAML template format |
| `nuclei -severity critical,high` | `waf-tester scan -msev critical,high` | Same severity filtering |
| `nuclei -rate-limit 100` | `waf-tester scan -rl 100` | Same rate limiting concept |
| `nuclei -cloud` | `waf-tester scan --metrics-port=9090` | Prometheus/Grafana instead of SaaS |

**Key difference:** Nuclei finds **vulnerabilities**. WAFtester finds **WAF bypasses** and measures WAF effectiveness. Use both: Nuclei for vuln scanning, WAFtester for WAF assessment.

</details>

<details>
<summary><strong>Coming from FFUF?</strong></summary>

FFUF focuses on web fuzzing. WAFtester has a compatible `fuzz` command plus full security assessment.

| FFUF Command | WAFtester Equivalent | What's Different |
|-------------|---------------------|-----------------|
| `ffuf -w wordlist -u URL/FUZZ` | `waf-tester fuzz -u URL/FUZZ -w wordlist` | Same concept, WAF-aware |
| `ffuf -mc 200 -fc 404` | `waf-tester fuzz -mc 200 -fc 404` | Identical syntax |
| `ffuf -mode clusterbomb` | `waf-tester fuzz -mode clusterbomb` | Same fuzzing modes |
| `ffuf -ac` | `waf-tester fuzz -ac` | Same auto-calibration |

**Key difference:** WAFtester's `fuzz` works like FFUF but adds WAF detection and evasion. If fuzzing through a WAF, WAFtester auto-applies tampers to avoid false 403s.

**Bonus:** WAFtester has 40+ other commands FFUF doesn't have — assessment, bypass hunting, mutation testing, protocol testing, and more.

</details>

<details>
<summary><strong>Coming from Burp Suite?</strong></summary>

Burp Suite is GUI-first with proxy intercept. WAFtester is CLI-first with automation focus.

| Burp Suite Feature | WAFtester Equivalent | Notes |
|-------------------|---------------------|-------|
| Spider/Crawler | `waf-tester crawl -u URL --browser` | Automated, no manual browsing |
| Scanner | `waf-tester auto -u URL --smart` | Full pipeline, CLI-native |
| Intruder (payload sets) | `waf-tester fuzz` + `mutate` | 2,800+ built-in attack payloads |
| Extensions | `waf-tester plugin install NAME` | Plugin ecosystem |
| Repeater | N/A (use `curl`) | WAFtester focuses on automation |
| SARIF export | `waf-tester scan -format sarif` | Native CI/CD integration |

**Key difference:** Burp Suite requires manual interaction and a GUI. WAFtester runs fully automated from CLI, making it ideal for CI/CD, batch testing, and scriptable workflows.

</details>

---

## Core Commands

This section covers the primary commands for WAF security testing. Each command serves a specific purpose in the assessment lifecycle.

### Which Command Do I Need?

```mermaid
flowchart TD
    A["🎯 What's your goal?"] --> B{"Full assessment?"}
    B -->|"Yes, automated"| C["<strong>auto</strong><br/>Full pipeline: detect → discover → scan → report"]
    B -->|"Yes, with metrics"| D["<strong>assess</strong><br/>Quantitative WAF scores: TPR/FPR/F1"]
    B -->|"No, targeted"| E{"What specifically?"}

    E --> F{"Find vulnerabilities?"}
    F -->|"Specific categories"| G["<strong>scan -category X</strong><br/>Surgical testing: sqli, xss, rce, etc."]
    F -->|"All categories"| H["<strong>scan -types all</strong><br/>Full coverage: 50+ categories"]

    E --> I{"Find WAF bypasses?"}
    I -->|"Automated"| J["<strong>bypass --smart</strong><br/>Smart bypass with auto-tampers"]
    I -->|"Manual mutation"| K["<strong>mutate -mutation full</strong><br/>16 encoders × 13 locations × 10 evasions"]

    E --> L{"Identify WAF vendor?"}
    L --> M["<strong>vendor</strong><br/>197+ WAF signatures + bypass hints"]

    E --> N{"Measure false positives?"}
    N --> O["<strong>fp -corpus builtin</strong><br/>Benign traffic → FPR calculation"]

    E --> P{"Fuzz paths/params?"}
    P --> Q["<strong>fuzz -u URL/FUZZ</strong><br/>FFUF-compatible directory/param fuzzing"]

    E --> R{"API protocol testing?"}
    R --> S{"Which protocol?"}
    S -->|GraphQL| T["<strong>scan -types graphql</strong>"]
    S -->|gRPC| U["<strong>grpc --fuzz</strong>"]
    S -->|SOAP| V["<strong>soap --fuzz</strong>"]
    S -->|REST/OpenAPI| W["<strong>openapi --fuzz</strong>"]

    style C fill:#e8f5e9
    style D fill:#e8f5e9
    style G fill:#e3f2fd
    style H fill:#e3f2fd
    style J fill:#fce4ec
    style K fill:#fce4ec
    style M fill:#fff3e0
    style O fill:#f3e5f5
    style Q fill:#e0f2f1
```

> **Still not sure?** Start with `waf-tester auto -u https://YOUR_TARGET --smart` — it runs the full pipeline automatically.

**Command Selection Guide:**

| Goal | Command | Time | Output |
|------|---------|------|--------|
| Complete automated assessment | `auto` | 5-15 min | Full report with all findings |
| Quantitative WAF metrics | `assess` | 3-10 min | Statistical scores (TPR, FPR, F1) |
| Targeted vulnerability scan | `scan` | 2-8 min | Findings for specific categories |
| Identify WAF vendor | `vendor` | 10-30 sec | Vendor name, confidence, bypass hints |
| Find WAF bypasses | `bypass` | 5-20 min | Confirmed bypass payloads |
| Test false positive rate | `fp` | 2-5 min | FPR percentage and blocked benign requests |

---

### Automated Scanning (auto)

**Purpose:** Execute a complete end-to-end WAF security assessment with zero manual configuration.

**TL;DR:** `waf-tester auto -u https://example.com --smart` — Full assessment in 5-15 minutes

The `auto` command chains discovery, JavaScript analysis, test planning, execution, and reporting phases automatically. It's the recommended starting point for most assessments.

#### Complexity Tiers

> **📋 Copy-Paste Ready** — 90% of users need exactly this:
> ```bash
> waf-tester auto -u https://YOUR_TARGET --smart
> ```

##### 🟢 Beginner — Just works, zero configuration
```bash
# "I just want to test this site"
waf-tester auto -u https://target.com
```
*Runs full pipeline: WAF detect → crawl → scan → report. Output in ./waf-assessment-*/*

##### 🟡 Intermediate — Smart mode with output control
```bash
# "I want smart WAF evasion and JSON output"
waf-tester auto -u https://target.com \
  --smart \
  -format json,html \
  -o results.json
```
*Smart mode auto-detects WAF and selects optimal bypass strategies*

##### 🔴 Advanced — Full control over every parameter
```bash
# "I'm a pro — give me everything"
waf-tester auto -u https://target.com \
  --smart --smart-mode=full \
  --browser \
  --tamper-auto \
  -c 100 -rl 500 \
  -service wordpress \
  -format html,json,sarif \
  -o ./full-assessment \
  --slack-webhook=$SLACK_URL \
  --metrics-port=9090
```
*Full-power scan with browser rendering, parallel workers, multi-format output, and real-time alerts*

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target on ports 80/443 |
| **Authorization** | Written permission to test (sends 2,800+ attack payloads) |
| **Memory** | ~500MB RAM for large targets |
| **Disk** | ~50MB for workspace (discovery data, reports) |
| **Time** | 5-15 minutes depending on target size |

#### Execution Phases

| Phase | Duration | What Happens | Requests |
|-------|----------|--------------|----------|
| **Connection** | 2-5s | TLS handshake, detect HTTP/2, measure latency | 3-5 |
| **WAF Detection** | 5-10s | Send probe payloads, match 197 vendor signatures | 10-20 |
| **Discovery** | 30-90s | Crawl site, parse JS, extract endpoints/params | 100-500 |
| **Planning** | 2-5s | Generate optimized test plan (local, no requests) | 0 |
| **Testing** | 2-8min | Execute 2,800+ payloads across all categories | 2,800-10,000 |
| **Analysis** | 5-15s | Calculate bypass rates, rank by severity (local) | 0 |
| **Reporting** | 2-5s | Generate HTML/JSON/Markdown reports (local) | 0 |

#### Basic Usage

```bash
waf-tester auto -u https://example.com
```

#### With Smart Mode (Recommended for WAFs)

Smart mode identifies the WAF vendor before testing and optimizes the assessment strategy. This significantly improves bypass discovery rates.

```bash
waf-tester auto -u https://example.com --smart
```

**What `--smart` does:**
1. Detects WAF vendor from 197 signatures (Cloudflare, AWS WAF, Akamai, etc.)
2. Selects tamper techniques proven effective against that specific WAF
3. Adjusts timing to avoid rate limiting
4. Uses WAF-specific block detection patterns

#### With Automatic Tamper Selection

Tamper scripts transform payloads to evade WAF detection. Auto-selection chooses tampers based on detected WAF.

```bash
# Auto-select optimal tampers based on detected WAF
waf-tester auto -u https://example.com --smart --tamper-auto

# Use specific tamper profile
waf-tester auto -u https://example.com --tamper-profile=aggressive

# Combine manual tampers with auto-selection
waf-tester auto -u https://example.com --tamper=nullbyte,space2comment --tamper-auto
```

**Tamper Profiles:**

| Profile | Techniques | Use Case |
|---------|------------|----------|
| `stealth` | Minimal, low-risk transformations | Production systems, avoid detection |
| `standard` | Balanced set of common evasions | General testing (default) |
| `aggressive` | All applicable techniques, chained | Red team, maximum bypass attempts |
| `bypass` | Heavy encoding, protocol tricks | WAF tuning, finding edge cases |

#### Full Options Reference

```bash
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=full \
  --tamper-auto \
  -c 100 \
  -rl 300 \
  --browser
```

| Option | Default | Description |
|--------|---------|-------------|
| `--smart` | off | Enable WAF-aware testing with vendor detection |
| `--smart-mode=MODE` | standard | `quick` (fast), `standard`, `full` (comprehensive), `bypass`, `stealth` |
| `--tamper=LIST` | none | Comma-separated tamper names (see [Tamper Scripts](#tamper-scripts)) |
| `--tamper-auto` | off | Auto-select tampers based on detected WAF |
| `--tamper-profile=P` | standard | Preset: `stealth`, `standard`, `aggressive`, `bypass` |
| `-c N` | 25 | Parallel workers (increase for speed, decrease for stealth) |
| `-rl N` | 150 | Max requests per second (reduce if rate limited) |
| `--browser` | off | Use headless Chrome for JS-heavy SPAs and authenticated areas |
| `-service NAME` | auto | Framework preset: `wordpress`, `django`, `rails`, etc. |
| `-format F` | html | Report format: `json`, `html`, `markdown`, `csv`, `sarif` |
| `-o FILE` | auto | Output file path (default: workspace/report.FORMAT) |

#### Sample Output

```
$ waf-tester auto -u https://api.example.com --smart --tamper-auto

WAFtester v2.6.5 — Comprehensive WAF Security Assessment

Target: https://api.example.com
Mode: Smart (WAF-aware) with auto-tamper

──────────────────────────────────────────────────────────────────────
 PHASE 1: WAF DETECTION                                         [2s]
──────────────────────────────────────────────────────────────────────
 ✓ Vendor: AWS WAF (confidence: 91%)
 ✓ Block response: 403 Forbidden
 ✓ Block indicators: x-amzn-requestid header, "Request blocked" body
 ✓ Auto-selected tampers: unicode_normalize, multipart_boundary, chunk_transfer

──────────────────────────────────────────────────────────────────────
 PHASE 2: DISCOVERY                                             [47s]
──────────────────────────────────────────────────────────────────────
 ✓ Crawled 156 pages (depth: 3)
 ✓ Parsed 34 JavaScript files
 ✓ Extracted 892 endpoints
 ✓ Discovered 2,847 parameters
 ✓ Found 18 forms, 12 file upload points

──────────────────────────────────────────────────────────────────────
 PHASE 3: TESTING                                             [4m12s]
──────────────────────────────────────────────────────────────────────
 [████████████████████████████████████████] 100% (9,234/9,234)

 Category Breakdown:
 ├─ SQLi:       1,247 tests | 1,198 blocked (96.1%) | 49 bypassed
 ├─ XSS:        1,089 tests | 1,034 blocked (95.0%) | 55 bypassed
 ├─ Traversal:    456 tests |   412 blocked (90.4%) | 44 bypassed
 ├─ RCE:          234 tests |   231 blocked (98.7%) | 3 bypassed
 ├─ SSRF:         189 tests |   178 blocked (94.2%) | 11 bypassed
 └─ [+45 more categories...]

──────────────────────────────────────────────────────────────────────
 RESULTS SUMMARY
──────────────────────────────────────────────────────────────────────
 🔴 Critical:    5 findings (RCE bypass, SQLi auth bypass)
 🟠 High:       23 findings (SQLi, XSS, SSRF bypasses)
 🟡 Medium:     67 findings (Path traversal, redirects)
 🔵 Low:       134 findings (Info disclosure, headers)
 ⚪ Info:      201 findings (Tech detection, fingerprints)

 Overall WAF Effectiveness: 94.2% blocked
 Bypass Rate: 5.8% (430 payloads evaded detection)

──────────────────────────────────────────────────────────────────────
 OUTPUT FILES
──────────────────────────────────────────────────────────────────────
 📁 ./waf-assessment-20260205-143022/
    ├─ report.html          Executive report with findings
    ├─ results.json         Machine-readable results
    ├─ discovery.json       Endpoint inventory
    ├─ bypasses.json        Confirmed bypass payloads
    └─ summary.txt          One-page executive summary

✅ Assessment complete in 5m03s
```

#### Service-Specific Scanning

When you know the target framework, use service presets for optimized testing:

```bash
waf-tester auto -u https://myblog.com -service wordpress
waf-tester auto -u https://myapp.com -service django
waf-tester auto -u https://store.com -service nextjs
```

| Service | Optimizations Applied |
|---------|----------------------|
| `wordpress` | WP-specific paths, plugin vulns, xmlrpc, wp-admin |
| `drupal` | Drupal paths, node access, views exploits |
| `django` | Debug pages, admin paths, template injection |
| `rails` | Rails routes, asset pipeline, mass assignment |
| `laravel` | Laravel paths, debug mode, Blade injection |
| `spring` | Actuator endpoints, SpEL injection, mass assignment |
| `nextjs` | API routes, _next paths, SSR injection points |
| `flask` | Debug mode, Jinja2 SSTI, Flask-specific paths |

#### Decision Guide

| Your Situation | Command Variation | Why |
|----------------|-------------------|-----|
| First assessment, unknown WAF | `auto -u URL --smart` | Auto-detect and optimize |
| Known WAF, need bypasses | `auto -u URL --smart --tamper-auto` | Maximum evasion |
| Red team, stealth required | `auto -u URL --smart-mode=stealth -rl 10` | Low and slow |
| CI/CD pipeline | `auto -u URL --stream -format sarif` | Machine-readable output |
| JS-heavy SPA | `auto -u URL --browser` | Headless browser for discovery |
| Rate-limited target | `auto -u URL -rl 20 -c 5` | Reduced request rate |
| Large target (>1000 pages) | `auto -u URL -c 100` | Parallel for speed |
| Specific framework | `auto -u URL -service wordpress` | Framework-optimized |

#### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| `connection refused` | Target unreachable | Check firewall, VPN. Test: `curl -I URL` |
| `0 endpoints found` | SPA without crawlable links | Add `--browser` for headless Chrome |
| Scan stalls at ~10% | WAF rate limiting | Reduce: `-rl 20 -c 5` |
| All requests blocked | IP banned or auth required | Use VPN, add auth headers |
| `SSL certificate error` | Self-signed/expired cert | Add `-k` to skip verification |
| `workspace exists` error | Previous scan same day | Use `-workspace-dir newname` |
| Very slow (>30 min) | Large target or slow network | Increase `-c 100`, or use `scan` for specific categories |
| Low bypass rate (0%) | WAF not in path, or very strict | Verify WAF presence with `vendor` command |

> **See Also:** [Smart Mode](#smart-mode) · [Tamper Scripts](#tamper-scripts) · [Intelligence Engine](#intelligence-engine-v265) · [Playbook: New Client](#playbook-1-new-client--first-waf-assessment)

---

### Enterprise Assessment (assess)

**Purpose:** Generate quantitative WAF effectiveness metrics for compliance reporting and vendor comparisons.

**TL;DR:** `waf-tester assess -u https://example.com -fp` — Statistical WAF scores with false positive testing

The `assess` command produces objective, reproducible metrics (detection rate, false positive rate, F1 score) that enable data-driven decisions about WAF configuration and vendor selection.

#### Complexity Tiers

> **📋 Copy-Paste Ready:**
> ```bash
> waf-tester assess -u https://YOUR_TARGET -fp -corpus builtin
> ```

##### 🟢 Beginner — Quick detection rate check
```bash
waf-tester assess -u https://target.com
```
*Quick detection rate check — sends ~2,800 attack payloads, shows TPR.*

##### 🟡 Intermediate — Full assessment with JSON export
```bash
waf-tester assess -u https://target.com \
  -fp -corpus builtin \
  -format json -o assessment.json
```
*Full assessment with false positive measurement and JSON export for tracking.*

##### 🔴 Advanced — Compliance-grade multi-format reports
```bash
waf-tester assess -u https://target.com \
  -fp -corpus "builtin,leipzig" \
  -categories sqli,xss,rce,ssrf,ssti \
  --smart \
  -format html,json,pdf \
  -o ./compliance-report \
  --threshold 90 \
  --metrics-port=9090
```
*Compliance-grade assessment with custom categories, multi-format reports, quality thresholds, and Prometheus metrics.*

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Written permission (sends attack payloads + benign traffic) |
| **Memory** | ~300MB RAM |
| **Time** | 3-10 minutes |
| **Corpus** | Built-in or custom benign traffic corpus for FP testing |

#### What Gets Measured

| Metric | Formula | Interpretation |
|--------|---------|----------------|
| **Detection Rate (TPR)** | Attacks Blocked / Total Attacks | Higher = better protection (target: >90%) |
| **False Positive Rate (FPR)** | Legitimate Blocked / Total Legitimate | Lower = less business disruption (target: <1%) |
| **Precision** | True Blocks / All Blocks | Higher = fewer false alarms |
| **Recall** | Same as TPR | Higher = fewer missed attacks |
| **F1 Score** | 2 × (Precision × Recall) / (Precision + Recall) | Balanced measure (target: >0.9) |
| **MCC** | Matthews Correlation Coefficient | Best single metric (-1 to +1, target: >0.8) |

#### Basic Assessment

```bash
waf-tester assess -u https://example.com
```

**What happens:** Sends ~2,800 attack payloads, records block/allow decisions, calculates detection metrics.

#### Full Assessment with False Positive Testing

```bash
waf-tester assess -u https://example.com \
  -fp \
  -corpus "builtin,leipzig" \
  -format json \
  -o assessment.json
```

**What happens:** Same as basic, plus sends ~5,000 benign requests from corpora to measure false positive rate.

#### Sample Output

```
$ waf-tester assess -u https://secure.example.com -fp -corpus builtin

WAFtester v2.6.5 — Enterprise WAF Assessment

Target: https://secure.example.com
Mode: Full assessment with false positive testing

═══════════════════════════════════════════════════════════════════════
 ATTACK DETECTION TESTING                                       [3m24s]
═══════════════════════════════════════════════════════════════════════

 Category          │ Total │ Blocked │ Bypassed │ Detection Rate
 ──────────────────┼───────┼─────────┼──────────┼───────────────
 SQL Injection     │  1247 │    1198 │       49 │  96.1%
 Cross-Site Script │  1089 │    1067 │       22 │  98.0%
 Remote Code Exec  │   234 │     232 │        2 │  99.1%
 Path Traversal    │   456 │     398 │       58 │  87.3%
 Server-Side RF    │   189 │     183 │        6 │  96.8%
 Command Injection │   178 │     175 │        3 │  98.3%
 XML External Ent  │    89 │      87 │        2 │  97.8%
 Template Inject   │   112 │      98 │       14 │  87.5%
 [+42 categories]  │   ...  │     ...  │      ...  │  ...
 ──────────────────┴───────┴─────────┴──────────┴───────────────
 TOTAL             │  2834 │    2712 │      122 │  95.7%

═══════════════════════════════════════════════════════════════════════
 FALSE POSITIVE TESTING                                          [1m47s]
═══════════════════════════════════════════════════════════════════════

 Corpus            │ Total │ Blocked │ Allowed  │ False Positive Rate
 ──────────────────┼───────┼─────────┼──────────┼────────────────────
 Built-in benign   │  2500 │      12 │     2488 │  0.48%
 Leipzig English   │  1500 │       4 │     1496 │  0.27%
 Leipzig German    │  1000 │       2 │      998 │  0.20%
 ──────────────────┴───────┴─────────┴──────────┴────────────────────
 TOTAL             │  5000 │      18 │     4982 │  0.36%

═══════════════════════════════════════════════════════════════════════
 ASSESSMENT METRICS
═══════════════════════════════════════════════════════════════════════

 Metric                    │ Score   │ Rating     │ Industry Target
 ──────────────────────────┼─────────┼────────────┼────────────────
 Detection Rate (TPR)      │ 95.7%   │ ★★★★☆     │ >90%
 False Positive Rate (FPR) │  0.36%  │ ★★★★★     │ <1%
 Precision                 │ 99.3%   │ ★★★★★     │ >95%
 Recall                    │ 95.7%   │ ★★★★☆     │ >90%
 F1 Score                  │ 0.975   │ ★★★★★     │ >0.90
 Matthews Correlation (MCC)│ 0.951   │ ★★★★★     │ >0.80
 ──────────────────────────┴─────────┴────────────┴────────────────

 Overall Grade: A (Excellent)

 Recommendations:
 • Path traversal detection (87.3%) below target - review traversal rules
 • Template injection (87.5%) below target - add SSTI signatures
 • 18 false positives detected - review for overly aggressive rules

═══════════════════════════════════════════════════════════════════════
 OUTPUT FILES
═══════════════════════════════════════════════════════════════════════
 📄 assessment.json        Full metrics in machine-readable format
 📄 assessment.html        Formatted report for stakeholders
 📄 false-positives.txt    List of blocked benign requests
 📄 bypasses.txt           List of unblocked attack payloads

✅ Assessment complete in 5m11s
```

#### Custom Categories

Focus on specific vulnerability categories for compliance:

```bash
# OWASP Top 10 focused
waf-tester assess -u https://example.com -categories sqli,xss,rce,xxe,ssrf

# PCI-DSS relevant
waf-tester assess -u https://example.com -categories sqli,xss,traversal

# API-focused
waf-tester assess -u https://example.com -categories sqli,nosqli,jwt,graphql
```

#### Available Corpora for False Positive Testing

| Corpus | Description | Size |
|--------|-------------|------|
| `builtin` | Curated benign traffic samples | 2,500 |
| `leipzig` | Natural language sentences (multiple languages) | 5,000+ |
| `/path/to/file.txt` | Custom corpus (one request per line) | Variable |

```bash
# Multiple corpora
waf-tester assess -u https://example.com -fp -corpus "builtin,leipzig"

# Custom corpus
waf-tester assess -u https://example.com -fp -corpus /path/to/benign-requests.txt
```

#### With Streaming Output

Stream results in real-time for CI/CD pipeline integration:

```bash
waf-tester assess -u https://example.com --stream -format json -o report.json
```

*Enables early failure detection without waiting for complete assessment.*

#### Decision Guide

| Your Goal | Command | Why |
|-----------|---------|-----|
| Baseline WAF effectiveness | `assess -u URL` | Quick detection rate check |
| Full compliance report | `assess -u URL -fp -corpus builtin,leipzig` | Detection + false positives |
| Vendor comparison | `assess -u URL -fp -format json` | Export for comparison dashboard |
| After rule changes | `assess -u URL -categories sqli` | Check specific rule category |
| CI/CD quality gate | `assess -u URL --stream -threshold 90` | Fail if detection <90% |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| FPR = 0% exactly | Corpus not reaching backend | Verify requests reach app, not cached |
| Detection = 100% | WAF blocking all traffic | May be blocking scanner, not payloads |
| Metrics fluctuating | Inconsistent WAF responses | Increase `-retries 5`, reduce `-rl` |
| Long runtime (>20 min) | Large corpus or slow target | Use smaller corpus, increase `-c` |

> **See Also:** [False Positive Testing](#false-positive-testing-fp) · [Output Formats](#output-formats) · [Playbook: Vendor Comparison](#playbook-3-waf-vendor-comparison--cloudflare-vs-aws-waf) · [Playbook: Compliance Audit](#playbook-9-compliance-audit--pci-dss--soc-2)

---

### Vulnerability Scanning (scan)

**Purpose:** Targeted vulnerability testing with granular control over categories, severity, and scope.

**TL;DR:** `waf-tester scan -u https://target.com -category sqli,xss` — Focused testing in 2-5 minutes

Unlike `auto`, the `scan` command offers surgical precision for testing specific vulnerability classes, making it ideal for follow-up testing, regression validation, and category-specific compliance.

#### Complexity Tiers

> **📋 Copy-Paste Ready:**
> ```bash
> waf-tester scan -u https://YOUR_TARGET -category sqli,xss --smart
> ```

##### 🟢 Beginner — Default categories, instant results
```bash
waf-tester scan -u https://target.com
```
*Tests default categories (sqli, xss, traversal, rce). Results printed to console.*

##### 🟡 Intermediate — Targeted categories with JSON export
```bash
waf-tester scan -u https://target.com \
  -category sqli,xss,rce \
  --smart \
  -format json \
  -o scan-results.json
```
*Targeted categories with WAF-aware testing and JSON export.*

##### 🔴 Advanced — Full control with evasion and alerting
```bash
waf-tester scan -u https://target.com \
  -category sqli,xss,rce,ssrf,ssti \
  --smart --tamper-auto --tamper-profile=aggressive \
  -c 50 -rl 200 \
  -msev critical,high \
  -ip "/api/" -ep "logout|health" \
  -format sarif -o results.sarif \
  --slack-webhook=$SLACK_URL
```
*Full control: categories, evasion, concurrency, severity filter, path scope, SARIF output, and alerts.*

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Written permission to test |
| **Memory** | ~200MB RAM |
| **Time** | 1-10 minutes (depends on categories) |

#### Category Selection

| Scan Type | Categories Tested | Approx. Time |
|-----------|-------------------|--------------|
| Default (no flag) | sqli, xss, traversal, rce | 3-5 min |
| `-category sqli` | SQL injection only | 1-2 min |
| `-category sqli,xss,rce` | Specified categories | 2-4 min |
| `-types all` | All 50+ categories | 10-15 min |

#### Basic Scan

```bash
waf-tester scan -u https://target.com
```

#### Category-Specific Scan

```bash
# Single category
waf-tester scan -u https://target.com -category sqli

# Multiple categories
waf-tester scan -u https://target.com -category sqli,xss,traversal

# All categories
waf-tester scan -u https://target.com -types all
```

#### With Smart Mode and Tampers

```bash
# Smart mode with auto-tamper
waf-tester scan -u https://target.com --smart --tamper-auto

# Aggressive bypass hunting
waf-tester scan -u https://target.com --tamper-profile=aggressive

# Stealth mode for production
waf-tester scan -u https://target.com --tamper-profile=stealth -rl 10
```

#### Sample Output

```
$ waf-tester scan -u https://api.example.com -category sqli,xss --smart

WAFtester v2.6.5 — Targeted Vulnerability Scan

Target: https://api.example.com
Categories: sqli, xss
Mode: Smart (AWS WAF detected)

Scanning [████████████████████████████████████████] 100% (2,336/2,336)

──────────────────────────────────────────────────────────────────────
 FINDINGS
──────────────────────────────────────────────────────────────────────

 🔴 CRITICAL: SQL Injection Authentication Bypass
    Endpoint: POST /api/login
    Parameter: username
    Payload: admin'--
    Evidence: HTTP 200, "Welcome admin" in response
    WAF Status: BYPASSED

 🟠 HIGH: Reflected XSS in Search
    Endpoint: GET /search?q=
    Parameter: q
    Payload: <script>alert(1)</script>
    Evidence: Payload reflected unencoded in response
    WAF Status: BYPASSED

 🟠 HIGH: SQL Injection in User Lookup
    Endpoint: GET /api/users?id=
    Parameter: id
    Payload: 1 OR 1=1
    Evidence: Multiple user records returned
    WAF Status: BYPASSED

 [... 23 more findings ...]

──────────────────────────────────────────────────────────────────────
 SUMMARY
──────────────────────────────────────────────────────────────────────

 Requests: 2,336 | Duration: 2m14s | Rate: 17.4 req/sec

 Findings by Severity:
 • Critical: 1
 • High: 8
 • Medium: 15
 • Low: 42
 • Info: 67

 WAF Effectiveness (sqli,xss): 94.3% blocked

✅ Scan complete. Results saved to scan-results.json
```

#### Severity and Category Filtering

```bash
# Only show critical and high findings
waf-tester scan -u https://target.com -msev critical,high

# Exclude low-severity noise
waf-tester scan -u https://target.com -fsev low,info

# Match specific categories in output
waf-tester scan -u https://target.com -mcat sqli,xss

# Filter out informational findings
waf-tester scan -u https://target.com -fcat info
```

#### Scope Control

```bash
# Exclude certain URL patterns
waf-tester scan -u https://target.com -ep "logout|signout|admin"

# Include only matching patterns
waf-tester scan -u https://target.com -ip "api/v2"

# Exclude certain test types
waf-tester scan -u https://target.com -et info,techdetect
```

#### OAuth Testing

Specialized testing for OAuth 2.0 implementations including authorization flow vulnerabilities.

```bash
# Scan OAuth endpoints for common vulnerabilities
waf-tester scan -u https://auth.example.com -types oauth \
  -oauth-client-id "client123" \
  -oauth-auth-endpoint "https://auth.example.com/authorize" \
  -oauth-token-endpoint "https://auth.example.com/token" \
  -oauth-redirect-uri "https://app.example.com/callback"
```

#### Debug Options

```bash
# Enable debug output
waf-tester scan -u https://target.com -debug

# Show request details
waf-tester scan -u https://target.com -dreq

# Show response details
waf-tester scan -u https://target.com -dresp

# CPU/Memory profiling
waf-tester scan -u https://target.com -profile -mem-profile
```

#### Dry Run

```bash
# Show what would be scanned without actually scanning
waf-tester scan -u https://target.com -dry-run
```

#### Report Options

```bash
# Custom report title and author
waf-tester scan -u https://target.com \
  -report-title "Security Assessment Q1 2026" \
  -report-author "Security Team"

# Include/exclude evidence and remediation
waf-tester scan -u https://target.com -ie=false -ir=false
```

#### Multiple Targets

```bash
# From file
waf-tester scan -l targets.txt -c 50

# With same options for all
waf-tester scan -l targets.txt -category sqli --smart -o results.json
```

#### Decision Guide

| Your Goal | Command | Why |
|-----------|---------|-----|
| Quick SQLi check | `scan -u URL -category sqli` | Fast, focused |
| OWASP Top 10 | `scan -u URL -types all -msev critical,high` | Comprehensive with severity filter |
| Regression test after fix | `scan -u URL -category sqli -ip "/api/users"` | Target specific endpoint |
| Production (no noise) | `scan -u URL -fsev low,info` | Only actionable findings |
| Compare before/after | `scan -u URL -format json -o before.json` | Export for diff |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| 0 findings | WAF blocking all, or no vulns | Check with `--smart` to verify WAF detection |
| Too many findings | Info-level noise | Use `-fsev info,low` to filter |
| Slow scan | Large category set | Use specific `-category` instead of `all` |
| Same finding repeated | Multiple parameters vulnerable | Expected - each is unique finding |

> **See Also:** [Smart Mode](#smart-mode) · [Output Formats](#output-formats) · [CI/CD Integration](#cicd-integration) · [Playbook: CI/CD Pipeline](#playbook-2-cicd-pipeline--block-deploys-on-waf-regression)

---

### WAF Detection (vendor)

**Purpose:** Identify WAF vendor, version, and configuration from 197+ signatures before testing.

**TL;DR:** `waf-tester vendor -u https://target.com` — Instant WAF identification in 10-30 seconds

Knowing the WAF vendor before testing enables targeted bypass techniques and helps interpret test results. This command should be your first step for any protected target.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Minimal (sends ~20 benign + ~5 trigger requests) |
| **Time** | 10-30 seconds |

#### Detection Methods

| Method | How It Works | Accuracy |
|--------|--------------|----------|
| **Header Analysis** | Looks for WAF-specific headers (cf-ray, x-amzn-requestid, x-sucuri-id) | High |
| **Cookie Detection** | Identifies WAF cookies (__cfduid, incap_ses_*, etc.) | High |
| **Block Page Analysis** | Matches block page patterns against 197 vendor signatures | Medium-High |
| **Error Fingerprinting** | Analyzes error responses for WAF-specific patterns | Medium |
| **Timing Analysis** | Measures response time patterns indicative of WAF processing | Low-Medium |

#### Basic Detection

```bash
waf-tester vendor -u https://target.com
```

#### Sample Output

```
$ waf-tester vendor -u https://secure.example.com

WAFtester v2.6.5 — WAF Vendor Detection

Target: https://secure.example.com

Probing target...
├─ Sending baseline requests (5)
├─ Sending trigger payloads (15)
└─ Analyzing response patterns

══════════════════════════════════════════════════════════════════════
 WAF DETECTED
══════════════════════════════════════════════════════════════════════

 Vendor:        Cloudflare
 Confidence:    94%
 Detection:     Header (cf-ray), Cookie (__cfduid), Block page pattern

 Block Behavior:
 ├─ Status Code:     403 Forbidden
 ├─ Block Header:    cf-ray: 7a8b9c0d1e2f3g4h
 ├─ Block Body:      "Attention Required! | Cloudflare"
 └─ Challenge Type:  JavaScript challenge (5s delay)

══════════════════════════════════════════════════════════════════════
 BYPASS HINTS
══════════════════════════════════════════════════════════════════════

 Cloudflare-specific evasion techniques:

 1. Unicode Normalization
    Cloudflare normalizes Unicode inconsistently.
    Try: %EF%BC%87 instead of ' for SQL injection

 2. Chunked Transfer Encoding
    Split payloads across chunks to bypass pattern matching.
    Use: --tamper=chunk_transfer

 3. HTTP/2 Pseudo-headers
    Cloudflare's HTTP/2 parsing differs from origin.
    Use: --tamper=http2_pseudo

 4. WebSocket Upgrade
    WebSocket traffic bypasses some WAF rules.
    Use: waf-tester websocket -u URL

 5. Multipart Boundary Manipulation
    Non-standard boundaries may bypass parsers.
    Use: --tamper=multipart_boundary

══════════════════════════════════════════════════════════════════════
 RECOMMENDED NEXT STEPS
══════════════════════════════════════════════════════════════════════

 # Run smart scan with auto-selected tampers:
 waf-tester scan -u https://secure.example.com --smart --tamper-auto

 # Run bypass hunting for this WAF:
 waf-tester bypass -u https://secure.example.com --smart

✅ Detection complete in 12s
```

#### Output Options

```bash
# JSON output for automation
waf-tester vendor -u https://target.com -output waf-info.json

# Verbose output with all detection details
waf-tester vendor -u https://target.com -v

# Quiet mode (vendor name only)
waf-tester vendor -u https://target.com -q
```

#### Multiple Targets

```bash
waf-tester vendor -l targets.txt -o vendors.json
```

#### Supported WAF Vendors (197+)

| Category | Examples |
|----------|----------|
| **Cloud WAFs** | Cloudflare, AWS WAF, Azure WAF, Google Cloud Armor, Fastly |
| **CDN WAFs** | Akamai, Imperva/Incapsula, Sucuri, StackPath, KeyCDN |
| **Enterprise** | F5 BIG-IP, Fortinet FortiWeb, Barracuda, Citrix NetScaler |
| **Open Source** | ModSecurity, Coraza, NAXSI, Shadow Daemon |
| **Appliances** | Palo Alto, Check Point, Juniper, SonicWall |
| **Hosting** | Wordfence (WordPress), SiteLock, GoDaddy |

#### Decision Guide

| Scenario | Command | Next Action |
|----------|---------|-------------|
| Unknown if WAF exists | `vendor -u URL` | If no WAF, use `scan` directly |
| WAF detected, need bypasses | `vendor -u URL -v` | Note bypass hints, use `--smart --tamper-auto` |
| Multiple targets to check | `vendor -l targets.txt` | Filter list for WAF-protected only |
| CI/CD WAF verification | `vendor -u URL -output json` | Parse JSON in pipeline |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "No WAF detected" but you know there is | WAF in transparent mode | Try `vendor -u URL -v` for deeper analysis |
| Low confidence (50-70%) | WAF using minimal fingerprints | Use `--smart` anyway, it will adapt |
| "Multiple WAFs detected" | CDN + WAF stack (common) | Both are real, test both bypass sets |
| Slow detection (>1 min) | Rate limiting or challenge | Reduce probes with `-probes 10` |

> **See Also:** [Smart Mode](#smart-mode) · [Bypass Hunting](#bypass-hunting-bypass) · [Playbook: New Client](#playbook-1-new-client--first-waf-assessment)

---

### Protocol Detection (protocol)

**Purpose:** Detect enterprise protocols (GraphQL, gRPC, SOAP, WCF) for specialized testing.

**TL;DR:** `waf-tester protocol -u https://target.com` — Find API protocols in 20-60 seconds

Modern applications use diverse protocols. This command identifies which protocols are in use so you can apply appropriate security tests.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Low impact (sends protocol-specific probes) |
| **Time** | 20-60 seconds |

#### Basic Detection

```bash
waf-tester protocol -u https://target.com
```

#### Sample Output

```
$ waf-tester protocol -u https://api.example.com

WAFtester v2.6.5 — Protocol Detection

Target: https://api.example.com

Probing for enterprise protocols...

══════════════════════════════════════════════════════════════════════
 DETECTED PROTOCOLS
══════════════════════════════════════════════════════════════════════

 ✓ GraphQL
   Endpoint:    /graphql
   Evidence:    Introspection query returned schema
   Operations:  Query, Mutation, Subscription
   Schema Size: 847 types, 2,341 fields
   → Run: waf-tester scan -u URL/graphql -types graphql

 ✓ REST API
   Endpoints:   /api/v1/*, /api/v2/*
   Evidence:    JSON responses, RESTful patterns
   Methods:     GET, POST, PUT, DELETE, PATCH
   Auth:        Bearer token (Authorization header)
   → Run: waf-tester scan -u URL -types api

 ✗ gRPC
   Status:      Not detected
   Attempted:   gRPC-Web, gRPC over HTTP/2

 ✗ SOAP/WSDL
   Status:      Not detected
   Attempted:   ?wsdl, /wsdl, /service.asmx

 ✗ WCF
   Status:      Not detected
   Attempted:   /mex, ?disco, .svc endpoints

══════════════════════════════════════════════════════════════════════
 RECOMMENDATIONS
══════════════════════════════════════════════════════════════════════

 # Test GraphQL for security issues:
 waf-tester scan -u https://api.example.com/graphql -types graphql

 # Full API security assessment:
 waf-tester auto -u https://api.example.com --smart

✅ Detection complete in 34s
```

#### Protocol-Specific Testing

```bash
# GraphQL testing
waf-tester scan -u https://api.example.com/graphql -types graphql

# gRPC testing
waf-tester grpc -u https://api.example.com:443

# SOAP/WSDL testing
waf-tester soap -u https://api.example.com/service.asmx?wsdl
```

#### What Each Protocol Detection Checks

| Protocol | Detection Method | Endpoints Probed |
|----------|------------------|------------------|
| **GraphQL** | Introspection query, __schema query | /graphql, /gql, /query, /api/graphql |
| **gRPC** | gRPC-Web headers, HTTP/2 SETTINGS | /, /grpc.*, application/grpc headers |
| **SOAP** | WSDL fetch, envelope detection | ?wsdl, /*.wsdl, /services, /*.asmx |
| **WCF** | MEX endpoint, .svc detection | /mex, ?disco, /*.svc |
| **REST** | JSON responses, HTTP method support | /api/*, /v1/*, /v2/* |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| GraphQL not detected | Introspection disabled | Use `scan -types graphql` anyway with field fuzzing |
| gRPC not detected | gRPC over TCP not HTTP | Use `waf-tester grpc` with proper port |
| All protocols "not detected" | Custom paths | Use `-paths /custom/api,/myservice` |

---

### Bypass Hunting (bypass)

**Purpose:** Systematically find WAF bypass payloads using mutation matrix and chaining.

**TL;DR:** `waf-tester bypass -u https://target.com --smart --tamper-auto` — Find bypasses in 5-20 minutes

The `bypass` command is specifically designed to find payloads that evade WAF detection. It uses a full mutation matrix with encoding combinations, location variations, and chainable evasion techniques.

#### Complexity Tiers

> **📋 Copy-Paste Ready:**
> ```bash
> waf-tester bypass -u https://YOUR_TARGET --smart --tamper-auto
> ```

##### 🟢 Beginner — Smart auto-detection, zero config
```bash
waf-tester bypass -u https://target.com --smart
```
*Auto-detects WAF, selects optimal bypass strategies. Shows confirmed bypasses.*

##### 🟡 Intermediate — Focused categories with exports
```bash
waf-tester bypass -u https://target.com \
  --smart --tamper-auto \
  -category sqli,xss \
  -format json -o bypasses.json
```
*Focused categories with auto-selected tamper scripts and JSON export.*

##### 🔴 Advanced — Full mutation matrix with chaining
```bash
waf-tester bypass -u https://target.com \
  --smart --smart-mode=bypass \
  -category sqli,xss,rce \
  -mutation full -chain -max-chain 3 \
  --tamper=space2comment,randomcase,charencode,unmagicquotes \
  -c 25 -rl 100 \
  -format html,json -o ./bypass-campaign
```
*Full mutation matrix with chaining, specific tamper scripts, and multi-format reporting.*

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Required (sends thousands of attack payload variants) |
| **Memory** | ~500MB RAM (mutation matrix is large) |
| **Time** | 5-20 minutes (full mutation), 2-5 minutes (targeted) |

#### How Bypass Hunting Works

| Phase | Actions | Payload Count |
|-------|---------|---------------|
| **Base Payloads** | Load category-specific attack payloads | ~500 |
| **Encoding Matrix** | Apply 15+ encoding schemes (URL, Unicode, Base64, etc.) | ×15 = ~7,500 |
| **Location Variants** | Test in different HTTP locations (path, query, header, body) | ×4 = ~30,000 |
| **Chaining** | Combine multiple techniques (if `-chain` enabled) | ×N = variable |
| **WAF-Specific** | Apply vendor-specific evasions (if `--smart`) | +targeted |

#### Basic Bypass Search

```bash
waf-tester bypass -u https://target.com
```

#### Smart Bypass with Vendor Detection

```bash
waf-tester bypass -u https://target.com --smart --tamper-auto
```

**What `--smart` does for bypass hunting:**
1. Detects WAF vendor
2. Selects tampers with proven bypass history for that vendor
3. Prioritizes techniques known to work against that WAF
4. Adjusts timing to avoid triggering rate limits

#### Category-Specific Bypass

```bash
# SQL injection bypasses only
waf-tester bypass -u https://target.com -category sqli

# XSS bypasses
waf-tester bypass -u https://target.com -category xss

# Multiple categories
waf-tester bypass -u https://target.com -category sqli,xss,rce
```

#### Full Mutation Matrix with Chaining

```bash
waf-tester bypass -u https://target.com \
  --smart \
  -mutation full \
  -chain \
  -max-chain 3 \
  -o bypasses.json
```

| Option | Effect | Trade-off |
|--------|--------|-----------|
| `-mutation full` | All encoding combinations | 10x more payloads, 10x longer |
| `-chain` | Combine multiple techniques | Finds complex bypasses, slower |
| `-max-chain 3` | Max 3 techniques per payload | Higher = more combinations |

#### Sample Output

```
$ waf-tester bypass -u https://secure.example.com --smart --tamper-auto -category sqli

WAFtester v2.6.5 — WAF Bypass Hunter

Target: https://secure.example.com
Category: sqli
Mode: Smart (Cloudflare detected)
Auto-tampers: unicode_normalize, chunk_transfer, multipart_boundary

══════════════════════════════════════════════════════════════════════
 BYPASS HUNTING PROGRESS
══════════════════════════════════════════════════════════════════════

 [████████████████████████████████████████] 100% (12,847/12,847)

 Phase 1: Base payloads           ✓ 423 payloads tested
 Phase 2: Encoding matrix         ✓ 6,345 variants generated
 Phase 3: Location testing        ✓ 4,128 location variants
 Phase 4: WAF-specific tampers    ✓ 1,951 Cloudflare-specific

══════════════════════════════════════════════════════════════════════
 CONFIRMED BYPASSES
══════════════════════════════════════════════════════════════════════

 🔴 BYPASS #1: SQL Injection Authentication Bypass
    Original:    ' OR 1=1--
    Bypass:      %EF%BC%87%20OR%201%EF%BC%9D1--
    Technique:   Unicode fullwidth apostrophe + equals
    Endpoint:    POST /api/login
    Parameter:   username
    Confidence:  HIGH (payload executed, auth bypassed)

 🔴 BYPASS #2: SQL Injection Data Extraction
    Original:    ' UNION SELECT * FROM users--
    Bypass:      '/**/UNION/**/SELECT/**/*/**/FROM/**/users--
    Technique:   Comment injection (space replacement)
    Endpoint:    GET /api/users?id=
    Parameter:   id
    Confidence:  HIGH (returned extra user data)

 🟠 BYPASS #3: SQL Injection (Blind)
    Original:    ' AND SLEEP(5)--
    Bypass:      '%20AND%20(SELECT%20SLEEP(5))--
    Technique:   URL encoding + subquery
    Endpoint:    GET /search?q=
    Parameter:   q
    Confidence:  MEDIUM (5s delay observed)

 [... 7 more bypasses found ...]

══════════════════════════════════════════════════════════════════════
 BYPASS STATISTICS
══════════════════════════════════════════════════════════════════════

 Total Payloads Tested:  12,847
 Blocked by WAF:         12,837 (99.9%)
 Confirmed Bypasses:     10 (0.08%)

 Bypasses by Technique:
 ├─ Unicode normalization:     4 bypasses
 ├─ Comment injection:         3 bypasses
 ├─ Chunk transfer:            2 bypasses
 └─ HTTP parameter pollution:  1 bypass

══════════════════════════════════════════════════════════════════════
 OUTPUT
══════════════════════════════════════════════════════════════════════

 📄 bypasses.json        All confirmed bypasses with evidence
 📄 bypass-report.html   Formatted report for remediation

✅ Bypass hunting complete in 8m34s
```

#### Decision Guide

| Your Goal | Command | Why |
|-----------|---------|-----|
| Quick bypass check | `bypass -u URL -category sqli` | Single category, faster |
| Maximum bypass discovery | `bypass -u URL --smart -mutation full -chain` | All techniques |
| Red team engagement | `bypass -u URL --smart --tamper-profile=aggressive` | Aggressive evasion |
| Stealth bypass testing | `bypass -u URL --smart-mode=stealth -rl 10` | Low and slow |
| Specific endpoint | `bypass -u URL -category sqli -ep "/api/login"` | Focused testing |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| 0 bypasses found | WAF is very strict or no vulns | Expected for well-tuned WAFs |
| All payloads blocked | IP banned | Rotate IP, reduce rate |
| Too many false positives | Backend error = "bypass" | Use `--smart` for better detection |
| Very slow (>1 hour) | Full mutation matrix | Use `-mutation standard`, specific category |

> **See Also:** [Mutation Engine](#mutation-engine) · [Tamper Scripts](#tamper-scripts) · [Smart Mode](#smart-mode) · [Playbook: Bug Bounty](#playbook-7-bug-bounty--quick-waf-bypass-discovery)

---

### Mutation Testing (mutate)

**Purpose:** Test payloads with systematic encoding and location variations to understand WAF parsing.

**TL;DR:** `waf-tester mutate -u https://target.com -encoders url,unicode` — Encoding analysis in 3-10 minutes

The `mutate` command helps understand how a WAF parses and normalizes input. Unlike `bypass`, it focuses on understanding WAF behavior rather than finding exploitable bypasses.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Required (sends attack payload variants) |
| **Memory** | ~300MB RAM |
| **Time** | 3-15 minutes |

#### Basic Mutation Testing

```bash
waf-tester mutate -u https://target.com
```

#### With Specific Encoders

```bash
waf-tester mutate -u https://target.com \
  -encoders url,double_url,unicode,html,base64
```

#### Available Encoders

| Encoder | Description | Example |
|---------|-------------|---------|
| `url` | Standard URL encoding | `'` → `%27` |
| `double_url` | Double URL encoding | `'` → `%2527` |
| `unicode` | Unicode encoding | `'` → `%u0027` |
| `unicode_full` | Fullwidth Unicode | `'` → `%EF%BC%87` |
| `html` | HTML entity encoding | `'` → `&#39;` |
| `html_hex` | HTML hexadecimal | `'` → `&#x27;` |
| `base64` | Base64 encoding | `'` → `Jw==` |
| `hex` | Hexadecimal | `'` → `0x27` |
| `octal` | Octal encoding | `'` → `\047` |
| `utf7` | UTF-7 encoding | `'` → `+ACc-` |

#### Full Mutation Matrix

```bash
waf-tester mutate -u https://target.com \
  -mutation full \
  -chain \
  -max-chain 3
```

#### Sample Output

```
$ waf-tester mutate -u https://target.com -encoders url,unicode,double_url

WAFtester v2.6.5 — Mutation Testing

Target: https://target.com
Encoders: url, unicode, double_url

══════════════════════════════════════════════════════════════════════
 MUTATION ANALYSIS
══════════════════════════════════════════════════════════════════════

 Payload: ' OR 1=1--

 Encoding          │ Variant                          │ WAF Result
 ──────────────────┼──────────────────────────────────┼───────────
 none              │ ' OR 1=1--                       │ BLOCKED
 url               │ %27%20OR%201%3D1--               │ BLOCKED
 double_url        │ %2527%2520OR%25201%253D1--       │ BLOCKED
 unicode           │ %u0027 OR 1=1--                  │ BLOCKED
 unicode_full      │ %EF%BC%87 OR 1=1--               │ ALLOWED ⚠️

 WAF Behavior Analysis:
 ├─ URL decoding:        Yes (handles %27)
 ├─ Double URL decoding: Yes (handles %2527)
 ├─ Unicode normalization: PARTIAL (misses fullwidth)
 └─ Recommendation:      Test fullwidth chars for bypasses

✅ Mutation testing complete
```

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| All mutations blocked | Strong WAF | Expected - use for analysis, not bypass |
| All mutations allowed | No WAF or disabled | Verify using `vendor` command |
| Very slow | Too many encoders | Use specific `-encoders` list |

---

### False Positive Testing (fp)

**Purpose:** Measure false positive rate by sending benign traffic through the WAF.

**TL;DR:** `waf-tester fp -u https://target.com -corpus builtin` — FPR measurement in 2-5 minutes

False positives (legitimate traffic blocked) hurt business more than missed attacks. This command quantifies the problem using curated benign traffic corpora.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Minimal (sends benign traffic only) |
| **Time** | 2-5 minutes |

#### Basic FP Test

```bash
waf-tester fp -u https://target.com
```

#### With Leipzig Corpus

The Leipzig corpus contains millions of natural language sentences in multiple languages.

```bash
waf-tester fp -u https://target.com -corpus leipzig
```

#### Custom Corpus

Use your own benign traffic samples:

```bash
waf-tester fp -u https://target.com -corpus /path/to/benign-requests.txt
```

#### Sample Output

```
$ waf-tester fp -u https://secure.example.com -corpus builtin,leipzig

WAFtester v2.6.5 — False Positive Testing

Target: https://secure.example.com
Corpora: builtin (2,500), leipzig (5,000)

Sending benign traffic...
[████████████████████████████████████████] 100% (7,500/7,500)

══════════════════════════════════════════════════════════════════════
 FALSE POSITIVE RESULTS
══════════════════════════════════════════════════════════════════════

 Corpus            │ Total │ Blocked │ Allowed  │ FP Rate
 ──────────────────┼───────┼─────────┼──────────┼────────
 builtin           │ 2,500 │      12 │    2,488 │ 0.48%
 leipzig-english   │ 2,500 │       4 │    2,496 │ 0.16%
 leipzig-german    │ 2,500 │       2 │    2,498 │ 0.08%
 ──────────────────┴───────┴─────────┴──────────┴────────
 TOTAL             │ 7,500 │      18 │    7,482 │ 0.24%

══════════════════════════════════════════════════════════════════════
 BLOCKED BENIGN REQUESTS (False Positives)
══════════════════════════════════════════════════════════════════════

 1. "The SELECT committee reviewed the union's proposal"
    Blocked: SQL keyword pattern (SELECT, UNION)

 2. "Please <update> your profile information"
    Blocked: HTML tag pattern

 3. "See the script attached for details"
    Blocked: Script keyword pattern

 [... 15 more false positives ...]

══════════════════════════════════════════════════════════════════════
 ASSESSMENT
══════════════════════════════════════════════════════════════════════

 False Positive Rate: 0.24%
 Rating: ★★★★★ Excellent (target: <1%)

 Impact: At 10,000 daily requests, expect ~24 legitimate blocks

 Recommendations:
 • Review blocking rules for "SELECT" and "UNION" without SQL context
 • Consider whitelisting common HTML-like patterns in user content
 • Rule #3 (script keyword) may be too aggressive

✅ FP testing complete in 2m47s
```

#### Available Corpora

| Corpus | Description | Requests |
|--------|-------------|----------|
| `builtin` | Curated benign traffic (forms, searches, user content) | 2,500 |
| `leipzig` | Natural language sentences (English, German, French, Spanish) | 5,000+ |
| Custom | Your own benign request file (one per line) | Variable |

#### Decision Guide

| Scenario | Command | Why |
|----------|---------|-----|
| Quick check | `fp -u URL` | Built-in corpus only |
| Full multilingual | `fp -u URL -corpus builtin,leipzig` | Comprehensive |
| Domain-specific | `fp -u URL -corpus /path/to/mytraffic.txt` | Your real traffic |
| CI/CD gate | `fp -u URL -threshold 1.0` | Fail if FPR > 1% |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| FPR = 0% | Requests not reaching WAF | Verify WAF is inline |
| FPR > 5% | Very aggressive rules | Review blocked requests, tune WAF |
| Inconsistent results | Caching | Bust cache with `?nocache=rand` |

---

### Content Fuzzing (fuzz)

Directory and content fuzzing with FUZZ keyword.

#### Complexity Tiers

> **📋 Copy-Paste Ready:**
> ```bash
> waf-tester fuzz -u https://YOUR_TARGET/FUZZ -w common
> ```

##### 🟢 Beginner — Built-in wordlist, instant results
```bash
waf-tester fuzz -u https://target.com/FUZZ -w common
```
*Uses built-in "common" wordlist. Shows discovered paths with status codes.*

##### 🟡 Intermediate — Custom wordlist with filtering
```bash
waf-tester fuzz -u https://target.com/FUZZ \
  -w wordlist.txt \
  -fc 404,403 \
  -mc 200,301,302 \
  -ac \
  -o fuzz-results.json
```
*Custom wordlist with status filtering, auto-calibration, and JSON output.*

##### 🔴 Advanced — Multi-keyword recursive deep fuzzing
```bash
waf-tester fuzz -u "https://target.com/FUZZ1/FUZZ2" \
  -w dirs.txt:files.txt \
  -fc 404 -fs 0 \
  -ac \
  -recursion -rd 3 \
  -er "api[_-]?key[=:][a-zA-Z0-9]+" \
  -sr -srd ./responses \
  -c 50 -rl 200 \
  -o deep-fuzz.json
```
*Multi-keyword fuzzing with recursion, regex extraction, response storage, and high concurrency.*

#### Directory Fuzzing

```bash
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt
```

#### Parameter Fuzzing

```bash
waf-tester fuzz -u "https://target.com/search?q=FUZZ" -w params.txt
```

#### With Filters

```bash
waf-tester fuzz -u https://target.com/FUZZ \
  -w wordlist.txt \
  -fc 404,403 \
  -fs 0
```

#### Multiple FUZZ Keywords

```bash
waf-tester fuzz -u "https://target.com/FUZZ1/FUZZ2" \
  -w wordlist1.txt:wordlist2.txt
```

#### Built-in Wordlists

```bash
# Use built-in presets instead of custom files
waf-tester fuzz -u https://target.com/FUZZ -w common
waf-tester fuzz -u https://target.com/api/FUZZ -w api
```

| Preset | Description |
|--------|-------------|
| `common` | Common directories and files |
| `api` | API endpoints |
| `backup` | Backup file extensions |
| `config` | Configuration files |
| `git` | Git repository files |

#### Wordlist Options

```bash
# Limit wordlist entries
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wmax 1000

# Skip first N entries
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wskip 500

# Shuffle wordlist
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wshuffle

# Wordlist type
waf-tester fuzz -u https://target.com/FUZZ -wt directories
waf-tester fuzz -u https://target.com/FUZZ -wt files
waf-tester fuzz -u https://target.com/FUZZ -wt parameters
waf-tester fuzz -u https://target.com/FUZZ -wt subdomains
```

#### Wordlist Transformations

```bash
# Convert to lowercase
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wlower

# Convert to uppercase
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wupper

# Add prefix/suffix
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -wprefix "api_" -wsuffix ".json"
```

#### Fuzzing Modes

```bash
# Sniper mode (default) - one position at a time
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -mode sniper

# Pitchfork mode - parallel positions, same index
waf-tester fuzz -u "https://target.com/FUZZ1/FUZZ2" \
  -w wordlist1.txt:wordlist2.txt -mode pitchfork

# Clusterbomb mode - all combinations
waf-tester fuzz -u "https://target.com/FUZZ1/FUZZ2" \
  -w wordlist1.txt:wordlist2.txt -mode clusterbomb
```

| Mode | Description |
|------|-------------|
| `sniper` | Replace one position at a time (default) |
| `pitchfork` | Replace all positions with same-index words |
| `clusterbomb` | All combinations of all wordlists |

#### Fuzz Position

```bash
# Fuzz URL parameter
waf-tester fuzz -u https://target.com/search?q=FUZZ -fp url

# Fuzz header value
waf-tester fuzz -u https://target.com -fp header -H "X-Custom: FUZZ"

# Fuzz POST body
waf-tester fuzz -u https://target.com -X POST -d "param=FUZZ" -fp body

# Fuzz cookie value
waf-tester fuzz -u https://target.com -fp cookie -b "session=FUZZ"
```

#### Recursive Fuzzing

```bash
# Enable recursion for discovered directories
waf-tester fuzz -u https://target.com/FUZZ -w dirs.txt -recursion

# Custom recursion depth
waf-tester fuzz -u https://target.com/FUZZ -w dirs.txt -recursion -rd 3
```

#### Response Extraction

```bash
# Extract content matching regex
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt \
  -er "api[_-]?key[=:][a-zA-Z0-9]+"

# Extract preset patterns
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -epr emails
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -epr urls
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -epr ips
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -epr secrets
```

#### Store Responses

```bash
# Store all responses
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -sr

# Custom response directory
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -sr -srd ./fuzz-responses

# Store only matching responses
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -sr -som
```

#### Auto-Calibration

```bash
# Enable auto-calibration
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -ac

# Custom calibration words
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -ac \
  -cw "random12345,notfound99"
```

#### Debug and Verbose

```bash
# Verbose output
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -v

# Debug mode (show requests/responses)
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -debug

# Debug request only
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -dreq

# Debug response only
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -dresp
```

---

### Protocol Probing (probe)

Protocol probing and WAF/CDN detection. The probe command is httpx-compatible with 100+ options for advanced recon.

#### Basic Probe

```bash
waf-tester probe -u https://target.com
```

#### Multiple Targets

```bash
waf-tester probe -l targets.txt -c 50 -o probes.json
```

#### With Streaming Output

```bash
waf-tester probe -l targets.txt --stream
```

#### Probe Information Gathered

- TLS/SSL configuration (JARM fingerprint)
- HTTP/2 and pipelining support
- WAF/CDN detection
- Server headers and technology detection
- Response characteristics (status, length, word/line count)
- Favicon hash (mmh3)
- DNS info (IP, CNAME, ASN)

#### Screenshots

Capture screenshots of web pages for visual recon:

```bash
# Enable screenshots
waf-tester probe -l targets.txt -ss

# With custom timeout
waf-tester probe -u https://target.com --screenshot -st 15

# Use system Chrome instead of embedded
waf-tester probe -l targets.txt -ss -system-chrome

# Exclude screenshot bytes from JSON (keep only file path)
waf-tester probe -l targets.txt -ss -esb -json

# Full page vs viewport screenshot
waf-tester probe -u https://target.com -ss -no-screenshot-full-page

# Headless browser options
waf-tester probe -l targets.txt -ss -ho "--proxy-server=http://localhost:8080"
```

| Flag | Description |
|------|-------------|
| `-ss`, `--screenshot` | Enable saving screenshot |
| `-st`, `--screenshot-timeout` | Screenshot timeout (seconds) |
| `-system-chrome` | Use local installed Chrome |
| `-esb`, `--exclude-screenshot-bytes` | Exclude screenshot bytes from JSON |
| `-no-screenshot-full-page` | Disable full page screenshot |
| `-ho`, `--headless-options` | Additional headless Chrome options |
| `-sid`, `--screenshot-idle` | Idle time before screenshot (seconds) |
| `-jsc`, `--javascript-code` | Execute JS after navigation |

#### Hash Calculation

Calculate response body hashes for fingerprinting:

```bash
# MD5 hash
waf-tester probe -u https://target.com -hash md5

# SHA256 hash
waf-tester probe -l targets.txt -hash sha256

# MurmurHash3 (Shodan/Censys compatible)
waf-tester probe -l targets.txt -hash mmh3

# Show header hash (for fingerprinting)
waf-tester probe -u https://target.com --header-hash

# Favicon hash for WAF/CDN detection
waf-tester probe -l targets.txt --favicon-hash
```

| Hash Type | Description |
|-----------|-------------|
| `md5` | MD5 body hash |
| `sha256` | SHA256 body hash |
| `mmh3` | MurmurHash3 (Shodan-compatible) |
| `simhash` | Similarity hash for deduplication |

#### Content Extraction

Extract content from responses using regex or presets:

```bash
# Extract with custom regex
waf-tester probe -u https://target.com -er "api[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]+)"

# Extract URLs from response
waf-tester probe -l targets.txt -ep url

# Extract IPv4 addresses
waf-tester probe -l targets.txt -ep ipv4

# Extract email addresses
waf-tester probe -l targets.txt --extract-preset mail

# Extract FQDNs (domains/subdomains)
waf-tester probe -l targets.txt -efqdn
```

| Preset | Description |
|--------|-------------|
| `url` | Extract URLs from response |
| `ipv4` | Extract IPv4 addresses |
| `mail` | Extract email addresses |

#### Simhash Deduplication

Filter near-duplicate responses based on content similarity:

```bash
# Enable simhash with threshold (0-64, lower = more similar)
waf-tester probe -l targets.txt -simhash 10

# Combine with filter duplicates
waf-tester probe -l targets.txt -simhash 8 -fd
```

#### Matchers and Filters

Filter results based on response characteristics:

```bash
# Match specific status codes
waf-tester probe -l targets.txt -mc 200,302

# Filter out 404 and 500 errors
waf-tester probe -l targets.txt -fc 404,500

# Match responses containing string
waf-tester probe -l targets.txt -ms "admin"

# Filter responses containing string
waf-tester probe -l targets.txt -fs "Not Found"

# Match by content length
waf-tester probe -l targets.txt -ml 1000-5000

# Match by line count
waf-tester probe -l targets.txt -mlc 10-100

# Match by word count
waf-tester probe -l targets.txt -mwc 50-500

# Match with regex
waf-tester probe -l targets.txt -mr "password|secret|token"

# Match by favicon hash (find similar tech)
waf-tester probe -l targets.txt -mfc "-123456789"

# Match specific CDN
waf-tester probe -l targets.txt -mcdn cloudflare

# Match response time
waf-tester probe -l targets.txt -mrt "<1s"
```

#### DSL Condition Matching

Advanced matching with DSL expressions (like Nuclei):

```bash
# Match with complex DSL condition
waf-tester probe -l targets.txt -mdc "status_code == 200 && contains(body, 'admin')"

# Filter with DSL condition
waf-tester probe -l targets.txt -fdc "content_length < 100"

# List available DSL variables
waf-tester probe -ldv
```

#### Output Options

Control output format and fields:

```bash
# Show content length, type, word/line count
waf-tester probe -l targets.txt -cl -ct -wc -lc

# Show server header
waf-tester probe -l targets.txt -server

# Show page title
waf-tester probe -l targets.txt -title

# Show resolved IP
waf-tester probe -l targets.txt -ip

# Show ASN info
waf-tester probe -l targets.txt -asn

# Show CDN/WAF detection
waf-tester probe -l targets.txt -cdn

# Show technology detection
waf-tester probe -l targets.txt -td

# Show HTTP/2 support
waf-tester probe -l targets.txt -http2

# Show WebSocket support
waf-tester probe -l targets.txt -ws

# Body preview (first N characters)
waf-tester probe -l targets.txt -bp 100

# CSV output
waf-tester probe -l targets.txt -csv -o results.csv

# JSON output with full response
waf-tester probe -l targets.txt -json -irr

# Include response headers in JSON
waf-tester probe -l targets.txt -json -irh

# Include base64 encoded response
waf-tester probe -l targets.txt -json -irrb

# HTML summary report
waf-tester probe -l targets.txt -html report.html
```

#### Store Responses

Save full HTTP responses to disk:

```bash
# Store responses
waf-tester probe -l targets.txt -sr

# Custom response directory
waf-tester probe -l targets.txt --store-response -srd ./responses

# Include redirect chain
waf-tester probe -l targets.txt -sr --store-chain
```

#### Rate Limiting and Delays

Control request rate:

```bash
# Requests per second
waf-tester probe -l targets.txt -rl 10

# Rate limit per host
waf-tester probe -l targets.txt -rl 5 -rlph

# Rate limit per minute
waf-tester probe -l targets.txt -rlm 100

# Delay between requests
waf-tester probe -l targets.txt -delay 100ms
```

#### Proxy Support

Route through proxy:

```bash
# HTTP proxy
waf-tester probe -l targets.txt -proxy http://localhost:8080

# HTTPS proxy
waf-tester probe -l targets.txt -proxy https://localhost:8080

# SOCKS4 proxy
waf-tester probe -l targets.txt -proxy socks4://localhost:1080

# SOCKS5 proxy
waf-tester probe -l targets.txt -proxy socks5://localhost:1080

# SOCKS5h proxy (DNS over proxy - enhanced anonymity)
waf-tester probe -l targets.txt -proxy socks5h://localhost:1080

# Burp Suite shortcut (127.0.0.1:8080)
waf-tester probe -l targets.txt --burp

# OWASP ZAP shortcut (127.0.0.1:8081)
waf-tester probe -l targets.txt --zap

# Replay proxy (duplicate traffic to security tool)
waf-tester scan -u https://target.com --replay-proxy http://localhost:8080

# Authenticated proxy
waf-tester probe -l targets.txt -proxy http://user:pass@localhost:8080
```

#### TLS/SSL Options

Advanced TLS configuration:

```bash
# Skip certificate verification
waf-tester probe -l targets.txt -k

# Custom SNI name
waf-tester probe -l targets.txt -sni custom.example.com

# TLS impersonation (client hello randomization)
waf-tester probe -l targets.txt -tlsi

# Use ztls library for TLS 1.3
waf-tester probe -l targets.txt -ztls

# TLS grab (extract TLS/SSL data)
waf-tester probe -l targets.txt -tls-grab
```

#### Raw Request Support

Import requests from files or Burp:

```bash
# Raw HTTP request file
waf-tester probe -rr request.txt

# Burp XML import
waf-tester probe -im burp -l burp-export.xml
```

---

### HTTP Smuggling (smuggle)

**Purpose:** Detect HTTP request smuggling vulnerabilities used to bypass WAF rules completely.

**TL;DR:** `waf-tester smuggle -u https://target.com` — Find critical smuggling vulns in 1-5 minutes

HTTP smuggling exploits differences between how front-end (CDN/WAF) and back-end servers parse HTTP requests. A successful smuggle lets attackers bypass ALL WAF rules by hiding payload in the "smuggled" portion.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target with CDN/proxy/WAF in front |
| **Authorization** | Required (full mode is invasive) |
| **Time** | 1-5 minutes |

#### How Smuggling Works

```
Normal Request Flow:
  Client → WAF → Backend
  [WAF sees same request as backend - protects properly]

Smuggling Attack:
  Client → WAF → Backend
  [WAF sees 1 request, backend sees 2 - second bypasses WAF]
```

#### Basic Smuggling Test

```bash
waf-tester smuggle -u https://target.com
```

#### Safe Mode vs Full Mode

```bash
# Safe mode (default) - timing-based detection only
waf-tester smuggle -u https://target.com -safe

# Full mode - payload injection (more accurate but invasive)
waf-tester smuggle -u https://target.com -safe=false
```

| Mode | Risk Level | Detection Method | Use When |
|------|------------|------------------|----------|
| `safe` | Low | Timing/delay analysis | Initial reconnaissance |
| `full` | High | Actual smuggled payloads | Confirmed testing with auth |

#### Sample Output

```
$ waf-tester smuggle -u https://app.example.com

WAFtester v2.6.5 — HTTP Smuggling Detection

Target: https://app.example.com
Mode: Safe (timing-based)

Probing for HTTP smuggling vulnerabilities...

══════════════════════════════════════════════════════════════════════
 SMUGGLING TEST RESULTS
══════════════════════════════════════════════════════════════════════

 Technique: CL.TE (Content-Length.Transfer-Encoding)
 ├─ Baseline response time:  45ms
 ├─ Smuggled response time:  10,043ms (10s delay detected!)
 └─ Status: 🔴 LIKELY VULNERABLE

 Technique: TE.CL (Transfer-Encoding.Content-Length)
 ├─ Baseline response time:  42ms
 ├─ Smuggled response time:  51ms
 └─ Status: ✅ Not vulnerable

 Technique: TE.TE (Transfer-Encoding obfuscation)
 ├─ Baseline response time:  48ms
 ├─ Variants tested:         12
 └─ Status: ✅ Not vulnerable

══════════════════════════════════════════════════════════════════════
 VULNERABILITY DETECTED
══════════════════════════════════════════════════════════════════════

 🔴 CL.TE Smuggling Confirmed

 Severity:    CRITICAL
 Impact:      Complete WAF bypass, request hijacking, cache poisoning

 What this means:
 The front-end proxy (Cloudflare) uses Content-Length.
 The back-end server uses Transfer-Encoding.
 Attackers can smuggle requests that bypass ALL WAF rules.

 Proof of concept (run with -safe=false for full test):
 waf-tester smuggle -u https://app.example.com -safe=false -v

══════════════════════════════════════════════════════════════════════
 RECOMMENDATIONS
══════════════════════════════════════════════════════════════════════

 Immediate:
 • Configure both servers to reject ambiguous requests
 • Disable HTTP/1.1 keep-alive if not needed

 Long-term:
 • Upgrade to HTTP/2 end-to-end (not vulnerable to classic smuggling)
 • Configure WAF to normalize and re-serialize requests

✅ Smuggling test complete in 1m23s
```

#### Multiple Targets

```bash
waf-tester smuggle -l targets.txt -o smuggle-results.json
```

#### Detection Techniques

| Technique | Description | Common Scenario |
|-----------|-------------|-----------------|
| `clte` | Content-Length.Transfer-Encoding | CDN uses CL, backend uses TE |
| `tecl` | Transfer-Encoding.Content-Length | CDN uses TE, backend uses CL |
| `tete` | Transfer-Encoding.Transfer-Encoding | Both use TE but parse differently |

#### Decision Guide

| Scenario | Command | Why |
|----------|---------|-----|
| Initial recon | `smuggle -u URL` | Safe mode first |
| Confirm vulnerability | `smuggle -u URL -safe=false -v` | Full payload testing |
| Bulk scanning | `smuggle -l targets.txt` | Multiple targets |
| Stealth testing | `smuggle -u URL -delay 5000` | Slow and careful |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Not vulnerable" but you suspect | HTTP/2 masking HTTP/1.1 | Force HTTP/1.1 with origin |
| Timeout on every test | Very slow backend | Increase `-timeout 30` |
| Inconsistent results | Load balancer rotating | Increase `-retries 5` |
| False positives | Slow backend responds after expected | Use `-delay 2000` between tests |

---

### Race Condition Testing (race)

**Purpose:** Exploit race conditions for double-spending, limit bypasses, and TOCTOU vulnerabilities.

**TL;DR:** `waf-tester race -u https://target.com/action -c 50` — Race condition check in seconds

Race conditions occur when an application doesn't properly handle concurrent requests. Results include double voucher redemption, overdrafts, limit bypasses, and authentication issues.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Required (actively exploits) |
| **Auth Token** | Usually needed for testing protected endpoints |
| **Time** | 10-60 seconds per test |

#### How Race Conditions Work

```
Normal Flow (sequential):                Race Attack (concurrent):
────────────────────────                  ─────────────────────────
Request 1 → Check balance → Deduct       50 Requests → All see $100 → All deduct
Result: $100 - $50 = $50                 Result: $100 - (50×$50) = -$2,400 🔴
```

#### Basic Race Test

```bash
waf-tester race -u https://target.com/checkout -c 50
```

#### Attack Types

```bash
# Double submit attack
waf-tester race -u https://target.com/submit -attack double_submit

# Token reuse attack  
waf-tester race -u https://target.com/action -attack token_reuse

# Rate limit bypass
waf-tester race -u https://target.com/api -attack limit_bypass

# Time-of-check to time-of-use
waf-tester race -u https://target.com/process -attack toctou
```

| Attack Type | Description | Example Scenario |
|-------------|-------------|------------------|
| `double_submit` | Submit same request simultaneously | Redeem voucher twice |
| `token_reuse` | Reuse single-use tokens concurrently | Transfer money with same auth |
| `limit_bypass` | Bypass rate limits with burst | Send 1000 emails instantly |
| `toctou` | Check happens before use | Download paid file free |

#### Sample Output

```
$ waf-tester race -u https://shop.example.com/apply-coupon -c 50 \
    -method POST -body '{"code":"SAVE50"}' -H "Authorization: Bearer xxx"

WAFtester v2.6.5 — Race Condition Testing

Target: https://shop.example.com/apply-coupon
Attack: double_submit
Concurrency: 50

Sending 50 concurrent identical requests...

══════════════════════════════════════════════════════════════════════
 RACE CONDITION RESULTS
══════════════════════════════════════════════════════════════════════

 Requests Sent:    50
 Response Time:    127ms - 4,231ms (spread: 4,104ms)

 Response Analysis:
 ├─ 200 OK:         47 responses
 ├─ 409 Conflict:    3 responses (coupon already used)
 └─ Distinct bodies: 2

 🔴 RACE CONDITION DETECTED

 Evidence:
 - 47 of 50 requests succeeded
 - Expected: 1 success, 49 conflicts
 - Coupon applied 47 times instead of 1

══════════════════════════════════════════════════════════════════════
 EXPLOITATION DETAILS
══════════════════════════════════════════════════════════════════════

 Successful responses (sample):
 
 Response #1:  {"status":"success","discount":"$50.00"}
 Response #14: {"status":"success","discount":"$50.00"}
 Response #29: {"status":"success","discount":"$50.00"}

 Total discount applied: $2,350 (should be $50)

══════════════════════════════════════════════════════════════════════
 RECOMMENDATIONS
══════════════════════════════════════════════════════════════════════

 • Implement database-level locking (SELECT FOR UPDATE)
 • Use atomic operations for critical state changes
 • Add idempotency keys for payment/discount endpoints
 • Consider pessimistic vs optimistic locking strategy

✅ Race test complete in 4.2s
```

#### Race Options

```bash
# Custom HTTP method
waf-tester race -u https://target.com/api -method POST

# Request body
waf-tester race -u https://target.com/api -method POST -body '{"amount":100}'

# Custom headers
waf-tester race -u https://target.com/api -H "Authorization: Bearer TOKEN"

# Number of concurrent requests
waf-tester race -u https://target.com/action -c 100

# Number of iterations
waf-tester race -u https://target.com/action -n 5

# Custom timeout
waf-tester race -u https://target.com/action -timeout 60
```

#### Decision Guide

| Target Endpoint | Command | Expected Result |
|-----------------|---------|-----------------|
| Coupon/voucher | `race -u URL/apply -c 50 -method POST` | Should see 1 success, 49 failures |
| Money transfer | `race -u URL/transfer -c 20 -body '...'` | Balance should not go negative |
| Rate-limited API | `race -u URL -c 200` | Should get 429 after limit |
| File download | `race -u URL/download -c 30` | Purchased files only |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| All 50 get "success" | No locking at all | Definite vulnerability |
| All 50 get "conflict" | Good locking exists | Not vulnerable (expected) |
| Mixed results (unstable) | Partial locking | Try higher concurrency |
| Connection errors | Server rate limiting | Lower concurrency with `-c 20` |

---

### Web Crawling (crawl)

**Purpose:** Discover all endpoints, forms, and resources across a web application.

**TL;DR:** `waf-tester crawl -u https://target.com -depth 5` — Full site crawl in 5-30 minutes

Crawling discovers the attack surface before testing. It finds hidden pages, forms, API endpoints, and JavaScript files that contain additional URLs.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Low (follows links, no attacks) |
| **Time** | 5-30 minutes (depends on site size) |

#### Basic Crawl

```bash
waf-tester crawl -u https://target.com
```

#### With Depth Control

```bash
waf-tester crawl -u https://target.com -depth 5 -max-pages 500
```

#### Sample Output

```
$ waf-tester crawl -u https://shop.example.com -depth 4 -max-pages 200

WAFtester v2.6.5 — Web Crawler

Target: https://shop.example.com
Depth: 4 | Max Pages: 200

Crawling...
[████████████████████████████████████████] 200/200 pages

══════════════════════════════════════════════════════════════════════
 CRAWL RESULTS
══════════════════════════════════════════════════════════════════════

 Pages Discovered:    200 (max reached)
 Links Found:         847
 Unique Endpoints:    156

 By Content Type:
 ├─ HTML pages:       134
 ├─ JavaScript:        42
 ├─ JSON responses:    18
 └─ Other:              6

══════════════════════════════════════════════════════════════════════
 FORMS DISCOVERED (12)
══════════════════════════════════════════════════════════════════════

 1. /login
    Method: POST | Fields: username, password, csrf_token

 2. /search
    Method: GET | Fields: q, category, sort

 3. /checkout
    Method: POST | Fields: cc_number, cvv, expiry, address
    ⚠️  Contains payment fields

 4. /contact
    Method: POST | Fields: name, email, message
    
 [... 8 more forms ...]

══════════════════════════════════════════════════════════════════════
 API ENDPOINTS (24)
══════════════════════════════════════════════════════════════════════

 /api/v1/products     GET
 /api/v1/cart         GET, POST, DELETE
 /api/v1/user         GET, PATCH
 /api/v1/orders       GET, POST
 /api/v1/payment      POST

 [... 19 more endpoints ...]

══════════════════════════════════════════════════════════════════════
 INTERESTING FINDINGS
══════════════════════════════════════════════════════════════════════

 ⚠️  /admin (403 Forbidden - exists but protected)
 ⚠️  /api/v1/debug (returned stack trace)
 ⚠️  /.git/config (200 OK - git exposed!)
 ⚠️  /backup.sql.bak (200 OK - database backup!)

══════════════════════════════════════════════════════════════════════
 OUTPUT
══════════════════════════════════════════════════════════════════════

 📄 crawl-results.json   Full crawl data
 📄 endpoints.txt        All endpoints (for fuzzing)
 📄 forms.txt            All forms discovered

✅ Crawl complete in 3m47s | 200 pages | 12 forms | 24 API endpoints
```

#### Scope Control

```bash
# Include subdomains
waf-tester crawl -u https://target.com -subdomains

# Include URL pattern (regex)
waf-tester crawl -u https://target.com -include "api|admin"

# Exclude URL pattern
waf-tester crawl -u https://target.com -exclude "logout|signout"
```

| Scope | Description |
|-------|-------------|
| `strict` | Same host only |
| `domain` | Same domain including subdomains |
| `loose` | Follow all links |

#### Content Extraction

```bash
# Extract forms (default: enabled)
waf-tester crawl -u https://target.com -forms

# Extract scripts (default: enabled)
waf-tester crawl -u https://target.com -scripts

# Extract email addresses
waf-tester crawl -u https://target.com -emails

# Extract HTML comments (for hidden endpoints/secrets)
waf-tester crawl -u https://target.com -comments

# Extract API endpoints
waf-tester crawl -u https://target.com -endpoints
```

#### Decision Guide

| Goal | Command | Output |
|------|---------|--------|
| Quick surface mapping | `crawl -u URL -depth 2` | Top-level pages |
| Full site discovery | `crawl -u URL -depth 5 -max-pages 1000` | Complete map |
| API discovery focus | `crawl -u URL -endpoints -scripts` | API endpoints from JS |
| Pre-scan recon | `crawl -u URL -o endpoints.txt` | Feed to scanner |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Crawl stuck at login | Auth required | Use `-cookie "session=X"` |
| Missing dynamic content | JavaScript rendering | Use `headless` command instead |
| Blocked after few pages | Rate limiting | Lower `-concurrency 5`, add `-delay 500` |
| Infinite loop | Query param variations | Use `-exclude "page=|offset="` |

---

### JavaScript Analysis (analyze)

**Purpose:** Extract endpoints, secrets, and DOM XSS sinks from JavaScript files.

**TL;DR:** `waf-tester analyze -u https://target.com` — Find hidden APIs and secrets in JS files

Modern SPAs hide their entire API structure in JavaScript. This command extracts URLs, methods, API keys, and identifies potential DOM XSS sinks.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | Access to target's JavaScript files |
| **Authorization** | None (reads public JS) |
| **Time** | 30 seconds - 5 minutes |

#### Basic Analysis

```bash
waf-tester analyze -u https://target.com
```

#### Analyze Local File

```bash
waf-tester analyze -file ./app.js
```

#### Sample Output

```
$ waf-tester analyze -u https://app.example.com

WAFtester v2.6.5 — JavaScript Analysis

Target: https://app.example.com
JavaScript files: 12

Analyzing JavaScript for security-relevant content...

══════════════════════════════════════════════════════════════════════
 API ENDPOINTS DISCOVERED (47)
══════════════════════════════════════════════════════════════════════

 Source: main.bundle.js

 GET  /api/v1/users
 GET  /api/v1/users/:id
 POST /api/v1/users
 PUT  /api/v1/users/:id
 DELETE /api/v1/users/:id

 GET  /api/v1/admin/users          ⚠️ Admin endpoint!
 POST /api/v1/admin/settings       ⚠️ Admin endpoint!

 Source: vendor.js

 GET  /api/internal/debug          ⚠️ Debug endpoint!
 POST /api/internal/eval           ⚠️ Eval endpoint!

 [... 39 more endpoints ...]

══════════════════════════════════════════════════════════════════════
 🔴 SECRETS DETECTED (3)
══════════════════════════════════════════════════════════════════════

 1. AWS Access Key
    File:     config.js (line 47)
    Pattern:  AKIAIOSFODNN7EXAMPLE
    Context:  aws_access_key_id = "AKIA..."
    Risk:     CRITICAL - Full AWS access

 2. Google Maps API Key
    File:     maps.js (line 12)
    Pattern:  AIzaSyB...
    Context:  key: "AIzaSyB..."
    Risk:     LOW - Public API, limited scope

 3. Stripe Test Key
    File:     checkout.js (line 203)
    Pattern:  sk_test_...
    Context:  Stripe("sk_test_...")
    Risk:     MEDIUM - Test key, verify not production

══════════════════════════════════════════════════════════════════════
 DOM XSS SINKS (8)
══════════════════════════════════════════════════════════════════════

 1. innerHTML assignment
    File:     app.js (line 892)
    Code:     element.innerHTML = userInput;
    Risk:     HIGH - Direct XSS if userInput not sanitized

 2. document.write
    File:     legacy.js (line 45)
    Code:     document.write("<div>" + data + "</div>");
    Risk:     HIGH - Classic DOM XSS

 3. eval
    File:     utils.js (line 234)
    Code:     eval(jsonData.callback);
    Risk:     CRITICAL - Code execution

 [... 5 more sinks ...]

══════════════════════════════════════════════════════════════════════
 RECOMMENDATIONS
══════════════════════════════════════════════════════════════════════

 Immediate:
 • Rotate AWS key AKIAIOSFODNN7EXAMPLE immediately
 • Review admin endpoints for authorization
 • Fix DOM XSS sinks (use textContent instead of innerHTML)

 Test these endpoints:
 waf-tester scan -u https://app.example.com -endpoints-file api-endpoints.txt

✅ Analysis complete in 47s | 47 endpoints | 3 secrets | 8 sinks
```

#### What It Finds

| Category | Examples | Risk |
|----------|----------|------|
| **API Endpoints** | fetch(), axios(), XMLHttpRequest URLs | Attack surface expansion |
| **HTTP Methods** | GET, POST, PUT, DELETE from code | API testing targets |
| **Secrets** | AWS, Google, Stripe, GitHub, Slack keys | Credential exposure |
| **DOM XSS Sinks** | innerHTML, document.write, eval | XSS vulnerabilities |

#### Extraction Options

```bash
# Extract URLs (default: enabled)
waf-tester analyze -u https://target.com -urls

# Extract API endpoints (default: enabled)
waf-tester analyze -u https://target.com -endpoints

# Extract secrets/credentials (default: enabled)
waf-tester analyze -u https://target.com -secrets

# Extract DOM XSS sinks (default: enabled)
waf-tester analyze -u https://target.com -sinks
```

#### Decision Guide

| Goal | Command | What You Get |
|------|---------|--------------|
| API discovery | `analyze -u URL -endpoints` | All API endpoints from JS |
| Secret hunting | `analyze -u URL -secrets` | API keys, tokens |
| XSS research | `analyze -u URL -sinks` | DOM XSS candidates |
| Full analysis | `analyze -u URL` | Everything |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| No endpoints found | Minified/obfuscated JS | Still works, may miss some |
| False positive secrets | Placeholder values | Verify before reporting |
| Missing dynamic JS | Loaded after interaction | Use `headless` for SPA |

---

### Headless Browser Testing (headless)

**Purpose:** Security testing with real browser rendering for JavaScript-heavy applications.

**TL;DR:** `waf-tester headless -u https://target.com` — Browser-based testing with screenshots

Single Page Applications (SPAs) require JavaScript execution to discover content. This command uses real Chrome/Chromium to render pages and extract security-relevant data.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Chrome/Chromium** | Installed locally (or uses embedded version) |
| **Memory** | ~500MB RAM per browser instance |
| **Time** | 30 seconds - 10 minutes |

#### Basic Headless Testing

```bash
waf-tester headless -u https://target.com
```

#### Multiple Targets with Streaming

```bash
waf-tester headless -l targets.txt --stream
```

#### Sample Output

```
$ waf-tester headless -u https://spa.example.com -screenshot -v

WAFtester v2.6.5 — Headless Browser Testing

Target: https://spa.example.com
Browser: Chromium (embedded)

Launching headless browser...

══════════════════════════════════════════════════════════════════════
 PAGE ANALYSIS
══════════════════════════════════════════════════════════════════════

 URL:           https://spa.example.com
 Title:         Example SPA Dashboard
 Final URL:     https://spa.example.com/dashboard (redirected)
 Load Time:     2,341ms

 Content:
 ├─ DOM Elements:     1,247
 ├─ JavaScript Files: 8
 ├─ CSS Files:        4
 └─ Images:           23

══════════════════════════════════════════════════════════════════════
 EXTRACTED URLs (34)
══════════════════════════════════════════════════════════════════════

 Internal:
 /api/v2/users
 /api/v2/settings
 /api/v2/dashboard/metrics
 /admin/users              ⚠️ Admin path
 /debug/logs               ⚠️ Debug path

 External:
 https://cdn.example.com/assets/*
 https://analytics.google.com/...

══════════════════════════════════════════════════════════════════════
 SCREENSHOT
══════════════════════════════════════════════════════════════════════

 📸 Saved: screenshots/spa.example.com.png
 Size: 1920x3400 (full page)

══════════════════════════════════════════════════════════════════════
 CONSOLE MESSAGES
══════════════════════════════════════════════════════════════════════

 ⚠️  WARNING: API key exposed in localStorage
 ⚠️  WARNING: Mixed content (HTTP resource on HTTPS page)
 🔴 ERROR: Uncaught TypeError: Cannot read property of null

✅ Headless test complete in 4.7s
```

#### Screenshots

```bash
# Take screenshots of all pages
waf-tester headless -u https://target.com -screenshot

# Custom screenshot directory
waf-tester headless -l targets.txt -screenshot -screenshot-dir ./screens
```

#### JavaScript Execution

```bash
# Execute custom JavaScript after page load
waf-tester headless -u https://target.com \
  -js "document.querySelectorAll('a').forEach(a => console.log(a.href))"
```

#### Browser Options

```bash
# Custom Chrome path
waf-tester headless -u https://target.com -chrome /path/to/chrome

# Show browser (non-headless for debugging)
waf-tester headless -u https://target.com -headless=false

# Custom timeout and wait
waf-tester headless -u https://target.com -timeout 60 -wait 5
```

#### Decision Guide

| Scenario | Command | Why |
|----------|---------|-----|
| SPA endpoint discovery | `headless -u URL -extract-urls` | JS renders all routes |
| Visual audit | `headless -l targets.txt -screenshot` | See what users see |
| JavaScript debugging | `headless -u URL -headless=false` | Watch in real browser |
| Pre-scan recon for SPA | `headless -u URL -o urls.txt` | Feed discovered URLs to scanner |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Chrome not found" | Chrome not installed | Install Chrome or use `-chrome /path` |
| Page doesn't load | JavaScript error | Check console messages, try `-wait 10` |
| Slow performance | Many browser instances | Lower concurrency in target list |
| Missing content | Content loaded on scroll | Use `-js "window.scrollTo(0, document.body.scrollHeight)"` |
| `-wait` | Wait time after page load (seconds) |
| `-extract-urls` | Extract URLs from page (default: true) |

---

## Workflow Commands

Workflow commands orchestrate multi-step security assessments with planning, execution, and reporting phases.

### Discovery and Planning (discover / learn)

**Purpose:** Map attack surface and create data-driven test plans.

**TL;DR:** `waf-tester discover -u URL && waf-tester learn -discovery discovery.json` — Discovery + plan in 2-5 minutes

The discovery→learn→run workflow enables systematic testing based on actual application structure rather than generic payloads.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to target |
| **Authorization** | Minimal (passive discovery) |
| **Time** | 2-5 minutes total |

#### Endpoint Discovery

```bash
waf-tester discover -u https://example.com
waf-tester discover -u https://example.com -output custom-discovery.json
```

#### Discovery Sources

| Source | Description | What It Finds |
|--------|-------------|---------------|
| `robots.txt` | Crawler directives | Hidden paths, disallowed areas |
| `sitemap.xml` | 9 standard locations | All indexed URLs |
| JavaScript | Inline and external | API endpoints, internal URLs |
| Wayback Machine | Archive.org | Historical endpoints, old versions |
| HTML forms | All pages | Input fields, actions |
| Service presets | Known patterns | Admin panels, API docs |

#### Sample Discovery Output

```
$ waf-tester discover -u https://shop.example.com

WAFtester v2.6.5 — Endpoint Discovery

Target: https://shop.example.com

══════════════════════════════════════════════════════════════════════
 DISCOVERY RESULTS
══════════════════════════════════════════════════════════════════════

 Source              │ Endpoints │ Time
 ────────────────────┼───────────┼──────
 robots.txt          │        12 │ 0.3s
 sitemap.xml         │        87 │ 1.2s
 JavaScript (8 files)│        34 │ 2.1s
 HTML forms          │         9 │ 0.8s
 Service presets     │         6 │ 0.1s
 ────────────────────┴───────────┴──────
 TOTAL               │       148 │ 4.5s

 Notable findings:
 ⚠️  /admin (from robots.txt disallow)
 ⚠️  /api/internal (from JavaScript)
 ⚠️  /debug (from service presets)

 📄 Output: discovery.json

✅ Discovery complete
```

#### Generate Test Plan

```bash
waf-tester learn -discovery discovery.json
waf-tester learn -discovery discovery.json -output custom-plan.json
```

The `learn` command analyzes discovery data and creates a prioritized test plan based on:
- Endpoint type (API, form, page)
- Input types detected (query, body, header)
- Risk indicators (admin, debug, internal)

---

### Test Execution (run)

**Purpose:** Execute security tests from a plan or standalone with granular control.

**TL;DR:** `waf-tester run -plan testplan.json` — Execute test plan with progress tracking

The `run` command executes tests with control over concurrency, rate limiting, filtering, and output format.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Network** | HTTPS access to all targets in plan |
| **Authorization** | Required (sends attack payloads) |
| **Test Plan** | Optional (generated by `learn` or manual) |
| **Time** | 5-60 minutes depending on plan size |

#### With Test Plan

```bash
waf-tester run -plan testplan.json
waf-tester run -plan testplan.json -format html -o report.html
```

#### Standalone Execution

```bash
waf-tester run -u https://example.com -c 50 -rl 200
```

#### Sample Plan Execution

```
$ waf-tester run -plan testplan.json

WAFtester v2.6.5 — Test Execution

Plan: testplan.json
Endpoints: 148
Tests: 24,560

══════════════════════════════════════════════════════════════════════
 EXECUTION PROGRESS
══════════════════════════════════════════════════════════════════════

 [████████████████████████████████████████] 100% (24,560/24,560)

 Phase   │ Status     │ Findings
 ────────┼────────────┼──────────
 sqli    │ ✓ Complete │ 3 potential
 xss     │ ✓ Complete │ 7 confirmed
 rce     │ ✓ Complete │ 0
 lfi     │ ✓ Complete │ 2 potential

══════════════════════════════════════════════════════════════════════
 RESULTS SUMMARY
══════════════════════════════════════════════════════════════════════

 Total Tests:      24,560
 Blocked by WAF:   23,891 (97.3%)
 Allowed/Vuln:        669 (2.7%)

 By Severity:
 ├─ Critical:   2
 ├─ High:       8
 ├─ Medium:    21
 └─ Low:       45

 📄 Output: results.json

✅ Execution complete in 12m34s
```

#### All Run Options

```bash
waf-tester run -u https://example.com \
  -c 50 \                    # Concurrent workers
  -rl 200 \                  # Rate limit (req/sec)
  -timeout 10 \              # HTTP timeout
  -retries 3 \               # Retry count
  -category sqli,xss \       # Filter categories
  -severity High,Critical \  # Filter severity
  -format json \             # Output format
  -o results.json            # Output file
```

| Option | Description | Default |
|--------|-------------|---------|
| `-c` | Concurrent workers | 25 |
| `-rl` | Max requests per second | 100 |
| `-timeout` | HTTP timeout (seconds) | 10 |
| `-retries` | Retry failed requests | 2 |
| `-category` | Filter test categories | all |
| `-severity` | Filter result severity | all |
| `-format` | Output format (json/html/csv) | json |

---

### Workflow Orchestration (workflow)

**Purpose:** Execute multi-step security workflows from YAML/JSON configuration files.

**TL;DR:** `waf-tester workflow -f security-workflow.yaml` — Automated multi-step assessment

The `workflow` command chains multiple commands together with variable substitution, enabling repeatable automated assessments.

#### Prerequisites

| Requirement | Details |
|-------------|---------|
| **Workflow File** | YAML or JSON workflow definition |
| **Network** | Access to all targets referenced |
| **Authorization** | Varies by workflow steps |
| **Time** | Depends on workflow complexity |

#### Basic Workflow Execution

```bash
waf-tester workflow -f security-workflow.yaml
```

#### With Input Variables

```bash
waf-tester workflow -f workflow.yaml -var "target=https://example.com,token=abc123"
```

#### Dry Run Mode

```bash
# Preview workflow steps without executing
waf-tester workflow -f workflow.yaml -dry-run
```

#### Sample Workflow Execution

```
$ waf-tester workflow -f full-assessment.yaml -var "target=https://shop.example.com"

WAFtester v2.6.5 — Workflow Orchestration

Workflow: Full Security Assessment
Steps: 4

══════════════════════════════════════════════════════════════════════
 WORKFLOW EXECUTION
══════════════════════════════════════════════════════════════════════

 Step 1: discover
 ├─ Command: waf-tester discover -u https://shop.example.com
 ├─ Duration: 4.5s
 └─ Status: ✓ Complete (148 endpoints)

 Step 2: learn
 ├─ Command: waf-tester learn -discovery discovery.json
 ├─ Duration: 1.2s
 └─ Status: ✓ Complete (24,560 tests planned)

 Step 3: scan
 ├─ Command: waf-tester run -plan testplan.json
 ├─ Duration: 12m34s
 └─ Status: ✓ Complete (12 findings)

 Step 4: report
 ├─ Command: waf-tester report -workspace .
 ├─ Duration: 3.2s
 └─ Status: ✓ Complete (report.html generated)

══════════════════════════════════════════════════════════════════════
 WORKFLOW COMPLETE
══════════════════════════════════════════════════════════════════════

 Total Duration: 12m43s
 Steps Passed:   4/4

 Outputs:
 ├─ discovery.json    Discovered endpoints
 ├─ testplan.json     Generated test plan
 ├─ results.json      Test results
 └─ report.html       Final report

✅ Workflow complete
```

#### Example Workflow File

```yaml
name: "Full Security Assessment"
description: "Complete security testing workflow"

steps:
  - name: discover
    command: waf-tester discover -u {{target}} -output discovery.json

  - name: learn
    command: waf-tester learn -discovery discovery.json -output testplan.json

  - name: scan
    command: waf-tester run -plan testplan.json -o results.json

  - name: report
    command: waf-tester report -workspace . -target "{{target}}"
```

#### Workflow Options

| Flag | Description | Default |
|------|-------------|---------|
| `-f`, `-file` | Workflow file (YAML or JSON) | required |
| `-var` | Input variables (name=value, comma-separated) | none |
| `-dry-run` | Preview without executing | false |
| `-timeout` | Workflow timeout in seconds | 300 |
| `-v` | Verbose output | false |
| `-json` | JSON output to stdout | false |
| `-o` | Output file for results | none |

#### Decision Guide

| Scenario | Approach | Why |
|----------|----------|-----|
| Quick one-time test | `auto` command | Simpler |
| Repeatable assessment | Create workflow YAML | Automate and document |
| CI/CD integration | Workflow + `-json` + `-o` | Parse results in pipeline |
| Custom multi-target | Use `-var` for each target | Same workflow, different targets |

#### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| "Variable not found" | Missing `-var` | Check variable names in workflow |
| Step fails mid-workflow | Previous output missing | Check step dependencies |
| Timeout exceeded | Workflow takes too long | Increase `-timeout 1800` |
| File already exists | Re-running workflow | Delete previous outputs or use unique names |

---

## Protocol Testing

### GraphQL Security Testing

```bash
# Automatic GraphQL endpoint detection
waf-tester auto -u https://api.example.com/graphql

# Deep GraphQL introspection
waf-tester scan -u https://api.example.com/graphql -types graphql
```

#### GraphQL Attack Categories

| Attack | Description |
|--------|-------------|
| Introspection exposure | Schema enumeration |
| Query depth attacks | Resource exhaustion |
| Batch query abuse | DoS via batching |
| Field suggestion | Information disclosure |
| Authorization bypass | Alias-based access |
| Directive injection | Malicious directives |

---

### gRPC Security Testing

```bash
# gRPC reflection-based testing
waf-tester scan -u grpc://service.example.com:50051 -types grpc

# With TLS
waf-tester scan -u grpcs://service.example.com:50051 -types grpc
```

#### gRPC Attack Categories

- Reflection enumeration
- Message field fuzzing
- Streaming abuse
- Metadata injection
- Proto type confusion

---

### SOAP/WSDL Security Testing

```bash
# WSDL-based SOAP testing
waf-tester scan -u https://api.example.com/service.wsdl -types soap
```

#### SOAP Attack Categories

- WSDL enumeration
- XML injection in SOAP body
- XXE attacks
- WS-Security bypass
- SOAP action manipulation

---

## Tamper Scripts

70+ tamper scripts ported from sqlmap for WAF bypass.

### Using Tampers

```bash
# Single tamper
waf-tester scan -u https://target.com --tamper=space2comment

# Multiple tampers (applied in sequence)
waf-tester scan -u https://target.com --tamper=space2comment,charencode,randomcase

# List all available tampers
waf-tester tampers --list

# List tampers by category
waf-tester tampers --category=encoding
```

### Auto-Select Tampers (v2.4.2+)

Let WAFtester automatically select optimal tampers based on detected WAF:

```bash
# Auto mode with automatic tamper selection
waf-tester auto -u https://target.com --tamper-auto

# Scan mode with smart WAF detection + auto tampers
waf-tester scan -u https://target.com --smart --tamper-auto

# Combine with custom tampers (custom applied first, then auto)
waf-tester scan -u https://target.com --tamper=nullbyte --tamper-auto
```

### Tamper Profiles (v2.4.2+)

Use predefined tamper profiles optimized for different scenarios:

```bash
# Stealth profile - minimal transformation, low detection risk
waf-tester scan -u https://target.com --tamper-profile=stealth

# Standard profile - balanced approach
waf-tester scan -u https://target.com --tamper-profile=standard

# Aggressive profile - maximum bypass attempts
waf-tester scan -u https://target.com --tamper-profile=aggressive

# Bypass profile - all available techniques
waf-tester scan -u https://target.com --tamper-profile=bypass
```

### WAF Intelligence Matrix (v2.4.2+)

Get WAF-specific tamper recommendations:

```bash
# Show recommended tampers for a specific WAF
waf-tester tampers --for-waf=cloudflare
waf-tester tampers --for-waf=aws_waf
waf-tester tampers --for-waf=modsecurity

# Show full WAF intelligence matrix (16+ vendors)
waf-tester tampers --matrix

# JSON output for automation
waf-tester tampers --for-waf=cloudflare --json
waf-tester tampers --matrix --json
```

Supported WAF vendors in the intelligence matrix:
- Cloudflare, AWS WAF, Akamai, Imperva, Azure WAF
- F5 BIG-IP, Fortinet FortiWeb, ModSecurity, Barracuda
- Sucuri, Radware, Citrix, Palo Alto, Sophos, Wallarm

### Test Payload Transformation (v2.4.2+)

Preview how tampers transform payloads step-by-step:

```bash
# Test single tamper
waf-tester tampers --test "' OR 1=1--" --tamper=space2comment

# Test tamper chain (see step-by-step transformation)
waf-tester tampers --test "SELECT * FROM users" --tamper=space2comment,randomcase,charencode

# Without --tamper, uses default chain
waf-tester tampers --test "admin'--"
```

### Tamper Categories

| Category | Count | Description |
|----------|-------|-------------|
| `encoding` | 12 | Base64, URL encoding, Unicode escapes |
| `space` | 12 | Space replacement (comments, tabs, etc.) |
| `sql` | 16 | SQL syntax transformations |
| `mysql` | 10 | MySQL-specific bypasses |
| `mssql` | 6 | MSSQL-specific bypasses |
| `waf` | 4 | WAF-specific bypasses (ModSecurity, etc.) |
| `http` | 3 | HTTP-level modifications (headers) |
| `obfuscation` | 6 | General obfuscation techniques |

### Popular Tamper Combinations

```bash
# ModSecurity bypass
--tamper=modsecurityversioned,space2comment

# Cloudflare bypass
--tamper=charunicodeencode,randomcase

# AWS WAF bypass
--tamper=between,equaltolike,space2morecomment

# Generic WAF bypass combo
--tamper=space2comment,randomcase,charencode,unmagicquotes
```

---

## Mutation Engine

The mutation engine automatically transforms payloads to bypass WAF filters.

### Encoders

16 encoding types available:

| Encoder | Description |
|---------|-------------|
| `raw` | No encoding - original payload |
| `url` | Standard URL percent-encoding |
| `double_url` | Double URL encoding |
| `triple_url` | Triple URL encoding |
| `html_decimal` | HTML decimal encoding (&#65;) |
| `html_hex` | HTML hex encoding (&#x41;) |
| `html_named` | HTML named entities (&amp;) |
| `unicode` | Unicode encoding (\u0041) |
| `utf7` | UTF-7 encoding |
| `utf16le` | UTF-16 Little Endian |
| `utf16be` | UTF-16 Big Endian |
| `overlong_utf8` | Overlong UTF-8 sequences |
| `wide_gbk` | Wide GBK encoding |
| `wide_sjis` | Wide Shift-JIS encoding |
| `base64` | Base64 encoding |
| `hex` | Hex encoding |
| `octal` | Octal encoding |
| `mixed` | Mixed encoding combinations |

```bash
waf-tester mutate -u https://target.com -encoders url,double_url,unicode
```

### Evasion Techniques

10 evasion techniques:

| Evasion | Description |
|---------|-------------|
| `case_swap` | Case manipulation (SeLeCt) |
| `sql_comment` | SQL comment insertion (SEL/**/ECT) |
| `whitespace_alt` | Alternative whitespace characters |
| `null_byte` | Null byte injection |
| `chunked` | Chunked encoding evasion |
| `hpp` | HTTP Parameter Pollution |
| `double_submit` | Double submit parameters |
| `content_type_mismatch` | Content-Type confusion |
| `unicode_normalization` | Unicode normalization attacks |
| `comment_wrapping` | Comment-wrapped payloads |

```bash
waf-tester mutate -u https://target.com -evasions case_swap,sql_comment
```

### Injection Locations

13 injection locations:

| Location | Description |
|----------|-------------|
| `query_param` | URL query parameter |
| `post_form` | POST form body |
| `post_json` | POST JSON body |
| `post_xml` | POST XML body |
| `header_xforward` | X-Forwarded-For header |
| `header_referer` | Referer header |
| `header_useragent` | User-Agent header |
| `header_custom` | Custom headers |
| `cookie` | Cookie values |
| `path_segment` | URL path segment |
| `multipart` | Multipart form data |
| `fragment` | URL fragment |
| `basic_auth` | Basic authentication |

```bash
waf-tester mutate -u https://target.com -locations query_param,post_json,cookie
```

### Protocol Mutations

8 protocol-level mutations:

| Mutation | Description |
|----------|-------------|
| `smuggle_clte` | CL.TE HTTP smuggling |
| `smuggle_tecl` | TE.CL HTTP smuggling |
| `smuggle_tete` | TE.TE HTTP smuggling |
| `http2_downgrade` | HTTP/2 downgrade attacks |
| `websocket_upgrade` | WebSocket upgrade attacks |
| `request_line` | Request line mutations |
| `header_folding` | Header folding |
| `te_obfuscation` | Transfer-Encoding obfuscation |

### Mutation Chaining

```bash
# Enable chaining
waf-tester mutate -u https://target.com -chain

# Set maximum chain depth
waf-tester mutate -u https://target.com -chain -max-chain 3

# Full mutation mode
waf-tester mutate -u https://target.com -mutation full
```

Mutation modes:
- `none` - No mutations
- `quick` - Fast essential mutations
- `standard` - Balanced coverage
- `full` - Complete mutation matrix

---

## Smart Mode

WAF-aware testing with 197+ vendor signatures.

```bash
# Enable smart mode
waf-tester scan -u https://target.com --smart

# With optimization level
waf-tester bypass -u https://target.com --smart --smart-mode=full

# Verbose output
waf-tester auto -u https://target.com --smart --smart-verbose
```

### Smart Mode Levels

| Mode | Description |
|------|-------------|
| `quick` | Fast detection, minimal adaptation |
| `standard` | Balanced detection and optimization |
| `full` | Complete WAF analysis and bypass |
| `bypass` | Focus on bypass techniques |
| `stealth` | Low and slow to avoid detection |

### What Smart Mode Does

1. **WAF Detection** - Identifies WAF from 197+ vendor signatures
2. **Rate Optimization** - Adjusts rate limit to avoid triggering blocks
3. **Encoder Priority** - Prioritizes encoders known to bypass that WAF
4. **Evasion Selection** - Enables effective evasion techniques
5. **Bypass Hints** - Shows specific bypass tips for the detected WAF

---

## Intelligence Engine (v2.6.5)

The Intelligence Engine transforms auto mode from "automated sequencing" to "adaptive reasoning" through advanced cognitive modules that learn and adapt during scans.

### Enabling Brain Mode

```bash
# Brain mode is enabled by default in auto scans
waf-tester auto -u https://target.com

# Verbose brain output showing learning insights
waf-tester auto -u https://target.com --brain-verbose

# Disable brain mode for deterministic testing
waf-tester auto -u https://target.com --brain=false
```

### Advanced Cognitive Modules

| Module | Purpose | Value |
|--------|---------|-------|
| **Bypass Predictor** | Predicts bypass probability before testing | Reduces wasted requests by 40%+ |
| **Mutation Strategist** | Suggests specific mutations when blocked | Improves bypass discovery rate |
| **Endpoint Clusterer** | Groups similar endpoints | Reduces redundant testing |
| **Anomaly Detector** | Detects honeypots, silent bans | Protects scan integrity |
| **Attack Path Optimizer** | Finds optimal paths through vulnerabilities | Prioritizes high-value chains |

### Persistence: Save and Resume Brain State

The Intelligence Engine can save learned patterns for future scans:

```bash
# Auto mode automatically saves state to workspace
waf-tester auto -u https://target.com --workspace ./assessment

# Resume a previous scan with learned state
waf-tester auto -u https://target.com --resume --workspace ./assessment
```

### Programmatic Usage

For developers integrating the intelligence package:

```go
import "github.com/waftester/waftester/pkg/intelligence"

// Create engine with default config
engine := intelligence.NewEngine(nil)

// Feed findings to the engine
engine.LearnFromFinding(&intelligence.Finding{
    Phase:    "waf-testing",
    Category: "sqli",
    Payload:  "' OR '1'='1",
    Blocked:  true,
})

// Get bypass predictions
predictions := engine.Predictor().PredictBatch(categories)

// Get mutation suggestions when blocked
suggestions := engine.MutationStrategist().SuggestMutations("sqli", payload, "cloudflare")

// Save brain state for future scans
engine.Save("/path/to/brain-state.json")

// Load previous brain state
engine.Load("/path/to/brain-state.json")
```

### WAF Profiler

The WAF Profiler learns WAF behavior patterns during testing:

```go
// Access the profiler
profiler := engine.WAFProfiler()

// Set detected WAF fingerprint from pkg/waf
profiler.SetFingerprint(fingerprint)

// Get category bypass effectiveness
sqliBypassRate := profiler.GetCategoryEffectiveness("sqli")

// Get best encoding techniques
encodings := profiler.GetBestEncodings(5)

// Generate summary report
summary := profiler.GenerateSummary()
fmt.Printf("Overall bypass rate: %.1f%%\n", summary.OverallBypassRate*100)
fmt.Printf("Weak categories: %v\n", summary.WeakCategories)
```

### Metrics and Observability

Track intelligence engine performance:

```go
metrics := engine.Metrics()

// After scan completes
snapshot := metrics.Snapshot()
fmt.Printf("Findings processed: %d\n", snapshot.FindingsProcessed)
fmt.Printf("Predictions accurate: %.1f%%\n", 
    float64(snapshot.PredictionsAccurate)/float64(snapshot.PredictionsRequested)*100)
```

---

## Integration Overview (v2.5.0+)

WAFtester provides comprehensive integration options for enterprise environments. This section helps you choose the right integration approach for your needs.

### Integration Decision Guide

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    What do you need to integrate?                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │  FILE OUTPUTS   │  │  REAL-TIME      │  │  OBSERVABILITY  │             │
│  │                 │  │  ALERTING       │  │  & HISTORY      │             │
│  └───────┬─────────┘  └───────┬─────────┘  └───────┬─────────┘             │
│          │                    │                    │                        │
│          ▼                    ▼                    ▼                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │ • SARIF (CI/CD) │  │ • Slack         │  │ • OpenTelemetry │             │
│  │ • JUnit (tests) │  │ • Teams         │  │ • Prometheus    │             │
│  │ • JSON/JSONL    │  │ • PagerDuty     │  │ • History Store │             │
│  │ • SonarQube     │  │ • Jira          │  └─────────────────┘             │
│  │ • GitLab SAST   │  │ • Webhook       │                                  │
│  │ • CycloneDX VEX │  │ • GitHub Issues │                                  │
│  │ • DefectDojo    │  │ • Azure DevOps  │                                  │
│  │ • HAR           │  │ • Elasticsearch │                                  │
│  │ • XML (legacy)  │  │ • GitHub Actions│                                  │
│  └─────────────────┘  └─────────────────┘                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Complete Integration Flag Reference

#### File Output Flags

| Flag | Format | Description |
|------|--------|-------------|
| `-format json` | JSON | Full results as JSON object |
| `-format jsonl` | JSONL | Newline-delimited JSON (streaming) |
| `-format sarif` | SARIF 2.1.0 | GitHub/GitLab Security integration |
| `-format junit` | JUnit XML | CI/CD test frameworks |
| `-format csv` | CSV | Spreadsheet analysis |
| `-format html` | HTML | Interactive reports |
| `-format markdown` | Markdown | Documentation |
| `-format pdf` | PDF | Executive reports |
| `-format sonarqube` | SonarQube | Generic Issue Import |
| `-format gitlab-sast` | GitLab SAST | Security Dashboard |
| `-format cyclonedx` | CycloneDX VEX | SBOM integration |
| `-format defectdojo` | DefectDojo | Findings import |
| `-format har` | HAR | HTTP Archive for replay |
| `--xml-export=FILE` | XML | Legacy XML with WASC/CWE compliance mapping (v2.6.8+) |

#### Real-time Alerting Flags

| Flag | Service | When to Use |
|------|---------|-------------|
| `--slack-webhook=URL` | Slack | Team notifications |
| `--teams-webhook=URL` | Microsoft Teams | Enterprise IM |
| `--pagerduty-key=KEY` | PagerDuty | On-call escalation |
| `--webhook=URL` | Any HTTP | Custom integrations |
| `--jira-url=URL` | Jira | Issue tracking |
| `--jira-project=KEY` | Jira | Project for issues |
| `--jira-email=EMAIL` | Jira | Authentication |
| `--jira-token=TOKEN` | Jira | API token |
| `--jira-issue-type=TYPE` | Jira | Issue type (Bug, Task, Story - default: Bug) |
| `--jira-labels=LABELS` | Jira | Comma-separated labels |
| `--jira-assignee=ID` | Jira | Assignee account ID |
| `--github-issues-token=TOKEN` | GitHub Issues | Create issues from bypasses (v2.6.8+) |
| `--github-issues-owner=ORG` | GitHub Issues | Repository owner |
| `--github-issues-repo=REPO` | GitHub Issues | Repository name |
| `--github-issues-url=URL` | GitHub Issues | GitHub Enterprise API URL |
| `--github-issues-labels=LABELS` | GitHub Issues | Comma-separated labels |
| `--github-issues-assignees=USERS` | GitHub Issues | Comma-separated assignees |
| `--ado-org=ORG` | Azure DevOps | Organization name (v2.6.8+) |
| `--ado-project=PROJECT` | Azure DevOps | Project name |
| `--ado-pat=TOKEN` | Azure DevOps | Personal Access Token |
| `--ado-work-item-type=TYPE` | Azure DevOps | Bug, Task, Issue (default: Bug) |
| `--ado-area-path=PATH` | Azure DevOps | Optional area path |
| `--ado-iteration-path=PATH` | Azure DevOps | Optional iteration/sprint path |
| `--ado-tags=TAGS` | Azure DevOps | Semicolon-separated tags |
| `--ado-assigned-to=USER` | Azure DevOps | Assigned user email/name |
| `--elasticsearch-url=URL` | Elasticsearch | SIEM integration (v2.6.8+) |
| `--elasticsearch-api-key=KEY` | Elasticsearch | API key auth |
| `--elasticsearch-username=USER` | Elasticsearch | Basic auth username |
| `--elasticsearch-password=PASS` | Elasticsearch | Basic auth password |
| `--elasticsearch-index=NAME` | Elasticsearch | Index name (default: waftester-YYYY.MM.DD) |
| `--elasticsearch-insecure` | Elasticsearch | Skip TLS verify |

#### Observability Flags

| Flag | Service | When to Use |
|------|---------|-------------|
| `--otel-endpoint=HOST:PORT` | OpenTelemetry | Distributed tracing |
| `--otel-insecure` | OpenTelemetry | Skip TLS verification |
| `--metrics-port=PORT` | Prometheus | Metrics scraping |
| `--history-path=DIR` | History Store | Scan result storage (v2.6.8+) |
| `--history-tags=TAGS` | History Store | Tag scans for filtering (v2.6.8+) |

#### CI/CD-Specific Flags

| Flag | Platform | Description |
|------|----------|-------------|
| `--github-output` | GitHub Actions | Set step outputs |
| `--github-summary` | GitHub Actions | Job summary report |
| `--stream` | All CI/CD | Non-animated output |

### Integration by Use Case

#### 1. Security Scanning in CI/CD Pipeline

**Goal:** Block deployments with critical vulnerabilities

```bash
# GitHub/GitLab - SARIF for Security tab
waf-tester scan -u $TARGET_URL --stream -format sarif -o results.sarif

# Jenkins/Azure DevOps - JUnit for test reporting
waf-tester scan -u $TARGET_URL --stream -format junit -o results.xml

# Exit code 1 on bypasses (use --policy for custom rules)
```

#### 2. Real-time Security Operations

**Goal:** Alert SOC team immediately on critical findings

```bash
waf-tester scan -u $TARGET_URL \
  --slack-webhook=$SLACK_WEBHOOK \
  --pagerduty-key=$PD_KEY
```

#### 3. Vulnerability Management

**Goal:** Track findings in vulnerability management system

```bash
# DefectDojo
waf-tester scan -u $TARGET_URL -format defectdojo -o findings.json

# SonarQube
waf-tester scan -u $TARGET_URL -format sonarqube -o issues.json
```

#### 4. Observability and Monitoring

**Goal:** Monitor WAF effectiveness over time

```bash
# Prometheus metrics + Grafana dashboards
waf-tester scan -u $TARGET_URL --metrics-port=9090

# OpenTelemetry traces to Jaeger/Tempo
waf-tester scan -u $TARGET_URL --otel-endpoint=localhost:4317
```

#### 5. Compliance and Reporting

**Goal:** Generate executive reports with evidence

```bash
waf-tester scan -u $TARGET_URL \
  -format pdf -o executive-report.pdf \
  -format html -o detailed-report.html \
  -format cyclonedx -o vulnerability-sbom.json
```

#### 6. SIEM Integration (v2.6.8+)

**Goal:** Stream results to Elasticsearch for centralized security monitoring

```bash
# Elasticsearch with API key auth
waf-tester scan -u $TARGET_URL \
  --elasticsearch-url=https://elastic.company.com:9200 \
  --elasticsearch-api-key=$ES_API_KEY \
  --elasticsearch-index=waftester-findings

# Self-signed certificates
waf-tester scan -u $TARGET_URL \
  --elasticsearch-url=https://localhost:9200 \
  --elasticsearch-username=elastic \
  --elasticsearch-password=$ES_PASSWORD \
  --elasticsearch-insecure
```

#### 7. GitHub Issues Integration (v2.6.8+)

**Goal:** Auto-create GitHub issues for each WAF bypass

```bash
waf-tester scan -u $TARGET_URL \
  --github-issues-token=$GITHUB_TOKEN \
  --github-issues-owner=myorg \
  --github-issues-repo=security-findings
```

#### 8. Azure DevOps Integration (v2.6.8+)

**Goal:** Auto-create Azure DevOps work items for each WAF bypass

```bash
# Basic work item creation
waf-tester scan -u $TARGET_URL \
  --ado-org=myorganization \
  --ado-project=SecurityTests \
  --ado-pat=$ADO_PAT

# With custom work item type and path
waf-tester scan -u $TARGET_URL \
  --ado-org=myorganization \
  --ado-project=SecurityTests \
  --ado-pat=$ADO_PAT \
  --ado-work-item-type=Task \
  --ado-area-path="SecurityTests\\Vulnerabilities" \
  --ado-iteration-path="SecurityTests\\Sprint 42"
```

Work items include:
- Formatted HTML description with severity and priority
- Repro steps with curl commands
- CWE links for remediation guidance
- Auto-assigned tags (waf-tester, security, waf-bypass)

#### 9. Historical Trend Analysis (v2.6.8+)

**Goal:** Track WAF effectiveness over time

```bash
# Store scan results for trend analysis
waf-tester scan -u $TARGET_URL \
  --history-path=./waftester-history \
  --history-tags=production,weekly

# Use with scheduled scans to build historical data
```

#### 10. Custom Report Templates (v2.6.8+)

**Goal:** Customize report branding and sections

```bash
# Minimal executive summary
waf-tester scan -u $TARGET_URL \
  --html report.html \
  --template-config pkg/report/templates/configs/minimal.yaml

# Full enterprise audit
waf-tester scan -u $TARGET_URL \
  --html report.html \
  --template-config pkg/report/templates/configs/enterprise.yaml
```

### Environment Variables

All flags can be set via environment variables:

| Environment Variable | Flag Equivalent |
|---------------------|-----------------|
| `WAFTESTER_SLACK_WEBHOOK` | `--slack-webhook` |
| `WAFTESTER_TEAMS_WEBHOOK` | `--teams-webhook` |
| `WAFTESTER_PAGERDUTY_KEY` | `--pagerduty-key` |
| `WAFTESTER_WEBHOOK_URL` | `--webhook` |
| `WAFTESTER_JIRA_URL` | `--jira-url` |
| `WAFTESTER_JIRA_PROJECT` | `--jira-project` |
| `WAFTESTER_JIRA_EMAIL` | `--jira-email` |
| `WAFTESTER_JIRA_TOKEN` | `--jira-token` |
| `WAFTESTER_GITHUB_ISSUES_TOKEN` | `--github-issues-token` |
| `WAFTESTER_GITHUB_ISSUES_OWNER` | `--github-issues-owner` |
| `WAFTESTER_GITHUB_ISSUES_REPO` | `--github-issues-repo` |
| `WAFTESTER_ADO_ORG` | `--ado-org` |
| `WAFTESTER_ADO_PROJECT` | `--ado-project` |
| `WAFTESTER_ADO_PAT` | `--ado-pat` |
| `WAFTESTER_ADO_WORK_ITEM_TYPE` | `--ado-work-item-type` |
| `WAFTESTER_ADO_AREA_PATH` | `--ado-area-path` |
| `WAFTESTER_ADO_ITERATION_PATH` | `--ado-iteration-path` |
| `WAFTESTER_ELASTICSEARCH_URL` | `--elasticsearch-url` |
| `WAFTESTER_ELASTICSEARCH_API_KEY` | `--elasticsearch-api-key` |
| `WAFTESTER_ELASTICSEARCH_USERNAME` | `--elasticsearch-username` |
| `WAFTESTER_ELASTICSEARCH_PASSWORD` | `--elasticsearch-password` |
| `WAFTESTER_ELASTICSEARCH_INDEX` | `--elasticsearch-index` |
| `WAFTESTER_ADO_TAGS` | `--ado-tags` |
| `WAFTESTER_ADO_ASSIGNED_TO` | `--ado-assigned-to` |
| `WAFTESTER_HISTORY_PATH` | `--history-path` |
| `WAFTESTER_HISTORY_TAGS` | `--history-tags` |
| `WAFTESTER_TEMPLATE_CONFIG` | `--template-config` |
| `WAFTESTER_XML_EXPORT` | `--xml-export` |
| `WAFTESTER_OTEL_ENDPOINT` | `--otel-endpoint` |
| `WAFTESTER_METRICS_PORT` | `--metrics-port` |

### Multiple Outputs

WAFtester can produce multiple outputs in a single scan:

```bash
# Generate all formats at once
waf-tester scan -u https://target.com \
  -format sarif -o results.sarif \
  -format junit -o results.xml \
  -format html -o report.html \
  -format json -o results.json \
  --slack-webhook=$SLACK_WEBHOOK \
  --metrics-port=9090
```

---

## Output Formats

**In this section:**
[HTML Reports](#html-reports-with-themes-v250) · [Markdown](#markdown-with-enhanced-features-v250) ·
[Console](#colorized-console-output-v250) · [Custom Templates](#custom-templates-v250) ·
[PDF Reports](#pdf-reports-v250) · [Enterprise](#enterprise-integrations-v250) ·
[JUnit XML](#junit-xml-reports-v250) · [CycloneDX VEX](#cyclonedx-vex-reports-v250) ·
[XML Export](#xml-export-v268) · [Elasticsearch](#elasticsearch-siem-integration-v268) ·
[GitHub Issues](#github-issues-integration-v268) · [Azure DevOps](#azure-devops-integration-v268) ·
[History](#historical-trend-analysis-v268) · [Templates](#template-configuration-v268) ·
[Alerting Hooks](#real-time-alerting-hooks-v250) · [GitHub Actions](#github-actions-integration-v250) ·
[OpenTelemetry](#opentelemetry-tracing-v250)

### Available Formats

| Format | Flag | Use Case | Enhancements |
|--------|------|----------|---------------------|
| JSON | `-format json` | Programmatic processing | Full scan events |
| JSONL | `-format jsonl` | Streaming, large datasets | Event types: scan_start, vulnerability, scan_complete |
| HTML | `-format html` | Human-readable reports | Themes, interactive charts, DataTables |
| SARIF | `-format sarif` | CI/CD integration, GitHub Security | 100% SARIF 2.1.0 compliant |
| Markdown | `-format markdown` or `-format md` | Documentation | TOC, OWASP sections, badges |
| CSV | `-format csv` | Spreadsheet analysis | OWASP columns, risk scores |
| Console | `-format console` | Terminal output (default) | Colorized, compact mode |
| Template | `--template=FILE` | Custom formats | Go template engine |
| PDF | `-format pdf` | Executive reports | Branding, digital signatures |
| JUnit | `-format junit` | CI/CD test frameworks | Jenkins, GitLab, Azure DevOps |
| CycloneDX | `-format cyclonedx` | SBOM vulnerability exchange | VEX 1.5 format |
| SonarQube | `-format sonarqube` | SonarQube integration | Generic issue import |
| GitLab SAST | `-format gitlab-sast` | GitLab Security Dashboard | gl-sast-report.json |
| DefectDojo | `-format defectdojo` | DefectDojo import | Findings format |
| HAR | `-format har` | HTTP Archive | Traffic replay |
| XML | `--xml-export=FILE` | Legacy SIEM/vulnerability platforms | WASC/CWE compliance mapping (v2.6.8+) |

### Basic Examples

```bash
waf-tester run -plan testplan.json -format json -o results.json
waf-tester run -plan testplan.json -format html -o report.html
waf-tester run -plan testplan.json -format sarif -o results.sarif
waf-tester scan -u https://target.com -format csv -o results.csv
```

### HTML Reports with Themes (v2.5.0+)

```bash
# Light theme (default) - clean professional look
waf-tester scan -u https://target.com -format html -o report.html

# Dark theme - reduced eye strain
waf-tester scan -u https://target.com -format html --html-theme=dark -o report.html

# Corporate theme - for enterprise reports
waf-tester scan -u https://target.com -format html --html-theme=corporate -o report.html

# Security theme - SOC-focused colors
waf-tester scan -u https://target.com -format html --html-theme=security -o report.html

# Custom branding
waf-tester scan -u https://target.com -format html \
  --html-logo=logo.png \
  --html-title="Q4 WAF Assessment" \
  -o report.html
```

### Markdown with Enhanced Features (v2.5.0+)

```bash
# Table of contents
waf-tester scan -u https://target.com -format md --md-toc -o report.md

# OWASP category grouping
waf-tester scan -u https://target.com -format md --md-owasp -o report.md

# GitHub-flavored Markdown with badges
waf-tester scan -u https://target.com -format md \
  --md-flavor=github \
  --md-badges \
  -o report.md

# Collapsible sections for long reports
waf-tester scan -u https://target.com -format md --md-collapsible -o report.md

# Full featured report
waf-tester scan -u https://target.com -format md \
  --md-toc \
  --md-owasp \
  --md-badges \
  --md-collapsible \
  -o report.md
```

### Colorized Console Output (v2.5.0+)

```bash
# Compact table mode (default)
waf-tester scan -u https://target.com --table-mode=compact

# Detailed table with all columns
waf-tester scan -u https://target.com --table-mode=detailed

# Wide table for large terminals
waf-tester scan -u https://target.com --table-mode=wide

# Minimal - one line per finding
waf-tester scan -u https://target.com --table-mode=minimal

# Disable colors (for pipes)
waf-tester scan -u https://target.com --no-color
```

### Custom Templates (v2.5.0+)

```bash
# Use built-in templates
waf-tester scan -u https://target.com --template=executive
waf-tester scan -u https://target.com --template=technical
waf-tester scan -u https://target.com --template=compliance

# Custom Go template file
waf-tester scan -u https://target.com --template=custom-report.tmpl -o report.html
```

Example custom template (`custom-report.tmpl`):
```html
<!DOCTYPE html>
<html>
<head><title>{{.Title}}</title></head>
<body>
  <h1>Security Assessment: {{.Target}}</h1>
  <p>Scan completed: {{.Timestamp}}</p>
  
  <h2>Summary</h2>
  <ul>
    <li>Total tests: {{.Summary.Total}}</li>
    <li>Blocked: {{.Summary.Blocked}}</li>
    <li>Bypassed: {{.Summary.Bypassed}}</li>
    <li>WAF Effectiveness: {{printf "%.1f" .Summary.Effectiveness}}%</li>
  </ul>
  
  {{range .Results}}
  <div class="finding {{.Severity | lower}}">
    <h3>{{.ID}}: {{.Category}}</h3>
    <p>Severity: {{.Severity}} | Status: {{.Outcome}}</p>
  </div>
  {{end}}
</body>
</html>
```

### PDF Reports (v2.5.0+)

```bash
# Basic PDF report
waf-tester scan -u https://target.com -format pdf -o report.pdf

# Executive summary PDF
waf-tester scan -u https://target.com -format pdf \
  --pdf-template=executive \
  -o executive-summary.pdf

# Branded PDF with logo and signature
waf-tester scan -u https://target.com -format pdf \
  --pdf-logo=company-logo.png \
  --pdf-header="Confidential - Internal Use Only" \
  --pdf-footer="Generated by Security Team" \
  -o branded-report.pdf

# PDF with digital signature (requires certificate)
waf-tester scan -u https://target.com -format pdf \
  --pdf-sign \
  --pdf-cert=signing-cert.p12 \
  -o signed-report.pdf
```

### Enterprise Integrations (v2.5.0+)

```bash
# SonarQube Generic Issue Import
waf-tester scan -u https://target.com -format sonarqube -o sonar-issues.json
# Upload: sonar-scanner -Dsonar.externalIssuesReportPaths=sonar-issues.json

# GitLab SAST Report
waf-tester scan -u https://target.com -format gitlab-sast -o gl-sast-report.json

# DefectDojo Import
waf-tester scan -u https://target.com -format defectdojo -o findings.json
# Import: curl -X POST https://defectdojo.example.com/api/v2/import-scan/

# HAR for traffic replay
waf-tester scan -u https://target.com -format har -o traffic.har
```

### JUnit XML Reports (v2.5.0+)

JUnit XML is the standard format for CI/CD test frameworks. WAFtester generates JUnit-compatible reports that integrate with Jenkins, GitLab CI, Azure DevOps, CircleCI, and more.

```bash
# Basic JUnit report
waf-tester scan -u https://target.com -format junit -o results.xml

# JUnit with custom test suite name
waf-tester scan -u https://target.com -format junit \
  --junit-suite="WAF Security Tests" \
  -o test-results.xml

# JUnit for Jenkins
waf-tester scan -u https://target.com -format junit -o junit-report.xml
# Jenkins: Post-build action -> Publish JUnit test result report

# JUnit for GitLab CI
waf-tester scan -u https://target.com -format junit -o junit.xml
# .gitlab-ci.yml: artifacts: reports: junit: junit.xml

# JUnit for Azure DevOps
waf-tester scan -u https://target.com -format junit -o test-results.xml
# Azure: PublishTestResults@2 task with testResultsFiles: '**/test-results.xml'
```

**Sample JUnit XML Output:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="WAFtester Security Scan" tests="2847" failures="119" errors="0" time="45.23">
  <testsuite name="SQL Injection" tests="847" failures="42" time="12.34">
    <testcase name="sqli-001: Union-based injection" classname="sqli.union" time="0.234">
      <failure message="WAF Bypass Detected" type="security">
Target: https://target.com/api/users?id=1
Payload: 1' UNION SELECT username,password FROM users--
Severity: Critical
OWASP: A03:2021 - Injection
Evidence: SQL syntax in response, 5 rows returned
Tampers: charunicodeencode, space2comment
      </failure>
    </testcase>
    <testcase name="sqli-002: Boolean-based blind" classname="sqli.blind" time="0.156"/>
    <testcase name="sqli-003: Time-based blind" classname="sqli.time" time="0.189"/>
  </testsuite>
  <testsuite name="Cross-Site Scripting" tests="623" failures="31" time="9.87">
    <testcase name="xss-001: Reflected XSS" classname="xss.reflected" time="0.123">
      <failure message="WAF Bypass Detected" type="security">
Target: https://target.com/search?q=test
Payload: &lt;script&gt;alert(1)&lt;/script&gt;
Severity: High
OWASP: A03:2021 - Injection
      </failure>
    </testcase>
  </testsuite>
</testsuites>
```

### CycloneDX VEX Reports (v2.5.0+)

CycloneDX VEX (Vulnerability Exploitability eXchange) format for SBOM integration and vulnerability tracking.

```bash
# Basic CycloneDX VEX report
waf-tester scan -u https://target.com -format cyclonedx -o vulnerabilities.json

# CycloneDX with component information
waf-tester scan -u https://target.com -format cyclonedx \
  --cyclonedx-component="web-application" \
  --cyclonedx-version="1.0.0" \
  -o vex-report.json

# CycloneDX for SBOM tools
waf-tester scan -u https://target.com -format cyclonedx -o waf-findings.vex.json
# Merge with your SBOM: cyclonedx merge --input-files sbom.json waf-findings.vex.json
```

**Sample CycloneDX VEX Output:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "timestamp": "2026-02-03T14:30:00Z",
    "tools": [
      {
        "vendor": "WAFtester",
        "name": "waf-tester",
        "version": "2.7.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "web-application",
      "version": "1.0.0"
    }
  },
  "vulnerabilities": [
    {
      "id": "WAFT-2026-0001",
      "source": { "name": "WAFtester" },
      "ratings": [
        {
          "severity": "critical",
          "method": "other",
          "vector": "WAF bypass with payload execution"
        }
      ],
      "cwes": [89],
      "description": "SQL Injection bypass detected via union-based technique",
      "detail": "The WAF failed to block a SQL injection payload using charunicodeencode and space2comment tampers.",
      "recommendation": "Update WAF rules to detect unicode-encoded SQL keywords",
      "advisories": [
        { "title": "OWASP A03:2021", "url": "https://owasp.org/Top10/A03_2021-Injection/" }
      ],
      "affects": [
        {
          "ref": "https://target.com/api/users",
          "versions": [{ "version": "N/A", "status": "affected" }]
        }
      ],
      "properties": [
        { "name": "waftester:category", "value": "sqli" },
        { "name": "waftester:payload", "value": "1' UNION SELECT * FROM users--" },
        { "name": "waftester:tampers", "value": "charunicodeencode,space2comment" },
        { "name": "waftester:waf_bypassed", "value": "true" }
      ]
    }
  ]
}
```

### XML Export (v2.6.8+)

XML output for legacy SIEM platforms, GRC tools, and vulnerability management systems that require structured XML data with WASC/CWE compliance mapping.

```bash
# Basic XML export
waf-tester scan -u https://target.com --xml-export=results.xml

# XML with evidence (request/response data)
waf-tester scan -u https://target.com --xml-export=results.xml \
  --xml-evidence

# XML alongside other formats
waf-tester scan -u https://target.com \
  --xml-export=waf-audit.xml \
  -format html -o report.html \
  -format sarif -o results.sarif
```

**Key Features:**
- DTD-style `<waftester-report>` root element with schema versioning
- Full compliance mapping: CWE IDs, WASC threat classifications, CVE references
- Aggregate summary statistics (detection rate, bypass count, latency)
- Evidence support with payload data and WAF signature details
- 49 WASC threat classifications with 60+ category aliases

**Sample XML Output:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<waftester-report version="2.7.0" generatedAt="2026-02-03T14:30:00Z">
  <generator>
    <name>WAFtester</name>
    <version>2.7.0</version>
  </generator>
  <target>
    <url>https://target.com</url>
    <wafVendor>Cloudflare</wafVendor>
  </target>
  <summary>
    <totalTests>2847</totalTests>
    <blockedTests>2695</blockedTests>
    <passedTests>152</passedTests>
    <errorTests>0</errorTests>
    <detectionRate>94.66</detectionRate>
    <bypassCount>152</bypassCount>
    <totalLatencyMs>45230</totalLatencyMs>
  </summary>
  <results>
    <result id="sqli-001">
      <category>sqli</category>
      <severity>Critical</severity>
      <outcome>bypass</outcome>
      <confidence>High</confidence>
      <statusCode>200</statusCode>
      <latencyMs>23.5</latencyMs>
      <target>
        <url>https://target.com/api/users</url>
        <method>GET</method>
      </target>
      <evidence>
        <payload>1' UNION SELECT * FROM users--</payload>
        <responsePreview>200 OK - data returned</responsePreview>
      </evidence>
      <compliance>
        <cwe>CWE-89</cwe>
        <wasc>WASC-19</wasc>
      </compliance>
    </result>
  </results>
</waftester-report>
```

### Elasticsearch SIEM Integration (v2.6.8+)

Stream WAF test results directly into Elasticsearch for real-time security analytics, Kibana dashboards, and SIEM correlation.

```bash
# Basic Elasticsearch output
waf-tester scan -u https://target.com \
  --elasticsearch-url=http://localhost:9200

# Elasticsearch with authentication
waf-tester scan -u https://target.com \
  --elasticsearch-url=https://es.company.com:9200 \
  --elasticsearch-username=waftester \
  --elasticsearch-password=$ES_PASSWORD

# Elasticsearch with API key auth and custom index
waf-tester scan -u https://target.com \
  --elasticsearch-url=https://es.company.com:9200 \
  --elasticsearch-api-key=$ES_API_KEY \
  --elasticsearch-index=security-waf-tests

# Full configuration with all options
waf-tester scan -u https://target.com \
  --elasticsearch-url=https://es.company.com:9200 \
  --elasticsearch-api-key=$ES_API_KEY \
  --elasticsearch-index=waftester-prod \
  --elasticsearch-insecure  # Skip TLS verification (dev only)
```

**Key Features:**
- Bulk API indexing for efficient high-volume writes (NDJSON format)
- Configurable batch size (default: 100 events per bulk request)
- Two authentication methods: Basic Auth or API Key
- Auto-generated daily indices (`waftester-YYYY.MM.DD`) or custom index names
- Optional ingest pipeline support
- TLS verification control

**Environment Variables:**

```bash
export WAFTESTER_ELASTICSEARCH_URL=https://es.company.com:9200
export WAFTESTER_ELASTICSEARCH_USERNAME=waftester
export WAFTESTER_ELASTICSEARCH_PASSWORD=secret
export WAFTESTER_ELASTICSEARCH_API_KEY=base64-encoded-key
export WAFTESTER_ELASTICSEARCH_INDEX=security-waf
```

**Sample Elasticsearch Document:**

```json
{
  "_index": "waftester-2026.02.03",
  "_source": {
    "@timestamp": "2026-02-03T14:30:00Z",
    "tool": "waftester",
    "version": "2.7.0",
    "target": "https://target.com",
    "waf_vendor": "Cloudflare",
    "category": "sqli",
    "severity": "Critical",
    "outcome": "bypass",
    "status_code": 200,
    "latency_ms": 23.5,
    "payload": "1' UNION SELECT * FROM users--",
    "cwe": "CWE-89",
    "request_method": "GET",
    "request_url": "https://target.com/api/users"
  }
}
```

**Kibana Query Examples:**

```
# Find all bypasses
outcome: "bypass"

# Critical SQL injection bypasses
category: "sqli" AND severity: "Critical" AND outcome: "bypass"

# Bypasses in the last 24 hours
outcome: "bypass" AND @timestamp >= now-24h

# Group by WAF vendor
waf_vendor: * | stats count by waf_vendor, outcome
```

### GitHub Issues Integration (v2.6.8+)

Automatically create GitHub Issues for WAF bypasses, integrating security findings into your development workflow.

```bash
# Basic GitHub Issues integration
waf-tester scan -u https://target.com \
  --github-issues-token=$GITHUB_TOKEN \
  --github-issues-owner=myorg \
  --github-issues-repo=waf-findings

# With custom labels and assignees
waf-tester scan -u https://target.com \
  --github-issues-token=$GITHUB_TOKEN \
  --github-issues-owner=myorg \
  --github-issues-repo=waf-findings \
  --github-issues-labels="security,waf-bypass,p1" \
  --github-issues-assignees="securitylead,devops-team"

# GitHub Enterprise Server
waf-tester scan -u https://target.com \
  --github-issues-token=$GITHUB_TOKEN \
  --github-issues-url=https://github.company.com/api/v3 \
  --github-issues-owner=security \
  --github-issues-repo=waf-audits

# Only create issues for critical/high bypasses (default behavior)
# Issues are created for bypass events with High+ severity
```

**Key Features:**
- Automatic issue creation for bypass events (High severity minimum by default)
- Rich markdown issue body with CWE links, severity labels, and reproduction steps
- Payload included as code blocks for easy copy-paste testing
- Configurable labels, assignees, and repository targeting
- GitHub Enterprise Server support via custom base URL
- Prevents duplicate issues through event filtering

**Sample Created Issue:**

```markdown
## 🔴 WAF Bypass Detected: SQL Injection

**Severity:** Critical
**Category:** sqli
**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

### Details

A WAF bypass was detected during security testing.

**Target:** `https://target.com/api/users`
**Method:** GET
**Status Code:** 200

### Payload

\```
1' UNION SELECT * FROM users--
\```

### Recommendations

- Review and update WAF rules for this attack category
- Consider adding virtual patching rules
- Test with additional evasion techniques

---
*Created by WAFtester v2.7.0*
```

### Azure DevOps Integration (v2.6.8+)

Create Azure DevOps Work Items for WAF bypasses, integrating security findings into your Azure Boards workflow with proper severity/priority mapping.

```bash
# Basic Azure DevOps integration
waf-tester scan -u https://target.com \
  --ado-org=myorg \
  --ado-project=SecurityTesting \
  --ado-pat=$ADO_PAT

# With custom work item type and area path
waf-tester scan -u https://target.com \
  --ado-org=myorg \
  --ado-project=SecurityTesting \
  --ado-pat=$ADO_PAT \
  --ado-work-item-type=Bug \
  --ado-area-path="SecurityTesting\\WAF" \
  --ado-iteration-path="SecurityTesting\\Sprint 42"

# With tags and assignee
waf-tester scan -u https://target.com \
  --ado-org=myorg \
  --ado-project=SecurityTesting \
  --ado-pat=$ADO_PAT \
  --ado-tags="security,waf-bypass,critical" \
  --ado-assigned-to="security-lead@company.com"
```

**Key Features:**
- Work item creation via Azure DevOps REST API v7.1 (JSON Patch)
- Severity mapping: Critical→1, High→2, Medium→3, Low→4
- Priority mapping: Critical→1, High→1, Medium→2, Low→3
- HTML description with reproduction steps and curl commands
- Configurable work item type, area path, iteration path, and tags
- Input sanitization via `html.EscapeString()` (Go stdlib)

**Severity and Priority Mapping:**

| WAFtester Severity | ADO Severity | ADO Priority |
|-------------------|-------------|-------------|
| Critical | 1 - Critical | 1 |
| High | 2 - High | 1 |
| Medium | 3 - Medium | 2 |
| Low | 4 - Low | 3 |

**Environment Variables:**

```bash
export WAFTESTER_ADO_ORG=myorg
export WAFTESTER_ADO_PROJECT=SecurityTesting
export WAFTESTER_ADO_PAT=your-personal-access-token
export WAFTESTER_ADO_WORK_ITEM_TYPE=Bug
export WAFTESTER_ADO_AREA_PATH="SecurityTesting\\WAF"
export WAFTESTER_ADO_ITERATION_PATH="SecurityTesting\\Sprint 42"
export WAFTESTER_ADO_TAGS="security,waf-bypass"
export WAFTESTER_ADO_ASSIGNED_TO="security-lead@company.com"
```

### Historical Trend Analysis (v2.6.8+)

Store scan results locally for trend analysis, regression detection, and historical comparison. The history store uses file-based JSON storage for portability.

```bash
# Enable scan history storage
waf-tester scan -u https://target.com \
  --history-path=./waf-history

# Tag scans for filtering
waf-tester scan -u https://target.com \
  --history-path=./waf-history \
  --history-tags="production,weekly,cloudflare"

# Compare two scans (by scan ID)
waf-tester history compare \
  --history-path=./waf-history \
  --base=scan-2026-01-01 \
  --compare=scan-2026-02-01

# View trend data for a target
waf-tester history trend \
  --history-path=./waf-history \
  --target=https://target.com

# List all stored scans
waf-tester history list \
  --history-path=./waf-history

# Get storage statistics
waf-tester history stats \
  --history-path=./waf-history
```

**Key Features:**
- File-based JSON storage — no database required, fully portable
- Atomic writes via temp file + `os.Rename` to prevent corruption
- Automatic scan record creation from `SummaryEvent`
- Trend analysis with `TrendPoint` data series (timestamp, grade, detection rate, bypass count)
- Per-category trend tracking via `CategoryTrend`
- Scan comparison with `ComparisonResult` (grade change, rate delta, bypass delta)
- Store statistics: total scans, unique targets, storage size, date range

**Stored Scan Record Fields:**
- Target URL, WAF vendor, overall grade (A+ to F)
- Detection rate, bypass count, false positive count
- Total/blocked/passed tests, scan duration
- Average and P95 latency metrics
- Per-category detection scores
- WAFtester version, user-defined tags, notes

**Sample Comparison Output:**

```json
{
  "base_id": "scan-2026-01-01",
  "compare_id": "scan-2026-02-01",
  "grade_change": 1,
  "detection_rate_delta": 2.3,
  "bypass_count_delta": -15,
  "false_positive_delta": -2,
  "category_deltas": {
    "sqli": 3.5,
    "xss": -1.2,
    "cmdi": 5.0
  },
  "improved": true
}
```

**Scheduled Scanning with History:**

```bash
# Cron job for weekly trend tracking
0 2 * * 0 waf-tester scan -u https://target.com \
  --history-path=/var/lib/waftester/history \
  --history-tags="weekly,production" \
  -format json -o /var/log/waftester/latest.json
```

### Template Configuration (v2.6.8+)

Customize HTML report branding, layout, sections, and styling using YAML configuration files. Built-in templates for minimal and enterprise reports.

```bash
# Minimal executive summary
waf-tester scan -u https://target.com \
  -format html -o report.html \
  --template-config=pkg/report/templates/configs/minimal.yaml

# Full enterprise audit report
waf-tester scan -u https://target.com \
  -format html -o report.html \
  --template-config=pkg/report/templates/configs/enterprise.yaml

# Custom branding config
waf-tester scan -u https://target.com \
  -format html -o report.html \
  --template-config=my-company-config.yaml
```

**Built-in Templates:**

| Template | Sections | Use Case |
|----------|----------|----------|
| `enterprise.yaml` | All sections, charts, TOC, compliance | Full audit, compliance review |
| `minimal.yaml` | Summary, grade, bypasses, recommendations | Quick assessment, executive brief |

**Custom Configuration Example:**

```yaml
# my-company-config.yaml
name: acme-security
version: "1.0"

branding:
  company_name: "ACME Corp Security Assessment"
  logo_url: "https://cdn.acme.com/logo.png"
  logo_position: left
  accent_color: "#1a5276"
  secondary_color: "#2e86c1"
  footer_text: "Confidential - ACME Internal"
  copyright: "© 2026 ACME Corp"
  contact_email: "security@acme.com"
  show_powered_by: true

layout:
  theme: light       # light, dark, auto
  page_width: wide   # full, wide (1400px), standard (1200px)
  show_table_of_contents: true
  compact_mode: false
  print_optimized: false

sections:
  executive_summary: true
  overall_grade: true
  enterprise_metrics: true
  category_breakdown: true
  confusion_matrix: false
  radar_chart: true
  bypasses: true
  false_positives: true
  all_results: false      # Omit large results table
  recommendations: true
  compliance_mapping: true
  latency_metrics: true
  browser_findings: false
  technical_details: false
  timeline: true

styling:
  font_family: "Inter, system-ui, sans-serif"
  font_size_base: "16px"
  border_radius: "8px"
  custom_css: ""

charts:
  show_radar: true
  show_bar: true
  show_line: true
  animation_duration: 400
  color_palette:
    - "#3b82f6"
    - "#ef4444"
    - "#22c55e"
    - "#f59e0b"

export:
  default_format: html
  include_raw_data: true
  export_buttons: true
  allowed_formats: [html, json, pdf]
```

**Key Features:**
- YAML-based configuration — version-controlled and shareable
- `LoadTemplateConfig()` reads YAML, `MergeConfig()` merges overrides
- `ValidateConfig()` returns errors for invalid settings
- 15+ toggleable report sections
- Full CSS/branding customization (accent colors, logo, fonts)
- Chart configuration (radar, bar, line charts with color palettes)
- Export controls (allowed formats, raw data embedding, export buttons)
- Print/PDF optimization mode

### Real-time Alerting Hooks (v2.5.0+)

WAFtester provides real-time alerting integrations to notify your team immediately when security issues are detected.

#### Quick Reference: Integration Flags

| Integration | Flag | Description |
|-------------|------|-------------|
| Generic Webhook | `--webhook` | Any HTTP endpoint |
| Slack | `--slack-webhook` | Slack incoming webhook |
| Microsoft Teams | `--teams-webhook` | Teams connector webhook |
| PagerDuty | `--pagerduty-key` | Routing key for incidents |
| Jira | `--jira-url` + `--jira-project` | Create issues for bypasses |
| OpenTelemetry | `--otel-endpoint` | Export traces to OTLP |
| Prometheus | `--metrics-port` | Expose /metrics endpoint |
| GitHub Actions | `--github-output` | Set step outputs |

```bash
# Slack notifications on critical findings
waf-tester scan -u https://target.com \
  --slack-webhook=https://hooks.slack.com/services/XXX/YYY/ZZZ

# Microsoft Teams webhook
waf-tester scan -u https://target.com \
  --teams-webhook=https://outlook.office.com/webhook/XXX

# PagerDuty for on-call escalation
waf-tester scan -u https://target.com \
  --pagerduty-key=YOUR_ROUTING_KEY

# Jira ticket creation (requires all 4 flags)
waf-tester scan -u https://target.com \
  --jira-url=https://company.atlassian.net \
  --jira-project=SEC \
  --jira-email=security@company.com \
  --jira-token=$JIRA_API_TOKEN

# Generic webhook (any HTTP endpoint)
waf-tester scan -u https://target.com \
  --webhook=https://your-api.com/waf-events

# Multiple hooks simultaneously
waf-tester scan -u https://target.com \
  --slack-webhook=$SLACK_WEBHOOK \
  --pagerduty-key=$PD_KEY \
  --webhook=$CUSTOM_WEBHOOK
```

**Sample Slack Webhook Payload:**

```json
{
  "blocks": [
    {
      "type": "header",
      "text": { "type": "plain_text", "text": "🚨 WAF Bypass Detected", "emoji": true }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Severity:*\n🔴 Critical" },
        { "type": "mrkdwn", "text": "*Category:*\nSQL Injection" },
        { "type": "mrkdwn", "text": "*Target:*\nhttps://target.com/api/users" },
        { "type": "mrkdwn", "text": "*OWASP:*\nA03:2021 - Injection" }
      ]
    },
    {
      "type": "section",
      "text": { "type": "mrkdwn", "text": "*Payload:*\n```1' UNION SELECT username,password FROM users--```" }
    },
    {
      "type": "context",
      "elements": [
        { "type": "mrkdwn", "text": "WAFtester v2.7.0 | Scan ID: a1b2c3d4 | 2026-02-03T14:30:00Z" }
      ]
    }
  ]
}
```

**Sample Generic Webhook Payload:**

```json
{
  "event": "bypass",
  "timestamp": "2026-02-03T14:30:00Z",
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "finding": {
    "id": "sqli-089",
    "category": "sqli",
    "severity": "Critical",
    "confidence": 0.95,
    "url": "https://target.com/api/users",
    "parameter": "id",
    "payload": "1' UNION SELECT username,password FROM users--",
    "tampers": ["charunicodeencode", "space2comment"],
    "waf_bypassed": true,
    "owasp": "A03:2021",
    "cwe": [89],
    "evidence": {
      "request": "GET /api/users?id=1%27%20UNION...",
      "response_code": 200,
      "response_time_ms": 847,
      "indicators": ["SQL syntax in response", "5 rows returned vs 1 expected"]
    }
  },
  "context": {
    "target": "https://target.com",
    "waf_vendor": "Cloudflare",
    "waf_confidence": 0.98,
    "total_tests": 2847,
    "total_bypasses": 119
  }
}
```

### GitHub Actions Integration (v2.5.0+)

Native GitHub Actions integration for step summaries and output variables.

```bash
# Enable GitHub Actions output (step outputs)
waf-tester scan -u https://target.com --github-output

# Enable GitHub Actions step summary (Markdown report in workflow)
waf-tester scan -u https://target.com --github-summary

# Both outputs and summary
waf-tester scan -u https://target.com --github-output --github-summary

# Outputs available: bypass_count, blocked_count, total_tests, effectiveness, 
#                    critical_count, high_count, waf_vendor, scan_duration
```

Example GitHub Actions workflow:

```yaml
- name: WAF Security Scan
  id: waf-scan
  run: |
    waf-tester scan -u ${{ secrets.TARGET_URL }} \
      --hook-github \
      --hook-github-summary \
      -format sarif -o results.sarif

- name: Check Results
  run: |
    echo "Bypasses found: ${{ steps.waf-scan.outputs.bypass_count }}"
    echo "WAF effectiveness: ${{ steps.waf-scan.outputs.effectiveness }}%"
    if [ "${{ steps.waf-scan.outputs.bypass_count }}" -gt 0 ]; then
      echo "::warning::WAF bypasses detected!"
    fi
```

**GitHub Actions Step Summary (rendered in workflow run):**

```markdown
## 🛡️ WAF Security Scan Results

| Metric | Value |
|--------|-------|
| Target | https://target.com |
| Total Tests | 2,847 |
| Blocked | 2,728 (95.8%) |
| Bypassed | 119 (4.2%) |
| WAF Vendor | Cloudflare |
| Scan Duration | 45.2s |

### Critical Bypasses (5)

| Category | Payload | Severity |
|----------|---------|----------|
| SQL Injection | `1' UNION SELECT...` | 🔴 Critical |
| XSS | `<script>alert(1)</script>` | 🟠 High |
| Path Traversal | `../../../etc/passwd` | 🟠 High |

<details>
<summary>Full scan details</summary>
// Complete findings JSON
</details>
```

**GitHub Actions Output Variables:**

```bash
# These are set automatically when --hook-github is used
echo "bypass_count=119" >> $GITHUB_OUTPUT
echo "blocked_count=2728" >> $GITHUB_OUTPUT
echo "total_tests=2847" >> $GITHUB_OUTPUT
echo "effectiveness=95.8" >> $GITHUB_OUTPUT
echo "critical_count=5" >> $GITHUB_OUTPUT
echo "high_count=23" >> $GITHUB_OUTPUT
echo "waf_vendor=Cloudflare" >> $GITHUB_OUTPUT
echo "scan_duration=45.2" >> $GITHUB_OUTPUT
```

### OpenTelemetry Tracing (v2.5.0+)

Export scan telemetry to OpenTelemetry-compatible backends (Jaeger, Zipkin, Grafana Tempo, etc.).

```bash
# Send traces to OTLP collector
waf-tester scan -u https://target.com \
  --otel-endpoint=localhost:4317

# With insecure connection (no TLS)
waf-tester scan -u https://target.com \
  --otel-endpoint=otel-collector.monitoring:4317 \
  --otel-insecure

# Secure connection (default)
waf-tester scan -u https://target.com \
  --otel-endpoint=otel.example.com:4317
```

**Sample OpenTelemetry Trace (JSON export):**

```json
{
  "resourceSpans": [
    {
      "resource": {
        "attributes": [
          { "key": "service.name", "value": { "stringValue": "waf-tester" } },
          { "key": "service.version", "value": { "stringValue": "2.7.0" } }
        ]
      },
      "scopeSpans": [
        {
          "scope": { "name": "waftester.scan" },
          "spans": [
            {
              "traceId": "5b8aa5a2d2c872e8321cf37308d69df2",
              "spanId": "051581bf3cb55c13",
              "name": "waf-scan",
              "kind": "SPAN_KIND_INTERNAL",
              "startTimeUnixNano": "1706968200000000000",
              "endTimeUnixNano": "1706968245230000000",
              "attributes": [
                { "key": "waf.target", "value": { "stringValue": "https://target.com" } },
                { "key": "waf.vendor", "value": { "stringValue": "Cloudflare" } },
                { "key": "waf.total_tests", "value": { "intValue": "2847" } },
                { "key": "waf.bypasses", "value": { "intValue": "119" } },
                { "key": "waf.effectiveness", "value": { "doubleValue": 95.8 } }
              ],
              "events": [
                {
                  "name": "finding",
                  "timeUnixNano": "1706968212340000000",
                  "attributes": [
                    { "key": "waf.category", "value": { "stringValue": "sqli" } },
                    { "key": "waf.severity", "value": { "stringValue": "critical" } },
                    { "key": "waf.outcome", "value": { "stringValue": "bypass" } },
                    { "key": "waf.owasp", "value": { "stringValue": "A03:2021" } },
                    { "key": "waf.cwe", "value": { "intValue": "89" } },
                    { "key": "waf.payload", "value": { "stringValue": "1' UNION SELECT..." } }
                  ]
                }
              ],
              "status": { "code": "STATUS_CODE_OK" }
            }
          ]
        }
      ]
    }
  ]
}
```

OpenTelemetry attributes exported:

| Attribute | Description |
|-----------|-------------|
| `waf.target` | Target URL being scanned |
| `waf.category` | Attack category (sqli, xss, etc.) |
| `waf.severity` | Finding severity level |
| `waf.outcome` | Test outcome (blocked, bypass, error) |
| `waf.owasp` | OWASP Top 10 category |
| `waf.cwe` | CWE identifiers |

### Output File Locations

| Command | Default Output |
|---------|----------------|
| `discover` | `./discovery.json` |
| `learn` | `./testplan.json` |
| `auto` | `workspaces/<domain>/<timestamp>/` |
| Others | Stdout (use `-o` to save) |

### Auto Command Workspace Structure

```
workspaces/<domain>/<timestamp>/
├── discovery.json
├── testplan.json
├── results.json
├── results.html
├── results.sarif
├── results.pdf          # v2.5.0+
├── results.md           # v2.5.0+
└── results.xml          # v2.6.8+ (--xml-export)
```

---

## CI/CD Integration

**In this section:**
[GitHub Actions](#github-actions) · [GitLab CI](#gitlab-ci) · [Azure DevOps](#azure-devops) ·
[Jenkins](#jenkins-pipeline-v250) · [CircleCI](#circleci-v250) · [Drone CI](#drone-ci-v250) ·
[Tekton](#tekton-pipeline-v250) · [ArgoCD](#argocd-pre-sync-hook-v250) · [Harness CI](#harness-ci-v250) ·
[AWS CodePipeline](#aws-codepipeline-v250) · [Prometheus](#prometheus-metrics-integration-v250)

Use `--stream` flag to disable animated progress for clean CI logs.

### JSON Output for Automation

```bash
# JSON output from any command
waf-tester auto -u https://target.com --json
waf-tester scan -u https://target.com --json > results.json
waf-tester probe -u https://target.com --json | jq '.waf'
waf-tester assess -u https://target.com --json -o assessment.json
waf-tester vendor -u https://target.com --json
```

### Streaming JSON Mode (v2.5.0+)

Real-time NDJSON events for CI/CD pipelines:

```bash
# Stream events to stdout
waf-tester scan -u https://target.com -stream -json

# Filter specific events
waf-tester scan -u https://target.com -stream -json | jq 'select(.type=="result")'

# Filter bypasses only
waf-tester scan -u https://target.com -stream -json | jq 'select(.type=="bypass")'

# Save to file (stderr has progress, stdout has events)
waf-tester scan -u https://target.com -stream -json 2>/dev/null > scan-events.jsonl

# Real-time critical alert
waf-tester scan -u https://target.com -stream -json | \
  jq -c 'select(.severity=="Critical")' | \
  while read event; do curl -X POST $WEBHOOK -d "$event"; done
```

#### Event Types (v2.5.0)

| Event | Description | Key Fields |
|-------|-------------|------------|
| `start` | Scan beginning | `target`, `categories`, `timestamp` |
| `progress` | Periodic status update | `tested`, `total`, `percent`, `bypasses` |
| `result` | Test completed | `category`, `severity`, `blocked`, `payload` |
| `bypass` | WAF bypass found | `category`, `severity`, `payload`, `tampers`, `evidence` |
| `summary` | Category summary | `category`, `total`, `blocked`, `bypassed`, `effectiveness` |
| `complete` | Scan finished | `duration_ms`, `total_tests`, `total_bypasses`, `metrics` |
| `error` | Error occurred | `message`, `category`, `recoverable` |

#### Sample Streaming Events (v2.5.0)

```json
{"type":"start","timestamp":"2026-02-03T10:00:00Z","target":"https://target.com","categories":["sqli","xss","traversal"],"waf_vendor":"Cloudflare","waf_confidence":0.98}
{"type":"progress","timestamp":"2026-02-03T10:00:05Z","tested":250,"total":2847,"percent":8.8,"bypasses":3,"current_category":"sqli"}
{"type":"result","timestamp":"2026-02-03T10:00:06Z","id":"sqli-042","category":"sqli","severity":"Medium","blocked":true,"response_code":403,"response_time_ms":45}
{"type":"bypass","timestamp":"2026-02-03T10:00:12Z","id":"sqli-089","category":"sqli","severity":"Critical","payload":"1' UNION/**/SELECT/**/username,password/**/FROM/**/users--","tampers":["space2comment","charunicodeencode"],"url":"https://target.com/api/users?id=1","evidence":{"response_code":200,"response_time_ms":847,"indicators":["SQL syntax in response","5 rows returned vs 1 expected"]},"owasp":"A03:2021","cwe":[89]}
{"type":"summary","timestamp":"2026-02-03T10:00:30Z","category":"sqli","total":847,"blocked":805,"bypassed":42,"errors":0,"effectiveness":95.0}
{"type":"progress","timestamp":"2026-02-03T10:00:35Z","tested":1500,"total":2847,"percent":52.7,"bypasses":58,"current_category":"xss"}
{"type":"bypass","timestamp":"2026-02-03T10:00:42Z","id":"xss-156","category":"xss","severity":"High","payload":"<img src=x onerror=alert(1)>","url":"https://target.com/search?q=test","evidence":{"response_code":200,"reflected":true},"owasp":"A03:2021","cwe":[79]}
{"type":"summary","timestamp":"2026-02-03T10:00:55Z","category":"xss","total":623,"blocked":592,"bypassed":31,"errors":0,"effectiveness":95.0}
{"type":"complete","timestamp":"2026-02-03T10:01:00Z","duration_ms":60000,"total_tests":2847,"total_blocked":2728,"total_bypasses":119,"metrics":{"detection_rate":0.958,"false_positive_rate":0.003,"precision":0.997,"f1_score":0.969}}
```

#### Processing Streaming Events

```bash
# Count bypasses by severity
waf-tester scan -u $TARGET -stream -json | \
  jq -s '[.[] | select(.type=="bypass")] | group_by(.severity) | map({severity: .[0].severity, count: length})'

# Extract all bypass payloads
waf-tester scan -u $TARGET -stream -json | \
  jq -r 'select(.type=="bypass") | .payload' > bypasses.txt

# Real-time dashboard (with timestamped progress)
waf-tester scan -u $TARGET -stream -json | \
  jq -r 'select(.type=="progress") | "\(.timestamp) | \(.percent)% | \(.bypasses) bypasses"'

# Fail CI on any Critical bypass
waf-tester scan -u $TARGET -stream -json | \
  jq -e 'select(.type=="bypass" and .severity=="Critical") | halt_error(1)' || exit 1
```

### GitHub Actions

```yaml
- name: WAF Security Scan
  run: |
    waf-tester scan -u ${{ secrets.TARGET_URL }} \
      --stream \
      -types sqli,xss,traversal \
      -sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### GitHub Actions with Streaming JSON

```yaml
- name: WAF Security Scan (Streaming)
  run: |
    waf-tester scan -u ${{ secrets.TARGET_URL }} \
      -stream -json > scan-events.jsonl 2>&1
    
    # Count critical vulnerabilities
    CRITICAL=$(jq -s '[.[] | select(.type=="vulnerability" and .data.severity=="Critical")] | length' scan-events.jsonl)
    echo "Found $CRITICAL critical vulnerabilities"
    
    # Fail if critical vulns found
    if [ "$CRITICAL" -gt 0 ]; then
      exit 1
    fi
```

### GitLab CI

```yaml
waf_scan:
  script:
    - waf-tester assess -u $TARGET_URL --stream -format json -o report.json
  artifacts:
    reports:
      security: report.json
```

### Azure DevOps

```yaml
- task: Bash@3
  inputs:
    targetType: 'inline'
    script: |
      waf-tester scan -u $(TARGET_URL) --stream -sarif -o $(Build.ArtifactStagingDirectory)/security.sarif
```

### Commands Supporting --stream

All major commands support `--stream`: `assess`, `auto`, `bypass`, `crawl`, `fuzz`, `headless`, `mutate`, `probe`, `scan`, `smuggle`, `fp`

### Jenkins Pipeline (v2.5.0+)

```groovy
pipeline {
    agent any
    stages {
        stage('WAF Security Scan') {
            steps {
                sh '''
                    waf-tester scan -u ${TARGET_URL} \
                        --stream \
                        -format sarif \
                        -o results.sarif \
                        --slack-webhook=${SLACK_WEBHOOK}
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif'
                    recordIssues tool: sarif(pattern: 'results.sarif')
                }
            }
        }
    }
}
```

### CircleCI (v2.5.0+)

```yaml
version: 2.1
jobs:
  waf-scan:
    docker:
      - image: ghcr.io/waftester/waftester:latest
    steps:
      - run:
          name: WAF Security Scan
          command: |
            waf-tester scan -u $TARGET_URL \
              --stream \
              -format sarif \
              -o results.sarif
      - store_artifacts:
          path: results.sarif
      - run:
          name: Check for Critical Findings
          command: |
            CRITICAL=$(jq '.runs[].results | map(select(.level == "error")) | length' results.sarif)
            if [ "$CRITICAL" -gt 0 ]; then
              echo "Found $CRITICAL critical findings"
              exit 1
            fi
```

### Drone CI (v2.5.0+)

```yaml
kind: pipeline
type: docker
name: security-scan

steps:
  - name: waf-scan
    image: ghcr.io/waftester/waftester:latest
    commands:
      - waf-tester scan -u $TARGET_URL --stream -format json -o results.json
      - waf-tester scan -u $TARGET_URL --stream -format sarif -o results.sarif
    environment:
      TARGET_URL:
        from_secret: target_url
```

### Tekton Pipeline (v2.5.0+)

```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: waf-security-scan
spec:
  params:
    - name: target-url
      type: string
  steps:
    - name: scan
      image: ghcr.io/waftester/waftester:latest
      script: |
        waf-tester scan -u $(params.target-url) \
          --stream \
          -format sarif \
          -o /workspace/results.sarif \
          --slack-webhook=$SLACK_WEBHOOK
```

### ArgoCD Pre-Sync Hook (v2.5.0+)

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: waf-security-scan
  annotations:
    argocd.argoproj.io/hook: PreSync
spec:
  template:
    spec:
      containers:
        - name: waf-scan
          image: ghcr.io/waftester/waftester:latest
          command:
            - waf-tester
            - scan
            - -u
            - $(TARGET_URL)
            - --stream
            - -format
            - sarif
          env:
            - name: TARGET_URL
              valueFrom:
                secretKeyRef:
                  name: waf-scan-config
                  key: target-url
      restartPolicy: Never
```

### Harness CI (v2.5.0+)

```yaml
stages:
  - stage:
      name: Security Scan
      type: SecurityTests
      spec:
        execution:
          steps:
            - step:
                type: Run
                name: WAF Scan
                spec:
                  connectorRef: docker-hub
                  image: ghcr.io/waftester/waftester:latest
                  command: |
                    waf-tester scan -u $TARGET_URL \
                      --stream \
                      -format json \
                      -o results.json \
                      --hook-pagerduty=$PAGERDUTY_KEY
```

### AWS CodePipeline (v2.5.0+)

```yaml
version: 0.2
phases:
  install:
    runtime-versions:
      golang: 1.22
    commands:
      - go install github.com/waftester/waftester/cmd/cli@latest
  build:
    commands:
      - waf-tester scan -u $TARGET_URL --stream -format sarif -o results.sarif
      - waf-tester scan -u $TARGET_URL --stream -format json -o results.json
artifacts:
  files:
    - results.sarif
    - results.json
reports:
  security-report:
    files:
      - results.sarif
    file-format: SARIFEXPORT
```

### Prometheus Metrics Integration (v2.5.0+)

Expose real-time metrics for Prometheus scraping during scan execution.

```bash
# Enable Prometheus metrics endpoint during scan
waf-tester scan -u https://target.com --metrics-port=9090

# Default metrics path is /metrics
# Access at: http://localhost:9090/metrics
```

**Metrics Exposed:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `waftester_tests_total` | Counter | `target`, `category`, `severity`, `outcome` | Total tests executed |
| `waftester_bypasses_total` | Counter | `target`, `category`, `severity` | WAF bypasses detected |
| `waftester_blocked_total` | Counter | `target`, `category` | Requests blocked by WAF |
| `waftester_errors_total` | Counter | `target`, `category` | Test errors |
| `waftester_response_time_seconds` | Histogram | `target`, `category` | Response time distribution |
| `waftester_effectiveness_percent` | Gauge | `target` | WAF effectiveness score |
| `waftester_scan_duration_seconds` | Gauge | `target` | Total scan duration |

**Example Prometheus Config:**

```yaml
scrape_configs:
  - job_name: 'waftester'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 5s
```

**Example Grafana Queries:**

```promql
# Bypass rate over time
rate(waftester_bypasses_total[5m])

# WAF effectiveness
waftester_effectiveness_percent{target="https://example.com"}

# Response time 95th percentile
histogram_quantile(0.95, waftester_response_time_seconds_bucket)
```

---

## Advanced Options

**In this section:**
[Headers & Auth](#headers-and-authentication) · [Proxies](#proxies) · [Rate Limiting](#rate-limiting) ·
[Response Filtering](#response-filtering) · [Realistic Mode](#realistic-mode) ·
[Resume & Checkpoints](#resume-and-checkpoints) · [JA3 Rotation](#ja3-fingerprint-rotation) ·
[Silent Ban Detection](#connection-drop--silent-ban-detection-v252)

### Headers and Authentication

```bash
# Custom headers
waf-tester scan -u https://target.com -H "Authorization: Bearer TOKEN"
waf-tester scan -u https://target.com -H "X-API-Key: secret"

# Multiple headers
waf-tester scan -u https://target.com \
  -H "Authorization: Bearer TOKEN" \
  -H "X-Custom: value"

# Cookies
waf-tester scan -u https://target.com -cookie "session=abc123"
```

### Proxies

```bash
# HTTP proxy
waf-tester scan -u https://target.com -proxy http://127.0.0.1:8080

# HTTPS proxy
waf-tester scan -u https://target.com -proxy https://127.0.0.1:8080

# SOCKS4 proxy
waf-tester scan -u https://target.com -proxy socks4://127.0.0.1:1080

# SOCKS5 proxy
waf-tester scan -u https://target.com -proxy socks5://127.0.0.1:1080

# SOCKS5h proxy (DNS queries routed through proxy)
waf-tester scan -u https://target.com -proxy socks5h://127.0.0.1:1080

# Burp Suite shortcut (sets proxy to 127.0.0.1:8080)
waf-tester scan -u https://target.com --burp -k

# OWASP ZAP shortcut (sets proxy to 127.0.0.1:8081)
waf-tester scan -u https://target.com --zap -k

# Replay proxy (duplicate traffic to security tool while scanning)
waf-tester scan -u https://target.com --replay-proxy http://127.0.0.1:8080

# SNI override (bypass CDN to test origin directly)
waf-tester scan -u https://cdn.example.com --sni origin.example.com

# Combined: Proxy + SNI + Burp replay
waf-tester scan -u https://target.com \
  -proxy socks5://tor-proxy:9050 \
  --sni internal.target.com \
  --replay-proxy http://127.0.0.1:8080
```

### Rate Limiting

```bash
# Set rate limit
waf-tester scan -u https://target.com -rl 100  # 100 req/sec

# Set concurrency
waf-tester scan -u https://target.com -c 50  # 50 parallel workers

# Combined
waf-tester scan -u https://target.com -c 25 -rl 200

# With delay between requests
waf-tester discover -u https://target.com -delay 2s
```

### Response Filtering

#### Matchers (what to report)

```bash
# Match status codes
waf-tester run -u https://target.com -mc 200,403,500

# Match response size
waf-tester run -u https://target.com -ms 1234
```

#### Filters (what to hide)

```bash
# Filter status codes
waf-tester run -u https://target.com -fc 404,500

# Filter response size
waf-tester run -u https://target.com -fs 0

# Auto-calibrate (detect baseline responses)
waf-tester run -u https://target.com -ac
```

### Realistic Mode

Makes requests look like real browser traffic:

```bash
waf-tester run -u https://target.com -R
waf-tester run -u https://target.com --realistic
```

Features:
- Rotating User-Agents (Chrome, Firefox, Safari)
- Real browser headers (Accept, Accept-Language)
- Intelligent WAF block detection
- Multi-location injection

### Resume and Checkpoints

```bash
# Enable checkpoints
waf-tester scan -u https://target.com -checkpoint scan.checkpoint

# Resume from checkpoint
waf-tester scan -resume scan.checkpoint
```

### JA3 Fingerprint Rotation

Evade WAF detection by rotating TLS fingerprints:

```bash
# Enable JA3 rotation with random profiles
waf-tester auto -u https://target.com -ja3-rotate

# Use specific browser profile
waf-tester auto -u https://target.com -ja3-rotate -ja3-profile chrome120
waf-tester auto -u https://target.com -ja3-rotate -ja3-profile firefox121
```

#### Available JA3 Profiles

| Profile | Description |
|---------|-------------|
| `chrome120` | Chrome 120 TLS fingerprint |
| `firefox121` | Firefox 121 TLS fingerprint |
| `safari17` | Safari 17 TLS fingerprint |
| `edge120` | Edge 120 TLS fingerprint |

### Connection Drop & Silent Ban Detection (v2.5.2)

WAFtester automatically detects when targets are dropping connections or silently banning your IP:

```bash
# Detection is automatic - no flags needed
waf-tester scan -u https://target.com

# View detection stats in verbose mode
waf-tester scan -u https://target.com -v
```

#### Detection Types

**Connection Drops** (network-level):
| Type | Description |
|------|-------------|
| `tcp_reset` | Connection reset by peer (RST packet) |
| `tls_abort` | TLS/SSL handshake failure |
| `timeout` | No response within timeout |
| `eof` | Unexpected end of stream |
| `tarpit` | Response 3x slower than baseline |
| `refused` | Connection actively refused |
| `dns` | DNS resolution failure |

**Silent Bans** (behavioral):
| Type | Description |
|------|-------------|
| `rate_limit` | Rate limiting detected |
| `ip_block` | IP-based blocking |
| `behavioral` | Fingerprint-based blocking |
| `honeypot` | Redirected to honeypot |
| `geo_block` | Geographic blocking |

#### Detection in JSON Output

```bash
waf-tester scan -u https://target.com -format json | jq '.results[] | select(.drop_detected or .ban_detected)'
```

Output includes:
```json
{
  "drop_detected": true,
  "drop_type": "tcp_reset",
  "ban_detected": false,
  "ban_type": "",
  "ban_confidence": 0,
  "latency_drift": 1.5
}
```

#### Automatic Recovery

When drops are detected:
1. WAFtester waits with exponential backoff (5s → 10s → 20s → 30s max)
2. After 2 successful probes, the host is considered recovered
3. For high-confidence bans (≥80%), the host is marked as permanently failed

### Additional Options

```bash
# Skip TLS verification
waf-tester scan -u https://target.com -k
waf-tester scan -u https://target.com --skip-verify

# Set timeout
waf-tester scan -u https://target.com -timeout 10

# Set retries
waf-tester scan -u https://target.com -retries 3

# Verbose output
waf-tester scan -u https://target.com -v

# Silent mode
waf-tester scan -u https://target.com -s

# No color output
waf-tester scan -u https://target.com -nc

# Show statistics
waf-tester scan -u https://target.com --stats

# Non-interactive mode
waf-tester scan -u https://target.com -noninteractive

# Store responses
waf-tester scan -u https://target.com -sr -srd ./responses/

# Add timestamp to output
waf-tester scan -u https://target.com -ts

# Dry run (list tests without executing)
waf-tester run -u https://target.com -dry-run
```

---

## Browser Scanning

For applications requiring authentication (SSO, MFA, CAPTCHA):

```bash
# Opens browser for manual login
waf-tester auto -u https://app.example.com

# Headless mode (no visible browser)
waf-tester auto -u https://app.example.com -browser-headless

# Disable browser scanning
waf-tester auto -u https://app.example.com -browser=false

# Custom login timeout
waf-tester auto -u https://app.example.com -browser-timeout 5m
```

**Requirements**: Chrome or Chromium installed.

---

## Multiple Targets

```bash
# From file
waf-tester scan -l targets.txt

# Comma-separated
waf-tester scan -u https://site1.com,https://site2.com

# From stdin
cat urls.txt | waf-tester probe -stdin

# With concurrency
waf-tester scan -l targets.txt -c 100 -rl 500
```

---

## Utility Commands

### Enterprise Report Generation (report)

Generate comprehensive HTML reports from workspace results:

```bash
# Generate report from workspace
waf-tester report -workspace ./workspaces/example.com/2026-02-01_10-00-00

# With custom output file
waf-tester report -workspace ./workspace -output custom-report.html

# With custom target name
waf-tester report -workspace ./workspace -target "Production API"
```

### Update Payloads

```bash
waf-tester update
```

### Validate Payloads

```bash
# Validate payload files for schema errors
waf-tester validate

# Validate nuclei templates
waf-tester validate-templates
```

### List Tampers

```bash
waf-tester tampers --list
waf-tester tampers --category encoding
```

---

## API & Protocol Commands (v2.6.2)

New dedicated commands for API and protocol testing, providing deeper integration than the generic `scan -types` approach.

### Template Scanner (template)

Run Nuclei-compatible YAML templates for custom vulnerability detection.

```bash
# Scan with templates from a directory
waf-tester template -u https://target.com -t templates/

# Scan with a single template file
waf-tester template -u https://target.com -t sqli-detection.yaml

# Filter by severity
waf-tester template -u https://target.com -t templates/ --severity critical,high

# Filter by tags
waf-tester template -u https://target.com -t templates/ --tags waf,bypass

# Validate templates without running
waf-tester template -t templates/ --validate

# Multiple targets from file
waf-tester template -l targets.txt -t templates/ -o results.json
```

### gRPC Testing (grpc)

Test gRPC services using server reflection.

```bash
# List available services via reflection
waf-tester grpc -u localhost:50051 --list

# Describe a specific service
waf-tester grpc -u localhost:50051 --describe grpc.health.v1.Health

# Call a specific method
waf-tester grpc -u localhost:50051 --call myservice.MyMethod \
  -d '{"field": "value"}'

# Call with metadata headers
waf-tester grpc -u localhost:50051 --call myservice.MyMethod \
  -d '{"id": 1}' \
  --metadata "authorization:Bearer token123"

# Fuzz all methods with injection payloads
waf-tester grpc -u localhost:50051 --fuzz --category sqli

# Fuzz with specific category
waf-tester grpc -u localhost:50051 --fuzz --category xss -o grpc-results.json
```

### SOAP/WSDL Testing (soap)

Test SOAP services and parse WSDL definitions.

```bash
# List operations from WSDL
waf-tester soap --wsdl https://api.example.com/service?wsdl --list

# Call a specific operation
waf-tester soap -u https://api.example.com/service \
  --operation GetUser \
  -d '<GetUser><id>1</id></GetUser>'

# Fuzz SOAP service with XXE payloads
waf-tester soap -u https://api.example.com/service --fuzz --category xxe

# Fuzz with SQL injection payloads
waf-tester soap -u https://api.example.com/service --fuzz --category sqli

# Save results
waf-tester soap --wsdl https://api.example.com?wsdl --list -o wsdl-operations.json
```

### OpenAPI Fuzzing (openapi)

Security test APIs using their OpenAPI/Swagger specification.

```bash
# List all endpoints from spec
waf-tester openapi -spec openapi.yaml --list

# List from URL
waf-tester openapi --spec-url https://api.example.com/openapi.json --list

# Fuzz all endpoints
waf-tester openapi -spec openapi.yaml --fuzz -u https://api.example.com

# Fuzz with specific attack type
waf-tester openapi -spec openapi.yaml --fuzz --scan-type sqli

# Filter to specific path
waf-tester openapi -spec openapi.yaml --fuzz --path /api/users

# With authentication
waf-tester openapi -spec openapi.yaml --fuzz \
  --bearer "eyJhbGc..." \
  -u https://api.example.com

# With API key
waf-tester openapi -spec openapi.yaml --fuzz \
  --api-key "my-secret-key" \
  --api-key-header "X-API-Key"
```

### CI/CD Generator (cicd)

Generate CI/CD pipeline configurations for WAF testing.

```bash
# List supported platforms
waf-tester cicd --list

# Generate GitHub Actions workflow
waf-tester cicd -p github-actions -u https://target.com -o .github/workflows/waf-test.yml

# Generate GitLab CI
waf-tester cicd -p gitlab-ci -u '$TARGET_URL' -o gitlab-waf.yml

# Generate Jenkins pipeline
waf-tester cicd -p jenkins -u https://target.com

# With Slack notifications
waf-tester cicd -p github-actions -u https://target.com --slack

# Custom scanners and fail conditions
waf-tester cicd -p github-actions -u https://target.com \
  --scanners sqli,xss \
  --fail-high \
  --fail-medium
```

### Plugin Manager (plugin)

Manage custom scanner plugins.

```bash
# List installed plugins
waf-tester plugin --list

# Load a plugin
waf-tester plugin --load ./my-scanner.so

# Get plugin info
waf-tester plugin --info my-scanner

# Run a specific plugin
waf-tester plugin --run my-scanner -u https://target.com

# Run with custom config
waf-tester plugin --run my-scanner -u https://target.com \
  --config-json '{"depth": 3}'
```

### Cloud Discovery (cloud)

Discover cloud resources (S3, Azure Blob, GCP Storage, etc.).

```bash
# Discover cloud resources for a domain
waf-tester cloud -d example.com

# Specific providers only
waf-tester cloud -d example.com --providers aws,azure

# Specific resource types
waf-tester cloud -d example.com --types storage,cdn

# Organization-based discovery
waf-tester cloud --org mycompany --types storage

# Passive only (no active requests)
waf-tester cloud -d example.com --passive

# With custom wordlist
waf-tester cloud -d example.com -w buckets.txt

# Save results
waf-tester cloud -d example.com -o cloud-resources.json
```

---

## Troubleshooting

### Quick Diagnostic

Run this first when anything goes wrong:

```bash
# Health check — verify target is reachable
waf-tester probe -u https://target.com -v

# Connectivity test
curl -sI https://target.com | head -5

# Version check
waf-tester --version
```

### Common Errors Reference

| Error / Symptom | Cause | Solution | Affected Commands |
|----------------|-------|----------|-------------------|
| `connection refused` | Target unreachable | Check firewall, VPN, DNS. Test: `curl -I URL` | All |
| `0 endpoints found` | SPA without crawlable links | Add `--browser` for headless Chrome rendering | auto, discover |
| `SSL certificate error` | Self-signed or expired cert | Add `-k` to skip TLS verification | All |
| Scan stalls at ~10% | WAF rate limiting the scanner | Reduce: `-rl 20 -c 5 --smart` | scan, auto, bypass |
| `403 on all requests` | IP blocked or auth required | VPN/proxy, or add auth: `-H "Authorization: Bearer $TOKEN"` | All |
| `workspace already exists` | Previous scan same day | Use `-workspace-dir newname` | auto |
| `no WAF detected` | WAF in transparent mode | Try `vendor -u URL -v` for deeper analysis | vendor |
| `Too many open files` | OS file descriptor limit | Run: `ulimit -n 10240` (Linux/Mac) | scan with high `-c` |
| `context deadline exceeded` | Target too slow | Increase: `-timeout 30` | All |
| `DNS resolution failed` | DNS misconfiguration | Try: `-dns-resolver 8.8.8.8` | All |
| 0 findings, 100% blocked | Scanner IP is banned | Smart mode detects this. Use VPN/proxy | scan, bypass |
| Inconsistent metrics | Caching or WAF inconsistency | Add cache bust: `?nocache=rand`, increase `-retries 5` | assess, fp |

### Performance Tuning

| Symptom | Current Setting | Better Setting | Why |
|---------|----------------|----------------|-----|
| Scan too slow | `-c 25` (default) | `-c 100 -rl 500` | More parallelism with controlled rate |
| Target dropping connections | `-c 100` | `-c 10 -rl 20` | Less aggressive, respect WAF limits |
| High memory usage | Default buffering | `-c 25 --stream` | Stream results instead of buffering |
| Scan taking >30 min | `-types all` (50+ cats) | `-category sqli,xss,rce` | Focus on critical categories first |
| Results too noisy | No severity filter | `-msev critical,high` | Only actionable findings |
| False positive concerns | No FP testing | Add `-fp -corpus builtin` to assess | Quantify false positives |

### WAF-Specific Troubleshooting

| WAF Vendor | Common Issue | Solution |
|------------|-------------|----------|
| **Cloudflare** | JS challenge blocks all requests | `--browser` or `--smart` (auto-handles challenges) |
| **Cloudflare** | Under Attack Mode enabled | Wait 5s or use `--browser -browser-timeout 10` |
| **AWS WAF** | Rate limiting at 100 req/s | `-rl 50 -c 10` to stay under limit |
| **AWS WAF** | Custom rules blocking scanner UA | `-H "User-Agent: Mozilla/5.0..."` |
| **Akamai** | Bot Manager triggered | `--realistic -ja3-rotate` for browser-like behavior |
| **Imperva** | CAPTCHA on repeated requests | `--browser` with manual CAPTCHA solve at start |
| **ModSecurity** | Paranoia level 4 blocks everything | Expected — use `--tamper-profile=aggressive` for bypass testing |
| **Azure WAF** | Custom rules with geo-blocking | Test from allowed region or add `X-Forwarded-For` |
| **F5 BIG-IP** | ASM session-based blocking | `--browser` to maintain session state |
| **Fortinet FortiWeb** | IP reputation blocking | Use fresh IP or proxy chain |

---

## Attack Categories Reference

### Full Category List

| Category | Description |
|----------|-------------|
| `sqli` | SQL injection |
| `xss` | Cross-site scripting |
| `traversal` | Path traversal (LFI) |
| `cmdi` | Command injection |
| `nosqli` | NoSQL injection |
| `ssrf` | Server-side request forgery |
| `ssti` | Server-side template injection |
| `xxe` | XML external entity |
| `ldapi` | LDAP injection |
| `xpath` | XPath injection |
| `crlf` | CRLF injection |
| `rfi` | Remote file inclusion |
| `rce` | Remote code execution |
| `deserialize` | Insecure deserialization |
| `prototype` | Prototype pollution |
| `smuggling` | HTTP request smuggling |
| `cors` | CORS misconfiguration |
| `oauth` | OAuth vulnerabilities |
| `jwt` | JWT attacks |
| `redirect` | Open redirect |
| `hostheader` | Host header injection |
| `cache` | Cache poisoning |
| `upload` | File upload vulnerabilities |
| `bizlogic` | Business logic flaws |
| `race` | Race conditions |
| `idor` | Insecure direct object reference |
| `csrf` | Cross-site request forgery |
| `clickjack` | Clickjacking |
| `websocket` | WebSocket vulnerabilities |
| `graphql` | GraphQL attacks |
| `grpc` | gRPC attacks |
| `soap` | SOAP/XML attacks |
| `ssi` | Server-side includes |
| `hpp` | HTTP parameter pollution |
| `massassign` | Mass assignment |
| `sensitivedata` | Sensitive data exposure |
| `brokenauth` | Broken authentication |
| `securitymisconfig` | Security misconfiguration |
| `accesscontrol` | Broken access control |
| `cryptofailure` | Cryptographic failures |

### Category Aliases

```bash
waf-tester scan -u https://target.com -types injection  # sqli, nosqli, cmdi, ldapi, xpath
waf-tester scan -u https://target.com -types all        # All categories
```

---

## Real-World Playbooks

Complete end-to-end walkthroughs for the most common assessment scenarios. Each playbook includes the full command sequence, expected output summary, and what to do with results.

> **Playbook Selection:**
> | Your Situation | Best Playbook |
> |---------------|---------------|
> | First time assessing a WAF | [Playbook 1: New Client](#playbook-1-new-client--first-waf-assessment) |
> | Adding to CI/CD pipeline | [Playbook 2: CI/CD Pipeline](#playbook-2-cicd-pipeline--block-deploys-on-waf-regression) |
> | Evaluating WAF vendors | [Playbook 3: Vendor Comparison](#playbook-3-waf-vendor-comparison--cloudflare-vs-aws-waf) |
> | Testing WordPress/CMS | [Playbook 4: WordPress](#playbook-4-wordpress-site-behind-waf) |
> | API security testing | [Playbook 5: API-First App](#playbook-5-api-first-application-graphql--rest) |
> | After WAF rule changes | [Playbook 6: Post-Incident](#playbook-6-post-incident--verify-waf-rule-fix) |
> | Bug bounty target | [Playbook 7: Bug Bounty](#playbook-7-bug-bounty--quick-waf-bypass-discovery) |
> | Ongoing monitoring | [Playbook 8: Production Monitoring](#playbook-8-production-monitoring--continuous-waf-health) |
> | Compliance audit | [Playbook 9: Compliance Audit](#playbook-9-compliance-audit--pci-dss--soc-2) |
> | Multi-region/CDN | [Playbook 10: Multi-Region](#playbook-10-multi-region--multi-cdn-assessment) |

---

### Playbook 1: New Client — First WAF Assessment

**Scenario:** You've been hired to assess a client's WAF. You have a target URL and written authorization. You need to deliver a report within 2 hours.

**Time budget:** 90 minutes active + 30 minutes reporting

| Phase | Time | Command | What You Get |
|-------|------|---------|--------------|
| **1. Recon** | 5 min | `waf-tester vendor -u $TARGET -v` | WAF type, confidence score, bypass hints |
| **2. Discovery** | 10 min | `waf-tester discover -u $TARGET --browser` | Endpoints, parameters, JavaScript APIs |
| **3. Assessment** | 30 min | `waf-tester assess -u $TARGET -fp -corpus builtin --smart -format json -o assessment.json` | TPR, FPR, F1 Score, MCC |
| **4. Bypass Hunt** | 30 min | `waf-tester bypass -u $TARGET --smart --tamper-auto -category sqli,xss,rce -format json -o bypasses.json` | Confirmed bypass payloads |
| **5. Evidence** | 15 min | `waf-tester scan -u $TARGET --smart -ie -ir -format html -o report.html` | Client-facing HTML report |

**Deliverables checklist:**
- [ ] `report.html` — Executive HTML report with severity ratings and remediation advice
- [ ] `assessment.json` — Machine-readable metrics for baseline tracking
- [ ] `bypasses.json` — Confirmed bypass payloads (for WAF rule improvement)
- [ ] Key metrics: Overall WAF effectiveness %, top 3 bypassed categories, FPR

**What to tell the client:**
> "Your WAF shows a {TPR}% detection rate with {FPR}% false positive rate (F1: {F1}).
> We found {N} confirmed bypasses, primarily in {categories}. See attached report
> for remediation priorities."

---

### Playbook 2: CI/CD Pipeline — Block Deploys on WAF Regression

**Scenario:** Engineering team deploys weekly. New code shouldn't reduce WAF effectiveness. Need a pipeline stage that fails on critical bypasses.

**GitHub Actions:**

```yaml
# .github/workflows/waf-test.yml
name: WAF Security Gate
on:
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am

jobs:
  waf-test:
    runs-on: ubuntu-latest
    steps:
      - name: Install WAFtester
        run: |
          curl -sSL https://get.waftester.com | sh
          waf-tester --version

      - name: WAF Assessment
        run: |
          waf-tester scan -u ${{ secrets.STAGING_URL }} \
            -category sqli,xss,rce \
            --smart --stream \
            -msev critical,high \
            -format sarif -o results.sarif \
            -format json -o results.json

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Quality Gate — Block on Critical Bypasses
        run: |
          CRITICAL=$(jq '[.results[] | select(.severity == "critical")] | length' results.json)
          HIGH=$(jq '[.results[] | select(.severity == "high")] | length' results.json)
          echo "::notice::Critical: $CRITICAL, High: $HIGH"
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::❌ $CRITICAL critical WAF bypasses — deployment blocked"
            exit 1
          fi
          echo "✅ No critical WAF bypasses found"
```

**GitLab CI:**

```yaml
# .gitlab-ci.yml
waf-security-gate:
  stage: security
  image: waftester/waftester:latest
  script:
    - waf-tester scan -u $STAGING_URL
        -category sqli,xss,rce
        --smart --stream
        -format json -o results.json
    - |
      CRITICAL=$(jq '[.results[] | select(.severity == "critical")] | length' results.json)
      if [ "$CRITICAL" -gt 0 ]; then exit 1; fi
  artifacts:
    reports:
      sast: results.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

**Expected outcome:** PRs with WAF regressions show a red check. SARIF results appear in GitHub Security tab.

---

### Playbook 3: WAF Vendor Comparison — Cloudflare vs AWS WAF

**Scenario:** Evaluating two WAF vendors. Need objective metrics for leadership decision.

```bash
#!/bin/bash
# vendor-comparison.sh — Run this with: bash vendor-comparison.sh

TARGETS=("https://cf-protected.example.com" "https://aws-protected.example.com")
LABELS=("Cloudflare" "AWS_WAF")

for i in "${!TARGETS[@]}"; do
  echo "=== Testing ${LABELS[$i]} ==="
  waf-tester assess -u "${TARGETS[$i]}" \
    -fp -corpus "builtin,leipzig" \
    --smart \
    -format json -o "${LABELS[$i],,}-results.json"
done

# Side-by-side comparison
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           WAF VENDOR COMPARISON REPORT               ║"
echo "╠══════════════════════════════════════════════════════╣"
for i in "${!LABELS[@]}"; do
  echo "║ ${LABELS[$i]}:"
  jq -r '"║   Detection Rate: \(.metrics.tpr)%\n║   False Positive:  \(.metrics.fpr)%\n║   F1 Score:        \(.metrics.f1)\n║   MCC:             \(.metrics.mcc)"' "${LABELS[$i],,}-results.json"
  echo "║"
done
echo "╚══════════════════════════════════════════════════════╝"
```

**What to present to leadership:**

| Metric | Target | Cloudflare | AWS WAF | Winner |
|--------|--------|-----------|---------|--------|
| Detection Rate (TPR) | >90% | {from output} | {from output} | Highest |
| False Positive Rate | <1% | {from output} | {from output} | Lowest |
| F1 Score | >0.90 | {from output} | {from output} | Highest |
| MCC | >0.80 | {from output} | {from output} | Highest |

---

### Playbook 4: WordPress Site Behind WAF

**Scenario:** Client has a WordPress site behind a WAF. Need to test WordPress-specific attacks and measure WAF coverage.

```bash
# Step 1: Identify WAF
waf-tester vendor -u https://myblog.com -v

# Step 2: WordPress-optimized assessment
# -service wordpress enables: WP-specific paths, plugin vulns, xmlrpc, wp-admin
waf-tester auto -u https://myblog.com \
  -service wordpress \
  --smart \
  --browser \
  -format html,json \
  -o ./wordpress-audit

# Step 3: Focus on WP-specific attack paths
waf-tester scan -u https://myblog.com \
  -category sqli,xss,traversal,rce,upload \
  --smart \
  -ip "wp-admin|wp-content|wp-includes|xmlrpc|wp-login" \
  -format json -o wp-specific.json

# Step 4: Test file upload bypass (critical for WP)
waf-tester scan -u https://myblog.com \
  -category upload \
  --smart --tamper-auto \
  -format json -o upload-bypass.json
```

**Key findings to look for:**
- `xmlrpc.php` accessible (brute force vector)
- `wp-admin` path traversal
- Plugin upload bypass
- Theme editor code injection
- REST API information disclosure

---

### Playbook 5: API-First Application (GraphQL + REST)

**Scenario:** Modern application with GraphQL API and REST endpoints. Need to test both protocol types.

```bash
# Step 1: Detect protocols
waf-tester protocol -u https://api.example.com

# Step 2: GraphQL-specific testing
waf-tester scan -u https://api.example.com/graphql \
  -types graphql \
  -H "Authorization: Bearer $TOKEN" \
  --smart \
  -format json -o graphql-results.json

# Step 3: REST API testing
waf-tester scan -u https://api.example.com \
  -category sqli,nosqli,ssrf,jwt,idor \
  -H "Authorization: Bearer $TOKEN" \
  --smart \
  -format json -o rest-results.json

# Step 4: JavaScript analysis (find hidden endpoints)
waf-tester analyze -u https://app.example.com -endpoints -secrets

# Step 5: OpenAPI spec fuzzing (if available)
waf-tester openapi -u https://api.example.com/openapi.json \
  --fuzz \
  -H "Authorization: Bearer $TOKEN" \
  -format json -o openapi-fuzz.json
```

**GraphQL-specific checks:**
- Introspection enabled? (information disclosure)
- Query depth limits? (DoS via nested queries)
- Batch query abuse?
- Field-level authorization gaps?

---

### Playbook 6: Post-Incident — Verify WAF Rule Fix

**Scenario:** WAF bypass was discovered in production. Team deployed rule fix. Need to verify the fix works without introducing false positives.

```bash
# BEFORE fix: capture baseline (you should already have this)
# waf-tester assess -u https://target.com -fp -corpus builtin -format json -o before-fix.json

# AFTER fix: run identical assessment
waf-tester assess -u https://target.com \
  -fp -corpus builtin \
  -format json -o after-fix.json

# Compare metrics
echo "=== BEFORE FIX ==="
jq '{tpr: .metrics.tpr, fpr: .metrics.fpr, f1: .metrics.f1}' before-fix.json

echo "=== AFTER FIX ==="
jq '{tpr: .metrics.tpr, fpr: .metrics.fpr, f1: .metrics.f1}' after-fix.json

# Specifically verify the reported bypass is now blocked
waf-tester scan -u https://target.com \
  -category sqli \
  -ip "/api/login" \
  --smart \
  -format json -o fix-verification.json

# Check false positives didn't increase
jq '.metrics.fpr' after-fix.json  # Should be <= before-fix FPR
```

**Verification criteria:**
- [ ] Specific bypass payload is now blocked
- [ ] Overall detection rate increased or stayed same
- [ ] False positive rate didn't increase
- [ ] No new categories with decreased detection

---

### Playbook 7: Bug Bounty — Quick WAF Bypass Discovery

**Scenario:** You have a bug bounty target. Time is limited. Need to find WAF bypasses quickly and document proof.

```bash
# Step 1: Quick vendor check (15 seconds)
waf-tester vendor -u $TARGET -q
# Output: "Cloudflare (94%)" — now you know what you're fighting

# Step 2: Full auto with smart mode (5-15 minutes)
waf-tester auto -u $TARGET \
  --smart \
  -c 50 -rl 100 \
  -format json -o quick-results.json

# Step 3: Focus on high-value bypasses
waf-tester bypass -u $TARGET \
  --smart --tamper-auto \
  -category sqli,xss,rce,ssrf \
  -msev critical,high \
  -format json -o bypasses.json

# Step 4: If bypasses found, generate evidence
BYPASSES=$(jq '[.results[] | select(.bypassed == true)] | length' bypasses.json)
if [ "$BYPASSES" -gt 0 ]; then
  echo "🎯 $BYPASSES bypasses found! Generating evidence..."
  waf-tester scan -u $TARGET \
    --smart \
    -ie -ir \
    -format html -o bug-bounty-report.html
fi

# Step 5: JavaScript analysis for bonus findings
waf-tester analyze -u $TARGET -secrets -endpoints
```

**Writing the bug bounty report:**
1. WAF vendor + version detected
2. Bypass payload (from `bypasses.json`)
3. HTTP request/response evidence (from `-ie -ir` flags)
4. Impact assessment (what the bypass enables)
5. Remediation recommendation

---

### Playbook 8: Production Monitoring — Continuous WAF Health

**Scenario:** Run scheduled WAF health checks and alert on degradation.

```bash
#!/bin/bash
# waf-health-check.sh — Run via cron: 0 */6 * * * /path/to/waf-health-check.sh

TARGET="https://production.example.com"
THRESHOLD_TPR=90
THRESHOLD_FPR=2
SLACK_WEBHOOK="$SLACK_WEBHOOK_URL"

# Run assessment
waf-tester assess -u $TARGET \
  -fp -corpus builtin \
  --smart -rl 20 \
  --history-path=/var/lib/waftester/history \
  --history-tags="production,scheduled" \
  -format json -o /tmp/waf-health.json 2>/dev/null

# Extract metrics
TPR=$(jq '.metrics.tpr' /tmp/waf-health.json)
FPR=$(jq '.metrics.fpr' /tmp/waf-health.json)
F1=$(jq '.metrics.f1' /tmp/waf-health.json)

# Alert on degradation
if (( $(echo "$TPR < $THRESHOLD_TPR" | bc -l) )); then
  curl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \
    -d "{\"text\":\"🚨 WAF Alert: Detection rate dropped to ${TPR}% (threshold: ${THRESHOLD_TPR}%)\"}"
fi

if (( $(echo "$FPR > $THRESHOLD_FPR" | bc -l) )); then
  curl -X POST "$SLACK_WEBHOOK" -H 'Content-type: application/json' \
    -d "{\"text\":\"⚠️ WAF Alert: False positive rate is ${FPR}% (threshold: ${THRESHOLD_FPR}%)\"}"
fi

echo "[$(date)] TPR=${TPR}% FPR=${FPR}% F1=${F1}" >> /var/log/waf-health.log
```

**Historical Trend Tracking (v2.6.8+):**

With `--history-path` enabled, scan results are automatically stored for trend analysis:

```bash
# View detection rate trend over time
waf-tester history trend \
  --history-path=/var/lib/waftester/history \
  --target=https://production.example.com

# Compare latest scan against previous baseline
waf-tester history compare \
  --history-path=/var/lib/waftester/history \
  --base=last-2 --compare=last-1
```

**Prometheus + Grafana integration:**

```bash
# Start with metrics endpoint
waf-tester assess -u $TARGET --metrics-port=9090

# In prometheus.yml:
# scrape_configs:
#   - job_name: 'waftester'
#     static_configs:
#       - targets: ['localhost:9090']
```

---

### Playbook 9: Compliance Audit — PCI DSS / SOC 2

**Scenario:** Auditor needs evidence that WAF is properly configured. Need quantitative metrics and formal report.

```bash
# Step 1: Full assessment with all corpora
waf-tester assess -u https://payment.example.com \
  -fp -corpus "builtin,leipzig" \
  --smart \
  -categories sqli,xss,traversal,rce,xxe,ssrf,cmdi \
  -format json,pdf,html \
  -o ./compliance-audit

# Step 2: Specific PCI DSS requirement validation
# Req 6.6: WAF in front of public-facing web applications
waf-tester vendor -u https://payment.example.com -output compliance-audit/waf-verification.json

# Step 3: False positive validation (business impact)
waf-tester fp -u https://payment.example.com \
  -corpus builtin,leipzig \
  -format json -o compliance-audit/false-positives.json

# Step 4: Generate compliance summary
echo "=== PCI DSS WAF Compliance Summary ==="
echo "Requirement 6.6 - Web Application Firewall:"
echo "  WAF Present: $(jq -r '.vendor' compliance-audit/waf-verification.json)"
echo "  Detection Rate: $(jq '.metrics.tpr' compliance-audit/assessment.json)%"
echo "  False Positive Rate: $(jq '.metrics.fpr' compliance-audit/false-positives.json)%"
echo "  OWASP Top 10 Coverage: $(jq '.metrics.owasp_coverage' compliance-audit/assessment.json)%"
```

**Auditor deliverables:**
- [ ] WAF vendor verification (JSON + PDF)
- [ ] Detection rate per OWASP Top 10 category
- [ ] False positive rate with benign traffic evidence
- [ ] Historical trend (if running Playbook 8)

---

### Playbook 10: Multi-Region / Multi-CDN Assessment

**Scenario:** Application deployed across multiple regions with different CDN/WAF configurations. Need to verify consistent protection.

```bash
#!/bin/bash
# multi-region-test.sh

declare -A REGIONS=(
  ["us-east"]="https://us-east.example.com"
  ["eu-west"]="https://eu-west.example.com"
  ["ap-south"]="https://ap-south.example.com"
)

for region in "${!REGIONS[@]}"; do
  echo "=== Testing $region ==="

  # WAF vendor check (may differ per region)
  waf-tester vendor -u "${REGIONS[$region]}" -output "${region}-vendor.json"

  # Full assessment
  waf-tester assess -u "${REGIONS[$region]}" \
    -fp -corpus builtin \
    --smart \
    -format json -o "${region}-results.json"
done

# Compare regions
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           MULTI-REGION COMPARISON                    ║"
echo "╠══════════════════════════════════════════════════════╣"
for region in "${!REGIONS[@]}"; do
  TPR=$(jq '.metrics.tpr' "${region}-results.json")
  FPR=$(jq '.metrics.fpr' "${region}-results.json")
  WAF=$(jq -r '.vendor' "${region}-vendor.json")
  echo "║ $region: WAF=$WAF TPR=${TPR}% FPR=${FPR}%"
done
echo "╚══════════════════════════════════════════════════════╝"
```

**Red flags to watch for:**
- Different WAF vendors per region (configuration drift)
- Significant TPR variance (>5% between regions)
- Higher FPR in specific regions (locale-specific rules)

---

## MCP Server Integration

WAFtester v2.7.0 includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server that enables AI agents and automation platforms to control WAFtester through a structured, typed interface.

### Stdio Mode (IDE)

Use stdio transport for IDE integrations where the editor manages the process lifecycle.

```bash
# Start MCP server in stdio mode (default)
waf-tester mcp

# With custom payload directory
waf-tester mcp --payload-dir /path/to/payloads
```

Supported IDEs:
- **VS Code** with GitHub Copilot or Cline
- **Claude Desktop** (see [configuration below](#claude-desktop-setup))
- **Cursor** with MCP support enabled

### HTTP Mode (Remote)

Use HTTP transport for remote deployments, Docker containers, and browser-based clients.

```bash
# Start HTTP server on port 8080
waf-tester mcp --http :8080

# Custom bind address
waf-tester mcp --http 0.0.0.0:9090
```

The HTTP server exposes three endpoints:

| Endpoint | Protocol | Use Case |
|----------|----------|----------|
| `/mcp` | Streamable HTTP | Modern MCP clients (2025-03-26 spec) |
| `/sse` | Server-Sent Events | n8n, older MCP clients (2024-11-05 spec) |
| `/health` | GET | Container readiness/liveness probes |

All endpoints include CORS headers for cross-origin requests.

#### Health Check

```bash
$ curl http://localhost:8080/health
{"status":"ok","service":"waf-tester-mcp"}
```

### Claude Desktop Setup

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "waf-tester",
      "args": ["mcp"],
      "env": {
        "WAF_PAYLOAD_DIR": "/path/to/payloads"
      }
    }
  }
}
```

Then ask Claude:

> "Detect what WAF is protecting https://example.com, then run a security scan focusing on SQL injection and XSS"

Claude will automatically call `detect_waf` followed by `scan` with the appropriate parameters, showing progress notifications as the scan runs.

### n8n Workflow Automation

n8n's MCP Client node connects to WAFtester's SSE endpoint for automated security workflows.

#### Setup

1. Start the MCP server in HTTP mode:

```bash
waf-tester mcp --http :8080
```

2. In n8n, add an **MCP Client** node:
   - **Transport**: SSE Endpoint
   - **URL**: `http://your-server:8080/sse`
   - **Authentication**: Bearer Token (if configured)

3. Connect to an **AI Agent** node (Claude, GPT, etc.)

4. All 10 WAFtester tools appear automatically for the AI agent

#### Example n8n Workflow

```
Trigger (Schedule/Webhook)
  → AI Agent (Claude)
    → MCP Client (waf-tester @ /sse)
      → detect_waf → scan → assess
    → Slack Notification (results summary)
```

The AI agent orchestrates the full workflow: WAF detection, targeted scanning based on the detected vendor, enterprise assessment, and notification delivery.

#### n8n with Authentication

```bash
# Start with bearer token auth
waf-tester mcp --http :8080 --auth-token $MCP_TOKEN
```

In n8n MCP Client node, set authentication to **Header Auth** with:
- **Header Name**: `Authorization`
- **Header Value**: `Bearer your-token-here`

### Docker Deployment

```dockerfile
FROM ghcr.io/waftester/waftester:latest

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["waf-tester", "mcp", "--http", ":8080"]
```

#### Docker Compose with n8n

```yaml
services:
  waf-tester-mcp:
    image: ghcr.io/waftester/waftester:latest
    command: ["mcp", "--http", ":8080"]
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
    volumes:
      - ./payloads:/payloads

  n8n:
    image: n8nio/n8n
    ports:
      - "5678:5678"
    environment:
      - N8N_AI_ENABLED=true
    depends_on:
      waf-tester-mcp:
        condition: service_healthy
```

Connect n8n to `http://waf-tester-mcp:8080/sse` using Docker's internal network.

#### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-tester-mcp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: waf-tester-mcp
  template:
    metadata:
      labels:
        app: waf-tester-mcp
    spec:
      containers:
        - name: waf-tester-mcp
          image: ghcr.io/waftester/waftester:latest
          args: ["mcp", "--http", ":8080"]
          ports:
            - containerPort: 8080
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: waf-tester-mcp
spec:
  selector:
    app: waf-tester-mcp
  ports:
    - port: 8080
      targetPort: 8080
```

### MCP Resources and Prompts

#### Reading Resources

AI agents can access domain knowledge resources without making network requests:

```
# In a conversation with Claude/GPT via MCP:

"Read the WAF testing guide"
→ Agent reads waftester://guide (comprehensive methodology)

"What evasion techniques are available?"
→ Agent reads waftester://evasion-techniques (encoders + evasion catalog)

"Show WAF signatures for Cloudflare"
→ Agent reads waftester://waf-signatures (vendor signatures + bypass tips)

"What OWASP categories does SQL injection map to?"
→ Agent reads waftester://owasp-mappings (OWASP Top 10 2021 mappings)
```

#### Using Prompt Templates

Prompt templates provide guided workflows that the AI agent follows step-by-step:

```
# Full security audit workflow
Prompt: security_audit
Args: target=https://example.com

# Targeted WAF bypass hunting
Prompt: waf_bypass
Args: target=https://example.com, category=sqli, stealth=true

# Enterprise assessment with metrics
Prompt: full_assessment
Args: target=https://example.com

# Attack surface discovery
Prompt: discovery_workflow
Args: target=https://example.com, service_type=webapp

# Evasion research for a specific payload
Prompt: evasion_research
Args: target=https://example.com, payload=<script>alert(1)</script>
```

#### Tool Chaining Patterns

The MCP server instructions guide AI agents through optimal tool chains:

```
# Workflow A: Full Security Assessment (Recommended)
detect_waf → discover → learn → scan → assess

# Workflow B: Quick WAF Bypass Hunt
detect_waf → scan → mutate → bypass

# Workflow C: WAF Effectiveness Audit
detect_waf → assess → (review grade, F1, FPR, recommendations)

# Workflow D: CI/CD Pipeline Generation
detect_waf → generate_cicd (with WAF-specific thresholds)
```

---

## Getting Help

```bash
# General help
waf-tester -h

# Command-specific help
waf-tester <command> -h

# Detailed documentation
waf-tester docs

# Topic-specific docs
waf-tester docs discover
waf-tester docs mutation
waf-tester docs categories
```

---

*For more information, see the [README](../README.md) and [CHANGELOG](../CHANGELOG.md).*
