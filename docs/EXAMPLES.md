# 🎯 WAF-Tester Examples Guide

> **The Complete Guide to WAF Testing** — From beginner to expert, every command explained.

This guide shows you every way to use WAF-Tester with real examples. Each example explains **what it does** and **when to use it**.

---

## 📖 Table of Contents

1. [Quick Start (5 minutes)](#-quick-start-5-minutes)
2. [The Smart Workflow (Recommended)](#-the-smart-workflow-recommended)
3. [Full Automated Scan (auto)](#-full-automated-scan-auto)
4. [Enterprise Assessment (assess)](#-enterprise-assessment-assess)
5. [Deep Vulnerability Scanning (scan)](#-deep-vulnerability-scanning-scan)
6. [WAF Detection (vendor)](#-waf-detection-vendor)
7. [WAF Bypass Hunting (bypass)](#-waf-bypass-hunting-bypass)
8. [Mutation Testing (mutate)](#-mutation-testing-mutate)
9. [False Positive Testing (fp)](#-false-positive-testing-fp)
10. [Content Fuzzing (fuzz)](#-content-fuzzing-fuzz)
11. [Protocol Probing (probe)](#-protocol-probing-probe)
12. [Web Crawling (crawl)](#-web-crawling-crawl)
13. [JavaScript Analysis (analyze)](#-javascript-analysis-analyze)
14. [Protocol Detection (protocol)](#-protocol-detection-protocol)
15. [Target Discovery (discover)](#-target-discovery-discover)
16. [Test Plan Generation (learn)](#-test-plan-generation-learn)
17. [Running Tests (run)](#-running-tests-run)
18. [Payload Management](#-payload-management)
19. [Output Formats](#-output-formats)
20. [Working with Multiple Targets](#-working-with-multiple-targets)
21. [Using Proxies](#-using-proxies)
22. [Smart Mode (WAF-Aware Testing)](#-smart-mode-waf-aware-testing)
23. [CI/CD Pipeline Integration](#-cicd-pipeline-integration)
24. [Real-World Scenarios](#-real-world-scenarios)

---

## 🚀 Quick Start (5 minutes)

### Your First Scan

```bash
# The simplest scan - just point at a target
waf-tester scan -u https://example.com
```

**What this does:** Scans the website for common vulnerabilities (SQL injection, XSS, etc.)

### The "I Want Everything" Command

```bash
# Full automated scan - discovers, plans, tests, and reports
waf-tester auto -u https://example.com
```

**What this does:** 
1. 🕵️ Discovers all endpoints (pages, forms, APIs)
2. 📝 Creates a smart test plan
3. 🎯 Tests for vulnerabilities
4. 📊 Generates a report

---

## 🧠 The Smart Workflow (Recommended)

This 3-step workflow is the **professional way** to test a website.

### Step 1: Discover the Target

```bash
# Find all pages, forms, and APIs
waf-tester discover -u https://example.com
```

**Output:** Creates `discovery.json` with all found endpoints.

**Why do this first?** You can't test what you can't see. Discovery finds hidden pages, API endpoints, and forms.

### Step 2: Learn and Plan

```bash
# Create a smart test plan based on what was found
waf-tester learn -discovery discovery.json
```

**Output:** Creates `testplan.json` with prioritized tests.

**Why do this?** Instead of blindly testing everything, this creates a targeted plan. Login pages get auth attacks, search pages get SQL injection tests, etc.

### Step 3: Run the Tests

```bash
# Execute the test plan
waf-tester run -plan testplan.json
```

**Why do this?** Runs exactly the right tests for each endpoint, in the right order.

### Complete Workflow Example

```bash
# Professional WAF assessment in 3 commands
waf-tester discover -u https://target.com -output disco.json
waf-tester learn -discovery disco.json -output plan.json
waf-tester run -plan plan.json -format html -o report.html
```

---

## 🚀 Full Automated Scan (auto)

The `auto` command does **everything** in one shot.

### Basic Auto Scan

```bash
waf-tester auto -u https://example.com
```

### With Smart WAF Detection

```bash
# Detects WAF vendor and optimizes attacks
waf-tester auto -u https://example.com --smart
```

**What --smart does:**
- Identifies the WAF (Cloudflare, AWS, Imperva, etc.)
- Adjusts attack speed to avoid rate limiting
- Prioritizes bypass techniques that work against that WAF

### Full Power Mode

```bash
# Maximum coverage with all features enabled
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=full \
  -c 100 \
  -rl 300 \
  --browser
```

**Options explained:**
| Option | What it does |
|--------|--------------|
| `--smart` | Enable WAF-aware testing |
| `--smart-mode=full` | Use all bypass techniques |
| `-c 100` | Use 100 parallel workers (faster) |
| `-rl 300` | 300 requests per second |
| `--browser` | Use real browser for authenticated scanning |

### Auto Scan for Specific Services

```bash
# For WordPress sites
waf-tester auto -u https://myblog.com -service wordpress

# For Django applications
waf-tester auto -u https://myapp.com -service django
```

**Available services:** `wordpress`, `drupal`, `nextjs`, `flask`, `django`

### Stealth Mode (Avoid Detection)

```bash
# Low and slow - avoid WAF detection
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=stealth \
  -c 5 \
  -rl 10
```

---

## 🏢 Enterprise Assessment (assess)

Professional WAF assessment with metrics that security teams understand.

### Basic Assessment

```bash
waf-tester assess -u https://example.com
```

### Full Assessment with False Positive Testing

```bash
waf-tester assess -u https://example.com \
  -fp \
  -corpus "builtin,leipzig"
```

**What this measures:**
- **Precision:** How many blocked requests were actually attacks?
- **Recall (F1):** How many attacks were blocked?
- **False Positive Rate:** How many normal requests were blocked?
- **MCC Score:** Overall WAF quality score

### Assessment for Specific Attack Types

```bash
# Test only SQL injection and XSS
waf-tester assess -u https://example.com \
  -categories "sqli,xss"
```

### Save Assessment Report

```bash
waf-tester assess -u https://example.com \
  -format json \
  -o assessment-report.json
```

---

## 🔍 Deep Vulnerability Scanning (scan)

The `scan` command does deep vulnerability testing.

### Basic Vulnerability Scan

```bash
waf-tester scan -u https://example.com
```

### Scan for Specific Vulnerabilities

```bash
# Only SQL injection
waf-tester scan -u https://example.com -types sqli

# SQL injection and XSS
waf-tester scan -u https://example.com -types sqli,xss

# Everything except fuzz testing
waf-tester scan -u https://example.com -exclude-types apifuzz
```

**Available scan types:**
| Category | Types |
|----------|-------|
| **Injection** | `sqli`, `nosqli`, `cmdi`, `ssti`, `xxe` |
| **Client-Side** | `xss`, `cors`, `redirect`, `prototype` |
| **File/Path** | `traversal`, `upload`, `smuggling` |
| **Auth/Session** | `oauth`, `jwt`, `bizlogic`, `race` |
| **API** | `graphql`, `apifuzz`, `websocket` |
| **Recon** | `wafdetect`, `waffprint`, `techdetect`, `osint` |

### Scan with Custom Headers

```bash
# Add authentication header
waf-tester scan -u https://api.example.com \
  -header "Authorization: Bearer eyJhbGc..."

# Multiple headers
waf-tester scan -u https://api.example.com \
  -header "Authorization: Bearer token123" \
  -cookie "session=abc123"
```

### Scan with Smart Mode

```bash
waf-tester scan -u https://example.com \
  --smart \
  --smart-mode=bypass \
  -types sqli,xss
```

### Save Scan Results

```bash
# JSON format
waf-tester scan -u https://example.com -json -output results.json

# HTML report
waf-tester scan -u https://example.com -html > report.html

# SARIF for CI/CD
waf-tester scan -u https://example.com -sarif -output results.sarif
```

### Speed Control

```bash
# Fast scan (be careful with WAFs!)
waf-tester scan -u https://example.com -concurrency 20 -rate-limit 100

# Slow scan (stealth mode)
waf-tester scan -u https://example.com -concurrency 2 -delay 1s
```

---

## 🎭 WAF Detection (vendor)

Identify what WAF is protecting a target.

### Detect WAF

```bash
waf-tester vendor -u https://example.com
```

**Output shows:**
- WAF vendor name (Cloudflare, AWS, Imperva, etc.)
- Confidence level
- Bypass hints

### Get Bypass Hints

```bash
waf-tester vendor -u https://example.com -hints
```

### List All Supported WAFs

```bash
waf-tester vendor -list
```

**Supports 197+ WAF vendors** including:
- Cloud: Cloudflare, AWS WAF, Azure WAF, GCP Cloud Armor
- Enterprise: Imperva, F5 BIG-IP, Fortinet, Barracuda
- Open Source: ModSecurity, NAXSI

### Save Detection Results

```bash
waf-tester vendor -u https://example.com -output waf-detection.json
```

---

## 🔓 WAF Bypass Hunting (bypass)

Find ways to bypass the WAF.

### Basic Bypass Hunt

```bash
waf-tester bypass -u https://example.com
```

### Hunt for SQL Injection Bypasses

```bash
waf-tester bypass -u https://example.com -category injection
```

### Smart Bypass Mode

```bash
# Let the tool auto-detect WAF and use known bypasses
waf-tester bypass -u https://example.com \
  --smart \
  --smart-mode=bypass
```

### Save Discovered Bypasses

```bash
waf-tester bypass -u https://example.com \
  -o bypasses.json
```

### With Realistic Mode

```bash
# Use browser-like requests to evade detection
waf-tester bypass -u https://example.com -R
```

---

## 🧬 Mutation Testing (mutate)

Test every encoding, location, and evasion combination.

### Show Available Mutations

```bash
waf-tester mutate -stats
```

### Basic Mutation Test

```bash
waf-tester mutate -u https://example.com/search?q=FUZZ
```

### Test a Single Payload with All Mutations

```bash
# Test <script>alert(1)</script> with all encodings
waf-tester mutate -u https://example.com \
  -payload "<script>alert(1)</script>"
```

### Mutation Modes

```bash
# Quick - fast overview (10 mutations)
waf-tester mutate -u https://example.com -mode quick

# Standard - good coverage (100+ mutations)
waf-tester mutate -u https://example.com -mode standard

# Full - exhaustive testing (1000+ mutations)
waf-tester mutate -u https://example.com -mode full

# Bypass - focus on bypass techniques
waf-tester mutate -u https://example.com -mode bypass
```

### Specific Encoders

```bash
waf-tester mutate -u https://example.com \
  -encoders "url,double_url,html_hex,unicode"
```

**Available encoders:**
- `url` - URL encoding (%3C → <)
- `double_url` - Double URL encoding (%253C → <)
- `html_hex` - HTML hex encoding (&#x3C; → <)
- `unicode` - Unicode encoding
- `base64` - Base64 encoding
- `utf7` - UTF-7 encoding

### Specific Evasions

```bash
waf-tester mutate -u https://example.com \
  -evasions "case_swap,sql_comment,space_replace"
```

**Available evasions:**
- `case_swap` - SeLeCt instead of SELECT
- `sql_comment` - SEL/**/ECT
- `space_replace` - SELECT%09FROM (tab instead of space)
- `null_byte` - SELECT%00FROM

### Test All Injection Points

```bash
waf-tester mutate -u https://example.com \
  -locations "query_param,post_json,header,cookie"
```

### Chain Mutations Together

```bash
# Apply encoding THEN evasion
waf-tester mutate -u https://example.com \
  -chain \
  -max-chain 3
```

---

## ✅ False Positive Testing (fp)

Test if the WAF blocks normal, harmless traffic.

### Basic FP Test

```bash
waf-tester fp -u https://example.com
```

### Test with Different Corpus Types

```bash
# All corpus types
waf-tester fp -u https://example.com -corpus all

# Only Leipzig corpus (real German text)
waf-tester fp -u https://example.com -corpus leipzig

# API-style requests
waf-tester fp -u https://example.com -corpus api

# Form submissions
waf-tester fp -u https://example.com -corpus forms

# Edge cases (special characters, Unicode)
waf-tester fp -u https://example.com -corpus edge
```

### Test Against Paranoia Levels (CRS)

```bash
# Test paranoia level 2 (default)
waf-tester fp -u https://example.com -pl 2

# Test paranoia level 4 (strictest)
waf-tester fp -u https://example.com -pl 4
```

### Local WAF Simulation

```bash
# Test without a real target (validates your WAF rules)
waf-tester fp -local
```

---

## 🔎 Content Fuzzing (fuzz)

Like `ffuf` but integrated with WAF testing.

### Basic Directory Fuzzing

```bash
waf-tester fuzz -u https://example.com/FUZZ \
  -w /path/to/wordlist.txt
```

### Use Built-in Wordlists

```bash
# Directory fuzzing
waf-tester fuzz -u https://example.com/FUZZ -wt directories

# File fuzzing
waf-tester fuzz -u https://example.com/FUZZ -wt files

# Parameter fuzzing
waf-tester fuzz -u https://example.com/api?FUZZ=test -wt parameters
```

### Fuzz with Extensions

```bash
# Try each word with .php, .html, .txt
waf-tester fuzz -u https://example.com/FUZZ \
  -w wordlist.txt \
  -e php,html,txt
```

### Filter Results

```bash
# Only show 200 and 403 responses
waf-tester fuzz -u https://example.com/FUZZ -mc 200,403

# Hide 404 responses
waf-tester fuzz -u https://example.com/FUZZ -fc 404

# Filter by response size
waf-tester fuzz -u https://example.com/FUZZ -fs 1234
```

### POST Data Fuzzing

```bash
waf-tester fuzz -u https://example.com/login \
  -X POST \
  -d "username=admin&password=FUZZ" \
  -w passwords.txt
```

### Header Fuzzing

```bash
waf-tester fuzz -u https://example.com \
  -H "X-Custom-Header: FUZZ" \
  -w wordlist.txt
```

### Auto-Calibrate (Automatic Filtering)

```bash
# Automatically detect and filter baseline responses
waf-tester fuzz -u https://example.com/FUZZ -ac
```

### Recursive Fuzzing

```bash
# When you find a directory, fuzz inside it too
waf-tester fuzz -u https://example.com/FUZZ \
  -recursion \
  -recursion-depth 3
```

### Save Responses

```bash
# Store all responses
waf-tester fuzz -u https://example.com/FUZZ \
  -sr \
  -srd ./responses

# Store only matching responses
waf-tester fuzz -u https://example.com/FUZZ \
  -sr \
  -som
```

---

## 🌐 Protocol Probing (probe)

Comprehensive HTTP probing (like httpx).

### Basic Probe

```bash
waf-tester probe -u https://example.com
```

### Probe Multiple Targets

```bash
# From command line
waf-tester probe -u "site1.com,site2.com,site3.com"

# From file
waf-tester probe -l targets.txt

# From stdin
cat targets.txt | waf-tester probe -stdin
```

### Show Specific Information

```bash
# Show title and status
waf-tester probe -u https://example.com -title

# Show IP and ASN
waf-tester probe -u https://example.com -ip -asn

# Show technologies
waf-tester probe -u https://example.com -td

# Show WAF/CDN
waf-tester probe -u https://example.com -cdn
```

### Filter Results

```bash
# Only show 200 OK responses
waf-tester probe -l targets.txt -mc 200

# Filter out errors
waf-tester probe -l targets.txt -fc 404,500,502,503
```

### Screenshot Capture

```bash
waf-tester probe -u https://example.com -ss
```

### Tech Detection

```bash
# Detect frameworks, CMS, servers
waf-tester probe -u https://example.com -tech
```

### TLS Information

```bash
waf-tester probe -u https://example.com -tls -jarm
```

---

## 🕷️ Web Crawling (crawl)

Discover pages and content.

### Basic Crawl

```bash
waf-tester crawl -u https://example.com
```

### Control Crawl Depth

```bash
# Shallow crawl (homepage + 1 level)
waf-tester crawl -u https://example.com -depth 1

# Deep crawl
waf-tester crawl -u https://example.com -depth 5
```

### Extract Specific Content

```bash
# Extract all forms
waf-tester crawl -u https://example.com -forms

# Extract emails
waf-tester crawl -u https://example.com -emails

# Extract API endpoints
waf-tester crawl -u https://example.com -endpoints

# Extract secrets/credentials
waf-tester crawl -u https://example.com -secrets
```

### Stay Within Scope

```bash
# Only crawl same domain
waf-tester crawl -u https://example.com -same-domain

# Include subdomains
waf-tester crawl -u https://example.com -subdomains
```

### JavaScript Rendering

```bash
# Use headless browser to render JavaScript
waf-tester crawl -u https://example.com -js
```

### Save Crawl Results

```bash
waf-tester crawl -u https://example.com -output crawl-results.json
```

---

## 📜 JavaScript Analysis (analyze)

Extract secrets and endpoints from JavaScript.

### Basic Analysis

```bash
waf-tester analyze -u https://example.com
```

### Analyze Local File

```bash
waf-tester analyze -file /path/to/app.js
```

### What It Finds

```bash
# Find API endpoints
waf-tester analyze -u https://example.com -endpoints

# Find secrets (API keys, tokens)
waf-tester analyze -u https://example.com -secrets

# Find DOM XSS sinks
waf-tester analyze -u https://example.com -sinks
```

### Output as JSON

```bash
waf-tester analyze -u https://example.com -json -output js-analysis.json
```

---

## 🔌 Protocol Detection (protocol)

Detect enterprise protocols (gRPC, SOAP, GraphQL, WCF).

### Detect Protocol

```bash
waf-tester protocol -u https://api.example.com
```

**Detects:**
- gRPC endpoints
- SOAP web services
- GraphQL APIs
- WCF services
- REST APIs

---

## 🔎 Target Discovery (discover)

Find endpoints before testing.

### Basic Discovery

```bash
waf-tester discover -u https://example.com
```

### Discovery Sources

The discover command checks:
- `robots.txt` - hidden paths
- `sitemap.xml` - all pages
- JavaScript files - API endpoints
- Wayback Machine - historical URLs
- HTML forms - login pages, search forms

### Discovery for Specific Services

```bash
# WordPress - checks wp-admin, wp-content, etc.
waf-tester discover -u https://blog.example.com -service wordpress

# Django - checks admin, api, static, etc.
waf-tester discover -u https://app.example.com -service django
```

### Control Discovery

```bash
waf-tester discover -u https://example.com \
  -depth 3 \
  -concurrency 20 \
  -output my-discovery.json
```

---

## 📋 Test Plan Generation (learn)

Create smart test plans.

### Generate Test Plan

```bash
waf-tester learn -discovery discovery.json
```

### What the Plan Contains

The test plan prioritizes tests:
- **P1 (Critical):** Auth endpoints → Auth attacks
- **P2 (High):** Search forms → SQL injection
- **P3 (Medium):** File uploads → Upload attacks
- **P4 (Low):** General pages → XSS
- **P5 (Info):** Everything else → Fuzzing

### Custom Output

```bash
waf-tester learn \
  -discovery discovery.json \
  -output my-testplan.json \
  -custom-payloads custom-payloads.json
```

---

## ▶️ Running Tests (run)

Execute WAF tests.

### Run with Test Plan

```bash
waf-tester run -plan testplan.json
```

### Run Against Target Directly

```bash
waf-tester run -u https://example.com
```

### Filter Tests

```bash
# Only XSS tests
waf-tester run -u https://example.com -category xss

# Only critical/high severity
waf-tester run -u https://example.com -severity High
```

### Mutation Testing

```bash
# Quick mutations
waf-tester run -u https://example.com -m quick

# Full mutation matrix
waf-tester run -u https://example.com -m full

# Specific encoders
waf-tester run -u https://example.com \
  -encoders "url,double_url" \
  -evasions "case_swap"
```

### Filter/Match Results

```bash
# Only show blocked requests (403)
waf-tester run -u https://example.com -mc 403

# Only show successful bypasses (200)
waf-tester run -u https://example.com -mc 200

# Hide server errors
waf-tester run -u https://example.com -fc 500,502,503
```

### Realistic Mode

```bash
# Browser-like requests, smart block detection
waf-tester run -u https://example.com -R
```

### Speed Control

```bash
# Fast testing
waf-tester run -u https://example.com -c 100 -rl 500

# Slow/stealth testing
waf-tester run -u https://example.com -c 5 -rl 10
```

### Save Results

```bash
# JSON Lines (for processing)
waf-tester run -u https://example.com -j -o results.jsonl

# HTML report
waf-tester run -u https://example.com -format html -o report.html

# SARIF (for GitHub/CI)
waf-tester run -u https://example.com -format sarif -o results.sarif
```

### Dry Run (Preview)

```bash
# See what tests would run without executing
waf-tester run -u https://example.com -dry-run
```

---

## 📦 Payload Management

### Validate Payloads

```bash
# Check all payload files for errors
waf-tester validate

# Check specific directory
waf-tester validate -payloads ./my-payloads
```

### Update Payloads

```bash
# Preview updates
waf-tester update -dry-run

# Apply updates
waf-tester update -auto-apply
```

### Validate Templates

```bash
# Check nuclei YAML templates
waf-tester validate-templates
```

---

## 📊 Output Formats

### Console (Default)

```bash
waf-tester scan -u https://example.com
```

### JSON

```bash
waf-tester scan -u https://example.com -json -output results.json
```

### JSON Lines (JSONL)

```bash
# One JSON object per line - great for streaming
waf-tester scan -u https://example.com -jsonl -output results.jsonl
```

### HTML Report

```bash
waf-tester scan -u https://example.com -html > report.html
# or
waf-tester scan -u https://example.com -format html -output report.html
```

### CSV

```bash
waf-tester scan -u https://example.com -csv > results.csv
```

### Markdown

```bash
waf-tester scan -u https://example.com -md > report.md
```

### SARIF (For CI/CD)

```bash
# GitHub Actions, Azure DevOps, etc.
waf-tester scan -u https://example.com -sarif -output results.sarif
```

---

## 📋 Working with Multiple Targets

### Command Line

```bash
# Comma-separated
waf-tester scan -u "site1.com,site2.com,site3.com"

# Repeated flag
waf-tester scan -u site1.com -u site2.com -u site3.com
```

### From File

```bash
# Create targets.txt:
# https://site1.com
# https://site2.com
# https://site3.com

waf-tester scan -l targets.txt
```

### From Stdin (Piping)

```bash
# From cat
cat targets.txt | waf-tester scan -stdin

# From other tools
subfinder -d example.com | waf-tester probe -stdin
```

---

## 🌐 Using Proxies

### HTTP Proxy

```bash
waf-tester scan -u https://example.com -proxy http://127.0.0.1:8080
```

### SOCKS5 Proxy

```bash
waf-tester scan -u https://example.com -proxy socks5://127.0.0.1:1080
```

### Burp Suite Integration

```bash
# Send all requests through Burp
waf-tester scan -u https://example.com -proxy http://127.0.0.1:8080 -k
```

The `-k` flag skips TLS verification (needed for Burp's certificate).

---

## 🧠 Smart Mode (WAF-Aware Testing)

Smart mode automatically detects the WAF and optimizes testing.

### Enable Smart Mode

```bash
waf-tester scan -u https://example.com --smart
```

### Smart Mode Types

```bash
# Quick - fast detection, minimal evasion
waf-tester scan -u https://example.com --smart --smart-mode=quick

# Standard - balanced approach (default)
waf-tester scan -u https://example.com --smart --smart-mode=standard

# Full - maximum evasion techniques
waf-tester scan -u https://example.com --smart --smart-mode=full

# Bypass - focus on finding bypasses
waf-tester scan -u https://example.com --smart --smart-mode=bypass

# Stealth - avoid detection
waf-tester scan -u https://example.com --smart --smart-mode=stealth
```

### See What Smart Mode Detects

```bash
waf-tester scan -u https://example.com --smart --smart-verbose
```

---

## 🔄 CI/CD Pipeline Integration

The `--stream` flag enables clean output for CI/CD pipelines by disabling animated progress bars and ANSI escape codes.

### GitHub Actions

```yaml
# .github/workflows/security.yml
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

All major commands support `--stream` for CI-friendly output:

| Command | Stream Support |
|---------|----------------|
| `assess` | ✅ Full LiveProgress + ExecutionManifest |
| `auto` | ✅ Skips JS analysis and param discovery progress |
| `bypass` | ✅ Full LiveProgress with metrics |
| `crawl` | ✅ Skips crawl progress animation |
| `fuzz` | ✅ Skips ffuf-style progress |
| `headless` | ✅ Full LiveProgress |
| `mutate` | ✅ Skips bypass hunting animation |
| `probe` | ✅ Uses existing `-s`/`--stream` flag |
| `scan` | ✅ Skips deep scan progress |
| `smuggle` | ✅ Full LiveProgress |
| `fp` | ✅ Streaming false positive testing |

### Best Practice

```bash
# Always use --stream in CI, combine with structured output
waf-tester assess -u https://app.example.com \
  --stream \
  -format json \
  -o assessment.json

# Parse results
cat assessment.json | jq '.metrics.f1_score'
```

---

## 🎯 Real-World Scenarios

### Scenario 1: Bug Bounty Quick Check

```bash
# Fast check for common vulnerabilities
waf-tester auto -u https://target.com --smart -c 50 -rl 100
```

### Scenario 2: Penetration Test Assessment

```bash
# Full professional assessment
waf-tester auto -u https://client-site.com \
  --smart \
  --smart-mode=full \
  --browser \
  -output-dir ./pentest-results
```

### Scenario 3: WAF Validation (Blue Team)

```bash
# Test if your WAF is working
waf-tester assess -u https://your-app.com \
  -fp \
  -corpus "builtin,leipzig" \
  -o waf-assessment.json
```

### Scenario 4: Find WAF Bypasses

```bash
# Hunt for bypasses
waf-tester bypass -u https://target.com \
  --smart \
  --smart-mode=bypass \
  -category injection \
  -o bypasses.json
```

### Scenario 5: CI/CD Security Check

```bash
# In your pipeline - use --stream for clean logs without ANSI escape codes
waf-tester scan -u https://staging.app.com \
  -types sqli,xss,traversal \
  --stream \
  -match-severity critical,high \
  -sarif -o security-results.sarif

# All major commands support --stream for CI:
# assess, auto, bypass, crawl, fuzz, headless, mutate, probe, scan, smuggle, fp
```

### Scenario 6: API Security Testing

```bash
# Test API endpoints
waf-tester scan -u https://api.example.com \
  -types sqli,nosqli,ssrf,jwt \
  -header "Authorization: Bearer $TOKEN" \
  -json -o api-security.json
```

### Scenario 7: WordPress Security Audit

```bash
waf-tester auto -u https://myblog.com \
  -service wordpress \
  --smart \
  -format html -o wordpress-audit.html
```

### Scenario 8: Test Through Burp Suite

```bash
# See all requests in Burp
waf-tester scan -u https://target.com \
  -proxy http://127.0.0.1:8080 \
  -k \
  -c 5 \
  -rl 10
```

### Scenario 9: Stealthy Reconnaissance

```bash
# Low and slow - avoid detection
waf-tester probe -l targets.txt \
  -c 2 \
  -delay 2s \
  -random-agent \
  -o recon.json
```

### Scenario 10: Find Hidden Content

```bash
# Comprehensive fuzzing
waf-tester fuzz -u https://example.com/FUZZ \
  -wt directories \
  -e php,html,txt,bak \
  -recursion \
  -ac \
  -o fuzz-results.json
```

---

## 💡 Tips and Tricks

### 1. Always Start with Discovery

```bash
waf-tester discover -u https://target.com
```

### 2. Use Smart Mode for Better Results

```bash
waf-tester auto -u https://target.com --smart
```

### 3. Save Everything

```bash
waf-tester scan -u https://target.com \
  -sr -srd ./responses \
  -json -o results.json
```

### 4. Use Dry Run First

```bash
waf-tester run -u https://target.com -dry-run
```

### 5. Control Your Speed

```bash
# Aggressive: -c 100 -rl 500
# Normal:    -c 25 -rl 150
# Stealth:   -c 5 -rl 10
```

### 6. Check for False Positives

```bash
waf-tester fp -u https://target.com
```

---

## 🆘 Getting Help

### Command Help

```bash
waf-tester --help
waf-tester scan -h
waf-tester auto -h
```

### Version

```bash
waf-tester -version
```

---

## 📚 Quick Reference Card

| Task | Command |
|------|---------|
| Full auto scan | `waf-tester auto -u URL --smart` |
| Detect WAF | `waf-tester vendor -u URL` |
| Vulnerability scan | `waf-tester scan -u URL` |
| Find bypasses | `waf-tester bypass -u URL --smart` |
| Test false positives | `waf-tester fp -u URL` |
| Fuzz directories | `waf-tester fuzz -u URL/FUZZ -wt directories` |
| Crawl website | `waf-tester crawl -u URL -depth 3` |
| Analyze JavaScript | `waf-tester analyze -u URL` |
| Probe targets | `waf-tester probe -l targets.txt` |
| Enterprise assessment | `waf-tester assess -u URL -fp` |

---

**Made with ❤️ by the WAFtester team**

*For more information, visit [waftester.com](https://waftester.com)*
