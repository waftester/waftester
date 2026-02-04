# WAFtester Examples Guide

Complete usage examples for WAFtester commands and features.

## Table of Contents

- [Quick Start](#quick-start)
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
  - [Discovery and Planning](#discovery-and-planning)
  - [Test Execution (run)](#test-execution-run)
  - [Workflow Orchestration](#workflow-orchestration)
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
- [Output Formats](#output-formats)
  - [HTML Reports with Themes](#html-reports-with-themes-v250)
  - [Markdown with Enhanced Features](#markdown-with-enhanced-features-v250)
  - [Colorized Console Output](#colorized-console-output-v250)
  - [Custom Templates](#custom-templates-v250)
  - [PDF Reports](#pdf-reports-v250)
  - [Enterprise Integrations](#enterprise-integrations-v250)
  - [JUnit XML Reports](#junit-xml-reports-v250)
  - [CycloneDX VEX Reports](#cyclonedx-vex-reports-v250)
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
  - [Enterprise Report Generation](#enterprise-report-generation-report)
- [API & Protocol Commands (v2.6.2)](#api--protocol-commands-v262)
  - [Template Scanner (template)](#template-scanner-template)
  - [gRPC Testing (grpc)](#grpc-testing-grpc)
  - [SOAP/WSDL Testing (soap)](#soapwsdl-testing-soap)
  - [OpenAPI Fuzzing (openapi)](#openapi-fuzzing-openapi)
  - [CI/CD Generator (cicd)](#cicd-generator-cicd)
  - [Plugin Manager (plugin)](#plugin-manager-plugin)
  - [Cloud Discovery (cloud)](#cloud-discovery-cloud)
- [Attack Categories Reference](#attack-categories-reference)
- [Real-World Scenarios](#real-world-scenarios)

---

## Quick Start

### One Command

```bash
waf-tester auto -u https://example.com
```

This discovers endpoints, generates a test plan, runs tests, and creates reports.

### Three-Step Workflow

```bash
# 1. Discover endpoints
waf-tester discover -u https://example.com

# 2. Generate test plan
waf-tester learn -discovery discovery.json

# 3. Run tests
waf-tester run -plan testplan.json -format html -o report.html
```

---

## Core Commands

### Automated Scanning (auto)

Full automated workflow: discover → analyze JS → learn → run → report.

#### Basic Usage

```bash
waf-tester auto -u https://example.com
```

#### With Smart Mode

Smart mode detects the WAF vendor and optimizes testing:

```bash
waf-tester auto -u https://example.com --smart
```

#### With Automatic Tamper Selection (v2.4.2+)

```bash
# Auto-select optimal tampers based on detected WAF
waf-tester auto -u https://example.com --smart --tamper-auto

# Use specific tamper profile
waf-tester auto -u https://example.com --tamper-profile=aggressive

# Combine manual tampers with auto-selection
waf-tester auto -u https://example.com --tamper=nullbyte --tamper-auto
```

#### Full Options

```bash
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=full \
  --tamper-auto \
  -c 100 \
  -rl 300 \
  --browser
```

| Option | Description |
|--------|-------------|
| `--smart` | Enable WAF-aware testing |
| `--smart-mode=MODE` | Optimization level: `quick`, `standard`, `full`, `bypass`, `stealth` |
| `--tamper=LIST` | Comma-separated tampers to apply (v2.4.2+) |
| `--tamper-auto` | Auto-select tampers based on WAF (v2.4.2+) |
| `--tamper-profile=PROFILE` | Use preset: stealth, standard, aggressive, bypass (v2.4.2+) |
| `-c N` | Parallel workers (default: 25) |
| `-rl N` | Requests per second (default: 150) |
| `--browser` | Enable authenticated browser scanning |

#### Service-Specific Scanning

```bash
waf-tester auto -u https://myblog.com -service wordpress
waf-tester auto -u https://myapp.com -service django
waf-tester auto -u https://store.com -service nextjs
```

Available services: `wordpress`, `drupal`, `nextjs`, `flask`, `django`, `rails`, `laravel`, `spring`

#### Stealth Mode

Low and slow scanning to avoid detection:

```bash
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=stealth \
  -c 5 \
  -rl 10
```

---

### Enterprise Assessment (assess)

Professional WAF assessment with quantitative metrics.

#### Basic Assessment

```bash
waf-tester assess -u https://example.com
```

#### Full Assessment with Output

```bash
waf-tester assess -u https://example.com \
  -fp \
  -corpus "builtin,leipzig" \
  -format json \
  -o assessment.json
```

#### Metrics Produced

| Metric | Description |
|--------|-------------|
| **Detection Rate (TPR)** | Percentage of attacks blocked |
| **False Positive Rate (FPR)** | Percentage of legitimate traffic blocked |
| **Precision** | Percentage of blocks that were real attacks |
| **Recall** | Percentage of real attacks that were blocked |
| **F1 Score** | Harmonic mean of precision and recall |
| **MCC** | Matthews Correlation Coefficient |

#### Custom Categories

```bash
waf-tester assess -u https://example.com \
  -categories sqli,xss,rce \
  -o assessment.json
```

#### With Streaming Output for CI

```bash
waf-tester assess -u https://example.com --stream -format json -o report.json
```

---

### Vulnerability Scanning (scan)

Deep vulnerability scanning with 50+ attack categories.

#### Basic Scan

```bash
waf-tester scan -u https://target.com
```

#### With Smart Mode and Tampers (v2.4.2+)

```bash
# Smart mode with auto-tamper selection
waf-tester scan -u https://target.com --smart --tamper-auto

# Specific tampers for known WAF
waf-tester scan -u https://target.com --tamper=space2comment,randomcase

# Aggressive tamper profile
waf-tester scan -u https://target.com --tamper-profile=aggressive

# Stealth profile for low detection risk
waf-tester scan -u https://target.com --tamper-profile=stealth
```

#### Specific Categories

```bash
waf-tester scan -u https://target.com -category sqli,xss,traversal
waf-tester scan -u https://target.com -types sqli,xss,traversal  # alias
```

#### Multiple Targets

```bash
waf-tester scan -l targets.txt -c 50
```

#### All Available Categories

```bash
waf-tester scan -u https://target.com -types all
```

See [Attack Categories Reference](#attack-categories-reference) for full list.

#### Severity Filtering

```bash
# Match only critical and high severity findings
waf-tester scan -u https://target.com -msev critical,high

# Filter out low severity
waf-tester scan -u https://target.com -fsev low

# Match specific category
waf-tester scan -u https://target.com -mcat sqli,xss

# Filter specific category
waf-tester scan -u https://target.com -fcat info
```

#### OAuth Testing

```bash
# Scan OAuth endpoints
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

#### Scope Control

```bash
# Exclude scan types
waf-tester scan -u https://target.com -et info,techdetect

# Exclude URL patterns
waf-tester scan -u https://target.com -ep "logout|signout"

# Include only matching patterns
waf-tester scan -u https://target.com -ip "api/v2"
```

---

### WAF Detection (vendor)

Detect WAF vendor from 197+ signatures.

#### Detect WAF Vendor

```bash
waf-tester vendor -u https://target.com
```

#### JSON Output

```bash
waf-tester vendor -u https://target.com -output waf-info.json
```

#### With Bypass Hints

The vendor command shows WAF-specific bypass techniques:

```bash
waf-tester vendor -u https://target.com -v
```

---

### Protocol Detection (protocol)

Enterprise protocol detection (gRPC, SOAP, GraphQL, WCF).

```bash
waf-tester protocol -u https://target.com
```

Detects:
- GraphQL endpoints
- gRPC services
- SOAP/WSDL services
- WCF endpoints
- REST API patterns

---

### Bypass Hunting (bypass)

WAF bypass finder using full mutation matrix.

#### Basic Bypass Search

```bash
waf-tester bypass -u https://target.com
```

#### Smart Bypass with Chaining

```bash
waf-tester bypass -u https://target.com \
  --smart \
  --smart-mode=full \
  -chain \
  -o bypasses.json
```

#### Category-Specific

```bash
waf-tester bypass -u https://target.com -category injection
waf-tester bypass -u https://target.com -category sqli -mutation full
```

#### With Tamper Scripts

```bash
# Manual tamper selection
waf-tester bypass -u https://target.com \
  --smart \
  --tamper=space2comment,randomcase

# Auto-select tampers based on detected WAF (v2.4.2+)
waf-tester bypass -u https://target.com \
  --smart \
  --tamper-auto

# Use aggressive profile for maximum bypass attempts
waf-tester bypass -u https://target.com \
  --smart \
  --tamper-profile=aggressive
```

---

### Mutation Testing (mutate)

Test payloads with all encoding/location/evasion combinations.

#### Basic Mutation

```bash
waf-tester mutate -u https://target.com
```

#### With Specific Encoders

```bash
waf-tester mutate -u https://target.com \
  -encoders url,double_url,unicode,html
```

#### Full Mutation Matrix

```bash
waf-tester mutate -u https://target.com \
  -mutation full \
  -chain \
  -max-chain 3
```

See [Mutation Engine](#mutation-engine) for all available mutators.

---

### False Positive Testing (fp)

Test WAF with legitimate traffic to measure false positive rate.

#### Basic FP Test

```bash
waf-tester fp -u https://target.com
```

#### With Leipzig Corpus

```bash
waf-tester fp -u https://target.com -corpus leipzig
```

#### Custom Corpus

```bash
waf-tester fp -u https://target.com -corpus /path/to/corpus.txt
```

#### Available Corpora

| Corpus | Description |
|--------|-------------|
| `builtin` | Built-in legitimate traffic samples |
| `leipzig` | Leipzig corpora for natural language |
| Custom path | Your own legitimate request corpus |

---

### Content Fuzzing (fuzz)

Directory and content fuzzing with FUZZ keyword.

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

# SOCKS5 proxy
waf-tester probe -l targets.txt -proxy socks5://localhost:1080
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

HTTP request smuggling testing.

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

#### Multiple Targets

```bash
waf-tester smuggle -l targets.txt -o smuggle-results.json
```

#### Detection Options

```bash
# Custom timeout
waf-tester smuggle -u https://target.com -timeout 15

# Delay between requests (milliseconds)
waf-tester smuggle -u https://target.com -delay 2000

# Retries per technique
waf-tester smuggle -u https://target.com -retries 5

# Verbose output
waf-tester smuggle -u https://target.com -v
```

| Technique | Description |
|-----------|-------------|
| `clte` | Content-Length.Transfer-Encoding |
| `tecl` | Transfer-Encoding.Content-Length |
| `tete` | Transfer-Encoding.Transfer-Encoding |

---

### Race Condition Testing (race)

Test for race conditions in web applications.

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

| Attack Type | Description |
|-------------|-------------|
| `double_submit` | Submit same request twice simultaneously |
| `token_reuse` | Reuse single-use tokens concurrently |
| `limit_bypass` | Bypass rate limits with concurrent requests |
| `toctou` | Time-of-check to time-of-use vulnerabilities |

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

---

### Web Crawling (crawl)

Advanced web crawler with scope control.

#### Basic Crawl

```bash
waf-tester crawl -u https://target.com
```

#### With Depth Control

```bash
waf-tester crawl -u https://target.com -depth 5 -max-pages 500
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

#### Rate Control

```bash
# Concurrent crawlers
waf-tester crawl -u https://target.com -concurrency 10

# Delay between requests (milliseconds)
waf-tester crawl -u https://target.com -delay 100

# Request timeout
waf-tester crawl -u https://target.com -timeout 15
```

---

### JavaScript Analysis (analyze)

JavaScript analysis for URLs, methods, secrets, and DOM sinks.

#### Basic Analysis

```bash
waf-tester analyze -u https://target.com
```

#### Analyze Local File

```bash
waf-tester analyze -file ./app.js
```

#### Multiple Targets

```bash
waf-tester analyze -l js-urls.txt -o analysis.json
```

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

#### What It Finds

- **API Endpoints**: fetch(), axios(), jQuery.ajax(), XMLHttpRequest
- **HTTP Methods**: Inferred from URL patterns and code context
- **Secrets**: API keys, tokens, credentials (AWS, Google, GitHub, Stripe, etc.)
- **DOM XSS Sinks**: innerHTML, document.write, eval, etc.

---

### Headless Browser Testing (headless)

Browser-based security testing with real Chrome/Chromium.

#### Basic Headless Testing

```bash
waf-tester headless -u https://target.com
waf-tester headless -u https://target.com --stream
```

#### Multiple Targets

```bash
waf-tester headless -l targets.txt -o results.json
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

# Show browser (non-headless)
waf-tester headless -u https://target.com -headless=false

# Custom timeout and wait
waf-tester headless -u https://target.com -timeout 60 -wait 5
```

#### URL Extraction

```bash
# Extract URLs from pages (default enabled)
waf-tester headless -l targets.txt -extract-urls -o urls.json -v
```

| Flag | Description |
|------|-------------|
| `-screenshot` | Take screenshots |
| `-screenshot-dir` | Screenshot output directory |
| `-js` | JavaScript to execute after load |
| `-chrome` | Path to Chrome executable |
| `-headless` | Run in headless mode (default: true) |
| `-timeout` | Page load timeout (seconds) |
| `-wait` | Wait time after page load (seconds) |
| `-extract-urls` | Extract URLs from page (default: true) |

---

## Workflow Commands

### Discovery and Planning

#### Endpoint Discovery

```bash
waf-tester discover -u https://example.com
waf-tester discover -u https://example.com -output custom-discovery.json
```

Discovery sources:
- robots.txt
- sitemap.xml (9 locations)
- JavaScript analysis
- Wayback Machine
- HTML forms
- Service presets

#### Generate Test Plan

```bash
waf-tester learn -discovery discovery.json
waf-tester learn -discovery discovery.json -output custom-plan.json
```

---

### Test Execution (run)

Execute tests from a plan or standalone.

#### With Test Plan

```bash
waf-tester run -plan testplan.json
waf-tester run -plan testplan.json -format html -o report.html
```

#### Standalone

```bash
waf-tester run -u https://example.com -c 50 -rl 200
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

---

### Workflow Orchestration

Execute multi-step security workflows from YAML/JSON files.

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

#### Workflow Options

```bash
# Custom timeout (seconds)
waf-tester workflow -f workflow.yaml -timeout 600

# Verbose output
waf-tester workflow -f workflow.yaml -v

# JSON output
waf-tester workflow -f workflow.yaml -json

# Save results to file
waf-tester workflow -f workflow.yaml -o workflow-results.json
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

| Flag | Description |
|------|-------------|
| `-f`, `-file` | Workflow file (YAML or JSON) |
| `-var` | Input variables (name=value, comma-separated) |
| `-dry-run` | Preview without executing |
| `-timeout` | Workflow timeout in seconds (default: 300) |
| `-v` | Verbose output |
| `-json` | JSON output to stdout |
| `-o` | Output file for results |

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
│  │                 │  │  ALERTING       │  │                 │             │
│  └───────┬─────────┘  └───────┬─────────┘  └───────┬─────────┘             │
│          │                    │                    │                        │
│          ▼                    ▼                    ▼                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │ • SARIF (CI/CD) │  │ • Slack         │  │ • OpenTelemetry │             │
│  │ • JUnit (tests) │  │ • Teams         │  │ • Prometheus    │             │
│  │ • JSON/JSONL    │  │ • PagerDuty     │  │                 │             │
│  │ • SonarQube     │  │ • Jira          │  │                 │             │
│  │ • GitLab SAST   │  │ • Webhook       │  │                 │             │
│  │ • CycloneDX VEX │  │ • GitHub Actions│  │                 │             │
│  │ • DefectDojo    │  │                 │  │                 │             │
│  │ • HAR           │  │                 │  │                 │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
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

#### Observability Flags

| Flag | Service | When to Use |
|------|---------|-------------|
| `--otel-endpoint=HOST:PORT` | OpenTelemetry | Distributed tracing |
| `--otel-insecure` | OpenTelemetry | Skip TLS verification |
| `--metrics-port=PORT` | Prometheus | Metrics scraping |

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

### Available Formats

| Format | Flag | Use Case | v2.5.0 Enhancements |
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
        "version": "2.5.0"
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
        { "type": "mrkdwn", "text": "WAFtester v2.5.0 | Scan ID: a1b2c3d4 | 2026-02-03T14:30:00Z" }
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
          { "key": "service.version", "value": { "stringValue": "2.5.0" } }
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
└── results.md           # v2.5.0+
```

---

## CI/CD Integration

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

# SOCKS5 proxy
waf-tester scan -u https://target.com -proxy socks5://127.0.0.1:1080

# Burp Suite integration
waf-tester scan -u https://target.com -proxy http://127.0.0.1:8080 -k
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

## Real-World Scenarios

### Bug Bounty Quick Check

```bash
waf-tester auto -u https://target.com --smart -c 50 -rl 100
```

### Penetration Test

```bash
waf-tester auto -u https://client-site.com \
  --smart \
  --smart-mode=full \
  --browser \
  -output-dir ./pentest-results
```

### WAF Validation (Blue Team)

```bash
waf-tester assess -u https://your-app.com \
  -fp \
  -corpus "builtin,leipzig" \
  -o waf-assessment.json
```

### Find WAF Bypasses

```bash
waf-tester bypass -u https://target.com \
  --smart \
  --smart-mode=bypass \
  -category injection \
  --tamper=space2comment,randomcase \
  -o bypasses.json
```

### CI/CD Security Gate

```bash
waf-tester scan -u https://staging.example.com \
  --stream \
  -types sqli,xss,rce \
  -sarif -o security-results.sarif
```

### API Security Testing

```bash
waf-tester scan -u https://api.example.com \
  -types sqli,nosqli,ssrf,jwt \
  -H "Authorization: Bearer $TOKEN" \
  -json -o api-security.json
```

### GraphQL API Testing

```bash
waf-tester scan -u https://api.example.com/graphql \
  -types graphql \
  -H "Authorization: Bearer $TOKEN" \
  --json
```

### WordPress Audit

```bash
waf-tester auto -u https://myblog.com \
  -service wordpress \
  --smart \
  -format html -o wordpress-audit.html
```

### Authenticated Testing

```bash
# Opens browser for manual login
waf-tester auto -u https://app.example.com --browser

# With custom timeout
waf-tester auto -u https://app.example.com --browser -browser-timeout 5m
```

### Stealth Reconnaissance

```bash
waf-tester discover -u https://target.com \
  -c 3 \
  -rl 5 \
  -delay 2s \
  -o recon.json
```

### Parameter Discovery

```bash
waf-tester fuzz -u "https://target.com/api?FUZZ=test" \
  -w params.txt \
  -mc 200 \
  -o fuzz-results.json
```

### Full Bypass Campaign

```bash
waf-tester bypass -u https://target.com \
  --smart \
  --smart-mode=full \
  -mutation full \
  -chain \
  --tamper=space2comment,charencode,randomcase \
  -o full-bypass-results.json
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
