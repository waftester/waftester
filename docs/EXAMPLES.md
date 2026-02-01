# WAFtester Examples Guide

Complete usage examples for WAFtester commands.

## Table of Contents

- [Quick Start](#quick-start)
- [Automated Scanning (auto)](#automated-scanning-auto)
- [Enterprise Assessment (assess)](#enterprise-assessment-assess)
- [Vulnerability Scanning (scan)](#vulnerability-scanning-scan)
- [WAF Detection (vendor)](#waf-detection-vendor)
- [Bypass Hunting (bypass)](#bypass-hunting-bypass)
- [Mutation Testing (mutate)](#mutation-testing-mutate)
- [False Positive Testing (fp)](#false-positive-testing-fp)
- [Content Fuzzing (fuzz)](#content-fuzzing-fuzz)
- [Protocol Probing (probe)](#protocol-probing-probe)
- [Discovery and Planning](#discovery-and-planning)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
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

## Automated Scanning (auto)

### Basic Usage

```bash
waf-tester auto -u https://example.com
```

### With Smart Mode

Smart mode detects the WAF vendor and optimizes testing:

```bash
waf-tester auto -u https://example.com --smart
```

### Full Options

```bash
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=full \
  -c 100 \
  -rl 300 \
  --browser
```

| Option | Description |
|--------|-------------|
| `--smart` | Enable WAF-aware testing |
| `--smart-mode=full` | Use all bypass techniques |
| `-c 100` | 100 parallel workers |
| `-rl 300` | 300 requests per second |
| `--browser` | Enable authenticated browser scanning |

### Service-Specific Scanning

```bash
waf-tester auto -u https://myblog.com -service wordpress
waf-tester auto -u https://myapp.com -service django
```

Available services: `wordpress`, `drupal`, `nextjs`, `flask`, `django`

### Stealth Mode

```bash
waf-tester auto -u https://example.com \
  --smart \
  --smart-mode=stealth \
  -c 5 \
  -rl 10
```

---

## Enterprise Assessment (assess)

Professional WAF assessment with quantitative metrics.

### Basic Assessment

```bash
waf-tester assess -u https://example.com
```

### Full Assessment with Output

```bash
waf-tester assess -u https://example.com \
  -fp \
  -corpus "builtin,leipzig" \
  -format json \
  -o assessment.json
```

### Metrics Produced

- **Detection Rate (TPR)** - Percentage of attacks blocked
- **False Positive Rate (FPR)** - Percentage of legitimate traffic blocked
- **Precision** - Percentage of blocks that were real attacks
- **F1 Score** - Harmonic mean of precision and recall
- **MCC** - Matthews Correlation Coefficient

### Custom Categories

```bash
waf-tester assess -u https://example.com \
  -categories sqli,xss,rce \
  -o assessment.json
```

---

## Vulnerability Scanning (scan)

### Basic Scan

```bash
waf-tester scan -u https://target.com
```

### Specific Categories

```bash
waf-tester scan -u https://target.com -category sqli,xss,traversal
```

### Multiple Targets

```bash
waf-tester scan -l targets.txt -c 50
```

### All Available Categories

```bash
waf-tester scan -u https://target.com -types all
```

Categories: `sqli`, `xss`, `traversal`, `cmdi`, `nosqli`, `ssrf`, `ssti`, `xxe`, `smuggling`, `oauth`, `jwt`, `cors`, `redirect`, `hostheader`, `cache`, `upload`, `deserialize`, `bizlogic`, `race`

---

## WAF Detection (vendor)

### Detect WAF Vendor

```bash
waf-tester vendor -u https://target.com
```

### JSON Output

```bash
waf-tester vendor -u https://target.com -output waf-info.json
```

### Protocol Detection

```bash
waf-tester protocol -u https://target.com
```

---

## Bypass Hunting (bypass)

### Basic Bypass Search

```bash
waf-tester bypass -u https://target.com
```

### Smart Bypass with Chaining

```bash
waf-tester bypass -u https://target.com \
  --smart \
  --smart-mode=full \
  -chain \
  -o bypasses.json
```

### Category-Specific

```bash
waf-tester bypass -u https://target.com -category injection
```

---

## Mutation Testing (mutate)

### Basic Mutation

```bash
waf-tester mutate -u https://target.com
```

### With Specific Encoders

```bash
waf-tester mutate -u https://target.com \
  -encoders url,double_url,unicode,html
```

### Available Encoders

`url`, `double_url`, `triple_url`, `unicode`, `html`, `hex`, `base64`, `utf7`, `utf16`

---

## False Positive Testing (fp)

Test WAF with legitimate traffic to measure false positive rate.

### Basic FP Test

```bash
waf-tester fp -u https://target.com
```

### With Leipzig Corpus

```bash
waf-tester fp -u https://target.com -corpus leipzig
```

### Custom Corpus

```bash
waf-tester fp -u https://target.com -corpus /path/to/corpus.txt
```

---

## Content Fuzzing (fuzz)

### Directory Fuzzing

```bash
waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt
```

### Parameter Fuzzing

```bash
waf-tester fuzz -u "https://target.com/search?q=FUZZ" -w params.txt
```

### With Filters

```bash
waf-tester fuzz -u https://target.com/FUZZ \
  -w wordlist.txt \
  -fc 404,403 \
  -fs 0
```

---

## Protocol Probing (probe)

### Basic Probe

```bash
waf-tester probe -u https://target.com
```

### Multiple Targets

```bash
waf-tester probe -l targets.txt -c 50 -o probes.json
```

### With Streaming Output

```bash
waf-tester probe -l targets.txt --stream
```

---

## Discovery and Planning

### Endpoint Discovery

```bash
waf-tester discover -u https://example.com
waf-tester discover -u https://example.com -output custom-discovery.json
```

### Generate Test Plan

```bash
waf-tester learn -discovery discovery.json
waf-tester learn -discovery discovery.json -output custom-plan.json
```

### Execute Plan

```bash
waf-tester run -plan testplan.json
waf-tester run -plan testplan.json -format html -o report.html
```

---

## Output Formats

### Available Formats

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `-format json` | Programmatic processing |
| JSONL | `-format jsonl` | Streaming, large datasets |
| HTML | `-format html` | Human-readable reports |
| SARIF | `-format sarif` | CI/CD integration |
| Markdown | `-format markdown` | Documentation |
| CSV | `-format csv` | Spreadsheet analysis |

### Examples

```bash
waf-tester run -plan testplan.json -format json -o results.json
waf-tester run -plan testplan.json -format html -o report.html
waf-tester run -plan testplan.json -format sarif -o results.sarif
```

### Output File Locations

| Command | Default Output |
|---------|----------------|
| `discover` | `./discovery.json` |
| `learn` | `./testplan.json` |
| `auto` | `workspaces/<domain>/<timestamp>/` |
| Others | Stdout (use `-o` to save) |

---

## CI/CD Integration

Use `--stream` flag to disable animated progress for clean CI logs.

### Streaming JSON Mode (v2.3.3+)

For real-time machine-readable output, use `-stream -json`:

```bash
# Stream events to stdout as NDJSON
waf-tester scan -u https://target.com -stream -json

# Pipe to jq for filtering
waf-tester scan -u https://target.com -stream -json | jq 'select(.type=="vulnerability")'

# Save to file while watching progress
waf-tester scan -u https://target.com -stream -json 2>/dev/null > scan-events.jsonl
```

**Event Types:**

| Event | Description | Data Fields |
|-------|-------------|-------------|
| `scan_start` | Scanner beginning | `scanner` |
| `vulnerability` | Finding discovered | `category`, `severity`, `type`, etc. |
| `scan_complete` | Scanner finished | `scanner`, `vulns` (count) |
| `scan_end` | All scanners done | `target`, `duration_ms`, `total_vulns`, `by_severity` |

**Example Events:**

```json
{"type":"scan_start","timestamp":"2026-02-01T10:00:00Z","data":{"scanner":"sqli"}}
{"type":"vulnerability","timestamp":"2026-02-01T10:00:01Z","data":{"category":"sqli","severity":"High","type":"error-based"}}
{"type":"scan_complete","timestamp":"2026-02-01T10:00:05Z","data":{"scanner":"sqli","vulns":3}}
{"type":"scan_end","timestamp":"2026-02-01T10:01:00Z","data":{"target":"https://target.com","duration_ms":60000,"total_vulns":15}}
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

All major commands support `--stream` for CI-friendly output: `assess`, `auto`, `bypass`, `crawl`, `fuzz`, `headless`, `mutate`, `probe`, `scan`, `smuggle`, `fp`

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

---

## Working with Proxies

```bash
# HTTP proxy
waf-tester scan -u https://target.com -proxy http://127.0.0.1:8080

# SOCKS5 proxy
waf-tester scan -u https://target.com -proxy socks5://127.0.0.1:1080

# Burp Suite integration
waf-tester scan -u https://target.com -proxy http://127.0.0.1:8080 -k
```

---

## Multiple Targets

```bash
# From file
waf-tester scan -l targets.txt

# Comma-separated
waf-tester scan -u https://site1.com,https://site2.com

# With concurrency
waf-tester scan -l targets.txt -c 100 -rl 500
```

---

## Smart Mode

Smart mode detects WAF vendors and adapts testing:

```bash
# Basic smart mode
waf-tester scan -u https://target.com --smart

# Full bypass hunting
waf-tester bypass -u https://target.com --smart --smart-mode=full

# Stealth mode
waf-tester auto -u https://target.com --smart --smart-mode=stealth
```

Smart mode options: `basic`, `full`, `bypass`, `stealth`
