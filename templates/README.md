# Templates

Pre-built templates for WAF security testing, reporting, CI/CD integration, and scan configuration.

## Directory Structure

```
templates/
├── nuclei/                      # Nuclei-compatible YAML scanning templates
│   ├── http/
│   │   ├── waf-bypass/          # WAF bypass detection templates
│   │   └── waf-detection/       # WAF vendor fingerprinting
│   └── workflows/               # Conditional scan chains
├── workflows/                   # Multi-step scan orchestration
├── policies/                    # CI/CD pass/fail gate policies
├── overrides/                   # Test override configurations
├── output/                      # Go text/template output formats
└── report-configs/              # HTML report theme/layout configs
```

---

## Nuclei Templates

Nuclei-compatible YAML templates for WAF bypass testing and detection.

### WAF Bypass Templates (`nuclei/http/waf-bypass/`)

| Template | Severity | Description |
|----------|----------|-------------|
| `sqli-basic.yaml` | Critical | Basic SQL injection bypass tests |
| `sqli-evasion.yaml` | Critical | SQLi with evasion (case alt, comments, encoding) |
| `xss-basic.yaml` | High | Basic XSS bypass tests |
| `xss-evasion.yaml` | High | XSS with encoding and tag mutation |
| `rce-bypass.yaml` | Critical | Command injection with evasion |
| `lfi-bypass.yaml` | High | Path traversal / LFI bypass |
| `ssrf-bypass.yaml` | High | SSRF with IP encoding tricks |
| `ssti-bypass.yaml` | Critical | Server-side template injection |
| `crlf-bypass.yaml` | Medium | CRLF header injection |
| `xxe-bypass.yaml` | Critical | XML external entity injection |
| `nosqli-bypass.yaml` | High | NoSQL injection (MongoDB operators) |

### WAF Detection Templates (`nuclei/http/waf-detection/`)

| Template | Description |
|----------|-------------|
| `cloudflare-detect.yaml` | Cloudflare WAF fingerprinting |
| `aws-waf-detect.yaml` | AWS WAF / Shield detection |
| `akamai-detect.yaml` | Akamai Kona Site Defender |
| `modsecurity-detect.yaml` | ModSecurity / OWASP CRS |
| `azure-waf-detect.yaml` | Azure Front Door / Azure WAF |

### Nuclei Workflows (`nuclei/workflows/`)

| Workflow | Description |
|----------|-------------|
| `waf-assessment-workflow.yaml` | Detect WAF then run all bypass templates |

### Usage

```bash
# Run a single template
waf-tester nuclei -t templates/nuclei/http/waf-bypass/sqli-basic.yaml -u https://example.com

# Run all bypass templates
waf-tester nuclei -t templates/nuclei/http/waf-bypass/ -u https://example.com

# Run the full assessment workflow
waf-tester nuclei -t templates/nuclei/workflows/waf-assessment-workflow.yaml -u https://example.com
```

---

## Workflow Templates

Multi-step scan orchestration YAML files for common assessment patterns.

| Workflow | Description |
|----------|-------------|
| `full-scan.yaml` | Complete: detect, learn, scan, report (HTML + SARIF) |
| `quick-probe.yaml` | Fast WAF detection + critical vulnerability probe |
| `ci-gate.yaml` | CI/CD security gate with policy enforcement |
| `waf-detection.yaml` | WAF detection + fingerprinting + behavior probing |
| `api-scan.yaml` | API-focused assessment (SQLi, NoSQLi, SSRF, JWT, GraphQL) |

### Usage

```bash
waf-tester workflow run templates/workflows/full-scan.yaml \
  --input target=https://example.com \
  --input output_dir=./results
```

---

## Policy Templates

CI/CD pass/fail gate policies defining bypass thresholds and effectiveness requirements.

| Policy | Strictness | Effectiveness | Use Case |
|--------|------------|---------------|----------|
| `permissive.yaml` | Low | 60%+ | Development environments |
| `standard.yaml` | Medium | 85%+ | General assessments |
| `strict.yaml` | High | 95%+ | Production security gates |
| `owasp-top10.yaml` | High | 90%+ | OWASP Top 10 compliance |
| `pci-dss.yaml` | Maximum | 99%+ | PCI DSS 4.0 compliance |

### Usage

```bash
waf-tester run -u https://example.com --policy templates/policies/strict.yaml
```

---

## Override Templates

Test override configurations for customizing scan behavior.

| Override | Description |
|----------|-------------|
| `false-positive-suppression.yaml` | Skip known false positive triggers |
| `api-only.yaml` | Skip browser-specific tests for JSON APIs |
| `crs-tuning.yaml` | Tuned for OWASP CRS environments |

### Usage

```bash
waf-tester run -u https://api.example.com --overrides templates/overrides/api-only.yaml
```

---

## Output Format Templates

Go `text/template` files for custom output formatting. Full Sprig function library available.

| Template | Format | Description |
|----------|--------|-------------|
| `asff.tmpl` | JSON | AWS Security Hub Finding Format (ASFF) |
| `csv.tmpl` | CSV | Comma-separated values export |
| `text-summary.tmpl` | Text | Human-readable summary with severity icons |
| `markdown-report.tmpl` | Markdown | Full report in Markdown tables |
| `slack-notification.tmpl` | JSON | Slack Block Kit notification payload |
| `junit.tmpl` | XML | JUnit test report for CI/CD systems |

### Usage

```bash
# Use a file template
waf-tester run -u https://example.com --template templates/output/markdown-report.tmpl

# Pipe to Slack
waf-tester run -u https://example.com --template templates/output/slack-notification.tmpl \
  | curl -X POST -H 'Content-Type: application/json' -d @- $SLACK_WEBHOOK
```

### Template Data

Templates have access to these fields:

| Field | Type | Description |
|-------|------|-------------|
| `.ScanID` | string | Unique scan identifier |
| `.Target` | string | Target URL |
| `.Timestamp` | string | RFC3339 timestamp |
| `.Duration` | float64 | Scan duration in seconds |
| `.TotalTests` | int | Total tests run |
| `.Blocked` | int | Tests blocked by WAF |
| `.BypassCount` | int | Bypasses detected |
| `.Errors` | int | Error count |
| `.Effectiveness` | float64 | WAF effectiveness percentage |
| `.Grade` | string | Letter grade (A+, A, B, etc.) |
| `.Results[]` | array | All test results |
| `.Bypasses[]` | array | Only bypass results |
| `.SeverityCounts` | map | Bypass counts by severity |
| `.CategoryCounts` | map | Bypass counts by category |

Custom functions: `escapeCSV`, `escapeXML`, `severityIcon`, `json`, `prettyJSON`, `owaspLink`, `cweLink`, plus the full [Sprig](http://masterminds.github.io/sprig/) library.

---

## Report Template Configs

HTML report theme and layout configurations.

| Config | Theme | Description |
|--------|-------|-------------|
| `minimal.yaml` | Light | Condensed essential findings |
| `enterprise.yaml` | Light | Full-featured enterprise report |
| `dark.yaml` | Dark | Dark theme for presentations |
| `compliance.yaml` | Light | Compliance-focused with evidence |
| `print.yaml` | Light | Print/PDF optimized, grayscale |

### Usage

```bash
waf-tester scan https://example.com --html report.html \
  --template-config templates/report-configs/dark.yaml
```

### Custom Configs

Copy any config and customize. All available options:

- **Branding**: Company name, logo, colors, footer
- **Layout**: Theme (light/dark/auto), page width, TOC, compact mode
- **Sections**: Enable/disable any report section
- **Styling**: Fonts, colors, border radius, custom CSS
- **Charts**: Radar/bar/line charts, color palette, animation
- **Export**: Default format, allowed formats, raw data embedding

---

## Contributing Templates

1. Follow the Nuclei template format for scanning templates
2. Include `id`, `info.name`, `info.author`, `info.severity`, `info.description`, and `info.tags`
3. Use descriptive filenames matching the template ID
4. Add your template to the appropriate subdirectory
5. Update this README with the new template
