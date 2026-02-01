# WAFtester

Adaptive WAF security testing toolkit. Discover endpoints, detect WAF vendors, and test security rules with 1,500+ attack payloads.

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://go.dev/)

## Overview

WAFtester is a command-line tool for security professionals to assess Web Application Firewall configurations. It combines endpoint discovery, WAF fingerprinting, and payload testing into an adaptive workflow that adjusts based on what it finds.

**Key capabilities:**

- **Authenticated browser scanning** - Opens a real browser window for manual login (MFA, CAPTCHA, SSO)
- Detects 197 WAF vendors from response signatures
- Includes 1,500+ community payloads (SQL injection, XSS, path traversal, etc.)
- Smart mode adapts rate limits and evasion techniques per vendor
- Outputs to JSON, SARIF, CSV, HTML, and Markdown
- Enterprise assessment mode with F1, precision, and MCC metrics

## Requirements

- **Go 1.22+** for building from source
- **Chrome or Chromium** (optional) - Required for authenticated browser scanning with manual login

## Installation

### From Source

```bash
go install github.com/waftester/waftester/cmd/cli@latest
```

### Binary Releases

Download from the [releases page](https://github.com/waftester/waftester/releases).

### Verify Installation

```bash
waf-tester -h
```

## 🚀 Quick Start

### One Command To Do Everything

```bash
waf-tester auto -u https://example.com
```

**What happens:**
```
📡 Finding all pages...     Found 47 pages, 12 forms
📝 Making test plan...      156 security tests
🎯 Running tests...         [████████████████] 100%

✅ Done! Files saved to:
   📂 workspaces/example.com/2026-02-01_14-30-00/
      📄 results.json    ← For scripts
      📊 results.html    ← Open in browser!
```

### Step-by-Step (More Control)

```bash
# Step 1: Find all pages on the website
waf-tester discover -u https://example.com
# → Creates: discovery.json

# Step 2: Make a smart test plan
waf-tester learn -discovery discovery.json
# → Creates: testplan.json

# Step 3: Run the tests, get a report
waf-tester run -plan testplan.json -format html -o report.html
# → Creates: report.html (open in browser!)
```

📖 **[See Full Examples Guide](docs/EXAMPLES.md)** for more commands and options.

## Commands

| Command | Description |
|---------|-------------|
| `auto` | Full automated workflow: discover, analyze, learn, run, report |
| `discover` | Crawl target and find endpoints from multiple sources |
| `learn` | Analyze discovery results and generate targeted test plan |
| `run` | Execute tests using a plan or manual configuration |
| `scan` | Deep vulnerability scanning (SQLi, XSS, SSRF, etc.) |
| `assess` | Enterprise WAF assessment with quantitative metrics |
| `bypass` | WAF bypass finder using mutation matrix |
| `mutate` | Test payloads with encoding/evasion combinations |
| `probe` | Protocol probing and WAF/CDN detection |
| `fuzz` | Directory and content fuzzing |
| `fp` | False positive testing with Leipzig corpus |
| `vendor` | Vendor-specific WAF detection with bypass hints |

Run `waf-tester <command> -h` for command-specific options.

## Usage Examples

### Basic Scanning

```bash
# Scan with automatic WAF detection
waf-tester scan -u https://target.com

# Scan specific categories
waf-tester scan -u https://target.com -category sqli,xss

# Multi-target from file
waf-tester scan -l targets.txt -c 50
```

### Smart Mode

Smart mode detects the WAF vendor and optimizes testing accordingly:

```bash
waf-tester scan -u https://target.com --smart
waf-tester bypass -u https://target.com --smart --smart-mode=full
```

### 📂 Where Are My Files?

**Every command tells you:**
```
✓ Results saved to ./results.json
✓ Report saved to ./report.html
```

**Quick answer:**

| Command | Your Files Are In |
|---------|-------------------|
| `auto` | `workspaces/example.com/2026-02-01.../results.html` ← **Open this!** |
| `discover` | `./discovery.json` |
| `learn` | `./testplan.json` |
| Other commands | Wherever you put `-o filename.json` |

**Want files somewhere else?**
```bash
# Save to your Desktop
waf-tester auto -u https://example.com -output-dir ~/Desktop/my-scan
```

### Output Formats

```bash
# HTML report (prettiest - open in browser)
waf-tester run -plan testplan.json -format html -o report.html

# JSON (for scripts)
waf-tester run -plan testplan.json -format json -o results.json

# SARIF (for GitHub/GitLab)
waf-tester run -plan testplan.json -format sarif -o results.sarif
```

### Mutation Testing

```bash
# Test with URL encoding variations
waf-tester mutate -u https://target.com -encoders url,double_url,unicode

# Full bypass hunting
waf-tester bypass -u https://target.com -m full -chain
```

### Enterprise Assessment

```bash
# Quantitative WAF assessment with metrics
waf-tester assess -u https://target.com -o assessment.json
```

### Authenticated Browser Scanning

For applications requiring login (SSO, MFA, CAPTCHA), WAFtester opens a real browser window where you manually authenticate. After login, it captures all network traffic, tokens, and API calls.

```bash
# Auto mode with browser (default: opens visible browser for manual login)
waf-tester auto -u https://app.example.com

# Browser opens → you log in manually → WAFtester captures:
#   • All network requests and responses
#   • JWT tokens and API keys in storage
#   • Third-party API integrations
#   • Authentication flow details

# Run browser in headless mode (no manual login)
waf-tester auto -u https://app.example.com -browser-headless

# Disable browser scanning entirely
waf-tester auto -u https://app.example.com -browser=false

# Increase login timeout (default: 3 minutes)
waf-tester auto -u https://app.example.com -browser-timeout 5m
```

**Note:** Authenticated browser scanning requires Chrome or Chromium installed on your system.

## Configuration

Common flags across commands:

| Flag | Description |
|------|-------------|
| `-u`, `-target` | Target URL(s), comma-separated |
| `-l` | File containing target URLs |
| `-c` | Concurrent workers (default: 25) |
| `-rl`, `-rate-limit` | Requests per second (default: 150) |
| `-timeout` | HTTP timeout in seconds (default: 5) |
| `-x`, `-proxy` | HTTP/SOCKS5 proxy |
| `-k`, `-skip-verify` | Skip TLS certificate verification |
| `-format` | Output format: json, jsonl, sarif, csv, md, html |
| `-o` | Output file path |
| `-v`, `-verbose` | Verbose output |
| `-s`, `-silent` | Silent mode |
| `--stream` | CI/pipeline mode - no animated progress |

### Browser Scanning Flags

| Flag | Description |
|------|-------------|
| `-browser` | Enable/disable browser scanning (default: true) |
| `-browser-headless` | Run browser in headless mode, no visible window |
| `-browser-timeout` | Time to wait for manual login (default: 3m) |

## Payloads

Community payloads are located in `payloads/community/` and organized by category:

```
payloads/community/
├── auth/           # Authentication bypass
├── injection/      # SQL, NoSQL, command injection
├── traversal/      # Path traversal
├── xss/            # Cross-site scripting
└── ...
```

Update payloads from upstream sources:

```bash
waf-tester update
```

## Documentation

- **[📖 Complete CLI Examples Guide](docs/EXAMPLES.md)** - 100+ examples for every command
- [Installation Guide](docs/INSTALLATION.md)

## License

WAFtester core is licensed under the [Business Source License 1.1](LICENSE).

- Free for internal security testing, development, and non-commercial use
- Commercial use for competing WAF testing services requires a license
- Converts to Apache 2.0 on January 31, 2030

Community payloads in `payloads/community/` are [MIT licensed](LICENSE-COMMUNITY).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
