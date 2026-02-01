# WAFtester

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/waftester/waftester)](https://github.com/waftester/waftester/releases)

Adaptive WAF security testing toolkit. Discover endpoints, detect WAF vendors, and test security rules with 2,800+ attack payloads.

## Features

- Authenticated browser scanning with manual login support (MFA, CAPTCHA, SSO)
- Detection of 197 WAF vendors from response signatures
- 2,800+ community payloads (SQL injection, XSS, path traversal, etc.)
- Smart mode adapts rate limits and evasion techniques per vendor
- Enterprise assessment with F1, precision, recall, and MCC metrics
- Multiple output formats: JSON, SARIF, CSV, HTML, Markdown

## Requirements

- Go 1.22+ (for building from source)
- Chrome or Chromium (optional, for authenticated browser scanning)

## Installation

```bash
# From source
go install github.com/waftester/waftester/cmd/cli@latest

# Or download binary from releases
# https://github.com/waftester/waftester/releases
```

Verify installation:

```bash
waf-tester -h
```

## Quick Start

Full automated scan:

```bash
waf-tester auto -u https://example.com
```

Step-by-step workflow:

```bash
# 1. Discover endpoints
waf-tester discover -u https://example.com

# 2. Generate test plan
waf-tester learn -discovery discovery.json

# 3. Execute tests
waf-tester run -plan testplan.json -format html -o report.html
```

## Commands

| Command | Description |
|---------|-------------|
| `auto` | Full workflow: discover, analyze, learn, run, report |
| `discover` | Crawl target and find endpoints |
| `learn` | Generate targeted test plan from discovery |
| `run` | Execute tests from plan |
| `scan` | Deep vulnerability scanning |
| `assess` | Enterprise WAF assessment with metrics |
| `bypass` | WAF bypass finder using mutation matrix |
| `mutate` | Test payloads with encoding/evasion combinations |
| `probe` | Protocol probing and WAF detection |
| `fuzz` | Directory and content fuzzing |
| `fp` | False positive testing |
| `vendor` | Vendor-specific WAF detection |

Run `waf-tester <command> -h` for options.

## Usage Examples

```bash
# Basic scan
waf-tester scan -u https://target.com

# Scan specific categories
waf-tester scan -u https://target.com -category sqli,xss

# Multi-target from file
waf-tester scan -l targets.txt -c 50

# Smart mode (adapts to detected WAF)
waf-tester scan -u https://target.com --smart

# Bypass hunting
waf-tester bypass -u https://target.com --smart --smart-mode=full

# Enterprise assessment
waf-tester assess -u https://target.com -o assessment.json
```

## Output

Results are saved to the location you specify with `-o`:

```bash
waf-tester run -plan testplan.json -o results.json
waf-tester run -plan testplan.json -format html -o report.html
waf-tester run -plan testplan.json -format sarif -o results.sarif
```

The `auto` command creates a workspace directory:

```
workspaces/<domain>/<timestamp>/
├── discovery.json
├── testplan.json
├── results.json
├── results.html
└── results.sarif
```

## Configuration

| Flag | Description |
|------|-------------|
| `-u`, `-target` | Target URL(s) |
| `-l` | File containing target URLs |
| `-c` | Concurrent workers (default: 25) |
| `-rl` | Requests per second (default: 150) |
| `-timeout` | HTTP timeout in seconds (default: 5) |
| `-x`, `-proxy` | HTTP/SOCKS5 proxy |
| `-format` | Output format: json, sarif, csv, html, md |
| `-o` | Output file path |
| `--stream` | CI/CD mode (no animated progress) |

## Browser Scanning

For applications requiring login:

```bash
# Opens browser for manual authentication
waf-tester auto -u https://app.example.com

# Headless mode
waf-tester auto -u https://app.example.com -browser-headless

# Disable browser
waf-tester auto -u https://app.example.com -browser=false
```

## Documentation

- [Examples Guide](docs/EXAMPLES.md) - Detailed usage examples
- [Installation Guide](docs/INSTALLATION.md)
- [Contributing](CONTRIBUTING.md)

## License

Core engine: [Business Source License 1.1](LICENSE) (converts to Apache 2.0 on Jan 31, 2030)

Community payloads (`payloads/community/`): [MIT](LICENSE-COMMUNITY)
