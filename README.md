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
- **70+ sqlmap-compatible tamper scripts** for WAF bypass (v2.4.0+)
- **Full GraphQL, gRPC, and SOAP/WSDL protocol support** (v2.4.0+)

## Protocol Support

WAFtester provides native security testing for modern API protocols beyond traditional HTTP:

### GraphQL Security Testing

```bash
# Automatic GraphQL endpoint detection and testing
waf-tester auto -u https://api.example.com/graphql

# Deep GraphQL introspection and schema analysis
waf-tester scan -u https://api.example.com/graphql -types graphql

# GraphQL-specific attack categories:
# - Introspection exposure
# - Query depth attacks
# - Batch query abuse
# - Field suggestion exploitation
# - Authorization bypass via aliases
# - Directive injection
```

**Supported GraphQL Features:**
- Schema introspection and type enumeration
- Mutation fuzzing with type-aware payloads
- Query complexity analysis
- Subscription testing
- Persisted query detection

### gRPC Security Testing

```bash
# gRPC reflection-based testing
waf-tester scan -u grpc://service.example.com:50051 -types grpc

# With TLS
waf-tester scan -u grpcs://service.example.com:50051 -types grpc

# gRPC-specific attack categories:
# - Reflection enumeration
# - Message field fuzzing
# - Streaming abuse
# - Metadata injection
# - Proto type confusion
```

**Supported gRPC Features:**
- Server reflection for service discovery
- Automatic proto message construction
- Unary, server streaming, client streaming, and bidirectional testing
- TLS/mTLS support
- Metadata header injection

### SOAP/WSDL Security Testing

```bash
# WSDL-based SOAP testing
waf-tester scan -u https://api.example.com/service.wsdl -types soap

# SOAP-specific attack categories:
# - WSDL enumeration
# - XML injection in SOAP body
# - XXE attacks
# - WS-Security bypass
# - SOAP action manipulation
```

**Supported SOAP Features:**
- Automatic WSDL parsing
- Operation enumeration
- Type-aware XML payload generation
- WS-Security header support
- MTOM/XOP attachment handling

## Tamper Scripts

WAFtester includes 70+ tamper scripts (ported from sqlmap) for WAF bypass. Use `--tamper` to apply transformations:

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

### Popular Tampers

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
waf-tester scan -u https://target.com -types sqli,xss

# Multi-target from file
waf-tester scan -l targets.txt -c 50

# Smart mode (adapts to detected WAF)
waf-tester scan -u https://target.com --smart

# Bypass hunting
waf-tester bypass -u https://target.com --smart --smart-mode=full

# Enterprise assessment
waf-tester assess -u https://target.com -o assessment.json

# Streaming JSON for CI/CD pipelines (v2.3.3+)
waf-tester scan -u https://target.com -stream -json | jq

# Save real-time events to NDJSON file
waf-tester scan -u https://target.com -stream -json > scan-events.jsonl
```

### CI/CD Pipeline Integration

Use `--json` for machine-readable output in automation pipelines:

```bash
# JSON output for automation (v2.3.4+)
waf-tester auto -u https://target.com --json
waf-tester scan -u https://target.com --json > results.json
waf-tester probe -u https://target.com --json | jq '.waf'

# Real-time streaming JSON for CI/CD pipelines
waf-tester scan -u $TARGET_URL -stream -json | jq 'select(.type=="vulnerability")'

# Save events to NDJSON file
waf-tester scan -u $TARGET_URL -stream -json > scan-events.jsonl

# Filter critical vulnerabilities and fail build
waf-tester scan -u $TARGET_URL -stream -json | jq 'select(.data.severity=="Critical")' | grep -q . && exit 1
```

**Key Flags for Automation:**

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (use with any command) |
| `-stream -json` | Real-time NDJSON events for pipelines |
| `-sarif` | SARIF format for GitHub Security tab |
| `-o` | Write output to file |

Event types emitted in streaming mode:
- `scan_start` - Scanner beginning execution
- `vulnerability` - Vulnerability discovered
- `scan_complete` - Scanner finished (guaranteed even on errors)
- `scan_end` - All scanners complete with summary

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
