# @waftester/cli

[![npm](https://img.shields.io/npm/v/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![downloads](https://img.shields.io/npm/dw/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![license](https://img.shields.io/npm/l/@waftester/cli)](https://github.com/waftester/waftester/blob/main/LICENSE)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://npmjs.com/package/@waftester/cli)

The most comprehensive WAF testing CLI & MCP server. Detect, fingerprint, and bypass Web Application Firewalls with **2,800+ payloads**, **96 tamper scripts**, and quantitative security metrics (FPR, F1, MCC).

## Why WAFtester?

| Traditional Approach | WAFtester |
|---------------------|-----------|
| Chain 5+ tools (wafw00f, sqlmap, nuclei, scripts) | Single `auto` command — end-to-end |
| Manually select tampers per WAF vendor | Auto-selects from 96 tampers based on detected WAF |
| Binary pass/fail results | Statistical metrics: FPR, Precision, F1 Score, MCC |
| HTTP only | Native GraphQL, gRPC, SOAP, WebSocket support |
| Manual result correlation | Unified JSON, SARIF, HTML, JUnit, CycloneDX output |

## Quick Start

```bash
# Run without installing — downloads correct binary for your platform
npx -y @waftester/cli scan -u https://example.com

# Or install globally
npm install -g @waftester/cli
waf-tester scan -u https://example.com
```

## What You Can Do

### Full Automated Assessment

```bash
waf-tester auto -u https://target.com --smart
```

Executes the complete lifecycle: endpoint discovery → WAF fingerprinting → optimal tamper selection → 2,800+ payload testing → quantitative report generation.

### WAF Detection & Fingerprinting

Identify WAF vendors with 198 vendor signatures:

```
$ waf-tester vendor -u https://protected.example.com

  Vendor         Cloudflare
  Confidence     98%
  Evidence       cf-ray header, __cfduid cookie, 1020 error page

Recommended tampers: charunicodeencode, space2morecomment, randomcase
```

Covers Cloudflare, AWS WAF, Akamai, Imperva, Azure WAF, F5, ModSecurity, Fortinet, Barracuda, Sucuri, Radware, Citrix ADC, Palo Alto, Sophos, Wallarm, and more.

### Bypass Discovery

```
$ waf-tester bypass -u https://target.com --smart --tamper-auto

  Payload Variants Tested     2,847
  Blocked by WAF              2,728 (95.8%)
  Bypassed WAF                119 (4.2%)

Top Bypass Chains:
  1. charunicodeencode + space2morecomment    (42 bypasses)
  2. modsecurityversioned + randomcase        (31 bypasses)
  3. between + equaltolike                    (19 bypasses)
```

The mutation engine combines 49 mutator functions with base payloads for comprehensive encoding, evasion, and injection variation coverage.

Automate bypass chain discovery by testing tamper combinations against WAF rules:

```bash
# Automated bypass discovery — tests tamper combinations systematically
waf-tester bypass -u https://target.com --discover

# Write custom tamper scripts in Tengo and load from a directory
waf-tester scan -u https://target.com --tamper-dir ./my-tampers
```

### Enterprise Assessment with Metrics

```
$ waf-tester assess -u https://target.com -fp -o assessment.json

  Detection Rate (TPR)    94.2%
  False Positive Rate      0.3%
  Precision               99.7%
  Recall                  94.2%
  F1 Score                0.969
  MCC                     0.942
```

Includes benign traffic corpus testing (Leipzig integration) for false positive measurement.

### Service Presets

Use service presets for platform-specific testing. Presets add known endpoints and attack surface hints to improve discovery coverage.

```bash
# Test an Authentik identity provider
waf-tester auto -u https://sso.example.com -service authentik

# Test an n8n automation instance
waf-tester discover -u https://automation.example.com -service n8n

# Custom presets — drop JSON files in presets/ directory
WAF_TESTER_PRESET_DIR=./my-presets waf-tester auto -u https://target.com -service myapp
```

Built-in presets: `authentik`, `n8n`, `immich`, `webapp`, `intranet`. Create custom presets by adding JSON files — see the [Examples Guide](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md#service-presets).

### Targeted Scanning

```bash
# SQL injection and XSS
waf-tester scan -u https://target.com -types sqli,xss

# All 50+ attack categories
waf-tester scan -u https://target.com -types all

# Multi-protocol
waf-tester scan -u https://api.example.com/graphql -types graphql
waf-tester scan -u grpc://service:50051 -types grpc
waf-tester scan -u wss://api.example.com/socket -types websocket
```

### Browser & SPA Testing

```bash
# DOM event crawling — discovers hidden UI states in single-page apps
waf-tester headless -u https://spa.example.com --event-crawl

# Browser-based scanning for JavaScript-rendered targets
waf-tester headless -u https://app.example.com --smart
```

## MCP Server (AI Integration)

WAFtester includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server with **27 tools**, **7 guided prompts**, and **12 resources** for AI-powered security testing from Claude Desktop, VS Code, Cursor, and other MCP clients.

### Claude Desktop

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

### VS Code

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "waf-tester": {
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

### Cursor

Add to Cursor MCP settings:

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

## API Spec Scanning

Scan OpenAPI, Swagger, Postman, HAR, AsyncAPI, gRPC, and GraphQL endpoints with one command:

```bash
# OpenAPI / Swagger spec (auto-detected)
waf-tester scan --spec openapi.yaml -u https://api.example.com

# Postman Collection with environment variables
waf-tester scan --spec collection.postman_collection.json --env staging.postman_environment.json

# HAR recording from browser DevTools
waf-tester scan --spec recording.har -u https://api.example.com

# Preview endpoints without scanning
waf-tester scan --spec openapi.yaml -u https://api.example.com --dry-run
```

## Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| JSON | Automation, APIs | `-format json` |
| JSONL | Streaming, real-time | `-stream -json` |
| SARIF | GitHub/GitLab Security, VS Code | `-format sarif` |
| HTML | Stakeholder reports | `-format html` |
| PDF | Executive reports with severity matrix | `-format pdf` |
| Markdown | Documentation, wikis | `-format md` |
| CSV | Spreadsheets, data analysis | `-format csv` |
| JUnit | CI/CD test frameworks | `-junit-export results.xml` |
| XML | Legacy integrations | `-xml-export results.xml` |
| CycloneDX | SBOM vulnerability exchange | `-cyclonedx-export results.json` |
| SonarQube | SonarQube import | `-sonarqube-export results.json` |
| GitLab SAST | GitLab security dashboard | `-gitlab-sast-export results.json` |
| Console | Terminal display (default) | `-format console` |

## CI/CD Integration

### GitHub Actions (Recommended)

Use the official [WAFtester Action](https://github.com/marketplace/actions/waftester-waf-security-testing) for zero-install CI/CD:

```yaml
- uses: waftester/waftester-action@v1
  with:
    target: ${{ env.TARGET_URL }}
    scan-type: scan
    format: sarif
```

### Alternative: npx in GitHub Actions

```yaml
- name: WAF Security Assessment
  run: |
    npx -y @waftester/cli scan -u ${{ env.TARGET_URL }} \
      -format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Also integrates with SonarQube, GitLab SAST, DefectDojo, Elasticsearch, Slack, Teams, PagerDuty, Jira, Azure DevOps, and OpenTelemetry.

## All 33 Commands

| Command | Description |
|---------|-------------|
| `auto` | Full automated assessment (discovery → detection → testing → report) |
| `scan` | Targeted vulnerability scanning across 50+ categories |
| `vendor` | WAF vendor detection and fingerprinting (198 signatures) |
| `probe` | WAF detection + protocol info in one pass |
| `bypass` | Bypass discovery with tamper chain optimization |
| `assess` | Enterprise assessment with statistical metrics |
| `tampers` | List and rank tamper scripts by WAF vendor effectiveness |
| `discover` | Full discovery (crawl + JS + sitemap + Wayback + event crawl) |
| `fuzz` | Smart fuzzing with parameter-aware mutation |
| `mutate` | Mutation matrix testing (49 mutator functions) |
| `headless` | Browser-based testing for JS-rendered targets |
| `template` | Run Nuclei-compatible YAML templates (HTTP, DNS, TCP, UDP) |
| `grpc` | Test gRPC services via reflection |
| `soap` | Test SOAP/WSDL endpoints |
| `mcp` | Start MCP server for AI-powered testing |
| `cicd` | Generate CI/CD pipeline configs |
| `crawl` | Spider target for endpoint and parameter discovery |
| `analyze` | JavaScript analysis for endpoints and secrets |
| `cloud` | Cloud resource discovery |
| `report` | Generate reports from saved results |
| `run` | Execute specific payload categories against target |
| `race` | Race condition testing |
| `smuggle` | HTTP request smuggling tests |
| `learn` | Analyze target and generate test plans |
| `fp` | False positive testing with benign traffic corpus |
| `protocol` | Protocol detection and fingerprinting |
| `validate` | Payload and spec validation |
| `workflow` | YAML workflow orchestration |
| `plugin` | Plugin management |
| `compare` | Compare two scan result JSON files (severity deltas, risk scores, CI exit code) |
| `update` | Check for and install updates |
| `docs` | Built-in command reference |
| `validate-templates` | Validate Nuclei/custom scan templates |

## Platform Support

| Platform | Architecture | Package |
|---|---|---|
| macOS | x64 (Intel) | `@waftester/darwin-x64` |
| macOS | arm64 (Apple Silicon) | `@waftester/darwin-arm64` |
| Linux | x64 | `@waftester/linux-x64` |
| Linux | arm64 | `@waftester/linux-arm64` |
| Windows | x64 | `@waftester/win32-x64` |
| Windows | arm64 | `@waftester/win32-arm64` |

ARM64 platforms with x64 emulation (Rosetta 2, Windows WoW) are supported as fallback.

## Environment Variables

| Variable | Description |
|---|---|
| `WAF_TESTER_BINARY_PATH` | Override binary path (skip platform resolution) |
| `WAF_TESTER_PAYLOAD_DIR` | Override bundled payload directory |
| `WAF_TESTER_PRESET_DIR` | Override bundled service preset directory |
| `WAF_TESTER_TEMPLATE_DIR` | Override bundled template directory |

## License

[Business Source License 1.1](https://github.com/waftester/waftester/blob/main/LICENSE) — converts to open source after the change date. See [LICENSE](https://github.com/waftester/waftester/blob/main/LICENSE) for full terms.

Community payloads are licensed under [MIT](https://github.com/waftester/waftester/blob/main/LICENSE-COMMUNITY).

## Links

- [Website](https://waftester.com)
- [Documentation](https://waftester.com/docs)
- [Command Reference](https://waftester.com/commands)
- [Cheat Sheet](https://waftester.com/cheat-sheet)
- [GitHub](https://github.com/waftester/waftester)
- [Examples](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md)
- [Changelog](https://github.com/waftester/waftester/blob/main/CHANGELOG.md)
- [Issues](https://github.com/waftester/waftester/issues)
