# @waftester/cli

[![npm](https://img.shields.io/npm/v/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![downloads](https://img.shields.io/npm/dw/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![license](https://img.shields.io/npm/l/@waftester/cli)](https://github.com/waftester/waftester/blob/main/LICENSE)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-blue)](https://npmjs.com/package/@waftester/cli)

The most comprehensive WAF testing CLI & MCP server. Detect, fingerprint, and bypass Web Application Firewalls with **2,800+ payloads**, **70+ tamper scripts**, and quantitative security metrics (FPR, F1, MCC).

## Why WAFtester?

| Traditional Approach | WAFtester |
|---------------------|-----------|
| Chain 5+ tools (wafw00f, sqlmap, nuclei, scripts) | Single `auto` command — end-to-end |
| Manually select tampers per WAF vendor | Auto-selects from 70+ tampers based on detected WAF |
| Binary pass/fail results | Statistical metrics: FPR, Precision, F1 Score, MCC |
| HTTP only | Native GraphQL, gRPC, SOAP, WebSocket support |
| Manual result correlation | Unified JSON, SARIF, HTML, JUnit, CycloneDX output |

## Quick Start

```bash
# Run without installing — downloads correct binary for your platform
npx -y @waftester/cli scan --target https://example.com

# Or install globally
npm install -g @waftester/cli
waf-tester scan --target https://example.com
```

## What You Can Do

### Full Automated Assessment

```bash
waf-tester auto -u https://target.com --smart
```

Executes the complete lifecycle: endpoint discovery → WAF fingerprinting → optimal tamper selection → 2,800+ payload testing → quantitative report generation.

### WAF Detection & Fingerprinting

Identify WAF vendors with 197 vendor signatures:

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

## MCP Server (AI Integration)

WAFtester includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server for AI-powered security testing from Claude Desktop, VS Code, Cursor, and other MCP clients.

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

## Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| JSON | Automation, APIs | `-format json` |
| JSONL | Streaming, real-time | `-stream -json` |
| SARIF | GitHub/GitLab Security, VS Code | `-format sarif` |
| HTML | Stakeholder reports | `-format html` |
| JUnit | CI/CD test frameworks | `-format junit` |
| CycloneDX | SBOM vulnerability exchange | `-format cyclonedx` |

## CI/CD Integration

```yaml
# GitHub Actions
- name: WAF Security Assessment
  run: |
    npx -y @waftester/cli scan -u ${{ env.TARGET_URL }} \
      -format sarif -o results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

Also integrates with SonarQube, GitLab SAST, DefectDojo, Elasticsearch, Slack, Teams, PagerDuty, Jira, Azure DevOps, and OpenTelemetry.

## All 33 Commands

| Command | Description |
|---------|-------------|
| `auto` | Full automated assessment (discovery → detection → testing → report) |
| `scan` | Targeted vulnerability scanning across 50+ categories |
| `vendor` | WAF vendor detection and fingerprinting (197 signatures) |
| `bypass` | Bypass discovery with tamper chain optimization |
| `assess` | Enterprise assessment with statistical metrics |
| `tampers` | List and rank tamper scripts by WAF vendor effectiveness |
| `run` | Execute specific payload categories against target |
| `fuzz` | Smart fuzzing with parameter-aware mutation |
| `crawl` | Spider target for endpoint and parameter discovery |
| `mcp` | Start MCP server for AI-powered testing |
| `nuclei` | Run Nuclei templates with WAF-aware configuration |
| `benchmark` | Performance benchmarking and rate limit detection |
| `compare` | Compare assessments across WAF configs or vendors |
| `report` | Generate reports from saved results |
| `version` | Show version and build information |
| ... | 18 more specialized commands |

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
| `WAF_TESTER_TEMPLATE_DIR` | Override bundled template directory |

## License

[Business Source License 1.1](https://github.com/waftester/waftester/blob/main/LICENSE) — converts to open source after the change date. See [LICENSE](https://github.com/waftester/waftester/blob/main/LICENSE) for full terms.

Community payloads are licensed under [MIT](https://github.com/waftester/waftester/blob/main/LICENSE-COMMUNITY).

## Links

- [GitHub](https://github.com/waftester/waftester)
- [Documentation](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md)
- [Changelog](https://github.com/waftester/waftester/blob/main/CHANGELOG.md)
- [Issues](https://github.com/waftester/waftester/issues)
