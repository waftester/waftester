# WAFtester Command Reference

The definitive reference for every WAFtester CLI command, flag, environment variable, and output option. Each command section includes its aliases, a description of what it does and when to use it, a complete flag table with types and defaults, and practical examples.

For usage examples and real-world workflows, see the [Examples Guide](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md). For installation, see the [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md). For a quick task-oriented reference, see the [Cheat Sheet](https://waftester.com/cheat-sheet).

**Document Version:** 2.9.38
**Last Updated:** February 2026

> **Reading order:** This is the flag reference. For real-world examples, see [EXAMPLES.md](EXAMPLES.md). For a quick copy-paste reference, see the [Cheat Sheet](https://waftester.com/cheat-sheet). For a beginner guide, see [waftester.com/docs](https://waftester.com/docs).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Which Command Should I Use?](#which-command-should-i-use)
- [How Commands Relate](#how-commands-relate)
- [Usage](#usage)
- [Global Options](#global-options)
- [Environment Variables](#environment-variables)
- [Glossary](#glossary)
- **Core Scanning**
  - [auto](#auto) — Autonomous full-spectrum assessment
  - [scan](#scan) — Targeted vulnerability scanning
  - [run](#run) — Test plan execution
- **Bypass and Evasion**
  - [bypass](#bypass) — WAF bypass discovery
  - [mutate](#mutate) — Payload mutation engine
  - [tampers](#tampers) — Tamper technique management
- **Assessment**
  - [assess](#assess) — WAF assessment and benchmarking
  - [fp](#fp) — False positive testing
  - [vendor](#vendor) — WAF vendor detection
- **Discovery and Recon**
  - [probe](#probe) — HTTP probing and fingerprinting
  - [crawl](#crawl) — Web crawling with JS support
  - [discover](#discover) — Endpoint discovery
  - [learn](#learn) — Test plan generation
  - [analyze](#analyze) — JavaScript analysis
  - [headless](#headless) — Headless browser testing
- **Protocol Testing**
  - [protocol](#protocol) — Protocol detection
  - [template](#template) — Nuclei template scanning
  - [smuggle](#smuggle) — HTTP request smuggling
  - [race](#race) — Race condition testing
  - [openapi](#openapi) — ~~Removed~~ (use `scan --spec` instead)
  - [grpc](#grpc) — gRPC service testing
  - [soap](#soap) — SOAP/WSDL service testing
- **Utilities**
  - [fuzz](#fuzz) — Directory and parameter fuzzing
  - [workflow](#workflow) — YAML workflow orchestration
  - [cloud](#cloud) — Cloud infrastructure discovery
  - [cicd](#cicd) — CI/CD pipeline generation
  - [plugin](#plugin) — Plugin management
  - [mcp](#mcp) — Model Context Protocol server
  - [validate](#validate) — Payload and spec validation
  - [validate-templates](#validate-templates) — Template validation
  - [compare](#compare) — Compare two scan result JSON files
  - [report](#report) — Enterprise HTML report generation
  - [update](#update) — Payload updater
- [Understanding Matchers and Filters](#understanding-matchers-and-filters)
- [Recommended Flag Combinations](#recommended-flag-combinations)
- [Performance and Footprint](#performance-and-footprint)
- [Shared Flag Groups](#shared-flag-groups)
  - [Output Flags](#output-flags)
  - [Enterprise Integration Flags](#enterprise-integration-flags)
- [Attack Categories Reference](#attack-categories-reference)
- [Exit Codes](#exit-codes)
- [Flag Naming Notes](#flag-naming-notes)
- [See Also](#see-also)

---

## Quick Start

New to WAFtester? Start here.

```bash
# Install
npm install -g @waftester/cli

# Full automated audit (recommended for first use)
waftester auto -u https://target.com

# Quick scan for specific vulnerabilities
waftester scan -u https://target.com -types sqli,xss --smart
```

See the [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md) for all installation methods (Go, Homebrew, npm, Scoop, AUR, Docker, binary).

---

## Which Command Should I Use?

| Goal | Command | Description |
|------|---------|-------------|
| Full automated audit | [`auto`](#auto) | Runs discovery, scanning, bypass, assessment, and reporting in one pass |
| Test specific vulnerabilities | [`scan`](#scan) | Targeted scanning with control over attack types and output |
| Find WAF bypasses | [`bypass`](#bypass) | Discovers payloads that evade WAF rules |
| Benchmark WAF effectiveness | [`assess`](#assess) | F1 scores, detection rates, and false positive analysis |
| Discover endpoints first, then scan | [`discover`](#discover) → [`learn`](#learn) → [`run`](#run) | Three-step workflow: map target, generate test plan, execute |
| Fuzz directories or parameters | [`fuzz`](#fuzz) | ffuf-compatible directory and parameter fuzzing |
| Identify the WAF vendor | [`vendor`](#vendor) | Detects WAF product from 198+ signatures |
| Scan an API spec | [`scan --spec`](#scan) | OpenAPI, Swagger, Postman, HAR, AsyncAPI, gRPC, GraphQL |
| Run in CI/CD | [`cicd`](#cicd) | Generates pipeline configs for GitHub Actions, GitLab CI, Azure DevOps |
| Connect to AI agents | [`mcp`](#mcp) | MCP server for Claude, Copilot, Cursor, n8n |
| Compare before/after scans | [`compare`](#compare) | Severity deltas, new/fixed categories, WAF vendor changes |

---

## How Commands Relate

Commands are not isolated — they feed into each other. This diagram shows the most common data flows:

```
                       +-----------+
                       |  vendor   |  Identify WAF
                       +-----+-----+
                             |  informs tamper selection
                             v
+----------+  endpoints  +-------+  test plan  +------+
| discover |------------>| learn |------------>| run  |
+----------+             +-------+             +------+
      |                                           |
      | feeds                                     | results
      v                                           v
+----------+                                +---------+
|  crawl   |                                | report  |
+----------+                                +---------+

+----------+  does all of the above in one pass
|   auto   |--> vendor -> discover -> scan -> assess -> report
+----------+

+----------+  bypass payloads   +----------+
|  bypass  |<------------------>| tampers  |
+----------+  tamper transforms +----------+
      |
      | variants
      v
+----------+
|  mutate  |  Expand payload space
+----------+
```

**Shortcut:** If you don't know where to start, use `auto`. It runs the entire pipeline.

---

## Usage

```
waftester <command> [flags]
```

When no command is specified, `run` is used as the default. Commands accept flags with a single dash (`-flag`) or double dash (`--flag`); both forms are equivalent. Boolean flags can be negated with `--flag=false`. Multi-value flags (e.g., `-header`) can be repeated.

## Global Options

These options are available regardless of which command is invoked.

| Flag | Description |
|------|-------------|
| `-v`, `--version`, `version` | Print version and exit |
| `-h`, `--help`, `help` | Print usage summary |
| `docs`, `doc`, `man`, `manual` | Print detailed built-in documentation |

## Environment Variables

Environment variables override flag defaults. They are useful for CI/CD or Docker environments where flags would be repetitive. All variables use the `WAF_TESTER_` prefix (except the legacy `WAFTESTER_INTEGRATION`).

| Variable | Description |
|----------|-------------|
| `WAF_TESTER_PAYLOAD_DIR` | Override default payload directory (`./payloads`). Used by the CLI, npm shim, and MCP server. |
| `WAF_TESTER_PRESET_DIR` | Override default service preset directory (`./presets`). Used by discovery and MCP server. |
| `WAF_TESTER_TEMPLATE_DIR` | Override default Nuclei template directory (`./templates/nuclei`). Used by scan, template, and MCP commands. |
| `WAF_TESTER_HTTP_ADDR` | Default HTTP listen address for the MCP server when `--http` is not specified. |
| `WAF_TESTER_BINARY_PATH` | Override the resolved binary path. Primarily used by the npm shim for development or custom installations. |
| `WAFTESTER_INTEGRATION` | Set to any non-empty value to enable integration tests that make real HTTP requests. Test suite only. |

---

## Glossary

Key terms used throughout this reference:

| Term | Meaning |
|------|---------|
| **Auto-calibrate** | Automatically determines baseline response characteristics (size, word count, status code) and excludes noise from results. Use `-ac` to enable. |
| **Bypass** | A payload that reaches the application without being blocked by the WAF. This is what you are testing for. |
| **Chain mode** | Applies multiple mutation transforms sequentially to a single payload, exponentially expanding the payload space. |
| **Evasion** | A technique that transforms a payload to avoid WAF pattern matching while preserving its attack semantics. |
| **F1 score** | Harmonic mean of precision and recall. Ranges from 0 to 1. Higher is better. An F1 of 0.95 means the WAF catches most attacks with few false positives. |
| **False positive (FP)** | A legitimate request that the WAF incorrectly blocks. High FP rates break real users. |
| **Filter** | Excludes responses matching criteria from results. The inverse of a matcher. |
| **FUZZ keyword** | A placeholder in URLs, headers, or body. WAFtester substitutes each wordlist entry at this position. |
| **Matcher** | Selects responses that meet criteria (status code, size, regex). Only matched responses appear in output. |
| **MCC** | Matthews Correlation Coefficient. A balanced metric that accounts for true/false positives/negatives. Ranges from -1 to +1. Above 0.8 is strong. |
| **Mutation** | A transformation applied to a payload: encoding (base64, URL, hex), case changes, comment injection, null bytes, etc. |
| **Paranoia level** | Controls how aggressive the test corpus is, corresponding to ModSecurity CRS paranoia levels (1-4). Higher = more edge cases, more traffic. |
| **Realistic mode** | Sends browser-like headers (Accept, Accept-Language, Referer, realistic User-Agent) to mimic organic traffic and avoid bot detection. |
| **Smart mode** | WAF-aware adaptive scanning that detects blocking patterns and adjusts payloads, timing, and evasion techniques automatically. |
| **Tamper** | A named transformation technique (e.g., `space2comment`, `between`, `urlenc`) that modifies payloads to evade WAF rules. Written as `.tengo` scripts. |
| **TPR** | True Positive Rate (recall). The percentage of attack payloads correctly blocked by the WAF. |

---

## Commands

### `auto`

**Aliases:** `superpower`, `sp`

The most powerful command in WAFtester. Runs a multi-phase autonomous assessment that chains together endpoint discovery, leaky path detection, parameter mining, WAF vendor fingerprinting, smart tamper selection, 2,800+ payload testing with adaptive rate limiting, false-positive assessment, and browser-based validation into a single invocation. An AI "brain" coordinates phases, learns from responses, and adjusts strategy in real time.

Results are written to a workspace directory containing JSON, Markdown, and HTML reports. Use `--resume` to continue an interrupted scan from the last checkpoint.

**When to use:** You want a single command that does everything. Ideal for first-time assessments, CI/CD pipelines, and hands-off security audits.

**When NOT to use:** On production systems without `--smart-mode=stealth` and a conservative rate limit. The default mode sends 2,800+ payloads at 200 req/s, which can trigger WAF bans, alert SOC teams, or degrade application performance. Use `scan` with a narrow `-types` filter when you only need to test specific categories.

#### Target

Specify one or more URLs to scan. At least one target is required.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | File containing target URLs |
| `-stdin` | | bool | false | Read targets from stdin |

#### Core

Controls concurrency, rate limiting, timeouts, and the workspace output. These settings directly affect scan speed and stealth.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-service` | string | | Service type hint for payload selection (e.g., `wordpress`, `api`, `spa`) |
| `-payloads` | string | `./payloads` | Payload directory |
| `-c` | int | 50 | Concurrent workers |
| `-rl` | int | 200 | Rate limit (requests/second) |
| `-timeout` | int | 10 | Request timeout in seconds |
| `-skip-verify` | bool | false | Skip TLS certificate verification |
| `-depth` | int | 3 | Crawl depth for endpoint discovery |
| `-output-dir` | string | | Workspace output directory |
| `-v` | bool | false | Verbose output |
| `-no-clean` | bool | false | Preserve workspace directory after scan |
| `-dry-run` | bool | false | Preview scan plan without executing |
| `-yes` | bool | false | Skip interactive confirmations |
| `-scan-config` | string | | Scan configuration file |

#### Smart Mode

Smart mode adapts scanning behavior based on detected WAF responses. It analyzes blocking patterns and adjusts payloads, timing, and evasion techniques to maximize coverage while minimizing detection.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-smart` | bool | false | Enable WAF-aware adaptive scanning |
| `-smart-mode` | string | `standard` | Smart mode profile: `quick` (fast validation), `standard` (balanced), `full` (maximum coverage), `bypass` (focus on finding bypasses), `stealth` (slow, minimal footprint) |
| `-smart-verbose` | bool | false | Show smart mode decision details |

#### Tamper Engine

Tamper techniques transform payloads to evade WAF pattern matching. Techniques include encoding variants, comment injection, case manipulation, whitespace substitution, and protocol-level tricks. Use `--tamper-auto` to let WAFtester pick the best tampers for the detected WAF.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-tamper` | string | | Comma-separated tamper techniques (e.g., `space2comment,between`) |
| `-tamper-auto` | bool | false | Auto-select tampers based on detected WAF vendor |
| `-tamper-profile` | string | `standard` | Tamper profile: `stealth` (minimal transforms), `standard` (common bypasses), `aggressive` (heavy encoding), `bypass` (all techniques) |
| `-tamper-dir` | string | | Directory of custom `.tengo` script tampers to load before the scan |

#### Phases

The auto command runs multiple phases sequentially. These flags control which phases execute. Disable phases you don't need to speed up the scan.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-assess` | bool | true | Run assessment phase (F1, MCC, FPR metrics) |
| `-assess-corpus` | string | `builtin,leipzig` | False positive corpus for assessment |
| `-leaky-paths` | bool | true | Check for exposed sensitive paths |
| `-leaky-categories` | string | | Leaky path categories to check |
| `-discover-params` | bool | true | Discover hidden parameters |
| `-param-wordlist` | string | | Custom parameter discovery wordlist |
| `-full-recon` | bool | false | Full reconnaissance pass |
| `-browser` | bool | true | Run browser-based validation phase |
| `-browser-headless` | bool | false | Run browser in headless mode |
| `-browser-timeout` | duration | | Browser action timeout |
| `-no-detect` | bool | false | Skip WAF vendor detection |

#### Brain

The brain is an AI coordination layer that observes scan results in real time, identifies patterns (e.g., which payloads get blocked vs. pass), and adjusts the scan strategy. It recommends focus areas, suggests tamper switches, and detects anomalous WAF behavior.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-brain` | bool | true | Enable AI-powered scan intelligence |
| `-brain-verbose` | bool | false | Show brain reasoning output (recommendations, learning events) |

#### Resume

The auto command writes checkpoints after each phase. If a scan is interrupted (Ctrl+C, timeout, crash), use `--resume` to pick up from the last completed phase without re-running earlier work.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-resume` | bool | false | Resume scan from last checkpoint |
| `-checkpoint` | string | | Explicit checkpoint file path (default: auto-detected from workspace) |

#### Scan Control

Fine-grained control over what gets tested and how aggressively.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-intensity` | string | `normal` | Scan intensity level |
| `-group` | string | | Test group filter |
| `-skip-group` | string | | Skip specific test groups |
| `-adaptive-rate` | bool | true | Enable adaptive rate limiting |
| `-ja3-rotate` | bool | false | Rotate JA3 TLS fingerprints |
| `-ja3-profile` | string | | Specific JA3 profile |
| `-report-formats` | string | `json,md,html` | Output report formats |

#### API Spec

Drive the scan from an API specification file. WAFtester parses endpoints, parameters, schemas, and authentication requirements from the spec and generates targeted test payloads. Supports OpenAPI 3.x, Swagger 2.0, Postman Collections, HAR files, AsyncAPI, GraphQL schemas, and gRPC reflection.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-spec` | string | | API spec file path (OpenAPI, Swagger, Postman, HAR, AsyncAPI, GraphQL, gRPC) |
| `-spec-url` | string | | API spec URL (fetched at runtime) |

Plus the full set of [output flags](#output-flags) and [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Full autonomous assessment
waftester auto -u https://target.com

# With smart tamper selection
waftester auto -u https://target.com --smart --tamper-auto

# Custom tampers + increased rate
waftester auto -u https://target.com --tamper-dir=./my-tampers -rl 500

# Resume interrupted scan
waftester auto -u https://target.com --resume

# API spec-driven assessment
waftester auto -u https://api.example.com --spec openapi.yaml
```

---

### `scan`

Targeted vulnerability scanning across 50+ attack categories including SQL injection, XSS, SSTI, SSRF, LFI, RFI, command injection, LDAP injection, NoSQL injection, prototype pollution, CRLF injection, XXE, and more. Each category uses curated payloads with WAF-specific evasion variants.

Unlike `auto`, the `scan` command gives you direct control over which attack types to run, how results are filtered, and how output is formatted. It does not run discovery or assessment phases.

**When to use:** You know what you want to test and need precise control. Ideal for targeted scans, regression testing, and integration into custom scripts.

**When NOT to use:** Against targets you do not own or have written authorization to test. Even with `-types` limiting the scope, every payload is a real attack attempt that will appear in server and WAF logs.

#### Target

Specify one or more URLs to scan. Targets can also be read from a file or piped via stdin.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list file |
| `-stdin` | | bool | false | Read targets from stdin |

#### Core

Configure what gets scanned, how fast, and where results go.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-types` | `-t` | string | `all` | Attack types to run (comma-separated, e.g., `sqli,xss,ssti,cmdi`) |
| `-concurrency` | | int | 5 | Concurrent requests |
| `-timeout` | | int | 30 | Request timeout in seconds |
| `-skip-verify` | | bool | false | Skip TLS verification |
| `-verbose` | | bool | false | Verbose output |
| `-output` | | string | | Output file |
| `-json` | | bool | false | JSON output format |
| `-payloads` | | string | `./payloads` | Payload directory |
| `-template-dir` | | string | `./templates/nuclei` | Template directory |

#### Smart Mode

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-smart` | bool | false | Smart WAF-adaptive mode |
| `-smart-mode` | string | `standard` | Smart profile |
| `-smart-verbose` | bool | false | Smart mode details |

#### Tamper Engine

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-tamper` | string | | Tamper techniques |
| `-tamper-auto` | bool | false | Auto-select tampers |
| `-tamper-profile` | string | `standard` | Tamper profile |
| `-tamper-dir` | string | | Custom `.tengo` tamper directory |

#### Rate Limiting

Controls request throughput to avoid triggering rate-based WAF bans or overwhelming the target. Use `-delay` and `-jitter` for randomized spacing that mimics organic traffic.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-rate-limit` | `-rl` | int | 50 | Requests per second |
| `-rate-limit-per-host` | `-rlph` | bool | false | Apply rate limit per host |
| `-delay` | | duration | 0 | Delay between requests |
| `-jitter` | | duration | 0 | Random jitter added to delay |

#### Request

Customize HTTP request properties. Use `-proxy` to route through Burp Suite or ZAP for inspection. Headers and cookies are applied to every request.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-proxy` | `-x` | string | | Proxy URL (HTTP/HTTPS/SOCKS4/SOCKS5) |
| `-user-agent` | `-ua` | string | | Custom User-Agent header |
| `-random-agent` | `-ra` | bool | false | Randomize User-Agent |
| `-header` | `-H` | string[] | | Custom headers (repeatable) |
| `-cookie` | `-b` | string | | Cookie string |
| `-retries` | `-r` | int | 2 | Retry count on failure |
| `-max-errors` | `-me` | int | 10 | Max errors before stopping |
| `-follow-redirects` | `-fr` | bool | true | Follow HTTP redirects |
| `-max-redirects` | | int | 10 | Maximum redirect chain length |
| `-respect-robots` | `-rr` | bool | false | Respect robots.txt directives |

#### OAuth

OAuth 2.0 authentication for scanning protected endpoints. WAFtester handles the token exchange automatically.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-oauth-client-id` | string | | OAuth client ID |
| `-oauth-auth-endpoint` | string | | OAuth authorization endpoint |
| `-oauth-token-endpoint` | string | | OAuth token endpoint |
| `-oauth-redirect-uri` | string | | OAuth redirect URI |

#### Filtering

Narrow scan scope or results. Match flags select only results meeting criteria. Filter flags exclude results meeting criteria. Combine both for precise targeting.

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-match-severity` | `-msev` | string | Match by severity level (critical, high, medium, low, info) |
| `-filter-severity` | `-fsev` | string | Filter out severity level |
| `-match-category` | `-mcat` | string | Match by attack category |
| `-filter-category` | `-fcat` | string | Filter out category |
| `-stop-on-first` | `-sof` | bool | Stop after first finding |
| `-exclude-types` | `-et` | string | Exclude attack types |
| `-exclude-patterns` | `-ep` | string | Exclude URL patterns |
| `-include-patterns` | `-ip` | string | Include only matching URLs |

#### Output Format

Control how results are displayed. For file exports (SARIF, JUnit, etc.), see [output flags](#output-flags).

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-format` | | string | `console` | Output format (`console`, `json`, `jsonl`, `csv`, `md`, `html`) |
| `-sarif` | | bool | false | SARIF output |
| `-md` | | bool | false | Markdown output |
| `-html` | | bool | false | HTML output |
| `-csv` | | bool | false | CSV output |
| `-silent` | `-s`, `-q` | bool | false | Suppress all output except results |
| `-no-color` | `-nc` | bool | false | Disable colored output |
| `-stream` | | bool | false | Stream results in real-time |
| `-timestamp` | `-ts` | bool | false | Add timestamps to vulnerability output |

#### Report

Metadata for generated reports. These values appear in report headers and footers.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-report-title` | string | | Custom report title |
| `-report-author` | string | | Report author name |
| `-include-evidence` | bool | true | Include evidence in reports |
| `-include-remediation` | bool | true | Include remediation guidance |

#### Scan Control

Limit scan scope, resume interrupted scans, or preview the test plan without executing.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-max-payloads` | `-mp` | int | 0 | Maximum payloads per type (0 = unlimited) |
| `-max-params` | | int | 0 | Maximum parameters to test (0 = unlimited) |
| `-resume` | | bool | false | Resume from checkpoint |
| `-checkpoint` | `-cp` | string | | Checkpoint file |
| `-dry-run` | `-dr` | bool | false | Preview without executing |
| `-no-detect` | | bool | false | Skip WAF detection |

#### Debug

Diagnostic flags for troubleshooting scan behavior. CPU and memory profiling write pprof files for `go tool pprof` analysis.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-debug` | | bool | false | Debug mode |
| `-debug-request` | `-dreq` | bool | false | Print raw requests |
| `-debug-response` | `-dresp` | bool | false | Print raw responses |
| `-profile` | | bool | false | CPU profiling |
| `-mem-profile` | | bool | false | Memory profiling |

#### API Spec

| Flag | Type | Description |
|------|------|-------------|
| `-spec` | string | API spec file |
| `-spec-url` | string | API spec URL |

Plus [output flags](#output-flags) and [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Scan for SQL injection and XSS
waftester scan -u https://target.com -types sqli,xss

# Full scan with smart mode
waftester scan -u https://target.com --smart --tamper-auto

# Custom tampers from a directory
waftester scan -u https://target.com --tamper-dir=./my-tampers

# With proxy and custom headers
waftester scan -u https://target.com -x http://127.0.0.1:8080 -H "Authorization: Bearer token"

# Multiple targets from file
waftester scan -l targets.txt -types all --json -o results.json
```

**Related:** [`auto`](#auto) (hands-off automated scanning), [`bypass`](#bypass) (find WAF bypasses), [`assess`](#assess) (WAF effectiveness benchmarking). For API spec scanning, use the `--spec` flag or see the [API Spec Scanning Guide](https://github.com/waftester/waftester/blob/main/docs/API-SPEC-SCANNING.md).

---

### `run`

The low-level test runner and the default command when no subcommand is provided. Executes test plans generated by `learn` or runs ad-hoc scans with full control over mutation engines, matchers, and filters.

The `run` command is heavily inspired by `ffuf` and `nuclei` workflows. It supports response matching (by status code, size, word count, line count, regex), response filtering, auto-calibration, mutations (encoding, chaining, evasion), and proxy replay for seamless integration with Burp Suite or ZAP.

**When to use:** You have a test plan from `discover`/`learn`, want mutation control, or need matcher/filter logic similar to `ffuf`.

#### Target

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list file |
| `-plan` | | string | | Test plan file (JSON) |
| `-stdin` | | bool | false | Read targets from stdin |

#### Core

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-concurrency` | `-c` | int | varies | Concurrent workers |
| `-rate-limit` | `-rl` | int | varies | Rate limit (req/s) |
| `-retries` | | int | 1 | Retry count |
| `-payloads` | `-p` | string | `./payloads` | Payload directory |
| `-category` | `-cat` | string | | Attack category filter |
| `-severity` | | string | | Severity filter |
| `-dry-run` | | bool | false | Preview without executing |

#### Mutation

The mutation engine transforms payloads through encoders (base64, URL, HTML entity, hex, etc.), injection locations (query, body, header, path, fragment), and evasion techniques (case randomization, comment insertion, null bytes). Chain mode applies multiple transforms sequentially, exponentially expanding the payload space.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-mutation` | `-m` | string | `none` | Mutation mode (`none`, `quick`, `full`, `exhaustive`) |
| `-encoders` | | string | | Encoders to apply |
| `-locations` | | string | | Injection locations |
| `-evasions` | | string | | Evasion techniques |
| `-chain` | | bool | false | Chain mutations |
| `-max-chain` | | int | 2 | Maximum chain depth |

#### Matchers

Matchers select responses that meet criteria. Only matched responses appear in output. Use `-auto-calibrate` to automatically determine baseline response characteristics and filter noise.

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-match-code` | `-mc` | string | Match HTTP status codes (e.g., `200,403`, `200-299`) |
| `-match-size` | `-ms` | string | Match response size |
| `-match-words` | `-mw` | string | Match word count |
| `-match-lines` | `-ml` | string | Match line count |
| `-match-regex` | `-mr` | string | Match by regex pattern |
| `-auto-calibrate` | `-ac` | bool | Auto-calibrate matchers |

#### Filters

Filters exclude responses that match criteria. The inverse of matchers. Combine matchers and filters for precise result selection.

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-filter-code` | `-fc` | string | Filter out status codes (e.g., `404,500`) |
| `-filter-size` | `-fs` | string | Filter by response size |
| `-filter-words` | `-fw` | string | Filter by word count |
| `-filter-lines` | `-fl` | string | Filter by line count |
| `-filter-regex` | `-fr` | string | Filter by regex |

#### Output

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-output` | `-o` | string | | Output file |
| `-format` | | string | `console` | Output format |
| `-jsonl` | `-j` | bool | false | JSONL output |
| `-verbose` | `-v` | bool | false | Verbose output |
| `-silent` | `-s` | bool | false | Silent mode |
| `-no-color` | `-nc` | bool | false | No colored output |
| `-stats` | | bool | false | Show live stats |
| `-stats-interval` | | int | 5 | Stats refresh interval (seconds) |
| `-noninteractive` | `-ni` | bool | false | Non-interactive mode |
| `-store-response` | `-sr` | bool | false | Store raw responses to disk |
| `-store-response-dir` | `-srd` | string | `responses` | Response storage directory |
| `-timestamp` | `-ts` | bool | false | Add timestamps to output |

#### Network

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-proxy` | `-x` | string | | Proxy URL |
| `-replay-proxy` | `-rp` | string | | Replay proxy for findings |
| `-sni` | | string | | Override TLS SNI hostname |
| `-burp` | | bool | false | Use Burp Suite proxy shortcut |
| `-zap` | | bool | false | Use OWASP ZAP proxy shortcut |
| `-skip-verify` | `-k` | bool | false | Skip TLS verification |
| `-realistic` | `-R` | bool | false | Realistic mode (browser-like behavior) |
| `-detect` | | bool | true | WAF detection |

#### Examples

```bash
# Execute a test plan
waftester run --plan testplan.json -u https://target.com

# Quick scan with mutation
waftester run -u https://target.com -m quick --chain

# Match specific status codes
waftester run -u https://target.com -mc 200,403 -fc 404

# Store responses for analysis
waftester run -u https://target.com -sr -srd ./responses
```

**Related:** [`discover`](#discover) → [`learn`](#learn) → `run` (three-step workflow). For simpler scanning, use [`scan`](#scan) instead.

---

### `bypass`

Dedicated WAF bypass finder. Sends the full payload library against a target and identifies which payloads bypass the WAF (i.e., reach the application without being blocked). Results are ranked by confidence and categorized by attack type.

With `--smart` mode, the engine adapts in real time: it detects blocking patterns, switches tamper techniques, and focuses on the most promising bypass vectors.

**When to use:** You know a WAF is present and want to find what gets through. Pair with `tampers --discover` for maximum coverage.

**When NOT to use:** Without explicit authorization. Bypass payloads reach the application behind the WAF. If a payload succeeds, it has executed against the real application, not a sandbox.

**Related:** [`mutate`](#mutate) (payload mutation engine), [`tampers`](#tampers) (tamper technique management), [`vendor`](#vendor) (identify the WAF first)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target`, `-u` | | string | | Target URL |
| `-payloads` | | string | `./payloads` | Payload directory |
| `-category` | | string | `injection` | Attack category |
| `-c` | | int | 10 | Concurrent requests |
| `-o` | | string | `bypasses.json` | Output file |
| `-k` | | bool | false | Skip TLS verification |
| `-stream` | | bool | false | Stream results |
| `-realistic` | `-R` | bool | false | Realistic mode |
| `-ac` | | bool | false | Auto-calibrate |
| `-smart` | | bool | false | Smart WAF-adaptive mode |
| `-smart-mode` | | string | `bypass` | Smart profile |
| `-smart-verbose` | | bool | false | Smart mode details |
| `-no-detect` | | bool | false | Skip WAF detection |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Find bypass payloads for injection attacks
waftester bypass -u https://target.com

# Smart bypass with auto-calibration
waftester bypass -u https://target.com --smart -ac

# Category-specific bypass
waftester bypass -u https://target.com --category xss
```

---

### `mutate`

Payload mutation engine. Takes a set of payloads and generates variants by applying encoders (base64, URL, HTML entity, double-URL, hex, unicode), evasion techniques (case randomization, whitespace tricks, comment injection, null byte insertion), and injection location permutations (query string, POST body, headers, URL path, fragment).

Chain mode applies multiple transforms sequentially, producing an exponential payload space useful for deep WAF rule-set testing.

**When to use:** You want to expand a payload set to test WAF rule coverage, or need to generate evasion variants of known bypasses.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target`, `-u` | | string | | Target URL |
| `-payloads` | | string | `./payloads` | Payload directory |
| `-category` | | string | | Attack category |
| `-payload-file` | | string | | Custom payload file |
| `-payload` | | string | | Single raw payload string |
| `-mode` | | string | `quick` | Mutation mode |
| `-encoders` | | string | | Encoders to apply |
| `-locations` | | string | | Injection locations |
| `-evasions` | | string | | Evasion techniques |
| `-chain` | | bool | false | Chain mutations |
| `-c` | | int | 10 | Concurrency |
| `-timeout` | | int | 10 | Timeout (seconds) |
| `-k` | | bool | false | Skip TLS |
| `-realistic` | `-R` | bool | false | Realistic mode |
| `-ac` | | bool | false | Auto-calibrate |
| `-smart` | | bool | false | Smart mode |
| `-smart-mode` | | string | | Smart profile |
| `-smart-verbose` | | bool | false | Smart verbose |
| `-o` | | string | | Output file |
| `-v` | | bool | false | Verbose |
| `-stats` | | bool | false | Show stats |
| `-dry-run` | | bool | false | Preview mutations |
| `-stream` | | bool | false | Stream results |
| `-no-detect` | | bool | false | Skip WAF detection |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Quick mutation scan
waftester mutate -u https://target.com --mode quick

# Full mutation with chaining
waftester mutate -u https://target.com --mode full --chain

# Mutate a single payload
waftester mutate --payload "<script>alert(1)</script>" --encoders base64,url
```

---

### `fuzz`

High-performance directory, file, and parameter fuzzer. Place the `FUZZ` keyword in the URL (or request body, headers) to mark the injection point. WAFtester substitutes each wordlist entry, sends the request, and applies matchers/filters to identify interesting responses.

Supports recursive directory discovery, file extension brute-forcing, multiple fuzzing modes (sniper, pitchfork, cluster bomb), and response extraction via regex or presets.

**When to use:** Directory discovery, parameter brute-forcing, virtual host enumeration, or any scenario where you need to iterate a wordlist against a URL pattern.

**When NOT to use:** With large wordlists against rate-limited or shared-hosting targets without throttling (`-rate`). A 100k-entry wordlist at full speed can trigger IP bans and affect other tenants on the same server.

#### Target

The `FUZZ` keyword marks where wordlist entries are substituted. Place it anywhere in the URL, path, query string, headers, or POST body.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) (use `FUZZ` as injection placeholder) |
| `-l` | | string | | Target list file |
| `-stdin` | | bool | false | Read stdin |

#### Wordlist

Wordlist source and transformation options. Apply prefixes, suffixes, case changes, or shuffling before fuzzing.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-w` | | string | | Wordlist file |
| `-wt` | | string | `directories` | Wordlist type |
| `-wmax` | | int | 0 | Max entries (0 = unlimited) |
| `-wskip` | | int | 0 | Skip first N entries |
| `-wshuffle` | | bool | false | Shuffle wordlist |
| `-wlower` | | bool | false | Lowercase all entries |
| `-wupper` | | bool | false | Uppercase all entries |
| `-wprefix` | | string | | Prefix each entry |
| `-wsuffix` | | string | | Suffix each entry |

#### Request

HTTP request configuration for fuzzing. Set methods, headers, cookies, extensions, rate limits, and threading.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-X` | | string | `GET` | HTTP method |
| `-d` | | string | | POST data |
| `-H` | | string | | Custom header |
| `-b` | | string | | Cookie |
| `-e` | | string | | File extensions (comma-separated) |
| `-t` | | int | 40 | Thread count |
| `-rate` | | int | 100 | Rate limit (req/s) |
| `-timeout` | | int | 10 | Request timeout |
| `-r` | | bool | false | Follow redirects |
| `-k` | | bool | false | Skip TLS |
| `-retries` | | int | 0 | Retries |
| `-delay` | | duration | 0 | Delay between requests |
| `-jitter` | | duration | 0 | Random jitter |

#### Matchers

Select responses that match criteria. Only matched responses appear in results. Use auto-calibrate (`-ac`) to automatically determine baseline characteristics and exclude noise.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-mc` | | string | `200,204,301,302,307,401,403,405` | Match status codes |
| `-ms` | | string | | Match response size |
| `-mw` | | string | | Match word count |
| `-ml` | | string | | Match line count |
| `-mr` | | string | | Match regex |
| `-ac` | | bool | false | Auto-calibrate matchers |
| `-calibration-words` | `-cw` | string | | Calibration words |

#### Filters

Exclude responses matching criteria. The inverse of matchers.

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-fc` | | string | Filter status codes |
| `-fs` | | string | Filter response size |
| `-fw` | | string | Filter word count |
| `-fl` | | string | Filter line count |
| `-fr` | | string | Filter regex |

#### Output

Control result display format and verbosity.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-csv` | | bool | false | CSV output |
| `-html-output` | | bool | false | HTML output |
| `-md` | | bool | false | Markdown |
| `-stream` | | bool | false | Stream results |
| `-s` | | bool | false | Silent mode |
| `-nc` | | bool | false | No color |
| `-verbose` | `-v` | bool | false | Verbose |
| `-timestamp` | `-ts` | bool | false | Timestamps |

#### Advanced

Recursive fuzzing, response storage, extraction, proxy, and debug options.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-recursion` | | bool | false | Enable recursive fuzzing |
| `-recursion-depth` | `-rd` | int | 2 | Maximum recursion depth |
| `-mode` | | string | `sniper` | Fuzzing mode |
| `-fuzz-position` | `-fp` | string | | Fuzz position marker |
| `-extract` | `-er` | string | | Extract regex from responses |
| `-extract-preset` | `-epr` | string | | Extraction preset |
| `-store-response` | `-sr` | bool | false | Store responses |
| `-store-response-dir` | `-srd` | string | `./responses` | Storage directory |
| `-store-only-matches` | `-som` | bool | false | Store only matching responses |
| `-proxy` | `-x` | string | | Proxy URL |
| `-debug` | | bool | false | Debug mode |
| `-debug-request` | `-dreq` | bool | false | Debug requests |
| `-debug-response` | `-dresp` | bool | false | Debug responses |
| `-no-detect` | | bool | false | Skip WAF detection |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Directory fuzzing
waftester fuzz -u https://target.com/FUZZ -w wordlist.txt

# Parameter fuzzing with extensions
waftester fuzz -u https://target.com/FUZZ -w words.txt -e php,asp,html

# Recursive directory discovery
waftester fuzz -u https://target.com/FUZZ -w dirs.txt --recursion -rd 3

# Filter 404s and match by size
waftester fuzz -u https://target.com/FUZZ -w words.txt -fc 404 -ms 1234
```

---

### `probe`

Multi-protocol HTTP probing and fingerprinting engine. For each target, `probe` performs TLS certificate analysis, JARM fingerprinting, technology detection (frameworks, CMS, languages), WAF identification, favicon hashing, CDN detection, HTTP/2 and WebSocket support checks, and DNS resolution.

Designed for processing large target lists efficiently. Pipe the output of subdomain enumeration tools directly into `probe` to quickly fingerprint an entire attack surface.

**When to use:** Asset inventory, technology mapping, WAF detection at scale, or pre-scan reconnaissance.

**Related:** [`vendor`](#vendor) (dedicated WAF detection), [`discover`](#discover) (endpoint discovery)

#### Target

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-list` | `-l` | string | | Target list file |
| `-stdin` | | bool | false | Read stdin |
| `-output-file` | `-o` | string | | Output file |

#### Probe Modules

Enable or disable individual probe modules. All are enabled by default. Disable modules you don't need to speed up large scans.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-tls` | bool | true | TLS certificate analysis |
| `-headers` | bool | true | HTTP header analysis |
| `-http` | bool | true | HTTP probe |
| `-waf` | bool | true | WAF detection |
| `-favicon` | bool | true | Favicon hash |
| `-jarm` | bool | true | JARM TLS fingerprint |
| `-tech` | bool | true | Technology detection |
| `-dns` | bool | true | DNS resolution |

#### Display Fields

Select which fields appear in output. By default, only the URL and status are shown. Enable additional fields to see server headers, technologies, IP addresses, CDN info, and more.

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-cl` | | bool | Content length |
| `-ct` | | bool | Content type |
| `-wc` | | bool | Word count |
| `-lc` | | bool | Line count |
| `-server` | | bool | Server header |
| `-method` | | bool | HTTP method |
| `-location` | | bool | Redirect location |
| `-title` | | bool | Page title |
| `-ip` | | bool | IP address |
| `-asn` | | bool | ASN information |
| `-cdn` | | bool | CDN detection |
| `-tech-detect` | `-td` | bool | Technologies |
| `-cname` | | bool | CNAME records |
| `-http2` | | bool | HTTP/2 support |
| `-pipeline` | | bool | Pipeline support |
| `-scheme` | | bool | URL scheme |
| `-websocket` | `-ws` | bool | WebSocket support |
| `-cpe` | | bool | CPE identifiers |
| `-wordpress` | `-wp` | bool | WordPress detection |
| `-favicon-hash` | | bool | Favicon hash value |
| `-header-hash` | | bool | Header hash |
| `-show-version` | | bool | Detected software version |
| `-stats` | | bool | Statistics |

#### Output Format

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-json` | `-j` | bool | false | JSON output |
| `-jsonl` | | bool | false | JSONL output |
| `-csv` | | bool | false | CSV output |
| `-silent` | | bool | false | Silent mode |
| `-1` | | bool | false | One-liner output |
| `-verbose` | `-v` | bool | false | Verbose |
| `-no-color` | `-nc` | bool | false | No color |

#### Request

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-x` | | string | `GET` | HTTP method |
| `-body` | | string | | Request body |
| `-H` | | string | | Custom headers |
| `-random-agent` | | bool | false | Random User-Agent |
| `-probe` | | bool | false | Probe mode |
| `-timeout` | | int | 10 | Timeout |
| `-c` | | int | 0 | Concurrency (0 = auto) |
| `-threads` | `-t` | int | 10 | Thread count |

#### Network

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-skip-verify` | `-k` | bool | false | Skip TLS |
| `-retries` | | int | 0 | Retries |
| `-delay` | | duration | 0 | Delay |
| `-rate-limit` | `-rl` | int | 0 | Rate limit |
| `-rate-limit-per-host` | `-rlph` | bool | false | Per-host rate limit |
| `-rate-limit-minute` | `-rlm` | int | 0 | Rate limit per minute |
| `-proxy` | | string | | Proxy |
| `-fr` | | bool | false | Follow redirects |
| `-max-redirects` | | int | 10 | Max redirects |

#### Matchers

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-match-code` | `-mc` | string | Match status code |
| `-match-string` | `-ms` | string | Match string in response |
| `-match-length` | `-ml` | string | Match content length |
| `-match-line-count` | `-mlc` | string | Match line count |
| `-match-word-count` | `-mwc` | string | Match word count |
| `-match-regex` | `-mr` | string | Match regex |
| `-match-favicon` | `-mfc` | string | Match favicon hash |
| `-match-cdn` | `-mcdn` | string | Match CDN |
| `-match-response-time` | `-mrt` | string | Match response time |

#### Filters

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-filter-code` | `-fc` | string | Filter status code |
| `-filter-string` | `-fs` | string | Filter string |
| `-filter-length` | `-fl` | string | Filter length |
| `-filter-line-count` | `-flc` | string | Filter line count |
| `-filter-word-count` | `-fwc` | string | Filter word count |
| `-filter-regex` | `-fe` | string | Filter regex |
| `-filter-favicon` | `-ffc` | string | Filter favicon |
| `-filter-cdn` | `-fcdn` | string | Filter CDN |
| `-filter-response-time` | `-frt` | string | Filter response time |
| `-filter-error-page` | `-fep` | bool | Filter error pages |
| `-filter-duplicates` | `-fd` | bool | Filter duplicates |

#### Extract

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-extract-regex` | `-er` | string | Extract regex |
| `-extract-preset` | `-ep` | string | Extraction preset |
| `-extract-fqdn` | `-efqdn` | bool | Extract FQDNs |

#### Storage

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-store-response` | `-sr` | bool | false | Store responses |
| `-store-response-dir` | `-srd` | string | `./responses` | Storage directory |
| `-store-chain` | | bool | false | Store redirect chains |

#### Output Control

Fine-tune what appears in probe results. Enable body previews, full response capture, or chain tracking for redirect analysis.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-body-preview` | `-bp` | int | 0 | Body preview bytes |
| `-output-all` | `-oa` | bool | false | Output all results |
| `-omit-body` | `-ob` | bool | false | Omit body |
| `-csv-output-encoding` | `-csvo` | string | `utf-8` | CSV encoding |
| `-include-response-header` | `-irh` | bool | false | Include headers |
| `-include-response` | `-irr` | bool | false | Include full response |
| `-include-response-base64` | `-irrb` | bool | false | Include base64 response |
| `-include-chain` | | bool | false | Include redirect chain |
| `-protocol` | `-pr` | string | | Protocol filter |
| `-list-output-fields` | `-lof` | bool | false | List available fields |
| `-exclude-output-fields` | `-eof` | string | | Exclude fields from output |
| `-strip` | | string | | Strip from output |

#### Advanced

Power-user flags for DNS resolution, TLS analysis, VHost enumeration, and protocol-level inspection.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-config` | | string | | Config file |
| `-resolvers` | `-r` | string | | DNS resolvers |
| `-allow` | | string | | Allow list |
| `-deny` | | string | | Deny list |
| `-sni-name` | `-sni` | string | | SNI hostname |
| `-auto-referer` | | bool | false | Auto-set Referer header |
| `-unsafe` | | bool | false | Unsafe mode |
| `-resume` | | bool | false | Resume scan |
| `-follow-host-redirects` | `-fhr` | bool | false | Follow host redirects |
| `-respect-hsts` | `-rhsts` | bool | false | Respect HSTS |
| `-vhost-input` | | bool | false | VHost input mode |
| `-ports` | `-p` | string | | Ports to probe |
| `-path` | | string | | Path to append |
| `-probe-all-ips` | `-pa` | bool | false | Probe all resolved IPs |
| `-tls-probe` | | bool | false | TLS probe mode |
| `-csp-probe` | | bool | false | CSP probe mode |
| `-tls-grab` | | bool | false | Grab TLS certificate |
| `-vhost` | | bool | false | VHost mode |
| `-list-dsl-variables` | `-ldv` | bool | false | List DSL variables |
| `-no-stdin` | | bool | false | Disable stdin |
| `-secret-file` | `-sf` | string | | Secret file for matching |
| `-health-check` | `-hc` | bool | false | Health check mode |
| `-debug-req` | | bool | false | Debug requests |
| `-debug-resp` | | bool | false | Debug responses |
| `-stats-interval` | `-si` | int | 5 | Stats interval |
| `-trace` | `-tr` | bool | false | Request tracing |
| `-no-fallback` | `-nf` | bool | false | No fallback |
| `-no-fallback-scheme` | `-nfs` | bool | false | No fallback scheme |
| `-stream` | `-s` | bool | false | Streaming |
| `-skip-dedupe` | `-sd` | bool | false | Skip deduplication |
| `-leave-default-ports` | `-ldp` | bool | false | Keep default ports in URLs |
| `-ztls` | | bool | false | ZTLS mode |
| `-no-decode` | | bool | false | No URL decoding |
| `-tls-impersonate` | `-tlsi` | bool | false | TLS impersonation |
| `-debug` | | bool | false | Debug mode |
| `-hash` | | string | | Hash type |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Probe targets from a file
waftester probe -l urls.txt -json

# Show technology and server info
waftester probe -u https://target.com -td -server -title

# Filter by status code and extract FQDNs
waftester probe -l urls.txt -mc 200 -efqdn
```

---

### `crawl`

Recursive web crawler with content discovery, JavaScript analysis, and data extraction. Crawls a site to a configurable depth, following links and optionally rendering JavaScript to discover dynamically loaded content. Extracts forms, API endpoints, parameters, email addresses, HTML comments, and embedded secrets.

With JS rendering enabled, WAFtester launches a headless browser to execute client-side JavaScript, catching single-page app routes and AJAX endpoints that static crawlers miss.

**When to use:** Pre-scan reconnaissance, attack surface mapping, or feeding discovered endpoints into `scan` or `auto`.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list |
| `-stdin` | | bool | false | Read stdin |
| `-output` | | string | | Output file |
| `-depth` | | int | 3 | Maximum crawl depth |
| `-max-pages` | | int | 100 | Maximum pages |
| `-concurrency` | | int | 5 | Concurrency |
| `-timeout` | | int | 10 | Request timeout |
| `-delay` | | int | 0 | Delay between requests (ms) |
| `-include` | | string | | Include URL regex |
| `-exclude` | | string | | Exclude URL regex |
| `-subdomains` | | bool | false | Include subdomains |
| `-forms` | | bool | true | Extract forms |
| `-scripts` | | bool | true | Extract JavaScript |
| `-links` | `-el` | bool | true | Extract links |
| `-emails` | `-ee` | bool | false | Extract email addresses |
| `-comments` | `-ec` | bool | false | Extract HTML comments |
| `-endpoints` | `-eep` | bool | true | Extract API endpoints |
| `-params` | `-epa` | bool | true | Extract parameters |
| `-secrets` | `-es` | bool | false | Detect secrets |
| `-same-domain` | `-sd` | bool | true | Restrict to same domain |
| `-same-port` | `-sp` | bool | false | Restrict to same port |
| `-respect-robots` | `-rr` | bool | false | Respect robots.txt |
| `-respect-nofollow` | `-rnf` | bool | false | Respect nofollow |
| `-json` | | bool | false | JSON output |
| `-output-urls` | `-ou` | bool | false | Output URLs only |
| `-csv` | | bool | false | CSV |
| `-md` | | bool | false | Markdown |
| `-silent` | `-s` | bool | false | Silent |
| `-verbose` | `-v` | bool | false | Verbose |
| `-no-color` | `-nc` | bool | false | No color |
| `-proxy` | `-x` | string | | Proxy |
| `-skip-verify` | `-k` | bool | false | Skip TLS |
| `-user-agent` | `-ua` | string | | User-Agent |
| `-random-agent` | `-ra` | bool | false | Random UA |
| `-header` | `-H` | string | | Custom header |
| `-cookie` | `-b` | string | | Cookie |
| `-javascript` | `-js` | bool | false | Enable JS rendering |
| `-js-timeout` | `-jst` | int | 10 | JS render timeout |
| `-wait-for` | `-wf` | string | | Wait for CSS selector |
| `-resume` | | bool | false | Resume crawl |
| `-checkpoint` | `-cp` | string | | Checkpoint file |
| `-debug` | | bool | false | Debug |
| `-debug-request` | `-dreq` | bool | false | Debug requests |
| `-stream` | | bool | false | Stream results |
| `-no-detect` | | bool | false | Skip WAF detection |

#### Examples

```bash
# Crawl with depth 5
waftester crawl -u https://target.com --depth 5

# Crawl with JS rendering
waftester crawl -u https://target.com --js --endpoints --params

# Extract secrets and emails
waftester crawl -u https://target.com --secrets --emails --json
```

---

### `discover`

Automated service discovery and endpoint enumeration. Probes a target to identify API endpoints, query parameters, form fields, and service characteristics. The output feeds directly into `learn` to generate test plans.

Discovery combines passive analysis (HTML/JS parsing, link extraction) with active probing (common path checks, parameter detection) to build a target map. When a `-service` preset is specified, discovery also probes service-specific endpoints from the matching JSON preset file (see `presets/` directory).

**When to use:** Before `learn` + `run` workflows, or when you need a structured endpoint inventory for manual review.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list |
| `-stdin` | | bool | false | Read stdin |
| `-service` | | string | | Service preset name (loads `presets/<name>.json` for service-specific endpoints). Built-in: `authentik`, `n8n`, `immich`, `webapp`, `intranet`. Custom: add JSON to `presets/` directory. |
| `-output` | | string | `discovery.json` | Output file |
| `-timeout` | | int | 10 | Timeout |
| `-concurrency` | | int | 10 | Concurrency |
| `-depth` | | int | 3 | Discovery depth |
| `-skip-verify` | | bool | false | Skip TLS |
| `-verbose` | | bool | false | Verbose |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Discover endpoints
waftester discover -u https://target.com -o endpoints.json

# Deep discovery
waftester discover -u https://target.com --depth 5 --verbose

# Discover with service preset (adds known endpoints for the platform)
waftester discover -u https://sso.example.com -service authentik

# Custom preset directory
WAF_TESTER_PRESET_DIR=./my-presets waftester discover -u https://target.com -service myapp
```

**Related:** [`learn`](#learn) (generate test plan from discovery results) → [`run`](#run) (execute the test plan)

---

### `learn`

Test plan generator. Converts discovery results into executable test configurations for the `run` command. Selects attack types, payloads, and injection points based on discovered endpoints and parameters.

The generated test plan is a JSON file containing target URLs, parameter maps, payload selections, and matcher/filter rules. Edit the plan manually or feed it directly to `run`.

**When to use:** After `discover`, to create a reusable, auditable test plan. Useful for approval workflows where scans must be reviewed before execution.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list |
| `-stdin` | | bool | false | Read stdin |
| `-discovery` | | string | `discovery.json` | Discovery input file |
| `-payloads` | | string | `./payloads` | Payload directory |
| `-output` | | string | `testplan.json` | Output test plan file |
| `-custom-payloads` | | string | | Custom payload file |
| `-verbose` | | bool | false | Verbose |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Generate test plan from discovery
waftester learn -u https://target.com -o testplan.json

# Use custom payloads
waftester learn -u https://target.com --custom-payloads my-payloads.json
```

**Related:** [`discover`](#discover) (find endpoints first) → [`run`](#run) (execute the generated test plan)

---

### `analyze`

Static JavaScript analysis engine. Parses JavaScript files (local or remote) to extract URLs, API endpoints, hardcoded secrets (API keys, tokens, credentials), and DOM XSS sinks (`innerHTML`, `document.write`, `eval`). Works on minified and bundled code.

Contrast with `crawl --js`: the `analyze` command performs deep static analysis of individual JavaScript files, while `crawl` renders pages and discovers links dynamically.

**When to use:** Bug bounty recon, auditing client-side JavaScript for secrets and DOM sinks, or extracting hidden API endpoints from single-page app bundles.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) with JavaScript |
| `-l` | | string | | Target list |
| `-stdin` | | bool | false | Read stdin |
| `-file` | | string | | Local JavaScript file |
| `-output` | | string | | Output file |
| `-urls` | | bool | true | Extract URLs |
| `-endpoints` | | bool | true | Extract API endpoints |
| `-secrets` | | bool | true | Detect secrets |
| `-sinks` | | bool | true | Detect DOM sinks |
| `-json` | | bool | false | JSON output |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Analyze JavaScript from a target
waftester analyze -u https://target.com/app.js

# Analyze a local file
waftester analyze --file bundle.js --json

# Extract only endpoints and secrets
waftester analyze -u https://target.com --urls=false --sinks=false
```

---

### `headless`

Headless Chromium browser for interactive testing. Loads pages in a real browser environment with full JavaScript execution, captures screenshots, runs custom JS snippets, and performs DOM event crawling (clicking buttons, following dynamic links, interacting with forms).

DOM event crawling triggers JavaScript event handlers to discover application routes and functionality hidden behind user interactions. This finds endpoints that no static crawler or API spec can reveal.

**When to use:** Testing single-page applications, capturing visual evidence, executing custom JS payloads, or discovering functionality behind click handlers.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string | | Target URL |
| `-l` | | string | | Target list |
| `-chrome` | | string | | Chrome binary path |
| `-headless` | | bool | true | Run headless (no GUI) |
| `-timeout` | | int | 30 | Page load timeout |
| `-wait` | | int | 2 | Wait seconds after page load |
| `-screenshot` | | bool | false | Capture screenshots |
| `-screenshot-dir` | | string | `screenshots` | Screenshot directory |
| `-extract-urls` | | bool | true | Extract URLs from page |
| `-js` | | string | | JavaScript to execute |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |
| `-stream` | | bool | false | Stream results |
| `-event-crawl` | | bool | false | Enable DOM event crawling |
| `-max-clicks` | | int | 50 | Max click events during event crawl |
| `-click-timeout` | | int | 5 | Click timeout in seconds |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Basic headless browsing
waftester headless -u https://target.com --screenshot

# With JavaScript execution
waftester headless -u https://target.com --js "document.title"

# DOM event crawling
waftester headless -u https://target.com --event-crawl --max-clicks 100

# Multiple targets
waftester headless -l urls.txt --extract-urls --json
```

---

### `assess`

**Aliases:** `assessment`, `benchmark`

Quantitative WAF effectiveness measurement. Sends a curated mix of attack payloads and benign requests to compute detection accuracy (true positive rate, false positive rate), F1 score, and Matthews Correlation Coefficient (MCC). These metrics give an objective comparison between WAF products, rule sets, or configuration changes.

The assessment includes optional false-positive testing using a corpus of legitimate requests that frequently trigger WAF false positives (e.g., SQL-like usernames, legitimate HTML content).

**When to use:** WAF product evaluation, before/after rule change comparison, compliance evidence, or vendor benchmarking.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-c` | int | 25 | Concurrency |
| `-timeout` | int | 10 | Timeout |
| `-categories` | string | | Category filter |
| `-payloads` | string | `./payloads` | Payload directory |
| `-fp` | bool | true | Include false positive testing |
| `-corpus` | string | `builtin` | FP corpus source |
| `-custom-corpus` | string | | Custom FP corpus path |
| `-detect-waf` | bool | true | WAF detection |
| `-o` | string | | Output file |
| `-format` | string | `console` | Output format |
| `-v` | bool | false | Verbose |
| `-stream` | bool | false | Stream results |
| `-k` | bool | false | Skip TLS |
| `-no-detect` | bool | false | Skip WAF detection |

#### Examples

```bash
# Full assessment with false positive testing
waftester assess -u https://target.com -fp

# Assessment with custom corpus
waftester assess -u https://target.com --custom-corpus ./my-corpus.txt

# Category-specific assessment
waftester assess -u https://target.com --categories sqli,xss
```

---

### `fp`

**Aliases:** `falsepositive`, `false-positive`

Dedicated false positive testing. Sends a corpus of legitimate HTTP requests through the WAF and measures how many are incorrectly blocked. The built-in corpus covers common false-positive triggers: SQL-like usernames, HTML in user content, URLs containing path traversal-like patterns, and Unicode edge cases.

Paranoia levels (1-4) correspond to ModSecurity CRS paranoia levels, controlling how aggressive the test corpus is.

**When to use:** After WAF deployment or rule changes, to verify that legitimate traffic is not being blocked. Pairs with `assess` for a complete accuracy picture.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-c` | int | 5 | Concurrency |
| `-timeout` | int | 10 | Timeout |
| `-pl` | int | 2 | Paranoia level |
| `-corpus` | string | `all` | Corpus type |
| `-dynamic` | string | | Dynamic corpus |
| `-output` | string | | Output file |
| `-v` | bool | false | Verbose |
| `-stream` | bool | false | Stream results |
| `-local` | bool | false | Local mode |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# False positive test
waftester fp -u https://target.com

# High paranoia level
waftester fp -u https://target.com -pl 4

# Local mode with custom corpus
waftester fp -u https://target.com --local --corpus custom
```

---

### `vendor`

**Aliases:** `waf-detect`, `detect-waf`

WAF vendor detection and fingerprinting. Sends crafted requests and analyzes responses (headers, cookies, error pages, status codes, body content) to identify the WAF product from a database of 198 signatures. Detection covers cloud WAFs (Cloudflare, AWS WAF, Akamai, Azure Front Door, Imperva), CDN-integrated WAFs, and self-hosted solutions (ModSecurity, NAXSI).

Results inform tamper selection and evasion strategy. The `auto` command runs vendor detection automatically; use this command standalone when you only need identification.

**When to use:** Quick WAF identification before manual testing, or feeding results into `tampers --for-waf`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-timeout` | int | 10 | Timeout |
| `-output` | string | | Output file |
| `-autotune` | bool | false | Auto-tune detection sensitivity |
| `-hints` | bool | true | Show detection hints |
| `-list` | bool | false | List all known WAF vendors |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Detect WAF vendor
waftester vendor -u https://target.com

# Auto-tune detection
waftester vendor -u https://target.com --autotune

# List supported WAFs
waftester vendor --list
```

---

### `protocol`

**Alias:** `proto`

HTTP protocol support detection and analysis. Tests a target for HTTP/1.0, HTTP/1.1, HTTP/2 (h2, h2c), and HTTP/3 (QUIC) support, TLS versions, supported cipher suites, and protocol-level behaviors (keep-alive, pipelining, content negotiation). Useful for identifying protocol-level attack surfaces like HTTP/2 smuggling or downgrade attacks.

**When to use:** Pre-scan protocol reconnaissance, or before running `smuggle` to understand the target's protocol stack.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-u` | string | | Target URL |
| `-timeout` | int | 10 | Timeout |
| `-output` | string | | Output file |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Detect protocols
waftester protocol -u https://target.com
```

---

### `tampers`

**Alias:** `tamper`

Tamper technique management. Lists all available payload transformation techniques, recommends WAF-specific bypasses, tests transformations interactively, and discovers effective tampers automatically against a live target.

The discovery mode (`--discover`) sends tampered payloads to a target, measures which transformations bypass the WAF, confirms results across multiple rounds to eliminate false positives, and ranks the effective techniques.

**When to use:** Reviewing available tampers before a scan, getting WAF-specific recommendations, or discovering which transformations actually bypass a target WAF.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-list` | bool | false | List all tamper techniques |
| `-category` | string | | Filter by tamper category |
| `-for-waf` | string | | Show tampers effective for a specific WAF |
| `-test` | string | | Test payload to transform |
| `-tamper` | string | | Specific tamper to apply |
| `-matrix` | bool | false | Show evasion matrix |
| `-json` | bool | false | JSON output |
| `-discover` | bool | false | Discover effective bypass tampers against a target |
| `-target` | string | | Target URL for discovery |
| `-concurrency` | int | 5 | Discovery concurrency |
| `-top-n` | int | 5 | Number of top results to show |
| `-confirm` | int | 2 | Confirmation rounds for discovery |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# List all tampers
waftester tampers --list

# WAF-specific recommendations
waftester tampers --for-waf=cloudflare

# Test a payload with a tamper
waftester tampers --test "<script>alert(1)</script>" --tamper space2comment

# Show evasion matrix
waftester tampers --matrix

# Auto-discover bypass tampers
waftester tampers --discover --target https://target.com --top-n 10
```

---

### `template`

**Aliases:** `templates`, `nuclei`

Nuclei-compatible template scanner. Executes YAML-based vulnerability detection templates against targets. Templates define request patterns, matchers, and extractors for specific CVEs, misconfigurations, or technology fingerprints.

WAFtester ships with built-in templates and can load custom templates from a directory. Templates can be filtered by tags (e.g., `cve`, `sqli`, `misconfig`) and severity level.

**When to use:** CVE-specific scanning, running community detection templates, or building reproducible vulnerability checks as YAML files.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-target`, `-u` | string | | Target URL |
| `-l` | string | | Target list |
| `-t` | string | | Template file or glob |
| `-templates` | string | | Templates directory |
| `-tags` | string | | Template tags filter |
| `-severity` | string | | Severity filter |
| `-exclude-tags` | string | | Exclude tags |
| `-c` | int | 25 | Concurrency |
| `-rl` | int | 150 | Rate limit |
| `-timeout` | int | 10 | Timeout |
| `-retries` | int | 1 | Retries |
| `-o` | string | | Output file |
| `-json` | bool | false | JSON output |
| `-silent` | bool | false | Silent mode |
| `-v` | bool | false | Verbose |
| `-validate` | bool | false | Validate templates |
| `-enrich` | bool | false | Enrich templates with payload data |
| `-payloads` | string | `./payloads` | Payload directory |

#### Examples

```bash
# Scan with specific template
waftester template -u https://target.com -t templates/sqli-auth-bypass.yaml

# Scan with tag filter
waftester template -u https://target.com --tags cve,sqli --severity critical,high

# Validate templates
waftester template --validate -t ./templates/
```

#### Subcommands

The `template` command also supports positional subcommands for browsing bundled templates:

| Subcommand | Description |
|------------|-------------|
| `template list` | List all bundled template categories with counts |
| `template list <category>` | List templates in a category (e.g., `nuclei`, `policies`, `workflows`, `overrides`, `output`, `report-configs`) |
| `template show <category>/<name>` | Display template contents (e.g., `policies/strict`, `workflows/full-scan`) |

```bash
# List template categories
waftester template list

# List templates in a category
waftester template list policies

# Show a specific template
waftester template show policies/strict
waftester template show nuclei/http/waf-bypass/sqli-basic
```

---

### `smuggle`

HTTP request smuggling detection and exploitation testing. Tests for CL.TE, TE.CL, TE.TE, and H2.CL smuggling variants by sending ambiguous requests and analyzing how the target's frontend/backend infrastructure interprets them.

Safe mode (default) uses non-destructive timing-based probes that do not inject smuggled requests that could affect other users. Disable safe mode only in controlled environments.

**When to use:** Testing reverse proxy and CDN configurations for request smuggling vulnerabilities. Run `protocol` first to understand the target's HTTP stack.

**When NOT to use:** On shared infrastructure (CDNs, shared load balancers) without coordination. Smuggled requests can affect other users behind the same proxy. Keep safe mode enabled (the default) unless you are in an isolated test environment.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string | | Target URL |
| `-l` | | string | | Target list |
| `-safe` | | bool | true | Safe mode (non-destructive probes) |
| `-timeout` | | int | 10 | Timeout |
| `-delay` | | int | 1000 | Delay between probes (ms) |
| `-retries` | | int | 3 | Retries |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |
| `-stream` | | bool | false | Stream results |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Safe smuggling test
waftester smuggle -u https://target.com

# Full testing with longer delay
waftester smuggle -u https://target.com --safe=false --delay 2000
```

---

### `race`

Race condition testing for TOCTOU (time-of-check-time-of-use), double-submit, and limit-bypass vulnerabilities. Sends concurrent identical requests to detect business logic flaws where the application fails to handle simultaneous access correctly, such as processing a coupon code twice, exceeding account balance limits, or bypassing rate limiters.

**When to use:** Testing checkout flows, coupon redemption, vote/like counters, account balance transfers, or any endpoint where concurrent access could produce unintended results.

**When NOT to use:** Against live production checkout, payment, or financial endpoints without a test account. Race condition exploits can cause real financial transactions: double charges, duplicate orders, or balance manipulation. Always test in staging first.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string | | Target URL |
| `-method` | | string | `POST` | HTTP method |
| `-body` | | string | | Request body |
| `-H` | | string | | Custom header |
| `-attack` | | string | `double_submit` | Attack type |
| `-c` | | int | 50 | Concurrent requests |
| `-n` | | int | 1 | Iterations |
| `-timeout` | | int | 30 | Timeout |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Double-submit race test
waftester race -u https://target.com/checkout -c 100

# Custom body and method
waftester race -u https://target.com/api/transfer --method POST --body '{"amount":100}'
```

---

### `workflow`

YAML-based workflow orchestration. Define multi-step security testing pipelines as YAML files, chaining discovery, scanning, assessment, and reporting steps with conditional logic and variable substitution. Steps can depend on previous step outputs, enabling dynamic pipelines.

**When to use:** Repeatable multi-stage security audits, custom pipeline automation, or when `auto` mode does not fit your specific workflow.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-file` | `-f` | string | | Workflow YAML file |
| `-var` | | string | | Variables (`key=value`, repeatable) |
| `-dry-run` | | bool | false | Preview without executing |
| `-continue-on-error` | | bool | false | Continue on step failure |
| `-timeout` | | int | 300 | Workflow timeout (seconds) |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Execute a workflow
waftester workflow -f recon.yaml

# With variables
waftester workflow -f pipeline.yaml --var target=https://target.com --var depth=5

# Dry run
waftester workflow -f pipeline.yaml --dry-run
```

---

### `openapi`

**Aliases:** `openapi-fuzz`, `swagger`

> **Removed.** The standalone `openapi` command has been removed. Use `auto --spec` or `scan --spec` instead, which provide the same API spec scanning capabilities integrated with the full scanning pipeline.

```bash
# Replacement — scan an OpenAPI spec
waftester scan --spec openapi.yaml -u https://api.example.com

# Or with full auto assessment
waftester auto -u https://api.example.com --spec openapi.yaml
```

---

### `grpc`

**Alias:** `grpc-test`

gRPC service security testing. Uses gRPC server reflection to discover services and methods, then tests them with injection payloads, malformed protobuf messages, and type-confusion inputs. Supports listing services, calling individual methods, and automated fuzzing across all discovered endpoints.

**When to use:** Testing gRPC APIs (microservices, internal APIs). The target must support gRPC reflection, or you can provide the proto definitions.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-target`, `-u` | string | | gRPC target address |
| `-list` | bool | false | List gRPC services |
| `-describe` | string | | Describe a service |
| `-call` | string | | Call a specific method |
| `-fuzz` | bool | false | Fuzz services |
| `-d` | string | `{}` | Request data (JSON) |
| `-metadata` | string | | gRPC metadata |
| `-category` | string | `injection` | Attack category |
| `-payloads` | string | `./payloads` | Payload directory |
| `-template-dir` | string | `./templates/nuclei` | Template directory |
| `-timeout` | int | 30 | Timeout |
| `-o` | string | | Output file |
| `-json` | bool | false | JSON output |
| `-v` | bool | false | Verbose |

#### Examples

```bash
# List gRPC services
waftester grpc -u localhost:50051 --list

# Call a method
waftester grpc -u localhost:50051 --call UserService.GetUser -d '{"id": 1}'

# Fuzz gRPC services
waftester grpc -u localhost:50051 --fuzz --category injection
```

---

### `soap`

**Alias:** `wsdl`

SOAP/WSDL service security testing. Parses WSDL definitions to discover operations, generates SOAP envelopes for each operation, and tests for XXE (XML External Entity), XML injection, SSRF (via SOAP attributes), and command injection. Supports custom SOAPAction headers, namespace overrides, and request body templates.

**When to use:** Testing legacy SOAP/XML web services. For REST APIs, use `scan --spec` instead.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-endpoint`, `-u` | string | | SOAP endpoint URL |
| `-wsdl` | string | | WSDL URL |
| `-list` | bool | false | List operations |
| `-operation` | string | | Target operation |
| `-action` | string | | SOAPAction header |
| `-ns` | string | | Namespace |
| `-d` | string | | Request data |
| `-f` | string | | Request body from file |
| `-H` | string | | Custom header |
| `-fuzz` | bool | false | Fuzz operations |
| `-category` | string | `xxe` | Attack category |
| `-payloads` | string | | Payload directory |
| `-template-dir` | string | | Template directory |
| `-timeout` | int | 30 | Timeout |
| `-o` | string | | Output file |
| `-json` | bool | false | JSON output |
| `-v` | bool | false | Verbose |

#### Examples

```bash
# List SOAP operations
waftester soap --wsdl https://api.example.com?wsdl --list

# Fuzz a specific operation
waftester soap --wsdl https://api.example.com?wsdl --operation GetUser --fuzz

# Custom SOAP request
waftester soap -u https://api.example.com --action GetUser -f request.xml
```

---

### `cloud`

**Alias:** `cloud-discover`

Cloud infrastructure discovery and enumeration. Identifies exposed cloud resources (S3 buckets, Azure Blob containers, GCP Storage buckets), misconfigured permissions, and publicly accessible services across AWS, Azure, and GCP. Combines passive techniques (certificate transparency logs, DNS enumeration) with active brute-forcing using wordlists.

**When to use:** Attack surface discovery for organizations using cloud infrastructure. Run early in an engagement to find shadow IT and misconfigured storage.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-domain` | `-d` | string | | Target domain |
| `-org` | | string | | Organization name |
| `-providers` | | string | `all` | Cloud providers (`aws`, `azure`, `gcp`, or `all`) |
| `-types` | | string | `all` | Resource types |
| `-w` | | string | | Wordlist for brute-forcing |
| `-c` | | int | 50 | Concurrency |
| `-timeout` | | int | 10 | Timeout |
| `-passive` | | bool | false | Passive-only mode |
| `-ct` | | bool | true | Certificate transparency lookup |
| `-dns` | | bool | true | DNS enumeration |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |

#### Examples

```bash
# Discover cloud resources
waftester cloud -d example.com

# AWS-only with wordlist
waftester cloud -d example.com --providers aws -w wordlist.txt

# Passive-only recon
waftester cloud -d example.com --passive --json
```

---

### `cicd`

**Aliases:** `ci-cd`, `pipeline`

CI/CD pipeline generator. Produces ready-to-use pipeline configuration files for GitHub Actions, GitLab CI, Azure Pipelines, Jenkins, and other CI platforms. Generated pipelines run WAFtester scans on push/PR/schedule, upload SARIF results, and optionally fail builds on high-severity findings.

**When to use:** Setting up automated security testing in your CI/CD pipeline. The generated files are fully functional and can be committed directly.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-platform` | `-p` | string | | CI platform (`github`, `gitlab`, `azure`, `jenkins`, etc.) |
| `-list` | | bool | false | List available platforms |
| `-target` | `-u` | string | | Target URL |
| `-scanners` | | string | `all` | Scanner types |
| `-fail-high` | | bool | true | Fail pipeline on high severity |
| `-fail-medium` | | bool | false | Fail on medium severity |
| `-on-push` | | bool | true | Trigger on push |
| `-on-pr` | | bool | true | Trigger on pull request |
| `-on-schedule` | | bool | false | Scheduled trigger |
| `-cron` | | string | `0 0 * * *` | Cron schedule |
| `-branches` | | string | `main,master` | Branch filter |
| `-timeout` | | string | `30m` | Pipeline timeout |
| `-concurrency` | | int | 50 | Concurrency |
| `-rate-limit` | | int | 10 | Rate limit |
| `-output-format` | | string | `sarif` | Output format |
| `-upload-artifacts` | | bool | true | Upload artifacts |
| `-slack` | | bool | false | Slack notifications |
| `-slack-webhook` | | string | `SLACK_WEBHOOK_URL` | Slack webhook |
| `-o` | | string | | Output file |
| `-docker-image` | | string | | Docker image override |
| `-version` | | string | `latest` | WAFtester version |

#### Examples

```bash
# Generate GitHub Actions workflow
waftester cicd -p github -u https://target.com -o .github/workflows/waf-test.yml

# GitLab with schedule
waftester cicd -p gitlab --on-schedule --cron "0 2 * * 1"

# List supported platforms
waftester cicd --list
```

---

### `plugin`

**Alias:** `plugins`

Plugin management for extending WAFtester with custom Go plugins (`.so` shared libraries). Plugins can implement custom scanners, output formatters, or payload generators that integrate with the WAFtester execution pipeline.

**When to use:** Extending WAFtester with organization-specific scanning logic, custom output integrations, or proprietary payload generators.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-list` | bool | false | List installed plugins |
| `-load` | string | | Load plugin (.so file) |
| `-run` | string | | Run a loaded plugin |
| `-info` | string | | Show plugin info |
| `-dir` | string | `./plugins` | Plugin directory |
| `-target`, `-u` | string | | Target URL for plugin |
| `-config` | string | | Plugin config file |
| `-config-json` | string | | Inline JSON config |
| `-o` | string | | Output file |
| `-json` | bool | false | JSON output |
| `-v` | bool | false | Verbose |

#### Examples

```bash
# List plugins
waftester plugin --list

# Run a plugin
waftester plugin --run custom-scanner -u https://target.com

# Load and run with config
waftester plugin --load ./custom.so --run custom-scanner --config plugin.yaml
```

---

### `mcp`

**Alias:** `mcp-server`

Model Context Protocol (MCP) server for AI agent integration. Exposes WAFtester's scanning, analysis, and reporting capabilities as MCP tools and resources that AI assistants (Claude, GPT, Copilot) can invoke programmatically. Supports stdio transport (for IDE integration) and HTTP transport (for remote agents).

**When to use:** Connecting WAFtester to AI development environments (VS Code, Claude Desktop, Cursor) or building AI-powered security workflows.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-stdio` | bool | true | Use stdio transport (for IDE integration) |
| `-http` | string | | HTTP listen address (e.g., `:8080`) |
| `-payloads` | string | `$WAF_TESTER_PAYLOAD_DIR` or `./payloads` | Payload directory |
| `-presets` | string | `$WAF_TESTER_PRESET_DIR` or `./presets` | Service preset directory |
| `-templates` | string | `$WAF_TESTER_TEMPLATE_DIR` or `./templates/nuclei` | Template directory |
| `-tamper-dir` | string | | Directory of custom `.tengo` tamper scripts to load for `discover_bypasses` and `scan` tools |

#### Examples

```bash
# Stdio mode (default, for IDE/Claude Desktop)
waftester mcp

# HTTP mode for remote access
waftester mcp --http :8080

# With tamper scripts for bypass discovery
waftester mcp --tamper-dir ./my-tampers

# Custom payload directory
WAF_TESTER_PAYLOAD_DIR=/opt/payloads waftester mcp
```

---

### `validate`

Payload and API specification validator. Checks payload JSON files for schema compliance, duplicate IDs, missing fields, and encoding issues. Validates API specifications (OpenAPI, Swagger) for structural correctness, reachable servers, and security definition completeness.

**When to use:** Before committing payload changes, after updating API specs, or in CI pipelines to catch spec/payload regressions early.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-spec` | string | | API spec file to validate |
| `-spec-url` | string | | API spec URL to validate |
| `-allow-internal` | bool | false | Allow internal/private URLs in specs |
| `-payloads` | string | `./payloads` | Payload directory |
| `-fail-fast` | bool | false | Stop on first error |
| `-verbose` | bool | false | Verbose output |
| `-output` | string | | Output JSON file |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Validate payloads
waftester validate --payloads ./payloads

# Validate an API spec
waftester validate --spec openapi.yaml

# Strict validation
waftester validate --payloads ./payloads --fail-fast --verbose
```

---

### `validate-templates`

Nuclei template validator. Checks YAML template files for syntax errors, missing required fields (id, info, requests), invalid matchers/extractors, and best-practice violations. Strict mode enforces additional rules (unique IDs, proper severity tags, description length).

**When to use:** After writing or modifying Nuclei templates, or in CI to prevent broken templates from being merged.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-templates` | string | `./templates/nuclei` | Template directory |
| `-strict` | bool | false | Strict validation mode |
| `-verbose` | bool | false | Verbose output |
| `-output` | string | | Output JSON file |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Validate templates
waftester validate-templates --templates ./templates/nuclei

# Strict mode
waftester validate-templates --strict --verbose
```

---

### `report`

**Aliases:** `html-report`, `enterprise-report`

Enterprise HTML report generator. Reads results from an `auto` scan workspace directory and produces a self-contained HTML report with executive summary, finding details, severity distribution charts, WAF effectiveness metrics, and remediation guidance. The report is designed for stakeholder consumption.

**When to use:** After an `auto` scan, when you need a presentation-ready report for management, clients, or compliance evidence.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-workspace` | string | | Workspace directory path (from `auto` scan) |
| `-output` | string | | Output HTML file path |
| `-target` | string | | Target name for report header |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Generate report from workspace
waftester report --workspace ./waftester-workspace-abc123 --output report.html

# With custom target name
waftester report --workspace ./results --output report.html --target "Production API"
```

---

### `update`

Payload update manager. Synchronizes local payload files with upstream sources (OWASP, community repositories). Shows a diff of changes, supports dry-run preview, and handles version bumps for the payload manifest. Destructive changes (payload removals, ID changes) require explicit opt-in.

**When to use:** Keeping payloads current with the latest attack techniques and WAF bypass discoveries.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-payloads` | string | `./payloads` | Payload directory |
| `-source` | string | `OWASP` | Payload source |
| `-dry-run` | bool | false | Preview changes |
| `-auto-apply` | bool | false | Auto-apply non-destructive updates |
| `-skip-destructive` | bool | false | Skip destructive payload updates |
| `-version-bump` | string | `minor` | Version bump type (`major`, `minor`, `patch`) |
| `-output` | string | `payload-update-report.json` | Report file |

Plus [enterprise integration flags](#enterprise-integration-flags).

#### Examples

```bash
# Check for updates
waftester update --dry-run

# Apply updates
waftester update --auto-apply

# Skip destructive changes
waftester update --skip-destructive
```

### `compare`

**Alias:** `diff`

Compare two scan result JSON files and show what changed. Reports severity deltas, severity-weighted risk scores, new/fixed vulnerability categories, WAF vendor changes (including multi-WAF environments), and an overall verdict (improved, regressed, or unchanged).

Auto-detects the JSON format: accepts both `scan -format json` output and autoscan workspace `summary.json` output.

**When to use:** After adjusting WAF rules, upgrading WAF vendors, or testing A/B configurations. Compare a baseline scan against a current scan to measure security posture changes.

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-before` | string | | First scan result JSON (baseline) |
| `-after` | string | | Second scan result JSON (current) |
| `-format` | string | `console` | Output format: `console`, `json` |
| `-o` | string | | Output file |

Positional arguments are also supported: `waf-tester compare before.json after.json`

#### Verdict Logic

| Verdict | Condition |
|---------|-----------|
| `improved` | Total vulnerabilities decreased, or same total but severity shifted down (e.g., critical → low) |
| `regressed` | Total vulnerabilities increased, or same total but severity shifted up (e.g., low → critical) |
| `unchanged` | No change in total count or severity-weighted risk score |

Severity weights: critical=10, high=5, medium=2, low=1, info=0. A risk score row appears in console output when severity shifts are detected.

#### CI/CD Integration

Exits with code 1 when the verdict is `regressed`. Use in CI pipelines to gate deployments on WAF effectiveness:

```bash
waf-tester compare baseline.json current.json || echo "WAF regression detected"
```

#### Examples

```bash
# Compare two scan results
waf-tester compare --before baseline.json --after current.json

# Positional args
waf-tester compare baseline.json current.json

# JSON output to file
waf-tester compare --before a.json --after b.json --format json -o diff.json

# Compare autoscan summaries
waf-tester compare summary-before.json summary-after.json
```

---

## Shared Flag Groups

These flag groups are shared across multiple commands. Rather than duplicating them in every command section, they are documented here once.

### Output Flags

File export formats for persisting scan results. Most security scanners and CI/CD platforms consume one or more of these formats. SARIF is the standard for GitHub Code Scanning, JUnit is used by most CI runners for test reporting, and CycloneDX/SonarQube integrate with supply chain and code quality tools.

Available on `auto`, `scan`, `run`, `probe`, `fuzz`, and `bypass` commands (subset varies by command).

| Flag | Type | Description |
|------|------|-------------|
| `-json-export` | string | JSON export path |
| `-jsonl-export` | string | JSONL export path |
| `-sarif-export` | string | SARIF export path |
| `-junit-export` | string | JUnit XML export path |
| `-csv-export` | string | CSV export path |
| `-html-export` | string | HTML export path |
| `-md-export` | string | Markdown export path |
| `-pdf-export` | string | PDF export path |
| `-xml-export` | string | XML export path |
| `-sonarqube-export` | string | SonarQube export path |
| `-gitlab-sast-export` | string | GitLab SAST export path |
| `-defectdojo-export` | string | DefectDojo export path |
| `-har-export` | string | HAR export path |
| `-cyclonedx-export` | string | CycloneDX export path |

#### Content Control

Control the verbosity of exported data. Omit raw request/response bodies for smaller files, or restrict output to bypass-only findings for focused analysis.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-omit-raw` | bool | false | Omit raw request/response data |
| `-omit-evidence` | bool | false | Omit evidence details |
| `-only-bypasses` | bool | false | Only output bypass findings |
| `-batch-size` | int | 100 | Batch size for output |

#### Stats

Live scan progress statistics. Displays request rates, finding counts, and estimated time remaining during long-running scans.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-stats` | bool | false | Show live statistics |
| `-stats-json` | bool | false | Statistics in JSON format |
| `-stats-interval` | int | 5 | Stats refresh interval (seconds) |

### Enterprise Integration Flags

Integration flags for connecting WAFtester findings to external systems: ticketing (Jira, GitHub Issues, Azure DevOps), communication (Slack, Teams, PagerDuty), observability (OpenTelemetry, Elasticsearch, Prometheus), and CI/CD platforms (GitHub Actions summaries, policy gates).

Available on most commands. Findings are sent to configured integrations in real time as they are discovered.

#### Webhooks and CI

Send findings to webhooks, Slack/Teams channels, or CI-specific output formats.

| Flag | Type | Description |
|------|------|-------------|
| `-webhook` | string | Webhook URL for findings |
| `-webhook-all` | bool | Send all results to webhook |
| `-github-output` | bool | Write GitHub Actions `$GITHUB_OUTPUT` |
| `-github-summary` | bool | Write GitHub Actions job summary |
| `-slack-webhook` | string | Slack webhook URL |
| `-teams-webhook` | string | Microsoft Teams webhook URL |
| `-pagerduty-key` | string | PagerDuty routing key |
| `-metrics-port` | int | Prometheus metrics port |

#### Jira

Automatically create Jira tickets for findings. Each finding becomes a Jira issue with severity-mapped priority, attack details, and reproduction steps.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-jira-url` | string | | Jira base URL |
| `-jira-project` | string | | Jira project key |
| `-jira-email` | string | | Jira email |
| `-jira-token` | string | | Jira API token |
| `-jira-issue-type` | string | `Bug` | Issue type |
| `-jira-labels` | string | | Labels (comma-separated) |
| `-jira-assignee` | string | | Assignee |

#### GitHub Issues

Create GitHub issues for findings. Works with GitHub.com and GitHub Enterprise Server.

| Flag | Type | Description |
|------|------|-------------|
| `-github-issues-token` | string | GitHub personal access token |
| `-github-issues-owner` | string | Repository owner |
| `-github-issues-repo` | string | Repository name |
| `-github-issues-url` | string | GitHub Enterprise URL |
| `-github-issues-labels` | string | Labels (comma-separated) |
| `-github-issues-assignees` | string | Assignees (comma-separated) |

#### Azure DevOps

Create Azure DevOps work items for findings. Supports custom work item types, area paths, and iteration paths.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-ado-org` | string | | Organization |
| `-ado-project` | string | | Project |
| `-ado-pat` | string | | Personal access token |
| `-ado-work-item-type` | string | `Bug` | Work item type |
| `-ado-area-path` | string | | Area path |
| `-ado-iteration-path` | string | | Iteration path |
| `-ado-assigned-to` | string | | Assigned user |
| `-ado-tags` | string | | Tags |

#### OpenTelemetry

Export scan telemetry (traces and metrics) to an OpenTelemetry collector for integration with Jaeger, Grafana, Datadog, or other observability platforms.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-otel-endpoint` | string | | OTEL collector endpoint |
| `-otel-insecure` | bool | false | Use insecure connection |

#### Elasticsearch

Index findings into Elasticsearch for Kibana dashboards, historical trend analysis, and full-text search across scan results.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-elasticsearch-url` | string | | Elasticsearch URL |
| `-elasticsearch-api-key` | string | | API key |
| `-elasticsearch-username` | string | | Username |
| `-elasticsearch-password` | string | | Password |
| `-elasticsearch-index` | string | | Index name |
| `-elasticsearch-insecure` | bool | false | Skip TLS verification |

#### History and Policy

Scan history tracking, policy enforcement, and baseline comparison. History stores previous scan results for trend analysis. Policies define acceptable security thresholds. Baselines allow diffing current results against a known-good state.

| Flag | Type | Description |
|------|------|-------------|
| `-history-path` | string | History storage path |
| `-history-tags` | string | History tags |
| `-template-config` | string | Template config path |
| `-policy` | string | Policy file |
| `-baseline` | string | Baseline file for comparison |
| `-overrides` | string | Overrides configuration file |

---

## Understanding Matchers and Filters

Matchers and filters control which responses appear in your results. They exist on `run`, `fuzz`, and `probe` commands, but the flag names differ between commands because each command evolved from different design lineages.

**Core concept:** A matcher _includes_ responses that meet criteria. A filter _excludes_ responses that meet criteria. They are inverses of each other. When both are set, matchers run first, then filters remove from the matched set.

### How it works

1. WAFtester sends a request with each payload or wordlist entry.
2. The response is checked against matchers. If no matcher matches, the response is discarded.
3. Remaining responses are checked against filters. If a filter matches, the response is discarded.
4. Surviving responses appear in your output as findings.

### Auto-calibrate

The `-ac` / `-auto-calibrate` flag sends a few baseline requests (random strings that should not trigger interesting behavior) and learns the "normal" response characteristics (status code, size, word count). It then automatically sets filters to exclude responses matching that baseline. This eliminates noise without manual tuning.

### Flag name differences by command

The same concept uses different flag names depending on the command:

| Concept | `run` / `fuzz` | `probe` |
|---------|----------------|---------|
| Match status code | `-mc` | `-match-code` (`-mc`) |
| Match size | `-ms` | `-match-length` (`-ml`) |
| Match words | `-mw` | `-match-word-count` (`-mwc`) |
| Match lines | `-ml` | `-match-line-count` (`-mlc`) |
| Match regex | `-mr` | `-match-regex` (`-mr`) |
| Match string | — | `-match-string` (`-ms`) |
| Filter status code | `-fc` | `-filter-code` (`-fc`) |
| Filter size | `-fs` | `-filter-length` (`-fl`) |
| Filter words | `-fw` | `-filter-word-count` (`-fwc`) |
| Filter lines | `-fl` | `-filter-line-count` (`-flc`) |
| Filter regex | `-fr` | `-filter-regex` (`-fe`) |

Why the difference? `run` and `fuzz` follow the short-flag convention from `ffuf` (a widely-used fuzzer). `probe` uses self-documenting long names because it runs many probe types and short flags would collide. See [Flag Naming Notes](#flag-naming-notes) for more detail.

### Quick examples

```bash
# Show only 200 and 403 responses
waftester fuzz -u https://target.com/FUZZ -w wordlist.txt -mc 200,403

# Exclude 404s and error pages
waftester fuzz -u https://target.com/FUZZ -w wordlist.txt -fc 404

# Auto-calibrate (recommended for most scans)
waftester run -u https://target.com -ac

# Match by response size range (probe)
waftester probe -u https://target.com -match-length "100-5000"

# Combine matchers and filters
waftester fuzz -u https://target.com/FUZZ -w wordlist.txt -mc 200-399 -fs 0
```

---

## Recommended Flag Combinations

Common recipes for frequent tasks. Copy-paste and adjust the target URL.

| Task | Command |
|------|---------|
| **First scan** (safe, low-noise) | `waftester scan -u URL --smart --smart-mode=stealth -types sqli,xss` |
| **Full assessment** (everything) | `waftester auto -u URL` |
| **Stealth mode** (SOC-safe) | `waftester auto -u URL --smart --smart-mode=stealth -rl 20 -c 5` |
| **Bypass hunt** | `waftester bypass -u URL --smart --tamper-auto` |
| **Bypass hunt + custom tampers** | `waftester bypass -u URL --tamper-dir=./my-tampers --tamper-auto` |
| **CI/CD gate** (fail on findings) | `waftester scan -u URL -types sqli,xss -json-export results.json --github-summary` |
| **API spec testing** | `waftester auto -u URL --spec openapi.yaml` |
| **Regression test** (specific types) | `waftester scan -u URL -types sqli -mc 200 --baseline prev.json` |
| **Directory brute-force** | `waftester fuzz -u URL/FUZZ -w wordlist.txt -mc 200,301,403 -ac` |
| **WAF vendor ID + tailored bypass** | `waftester vendor -u URL && waftester bypass -u URL --tamper-auto` |
| **Minimal footprint recon** | `waftester probe -l targets.txt -c 5 -rl 10 -title -server -td` |
| **Full audit with reports** | `waftester auto -u URL -report-formats json,md,html --jira-url JIRA --slack-webhook SLACK` |

---

## Performance and Footprint

Approximate resource usage by command. Actual numbers vary with target response times, network conditions, and payload counts.

| Command | Typical Requests | Peak Memory | Notes |
|---------|-----------------|-------------|-------|
| `auto` | 3,000–10,000+ | 200–500 MB | Multi-phase: discovery + scan + assessment + browser |
| `scan` | 500–5,000 | 100–300 MB | Depends on `-types` selection and payload count |
| `bypass` | 2,000–5,000 | 150–300 MB | Full payload library against single target |
| `fuzz` | Wordlist-dependent | 50–200 MB | 100k wordlist ≈ 100k requests |
| `probe` | 1 per target × modules | 50–150 MB | 8 modules × target count |
| `assess` | 200–1,000 | 100–200 MB | Payload set + false positive corpus |
| `race` | `-n` × `-c` | 20–50 MB | Burst: all concurrent requests fire simultaneously |
| `smuggle` | 10–50 per technique | 30–50 MB | Low volume, technique-based |
| `crawl` | Site-dependent | 100–500 MB | Headless browser adds memory |

### Controlling footprint

| Goal | Flags |
|------|-------|
| Reduce request rate | `-rl 20` (requests/sec) or `-delay 500ms` |
| Limit concurrency | `-c 5` (workers) or `-threads 5` |
| Reduce total requests | `-types sqli,xss` (fewer categories) |
| Stealth mode | `--smart --smart-mode=stealth` (auto-adapts) |
| Skip phases in `auto` | `--no-detect`, `--assess=false`, `--browser=false` |

---

## Attack Categories Reference

The `-types` flag on `scan`, `auto`, and `bypass` accepts these category names. Use `all` to run every category, or comma-separate specific ones.

| Category | Description | Aliases |
|----------|-------------|---------|
| `sqli` | SQL injection | `sql-injection`, `sql` |
| `xss` | Cross-site scripting | `cross-site-scripting` |
| `ssti` | Server-side template injection | `template-injection` |
| `ssrf` | Server-side request forgery | `request-forgery` |
| `lfi` | Local file inclusion | `file-inclusion` |
| `rfi` | Remote file inclusion | |
| `cmdi` | OS command injection | `command-injection`, `os-injection` |
| `xxe` | XML external entity injection | |
| `ldap` | LDAP injection | `ldap-injection` |
| `nosql` | NoSQL injection | `nosql-injection`, `nosqli` |
| `prototype` | Prototype pollution | `prototype-pollution` |
| `crlf` | CRLF injection | `crlf-injection` |
| `ssi` | Server-side includes | |
| `deserialization` | Insecure deserialization | `deserialize` |
| `jwt` | JWT vulnerabilities | |
| `cors` | CORS misconfiguration | |
| `csrf` | Cross-site request forgery | |
| `clickjack` | Clickjacking | `clickjacking` |
| `redirect` | Open redirect | `open-redirect` |
| `hpp` | HTTP parameter pollution | |
| `traversal` | Path traversal | `path-traversal`, `directory-traversal` |
| `idor` | Insecure direct object reference | |
| `mass-assign` | Mass assignment | `mass-assignment` |
| `broken-auth` | Broken authentication | `authentication` |
| `session-fixation` | Session fixation | |
| `sensitive-data` | Sensitive data exposure | `data-exposure` |
| `security-misconfig` | Security misconfiguration | `misconfiguration` |
| `host-header` | Host header injection | |
| `response-split` | HTTP response splitting | |
| `rce` | Remote code execution | `code-execution` |
| `smuggling` | HTTP request smuggling | `request-smuggling` |
| `race` | Race conditions | `race-condition` |
| `graphql` | GraphQL vulnerabilities | |
| `grpc` | gRPC testing | |
| `soap` | SOAP/WSDL testing | |
| `websocket` | WebSocket testing | `ws` |
| `oauth` | OAuth vulnerabilities | |
| `crypto` | Cryptographic failures | `cryptographic-failures` |
| `buffer-overflow` | Buffer overflow | `overflow` |
| `input-validation` | Input validation bypass | |
| `cloud` | Cloud misconfigurations | `cloud-misconfig` |
| `subdomain-takeover` | Subdomain takeover | `takeover` |
| `dns` | DNS-related attacks | |
| `api-abuse` | API abuse patterns | |
| `biz-logic` | Business logic flaws | `business-logic` |
| `all` | All categories | |

For the full table with payload counts per category, see [EXAMPLES.md: Attack Categories](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md#attack-categories-reference).

---

## Exit Codes

WAFtester uses standard exit codes for CI/CD integration. Scripts and pipelines should check the exit code to determine pass/fail status.

| Code | Meaning |
|------|---------|
| 0 | Success — no findings, or all tests passed |
| 1 | Findings detected, scan errors, or policy violation |
| 2 | Invalid flag syntax (from Go flag parser) |

### CI/CD usage

```bash
waftester scan -u https://target.com -types sqli,xss -json-export results.json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "No findings — pipeline passes"
elif [ $EXIT_CODE -eq 1 ]; then
  echo "Findings detected — review results.json"
  exit 1
elif [ $EXIT_CODE -eq 2 ]; then
  echo "Configuration error — check flags"
  exit 2
fi
```

---

## Flag Naming Notes

WAFtester commands evolved from different design lineages, which is why flag names are not perfectly uniform across all commands.

### Short flags (`run`, `fuzz`, `bypass`, `scan`)

These commands follow the `ffuf` naming convention: short single-character or two-character flags like `-mc`, `-fc`, `-ms`, `-fs`. This is intentional — `run` and `fuzz` are designed to feel familiar to `ffuf` users, and `scan`/`bypass` inherit the same patterns for consistency within the attack-oriented commands.

### Long flags (`probe`, `crawl`, `headless`)

Reconnaisance and discovery commands use self-documenting long flag names like `-match-code`, `-filter-code`, `-match-string`. These commands have many more flags (probe has 60+) and short names would collide or become cryptic.

### Global flags

Global flags use the long form with a `-` prefix: `-target`, `-output`, `-timeout`, `-skip-verify`. These are consistent across all commands.

### Why not unify?

Changing flag names would break existing scripts, CI/CD pipelines, and muscle memory. The current split (short for attack commands, long for recon commands) matches the conventions of the tools that inspired each command family. If you're unsure which flags a command accepts, run `waftester <command> --help`.

---

## See Also

- [Examples Guide](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md) — Real-world usage examples with annotated output for every command
- [API Spec Scanning](https://github.com/waftester/waftester/blob/main/docs/API-SPEC-SCANNING.md) — Detailed guide for OpenAPI, Swagger, Postman, and HAR-driven scanning
- [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md) — Installation methods (Go, Homebrew, npm, Scoop, AUR, Docker, binary)
- [Changelog](https://waftester.com/changelog) — Version history and breaking changes
- [Cheat Sheet](https://waftester.com/cheat-sheet) — Task-oriented quick reference with copy-paste commands
- [All 49 Scan Types](https://waftester.com/cheat-sheet#all-scan-types) — Complete list of attack categories for the `-types` flag
