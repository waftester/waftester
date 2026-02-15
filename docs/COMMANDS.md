# WAFtester Command Reference

The definitive reference for every WAFtester CLI command, flag, environment variable, and output option. Each command section includes its aliases, a description of what it does and when to use it, a complete flag table with types and defaults, and practical examples.

For usage examples and real-world workflows, see [EXAMPLES.md](EXAMPLES.md). For installation, see [INSTALLATION.md](INSTALLATION.md).

**Document Version:** 2.9.4
**Last Updated:** February 2026

---

## Table of Contents

- [Usage](#usage)
- [Global Options](#global-options)
- [Environment Variables](#environment-variables)
- [Commands](#commands)
  - [auto](#auto) — Autonomous full-spectrum assessment
  - [scan](#scan) — Targeted vulnerability scanning
  - [run](#run) — Test plan execution
  - [bypass](#bypass) — WAF bypass discovery
  - [mutate](#mutate) — Payload mutation engine
  - [fuzz](#fuzz) — Directory and parameter fuzzing
  - [probe](#probe) — HTTP probing and fingerprinting
  - [crawl](#crawl) — Web crawling with JS support
  - [discover](#discover) — Endpoint discovery
  - [learn](#learn) — Test plan generation
  - [analyze](#analyze) — JavaScript analysis
  - [headless](#headless) — Headless browser testing
  - [assess](#assess) — WAF assessment and benchmarking
  - [fp](#fp) — False positive testing
  - [vendor](#vendor) — WAF vendor detection
  - [protocol](#protocol) — Protocol detection
  - [tampers](#tampers) — Tamper technique management
  - [template](#template) — Nuclei template scanning
  - [smuggle](#smuggle) — HTTP request smuggling
  - [race](#race) — Race condition testing
  - [workflow](#workflow) — YAML workflow orchestration
  - [openapi](#openapi) — OpenAPI/Swagger testing
  - [grpc](#grpc) — gRPC service testing
  - [soap](#soap) — SOAP/WSDL service testing
  - [cloud](#cloud) — Cloud infrastructure discovery
  - [cicd](#cicd) — CI/CD pipeline generation
  - [plugin](#plugin) — Plugin management
  - [mcp](#mcp) — Model Context Protocol server
  - [validate](#validate) — Payload and spec validation
  - [validate-templates](#validate-templates) — Template validation
  - [report](#report) — Enterprise HTML report generation
  - [update](#update) — Payload updater
- [Shared Flag Groups](#shared-flag-groups)
  - [Output Flags](#output-flags)
  - [Enterprise Integration Flags](#enterprise-integration-flags)
- [Exit Codes](#exit-codes)
- [See Also](#see-also)

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
| `WAF_TESTER_TEMPLATE_DIR` | Override default Nuclei template directory (`./templates/nuclei`). Used by scan, template, and MCP commands. |
| `WAF_TESTER_HTTP_ADDR` | Default HTTP listen address for the MCP server when `--http` is not specified. |
| `WAF_TESTER_BINARY_PATH` | Override the resolved binary path. Primarily used by the npm shim for development or custom installations. |
| `WAFTESTER_INTEGRATION` | Set to any non-empty value to enable integration tests that make real HTTP requests. Test suite only. |

---

## Commands

### `auto`

**Aliases:** `superpower`, `sp`

The most powerful command in WAFtester. Runs a multi-phase autonomous assessment that chains together endpoint discovery, leaky path detection, parameter mining, WAF vendor fingerprinting, smart tamper selection, 2,800+ payload testing with adaptive rate limiting, false-positive assessment, and browser-based validation into a single invocation. An AI "brain" coordinates phases, learns from responses, and adjusts strategy in real time.

Results are written to a workspace directory containing JSON, Markdown, and HTML reports. Use `--resume` to continue an interrupted scan from the last checkpoint.

**When to use:** You want a single command that does everything. Ideal for first-time assessments, CI/CD pipelines, and hands-off security audits.

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
| `-smart-mode` | string | `standard` | Smart mode profile: `stealth` (slow, minimal footprint), `standard` (balanced), `aggressive` (fast, noisy), `bypass` (focus on finding bypasses) |
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
| `-types` | | string | `all` | Attack types to run (comma-separated, e.g., `sqli,xss,ssti,cmdi`) |
| `-concurrency` | | int | 5 | Concurrent requests |
| `-timeout` | | int | 10 | Request timeout in seconds |
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
| `-max-depth` | `-mxd` | int | 5 | Maximum crawl depth |

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
| `-silent` | `-s` | bool | false | Suppress all output except results |
| `-no-color` | `-nc` | bool | false | Disable colored output |
| `-timestamp` | `-ts` | bool | false | Add timestamps to output |
| `-stream` | | bool | false | Stream results in real-time |

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
| `-category` | | string | | Attack category filter |
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
| `-timestamp` | `-ts` | bool | false | Timestamps |
| `-noninteractive` | `-ni` | bool | false | Non-interactive mode |
| `-store-response` | `-sr` | bool | false | Store raw responses to disk |
| `-store-response-dir` | `-srd` | string | `responses` | Response storage directory |

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

---

### `bypass`

Dedicated WAF bypass finder. Sends the full payload library against a target and identifies which payloads bypass the WAF (i.e., reach the application without being blocked). Results are ranked by confidence and categorized by attack type.

With `--smart` mode, the engine adapts in real time: it detects blocking patterns, switches tamper techniques, and focuses on the most promising bypass vectors.

**When to use:** You know a WAF is present and want to find what gets through. Pair with `tampers --discover` for maximum coverage.

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

High-performance directory, file, and parameter fuzzer. Place the `FUZZ` keyword in the URL (or request body, headers) to mark the injection point. WAFtester substitutes each wordlist entry, sends the request, and applies matchermatchers/filters to identify interesting responses.

Supports recursive directory discovery, file extension brute-forcing, multiple fuzzing modes (sniper, pitchfork, cluster bomb), and response extraction via regex or presets.

**When to use:** Directory discovery, parameter brute-forcing, virtual host enumeration, or any scenario where you need to iterate a wordlist against a URL pattern.

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

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `-fc` | | string | Filter status codes |
| `-fs` | | string | Filter response size |
| `-fw` | | string | Filter word count |
| `-fl` | | string | Filter line count |
| `-fr` | | string | Filter regex |

#### Output

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

Discovery combines passive analysis (HTML/JS parsing, link extraction) with active probing (common path checks, parameter detection) to build a target map.

**When to use:** Before `learn` + `run` workflows, or when you need a structured endpoint inventory for manual review.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-target` | `-u` | string[] | | Target URL(s) |
| `-l` | | string | | Target list |
| `-stdin` | | bool | false | Read stdin |
| `-service` | | string | | Service type hint |
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
```

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

WAF vendor detection and fingerprinting. Sends crafted requests and analyzes responses (headers, cookies, error pages, status codes, body content) to identify the WAF product from a database of 197 signatures. Detection covers cloud WAFs (Cloudflare, AWS WAF, Akamai, Azure Front Door, Imperva), CDN-integrated WAFs, and self-hosted solutions (ModSecurity, NAXSI).

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

---

### `smuggle`

HTTP request smuggling detection and exploitation testing. Tests for CL.TE, TE.CL, TE.TE, and H2.CL smuggling variants by sending ambiguous requests and analyzing how the target's frontend/backend infrastructure interprets them.

Safe mode (default) uses non-destructive timing-based probes that do not inject smuggled requests that could affect other users. Disable safe mode only in controlled environments.

**When to use:** Testing reverse proxy and CDN configurations for request smuggling vulnerabilities. Run `protocol` first to understand the target's HTTP stack.

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

API specification-driven security testing. Parses OpenAPI 3.x or Swagger 2.0 specs to enumerate endpoints, extract parameter schemas, and generate targeted attack payloads that respect the API contract (correct content types, required fields, valid enum values) while injecting malicious data into individual parameters.

This approach tests WAF rules in the context of the actual API surface, catching parameter-specific bypasses and schema-aware injection vectors that generic scanning would miss.

**When to use:** Testing REST APIs that have an OpenAPI/Swagger spec. For GraphQL, gRPC, or SOAP, use the dedicated commands instead.

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `-spec` | `-s` | string | | API specification file |
| `-spec-url` | | string | | API spec URL |
| `-base-url` | `-u` | string | | Base URL override |
| `-list` | | bool | false | List spec endpoints |
| `-fuzz` | | bool | false | Fuzz endpoints |
| `-scan-type` | | string | `all` | Scan type filter |
| `-path` | | string | | Path filter |
| `-method` | | string | | Method filter |
| `-auth-header` | | string | | Authorization header |
| `-api-key` | | string | | API key |
| `-api-key-header` | | string | `X-API-Key` | API key header name |
| `-bearer` | | string | | Bearer token |
| `-payloads` | | string | | Payload directory |
| `-template-dir` | | string | | Template directory |
| `-o` | | string | | Output file |
| `-json` | | bool | false | JSON output |
| `-v` | | bool | false | Verbose |

#### Examples

```bash
# List endpoints from spec
waftester openapi --spec openapi.yaml --list

# Fuzz all endpoints
waftester openapi --spec openapi.yaml --fuzz -u https://api.example.com

# Auth-protected API
waftester openapi --spec openapi.yaml --fuzz --bearer "$TOKEN" -u https://api.example.com
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

**When to use:** Testing legacy SOAP/XML web services. For REST APIs, use `scan` or `openapi` instead.

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
| `-templates` | string | `$WAF_TESTER_TEMPLATE_DIR` or `./templates/nuclei` | Template directory |

#### Examples

```bash
# Stdio mode (default, for IDE/Claude Desktop)
waftester mcp

# HTTP mode for remote access
waftester mcp --http :8080

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

## Exit Codes

WAFtester uses standard exit codes for CI/CD integration. Scripts and pipelines should check the exit code to determine pass/fail status.

| Code | Meaning |
|------|---------|
| 0 | Success (no findings or all tests passed) |
| 1 | Findings detected or scan errors |
| 2 | Invalid arguments or configuration |

---

## See Also

- [Examples Guide](EXAMPLES.md) — Real-world usage examples with annotated output for every command
- [API Spec Scanning](API-SPEC-SCANNING.md) — Detailed guide for OpenAPI, Swagger, Postman, and HAR-driven scanning
- [Installation](INSTALLATION.md) — Installation methods (Go, Homebrew, npm, Scoop, AUR, Docker, binary)
- [Changelog](../CHANGELOG.md) — Version history and breaking changes
