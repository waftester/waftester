# Changelog

All notable changes to WAFtester will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.2] - 2026-02-07

### Added

#### Unified Payload Provider (`pkg/payloadprovider`)

Bridges the JSON payload database (2,800+ payloads) and Nuclei template system (~226 vectors) into a single unified provider:

- **`payloadprovider.Provider`** — loads both sources, merges with deduplication, provides category-aware queries (`GetByCategory`, `GetByTags`, `GetStats`)
- **`payloadprovider.CategoryMapper`** — bidirectional mapping for 20+ categories (e.g. `sqli` ↔ `SQL-Injection`, `lfi` ↔ `Path-Traversal`)
- **Template enrichment** — `--enrich` flag on `template` command injects JSON payloads into Nuclei templates for maximum bypass coverage
- **Scan enrichment** — `scan` command WAF evasion scanner now pulls payloads from the unified provider instead of 3 hardcoded strings
- **MCP integration** — new `waftester://payloads/unified` resource; `list_payloads` tool reports unified stats; prompts reference the bridge
- **Smart mode** — `GetTemplateRecommendations` suggests vendor-specific JSON payload files and the `--enrich` flag
- **Default constants** — `defaults.PayloadDir` and `defaults.TemplateDir` replace all hardcoded path strings
- **23 unit tests** — table-driven tests for provider, mapper, edge cases

#### Pre-Built Template Library

WAFtester now ships a complete `templates/` directory in release archives and Docker images, providing ready-to-use configurations for every template system:

- **17 Nuclei templates** — WAF bypass (SQLi, XSS, RCE, LFI, SSRF, SSTI, CRLF, XXE, NoSQLi) and vendor detection (Cloudflare, AWS WAF, Akamai, ModSecurity, Azure WAF), plus a full assessment workflow
- **5 workflow templates** — Full scan, quick probe, CI gate, WAF detection, API scan
- **5 policy templates** — Permissive, standard, strict, OWASP Top 10, PCI-DSS compliance gates
- **3 override templates** — False positive suppression, API-only mode, CRS tuning
- **6 output templates** — CSV, ASFF (AWS Security Hub), JUnit XML, Markdown, Slack notification, text summary
- **5 report config templates** — Minimal, enterprise, dark theme, compliance, print/PDF

#### Template Validation Tests

- 11 structural tests validate all shipped templates: Nuclei YAML fields, workflow steps, policy names, override structure, Go template syntax, report config format, directory integrity
- CI enforcement ensures templates ship in release archives (goreleaser) and Docker images

#### CLI Flag Consistency Audit

Comprehensive audit and fix of all 33 CLI commands for unified payload flag consistency:

- **`scan` command** — added `--payloads` and `--template-dir` flags; WAF evasion scanner now uses configurable directories instead of hardcoded defaults
- **`grpc` / `soap` / `openapi`** — added `--payloads` and `--template-dir` flags; unified fuzz payloads now respect custom directories
- **`assess` command** — added `--payloads` flag wired to `assessment.Config.PayloadDir`
- **`template` command** — renamed `--payload-dir` to `--payloads` for cross-command consistency
- **`validate-templates`** — fixed default from `"../templates"` to `defaults.TemplateDir`
- **`unified_payloads.go`** — all shared helpers now accept `templateDir` parameter instead of hardcoding `defaults.TemplateDir`
- **MCP server** — `validatePayloadDir` now uses user-supplied `--templates` directory for unified payload counts

### Fixed

- **Templates included in releases** — `templates/**/*` added to `.goreleaser.yaml` archive files (previously only `payloads/` and source-internal configs shipped)
- **Templates included in Docker** — `COPY templates/ ./templates/` added to Dockerfile
- **Report config paths** — Examples and workflows reference canonical `templates/report-configs/` instead of source-internal `pkg/report/templates/configs/`
- **MCP resource count** — version resource correctly reports 10 resources (was 9)
- **CLI flag naming** — `template --payload-dir` renamed to `--payloads` to match all other commands
- **MCP startup validation** — `validatePayloadDir` now uses user-supplied `--templates` value instead of hardcoded default
- **`validate-templates` default path** — changed from `"../templates"` to `defaults.TemplateDir` (`./templates/nuclei`)

---

## [2.7.1] - 2026-02-07

### Security

- **Removed insecure crypto fallbacks** — `generateCacheBuster()` (cache), `generateWebSocketKey()` (websocket), and `randomHex()` (calibration) no longer fall back to `time.Now().UnixNano()` when `crypto/rand` fails — they now return errors instead of predictable values
- **Removed `python`/`python3` from workflow command allowlist** — prevented arbitrary code execution via workflow files
- **HTML report XSS hardening** — `safeHTML` template function now escapes content with `template.HTMLEscapeString` before casting to `template.HTML`

### Fixed

- **Partial body reads** — replaced `resp.Body.Read(buf)` with `io.ReadAll(io.LimitReader(...))` in cache and traversal packages to prevent truncated response data
- **OAuth/PKCE functions return errors** — `GenerateState()`, `GenerateNonce()`, and `GeneratePKCEPair()` now return `(string, error)` / `(string, string, error)` instead of silently using weak fallbacks
- **URL mutation in NoSQL injection** — `testQueryParam` now clones the URL via value copy to prevent shared pointer corruption across loop iterations
- **Case-sensitive severity scoring** — scoring engine now normalizes severity to lowercase before lookup, fixing mismatches with `"critical"` vs `"Critical"`
- **SSRF false positives** — `isLocalResponse` no longer treats any HTTP 200 as SSRF evidence; requires body content matching internal service patterns
- **SSTI false positives** — baseline comparison added to `analyzeResponse` to skip math results and expected outputs already present in normal page content
- **Session fixation false positives** — scanner now checks if server actually set a session cookie before flagging fixation vulnerability
- **IDOR false positives** — `testAccess` now reads response body and checks for access-denied patterns in 200 responses; horizontal privilege test compares response bodies for similarity
- **Baseline capture timing** — `executor.go` now captures detection baseline after body is read, ensuring accurate `ContentLength`
- **Request body replay on retry** — POST request bodies are re-created on retry attempts in executor (readers are consumed after first use)
- **Silent ban detector** — `headerChanges` counter resets on successful response to prevent monotonic accumulation causing false ban detections
- **Health monitor restart** — `stopCh` channel recreated on `Start()` to allow proper Stop/Start cycling
- **Worker pool `Submit` on close** — recover from send-on-closed-channel panic when `Close()` races with `Submit()`; `ParallelFor` compensates `wg.Done()` for failed submits
- **Crawler shutdown** — replaced polling `default` case with `atomic.Int64` in-flight counter for clean queue closure
- **DNS brute-force rate limiting** — added `QueryDelay` config (default 50ms) to prevent DNS server throttling
- **SOCKS proxy fallback** — explicit dialer initialization when SOCKS dialer creation fails (was silently nil)
- **Proxy dial timeout** — fixed goroutine/connection leak by using channel-send-or-close pattern instead of select-after-send
- **TLS transport leaks** — `DisableKeepAlives=true` and `CloseIdleConnections()` added to per-request JA3 and fallback transports
- **Checkpoint defensive copy** — `Load()` returns deep copy of state to prevent external modification from racing with manager
- **Distributed coordinator** — `GetNodes()`, `GetTasks()`, and `GetTask()` return deep copies to prevent callers from mutating internal state
- **History store** — `Get()` and `List()` return deep copies of `ScanRecord` to prevent mutation of cached data
- **OOB detector timeout** — `CheckInteractions` enforces 30-second context timeout to prevent hanging on unresponsive OOB servers
- **Recon error propagation** — `FullScan` now returns aggregated errors via `errors.Join` instead of silently discarding them
- **Mutation executor streaming** — `StreamResults` stats channel changed from synchronous return to buffered `<-chan *ExecutionStats` to prevent goroutine hangs
- **Runner context cancellation** — `RunWithCallback` now waits for in-flight goroutines before returning on context cancellation

### Improved

- **Concurrent map safety** — added `sync.RWMutex` to encoder registry, metrics `Calculator`, evasion engine `rng`, and timing attack `rng`
- **Deterministic iteration** — evasion engine `List()`, `ListByCategory()`, `GenerateVariants()`, and `generateChains()` now sort technique IDs for stable output
- **JWT algorithm confusion** — expanded from RS256→HS256 only to all asymmetric algorithms (RS/ES/PS 256/384/512) → all HMAC variants
- **CSRF token detection** — added `_csrf`, `nonce`, meta tag patterns, and `X-CSRFToken` header
- **Command injection payloads** — added Windows pipe separator and 5 new output-based payloads (ipconfig, systeminfo, net user, echo pipe, tasklist)
- **Mass assignment parameters** — added framework-specific parameters for Rails, Django, Spring, Laravel, and Node.js
- **LFI payloads** — integrated null byte injection and Unicode/double-encoding payloads into main `Payloads()` function
- **HPP payload encoding** — XSS and path traversal HPP payloads now use `url.QueryEscape` for proper encoding
- **XSS reflection detection** — added NFKC Unicode normalization check for fullwidth character bypasses
- **GraphQL introspection retry** — added backoff retry (3 attempts) for rate-limited or temporarily failing introspection queries
- **Upload size enforcement** — `TestUpload` now checks payload size against `MaxFileSize` before building multipart request
- **Cloud discovery** — added `ProviderAkamai` and `ProviderOracle` constants; fixed `NewAzureClient` parameter order
- **Rate limiter in WAF detection** — `detectWAF` now calls `a.limiter.Wait(ctx)` before secondary probe request
- **WebSocket validation** — `CheckWebSocket` and `TestOriginValidation` now verify `Sec-WebSocket-Accept` header per RFC 6455
- **Intelligence predictor** — `PredictBatch` uses internal `predictLocked()` to avoid re-entrant RLock deadlock

### Tests

- Added 10 regression test files covering concurrency, URL mutation, crypto fallback, scoring, streaming, body reads, and workflow allowlist
- Added 7 structural enforcement tests: crypto fallback, template HTML, body reads, math/rand in security paths, workflow allowlist, concurrent map access, HTTP body closure
- Updated `cache_test.go` and `websocket_test.go` for new `(string, error)` signatures
- Updated `ssti_test.go` for baseline parameter and adjusted `MaxPayloads` request count
- Updated `ssrf_test.go` for stricter `isLocalResponse` body matching
- Updated `scoring_test.go` for lowercase severity map keys and case-insensitive validation
- Updated `distributed_test.go` to modify internal state directly instead of through defensive-copy getters
- Cleared all structural test known-violation ratchet lists (17 violations → 0)

---

## [2.7.0] - 2026-02-07

### Added

#### Container Packaging — `ghcr.io/waftester/waftester`

- **Multi-architecture Docker image** published to GitHub Container Registry
  - Multi-stage Dockerfile: `golang:1.24-alpine` build → `distroless/static-debian12:nonroot` runtime (~5 MB)
  - Native Go cross-compilation via `TARGETARCH`/`TARGETOS` (no QEMU emulation for build)
  - Multi-arch manifest: `linux/amd64` + `linux/arm64`
  - BuildKit cache mounts for fast rebuilds (`/go/pkg/mod`, `/root/.cache/go-build`)
  - Attack payloads bundled in image — self-contained, no volume mounts required
  - MCP-specific OCI labels: `io.modelcontextprotocol.server=true`

- **Docker Compose** for local development (`docker-compose.yml`)
  - Environment-substituted build args: `${VERSION:-dev}`, `${COMMIT:-local}`, `${BUILD_DATE:-}`
  - Security hardening: `read_only: true`, `tmpfs: /tmp:noexec,nosuid,size=64m`, `no-new-privileges:true`
  - Port 8080 exposed, `restart: unless-stopped`

- **CI/CD workflow** (`.github/workflows/docker-publish.yml`)
  - Triggered by `workflow_run` from CI (same gate pattern as `release.yml`) + PR direct trigger
  - Multi-arch build via QEMU + Docker Buildx
  - Semver tag strategy: `1.2.3`, `1.2`, `1`, `latest` on tagged releases; `edge` on main; `sha-*` always
  - SBOM + provenance attestation on release images
  - GitHub Actions cache for layer reuse
  - All 5 Docker action SHAs pinned and verified: metadata-action v5.10.0, setup-qemu v3.7.0, setup-buildx v3.12.0, login v3.7.0, build-push v6.18.0

- **`.dockerignore`** minimizes build context and prevents sensitive content leaks
  - Excludes `.git`, `.github`, `.claude`, IDE configs, tests, docs, build artifacts
  - Excludes `payloads/premium/` and `payloads/.cache/` to prevent licensed content from leaking into public images

#### MCP Server — AI-Native WAF Testing Interface

- **Enterprise MCP Server** (`pkg/mcpserver/`): Model Context Protocol server enabling AI agents (Claude, GPT, Copilot) and automation platforms (n8n, Langflow) to control WAFtester programmatically
  - Full [MCP 2025-03-26 specification](https://modelcontextprotocol.io/) compliance via Go SDK v1.2.0
  - **Dual transport**: Stdio for IDE integrations (VS Code, Claude Desktop, Cursor) + HTTP for remote/Docker deployments
  - **Dual HTTP protocol**: Streamable HTTP (`/mcp`) for modern clients + legacy SSE (`/sse`) for n8n and older MCP clients
  - CORS middleware for browser-based and cross-origin MCP clients
  - Health endpoint (`/health`) for Kubernetes/Docker readiness probes

- **10 MCP Tools** with opinionated descriptions optimized for LLM tool selection:

  | Tool | Purpose |
  |------|---------|
  | `list_payloads` | Browse attack payload catalog with category/severity filtering |
  | `detect_waf` | Fingerprint WAF vendor, version, and CDN layers |
  | `discover` | Map attack surface from robots.txt, sitemap, JS, Wayback Machine |
  | `learn` | Generate intelligent test plans from discovery results |
  | `scan` | Execute WAF bypass tests with curated payloads |
  | `assess` | Enterprise assessment with F1, precision, MCC, FPR metrics |
  | `mutate` | Apply encoding/evasion transformations to payloads |
  | `bypass` | Systematic bypass testing with mutation matrix |
  | `probe` | TLS, HTTP/2, and technology fingerprinting |
  | `generate_cicd` | Generate CI/CD pipeline YAML (GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI, Bitbucket) |

- **8 MCP Resources** providing domain knowledge without network calls:
  - `waftester://version` — Server capabilities and tool inventory
  - `waftester://payloads` — Full payload catalog with category breakdown
  - `waftester://payloads/{category}` — Per-category payload listing (template)
  - `waftester://guide` — Comprehensive WAF testing methodology guide
  - `waftester://waf-signatures` — 12 WAF vendor signatures with bypass tips
  - `waftester://evasion-techniques` — Evasion encoding catalog with effectiveness ratings
  - `waftester://owasp-mappings` — OWASP Top 10 2021 category mappings with CWE references
  - `waftester://config` — Default configuration values and bounds

- **5 MCP Prompts** for guided workflow templates:
  - `security_audit` — Full security assessment workflow
  - `waf_bypass` — Targeted bypass hunting with stealth options
  - `full_assessment` — Enterprise assessment with statistical metrics
  - `discovery_workflow` — Attack surface mapping workflow
  - `evasion_research` — Payload evasion research and encoding

- **Comprehensive Server Instructions**: 300+ line operating manual embedded in server that guides AI agents through tool selection, workflow orchestration, result interpretation, rate limiting, and error recovery

- **n8n Integration**: Validated compatibility with n8n's MCP Client node
  - SSE transport endpoint at `/sse` (2024-11-05 spec)
  - Bearer, Header, and OAuth2 authentication support via CORS headers
  - Tool filtering (All/Selected/All Except) works with tool annotations

#### MCP Server Infrastructure

- **CORS Middleware**: Permissive cross-origin headers for browser-based clients
  - Origin echo (reflects request origin) with `*` fallback
  - Exposes `Mcp-Session-Id` header for session tracking
  - Allows `Authorization`, `Mcp-Session-Id`, `Last-Event-ID` headers
  - OPTIONS preflight with 24-hour cache (`Max-Age: 86400`)

- **Health Endpoint with Readiness**: `/health` endpoint for container orchestrators
  - Returns 503 `{"status":"starting"}` during startup validation
  - Transitions to 200 `{"status":"ok"}` after `MarkReady()` (payload dir validated)
  - Method-restricted to GET/HEAD (returns 405 for other methods)
  - JSON content type with proper CORS headers

- **Startup Payload Validation**: Server validates payload directory at startup before accepting connections
  - Checks directory exists, loads all payloads via `payloads.NewLoader()`
  - Logs payload count on success; exits with hint on failure
  - Prevents silent operation with missing/corrupted payload data

- **Environment Variable Support**: Docker/Kubernetes-friendly configuration
  - `WAF_TESTER_PAYLOAD_DIR` — override payload directory path
  - `WAF_TESTER_HTTP_ADDR` — set HTTP listen address (alternative to `--http` flag)

- **HTTP Server Hardening**: Production-grade HTTP server configuration
  - `ReadHeaderTimeout: 10s` — prevents slowloris attacks
  - `ReadTimeout: 30s`, `WriteTimeout: 60s`, `IdleTimeout: 120s`
  - `MaxHeaderBytes: 1MB` — limits header memory allocation

- **Graceful Shutdown**: Clean shutdown on SIGINT/SIGTERM
  - 15-second drain period for in-flight requests before forceful close
  - Logs shutdown progress to stderr

- **Progress Notifications**: Tools report `notifyProgress()` with percentage and status messages during long-running operations (scan, assess, bypass)

- **Structured Logging**: Tools emit `logToSession()` events with typed `mcp.LoggingLevel` constants for real-time operation visibility

### Fixed

- **P0 Data Race in Scan Tool**: `received` and `bypasses` counters in `handleScan` were bare `int` accessed from concurrent goroutines in the `OnResult` callback — replaced with `sync/atomic.Int64`
- **Logging Level Type Safety**: The MCP SDK defines `LoggingLevel` as `type string` with no exported constants — defined typed `logInfo`/`logWarning` constants to prevent raw string errors
- **Scan Tool Missing Annotations**: Added `ReadOnlyHint` and `IdempotentHint` to scan tool annotations (both `false`)
- **WAF Signatures Count Mismatch**: `total_signatures` was 25 but only 12 entries defined — corrected to 12
- **Target URL Validation**: All 6 network tools (`detect_waf`, `discover`, `scan`, `assess`, `bypass`, `probe`) now validate URL scheme (http/https only) and host before making requests — prevents confusing errors from malformed URLs
- **`json.MarshalIndent` Error Handling**: 5 resource handlers silently discarded marshal errors (`data, _ :=`) — all now use `data, err :=` and return `fmt.Errorf(...)` on failure
- **User-Agent Hardcoded String**: Replaced hardcoded `"waf-tester/probe"` in probe tool with `defaults.UserAgent("probe")` to match centralized UA management
- **Response Body Drain**: Probe tool now drains up to 4KB before closing response body (`io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))`) to allow HTTP connection reuse
- **WAF Vendor List Accuracy**: Version resource updated from 25 inaccurate vendor names to 26 actual WAF vendors matching the detection code; added `supported_cdn_vendors` field with 9 CDN entries
- **Server Instructions Accuracy**: Corrected payload count to "2,800+" and signature count to "26 WAF + 9 CDN detection signatures"; fixed waf-signatures resource reference from 26 to 12 entries
- **Bypass Tool Error Messages**: Empty target error now includes example JSON with both `target` and `payloads` fields, matching other tool error patterns

### Removed

- **Unused `SessionTimeout` Config Field**: Removed from `Config` struct along with unused `time` import

### Tests

- **44 tests** covering full MCP protocol surface:
  - Server creation (2): nil safety, default config
  - Tool registration (3): count, descriptions, annotations
  - Resource registration (2): static resources, template resources
  - Resource content (7): version, guide, WAF signatures, evasion techniques, OWASP mappings, config, payloads
  - Prompt registration (2): count, arguments
  - Prompt invocation (4): security_audit, waf_bypass, evasion_research, missing target
  - Tool invocation (5): list_payloads, list_payloads with filter, mutate, generate_cicd, generate_cicd all platforms (6 subtests)
  - Target URL validation (3): empty target rejection across all 6 network tools (6 subtests), invalid scheme rejection (ftp://), missing scheme rejection (bare hostname)
  - Hook tests (2): event bridge, nil callback
  - Server capabilities (1): initialization result validation
  - Edge cases (3): nonexistent tool/resource/prompt
  - HTTP transport (2): HTTPHandler, SSEHandler return non-nil
  - Health endpoint (3): 200 OK when ready, 503 Service Unavailable when not ready, 405 for invalid methods
  - CORS (3): headers with origin echo, preflight OPTIONS, default origin fallback
  - Data consistency (2): WAF signatures count matches entries, scan annotations complete

## [2.6.8] - 2026-02-06

### Added

#### New Output Formats
- **XML Export** (`--xml`): Legacy XML format for enterprise SIEM/vulnerability management platforms
  - DTD-style structure with full compliance mapping (CWE, OWASP, WASC)
  - Auto-populated WASC IDs via `defaults.GetWASCID()` mapping

#### New Integrations
- **Elasticsearch SIEM Integration** (`--elasticsearch-url`): Stream results to Elasticsearch
  - Bulk API support for high-throughput indexing
  - API key and basic auth support (`--elasticsearch-api-key`, `--elasticsearch-username`)
  - TLS skip verify option (`--elasticsearch-insecure`) for self-signed certs

- **GitHub Issues Integration** (`--github-issues-token`): Auto-create issues from bypasses
  - Creates formatted markdown issues with CWE links and severity labels
  - Configurable via `--github-issues-owner` and `--github-issues-repo`

- **Azure DevOps Integration** (`--ado-org`, `--ado-project`, `--ado-pat`): Auto-create work items from bypasses
  - Creates formatted HTML work items with severity/priority mapping
  - Supports Bug, Task, Issue work item types via `--ado-work-item-type`
  - Optional area path (`--ado-area-path`) and iteration path (`--ado-iteration-path`)
  - Includes repro steps with curl commands when available

- **Historical Scan Storage** (`--history-path`): JSON-based scan history for trend analysis
  - Stores detection rates, grades, category scores, latency metrics
  - Enables scan comparison and regression detection
  - Tag scans with `--history-tags` for organization

#### Report Customization
- **Template Configuration** (`--template-config`): YAML-based report customization
  - Pre-built templates: `minimal.yaml` (executive summary), `enterprise.yaml` (full audit)
  - Customize branding (logo, colors, company name)
  - Enable/disable sections (charts, metrics, compliance mapping)
  - Theme selection (light/dark/auto), print optimization

### Fixed
- **Missing CLI Wiring**: XML export, Elasticsearch, History, and Template Config flags were defined in `output.Config`/`BuildDispatcher` but never exposed via CLI flags — all 4 features are now fully wired into all 6 `Register*` variants with `ToConfig()` mapping
- **Elasticsearch Unbounded Read**: `io.ReadAll(resp.Body)` on error paths replaced with `io.LimitReader(resp.Body, 4096)` to prevent memory exhaustion from malicious servers
- **Elasticsearch Double-Flush Race**: `Write()` now drains buffer inside the lock before calling `bulkInsert()`, eliminating concurrent redundant HTTP calls
- **Template Config OR-Logic Bug**: `mergeSectionConfig()` used OR logic (`base || override`), making it impossible for minimal template to disable sections — now uses override values directly
- **Template ValidateConfig Silent Fix**: `ValidateConfig()` silently corrected invalid values instead of returning errors — now returns descriptive validation errors
- **History Store Crash Corruption**: `saveIndex()` now uses atomic write (temp file + `os.Rename`) to prevent data loss if process crashes mid-write
- **History ListAll Time Bound**: `ListAll()`/`GetLatest()` used `time.Now().Add(24h)` as upper bound — replaced with `time.Date(9999,...)` sentinel to handle clock drift
- **Raw http.Client Usage**: Elasticsearch and GitHub Issues now use `httpclient.New()` for proper timeouts and TLS config
- **WASC Mapping Unused**: XML writer now populates WASC field from category mapping

### Changed
- **Custom `itoa()` Removed**: Replaced hand-rolled 22-line `itoa()` in XML writer with `strconv.Itoa`
- **Custom `escapeHTML()` Removed**: Replaced custom HTML escaping in Azure DevOps hook with stdlib `html.EscapeString`
- **`WASCOrdered` Immutable**: Converted from mutable `var []string` to function returning a defensive copy
- **MergeConfig Expanded**: Template config merging now handles all fields including Sections, Styling, and Export settings
- **Release Packaging**: Template configs now included in release archives

### Removed
- **Duplicate Code**: Deleted ~800 lines of dead code in `pkg/integrations/` (duplicated hooks/jira.go and hooks/slack.go)

## [2.6.7] - 2026-02-05

### Added

#### High-Performance JSON Package
- **New `pkg/jsonutil` Package**: Drop-in replacement for `encoding/json` using `github.com/go-json-experiment/json`
  - 2-3x faster JSON marshaling/unmarshaling in hot paths
  - Compatible API: `Unmarshal`, `Marshal`, `MarshalIndent`, `NewStreamEncoder`, `NewStreamDecoder`
  - Streaming encoder with `SetIndent()` support matching `encoding/json` behavior
  - Comprehensive test suite with benchmarks

#### Structural Enforcement Tests
- **`TestHotPathsUseJsonutil`**: Verifies 8 hot path files use `jsonutil` instead of `encoding/json`
- **`TestUploadUsesBufferPool`**: Ensures `upload.go` uses `bufpool.Get()/Put()` for buffer management
- **`TestJsonutilPackageExists`**: Validates `jsonutil` has all required functions
- **`TestSlicePreallocationInHotPaths`**: Enforces minimum pre-allocated slices in hot paths
- **`TestGoreleaserHasTrimpath`**: Ensures `.goreleaser.yaml` includes `-trimpath` flag

### Changed

#### Performance Optimizations
- **Build Optimization**: Added `-trimpath` flag to goreleaser for smaller, reproducible binaries
- **Payload Loading**: Migrated `pkg/payloads/loader.go` and `database.go` to fast JSON
- **Output Writers**: Migrated `json.go`, `jsonl.go`, `sarif.go`, `html.go` to `jsonutil`
- **Export Builder**: Migrated all 7 encoder sites in `builder.go` to `jsonutil`
- **Upload Package**: Now uses `bufpool` for multipart buffer allocation + `jsonutil` for JSON

#### Memory Allocation Improvements
- **Slice Pre-allocation**: Added capacity hints to reduce allocations:
  - `pkg/payloads/loader.go`: `allPayloads := make([]Payload, 0, 2048)`
  - `pkg/xss/xss.go`: 6 pre-allocated slices in hot functions
  - `pkg/xxe/xxe.go`: 4 pre-allocated slices in payload generation

### Technical Details

- Package test coverage increased from 98.5% to 99.2% (132/133 packages)
- All 146 packages pass tests
- Binary size with optimizations: ~25.7 MB (with `-trimpath -s -w`)

## [2.6.6] - 2026-02-05

### Fixed

#### Critical Security Fixes
- **OAuth Predictable Tokens**: `GenerateState()`, `GenerateNonce()`, `GeneratePKCEPair()` now use `crypto/rand` instead of deterministic patterns - prevents CSRF and token hijacking attacks

#### High Priority Fixes
- **Checkpoint Double-Counting**: Fixed `MarkCompleted()` counting same target multiple times
- **Checkpoint Data Race**: Added mutex lock in `GetProgress()` before reading `CompletedTargets`
- **Checkpoint State Leak**: `GetState()` now returns defensive copy with deep-copied maps
- **Goroutine/Connection Leak**: Fixed `TimeoutDialer.DialContext()` in proxy.go - now checks context cancellation after dial
- **SSTI rand.Int Nil Panic**: Added error check with fallback values in `randomMathValues()`
- **SSTI Defer in Loop**: Replaced defer with immediate close to prevent connection exhaustion
- **OpenAPI http.Get Timeout**: `ParseURL()` now uses context with 30s timeout - prevents hanging on slow servers
- **SOAP Client No Context**: Added `CallWithContext()` with timeout/cancellation support

#### Medium Priority Fixes
- **TOCTOU Race**: Fixed race condition in `hosterrors.MarkError()` - all state modifications now under single lock
- **Detector.Clear Incomplete**: Now also calls `connMon.Clear()` to prevent stale connection data
- **WorkerPool Map/Filter Hang**: Added `wg.Done()` compensation when `Submit()` fails
- **WorkerPool Panic Respawn**: Worker now respawns after panic recovery
- **WorkerPool CAS Race**: Emergency worker spawning uses atomic CAS instead of check-then-increment
- **RateLimiter Missing Clear**: Added `ClearHost()` and `ClearAllHosts()` methods
- **WAF Strategy Cache Leak**: Added TTL-based eviction and max size limit (1000 entries, 30min TTL)
- **SSRF Callbacks Leak**: Added `ClearCallbacks()` and `CleanupExpiredCallbacks(maxAge)` methods
- **OOB Payloads Leak**: Added `ClearPayloads()` and `CleanupExpiredPayloads(maxAge)` methods
- **BatchCapturer Goroutine Leak**: `Stop()` now drains channels to unblock workers
- **Recursive Fuzzer Leak**: Added `ClearVisited()` and `Reset()` methods for memory management
- **Discovery Maps Nil Panic**: Initialize `discoveredSecrets`, `discoveredS3Buckets`, `discoveredSubdomains` in constructor
- **WildcardDetector Nil Check**: Added nil check before calling `AddBaseline()`
- **AI Context Cancellation**: `generateWithMutationsCtx()` now respects context cancellation
- **Gzip Reader Defer**: Use defer for gzip reader close - panic-safe resource cleanup
- **Wordlist Bounds Check**: `generateNumeric()` validates max > min and caps at 10M entries
- **Smuggling Unbounded Copy**: Added 10MB limit to `io.Copy` from network socket
- **DNS Context Leak**: Added `defer cancel()` after `context.WithCancel()`
- **NoSQL Body Close**: Use defer for response body close - panic-safe cleanup
- **TLS Redundant Mutex**: Removed unnecessary lock/unlock for already-captured profile variable

#### Low Priority Fixes
- **Runner Zero Burst**: Added `if burst < 1 { burst = 1 }` to prevent division by zero
- **apiabuse String Bug**: Fixed `string(rune(requests))` to `fmt.Sprintf("%d", requests)`
- **DNS Loop Variable Capture**: Capture resolver variable explicitly in closure

### Performance Improvements

- **Fuzzer Buffer Pooling**: Use `bufpool.GetSlice()` for body read buffers - reduces GC pressure
- **Fuzzer Byte-Based Counting**: `countWords()` and line counting operate on bytes, not strings
- **Fuzzer needsBodyString()**: Avoid string conversion when not needed
- **Runner Host Cache**: Added `sync.Map` cache for URL host extraction - eliminates repeated parsing
- **RateLimiter Atomic Time**: Changed `lastRequest` from `time.Time` to atomic `int64` nanoseconds
- **RateLimiter Reusable Timer**: Replaced `time.After()` allocations with reusable timer pattern
- **SQLi Quick-Check Filter**: `containsSQLKeyword()` fast-path avoids regex on non-SQL responses
- **JSHexEncoder O(n)**: Fixed O(n²) decode loop using `strconv.ParseUint` and `strings.Builder`

### Improved Error Handling

- **rand.Read Fallbacks**: All `rand.Read()` calls now check errors and provide time-based fallbacks:
  - `pkg/websocket/websocket.go`: `generateWebSocketKey()`
  - `pkg/cache/cache.go`: `generateCacheBuster()`
  - `pkg/realistic/calibration.go`: `randomHex()`
  - `pkg/jwt/jwt.go`: Random signature generation
  - `pkg/probes/jarm.go`: JARM probe random bytes

## [2.6.5] - 2026-02-06

### Added

- **Advanced Cognitive Modules** (`pkg/intelligence/`): 5 new learning subsystems for intelligent WAF analysis
  - **Bypass Predictor**: Predicts bypass probability before testing using learned patterns from:
    - Category success rates (SQLi, XSS, CMDI, etc.)
    - Encoding effectiveness (URL, Unicode, Hex, HTML entity)
    - Endpoint pattern recognition
    - Technology-specific vulnerabilities
  - **Mutation Strategist**: Suggests specific mutations when blocked, learns which bypass techniques work for specific WAF patterns
    - Built-in knowledge for Cloudflare, AWS WAF, Akamai, ModSecurity, Imperva, F5
    - Tracks encoding effectiveness and category-specific mutations
  - **Endpoint Clusterer**: Groups similar endpoints to optimize testing order
    - Reduces redundant testing on similar endpoints
    - Infers behavior from cluster representatives
    - Suggests optimal testing order based on cluster analysis
  - **Anomaly Detector**: Detects honeypots, silent bans, behavior shifts
    - Baseline calibration for normal server behavior
    - Rate limiting detection with automatic backoff
    - Honeypot detection (too-good-to-be-true bypass rates)
    - Silent ban detection (sudden behavior changes)
  - **Attack Path Optimizer**: Finds optimal paths through vulnerability chains
    - Graph-based attack modeling with escalation paths
    - Prioritizes high-value targets (RCE > SQLi > XSS)
    - Node pruning for memory-efficient large scans

- **WAF Profiler Integration**: Enhanced WAF fingerprinting with behavioral learning
  - Tracks bypass effectiveness by attack category
  - Records encoding success rates for targeted mutations
  - Latency analysis for blocked vs. bypassed requests
  - Automatic weakness/strength detection
  - Integrated with Engine for real-time profiling

- **Persistence Layer**: Save and resume brain state across sessions
  - `Engine.Save(path)` / `Engine.Load(path)` for file-based persistence
  - `Engine.ExportJSON()` / `Engine.ImportJSON()` for programmatic access
  - `Engine.Reset()` clears all learned state
  - Per-module Export/Import/Reset for granular control

- **Observability Metrics**: Performance tracking for intelligence operations
  - Findings processed/blocked/bypassed counters
  - Prediction accuracy tracking
  - Mutation success rate monitoring
  - Memory eviction tracking
  - Save/Load operation counters

- **Configuration System**: Centralized configuration for all modules
  - `PredictorConfig`, `MutatorConfig`, `ClustererConfig`, `AnomalyConfig`
  - `PathfinderConfig` with BFS depth limits and category values
  - `MemoryConfig` with eviction policies
  - `DefaultXxxConfig()` factory functions for sensible defaults

### Changed

- **Memory Management**: LRU eviction prevents unbounded memory growth
  - Default limit: 10,000 findings
  - Evicts oldest 10% when capacity reached
  - Configurable via `Memory.SetMaxFindings()`
  
- **BFS Pathfinding**: Added safety limits to prevent resource exhaustion
  - Configurable depth limit (default: 10)
  - Queue size limit (10,000 items) prevents memory exhaustion
  - Node pruning removes low-value paths

- **Empty Slice Returns**: Methods now return empty slices instead of nil
  - `Memory.GetByCategory()`, `Memory.GetByPhase()` return `[]` not `nil`
  - Safer for callers, no nil checks required

### Fixed

- **Data Loss Bug**: Memory.Import() now preserves category priorities
- **StatusCode Bug**: Fixed `extractBlockSignature()` using incorrect string conversion
  - Was: `string(rune(statusCode))` → garbage output
  - Now: `fmt.Sprintf("%d", statusCode)` → correct "403" output
- **Thread Safety**: Added mutex locks to callback setters (OnInsight, OnChain, OnAnomaly)
- **Nil Pointer**: Added nil checks in `feedAdvancedModules()` and `AddNode()`
- **formatPct**: Simplified overly complex percentage formatting function

## [2.6.4] - 2026-02-05

### Added

- **Brain Mode** (`pkg/intelligence/`): 🧠 Transform auto mode from "automated sequencing" to "adaptive reasoning"
  - **Learning Memory**: Stores all findings with indexing by category, phase, and path for cross-phase correlation
  - **WAF Behavioral Model**: Learns WAF patterns (block rates, weaknesses, strengths) to adapt attack strategies
  - **Technology Profiling**: Auto-detects frameworks, databases, servers, and languages to inform payload selection
  - **Attack Chain Building**: Combines low-severity findings into high-impact compound attacks:
    - Secret + Auth chains (leaked credentials + authentication endpoints)
    - Leaky Path + Parameter chains (exposed paths + injectable parameters)
    - Pattern Exploitation chains (consistent bypass patterns across endpoints)
    - SSRF + Cloud chains (SSRF vulnerabilities + cloud metadata endpoints)
    - XSS + DOM chains (XSS vulnerabilities + DOM sinks)
    - SQLi + Auth Bypass chains (SQL injection + authentication bypass)
  - **Smart Payload Recommendations**: Prioritizes payloads based on technology fingerprinting and bypass history
  - **Resource Optimization**: Allocates testing resources to most promising attack vectors
  - **Real-Time Insights**: Generates actionable insights during scan (bypass clusters, weak WAF rules, high-value endpoints)
  - New flags: `--brain` (enabled by default), `--brain-verbose`
  - Brain summary displayed before final report with top weaknesses, chains, and recommendations

- **Enhanced Auto Mode Intelligence**:
  - **Auto-Resume**: Interrupted auto scans can now be resumed from the last checkpoint using `--resume` flag
  - **Auto-Report Multi-Format**: Generates multiple report formats using `--report-formats` flag (supports json, md, html, sarif)
  - **Auto-Escalation**: Automatically reduces rate and concurrency when connection drops, silent bans, or HTTP 429 responses are detected
  - **Auto-Rate Adjustment**: Integrates adaptive rate limiting from `pkg/ratelimit` to dynamically adjust request rate based on WAF response

- **SARIF Report Generation**:
  - New SARIF 2.1.0 format output for CI/CD integration (GitHub Code Scanning, Azure DevOps)
  - Use `--report-formats sarif` or `--report-formats json,md,html,sarif` for multi-format output
  - SARIF reports include bypass severity scores, endpoint locations, and reproducible curl commands

- **New Auto Mode Flags**:
  - `--resume`: Resume a previously interrupted auto scan from checkpoint
  - `--checkpoint <file>`: Custom checkpoint file path (default: `<workspace>/checkpoint.json`)
  - `--report-formats <list>`: Comma-separated output formats (default: json,md,html)
  - `--adaptive-rate`: Enable dynamic rate adjustment based on WAF response (default: true)

- **Auto Mode Checkpoint Integration** (`pkg/checkpoint/`):
  - Auto mode now saves progress after each phase completion
  - Checkpoint file stored in workspace directory as `checkpoint.json`
  - Supports resumption from discovery, JS analysis, parameter discovery, and WAF testing phases

- **Detection-Triggered Auto-Escalation**:
  - Registers callbacks with `pkg/detection` to automatically respond to:
    - Connection drops (3+ consecutive drops trigger escalation)
    - Silent bans (WAF behavioral changes trigger escalation)
    - HTTP 429 Too Many Requests responses
  - Escalation reduces rate by 50% and concurrency by 50% (floors: rate=10, concurrency=5)
  - Maximum 5 escalation events per scan to prevent stalling

### Changed

- **Documentation Overhaul**:
  - Complete README.md rewrite with enterprise-grade structure and professional presentation
  - Reorganized content following industry best practices (Nuclei, Trivy, httpx patterns)
  - Added problem/solution narrative explaining WAFtester's value proposition
  - Enhanced comparison tables with detailed feature breakdowns
  - Removed all emojis for enterprise consistency

- **Examples Guide Enhancement** (`docs/EXAMPLES.md`):
  - Added detailed "When to Use" guidance for all core commands
  - Expanded command descriptions with business context and value propositions
  - Added interpretation guidance for assessment metrics
  - Included expected output descriptions for each command category
  - Structured examples by use case with recommendation tables

### Fixed

- Auto mode progress display correctly updates phase count during multi-format report generation
- Executor uses current adaptive rate values instead of initial flag values

---

## [2.6.3] - 2026-02-04

### Added

- **Comprehensive Proxy & SNI Support** (`pkg/httpclient/`):
  - **SOCKS4/SOCKS5/SOCKS5h Proxy Support**: Full compatibility with all major SOCKS proxy protocols
  - **SNI Override** (`--sni`): Override TLS ServerName for CDN bypass and origin testing
  - **Replay Proxy** (`--replay-proxy`/`-rp`): Duplicate traffic to security tools like Burp Suite
  - **Burp Suite Shortcut** (`--burp`): Automatically configures proxy to 127.0.0.1:8080
  - **ZAP Shortcut** (`--zap`): Automatically configures proxy to 127.0.0.1:8081
  - **DNS-over-Proxy** (`socks5h://`): Route DNS lookups through SOCKS5 proxy for enhanced anonymity
  - **Timeout Dialer**: Configurable connection timeouts for SOCKS proxies (matches fastdialer pattern)

- **New CLI Flags**:
  - `--sni <hostname>`: Override TLS SNI for origin server testing behind CDN/WAF
  - `--replay-proxy <url>` / `-rp <url>`: Send duplicate requests to security proxy
  - `--burp`: Shortcut for `--proxy http://127.0.0.1:8080` (Burp Suite default)
  - `--zap`: Shortcut for `--proxy http://127.0.0.1:8081` (OWASP ZAP default)

- **HTTP Client Enhancements** (`pkg/httpclient/`):
  - `proxy.go`: New module for proxy URL parsing, validation, and SOCKS dialer creation
  - `ParseProxyURL()`: Parse and validate proxy URLs with scheme-aware default ports
  - `CreateSOCKSDialer()`: Create SOCKS4/5/5h dialers with authentication support
  - `ValidateProxyURL()`: Validate proxy URLs support (http, https, socks4, socks5, socks5h)
  - `TimeoutDialer`: Wrapper for proxied connections with configurable timeouts
  - `WithSNI()`, `WithProxyAndSNI()`, `WithBurp()`, `WithZAP()`: Convenience functions

- **Output Enhancements**:
  - Proxy, ReplayProxy, and SNI fields added to JSON output metadata
  - Streaming events include proxy/SNI configuration in scan config
  - Enhanced JSON output includes full execution metadata with proxy settings

- **Competitive Parity**: Feature matching with industry-leading tools
  - Matches nuclei: HTTP/SOCKS5 proxy, proxy-all, SNI passthrough
  - Matches ffuf: replay-proxy for Burp integration
  - Matches feroxbuster: --burp shortcut convenience
  - Matches httpx: sni parameter for TLS override
  - Exceeds many competitors: socks5h DNS-over-proxy support

### Changed

- Updated `pkg/httpclient/httpclient.go` Config struct with SNI, ReplayProxy, ProxyDNS fields
- Updated `pkg/config/config.go` with new proxy/SNI CLI flag definitions
- Updated `pkg/output/events/start.go` ScanConfig with proxy metadata
- Updated `pkg/output/enhanced.go` ExecutionMetadata with proxy/SNI fields

### Tests

- Added comprehensive proxy test suite (`pkg/httpclient/proxy_test.go`):
  - ParseProxyURL: 12 test cases covering all supported schemes and edge cases
  - ProxyConfigAddress, ProxyConfigAuth, ProxyConfigDNSRemote tests
  - ValidateProxyURL tests for scheme validation
  - TimeoutDialer context timeout behavior tests
  - BurpProxyURL and ZAPProxyURL constant validation

---

## [2.6.2] - 2026-02-04

### Added

- **7 New CLI Commands**: Wire orphaned packages to CLI for full feature access
  - `template` / `nuclei`: Nuclei-compatible YAML template scanner
  - `grpc` / `grpc-test`: gRPC service testing via reflection
  - `soap` / `wsdl`: SOAP/WSDL service testing and fuzzing
  - `openapi` / `swagger`: OpenAPI specification security fuzzing
  - `cicd` / `pipeline`: CI/CD pipeline configuration generator
  - `plugin` / `plugins`: Plugin management system
  - `cloud` / `cloud-discover`: Cloud resource discovery (AWS, Azure, GCP)

- **Package Enhancements**:
  - `pkg/nuclei`: Added `FilterOptions` struct and `LoadDirectory()` for recursive template loading
  - `pkg/cloud`: Added `ResourceType` constants, `Discoverer`, `DiscovererConfig`, `DiscoveryRequest`, `DiscoveryResults`
  - `pkg/grpc`: Added `InvokeMethod()` for raw gRPC invocation with service/method parsing
  - `pkg/openapi`: Added `ParseFromFile()`, `ParseFromURL()` convenience functions
  - `pkg/openapi`: Added `TestGenerator`, `GeneratorOptions`, `GeneratedTestCase`, `ExecuteFuzzTest()`
  - `pkg/plugin`: Added `LoadBuiltins()`, `LoadFromDirectory()`, `IsBuiltin()`, `GetPluginInfo()`
  - `pkg/soap`: Added `FetchAndParseWSDL()`, `GetOperations()` for WSDL parsing
  - `pkg/ui`: Added ANSI color constants (Reset, Bold, Red, Green, Yellow, Blue, Magenta, Cyan, White, BoldRed)

- **Documentation**:
  - `docs/STRUCTURAL_ANALYSIS_REPORT.md`: Comprehensive codebase analysis report
  - Updated CLI usage documentation with new API & Protocol Testing section

### Fixed

- **Duplicate Function Resolution** (`pkg/nuclei/nuclei.go`):
  - Removed duplicate `FilterTemplates()` function, kept new `FilterOptions`-based version
  - Added missing `filepath` import for directory walking

- **Package Interface Corrections**:
  - Fixed `cmd_plugin.go` to handle two-value `manager.Get()` return
  - Fixed `pkg/soap/client.go` to use `duration.HTTPFuzzing` instead of hardcoded timeout

- **Test Fixes**:
  - Updated `pkg/nuclei/nuclei_test.go` to use new `FilterOptions` signature

### Changed

- Updated `cmd/cli/main.go` with 7 new command switch cases
- Updated `cmd/cli/cmd_docs.go` with new API & Protocol Testing section

---

## [2.6.1] - 2026-02-04

### Added

- **io_uring Support for Linux 5.1+** (`pkg/iouring/`): Zero-copy async I/O
  - `iouring_linux.go`: Full io_uring implementation with submission/completion queues
  - `iouring_stub.go`: Cross-platform stub for non-Linux systems
  - `Supported()`: Runtime detection of io_uring availability
  - `Read()/Write()`: Async file descriptor operations
  - Expected 2-5x throughput improvement on supported kernels

- **Platform-Specific Socket Optimizations** (`pkg/sockopt/`): High-performance networking
  - `sockopt_linux.go`: Linux socket tuning (TCP_NODELAY, 256KB buffers, TCP_QUICKACK)
  - `sockopt_stub.go`: No-op stub for other platforms
  - `OptimizeConn()`: Apply optimizations to existing connections
  - `DialControl()`: Pre-apply optimizations during dial
  - 10-20% latency reduction on Linux

- **HTTP Client Socket Integration** (`pkg/httpclient/httpclient.go`):
  - Integrated `sockopt.OptimizeConn()` for DNS-cached connections
  - Integrated `sockopt.DialControl()` for standard dialer
  - Automatic platform-specific optimization on all HTTP requests

- **New Tests**: 10 additional tests for new packages
  - `TestRingEmptyBuffer`: Empty/nil buffer handling for io_uring
  - `TestResponseReadFromReader`: Reader-based response pooling
  - `TestResponseReadFromReaderNil`: Nil reader handling
  - `TestResponseReadFromLimited`: Size-limited response reading
  - `TestPool_Go`: Worker pool Go() alias verification
  - `TestPool_Waiting`: Worker pool queue depth verification

### Fixed

- **Nil Pointer Prevention** (`pkg/sockopt/sockopt_linux.go`):
  - Added nil check in `OptimizeConn()` to prevent panic on nil connections

- **Empty Buffer Safety** (`pkg/iouring/iouring_linux.go`):
  - Added `len(buf) == 0` check in `Read()` to prevent index out of bounds
  - Added `len(buf) == 0` check in `Write()` to prevent index out of bounds

### Technical Details

- Build verification: `go build ./...` passes
- All 65 performance-related tests pass
- Lint verification: `golangci-lint run` clean
- Phase 4 of Performance Optimization Plan complete

---

## [2.6.0] - 2026-02-04

### Added

- **WAF Strategy Test Suite** (`pkg/waf/strategy/strategy_test.go`): 55 comprehensive tests
  - `TestNewStrategyEngine_*` - engine initialization tests
  - `TestBuildStrategy_*` - strategy building for all WAF vendors
  - `TestPipeline_*` - tamper pipeline execution tests
  - `TestRateLimiting_*` - WAF-aware rate limit configuration
  - `TestTamperIntegration_*` - tamper chain integration tests
  - `TestConcurrencySafety_*` - thread-safe strategy access

### Changed

- **Massive CLI Architecture Refactoring**: Split `cmd/cli/main.go` from **14,962 → 348 lines** (97.7% reduction)
  - Created 14 focused command files for better maintainability:
    - `cmd_scan.go` (2,553 lines) - vulnerability scanning command
    - `cmd_autoscan.go` (2,114 lines) - automatic WAF testing command
    - `cmd_probe.go` (3,424 lines) - protocol probing (httpx-compatible)
    - `cmd_docs.go` (1,269 lines) - all documentation printing functions
    - `cmd_misc.go` (824 lines) - smuggle, race, workflow, headless commands
    - `cmd_fuzz.go` (649 lines) - content fuzzing command
    - `cmd_tests.go` (543 lines) - WAF testing workflow command
    - `cmd_mutate.go` (505 lines) - payload mutation command
    - `cmd_crawl.go` (419 lines) - web crawling command
    - `cmd_admin.go` (382 lines) - validate, update, report commands
    - `cmd_bypass.go` (315 lines) - WAF bypass discovery command
    - `cmd_analyze.go` (263 lines) - response analysis command
    - `cmd_discover.go` (243 lines) - endpoint discovery command
    - `cmd_learn.go` (178 lines) - WAF behavior learning command

### Fixed

- **Flaky Test Fix** (`pkg/evasion/advanced/tampers/tampers_test.go`): Fixed `TestChainByPriority_RespectsOrder`
  - Replaced non-deterministic `modsecurityversioned` tamper with deterministic `base64encode` and `unmagicquotes`
  - Test now reliably verifies priority ordering (Priority 0 before Priority 100)

- **Security Hardening** (`pkg/workflow/workflow.go`): Command injection prevention
  - Added `isAllowedExternalCommand()` with strict allowlist (echo, cat, grep, curl, nuclei, python, etc.)
  - Added `validateFilePath()` for path traversal protection
  - Blocks `..`, absolute paths, and suspicious patterns

- **Cryptographic Randomness**: Replaced insecure `math/rand` with `crypto/rand`
  - `pkg/tls/ja3.go`: Fixed 3 occurrences of random JA3 fingerprint generation
  - `pkg/ssrf/ssrf.go`: Fixed random ID generation for SSRF probes

### Removed

- **Duplicate Packages**: Deleted 3 redundant packages to reduce codebase confusion
  - `pkg/businesslogic/` - duplicate of `pkg/bizlogic/`
  - `pkg/insecuredeser/` - duplicate of `pkg/deserialize/`
  - `pkg/openredirect/` - duplicate of `pkg/redirect/`

### Technical Details

- Updated `cmd/cli/dispatcher_wiring_test.go` to scan all new command files
- All dispatcher wiring tests pass with new file structure
- Build verification: `go build ./...` passes
- Test verification: All CLI and structural tests pass

---

## [2.5.3] - 2026-02-03

### Added

- **Comprehensive Test Coverage Initiative**: 127 new tests bringing total from 3,321 to 3,448

- **Dispatcher Unit Tests** (`pkg/output/dispatcher/dispatcher_test.go`): 26 new tests
  - `TestNew_DefaultBatchSize`, `TestNew_CustomBatchSize` - configuration tests
  - `TestDispatch_ConcurrentSafe` - race-safe with 10 goroutines × 100 events
  - `TestWriterFailure_OthersStillReceive` - failure isolation verification
  - `TestAsyncHooks_NonBlocking` vs `TestSyncHooks_Blocking` - hook behavior
  - `TestRegisterDuringDispatch_Race` - concurrent registration safety
  - Thread-safe mockWriter/mockHook helpers with atomic counters

- **Core Race Tests** (`pkg/core/race_test.go`): 5 new tests
  - `TestExecutor_ConcurrentExecuteTest` - 50 payloads from multiple goroutines
  - `TestExecutor_SharedHTTPClient_Race` - 100 goroutines × 5 requests
  - `TestExecutor_RateLimiter_Race` - concurrent rate limit checks
  - `TestExecutor_Execute_Race` - full worker pool under load
  - `TestExecutor_OnResultCallback_Race` - callback thread safety

- **Evasion Package Tests** (`pkg/evasion/advanced/tampers/tampers_test.go`): 11 new tests
  - `TestGetAllTampers_NotEmpty` - verifies 68 tampers registered
  - `TestTamper_Apply_Transforms` - verifies transformation behavior
  - `TestTamper_ConcurrentApply` - 50 goroutines × 100 iterations
  - `TestTamperChain_AppliesInOrder` - chain ordering verification

- **Missing Package Tests**: 53 new tests across 4 packages
  - `pkg/leakypaths/leakypaths_test.go` - 10 tests for path detection
  - `pkg/params/params_test.go` - 12 tests for parameter handling
  - `pkg/recon/recon_test.go` - 11 tests for reconnaissance
  - `pkg/tls/tls_test.go` - 20 tests for TLS/JA3 fingerprinting

- **Mutation Concurrent Tests** (`pkg/mutation/registry_test.go`): 3 new tests
  - `TestRegistry_ConcurrentMutateWithAll` - 50 parallel goroutines
  - `TestRegistry_ConcurrentRegisterAndMutate` - concurrent ops
  - `TestChainMutate_ConcurrentChains` - parallel chain execution

- **Multi-Writer Integration Tests** (`pkg/output/integration_test.go`): 2 new tests
  - `TestMultiWriterScenario_JSONAndSARIF` - dual format output
  - `TestMultiWriterScenario_AllFormats` - json, sarif, csv, md, html

- **Runner Race Tests** (`pkg/runner/runner_test.go`): 4 new tests
  - `TestRunner_Run_ConcurrentStatsUpdate` - stats consistency under load
  - `TestRunner_Run_CallbackRace` - thread-safe callbacks
  - `TestRunner_HighConcurrency` - 100 targets × 50 workers
  - `TestRunner_RunWithCallback_ConcurrentRace` - streaming callbacks

- **Hook Contract Tests** (`pkg/output/hooks/hooks_test.go`): 6 new tests
  - `TestAllHooks_ImplementInterface` - compile-time checks
  - `TestSlackHook_RetryBehavior` - 5xx retry verification
  - `TestTeamsHook_Timeout` - timeout handling
  - `TestPrometheusHook_MetricsExport` - 7 core metrics
  - `TestOtelHook_SpanCreation` - trace span verification

- **Event Flow Tests** (`pkg/output/events/events_test.go`): 4 new tests
  - `TestEvent_ConcurrentJSON_Race` - 100 goroutines marshaling
  - `TestResultEvent_ConcurrentAccess` - parallel field reads
  - `TestBypassEvent_ConcurrentAccess` - parallel field reads
  - `TestSummaryEvent_ConcurrentAccess` - parallel field reads

- **Checkpoint Race Tests** (`pkg/checkpoint/checkpoint_test.go`): 5 new tests
  - `TestCheckpoint_ConcurrentMarkAndCheck` - parallel operations
  - `TestCheckpoint_ConcurrentSave` - parallel save operations
  - `TestCheckpoint_RapidUpdates` - rapid mixed operations
  - `TestCheckpoint_ConcurrentLoad` - concurrent file access
  - `TestCheckpoint_ConcurrentGetPending` - parallel pending retrieval

- **CLI Integration Tests** (`cmd/cli/integration_test.go`): 8 new tests
  - `TestCLI_Help_ShowsCommands` - help output verification
  - `TestCLI_InvalidCommand_ShowsHelp` - error handling
  - `TestCLI_Version_ShowsVersion` - version variants
  - `TestCLI_Validate_ValidPayloadFile` - real file validation
  - `TestCLI_Validate_InvalidFile` - error handling
  - Guarded with `WAFTESTER_INTEGRATION=1` env check

- **Structural Verification Tests** (`test/structural_test.go`): 6 new tests
  - `TestAllPackagesHaveTests` - 130/131 packages covered (99.2%)
  - `TestDispatcherWiringComplete` - 9 wiring test functions
  - `TestNoTODOsInTests` - informational scan
  - `TestVersion_Consistent` - semver validation
  - `TestCmdCliHasDispatcherWiringTests` - existence check
  - `TestGoModConsistency` - module configuration

- **CI Race Detection Workflow** (`.github/workflows/race-test.yml`)
  - Triggers on push to main/develop and PRs
  - Uses ubuntu-latest with gcc for race detector
  - Full race test: `go test -race -timeout 10m ./...`
  - Focused race tests: `go test -race -run ".*Race.*|.*Concurrent.*"`
  - Coverage reporting with artifact upload

### Changed

- Upgraded test count from 3,321 to 3,448 (+127 tests, +3.8%)
- Package test coverage: 184/189 → 188/189 (99.5%)
- Added race-safe patterns across all new tests using atomic operations

### Technical Details

- All concurrent tests use `sync.WaitGroup` for goroutine coordination
- Counter verification uses `atomic.Int32` or `sync/atomic` operations
- Mock implementations are thread-safe with `sync.Mutex` protection
- Tests designed to complete quickly (~50ms average per concurrent test)

---

## [2.5.2] - 2026-02-03

### Added

- **Connection Drop Detection** (`pkg/detection`): Comprehensive network-level failure detection
  - TCP Reset (RST) detection - catches forced connection terminations
  - TLS Handshake Abort detection - identifies SSL/TLS negotiation failures
  - Connection Timeout detection - detects unresponsive targets
  - Unexpected EOF detection - catches mid-stream connection closures
  - Tarpit detection - identifies intentional slow-response blocking (3x baseline threshold)
  - Connection Refused detection - catches active port rejection
  - DNS Resolution Failure detection - identifies hostname lookup issues
  - Per-host tracking with thread-safe atomic counters
  - Automatic recovery detection after consecutive successful probes

- **Silent Ban Detection** (`pkg/detection`): Behavioral analysis for subtle blocking patterns
  - Latency drift detection - flags 200%+ response time increases vs baseline
  - Body size drift detection - catches 50%+ content size changes
  - Header change monitoring - detects WAF header injection (Server, X-Cache, CF-Ray, etc.)
  - Consecutive error tracking - identifies systematic failures
  - Honeypot detection - catches 90%+ body size changes indicating redirect
  - Confidence scoring system (0.0-1.0) with multi-factor analysis
  - Ban type classification: RateLimit, IPBlock, Behavioral, Honeypot, GeoBlock, SessionPoison

- **Unified Detection Interface**: Combined monitoring with skip recommendations
  - `detection.Default()` singleton for global access
  - `ShouldSkipHost()` - returns skip recommendation with reason
  - `RecordError()`/`RecordResponse()` - unified tracking API
  - `CaptureBaseline()` - establishes normal behavior metrics
  - Thread-safe design with sync.RWMutex protection

- **Unified Detection Stats Output** (`pkg/output/detection`): Centralized stats display
  - Multi-format output: Console, JSON, Markdown, SARIF
  - `Stats` struct with `DropsDetected`, `BansDetected`, `HostsSkipped`, `Details`
  - `FromDetector()` - extracts stats from global detector singleton
  - `FromProvider()` - extracts from any `StatsProvider` interface implementation
  - `FromMap()` - constructs from `map[string]int` for flexible integration
  - `HasData()`, `Severity()`, `ExitCodeContribution()` - analysis methods
  - `ToJSON()` - structured JSON output for summary files
  - `WriteTo(io.Writer, Format)` - format-agnostic output
  - `PrintConsole()` - colorized console output with severity indicators
  - `Recommendations()` - actionable advice based on detection stats
  - Contract tests ensure all formats include required fields
  - Used by: `cmd/cli/assess.go`, `pkg/output/writer.go`, `cmd/cli/main.go`

- **New Configuration Constants** (`pkg/defaults`, Section 2.5.2):
  - `DropDetectConsecutiveThreshold` (3) - failures before flagging
  - `DropDetectTimeoutMultiplier` (3.0) - tarpit detection threshold
  - `DropDetectRecoveryProbes` (2) - successes needed for recovery
  - `DropDetectRecoveryWindow` (30s) - max backoff wait time
  - `SilentBanLatencyDriftThreshold` (2.0) - 200% latency increase
  - `SilentBanBodySizeDriftThreshold` (0.5) - 50% size change
  - `SilentBanConsecutiveErrors` (5) - error count threshold
  - `SilentBanMinSamples` (10) - minimum baseline samples
  - `SilentBanHeaderChangeThreshold` (3) - header change count
  - `SilentBanCooldownPeriod` (60s) - wait time after detection

### Technical Details

- New package: `pkg/detection/` with 5 files (types.go, connmon.go, silentban.go, detector.go, detector_test.go)
- 44 unit tests covering all detection scenarios
- Exponential backoff for recovery: 5s base, doubling up to 30s max
- EMA (α=0.3) for baseline latency/body size smoothing
- Key header monitoring: Server, X-Cache, X-CDN, CF-Ray, X-Request-ID, Set-Cookie, Content-Type, X-Frame-Options

### Integration

- **Executor Integration** (`pkg/core/executor.go`): Detection wired into test execution
  - Automatic baseline capture on successful responses
  - Drop detection on network errors with enhanced error categorization
  - Silent ban detection on response analysis
  - Skip recommendation before each request
  - Tarpit detection on slow responses

- **TestResult Fields** (`pkg/output/types.go`): New fields for detection data
  - `DropDetected`, `DropType` - connection drop information
  - `BanDetected`, `BanType`, `BanConfidence` - silent ban details
  - `LatencyDrift` - latency change ratio vs baseline

- **Event Types** (`pkg/output/events/detection.go`): Streaming events
  - `EventTypeDropDetected` - for connection drop events
  - `EventTypeBanDetected` - for silent ban events
  - `DropDetectedEvent`, `BanDetectedEvent` - structured event types

- **Hosterrors Bridge** (`pkg/detection/detector.go`): Synergy with existing cache
  - `SyncWithHostErrors()` - bridges detection with hosterrors cache
  - `ClearHostErrors()` - clears both systems
  - `ClearAll()` - resets all detection state for new scans
  - Automatic sync on 3+ consecutive drops
  - Permanent marking on high-confidence (≥80%) bans

- **CLI Hook Emitters** (`cmd/cli/output.go`): Real-time alerts for detection events
  - `EmitDropDetected()` - sends drop events to Slack, Teams, PagerDuty, OTEL
  - `EmitBanDetected()` - sends ban events to all configured hooks

- **Runner Integration** (`pkg/runner/runner.go`): Multi-target detection support
  - `EnableDetection()` - opt-in detection for runner tasks
  - Skip recommendation before each target
  - Error recording for failed tasks

- **Realistic Package Bridge** (`pkg/realistic/executor_integration.go`): Unified detection
  - `UseUnifiedDetection()` - enables unified detector alongside block detection
  - `ShouldSkipHost()` - check skip recommendation from unified detector

- **Execution Statistics** (`pkg/output/types.go`, `pkg/core/executor.go`):
  - `DropsDetected`, `BansDetected`, `HostsSkipped` in ExecutionResults
  - `DetectionStats` map with detailed detector metrics

- **CLI Detection Flag** (`pkg/config/config.go`): User control over detection
  - `--detect` / `--detection` flag (default: true)
  - Allows disabling detection when not needed

- **Assessment Integration** (`pkg/assessment/assessment.go`): Enterprise assessment detection
  - Detection system integrated into assessment workflow
  - Host skip checks before each payload test
  - Error/response recording for accurate metrics

- **Mutation Executor Integration** (`pkg/mutation/executor.go`): Bypass testing detection
  - Detection system integrated into mutation-based testing
  - Host skip checks prevent wasted requests on blocked hosts
  - Error/response recording for all mutation tests

- **Report Statistics** (`pkg/report/report.go`): Enterprise reports include detection
  - `DropsDetected`, `BansDetected`, `HostsSkipped` fields in Statistics
  - `DetectionStats` map for detailed breakdown

- **Fuzzer Integration** (`pkg/fuzz/fuzzer.go`): Directory fuzzing detection
  - Detection system integrated into content/directory fuzzing
  - Host skip checks prevent wasted requests on banned hosts
  - Error/response recording for all fuzz requests

- **API Fuzzer Integration** (`pkg/apifuzz/apifuzz.go`): API fuzzing detection
  - Detection system integrated into API endpoint fuzzing
  - Host skip checks in sendFuzzRequest and sendBodyFuzzRequest
  - Error/response recording for all API fuzz operations

- **Recursive Fuzzer Integration** (`pkg/recursive/recursive.go`): Recursive scanning detection
  - Detection system integrated into recursive directory scanning
  - Host skip checks before each directory request
  - Error/response recording with latency tracking

- **Detection Transport Wrapper** (`pkg/detection/transport.go`): Universal HTTP client wrapper
  - `WrapTransport()` - wraps any `http.RoundTripper` with detection
  - `WrapClient()` - convenience function to wrap existing `*http.Client`
  - `SkipHostError` - returned when host should be skipped
  - Automatic error/response recording for all requests
  - Pre-request skip checks prevent wasted requests
  - Zero-config integration with existing HTTP code

- **CLI Assess Command Integration** (`cmd/cli/main.go`): Deep scan detection
  - HTTP client wrapped with detection transport
  - Per-scanner skip checks in `runScanner()` helper
  - Emits `scanner_skipped` event when host is blocked
  - Prevents wasted time on banned hosts during vulnerability scans

- **HTTP Probe Detection** (`cmd/cli/main.go`): Probe request detection
  - `makeProbeHTTPRequestWithOptions()` wrapped with detection
  - All HTTP probing benefits from automatic detection

## [2.5.1] - 2026-02-03

### Fixed

- **Version Consistency**: Update `defaults.Version` to match release tag
- **GoReleaser Deprecations**: Fix deprecated config options
  - `snapshot.name_template` → `snapshot.version_template`
  - `archives.format` → `archives.formats` array
  - `archives.format_overrides.format` → `archives.overrides.formats`

## [2.5.0] - 2026-02-03

### Added

- **Complete Streaming/Hook Integration**: All 22 CLI commands now emit to enterprise hooks
  - Every command emits `EmitStart` for scan lifecycle tracking
  - Every command emits `EmitSummary` for completion metrics
  - Test-based commands (auto, run, mutate, bypass) emit `EmitResult` for individual test telemetry
  - Error paths emit `EmitError` for alerting on failures
  - Discovery commands emit `EmitBypass` for vulnerability/finding events
  - **179 total emission points** across the CLI

- **Architecture Enforcement Tests**: Prevent regression of hook wiring
  - `TestDispatcherWiringMinimumEmissions`: Minimum counts per emission method
  - `TestAllDispatcherContextsHaveEmitStart`: All 22 dispatchers emit start
  - `TestAllDispatcherContextsHaveEmitSummary`: All 15 summary-worthy dispatchers emit
  - `TestTestBasedCommandsHaveEmitResult`: 4 test commands emit per-result telemetry
  - `TestOnResultCallbacksHaveEmitResult`: OnResult callbacks wired to hooks
  - `TestMutationCallbacksHaveEmitResult`: Mutation callbacks wired to hooks
  - `TestErrorPathsHaveEmitError`: 11 error-prone commands emit errors
  - `TestDispatcherContextsHaveDeferClose`: All dispatchers properly closed
  - `TestNoOrphanedDispatcherContexts`: No init without EmitStart+Close

- **Streaming Event Architecture**: Real-time CI/CD-friendly output
  - New `pkg/output/events` package with typed events (Start, Progress, Result, Bypass, Summary, Complete, Error)
  - NDJSON streaming mode for pipeline integration (`-stream -json`)
  - Events emit to stdout while progress goes to stderr for proper pipe handling

- **Unified Output Builder**: Factory pattern for all output writers
  - New `pkg/output/builder.go` with fluent API for constructing output pipelines
  - Single entrypoint for all 15 writers with consistent configuration
  - Thread-safe dispatcher for concurrent multi-format output

- **15 Output Writers** (6 new in v2.5.0):
  - **JUnit XML** (`-format junit`): CI/CD test framework integration for Jenkins, GitLab CI, Azure DevOps
  - **CycloneDX VEX** (`-format cyclonedx`): SBOM vulnerability exchange format v1.5
  - **GitLab SAST** (`-format gitlab-sast`): Native gl-sast-report.json for GitLab Security Dashboard
  - **SonarQube** (`-format sonarqube`): Generic Issue Import format
  - **DefectDojo** (`-format defectdojo`): Vulnerability management platform import
  - **HAR** (`-format har`): HTTP Archive format for request/response analysis
  - Enhanced existing writers: HTML (themes), Markdown (TOC, OWASP sections), PDF (branding), CSV (OWASP columns)

- **8 Real-time Alerting Hooks**:
  - **Slack** (`--slack-webhook`): Rich message formatting with severity colors, field blocks
  - **Microsoft Teams** (`--teams-webhook`): Adaptive Cards with action buttons
  - **PagerDuty** (`--pagerduty-key`): Incident creation with severity routing
  - **Jira** (`--jira-url`, `--jira-project`): Automatic issue creation with configurable project/type
  - **GitHub Issues** (`--github-issues-token`, `--github-issues-owner`, `--github-issues-repo`): Auto-create issues for bypasses
  - **Azure DevOps** (`--ado-org`, `--ado-project`, `--ado-pat`): Work item creation with severity mapping
  - **OpenTelemetry** (`--otel-endpoint`): Distributed tracing with scan spans and finding events
  - **Prometheus** (`--metrics-port`): Metrics exposition endpoint for monitoring
  - **Generic Webhook** (`--webhook`): Custom HTTP POST for any integration

- **Exit Code Policy Engine**: Configurable pipeline failure conditions
  - New `pkg/output/policy` package for declarative exit code rules
  - Threshold-based (count, severity) and condition-based (bypass found) policies
  - CI/CD-friendly exit codes: 0=clean, 1=findings, 2=critical, 3=bypass

- **Baseline Comparison**: Track security posture over time
  - New `pkg/output/baseline` package for finding comparison
  - Detects new, fixed, and unchanged vulnerabilities between scans
  - JSON baseline files for CI/CD regression detection

- **Centralized OWASP Data**: Single source of truth for compliance mapping
  - New `pkg/defaults/owasp.go` with `OWASPTop10` map and utilities
  - `GetOWASPInfo(code)`, `GetAllOWASPCodes()`, `FormatOWASPReference()` helpers
  - AST-based guard test prevents OWASP duplication across codebase

- **Smart Mode Hook Integration**: WAF detection and bypass hints emit to CI/CD
  - Detected WAF vendor/confidence emits to all configured hooks
  - Recommended tampers for detected WAF sent to alerting channels
  - Bypass discovery hints streamed in real-time

- **Comprehensive Finding Emissions**: All security discoveries emit to hooks
  - Cloud assets: S3 buckets, subdomains, cloud URLs, attack surface
  - Browser risks, TLS issues, certificate problems
  - OAuth/SAML endpoints, authentication attack surface
  - Template validation errors, workflow step completions
  - Crawled scripts, headless page discoveries, probe technology detection
  - Policy violations from security misconfigurations

- **Centralized Timeout Configuration**: All durations in `pkg/duration`
  - Migrated hardcoded timeouts across 40+ files
  - `duration.Timeout*` and `duration.Interval*` constants
  - Prometheus hook uses centralized timeout values

### Changed

- **CLI Output Integration**: All scan commands now use unified output architecture
  - `cmd/cli/output.go` bridges CLI flags to output builder
  - Consistent flag handling for format, hooks, streaming, templates
  - Automatic format detection from file extension

- **HTML Reports**: Nuclei-level quality with interactive features
  - 4 themes: light, dark, corporate, security
  - Interactive severity charts with Chart.js
  - Collapsible finding details, syntax-highlighted code blocks
  - Executive summary with key metrics

- **PDF Reports**: Professional executive quality
  - Custom branding, signatures, watermarks
  - OWASP Top 10 compliance matrix
  - Severity distribution pie charts
  - Page headers/footers with metadata

- **Markdown Reports**: Wiki-ready documentation
  - Auto-generated table of contents (`--md-toc`)
  - OWASP category grouping (`--md-owasp`)
  - Collapsible sections with evidence

### Fixed

- **OpenTelemetry Hook**: Uses `defaults.Version` for service version
- **OpenTelemetry Tests**: Skip gracefully when collector unavailable
- **Webhook Hook**: Uses `defaults.RetryMedium` instead of hardcoded retry count
- **GitLab SAST Version**: Spec version (15.0.0) excluded from version consistency test
- **Prometheus Timeout**: Uses `duration.TimeoutHTTP` instead of hardcoded value
- **Tool Names**: Centralized hardcoded tool name strings

### Tests

- **29,000+ lines** of comprehensive test coverage:
  - `pkg/output/writers/writers_test.go`: All 15 writers
  - `pkg/output/hooks/hooks_test.go`: All 8 hooks
  - `pkg/output/events/events_test.go`: Event serialization/deserialization
  - `pkg/output/policy/policy_test.go`: Exit code policy evaluation
  - `pkg/output/baseline/baseline_test.go`: Baseline comparison logic
  - `pkg/output/integration_test.go`: End-to-end output pipeline
  - `pkg/defaults/defaults_test.go`: OWASP duplication guard
  - `cmd/cli/dispatcher_wiring_test.go`: 9 architecture enforcement tests (350 lines)

### Documentation

- **README.md**: Updated output formats table, enterprise integrations, alerting hooks
- **EXAMPLES.md**: Added JUnit, CycloneDX, GitHub Actions, OpenTelemetry sections
- **Integration Guide**: Comprehensive guide for CI/CD pipeline integration
- **Sample Outputs**: Complete sample output files for all 15 formats
- **SECURITY.md**: Updated supported versions for v2.5.x
- **CONTRIBUTING.md**: Added dispatcher wiring enforcement tests

## [2.4.3] - 2026-02-02

### Added
- **HTTP Client Pooling**: Industry-aligned connection pooling with semantic presets
  - New `pkg/httpclient` package with `NewScanner()`, `NewProbing()`, `NewAggressive()` presets
  - Aligned with fasthttp, Caddy, Traefik, Nuclei, HTTPx best practices
  
- **Centralized Configuration**: Single source of truth for all runtime defaults
  - New `pkg/defaults` package: Concurrency, Retry, Buffer, Channel, ContentType, UserAgent, Depth, MaxRedirects
  - New `pkg/duration` package: All timeout and interval constants
  
- **10 AST-Based Enforcement Tests**: Prevent configuration drift at compile time
  - `TestVersionConsistency`: Ensures ui.Version == defaults.Version, checks SECURITY.md
  - `TestNoHardcodedConcurrency`: All concurrency values use `defaults.Concurrency*`
  - `TestNoHardcodedRetries`: All retry counts use `defaults.Retry*`
  - `TestNoHardcodedMaxDepth`: All depth limits use `defaults.Depth*`
  - `TestNoHardcodedMaxRedirects`: All redirect limits use `defaults.MaxRedirects`
  - `TestNoHardcodedContentType`: All content types use `defaults.ContentType*`
  - `TestNoHardcodedUserAgent`: All UAs use `defaults.UA*` or `ui.UserAgentWithContext()`
  - `TestNoHardcodedTimeouts`: All timeouts use `duration.Timeout*`
  - `TestNoHardcodedIntervals`: All intervals use `duration.Interval*`
  - `TestNoRawHTTPClient`: No raw `&http.Client{}`, must use `httpclient.*`

### Changed
- **User-Agent Unification**: All components now use consistent UA format
  - Browser-like UAs use `defaults.UAChrome`, `defaults.UAFirefox`, etc.
  - Component-specific UAs use `ui.UserAgentWithContext("Component")` → `waftester/2.4.3 (Component)`
  
- **Version Management**: Single source of truth in `defaults.Version`
  - `ui.Version` now references `defaults.Version`
  - SARIF output, enhanced JSON, and all reports use centralized version

### Fixed
- **54+ Files Updated**: Migrated hardcoded values to centralized constants
- **Test Expectations**: Updated tests to use `defaults.*` constants instead of magic numbers

## [2.4.2] - 2026-02-02

### Added
- **Intelligent Tamper Engine**: Full integration of 70+ sqlmap-compatible tampers into auto and scan modes
  - New `--tamper` flag: Specify custom tampers (e.g., `--tamper=space2comment,randomcase`)
  - New `--tamper-auto` flag: Automatically select optimal tampers based on detected WAF
  - New `--tamper-profile` flag: Use predefined profiles (stealth, standard, aggressive, bypass, custom)
  
- **WAF Intelligence Matrix**: Curated tamper recommendations for 16+ WAF vendors
  - Cloudflare, AWS WAF, Akamai, Imperva, Azure WAF, F5 BIG-IP, Fortinet FortiWeb
  - ModSecurity, Barracuda, Sucuri, Radware, Citrix, Palo Alto, Sophos, Wallarm
  - Each vendor mapped to optimal tamper chains with effectiveness scores
  
- **Tampers Subcommand** (`waf-tester tampers`):
  - `--list`: List all 70+ available tampers with descriptions
  - `--category`: Filter by category (encoding, space, sql, mysql, mssql, waf, http, obfuscation)
  - `--for-waf=<vendor>`: Show recommended tampers for a specific WAF
  - `--test "<payload>"`: Test payload transformation step-by-step
  - `--matrix`: Display full WAF intelligence matrix
  - `--json`: Output in JSON format for automation

- **Real-time Metrics Collection**: Track tamper effectiveness during scans
  - Success rates, block rates, latency tracking per tamper
  - Top performers analysis for adaptive learning
  - Thread-safe atomic operations for concurrent scanning

- **Adaptive Learning**: Engine learns from scan results to optimize future tamper selection
  - `RecordSuccess`/`RecordFailure` methods update tamper rankings
  - Priority-based chaining adjusts based on observed effectiveness

### Changed
- **Auto Mode Enhancement**: Now automatically applies optimal tamper chains when WAF is detected
- **Scan Mode Enhancement**: Tamper flags available for manual bypass testing
- **Strategy Integration**: WAF strategy now includes tamper recommendations

### Documentation
- **README.md Updates**:
  - Added `tampers` command to Commands table
  - Expanded Tamper Scripts section with new flags and examples
  
- **EXAMPLES.md Updates**:
  - Added "With Automatic Tamper Selection" subsection to auto mode
  - Added "With Smart Mode and Tampers" subsection to scan mode
  - Enhanced bypass command with `--tamper-auto` and `--tamper-profile` examples
  - Expanded Tamper Scripts section with 5 new subsections:
    - Auto-Select Tampers (v2.4.2+)
    - Tamper Profiles (v2.4.2+)
    - WAF Intelligence Matrix (v2.4.2+)
    - Test Payload Transformation (v2.4.2+)
    - Full vendor list for matrix

## [2.4.1] - 2026-02-02

### Fixed
- **CI Release Workflow**: Release publishing now verifies tags are on the main branch before proceeding
  - Prevents accidental releases from feature/fix branches
  - Clear error message when tag is not on main

### Documentation
- **Comprehensive EXAMPLES.md Rewrite**: Expanded from 651 to 2,200+ lines
  - Added 100+ probe command options (httpx-compatible)
  - Added fuzz modes: sniper, pitchfork, clusterbomb
  - Added recursive fuzzing and wordlist transformations
  - Added scan severity/category filtering and OAuth testing
  - Added smuggle safe/full modes and race attack types
  - Added headless browser testing options
  - Added workflow orchestration with YAML examples
  - Added crawl content extraction options
  - Added analyze JavaScript analysis options

- **README Updates**:
  - Added 8 missing commands to Commands table
  - Added 4 new feature highlights
  - Enhanced command descriptions with compatibility notes

## [2.4.0] - 2026-02-02

### Fixed
- **Unicode Truncation Bugs**: Fixed `uint16` truncation for runes > 0xFFFF in hexutil and tampers packages
- **JSUnicodeEncoder Truncation**: Fixed encoder casting rune to byte, truncating characters > 255
- **Empty Payload Panic**: Fixed `payload[:1]` panic in protocol.go when payload is empty
- **Nil Dereference from url.Parse**: Fixed ignored errors causing nil pointer panics in:
  - `pkg/openapi/generator.go`
  - `pkg/brokenauth/brokenauth.go`
  - `pkg/apifuzz/apifuzz.go`
  - `pkg/discovery/sources.go`
  - `cmd/cli/main.go`
- **Nil Dereference from http.NewRequestWithContext**: Fixed ignored errors causing nil pointer panics in:
  - `pkg/securitymisconfig/securitymisconfig.go`
  - `pkg/enterprise/protocols.go`
  - `pkg/businesslogic/businesslogic.go`
  - `pkg/brokenauth/brokenauth.go`
  - `pkg/assessment/assessment.go`
  - `pkg/apiabuse/apiabuse.go`
  - `pkg/accesscontrol/accesscontrol.go`
- **Overlong UTF-8 Encoding**: Fixed `WriteOverlong2Byte`/`WriteOverlong3Byte` format bugs in hexutil

### Added
- **68 SQLMap-Compatible Tamper Scripts**: Complete port of sqlmap's tamper library for WAF bypass
  - `--tamper` flag to apply payload transformations
  - Support for tamper chaining: `--tamper "space2comment,randomcase,base64encode"`
  - Priority-based execution with `ChainByPriority()`
  - HTTP-level request transformations via `TransformRequest()`

- **Tamper Categories** (8 categories, 68 scripts):
  - `encoding` (12): base64encode, charencode, htmlencode, overlongutf8, unmagicquotes, etc.
  - `space` (12): space2comment, space2plus, space2dash, blankspace, varnishbypass, etc.
  - `sql` (16): apostrophemask, between, equaltolike, randomcase, symboliclogical, etc.
  - `mysql` (10): modsecurityversioned, versionedkeywords, misunion, multipleurlencode, etc.
  - `mssql` (6): mssqlblind, chardeclareandexec, topclause, bracketcomment, etc.
  - `waf` (4): informationschemacomment, luanginxwaf, jsonobfuscate, schemasplit
  - `http` (3): xforwardedfor, randomuseragent, varnishbypass
  - `obfuscation` (6): commentrandom, nullbyte, suffix, concat, slashstar, etc.

- **Protocol Testing Documentation**: README updated with guidance for:
  - GraphQL endpoint testing (introspection, mutations, batching)
  - gRPC service testing (reflection, protobuf payloads)
  - SOAP/XML testing (XXE, WSDL enumeration)

### Technical
- Thread-safe tamper registry with Get, List, ByCategory, ByTag functions
- Tamper interface: `Transform(payload string) string` + `TransformRequest(req *http.Request) *http.Request`
- Full test coverage for all 68 tampers (8 test files, 1000+ test cases)
- New package: `pkg/evasion/advanced/tampers/`

### Performance
- **Hex Lookup Tables**: Pre-computed 256-entry tables eliminate fmt.Sprintf overhead
- **Pre-allocated Buffers**: strings.Builder.Grow() prevents reallocations during transforms
- **Regex Caching**: All patterns use regexcache.MustGet() for 315x faster repeat matches
- **Batch Lookups**: GetMultiple() reduces lock contention for tamper chaining
- **Single-Pass Patterns**: SQL keyword matching uses alternation instead of per-keyword loops
- **Static Replacers**: HTMLEncode replacer created once at package level
- **Main App Encoding Optimization**: pkg/waf/evasion.go now uses hexutil lookup tables
- **Encoder Package Optimization**: pkg/encoding/encoders.go hot paths optimized
- **Mutation Encoder Optimization**: pkg/mutation/encoder hot paths optimized
- **New hexutil Package**: internal/hexutil provides shared high-performance encoding utilities

**Benchmarks** (Intel Ultra 7 265U):
- HexEscape: 380ns vs 7,435ns fmt.Sprintf (**19.6x faster**, 98% fewer allocs)
- URLEncode: 325ns vs 5,831ns fmt.Sprintf (**18.0x faster**, 98% fewer allocs)
- BinaryEncode: 361ns vs 5,844ns fmt.Sprintf (**16.2x faster**, 98% fewer allocs)
- UnicodeEscape: 743ns vs 7,123ns fmt.Sprintf (**9.6x faster**, 98% fewer allocs)
- CharEncode: 352ns/op, 1 alloc
- Chain(5 tampers): 5.8μs/op
- Registry Get(): 23ns/op, 0 allocs

## [2.3.5] - 2026-02-02

### Fixed
- **Clean JSON Output in Auto Mode**: All informational output now correctly goes to stderr when `-json` flag is used
- **Smart Mode Output**: `PrintSmartModeInfo()` now respects silent mode and uses stderr
- **Execution Manifest**: Default writer changed from stdout to stderr; respects `IsSilent()` check
- **Progress Display**: All progress bars and stats now properly output to stderr
- **Banner/Config**: All UI functions (`PrintConfig`, `PrintConfigLine`, `PrintBracketedInfo`, `PrintResult`) now use stderr
- **Results Summary**: `PrintSummary`, `PrintWAFEffectiveness`, `PrintLiveResult` use stderr and respect silent mode
- **Live Progress**: Default writer changed from stdout to stderr

### Changed
- Auto mode (`waf-tester auto -json`) now outputs only valid JSON to stdout
- All phase headers, progress indicators, and informational output redirected to stderr
- Silent mode automatically enabled for JSON/JSONL output formats

## [2.3.4] - 2026-02-01

### Performance
- **Comprehensive HTTP Keep-Alive Optimization**: Migrated 165+ `resp.Body.Close()` patterns to `iohelper.DrainAndClose()` for proper connection reuse
- **Safe Body Reading**: Migrated 23 `io.ReadAll(io.LimitReader())` patterns to `iohelper.ReadBody()` with size limits (8KB/100KB/1MB)
- **Regex Caching**: Migrated hot-path `regexp.MustCompile()` to `regexcache.MustGet()` (315x faster on cache hits)
- **Removed Redundant Code**: Eliminated duplicate `io.Copy(io.Discard)` calls after DrainAndClose

### Changed
- All scanner packages now use `iohelper` for consistent HTTP response handling
- WAF detection, discovery, and API packages optimized for connection pooling
- 83 files updated with consistent resource management patterns

### Documentation
- Added `--json` flag examples to README.md for automation/CI use cases
- Added `--json` automation section to docs/EXAMPLES.md
- Highlighted JSON output flag across all documentation

## [2.3.3] - 2026-02-01

### Added
- **Real-time Streaming JSON Events**: New `-stream -json` mode emits NDJSON events to stdout for CI/CD pipelines
  - Event types: `scan_start`, `vulnerability`, `scan_complete`, `scan_end`
  - Progress output goes to stderr, JSON events to stdout for clean piping
  - Example: `waf-tester scan -u https://target.com -stream -json | jq`
- **Guaranteed Event Emission**: All 35+ scanners now use `defer` pattern to emit `scan_complete` even on errors
- **Banner Suppression**: Banner and config output suppressed in `-stream -json` mode for clean JSON output

### Changed
- Refactored all scanners to use defer pattern for reliable event emission
- Error handling improved: errors are logged (if verbose) but don't skip completion events
- Streaming mode now properly separates progress (stderr) from data (stdout)

### Fixed
- Scanners no longer silently skip `scan_complete` events on early returns or errors
- `techdetect` scanner no longer hangs on slow `DiscoverAll()` calls
- Duplicate `streamJSON` variable declarations removed
- `wafdetect` scanner type mismatch with `WAFInfo` slice fixed

### CI/CD Improvements
- Pipeline tools can now reliably count scanner completions
- NDJSON output compatible with `jq`, log aggregators, and monitoring tools
- Clean stdout output suitable for `> results.jsonl` redirection

## [2.3.2] - 2026-02-01

### Added
- **CI/CD Pipeline Integration**: New `--stream` flag across 10+ commands for clean pipeline output
  - See: [CI/CD Pipeline Integration](docs/EXAMPLES.md#-cicd-pipeline-integration)
- **LiveProgress Component**: Unified progress display with Interactive/Streaming/Silent modes (`pkg/ui/liveprogress.go`)
- **ExecutionManifest Component**: Pre-run display showing payload counts, targets, categories (`pkg/ui/manifest.go`)
- Commands now show payload count and target summary before execution starts

### Changed
- Refactored `assess`, `bypass`, `smuggle`, `headless` commands to use LiveProgress
  - See: [Enterprise Assessment](docs/EXAMPLES.md#-enterprise-assessment-assess), [WAF Bypass Hunting](docs/EXAMPLES.md#-waf-bypass-hunting-bypass)
- Consolidated 400+ lines of duplicated inline progress code into reusable components
- All animated progress displays now respect `--stream` flag

### Fixed
- ANSI escape codes no longer pollute CI/CD pipeline logs when using `--stream`
- Consistent progress display behavior across all major commands

### CI/CD
- Releases now automatically marked as "Latest" on GitHub
- Tag overwrites supported for re-releases (preserves changelog history)

## [2.3.1] - 2026-01-31

### Added
- Authenticated browser scanning with manual login support (MFA, CAPTCHA, SSO)
- Community payloads now bundled in release archives
- Clear documentation for browser scanning requirements

### Fixed
- Race conditions in discovery, distributed, and deserialize packages
- Version embedding via ldflags in release builds
- Centralized 40+ hardcoded User-Agent strings to use `ui.UserAgent()`
- CI/CD template install paths now correctly reference `cmd/cli`

### Changed
- Updated README with browser scanning documentation
- All payload files included in release archives

## [2.3.0] - 2026-01-27

### Added
- Initial public release
- CLI with 50+ attack types
- 320+ command-line flags
- Community payload set (2,800+ payloads)
- WAF detection with 197 vendor signatures
- Smart mode with WAF-aware testing
- Multiple output formats (JSON, SARIF, Markdown, HTML)
- Enterprise assessment mode with quantitative metrics

### Security
- BSL 1.1 license for core engine
- MIT license for community payloads

---

[2.3.3]: https://github.com/waftester/waftester/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/waftester/waftester/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/waftester/waftester/compare/v2.3.0...v2.3.1
[2.7.1]: https://github.com/waftester/waftester/compare/v2.7.0...v2.7.1
[2.3.0]: https://github.com/waftester/waftester/releases/tag/v2.3.0
