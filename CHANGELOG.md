# Changelog

All notable changes to WAFtester will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.5] - 2026-02-06

### Added

- **Advanced Cognitive Modules** (`pkg/intelligence/`): 🧠 5 new learning subsystems for intelligent WAF analysis
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
  - **Slack** (`--hook-slack`): Rich message formatting with severity colors, field blocks
  - **Microsoft Teams** (`--hook-teams`): Adaptive Cards with action buttons
  - **PagerDuty** (`--hook-pagerduty`): Incident creation with severity routing
  - **Jira** (`--hook-jira`): Automatic issue creation with configurable project/type
  - **GitHub Actions** (`--hook-github`): Step summary and outputs for workflow integration
  - **OpenTelemetry** (`--hook-otel`): Distributed tracing with scan spans and finding events
  - **Prometheus** (`--hook-prometheus`): Metrics exposition endpoint for monitoring
  - **Generic Webhook** (`--hook-webhook`): Custom HTTP POST for any integration

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
[2.3.0]: https://github.com/waftester/waftester/releases/tag/v2.3.0
