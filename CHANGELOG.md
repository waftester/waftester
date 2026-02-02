# Changelog

All notable changes to WAFtester will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
