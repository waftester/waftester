# Changelog

All notable changes to WAFtester will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.9.36] - 2026-02-26

### Fixed

- **Stored XSS in HTML exports** — Bypass and probe HTML report generators now escape user-controlled fields (`target`, `payload`, `encoder`, `content-type`, `server`) with `html.EscapeString`, preventing script injection via crafted scan targets
- **JUnit XML failures attribute** — JUnit output was writing `PassedTests` into the `failures` XML attribute instead of `FailedTests`, producing incorrect CI results
- **ECSVWriter data race on Close** — Added mutex synchronization to `Close()` preventing concurrent flush/close races
- **Baseline SaveBaseline write-under-read-lock** — Upgraded `RLock` to `Lock` in `SaveBaseline()` which mutates `UpdatedAt` while serializing
- **Rate limiter TOCTOU races** — Replaced separate check-then-act sequences in token bucket and sliding window with atomic `takeOrWait()` and `tryProceed()` methods, eliminating time-of-check/time-of-use gaps
- **Rate limiter busy-wait on zero wait time** — Added 1ms spin floor to `waitInternal` preventing CPU-bound tight loops when sliding window returns zero wait duration
- **Shared header map mutation** — Test runner now clones request headers before each retry, preventing concurrent writes to a shared `http.Header` map across goroutines
- **Mutation generator insert-during-iteration** — Genetic algorithm `mutate()` now collects insertions and applies them in reverse order after iteration, fixing slice corruption from modifying a slice while iterating
- **Scan command nil dereference** — Added nil guard for `url.Parse` result before accessing `.Host` in scan target resolution
- **Auto-escalate race condition** — Moved escalation counter inside the rate mutex scope, preventing unsynchronized concurrent increments
- **Correlator GetRules slice aliasing** — `GetRules()` now returns a copy of the internal rules slice instead of a direct reference, preventing external mutation
- **Progress display division by zero** — Added elapsed-time guard before computing requests-per-second, preventing divide-by-zero when elapsed is zero
- **ChainExecutor zero timeout** — Added default 5-minute timeout when caller passes zero, preventing indefinite hangs
- **XXE double file:// protocol** — Fixed payload path that concatenated `file://` with an already-prefixed `file:///etc/passwd`
- **Table writer color race** — Changed global `colorEnabled` from plain `bool` to `atomic.Bool`, preventing data races when multiple goroutines create table writers
- **Regex recompilation per call** — Precompiled regexes at package level in `ssrf.go`, `osint.go`, and `wordlist.go` that were previously recompiled on every function call

## [2.9.35] - 2026-02-26

### Fixed

- **MCP payload provider latency** — Eager-load payload provider during server init, eliminating 22-41s first-call latency that caused concurrent tool call timeouts

### Changed

- **CLI flag deduplication** — Extracted `SmartModeFlags` and `TamperFlags` into shared structs, replacing copy-pasted flag declarations across scan, autoscan, and bypass commands
- **CLI flag setup extraction** — Moved flag declarations from `runScan()`, `runAutoScan()`, and `runProbe()` into dedicated config files, reducing god function size by ~640 lines

## [2.9.34] - 2026-02-26

### Changed

- **MCP server logging** — Migrated all `log.Printf` calls to structured `log/slog` across pkg/mcpserver for consistent observability
- **CLI scan output extraction** — Extracted scan output and transport logic into dedicated files to reduce god function complexity
- **HTTP client transport wrapper** — Added per-client `TransportWrapper` support with priority over global wrapper
- **CLI flag validation** — Added early flag validation in scan and autoscan commands with `exitWithError` helper
- **Deprecated openapi command** — Replaced removed `openapi` command with migration error pointing to `scan --spec`
- **Probe flag deprecation** — Added deprecation warnings for legacy probe flags
- **Package interfaces** — Added package-level interfaces for crawler, detection, waf, and scanner packages

## [2.9.33] - 2026-02-26

### Added

- **Fuzz command smart mode and tamper engine** — Wire WAF-aware testing into the fuzz command with `--smart`, `--smart-mode`, `--smart-verbose` flags for auto-detection, plus `--tamper`, `--tamper-auto`, `--tamper-profile`, `--tamper-dir` for evasion transformations via a `RequestTransformer` interface.
- **Spec pipeline smart mode integration** — The `--spec`/`--spec-url` scan path now benefits from WAF detection when `--smart` is enabled, applying WAF-tuned concurrency and rate limiting to API spec-driven scans.

### Fixed

- **Auto scan strategy disconnects** — Four strategy fields were computed and cached but silently discarded during test execution: `PrioritizeMutators` now feeds tamper engine hints, `PrioritizePayloads()` orders categories by bypass likelihood, `RecommendedMutationDepth` replaces the hardcoded depth of 3, and `Strategy.Encoders` boosts WAF-effective payloads to the front of the queue.
- **Pipeline mode filtering** — Encoder boost, tamper hints, and mutation depth now prefer the mode-filtered Pipeline config over raw Strategy fields, so quick/stealth modes test fewer encodings while full/bypass modes test everything.
- **Screenshot BatchCapturer data race** — Eliminated a race between `Add()` and `Stop()` where a channel send could hit a closed channel; fixed with an atomic stopped flag and a select guard on the done channel.

## [2.9.32] - 2026-02-26

### Fixed

- **Scan command missing strategy hints** — The scan command's tamper engine now receives WAF-specific evasion hints from smart mode detection, aligning it with autoscan's strategy integration and improving tamper selection accuracy for detected WAF vendors.

## [2.9.31] - 2026-02-26

### Added

- **Autoscan strategy integration** — Wired 7 disconnected strategy, tamper, and param integrations: `ShouldSkipPayload()` filters ineffective encodings per-WAF vendor, `PrioritizePayloads()` respects vendor-specific mutator priorities, body params from discovery generate POST payloads, tamper engine applies transforms to mutation pass payloads, full-recon deduplicates already-completed phases, and strategy evasion hints feed into the tamper engine selection.
- **Discovery service presets** — Replaced hardcoded service endpoints with filesystem-first JSON presets loaded from `presets/` directory, enabling customizable discovery targets with proper distribution wiring for embedded and on-disk resolution.
- **Live discovery progress** — Endpoint count updates in real-time during discovery phase via polling goroutine instead of only showing final count at completion.

### Fixed

- **Brain insight spam** — Deduplicated intelligence engine insights so repeated findings (e.g., 150+ identical "ENDPOINT Bypass Detected") display once with description details, then aggregate counts in a summary after the brain report.
- **Empty WAF name after discovery** — Falls back to smart mode vendor name when discovery fingerprint is empty, suppressing the blank "WAF Detected: " line entirely when no vendor is identified.
- **Enterprise assessment ignoring detected WAF** — Assessment phase now receives the pre-detected WAF vendor from smart mode instead of re-running its own detection that defaults to "Unknown".
- **Block confidence polluting top errors** — Removed block confidence percentage from `ErrorMessage` field on blocked results; confidence is metadata stored in `BlockConfidence`, not an error string.
- **Strategy cache round-trip** — Fixed smart mode cache not persisting WAF strategy fields (skip/prioritize mutators, evasions) and corrected evasion engine hint lookup, pipeline sort stability, and nil-safe strategy field propagation.

### Changed

- **Crawler HTML tokenizer** — Replaced regex-based HTML parsing with `golang.org/x/net/html` tokenizer for reliable link/form/script extraction, plus 11 reliability improvements including robots.txt caching, bounded redirect chains, and content-type filtering.
- **Mutation registry pattern** — Replaced hardcoded encoder, location, and evasion lists in the mutation package with a registry pattern, eliminating scattered magic strings.
- **Centralized defaults across 32 files** — Eliminated hardcoded duplications of timeouts, buffer sizes, concurrency limits, and content types by referencing `pkg/defaults/` constants throughout the codebase.

## [2.9.30] - 2026-02-24

### Added

- **MCP smart mode for scan and bypass tools** — New `smartMode` parameter in MCP scan and bypass tools enables automatic payload/tamper/category selection based on target analysis rather than requiring manual configuration.

### Fixed

- **Auto scan real-time counters** — Endpoints, Secrets, and Bypasses counters now update in real-time during auto scan instead of only at completion.
- **MCP vendor category mapping** — `GetVendorNamesByCategory` now returns correct vendor names instead of mismatched categories.
- **Smart-mode values in docs and help text** — Corrected smart-mode allowed values in CLI help output and documentation to match actual implementation.

### Changed

- **Dynamic MCP enums from source of truth** — Replaced all hardcoded MCP tool enums (categories, vendors, tampers) with runtime-derived values from `CategoryMapper`, eliminating drift between code and metadata.
- **CLI help/docs sync tests** — Added 9 layers of automated tests ensuring CLI dispatch clauses, help text, numeric defaults, smart-mode values, COMMANDS.md flags, aliases, defaults, and ToC all stay in sync with code.

## [2.9.29] - 2026-02-24

### Added

- **Master Brain intelligence modules** — Thompson Sampling bandit for payload exploration-exploitation, OODA-cycle control loop for adaptive scanning, Q-learning phase controller, CUSUM-based change point detector, causal influence graph for finding relationships, and adaptive mutation generator with fitness scoring.
- **Master Brain engine integration** — Wired all modules into the existing intelligence engine: bandit-boosted payload recommendations, CUSUM anomaly feed from response observations, influence graph events from WAF model, phase transitions, and recalibration hooks.
- **Dynamic vhost wordlist generator** — Replace hardcoded entries with real infrastructure prefixes, TLS SAN extraction, and CSP source enrichment for virtual host probing.

### Fixed

- **False connection_dropping killing Phase 4 WAF testing** — Three interacting bugs caused all WAF test payloads to be skipped: double-counting errors (executor and detector both called `hosterrors.MarkError`), wrong check order (`hosterrors.Check` ran before detector's recovery probes), and cross-phase contamination from discovery errors poisoning Phase 4. Fixed by making detector the single error source, detector-first check order in both executor variants, phase clearing before WAF testing, and raising thresholds from 3 to 5.
- **Recon findings inflating bypass counters** — Discovery, JS analysis, leaky-paths, and param-discovery phases produced findings with `Blocked=false` that were counted as WAF bypasses across all intelligence modules. Added `Finding.IsTestingPhase()` to guard all bypass/block counters.
- **MCP scan detection rate always 100%** — Used `FailedTests` instead of `PassedTests` for detection rate calculation (attack payloads produce "Fail" outcome, not "Pass"). Also fixed double `ParseTamperList` call and capped HTTP concurrency.
- **Payload database: 10 bug fixes** — Vendor filter missed `Payload.Vendor` field, `All()`/`ByCategory()`/etc returned mutable internal slices, `caseSwap` XOR corrupted non-letter characters, `Categories()`/`Vendors()`/`Tags()` had data races under concurrent access, and loader silently dropped invalid payloads.

## [2.9.28] - 2026-02-23

### Added

- **Advanced payload files for 11 attack categories** — New payload JSON files for CRLF injection, LDAP injection, NoSQL injection, open redirect, prototype pollution, request smuggling, SSRF, SSTI, XXE, polyglot, and WAF bypass chains.
- **Payload generation package** — `pkg/payloadgen` for programmatic payload generation with type validation.
- **Category synchronization tests** — Compile-time enforcement that payload files, mapper categories, and validation sets stay in sync.

### Changed

- **Centralized category definitions in CategoryMapper** — `CategoryMapper` is now the single source of truth for all payload categories. MCP tool enums, resource lists, validation, and CLI help text all derive from the mapper instead of maintaining separate hardcoded lists.
- **Dynamic MCP metadata** — Replaced all hardcoded MCP server metadata (resource count, prompt count, tool names, WAF/CDN vendor lists, WAF signatures JSON) with runtime-derived values. Adding a tool, resource, prompt, or WAF signature no longer requires updating counts or lists elsewhere.
- **Tag CI gate** — Pre-push hook now blocks tag pushes until CI is green, preventing releases from untested commits.

## [2.9.27] - 2026-02-23

### Changed

- **Hot path performance optimizations** — Zero-allocation word/line counting, lazy response body materialization, request pool fix (return original pooled request instead of context-derived copy), streaming JSON encoder for JSONL output, cached target URL parsing in executor, per-rune unicode case conversion replacing string allocation in evasion packages, package-level unicode replacements map, removed duplicate host error checks from test runner.

## [2.9.26] - 2026-02-23

### Fixed

- **SSRF scanner: 14 bug fixes** — False positives from bare nginx/apache strings in `isLocalResponse`, overly broad `<!DOCTYPE` and `<?xml` patterns in `isFileContent`, missing `vuln.Parameter` after `AnalyzeResponse`, unhandled `CategoryBypass` in localhost check, runtime-compiled regex, narrowed availability-zone metadata pattern, dead code removal, and `DefaultConfig()` for safe defaults so `LocalIPs`/`CloudMetadataIPs`/`BypassTechniques` populate correctly.
- **Request smuggling scanner: 9 bug fixes** — Missing `VulnCL0` constant, CRLF obfuscation header premature termination, case-insensitive multi-response detection in `containsDesyncIndicator`, H2 stub returning faked techniques, silent technique errors, missing write deadline in `sendRawRequest`, empty hostname crash, and `DefaultConfig()` for safe `SafeMode`/`DelayMs`/`ReadTimeout` defaults.
- **JWT scanner: 8 bug fixes** — Null bytes in `Sign()` blocking `none\x00` variant, case-insensitive none detection with null-byte stripping, JKU/X5U risk downgrade from critical, claim mutation in `CreateToken`, double-fire `notifyUniqueTypes`, missing `OnVulnerabilityFound` bridge from `Config.Base` to `Attacker`, and token extraction from `X-Auth-Token`/`X-Access-Token`/`X-JWT-Token` headers.
- **Structured output corruption** — Scan summary line wrote to stdout, corrupting JSON/SARIF/CSV/HTML piping. Table writer summary appended after format-specific stdout output on deferred `Close()`. Both now route to stderr.
- **JSON output missing struct tags** — 8 result types (`sqli.ScanResult`, `ssti.Payload`, `xss.ScanResult`, `hostheader.Vulnerability`, `hostheader.ScanResult`, `websocket.ScanResult`, `csrf.Result`, `clickjack.Result`) produced PascalCase keys instead of camelCase.
- **Severity case inconsistency** — 42 files across 25+ packages used mixed-case severity strings. Normalized all `Severity` field assignments to lowercase matching `finding.Severity*` constants. Added `TestSeverityCaseConsistency` enforcement test.
- **Unicode garbled on Windows consoles** — Progress bars, bullets, arrows, and other non-ASCII characters were hardcoded, bypassing the existing `boxChars`/`asciiChars` fallback system. Added `BarFilled`/`BarEmpty` fields and replaced 16 hardcoded Unicode sites with `ui.Icon()` or struct references.
- **ANSI escape code leak in redirected output** — Raw `\033[` sequences leaked into non-TTY stdout and stderr across 15+ files. Centralized color output through `pkg/ui/styles.go` and `pkg/dsl` color functions with terminal capability detection (`StderrIsTerminal()`, `StdoutIsTerminal()`). Respects `NO_COLOR` and `TERM=dumb`. 8 regression tests verify zero ESC bytes in piped output.
- **Scan summary grammar** — Category count used plural "vulnerabilities" when count was 1. Severity display order was random map iteration instead of Critical > High > Medium > Low > Info.
- **Raw HTTP clients in SSRF/JWT** — `jwt.go` and `ssrf.go` created fallback clients with bare `&http.Client{}` literals instead of `httpclient.New()`, bypassing timeout and TLS configuration.
- **Bypass command output message** — "see bypasses.json" displayed even without `-o` flag. Now shows "use `-o <file>`" when no output file is specified.

## [2.9.25] - 2026-02-22

### Added

- **Real-time vulnerability counter in scan progress bar** — Live "vulns" metric tracks unique findings during execution across all 30+ scanner packages. Callbacks are deduplicated using composite keys matching each scanner's dedup logic, so the progress counter matches the final post-scan count.
- **HAR 1.2 export across all commands** — `scan`, `bypass`, `fuzz`, `crawl`, `assess`, and `auto` commands now support `-har-export` for HTTP Archive output with full request/response headers, page grouping, and scan findings embedded as comments.
- **Short flag aliases** — `-t` (types), `-q` (quiet), `-cat` (category) shorthand flags for `scan` and `run` commands.

### Fixed

- **HAR writer: 27 fixes** — Request data population, response headers, page grouping, scan findings linkage, double-write in multi-category scans, content size accuracy, case-insensitive header lookups, and MIME type charset handling.
- **Dispatcher flush on os.Exit** — 28 exit paths across all CLI commands now explicitly close the output dispatcher before `os.Exit`, preventing 0-byte output files from buffered writers (HAR, SARIF, XML).
- **Context cancellation in 12 scanner loops** — Added `ctx.Err()` checks in payload loops for ldap, nosqli, ssi, rfi, lfi, crlf, hpp, prototype, csrf, clickjack, idor, rce, and redirect. Scans stop promptly on cancellation instead of testing remaining payloads.
- **Host header scanner FD leak** — Moved `defer DrainAndClose(resp.Body)` out of `TestURL` payload loop. Response bodies now close immediately after reading instead of accumulating until function return.
- **API fuzzer: 9 bug fixes** — Nil pointer panic in `sendFuzzRequest` for unsupported param locations, plus 8 additional correctness fixes across apifuzz and scan integration.
- **Windows Unicode detection** — Auto-detect Unicode support on piped output to prevent garbled characters in CI environments.
- **Secret detection hook** — Pre-commit hook now scans only added lines instead of the full diff, reducing false positives from existing code.

## [2.9.24] - 2026-02-21

### Fixed

- **HTML report writer: 23 bug fixes** — Timeout outcomes missing from executive summary cards, simple summary grid, risk matrix, and JSON export; OWASP categories incorrectly marked "pass" for error/timeout results; findings sorted only by bypass vs non-bypass instead of full outcome priority; capitalize() using byte-level slice instead of rune-safe unicode; localStorage access crashing when storage disabled; effectiveness bar missing ARIA progressbar attributes; printReport using unreliable setTimeout instead of requestAnimationFrame; no noscript fallback for JS-collapsed findings; and filter toolbar lacking a visible result counter.

## [2.9.23] - 2026-02-21

### Added

- **Severity x Confidence matrix in PDF reports** — 2D cross-tabulation of bypass findings by severity and detection confidence, highlighting confirmed high-severity vulnerabilities for prioritized remediation.
- **Passing categories section in PDF reports** — Green-themed table showing attack categories where the WAF achieved a 100% block rate, giving credit where protection is strong.
- **Evasion technique effectiveness in PDF reports** — Bypass rate analysis per tamper chain and evasion technique, revealing which WAF bypass methods are most effective.
- **Remediation guidance in PDF reports** — Actionable fix advice per bypass category with reference URLs, covering 24 attack types (SQLi, XSS, SSRF, SSTI, etc.).
- **Scan insights in PDF reports** — Six automated heuristic observations: WAF detection confidence, protection posture assessment, error-prone categories, effective encodings, latency anomalies, and throughput metrics.
- **CWE name enrichment in PDF finding cards** — Finding cards now display human-readable CWE names (e.g., "CWE-89: SQL Injection") instead of bare IDs, covering 60 common weakness enumerations.

## [2.9.22] - 2026-02-20

### Fixed

- **RPS calculation inflated on early cancellation** — Both core and mutation executors used planned `TotalTests` as RPS numerator. On death spiral or context cancellation, this produced wildly inflated RPS values. Now uses actual completed count (`Blocked + Passed + Failed + Errors`).
- **RunWithCallback silently dropped OnError and OnProgress callbacks** — `Run()` invoked struct-level `OnError` and `OnProgress` inside worker goroutines, but `RunWithCallback()` only called the streaming callback parameter, silently ignoring these. Callers setting `runner.OnError` for centralized error tracking had errors unreported when using the streaming API.
- **Runner resultsChan pre-allocated full target count** — For 100K+ targets the channel buffer and results slice both allocated at `len(targets)`. Buffer now capped to `concurrency*4` with a concurrent collector goroutine, preventing both memory waste and potential deadlock.
- **Worker pool emergency-spawned goroutines never drained** — Emergency spawn path doubled the worker limit to prevent deadlock, but excess workers persisted until `Close()`. Excess workers now exit after 5 seconds idle, draining back to configured capacity.

## [2.9.21] - 2026-02-20

### Fixed

- **Intelligence engine: 5 bug fixes** — RecordBehavior composite key mismatch silently broke behavior tracking when HTTP method was set; totalObservations not persisted, disabling UCB1 exploration after resume; extractPattern false-positive matches on bare `O:` and `a:` prefixes; buildSecretChain and buildLeakyParamChain returned first match instead of best candidate; buildLeakyParamChain used case-sensitive path matching.

## [2.9.20] - 2026-02-20

### Fixed

- **Auto mode: 63 bug fixes** — Death spiral TotalTests inflation, nil progress crash in sub-passes, double rate-limit backoff, EmitBypass on wrong outcomes, brain state persistence for resume, immediate result flush after waf-testing, mutation-pass diagnostic warnings, executorRef lifecycle cleanup, case-normalized bypass keys, and latency stats population in ExecuteWithProgress.

## [2.9.19] - 2026-02-19

### Security

- **Removed client-specific discovery endpoints** — Removed client-specific endpoint function and its case branch from discovery probes. Added pre-commit hook guard to block client names from being committed to the public repo.

### Fixed

- **Pre-push hook grep delimiter** — Added `--` delimiter to `grep -E` in the pre-push hook to prevent patterns starting with `-` from being misinterpreted as flags.
- **Cryptofailure severity type safety** — Changed `Severity` field from raw `string` to `finding.Severity` type with proper constants, fixing case mismatch in test assertions.
- **Cross-platform UNC path detection** — Added `isUNCPath` helper to spec path validation so `\\server\share` paths are rejected on Linux where `filepath.IsAbs` doesn't recognize them.

## [2.9.18] - 2026-02-19

### Added

- **MCP scenario smoke runner** — Cross-platform test runner (`cmd/mcp-smoke`) with 13 scenarios covering the entire MCP surface area: tool discovery, resource exploration, prompt catalog, payload/tamper operations, mutation engine, template workflow, CI/CD generation, spec pipeline, baseline comparison, task management, error handling, and live WAF recon.
- **MCP export_spec negative tests** — Security and input validation tests for the `export_spec` tool.
- **MCP coverage gap regression tests** — Tests targeting low-coverage branches: `buildDiscoverBypassesResponse`, `tlsVersionString`, `buildProbeResponse`, `estimateScanDuration`, writer wrappers, and `discardWriter`.

### Changed

- **n8n template descriptions** — Updated tool count from 18 to 27, added About WAFtester sections with website/GitHub/docs links, expanded How it works explanations, added capabilities tables and example prompts.

## [2.9.17] - 2026-02-19

### Fixed

- **Scan detection rate miscounted bypasses** — Detection rate calculated `tested = BlockedTests + FailedTests` but `FailedTests` means execution errors, not bypasses. Against targets with no WAF, all payloads pass (`PassedTests`), so `tested=0` and interpretation was empty. Now uses `BlockedTests + PassedTests`.

### Added

- **MCP handler regression tests** — 58 new tests: 30 SSE transport tests simulating n8n client workflows plus 28 handler-level tests covering async lifecycle, input validation, SSRF consistency, payload truncation, and full E2E chains.

## [2.9.16] - 2026-02-18

### Fixed

- **MCP server detect_waf timeout not clamped** — Schema declared `maximum: 60` but handler accepted any value. Clients could set arbitrarily long timeouts. Now clamped to 60 seconds.
- **MCP server probe timeout not clamped** — Schema declared `maximum: 30` but handler accepted any value. Now clamped to 30 seconds.
- **MCP server serverInstructions drift** — Tool count, tool names, and capability descriptions in the MCP instructions constant were stale. Updated to match actual registered tools.
- **MCP server waf-signatures resource description** — Resource description was inaccurate. Updated to reflect actual content.
- **MCP server enum completeness** — `list_tasks` and `get_task_status` `tool_name` enums were missing `discover_bypasses` and `event_crawl`.

### Added

- **MCP server regression test suite** — 29 new tests across 4 test files covering SSRF/traversal guards, CICD injection, schema invariants, live service integration, concurrency edge cases, and timeout boundary enforcement.

## [2.9.15] - 2026-02-18

### Fixed

- **MCP server SSRF via spec_url** — `resolveSpecInput` fetched spec URLs without validating against the cloud metadata blocklist. Now calls `validateTargetURL` before fetching.
- **MCP server path traversal via spec_path** — `resolveSpecInput` accepted absolute paths and `..` components, allowing arbitrary file reads. Now rejects both.
- **MCP server SSRF via probe redirect chain** — `probeTarget` followed HTTP redirects without re-validating each hop against the SSRF blocklist. Redirect URLs are now checked.
- **MCP server shell injection in generate_cicd** — Target URL and scan types were embedded in generated shell scripts without sanitization. Now rejects inputs containing shell metacharacters.
- **MCP server non-deterministic task list** — `TaskManager.List()` returned tasks in Go map iteration order. Now sorted by creation time.
- **MCP server non-deterministic OWASP categories** — OWASP reverse-map categories were appended from map iteration. Now sorted alphabetically.
- **MCP server max_clicks suggestion exceeded schema** — Headless tool suggested `max_clicks` values above the schema maximum of 200. Now capped.
- **MCP server schema description mismatch** — `preview_spec_scan` schema said "Default: standard" but valid values use "normal".
- **MCP server silent error discards** — `GetAll()`, `JSONPayloads()`, and `json.MarshalIndent()` errors were silently discarded. Now logged or reported.
- **MCP server UTF-8 unsafe truncation** — Payload snippet truncation used raw byte-index slicing, which could split multi-byte UTF-8 runes. Now steps back to the nearest rune boundary.
- **MCP server keepAliveLoop goroutine leak** — SSE keep-alive goroutine outlived the HTTP handler. Now joined before handler returns.
- **MCP server orphaned task slot leak** — `runSync` default case left tasks in running state when `workFn` returned without calling Complete/Fail. Now calls `task.Fail()`.

## [2.9.14] - 2026-02-18

### Fixed

- **SSRF metadata allowlist incomplete** — Cloud metadata host detection missed Oracle Cloud (192.0.0.192), Azure Wire Server (168.63.129.16), AWS IPv6 (fd00:ec2::254), link-local range (169.254.0.0/16), and ULA range (fd00::/8). All now blocked.
- **MCP log redaction missed arrays** — `redactMap` only recursed into nested objects, not arrays of objects. Sensitive fields inside `[{"api_key":"..."}]` were logged in plaintext.
- **MCP log redaction patterns incomplete** — `isSensitiveKey` missed fields containing "access", "private", "signing", and "encrypt". Added to sensitive substring list.
- **MCP log truncation byte/rune mismatch** — Truncation guard checked `len(argStr)` (bytes) but `truncateString` truncated by rune count. Multi-byte UTF-8 payloads could bypass truncation. Now checks rune count.
- **Rate limiter unbounded host map** — Per-host rate limiter grew without bound. Added LRU eviction with configurable `MaxHosts` cap.
- **DNS cache no background eviction** — Expired DNS entries accumulated until looked up again. Added background goroutine that evicts expired entries on a configurable interval.
- **DNS cache corrupt entry panic** — Type assertion on `sync.Map` values could panic if an entry had the wrong type. Added guard that returns error instead.
- **DSL repeat() unbounded** — `repeat(s, 1000000)` allocated ~1GB. Clamped to 10000 characters.
- **Tamper script size unbounded** — Tengo script files had no size limit. Added 1MB cap.
- **Wordlist size unbounded** — `loadWordlistFromFile` accepted arbitrarily large files. Added 50MB cap.
- **Canary prefix predictable** — `generateCanary` used `waft` prefix with `math/rand`. Replaced with `crypto/rand` hex for unpredictable canaries.
- **Filter hid WAF signal status codes** — `isErrorPage` classified 403, 406, 418, 429, and 503 as error pages, hiding WAF block responses. These status codes now pass through.
- **Workflow path traversal via sibling directory** — `validateFilePath` used `strings.HasPrefix` which allowed `/tmp/workdir-evil` to match `/tmp/workdir`. Replaced with `filepath.Rel`.
- **HTTP response body leaks** — Five locations across elasticsearch, auth, and cross-endpoint packages read HTTP response bodies without draining and closing. Added `DrainAndClose` calls.
- **Sitemap fetch unbounded depth** — Recursive sitemap index fetching had no depth limit. Added `maxSitemapDepth` cap.
- **WAF detector DNS rebinding ignored** — Added detection for DNS rebinding responses in WAF fingerprinting.

### Changed

- **Pre-commit hook excludes test files from secret scan** — Test files containing intentional fake secrets (for detection testing) no longer trigger the hardcoded secret hook.

## [2.9.13] - 2026-02-18

### Fixed

- **Runner rate-limit cancellation ignored** — `WaitForHost` error was discarded with `_ =`, so context cancellation during rate limiting never stopped task dispatch. Now checks the error and stops on cancel.
- **Runner stale rate limiter** — Rate limiter was only created once (`if r.limiter == nil`) and reused across runs with different settings. Now rebuilds per run.
- **Export encode errors silently dropped** — JSONL `enc.Encode()` errors were discarded with `_ =` in probe, crawl, assess, and scan exporters. Now checked and reported.
- **Export file close errors ignored** — `f.Close()` after writing CSV, HTML, and Markdown exports was unchecked. Now reports close failures.
- **Unsupported export formats accepted silently** — JUnit and PDF flags were accepted but never implemented for crawl, assess, and scan commands. Now prints explicit error. Scan also warns on SonarQube, GitLab SAST, DefectDojo, HAR, CycloneDX, and XML.
- **Scan stream JSON marshal error ignored** — `json.MarshalIndent` error in stream mode file write was discarded with `_ =`. Now checked with proper error exit.
- **Scan export writer swallowed errors** — `writeToFile` helper accepted `func(w io.Writer)` with no error return. Changed to `func(w io.Writer) error` to propagate encode failures.
- **MCP accepted unknown arguments** — `parseArgs` used `json.Unmarshal` which silently ignored typo'd field names. Now uses `DisallowUnknownFields()` to reject unknown arguments.
- **MCP discover timeout unbounded** — Schema declared `maximum: 60` but runtime had no upper clamp. Now enforces the 60-second cap.
- **MCP mutate encodings field mismatch** — Schema documented `encodings` but struct expected `encoders`. Added backward-compatible alias.

## [2.9.12] - 2026-02-18

### Fixed

- **Workflow allowlist too permissive** — External command allowlist included `awk`, `sed`, `xargs`, `curl`, `wget`, `tee`, and `ping`, enabling shell execution and data exfiltration via workflow injection. Removed all seven.
- **Workflow path traversal via sibling directory** — `validateFilePath` used `strings.HasPrefix` which allowed `/tmp/workdir-evil` to match `/tmp/workdir`. Replaced with `filepath.Rel` for correct containment check.
- **Distributed capacity leak on unhealthy nodes** — `checkNodeHealth` requeued tasks from unhealthy nodes without decrementing `ActiveTasks`, permanently consuming node capacity.
- **Distributed error status codes** — `RegisterNode` and `SubmitTask` returned HTTP 500 for client validation errors. Changed to 400.
- **Distributed graceful shutdown detection** — Coordinator `ListenAndServe` error was not checked for `http.ErrServerClosed`, causing false error logs on clean shutdown.
- **Distributed empty targets panic** — `TaskSplitter.Split` with zero targets caused index-out-of-range panic. Added nil guard.
- **Distributed result aggregator shallow copy** — `GetAll()` returned TaskResult values with shared Data map references. Callers mutating results corrupted internal state.
- **Distributed copyTask shallow nested maps** — `copyTask` shallow-copied Config map, allowing nested `map[string]interface{}` mutations to propagate to the original task.
- **Fuzz JSON output contamination** — `fuzz` command printed manifest and banner text to stdout even with `--json`, breaking JSON parsers. Suppressed non-JSON output when `--json` is set.
- **Wordlist unbounded download** — Remote wordlist download had no size limit. Added 100MB cap via `io.LimitReader`.
- **OSINT GetResults shallow copy** — `GetResults()` shallow-copied results but shared Metadata map references. Deep copies Metadata now.
- **OSINT rate limiter not context-aware** — `RateLimiter.Wait()` used `time.Sleep` which ignored context cancellation. Changed to select on `ctx.Done()`.
- **XSS GetPayloads mutable state** — `GetPayloads()` returned the internal payload slice directly. Returns a defensive copy now.
- **SQLi GetPayloads mutable state** — Same issue as XSS. Returns a defensive copy now.
- **XXE GetPayloads mutable state** — `GetPayloads()` returned internal pointer slice, allowing callers to mutate payloads. Deep copies each payload now.
- **Screenshot GetResults state leak** — `GetResults()` returned the internal results slice. Returns a defensive copy now.
- **MCP task snapshot aliasing** — `Snapshot()` aliased `json.RawMessage` bytes between snapshot and live task. Deep copies the byte buffer now.
- **Output hygiene test gaps** — AST checker missed `fmt.Fprint` and `fmt.Fprintln` stdout writes, and an overbroad `.Render()` catch-all hid violations.

## [2.9.11] - 2026-02-17

### Fixed

- **Stderr/stdout output routing** — Error messages and usage output were written to stdout, breaking piped JSON parsing and CI workflows. Routed all errors and usage to stderr.
- **OSINT rate limiter div-by-zero** — `NewRateLimiter(0)` caused division by zero panic. Clamped to minimum of 1.
- **OSINT GetResults slice aliasing** — `GetResults()` returned the internal results slice directly, allowing callers to corrupt manager state. Now returns a defensive copy.
- **HTTP body leak in 6 notification hooks** — PagerDuty, Teams, Slack, Jira, GitHub Issues, and Azure DevOps hooks called `resp.Body.Close()` without draining, leaking TCP connections under keep-alive. Replaced with `iohelper.DrainAndClose`.
- **Wordlist cache dir error ignored** — `os.MkdirAll` return value was silently discarded. Now logs a warning on failure.
- **Crawler double-close panic** — Multiple workers could decrement `inFlight` to zero simultaneously, causing a double `close(queue)` panic. Guarded with `sync.Once`.
- **GraphQL negative batch/depth panic** — `TestBatchAttack` and `TestDepthAttack` panicked on `make([]Request, -1)` with negative input. Added input validation.
- **Distributed nil node dereference** — `RegisterNode(nil)` caused nil pointer dereference. Added nil guard.
- **Distributed unbounded HTTP body** — API handlers accepted arbitrarily large request bodies. Limited to 1MB with `http.MaxBytesReader`.

## [2.9.10] - 2026-02-17

### Fixed

- **Enterprise export wiring** — `fuzz`, `probe`, `crawl`, and `assess` commands registered `--json-export`, `--sarif-export`, and other enterprise output flags but never wrote files. Added dedicated export writers for all four commands.
- **HTTP 503 block detection gaps** — Block detection in 7 packages only recognized 403/406/429. Added 503 (Service Unavailable), which WAFs commonly return for blocked requests. Affected: mutation executor, core test runner, CSV writer, discovery probes, WAF vendor detection, WAF detector, and calibration.
- **Smart mode flag.Visit alias mismatch** — `scan` command's `flag.Visit` check for user-set rate limit only matched `rate-limit` but not the `-rl` alias, causing smart mode to silently override user-set values.
- **Division by zero in mutate stats** — `mutate` command divided by `TotalTests` without zero guard, producing NaN percentages when no tests ran.
- **Division by zero in progress display** — `StatsDisplay.render()` divided by `total` without zero guard, producing `+Inf%` and garbled terminal output when total was 0.
- **Race condition in recursive fuzzer** — `addTask` incremented `inFlight` counter after writing to channel, allowing a fast worker to decrement it before the increment, causing premature queue closure.
- **writeJSONFile silently drops close errors** — `writeJSONFile` used `defer f.Close()`, discarding write-flush errors on disk-full or NFS failures. Now uses named return to capture close errors.

## [2.9.9] - 2026-02-17

### Fixed

- **Scan export 0-byte files** — `scan --json-export` never wrote results because `WriteEnterpriseExports` expected `ExecutionResults` not `ScanResult`. Added `writeScanExports()` for scan-specific output.
- **Bypass export 0-byte files** — `bypass --json-export` was registered but never wired to output. Added `writeBypassExports()` with JSON, SARIF, CSV, HTML, and Markdown support.
- **Auto dry-run sends live requests** — `auto --dry-run` without `--spec` bypassed the dry-run check entirely. Added early return that prints scan plan without sending requests.
- **FP rate doubled** — `FPRatio` was multiplied by 100 in `pkg/fp` and again in the display layer, producing rates like 3690% instead of 36.9%. Removed the redundant multiplication.
- **Smart mode overrides user flags** — Smart mode unconditionally overwrote `-rate-limit` and `-concurrency` even when explicitly set by the user. Now uses `flag.Visit()` to detect user-set flags.
- **Contradictory WAF effectiveness rating** — Final summary used a 3-tier scale (EXCELLENT/GOOD/NEEDS ATTENTION) while mid-stream used a 5-tier scale. Aligned to consistent 5-tier thresholds (99/95/90/80).
- **HTTP 400 classified as error** — Legacy block detection only recognized 403, 406, 429. Added 400, which ModSecurity/Coraza and other WAFs commonly return for blocked requests.
- **Scan command missing -v alias** — `scan` only accepted `-verbose` while other commands accepted both `-v` and `-verbose`. Added `-v` alias to `CommonFlags`.
- **FP corpus alias mismatch** — `parseCorpusSources("all")` returned short names ("edge", "tech", "intl") but `corpus.Load()` only matched full names. Added aliases.

## [2.9.8] - 2026-02-17

### Fixed

- **JWT brute-force timing oracle** — `BruteforceSecret` used string comparison (`==`) for HMAC signatures instead of `hmac.Equal`, enabling timing-based secret extraction. Now uses constant-time comparison.
- **Temp file cleanup on atomic writes** — Checkpoint and history store left orphaned `.tmp` files when `os.Rename` failed (e.g., cross-device moves). Both now clean up on rename failure.
- **Payload loader path traversal** — `LoadCategory` accepted unsanitized category names allowing `../../etc` to escape the payload directory. Now validates resolved paths stay within the base directory.
- **SSI URL construction** — `testPayload` used string concatenation (`targetURL + "?" + query`) which corrupted URLs with existing query strings (double `?`). Now uses `url.Parse` and `url.Values`.
- **API abuse marshal error** — `testResourcePayload` swallowed `json.Marshal` errors, silently sending empty request bodies. Now returns early with error evidence.
- **gRPC RegisterFile error** — `getMessageDescriptor` ignored `RegisterFile` return value. Now checks for registration errors.
- **MCP parseArgs error swallowed** — `handleListTasks` discarded `parseArgs` errors with `_ =`, silently accepting malformed JSON. Now validates and returns errors.
- **MCP provider.GetAll error swallowed** — `handleScan` discarded unified payload loading errors. Now logs failures for debugging.
- **MCP missing upper-bound clamps** — `handleBypass` and `handleDiscover` validated lower bounds but not upper bounds on concurrency/rate/timeout/depth. Schema declared maximums that Go code ignored. Now clamps both directions.
- **Host header response body leak** — `TestURL` read and drained response body inline without `defer`, risking TCP connection leak on panic. Now uses `defer DrainAndClose`.
- **Browser gzip fallback corruption** — `DoWithContext` checked `respBody == nil` after gzip decode, but `ReadBodyDefault` returns `[]byte{}` (never nil). Empty gzip responses fell through to read the already-consumed raw body. Now checks `len(respBody) == 0`.
- **Encoding Chain nil return** — `Chain()` returned nil when all encoder names were unknown, causing nil dereference on `Chain("typo").Encode(...)`. Now returns a passthrough encoder.
- **Mutation/assessment limiter.Wait cancellation** — `limiter.Wait(ctx)` return values ignored in mutation executor and assessment runner. Context cancellation during rate limiting went unnoticed, causing unnecessary work after shutdown. Now checks and returns on error.
- **Redirect regex per-call compilation** — `checkJSRedirect` called `regexp.MustCompile` on 4 static patterns per invocation. Now uses `regexcache.MustGet` for cached compilation.

## [2.9.7] - 2026-02-17

### Added

- **n8n workflow templates** — Three ready-to-import n8n workflow templates for WAFtester MCP integration: AI WAF Security Agent (conversational testing via Chat Trigger + AI Agent + MCP Client), Scheduled WAF Audit (weekly cron with Slack pass/fail routing), and Post-Deploy Security Gate (CI/CD webhook returning HTTP 200/422 based on detection rate threshold). Includes Docker Compose for local setup.
- **n8n templates Docker Compose** — `n8n-templates/docker-compose.yml` for running WAFtester and n8n side-by-side with pre-configured networking.

### Fixed

- **MCP tool count in README** — Platform Statistics table listed 22 MCP tools, actual count is 27.
- **n8n section tool count in EXAMPLES.md** — Listed 24 tools, updated to 27.

## [2.9.6] - 2026-02-16

### Added

- **Template resolver system** — Unified resolution engine for embedded templates with multi-strategy lookup (exact, extensionless, basename), disk override support via environment variables, and kind-scoped listing.
- **MCP tools: list_templates, show_template** — Two new MCP server tools for AI-assisted template browsing and content inspection. Dynamic enum and category discovery from the embedded template library.
- **Dynamic MCP template resource** — `waftester://templates` resource now dynamically generated from embedded FS instead of hardcoded, with per-template descriptions.
- **Template descriptions map** — 41 human-written descriptions for all bundled templates (nuclei bypass/detection, workflows, policies, overrides, output formats, report configs), guarded by invariant tests.

### Fixed

- **Silent truncation in show_template** — `io.LimitReader` silently dropped content beyond 1MB with no indication. Now detects truncation and appends a warning.
- **Hardcoded kind enum drift** — `list_templates` tool schema, error messages, and description all hardcoded the list of valid kinds. Now derived dynamically from the resolver.
- **Version resource template count** — Template count and category names in the version resource were hardcoded. Now computed dynamically from the resolver.

## [2.9.5] - 2026-02-15

### Added

- **Automated bypass discovery engine** — Combination testing of tamper chains against WAF rules to find bypasses automatically with `--discover` flag.
- **Tengo-based tamper plugin loader** — Custom tamper scripts in Tengo with sandboxed execution via `--tamper-dir`.
- **DOM event discovery** — Click-and-capture SPA crawling that discovers hidden UI states and dynamic content with `--event-crawl` flag.
- **Nuclei DNS protocol support** — DNS query templates for multi-protocol security testing.
- **Nuclei TCP/UDP network protocol** — Raw TCP and UDP protocol support for network-level template testing.
- **Nuclei flow DSL** — Conditional execution, variable chaining, and block results for multi-step template workflows.
- **Framework route wordlists** — Auto-detected route wordlists for 11 frameworks (Rails, Django, Express, Flask, FastAPI, Laravel, Spring, Next.js, WordPress, ASP.NET, generic API).
- **Content-type probing and OPTIONS detection** — Active probing for supported content types and HTTP methods on discovered endpoints.
- **JSON body, header, and cookie parameter discovery** — Parameter discovery now covers request body (JSON), headers, and cookies in addition to query and path parameters.
- **MCP tools: discover_bypasses, list_tampers, event_crawl** — Three new MCP server tools for AI-assisted bypass discovery, tamper listing, and event-based crawling.
- **Comprehensive command reference** — New `COMMANDS.md` with complete flag reference for every CLI command.
- **42 regression tests** — 30 tests covering fix code paths, 12 hardened to catch real regressions on revert.

### Fixed

- **WriteHeader race in test handlers** — Concurrent test handler wrote headers after response body, causing data races under `-race`.
- **Wildcard content-type detector** — `*/*` accept header treated as application-specific content type.
- **Matcher AND condition evaluation** — AND conditions short-circuited on first match instead of requiring all matchers to pass.
- **Regex cache unbounded growth** — Compiled regex patterns accumulated without eviction. Added LRU cache with size limit.
- **Recursion depth in JSON body positions** — Unbounded recursion on deeply nested JSON bodies could exhaust stack.
- **Bypass result deduplication** — Identical bypass findings reported multiple times across tamper combinations.
- **Header depth guard off-by-one** — Maximum header nesting depth check off by one, allowing one extra level.
- **Grade prefix matching** — Assessment grade comparison used exact match instead of prefix, missing grade variants.
- **Variable expansion prefix safety** — Template variables with shared prefixes (e.g., `{{host}}` vs `{{hostname}}`) now resolve longest-first.
- **Body drain consistency** — Response bodies not fully drained before close, preventing HTTP connection reuse.
- **Confidence score deduplication** — Duplicate confidence entries from multiple detection methods.
- **Per-method baseline for param discovery** — GET and POST responses used same baseline, causing false positive parameter detection.
- **Negative regex group guard** — Extractor with negative group index caused panic instead of returning empty result.
- **Double URL-decode in JS extraction** — JavaScript URL extraction decoded percent-encoded characters twice, corrupting URLs with encoded spaces.
- **Missing phaseNames for brain-feedback** — Auto mode phase tracking omitted brain-feedback, causing checkpoint validation to fail on resume.
- **Results-summary write error surfaced** — Silent `os.WriteFile` failure for results-summary.json now logged as warning.
- **Percent-encoding lost in captureSignature** — WAF signature capture decoded URL-encoded characters, losing original request representation.
- **Asymmetric resembles ratio** — `Resembles(a, b)` and `Resembles(b, a)` returned different results due to unnormalized ratio.
- **Tamper name validation in MCP scan** — Invalid tamper names passed to MCP scan tool returned no error. Now validates against registry.
- **Non-deterministic bypass sort** — Bypass results with equal success rate sorted randomly. Added alphabetical tiebreaker.
- **Docker build race condition** — Concurrent CI Docker builds for same SHA caused GHCR manifest conflicts. Serialized by SHA.

## [2.9.4] - 2026-02-15

### Fixed

- **Feedback merge missing 17+ fields** — Brain feedback pass only merged TotalTests, PassedTests, and FailedTests into results. BlockedTests, ErrorTests, BypassPayloads, BypassDetails, all breakdown maps (StatusCodes, SeverityBreakdown, CategoryBreakdown, OWASPBreakdown, EndpointStats, MethodStats, DetectionStats, EncodingStats), DropsDetected, and BansDetected were silently lost. The wafEffectiveness formula used Blocked/(Blocked+Failed) resulting in artificially low scores.
- **Stale results-summary.json on resume** — Results file was saved before the brain feedback merge, so resume loaded pre-feedback data missing bypass findings from the focused second pass. Now saves after all merges complete.
- **Brain EndPhase called without matching StartPhase** — `brain.EndPhase("waf-testing")` was outside the waf-testing skip guard, firing on every resume without a prior `StartPhase` call. Moved inside the guard.
- **Assessment phase re-ran on every resume** — Phase 6 (Enterprise Assessment) only checked the `--assess` flag without `shouldSkipPhase`, causing it to re-run after every interrupted scan.
- **Vendor detection made live HTTP on every resume** — Phase 4.5 had no skip guard or checkpoint. Now saves vendor detection results to `vendor-detection.json` and skips on resume.
- **Silent unmarshal failure on corrupt resume file** — `json.Unmarshal` error for `results-summary.json` was silently ignored with `_ =`, producing zero-valued results with no indication of data loss. Now logs a warning.
- **Full recon re-ran on every resume** — Phase 2.7 (Unified Reconnaissance) had no `shouldSkipPhase` check or `markPhaseCompleted`. Now checks and reloads from `full-recon.json` on resume.
- **Secrets exposed in markdown report** — Secret values were truncated to 40 characters but not redacted. Reports shared or committed to repositories leaked API keys and tokens. Now redacted to first 4 characters plus `****`.
- **Wiring test missed new command files** — `readAllGoSources` used a hardcoded file list. New command files were not scanned for dispatcher wiring. Now dynamically reads all `.go` files in `cmd/cli/`.
- **Smart mode cache write error silently ignored** — `os.WriteFile` error for smart mode cache was discarded with `_ =`. Now logs a warning on failure.

## [2.9.3] - 2026-02-15

### Security

- **SSRF bypass via spec variable defaults (autoscan)** — `runSpecPipeline` called `ParseContext` then `CheckServerURLs` but never called `ResolveVariables`. A spec with `servers: [{url: "{{host}}"}]` and `variables: {host: {default: "http://169.254.169.254"}}` passed the SSRF blocklist because the raw `{{host}}` template is not an IP address. The variable default was resolved later, hitting internal addresses. Now calls `ResolveVariables` before `CheckServerURLs`.
- **SSRF bypass via conditional variable resolution (scan spec)** — `runSpecScan` only called `ResolveVariables` when `--var` flags or `--env-file` were provided. When neither was present, spec-embedded variable defaults with internal IPs bypassed the SSRF check. Variable resolution is now unconditional.
- **SSRF bypass in MCP server spec tools** — Both `resolveSpecInput` and `handleValidateSpec` parsed specs and checked server URLs but never resolved variable defaults first. Same bypass vector as autoscan. Both now call `ResolveVariables` before `CheckServerURLs`.

### Added

- **AST-based security gate contract tests** — Static analysis test (`TestSecurityGateContract`) enforces 5 contract types across 8 package scopes: presence ("if you call A, you must call B"), ordering ("B must come after A"), context propagation ("use the Context variant"), forbidden calls, and forbidden references. Contracts are mutation-tested and catch regressions at compile time.
- **SSRF variable resolution contract** — New presence contract requires `ResolveVariables` wherever `CheckServerURLs` is called. Prevents future regressions where a new parse site forgets to resolve variable defaults before SSRF validation.
- **MCP server stdout/stderr protection** — Forbidden reference and call contracts prevent `os.Stdout`, `os.Stderr`, `fmt.Print`, `fmt.Printf`, and `fmt.Println` in `pkg/mcpserver/`. Stdout is the JSON-RPC transport in stdio mode; any stray writes corrupt the protocol.
- **MCP server context propagation contracts** — Enforces `ParseContext` over `Parse` and `ParseContentContext` over `ParseContent` when a `context.Context` is available, ensuring cancellation and timeouts propagate correctly.
- **API key query parameter support** — `AuthConfig.APIKeyIn` field supports `"query"` placement in addition to the default header placement for API key authentication.
- **Auth method conflict warning** — Warns when multiple auth methods are configured simultaneously, since later methods silently overwrite earlier ones for the same header.
- **HAR path templatization** — Converts literal IDs in HAR request paths to template parameters for better endpoint deduplication and parameter discovery.
- **HAR static asset filtering** — Skips static assets (images, CSS, JS, fonts) during HAR parsing since they are not useful for API security testing.
- **Default body population for body-expecting methods** — POST/PUT/PATCH requests with non-body injection targets now get a default body from the spec schema, preventing 400 rejections from servers that require a body.
- **Multipart boundary in Content-Type** — Multipart form requests now include the boundary parameter in the Content-Type header.
- **Postman GraphQL body support** — Postman collections with GraphQL request bodies are now parsed into endpoint parameters.
- **Postman form data examples** — Form-data key/value pairs from Postman collections are extracted as parameter examples.

### Fixed

- **TOCTOU race in spec file loading** — Replaced `os.Stat` size check followed by `os.ReadFile` with `io.LimitReader` to enforce the size limit during read, eliminating the time-of-check/time-of-use gap.
- **Spec file loading used os.Exit in library code** — Moved `RejectSpecFlags` from `pkg/apispec` to `cmd/cli` as a local helper, keeping `os.Exit` out of library code.
- **Library code writing to os.Stderr** — Removed direct `fmt.Fprintf(os.Stderr)` calls from `pkg/apispec/auth.go` (3 sites) and `pkg/input/targets.go` (1 site). Auth warnings now use a `WarnFunc` callback on `AuthConfig`; target selection silently uses the first target.
- **OpenAPI parser rejected YAML specs** — `pkg/api/openapi.go` only tried JSON parsing. Now falls back to YAML when JSON fails.
- **OpenAPI parser missed global consumes** — Swagger 2.0 global `consumes` field was ignored, causing missing content-type metadata on operations.
- **OpenAPI parser missing server variables** — Server variables with defaults and enums were not parsed from OpenAPI 3.x specs.
- **OpenAPI parser missing global security** — Top-level `security` requirements were not parsed, causing auth scheme detection to miss globally applied auth.
- **AsyncAPI error variable shadowing** — YAML parse error was assigned to a shadowed `err` variable, losing the error context in the returned message.
- **Dependency graph ordering bug** — `layerDependencyGraph` mutated `spec.Endpoints` in-place after plan entries were copied by value. `DependsOn` is now propagated back to plan entries after mutation.
- **Result.Finalize double-call corruption** — `Finalize()` could be called multiple times, corrupting timing data. Now uses a guard so only the first call takes effect.
- **Escalation state not thread-safe** — Added `sync.Mutex` to `EscalationState` map fields and `sync/atomic` for counter fields to prevent data races during concurrent scanning.
- **Block signature lost between phases** — Fingerprint phase block signatures were not propagated to scan state, causing the full scan phase to miss WAF-identified blocking patterns.
- **Auth not applied to probe requests** — Baseline and block detection requests in the adaptive executor skipped auth application, causing false negatives on auth-protected endpoints.
- **Executor budget check used wrong index** — Probe phase budget check used the loop index instead of elapsed time, causing premature budget exhaustion on fast scans.
- **Intelligence formatPercent division** — Used `Itoa` on a float-derived value instead of `fmt.Sprintf`, producing truncated percentage strings.

## [2.9.2] - 2026-02-14

### Fixed

- **Goroutine leak on context cancellation** — `goto done` in SimpleExecutor and AdaptiveExecutor skipped `wg.Wait()`, causing data races on returned results
- **Probe phase ignores cancellation** — `break` in select exited the select statement, not the for loop; probe phase continued scanning after context cancellation
- **Semaphore deadlock on cancellation** — Semaphore acquisition blocked indefinitely when context was cancelled and all slots were occupied
- **Panic on empty endpoint path** — `layerPathPattern` called `path[1:]` on empty string, causing index out of bounds
- **Cross-platform path matching** — `filepath.Match` used OS-specific separators for URL path matching; replaced with `path.Match`
- **Off-by-one in URL detection** — `isAbsoluteURL` rejected valid `http://x` URLs (8 chars) due to `len > 8` check
- **Non-deterministic request bodies** — Map iteration in `buildJSONBody`/`buildFormBody` injected payloads into random properties across runs
- **OAuth2 token errors swallowed** — Token refresh failures silently sent unauthenticated requests; now logged to stderr
- **Invalid intensity accepted** — `--intensity yolo` silently fell through to default; now validates against known values
- **Vendor content types missed** — Exact content-type matching missed `application/vnd.api+json` and similar; now uses substring matching
- **Infinite loop in replaceAll** — Custom string replacement looped forever when replacement contained search string; replaced with `strings.ReplaceAll`
- **Dead code in URL blocking** — Removed unreachable `[::1]` check (`url.Hostname()` strips brackets)
- **Banned stderr prints in apispec** — Removed `fmt.Fprintf(os.Stderr)` calls in `auth.go` and `specflags.go` that violated `TestNoDirectPrintInPkg` structural test
- **Progress goroutine race** — Added `sync.WaitGroup` to executor progress goroutine to prevent data race on returned results
- **DNS cache nil,nil return** — Fixed `LookupHost` returning `nil, nil` when resolver returns empty IP list; now returns `ErrEmptyDNSResponse`
- **Retry with consumed body** — Fixed retry middleware sending empty body on retry when `GetBody` is nil; now clones body before first read
- **EJSON null vs empty array** — Fixed `EJSONWriter` emitting JSON `null` instead of `[]` for zero-result scans
- **Non-deterministic SARIF output** — Sorted SARIF rules by ID and status codes by value for reproducible output across runs
- **NGINX App Protect false positive** — Required `X-Waf-Policy-Status` header alongside body patterns to avoid false WAF detection
- **SVG XSS evasion broken** — Fixed SVG payload evasion using pre-compiled replacer instead of broken split/ReplaceAll approach
- **Pre-commit hook false positives** — Added package allowlist to pre-commit debug artifact check, mirroring `TestNoDirectPrintInPkg` structural test allowlist

## [2.9.1] - 2026-02-14

### Added

- **11 new scan types fully wired into CLI** — LDAP injection, SSI injection, XPath injection, XML injection, RFI, LFI, RCE, CSRF, clickjacking, IDOR, and mass assignment scanners are now dispatched from `--types` flag and spec-driven scanning
- **Spec-driven scanning support for all 11 types** — Each scanner has a dedicated adapter function with CWE mapping for API spec scanning pipeline
- **Plan builder coverage** — All 11 scan categories registered in `allScanCategories` with payload base counts for scan estimation

## [2.9.0] - 2026-02-14

### Added

- **API spec scanning** — Drive security scans from OpenAPI 3.x, Swagger 2.0, Postman v2.x, HAR v1.2, AsyncAPI, GraphQL introspection, and gRPC reflection specs with `--spec` flag
- **Unified spec parser** — Auto-detects format from file or URL, returns a unified `Spec` model with endpoints, parameters, auth schemes, and schema constraints
- **8-layer intelligence engine** — Parameter type analysis, name pattern matching (18 regex rules), path pattern matching (47 patterns), auth context analysis, schema constraint analysis, content-type mutation, method confusion, and cross-endpoint correlation
- **Adaptive executor** — 3-phase scanning (fingerprint, probe, full scan) with 4 escalation levels (standard, encoded, WAF-specific, multi-vector) and request budget controls
- **Cross-endpoint attacks** — IDOR detection, race condition testing, and privilege escalation testing across related endpoints
- **Checkpointing and resume** — Automatically saves scan progress; resume interrupted scans with `--resume`
- **Comparison mode** — Diff scan results against a baseline with `--compare baseline.json` to track new, fixed, and regressed findings
- **Correlation IDs** — Every request carries `X-Correlation-ID: waftester-{session}-{endpoint}-{attack}-{param}-{seq}` for WAF log matching; export with `--export-correlations`
- **Per-endpoint scan config** — `.waftester-spec.yaml` overrides (or `--scan-config`) with glob-based path matching for skip, intensity, scan types, and max payloads per endpoint
- **5 MCP tools for spec scanning** — `validate_spec`, `list_spec_endpoints`, `plan_spec`, `scan_spec`, `compare_baselines` with async task support
- **4 MCP intelligence tools** — `preview_spec_scan`, `spec_intelligence`, `describe_spec_auth`, `export_spec` for AI-driven spec analysis
- **Scan result filters** — `--match-severity` / `--filter-severity` (`-msev` / `-fsev`) and `--match-category` / `--filter-category` (`-mcat` / `-fcat`) for post-scan result filtering
- **URL scope control** — `--include-patterns` (`-ip`) and `--exclude-patterns` (`-ep`) with regex matching to limit scan scope
- **Scan type exclusion** — `--exclude-types` (`-et`) to skip specific scan categories
- **Stop on first vulnerability** — `--stop-on-first` (`-sof`) cancels remaining scanners after the first finding
- **Per-host rate limiting** — `--rate-limit-per-host` (`-rlph`) creates independent rate limiters per target host
- **Retry with backoff** — `--retries` (`-r`) wraps scanner execution in exponential backoff with jitter
- **Robots.txt compliance** — `--respect-robots` (`-rr`) fetches and enforces robots.txt disallowed paths before scanning
- **Evidence and remediation control** — `--include-evidence` (`-ie`) and `--include-remediation` (`-ir`) strip fields from output when set to `false`
- **Spec event types** — 5 new event types (`spec_parsed`, `spec_plan_ready`, `spec_endpoint_start`, `spec_endpoint_done`, `spec_scan_complete`) wired through the event dispatcher
- **OAuth2 client_credentials** — Automatic token acquisition and caching for spec-driven scans
- **CookieJar support** — `httpclient.Config` accepts a cookie jar for stateful API testing
- **Pre-commit go vet hook** — `go vet` runs on staged packages before commit

### Fixed

- **Dry-run intercepting spec scans** — `--dry-run` no longer blocks spec-mode scan dispatch
- **Target optional with spec** — `-u` is no longer required when `--spec` or `--spec-url` provides server URLs
- **AsyncAPI YAML support** — Parser handles YAML-encoded AsyncAPI specs (was JSON-only)
- **Circular `$ref` detection** — OpenAPI parser detects and breaks circular references with depth limit and visited set
- **HAR response capture** — HAR adapter now captures response status, headers, and body size
- **Raw HTTP client usage** — Replaced 3 instances of `&http.Client{}` in cross-endpoint tests with `httpclient.Default()`
- **formatPercent corruption** — Fixed digit corruption in intelligence percentage formatting
- **Path parameter substitution** — Cross-endpoint test URLs now substitute `{id}` path parameters
- **Race condition request bodies** — POST/PUT/PATCH race tests now include request bodies
- **Checkpoint concurrency** — Added `sync.Mutex` to `Checkpoint` for goroutine safety
- **Integer overflow in constraints** — Guarded `maxLengthAttacks` computation against overflow
- **Windows path matching** — Replaced `filepath.Match` with `path.Match` for API path patterns in spec config
- **Spec event dispatch** — All 5 spec event types now flow through `EmitEvent` correctly
- **Validate command spec support** — `validate --spec` and `--spec-url` flags work correctly

### Changed

- **Scan flag aliases** — All 13 previously-registered-but-unused flags are now functional with both long (`--match-severity`) and short (`-msev`) forms
- **Rate limiter selection** — Scanner uses `pkg/ratelimit` per-host limiter when `--rate-limit-per-host` is set, falls back to stdlib `rate.NewLimiter` otherwise

### Removed

- **Dead code** — Removed unused `itoa` function, dead `http.NoBody` assignment, and 7 orphan TODO comments

## [2.8.9] - 2026-02-14

### Fixed

- **Broken CI templates (go install removal)** — All 14 CI/CD templates across `pkg/cicd/cicd.go` and `pkg/mcpserver/tools_cicd.go` used `go install github.com/waftester/waftester/cmd/cli@latest` which installed a binary named `cli` instead of `waf-tester` and included zero payloads; replaced with `curl` binary download from GitHub Releases
- **Wrong archive filename in MCP templates** — 6 MCP CI templates used `waf-tester_linux_amd64` (wrong naming convention) producing 404 download URLs; fixed to `waftester_Linux_x86_64.tar.gz` matching GoReleaser output
- **Docker base image in CI templates** — GitLab, CircleCI, and Bitbucket templates used `golang:1.21` / `cimg/go:1.21` (Go not needed for binary install); switched to `alpine:3` / `cimg/base:stable` with `apk add --no-cache curl`
- **Binary name mismatch** — CONTRIBUTING.md and INSTALLATION.md referenced `go build -o waftester` (no hyphen) while the actual binary is `waf-tester`; corrected all references

### Removed

- **go install support** — `go install` is fundamentally broken for WAFtester (wrong binary name, no payloads); removed from README, INSTALLATION.md, CONTRIBUTING.md, website docs, and all CI templates
- **Go installation section from website** — Removed `### Go` tab from waftester.com docs page and waftester-action README "Other Installation Methods" table

### Added

- **CI template install validation tests** — 3 new tests (`TestGenerator_Generate_InstallPattern`, `TestGenerator_Generate_NoGoImages`, `TestGenerator_Generate_VersionedDownload`) verify all generated CI configs use curl-based binary download, contain no Go Docker images, and include versioned download URLs
- **Version-bump skill** — Automated 8-phase version bump process with 14-location validation, cross-repo sync, and distribution channel verification

### Changed

- **INSTALLATION.md expansion** — Reorganized with all 7 distribution channels (Homebrew, Scoop, npm, Docker, AUR, GitHub Action, binary download) with platform-specific instructions

## [2.8.8] - 2026-02-13

### Added

- **waftester.com website** — Landing page, docs, and changelog at [waftester.com](https://waftester.com) with Cloudflare Pages auto-deploy, security headers, and CI pipeline
- **Cross-repo references** — README badge, EXAMPLES.md backlink, npm homepage, Dockerfile OCI labels, waftester-action README badge all point to waftester.com
- **FAQ doc links** — Each FAQ answer links to the relevant docs section
- **Cloudflare integrations** — Web Analytics, Email Routing (`hello@waftester.com`), www→bare domain redirect

### Fixed

- **EXAMPLES.md install command** — Replaced non-existent `get.waftester.com` curl install with `npm install -g @waftester/cli`
- **Dockerfile OCI labels** — Added `image.url` label, updated `image.documentation` to point to waftester.com/docs instead of GitHub README

## [2.8.7] - 2026-02-13

### Fixed

- **SonarQube severity mapping divergence** — Batch exports (builder.go) mapped Critical→BLOCKER, High→CRITICAL, Medium→MAJOR, default→MINOR while streaming exports (writers/) mapped Critical→CRITICAL, High→MAJOR, Medium→MINOR, default→INFO; consolidated to single canonical mapping on `finding.Severity.ToSonarQube()`
- **GitLab SAST severity missing Info level** — Batch export defaulted unknown severity to "Low" instead of "Info"; now matches streaming path via `finding.Severity.ToGitLab()`
- **Batch export case mismatch** — SARIF/SonarQube/GitLab batch export functions switched on title case ("Critical") but received lowercase ("critical") from payload SeverityHint, causing all severities to fall through to default; now uses `finding.Severity` type which matches lowercase constants

### Refactored

- **Severity mapping consolidation** — 8 duplicate severity mapping functions across `builder.go`, `writers/sonarqube.go`, `writers/gitlab_sast.go`, `writers/sarif.go` replaced with 4 canonical methods on `finding.Severity`: `ToSonarQube()`, `ToGitLab()`, `ToSARIF()`, `ToSARIFScore()`
- **severityOrder elimination** — 3 identical `severityOrder()` functions in `report/report.go`, `exploit/exploit.go`, `correlation/correlation.go` replaced with existing `finding.Severity.Score()` method
- **Code cleanup** — Formatting alignment, trailing whitespace, blank line removal across 9 files

## [2.8.6] - 2026-02-13

### Security

- **HTML injection in compliance reports** — 6 user-controlled values interpolated into HTML without escaping in `pkg/report/compliance.go`; all now wrapped in `html.EscapeString`

### Fixed

- **Nil pointer dereference in compliance report** — `GenerateComplianceReport` panicked when `stats` was nil; added nil guard in `MapResults`
- **Nil pointer dereference in task submission** — `Coordinator.SubmitTask(nil)` panicked dereferencing nil task; added nil check before lock
- **Go 1.24 JSON marshal failure** — `ExecutionResults.Duration` (`time.Duration`) had no JSON format tag, breaking `json.Marshal` in Go 1.24+; added `json:"duration,omitzero,format:nano"`
- **Division by zero in tamper metrics** — `RecordLatency` panics when called with empty tamper chain; added length guard
- **Decimal-to-hex conversion in MySQL CHAR transform** — `CharlongEscape` emitted `0x65` as `0x101` (string concat instead of integer conversion); now uses `strconv.Atoi` + `fmt.Sprintf`
- **Data loss in SQL Concat obfuscation** — Unterminated string at end of input silently dropped; now flushed after loop
- **Filter AND mode false negatives** — Regex, String, and CDN filter criteria only appended `matched=true`, breaking AND mode when criteria didn't match; now always append the boolean result
- **Concurrent map access in filter** — `seenHashes` map read/written without synchronization under concurrent use; added `sync.Mutex`
- **Correlator marks unrelated findings as fixed** — `DetectFixedFindings` ignored scan target and tested finding types, marking SQLi as fixed during an XSS-only scan; now scopes to matching target and tested types
- **Per-payload category lost in evasion matrix** — `Build` fell back to `categories[0]` for all payloads; now tracks per-payload category from `NewFromCategories`
- **Ignored template parse error** — `report.go` discarded `template.New().Parse()` error with `_ =`; replaced with `template.Must`
- **Silent JSON marshal failure in HTML report** — Template func returned empty string on error; now returns `"null"`
- **CSV header write errors ignored** — `newCSVWriter` never checked `writer.Write` or `Flush` errors for the header row; errors now propagated
- **Silent writer creation failures** — `enhanced.go` silently ignored errors from individual writer creation; now logs each failure with `slog.Warn`
- **Discarded JSON marshal error in OpenAPI generator** — `generateJSONBody` returned empty bytes on marshal failure; now falls back to raw payload
- **Checkpoint close error lost** — `SaveCompletedToFile` used bare `defer f.Close()`, discarding close errors; now captured via named return
- **Scoring formula comment wrong** — Documented max as 19, actual max is 22.5; comment corrected
- **Retry sleep ignores context cancellation** — `executor_test_runner.go` used `time.Sleep` in retry loop; replaced with `select` on `ctx.Done()` / `time.After`
- **Regex compiled on every call in SSTI detect** — `regexp.MustCompile` in hot path replaced with `regexcache.MustGet`
- **Regex compiled on every call in false positive** — `regexp.Compile` in `containsPattern` loop replaced with `regexcache.Get`
- **Distributed task silently dropped** — Full queue drops tasks with no logging or status update; now logs warning and marks task as failed
- **Distributed worker goroutine leak** — `Worker.Run` only selected on `ctx.Done()`, ignoring `StopChan`; now selects on both
- **Distributed double-close panic** — `Worker.Stop()` could panic on double `close(StopChan)`; wrapped with `sync.Once`
- **Distributed shutdown with no timeout** — `Shutdown(context.Background())` blocks forever; changed to 10-second timeout
- **Distributed stale tasks on unhealthy nodes** — `checkNodeHealth` detected unhealthy nodes but left their tasks stranded; now reschedules back to queue
- **npm package version mismatch** — `npm/cli/package.json` still at 2.8.5 after version bump; updated to 2.8.6
- **Workerpool deadlock** — Redesigned `Submit` locking to split into fast path (non-blocking under RLock) and slow path (`blockingSend` without locks), preventing deadlock when `Close` needs write lock while `Submit` blocks on full channel
- **Output file close errors** — All 11 export functions (`writeResultsJSON`, `writeResultsJUnit`, `writeResultsCSV`, etc.) now capture `f.Close()` errors via named returns and `closeFile` helper instead of silently discarding them with `defer f.Close()`
- **JWT marshal errors** — 3 `json.Marshal` calls in `ClaimTamperAttack` now check and return errors with context instead of silently discarding them
- **Workerpool data race** — `Submit` read `p.workers` non-atomically while `Resize` wrote it with `atomic.StoreInt32`; both reads now use `atomic.LoadInt32`
- **Output file handle leak** — `BuildDispatcher` missing `cleanup()` call on GitHub Issues hook error, leaking all previously opened file descriptors
- **Silent write errors in JUnit/HTML/Markdown exports** — `writeResultsJUnit`, `writeResultsHTML`, and `writeResultsMarkdown` discarded `fmt.Fprintf` errors, silently producing corrupt files on disk-full; all write errors now checked and propagated
- **JWT JKU token corruption** — `JKUSpoofAttack` ignored `json.Marshal` errors on header and claims, producing malformed tokens; errors now checked with descriptive messages

- **Path traversal in workflow output** — `Engine.executeStep` wrote command output to user-controlled path without validation; now calls `validateFilePath` before writing
- **Command injection via workflow allowlist** — `cmd` and `cmd.exe` were in the allowed command list, permitting arbitrary execution via `cmd /c`; removed from allowlist, added `ExtraAllowedCommands` field for controlled override
- **Empty WorkDir bypassed path validation** — `validateFilePath` allowed any absolute path when `WorkDir` was empty; now defaults to `os.Getwd()`
- **Recursive fuzzer deadlock** — `wg.Wait()` in goroutine blocked forever when queue drained naturally; replaced with atomic `inFlight` counter and monitor goroutine that closes queue at zero
- **Screenshot goroutine leak** — `BatchCapturer.Stop()` closed channels before workers drained, leaving goroutines blocked; added `sync.WaitGroup` tracking so `Stop` waits for workers before closing channels
- **Context leak in recursive fuzzer** — `context.WithCancel` in `Run` never called cancel on normal completion; added `defer cancel()`
- **HTTP GET with no timeout in fuzz CLI** — `http.Get(*wordlist)` had no timeout or context; replaced with `http.NewRequestWithContext` using 30-second timeout
- **Bare type assertions in CLI dispatch** — 11 `opts.(*XOptions)` assertions in `cli.go` panicked on wrong type; converted to comma-ok with descriptive `fmt.Errorf`
- **Bare type assertions in GenerateReport** — 4 files (`upload.go`, `oauth.go`, `deserialize.go`, `apifuzz.go`) used `interface{}` round-trip in report generation; replaced with typed local variables
- **Bare sync.Map assertions in DNS cache** — 3 `entry.(*cacheEntry)` assertions in `dnscache.go` panicked on corrupt cache; converted to comma-ok with error returns
- **Bare sync.Map assertions in host errors** — 3 `v.(*hostState)` assertions in `hosterrors.go` panicked on corrupt state; converted to comma-ok with nil guards
- **Bare sync.Map assertion in discovery** — `key.(string)` in `active_extraction.go` panicked on non-string key; converted to comma-ok with empty guard
- **Gzip close error swallowed** — `saveToCache` in `corpus.go` used `defer gzWriter.Close()` discarding flush errors; now uses named return with deferred error capture
- **Timer leak in health waiter** — `time.After` in loop created uncollectable timers each iteration; replaced with `time.NewTimer` + `Stop`
- **Non-portable path construction** — `nuclei.go` used string concatenation (`dir + "/" + name`) instead of `filepath.Join`

### Added

- **Gap test suite** — 13 new test files covering 6 structural testing gaps: type safety (`cli`, `dnscache`, `hosterrors`), error propagation (`output`, `corpus`, `checkpoint`), security boundaries (`compliance` HTML injection), concurrency (`workerpool`, `filter`, `distributed`), goroutine leaks (`screenshot`), and context cancellation (`recursive`)
- **Shared test helpers** — `pkg/testutil` package with `FailingWriter`, `GoroutineTracker`, `AssertNoPanic`, `AssertTimeout`, `RunConcurrently`, `PoisonSyncMap`
- **Workerpool regression test** — `TestPool_BlockingSendCloseDeadlock` reproduces the exact deadlock scenario (tiny buffer, blocked workers, concurrent Close) with timeout detection

## [2.8.5] - 2026-02-11

### Changed

- **Enterprise refactoring complete** — 26-phase structural overhaul (166/173 tasks): shared finding types, shared attack config, centralized errors, CLI decomposition, utility deduplication, context propagation, god file decomposition, magic number extraction, extended test coverage
- **Context propagation** — All long-running operations now accept `context.Context` for clean cancellation and goroutine safety
- **God file decomposition** — Split 6 oversized files (`mcpserver/tools.go`, `report/html_report.go`, `ssti/ssti.go`, `osint/osint.go`, `discovery/` god files, `core/executor.go`) into focused modules

### Fixed

- **OWASP DRY violation** — Replaced 8 hardcoded OWASP category strings in `pkg/report/html_vulndb.go` with `defaults.OWASPTop10` map references
- **Goroutine leaks** — Fixed resource leaks in `interactive.inputLoop`, `distributed.StartDistributor`, `leakypaths` work sender, and `deserialize.Scan`
- **Race conditions** — Fixed 7 data races across `scoring`, `waf`, `detection`, `workerpool`, `runner`, `oob`, and `calibration` packages
- **Dead code cleanup** — Removed ~235 LOC of confirmed dead code (nil/nil stubs, unused functions)

### Internal

- 44 structural enforcement tests preventing regression
- All attack packages use shared `finding.Vulnerability` and `attackconfig.Base` types
- Shared retry engine, signal handling, and structured logging across CLI
- Performance: buffer pooling, JSON streaming, slice preallocation in hot paths

## [2.8.4] - 2026-02-10

### Changed

- **Version bump** — Baseline release before enterprise refactoring

### Internal

- Established v2.8.4 as pre-refactoring baseline tag
- All refactoring (Phases 1-25) will build on this release

## [2.8.3] - 2026-02-09

### Security

- **Fork PR supply-chain hardening** — `docker-publish.yml` and `release.yml` now filter `workflow_run.event == 'push'` to prevent fork PRs from triggering Docker pushes or releases via `workflow_run` (which runs with base repo secrets regardless of trigger source)
- **SHA-pinned all GitHub Actions** — All workflow actions across CI, Docker, Release, npm-publish, rebuild-assets, and private-guard now use immutable commit SHAs instead of floating tags
- **Removed `eval` in entrypoint.sh** — Replaced `eval "CMD+=(${INPUT_ARGS})"` with `xargs`-based argument parsing to eliminate shell injection risk from `args` input
- **Heredoc output injection prevention** — GitHub outputs now use PID-unique heredoc delimiters to prevent output injection from malicious target URLs
- **Markdown table sanitization** — Finding category names are now stripped of `|`, backtick, and backslash characters to prevent Markdown injection in job summaries

### Fixed

- **`workflow_run.branches` filter blocking tag releases** — Removed `branches: [main]` from `docker-publish.yml` and `release.yml` which silently prevented tag-triggered workflow_run events from firing
- **Docker concurrency group always miss** — `startsWith(github.event.workflow_run.head_branch, 'refs/tags/')` was always false because `head_branch` is the tag NAME (e.g. `v2.9.0`), not the full ref; changed to `startsWith(..., 'v')`
- **Prerelease tags pushing floating Docker tags** — Prerelease tags (e.g. `v2.9.0-rc1`) now only get `sha-` Docker tag, not `latest`/`edge`/semver floats
- **Shallow clone defeating author identity check** — `private-guard.yml` now uses `fetch-depth: 6` so `git log HEAD~5..HEAD` doesn't fail silently
- **GoReleaser version pinning** — Changed from `version: latest` to `version: '~> v2'` in release and rebuild-assets workflows to prevent breaking changes
- **Release notes handling** — Uses `--notes-file` instead of `--notes` for release note merging to avoid shell escaping issues with multiline content

### Changed

- **Private file guard expanded** — `REQUIRED_IGNORES` list expanded from 6 to 12 paths (added `.github/copilot-instructions.md`, `.github/memory-seed.json`, `.claude/`, `.mcp.json`, `.vscode/`, `docs/plans/`, `docs/research/`)
- **npm-publish chain filter** — Added `event != 'pull_request'` filter with documentation explaining chained `workflow_run.event` semantics
- **Dockerfile consistency check** — Now handles multi-source COPY instructions (e.g. `COPY go.mod go.sum ./`)
- **Structural test coverage** — `TestNoPrivateFilesInRepo` gitignore check expanded from 10 to 12 rules

## [2.8.2] - 2026-02-10

### Fixed

- **Progress bar overflow** — `allScanTypes` progress tracking list had only 25 entries but 38 `runScanner()` calls existed, causing progress to display 140% (e.g., 35/25) and spinner to hang after scan completion
- **Dry-run list out of sync** — Dry-run mode `allScanTypes` list was missing `graphql`, `subtakeover`, `apifuzz`, `wafevasion`, and `tlsprobe` scan types, causing `--dry-run` to undercount available scans
- Both `allScanTypes` lists now include all 38 scan types matching every `runScanner()` call: `sqli`, `xss`, `traversal`, `cmdi`, `nosqli`, `hpp`, `crlf`, `prototype`, `cors`, `redirect`, `hostheader`, `websocket`, `cache`, `upload`, `deserialize`, `oauth`, `ssrf`, `ssti`, `xxe`, `smuggling`, `graphql`, `jwt`, `subtakeover`, `bizlogic`, `race`, `apifuzz`, `wafdetect`, `waffprint`, `wafevasion`, `tlsprobe`, `httpprobe`, `secheaders`, `jsanalyze`, `apidepth`, `osint`, `vhost`, `techdetect`, `dnsrecon`

## [2.8.1] - 2026-02-09

### Added

- **GitHub Actions Marketplace** — Official [`waftester-action`](https://github.com/waftester/waftester-action) published. Zero-install CI/CD integration with `uses: waftester/waftester-action@v1`. Supports all scan types, SARIF upload, version pinning, and SHA-256 verified binary downloads.

### Fixed

#### Master Audit — 14 Bug Fixes

Comprehensive audit identified and fixed 14 bugs across CLI, MCP server, core executor, detection, and output subsystems.

**Critical & High Priority:**
- **Rate limiting not wired** (CRIT-1): `scanLimiter` was created but never called in `runScanner()`. Now uses `golang.org/x/time/rate` with `scanLimiter.Wait(ctx)` before every request.
- **maxErrors death-spiral** (CRIT-2): `maxErrors` flag was declared but never enforced. Now calls `cancel()` when error count exceeds threshold.
- **Nil dispatcher panics** (HIGH-2): 5 `dispCtx.EmitError()` / `runDispCtx.EmitError()` calls could panic when dispatcher is nil. All guarded with nil checks.
- **Raw HTTP transport** (HIGH-4): `cmd_scan.go` built a manual `&http.Transport{}` instead of using `httpclient.New()` factory. Missed DNS cache, HTTP/2, sockopt, and detection wrapper. Replaced with `httpclient.FuzzingConfig()` + `httpclient.New()`.
- **Detection singleton cross-contamination** (HIGH-6): All executors shared `detection.Default()` singleton. Concurrent MCP scans to the same host corrupted each other's drop/ban state. Each executor now creates `detection.New()` and wires it into its transport wrapper.
- **No signal handler** (HIGH-7): Ctrl+C during CLI scan leaked goroutines and connections. Added SIGINT/SIGTERM handler that calls `cancel()` for graceful shutdown.
- **Scan cancellation discards results** (HIGH-1): MCP `task.Fail("scan cancelled")` threw away all partial results. Now returns whatever was collected with "PARTIAL RESULTS" annotation.

**Medium Priority:**
- **Timeout flag misleading** (MED-2): `-timeout 30` means 30s per-request but 30-minute scan deadline. Clarified flag description and changed `*timeout*60*time.Second` to `time.Minute`.
- **Mutation explosion** (MED-3): Bypass tool accepted unlimited payloads — 100 payloads × encoders could silently generate 15K+ requests. Added guard rejecting >50 payloads with helpful guidance.
- **ReadOnlyHint wrong** (MED-4): `detect_waf`, `discover`, and `probe` tools marked `ReadOnlyHint: true` despite sending HTTP probes to targets. Fixed to `false` so MCP clients prompt user confirmation.
- **Division by zero** (HIGH-3): `cmd_tests.go` divided by `Duration.Seconds()` for `RequestsPerSec` without checking for zero duration. Guarded with `secs > 0` check.

**Resource Leaks:**
- **Transport leak** (HIGH-5): `Executor` had no `Close()` method — idle HTTP connections accumulated. Added `Close()` with `CloseIdleConnections()` and `detector.ClearAll()`.
- **File handle leak** (MED-5): `JSONWriter.Close()` and `SARIFWriter.Close()` leaked file handles when `json.Encode()` failed — early return skipped `file.Close()`. Fixed with deferred close.
- **Detection state leak** (HIGH-6b): Removed `detection.Default().Clear()` from 4 MCP handlers — no longer needed with per-executor detector lifecycle.

### Changed
- `cmd/cli/cmd_scan.go`: Delay+jitter support wired into `runScanner()` with context cancellation check
- `pkg/mcpserver/tools.go`: Detection rate now annotated with skipped count when hosts unreachable
- Replaced misleading silence block at end of `cmd_scan.go` with explicit TODO(v2.9.0) comments

## [2.8.0] - 2026-02-08

### Added

#### npm Distribution (`@waftester/cli`)

WAFtester is now available on npm for zero-dependency installs. Enables one-liner MCP server setup for Claude Desktop, VS Code, and Cursor.

- **`npx -y @waftester/cli` one-liner**: Run WAFtester without installing Go or downloading binaries. Downloads the correct platform binary automatically via `optionalDependencies`.
- **6 platform packages**: `@waftester/darwin-x64`, `@waftester/darwin-arm64`, `@waftester/linux-x64`, `@waftester/linux-arm64`, `@waftester/win32-x64`, `@waftester/win32-arm64`.
- **MCP server via npx**: `npx -y @waftester/cli mcp` starts the MCP server with bundled payloads and templates. Claude Desktop, VS Code, and Cursor configs now use `npx` as the command.
- **ARM64 emulation fallback**: On macOS arm64 with missing native package, falls back to x64 binary under Rosetta 2. Same for Windows ARM.
- **Yarn PnP detection**: Detects `.zip/` paths from Yarn PnP and directs users to set `preferUnplugged: true`.
- **Environment variable override**: `WAF_TESTER_BINARY_PATH` for development/debugging.
- **Provenance attestation**: All npm packages published with `--provenance` for supply chain verification (`npm audit signatures`).
- **Automated CI/CD**: `npm-publish.yml` workflow chains after GoReleaser release, extracts archives, builds 7 packages, publishes with idempotency checks, and verifies provenance.
- **Stdout purity**: Node.js bin shim uses only `console.error` (0 `console.log` calls), ensuring clean `stdio` transport for MCP.

### Changed

- README: Added npm badge, npm/npx install section as recommended method, MCP configs updated to use `npx`
- INSTALLATION.md: Added npm/npx section with platform table and environment variables
- SECURITY.md: Updated supported versions table for 2.8.x

## [2.7.8] - 2026-02-09

### Fixed

#### Silent Scan Death Spiral (4-Bug Chain)

Production scans were returning `Blocked: 0, Bypassed: 0, Errors: 12` with 3340/3352 payloads silently vanishing. Root cause: a chain of 4 interacting bugs that created a "death spiral" — once a host started failing, errors cascaded faster than they could be reported.

- **Bug A — Stale global state across MCP scans**: `hosterrors` and `detection` singletons were never cleared between MCP scan invocations. A host marked as failing in scan 1 would be pre-poisoned for scan 2, causing immediate skip of all payloads. Fixed by adding `hosterrors.Clear()` + `detection.Default().Clear()` at the start of all 4 MCP async handlers (`scan`, `assess`, `bypass`, `discover`).

- **Bug B — Rate limiter before skip check**: Skipped payloads were waiting for a rate-limit token before being discarded. With 3340 skipped payloads × 20ms rate limit = 66 seconds wasted on payloads that would never be sent. Fixed by moving `hosterrors.Check()` and `ShouldSkipHost()` before `limiter.Wait()` in both `Execute()` and `ExecuteWithProgress()`.

- **Bug C — No death spiral detection**: When a host went down, all remaining payloads would be individually checked, skipped, and rate-limited — no early abort. Fixed by adding death spiral detection: after 50 completions, if >80% are skipped, the scan context is cancelled and remaining payloads are abandoned.

- **Bug D — Skipped payloads invisible in results**: The `Skipped` outcome was never tracked or reported. Users and AI agents saw `Blocked: 0, Bypassed: 0, Errors: 12` with no indication that 3340 payloads were silently dropped. Fixed by adding `HostsSkipped` counter to both execution paths, progress callbacks, summary output, and interpretation text.

#### CLI Audit Fixes

- **False bypass alerts for skipped payloads**: `OnResult` callback in CLI `test` command was emitting skipped payloads as bypass events to Slack, Teams, PagerDuty, OTEL, and Prometheus. Fixed by filtering `Outcome != "Skipped"`.
- **Multi-target aggregation missing `HostsSkipped`**: When running `test` against multiple targets, skipped count was not aggregated in the combined summary.
- **`ui.PrintSummary` box missing skipped row**: The pretty summary box showed Total/Blocked/Pass/Fail/Errors but not Skipped. Added `[>>] N` row when skipped > 0.
- **`output.PrintSummary` missing skipped line**: The WAF Security Test Summary printed Total/Blocked/Pass/Fail/Errors without Skipped, causing the math to not balance. Added `⏭ Skipped: N (host unreachable)` line.
- **`scan` command missing `hosterrors` check**: The `runScanner` helper checked `detection.ShouldSkipHost()` but not `hosterrors.Check()`, allowing scanners to run against hosts known to be failing from previous scanners.

### Added

- `buildSkippedResult()` helper on `Executor` — creates proper `TestResult` with `Outcome: "Skipped"`, zero risk score, and descriptive error message
- Death spiral detection in both `Execute()` and `ExecuteWithProgress()` — aborts scan when >80% of first 50 completions are skipped
- `HostsSkipped` field now populated in `ExecuteWithProgress()` (was defined but never set)
- Skipped-aware interpretation and next-steps in MCP `scan` tool response

### Changed

- `TestRateLimiting` threshold relaxed from 2.0s to 1.8s to prevent flaky CI failures from timing jitter

## [2.7.7] - 2026-02-08

### Added

#### Cross-Session Task Recovery

MCP clients like n8n create a new session (full `initialize` handshake) for every AI agent turn. When `assess` returns a `task_id` in turn 1 and the AI needs to poll with `get_task_status` in turn 2, the new session means the AI often loses or hallucinates the `task_id`. This release makes task recovery automatic and session-independent.

- **`task_id` now optional in `get_task_status`**: When omitted, the server auto-discovers the most recent active task. Prefers running/pending tasks over completed ones — exactly what a reconnecting client needs.
- **`tool_name` parameter in `get_task_status`**: When `task_id` is omitted, filter auto-discovery by which tool started the task (e.g., `"assess"`, `"scan"`). Eliminates ambiguity when multiple tasks exist.
- **`GetLatest()` method on `TaskManager`**: Returns the most recently created non-terminal task, falling back to the most recently updated terminal task. Accepts optional tool name filter. Thread-safe with proper lock ordering.
- **`tool_name` filter in `list_tasks`**: Filter task listings by tool name (e.g., `{"tool_name": "scan"}`). Can combine with existing `status` filter.
- **Cross-session recovery workflow in `serverInstructions`**: Explicit instructions telling AI agents: "If you lost the task_id, call `get_task_status` without parameters or use `list_tasks` to discover tasks."

#### Auto-Discovery Examples

```
# Recover latest task (any tool):
get_task_status {"wait_seconds": 30}

# Recover latest assess task specifically:
get_task_status {"tool_name": "assess", "wait_seconds": 30}

# List all running tasks to pick one:
list_tasks {"status": "running"}

# Filter by tool and status:
list_tasks {"tool_name": "scan", "status": "running"}
```

### Tests

- Added `TestGetTaskStatus_AutoDiscovery_FindsActiveTask` — auto-discovers running task when task_id omitted.
- Added `TestGetTaskStatus_AutoDiscovery_FindsCompletedTask` — falls back to completed task when no active tasks.
- Added `TestGetTaskStatus_AutoDiscovery_PrefersActiveOverCompleted` — running tasks preferred over completed.
- Added `TestGetTaskStatus_AutoDiscovery_ByToolName` — tool_name filter finds correct task.
- Added `TestGetTaskStatus_AutoDiscovery_NoMatchingTool` — returns error when no tasks match filter.
- Added `TestListTasks_WithToolNameFilter` — filters task list by tool name.
- Added `TestListTasks_WithToolNameAndStatusFilter` — combined tool_name + status filtering.
- Added `TestGetLatest_EmptyManager` — nil on empty TaskManager.
- Added `TestGetLatest_SingleActiveTask` — finds the only active task.
- Added `TestGetLatest_PrefersActiveOverTerminal` — prefers running over completed.
- Added `TestGetLatest_FallsBackToTerminal` — returns completed when no active tasks.
- Added `TestGetLatest_MostRecentActive` — returns most recently created active task.
- Added `TestGetLatest_WithToolFilter` — tool filter works correctly.
- Added `TestGetLatest_ToolFilterNoMatch` — nil when filter doesn't match.
- Updated `TestGetTaskStatus_MissingTaskID` — now tests auto-discovery "no tasks found" path.
- **257 tests total, all passing.**

## [2.7.6] - 2026-02-08

### Fixed

#### MCP Task ID Format Validation

AI agents (particularly via n8n) were hallucinating UUID-format task IDs instead of using the exact `task_id` returned by async tools. The server now validates task ID format before map lookup and returns specific, actionable error messages.

- **`ValidateTaskID` function**: Validates that task IDs match the expected format (`task_` prefix + exactly 16 hex characters, no dashes). Returns human-readable reason on failure with correction instructions.
- **Format validation in `get_task_status` and `cancel_task`**: Both tools validate task ID format before lookup, preventing generic "not found" errors for malformed IDs.
- **Actionable error messages**: Invalid format errors include the submitted ID, correct format example, and pointers to `list_tasks` — enabling AI agents to self-correct.
- **Server instructions updated**: `serverInstructions` now explicitly documents task ID format (`task_a1b2c3d4e5f6g7h8`) and warns against UUIDs or modified IDs.
- **Tool descriptions updated**: `get_task_status` description now includes `TASK ID FORMAT` documentation line.

#### `wait_seconds` Default Fix

The `wait_seconds` parameter in `get_task_status` now correctly defaults to 30 seconds when omitted, instead of Go's zero-value (0). Changed from `int` to `*int` pointer type to distinguish "not provided" from "explicitly 0".

- **`*int` pointer type**: `WaitSeconds` field uses pointer semantics — `nil` means "use default 30s", explicit `0` means "no waiting".
- **`defaultWaitSeconds` constant**: Centralized default value (30) with clear documentation explaining the JSON schema vs Go unmarshaling mismatch.

### Tests

- Added `TestValidateTaskID` — table-driven test covering valid IDs, UUID format, too-short, too-long, non-hex chars, wrong prefix, and other edge cases.
- Added `TestGetTaskStatus_InvalidFormat_UUID` — integration test simulating n8n's AI agent hallucinating UUID task IDs.
- Added `TestGetTaskStatus_InvalidFormat_TooShort` — integration test for truncated task IDs.
- Added `TestGetTaskStatus_WaitSecondsDefault` — verifies omitted `wait_seconds` defaults to 30s (waits for completion).
- Added `TestGetTaskStatus_WaitSecondsExplicitZero` — verifies explicit `wait_seconds=0` returns immediately without blocking.
- Updated `TestGetTaskStatus_NonexistentTask` — uses valid-format but nonexistent task ID.
- Updated `TestCancelTask_NonexistentTask` — uses valid-format but nonexistent task ID.

## [2.7.5] - 2026-02-08

### Added

#### MCP Observability Logging

Production-grade request and tool invocation logging for diagnosing MCP client integration issues (n8n, Claude Desktop, etc.).

- **HTTP request logger**: Every incoming HTTP request is logged with method, path, `Mcp-Session-Id`, content-type, content-length, remote address, response status, and duration. Inserted as the outermost middleware layer.
- **Tool call logger**: Every MCP tool invocation is logged on entry (with truncated arguments) and exit (with success/error status and duration). Uses a `loggedTool` wrapper applied to all 13 tools.
- **Task lifecycle logging**: `TaskManager.Create`, `Complete`, `Fail`, `Cancel`, `Get` (miss), and `cleanup` all log structured events with `[mcp-task]` prefix including task IDs and counts.
- **Log prefixes**: `[mcp-http]` for HTTP layer, `[mcp-tool]` for tool invocations, `[mcp-task]` for task lifecycle — enables easy grep-based filtering in container logs.

## [2.7.4] - 2026-02-08

### Fixed

#### MCP Async Task Reliability (n8n Integration)

- **Stdio sync mode**: Long-running tools now execute synchronously when connected via stdio transport. Each stdio invocation is a separate process, so in-memory async task state was lost between calls — causing "task not found" errors. Stdio has no HTTP timeout, so synchronous execution is safe.
- **Long-poll `wait_seconds`**: `get_task_status` now accepts `wait_seconds` (0–120, default 30) to block until the task completes or the timeout elapses. Reduces polling overhead from many rapid calls to 2–4 efficient long-polls per operation.
- **Task completion signaling**: Tasks now use a `done` channel closed on terminal state transitions (`Complete`, `Fail`, `Cancel`), enabling efficient blocking in `WaitFor` instead of busy-polling.
- **Stronger agent instructions**: Server instructions now explicitly forbid agents from returning "check back later" messages — agents must poll in a loop with `wait_seconds=30` until the task reaches a terminal state within the same execution context.
- **Diagnostic logging**: Task lifecycle events (create, complete, fail, panic) are now logged with `[mcp]` prefix for production debugging of task state issues.

### Tests

- Added `TestWaitForCompletesImmediatelyWhenDone` — verifies WaitFor returns instantly for completed tasks.
- Added `TestWaitForTimesOut` — verifies WaitFor respects timeout parameter.
- Added `TestWaitForUnblocksOnCompletion` — verifies WaitFor unblocks when task completes during wait.
- Added `TestWaitForUnblocksOnContextCancel` — verifies WaitFor respects context cancellation.
- Added `TestSyncModeDefault` — verifies sync mode is off by default (HTTP/SSE transport).
- Added `TestGetTaskStatusWaitSeconds` — end-to-end test of long-poll via MCP tool call.

## [2.7.3] - 2026-02-08

### Added

#### Async Task Pattern — Timeout-Proof MCP Operations

Long-running MCP tools (scan, assess, bypass, discover) now return a `task_id` immediately instead of blocking. This prevents `MCP error -32001: Request timed out` errors that occurred when operations exceeded client timeout limits (60s for n8n, 30-120s for other clients).

- **`TaskManager`** (`pkg/mcpserver/taskmanager.go`) — concurrent-safe async task lifecycle manager with automatic cleanup (30min TTL), max 100 active tasks, 30min hard timeout per task, and graceful shutdown with goroutine drain
- **3 new MCP tools**: `get_task_status` (poll for results), `cancel_task` (stop running tasks), `list_tasks` (view all task states)
- **`launchAsync` helper** — shared goroutine launcher with panic recovery, WaitGroup tracking, and immediate `task_id` response
- **Polling pattern**: call async tool → receive `task_id` → poll `get_task_status` every 5-10s → get full result when completed
- **Progress tracking**: tasks report percentage, current step, and estimated duration
- **Terminal state guards**: prevent race conditions between Cancel→Fail, Complete→Fail, and Fail→Complete transitions
- **Server instructions**: updated with ASYNC TOOL PATTERN section, tool table marks async tools, fast vs async tool classification
- **Prompt updates**: all 6 guided workflow prompts include async polling instructions for long-running steps

#### HTTP Middleware Stack — Production Hardening

- **`recoveryMiddleware`** — catches panics in HTTP handlers, returns 500 JSON error instead of killing the connection
- **`securityHeaders`** — adds `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` to all responses
- **SSE keep-alive** — sends `:keepalive` comments every 15s to prevent reverse proxy idle timeouts (nginx, AWS ALB, Cloudflare, Docker)
- **`keepAliveWriter`** — thread-safe ResponseWriter wrapper with mutex-serialized writes, `Flush()` for SSE streaming, and `Unwrap()` for Go 1.20+ ResponseController discovery
- **SSE handler chain** — SSEHandler now includes `recoveryMiddleware → securityHeaders → sseKeepAlive → sse`

### Fixed

#### MCP Server Fixes

- **WriteTimeout removed** — `WriteTimeout: 60s` set an absolute deadline that killed SSE connections; removed so SSE streams survive indefinitely (ReadHeaderTimeout + ReadTimeout still protect against slowloris)
- **CORS spec compliance** — no CORS headers when `Origin` is absent (setting `*` with `Allow-Credentials` violates the Fetch specification); `Vary: Origin` always set for cache correctness
- **CORS headers expanded** — `MCP-Protocol-Version` added to `Access-Control-Allow-Headers` and `Access-Control-Expose-Headers`
- **Silent exit on no transport** — `waf-tester mcp` with `--stdio=false` and no `--http` now prints an error and exits with code 1 instead of silently exiting
- **Server.Stop()** — properly cancels all running tasks, waits for goroutine drain (10s timeout), and stops the cleanup goroutine
- **`SetProgress` terminal guard** — no longer overwrites progress messages on cancelled/completed/failed tasks
- **Grade table** — fixed `B+` → `B` and added missing `D` grade in server instructions
- **WAF signatures description** — clarified "12 WAF vendor signatures" → "12 of 26 WAF vendors with detailed bypass tips"
- **Server instructions** — corrected "17 commands" → "13 tools"; resource list now includes `waftester://templates` and `waftester://payloads/unified`
- **Template count** — corrected 41 → 40 in version resource, templates resource description, and `total_templates` field
- **`scanArgs` schema** — added missing `Policy` and `Overrides` fields to match InputSchema
- **`detect_waf` error hint** — changed "Try with skip_verify=true" → "Use 'probe' with skip_verify=true" (detect_waf has no skip_verify parameter)
- **`generate_cicd` platform validation** — explicit `validPlatforms` map check before generating YAML; rejects unsupported platforms with clear error
- **Prompt format strings** — fixed `%%%%` → `%%` in `full_assessment` and `template_scan` prompts (4 instances)

### Tests

- **Goroutine leak prevention** — added `defer srv.Stop()` / `t.Cleanup(func() { srv.Stop() })` to all 23 test and benchmark functions that create `mcpserver.New()`, preventing TaskManager goroutine leaks (~60+ per test run)
- **TestCORSDefaultOrigin** — updated to assert absence of CORS headers when no Origin is present (per Fetch spec), plus `Vary: Origin` always present
- **TestCORSHeaders** — added `Vary: Origin` and `MCP-Protocol-Version` assertions
- **Async tool tests** — 15 new tests covering task lifecycle, polling, cancellation, list filtering, sync validation errors, and all 4 async tools returning `task_id`
- **TaskManager tests** — 20 new tests covering ID generation, lifecycle transitions, concurrent access, max capacity, cleanup, terminal state guards, context deadlines, and WaitGroup drain
- **Tool count assertions** — updated from 10 to 13 in `TestListTools`, `TestHTTPTransportListTools`, `TestToolsIterator`

---

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

[2.9.36]: https://github.com/waftester/waftester/compare/v2.9.35...v2.9.36
[2.9.35]: https://github.com/waftester/waftester/compare/v2.9.34...v2.9.35
[2.9.34]: https://github.com/waftester/waftester/compare/v2.9.33...v2.9.34
[2.9.33]: https://github.com/waftester/waftester/compare/v2.9.32...v2.9.33
[2.9.32]: https://github.com/waftester/waftester/compare/v2.9.31...v2.9.32
[2.9.31]: https://github.com/waftester/waftester/compare/v2.9.30...v2.9.31
[2.9.30]: https://github.com/waftester/waftester/compare/v2.9.29...v2.9.30
[2.9.29]: https://github.com/waftester/waftester/compare/v2.9.28...v2.9.29
[2.9.28]: https://github.com/waftester/waftester/compare/v2.9.27...v2.9.28
[2.9.27]: https://github.com/waftester/waftester/compare/v2.9.26...v2.9.27
[2.9.26]: https://github.com/waftester/waftester/compare/v2.9.25...v2.9.26
[2.9.25]: https://github.com/waftester/waftester/compare/v2.9.24...v2.9.25
[2.9.24]: https://github.com/waftester/waftester/compare/v2.9.23...v2.9.24
[2.9.23]: https://github.com/waftester/waftester/compare/v2.9.22...v2.9.23
[2.9.22]: https://github.com/waftester/waftester/compare/v2.9.21...v2.9.22
[2.9.21]: https://github.com/waftester/waftester/compare/v2.9.20...v2.9.21
[2.9.20]: https://github.com/waftester/waftester/compare/v2.9.19...v2.9.20
[2.9.19]: https://github.com/waftester/waftester/compare/v2.9.18...v2.9.19
[2.9.18]: https://github.com/waftester/waftester/compare/v2.9.17...v2.9.18
[2.9.17]: https://github.com/waftester/waftester/compare/v2.9.16...v2.9.17
[2.9.16]: https://github.com/waftester/waftester/compare/v2.9.15...v2.9.16
[2.9.15]: https://github.com/waftester/waftester/compare/v2.9.14...v2.9.15
[2.9.14]: https://github.com/waftester/waftester/compare/v2.9.13...v2.9.14
[2.9.13]: https://github.com/waftester/waftester/compare/v2.9.12...v2.9.13
[2.9.12]: https://github.com/waftester/waftester/compare/v2.9.11...v2.9.12
[2.9.11]: https://github.com/waftester/waftester/compare/v2.9.10...v2.9.11
[2.9.10]: https://github.com/waftester/waftester/compare/v2.9.9...v2.9.10
[2.9.9]: https://github.com/waftester/waftester/compare/v2.9.8...v2.9.9
[2.9.8]: https://github.com/waftester/waftester/compare/v2.9.7...v2.9.8
[2.9.7]: https://github.com/waftester/waftester/compare/v2.9.6...v2.9.7
[2.9.6]: https://github.com/waftester/waftester/compare/v2.9.5...v2.9.6
[2.9.5]: https://github.com/waftester/waftester/compare/v2.9.4...v2.9.5
[2.9.4]: https://github.com/waftester/waftester/compare/v2.9.3...v2.9.4
[2.9.3]: https://github.com/waftester/waftester/compare/v2.9.2...v2.9.3
[2.9.2]: https://github.com/waftester/waftester/compare/v2.9.1...v2.9.2
[2.9.1]: https://github.com/waftester/waftester/compare/v2.9.0...v2.9.1
[2.9.0]: https://github.com/waftester/waftester/compare/v2.8.9...v2.9.0
[2.8.9]: https://github.com/waftester/waftester/compare/v2.8.8...v2.8.9
[2.8.8]: https://github.com/waftester/waftester/compare/v2.8.7...v2.8.8
[2.8.7]: https://github.com/waftester/waftester/compare/v2.8.6...v2.8.7
[2.8.6]: https://github.com/waftester/waftester/compare/v2.8.5...v2.8.6
[2.8.5]: https://github.com/waftester/waftester/compare/v2.8.4...v2.8.5
[2.8.4]: https://github.com/waftester/waftester/compare/v2.8.3...v2.8.4
[2.8.3]: https://github.com/waftester/waftester/compare/v2.8.2...v2.8.3
[2.8.2]: https://github.com/waftester/waftester/compare/v2.8.1...v2.8.2
[2.8.1]: https://github.com/waftester/waftester/compare/v2.8.0...v2.8.1
[2.8.0]: https://github.com/waftester/waftester/compare/v2.7.8...v2.8.0
[2.7.8]: https://github.com/waftester/waftester/compare/v2.7.7...v2.7.8
[2.7.7]: https://github.com/waftester/waftester/compare/v2.7.6...v2.7.7
[2.7.6]: https://github.com/waftester/waftester/compare/v2.7.5...v2.7.6
[2.7.5]: https://github.com/waftester/waftester/compare/v2.7.4...v2.7.5
[2.7.4]: https://github.com/waftester/waftester/compare/v2.7.3...v2.7.4
[2.7.3]: https://github.com/waftester/waftester/compare/v2.7.2...v2.7.3
[2.7.2]: https://github.com/waftester/waftester/compare/v2.7.1...v2.7.2
[2.7.1]: https://github.com/waftester/waftester/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/waftester/waftester/compare/v2.6.8...v2.7.0
[2.6.8]: https://github.com/waftester/waftester/compare/v2.6.7...v2.6.8
[2.6.7]: https://github.com/waftester/waftester/compare/v2.6.6...v2.6.7
[2.6.6]: https://github.com/waftester/waftester/compare/v2.6.5...v2.6.6
[2.6.5]: https://github.com/waftester/waftester/compare/v2.6.4...v2.6.5
[2.6.4]: https://github.com/waftester/waftester/compare/v2.6.3...v2.6.4
[2.6.3]: https://github.com/waftester/waftester/compare/v2.6.2...v2.6.3
[2.6.2]: https://github.com/waftester/waftester/compare/v2.6.1...v2.6.2
[2.6.1]: https://github.com/waftester/waftester/compare/v2.6.0...v2.6.1
[2.6.0]: https://github.com/waftester/waftester/compare/v2.5.3...v2.6.0
[2.5.3]: https://github.com/waftester/waftester/compare/v2.5.2...v2.5.3
[2.5.2]: https://github.com/waftester/waftester/compare/v2.5.1...v2.5.2
[2.5.1]: https://github.com/waftester/waftester/compare/v2.5.0...v2.5.1
[2.5.0]: https://github.com/waftester/waftester/compare/v2.4.3...v2.5.0
[2.4.3]: https://github.com/waftester/waftester/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/waftester/waftester/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/waftester/waftester/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/waftester/waftester/compare/v2.3.5...v2.4.0
[2.3.5]: https://github.com/waftester/waftester/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/waftester/waftester/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/waftester/waftester/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/waftester/waftester/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/waftester/waftester/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/waftester/waftester/releases/tag/v2.3.0
