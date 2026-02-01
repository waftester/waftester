# Changelog

All notable changes to WAFtester will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[2.3.2]: https://github.com/waftester/waftester/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/waftester/waftester/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/waftester/waftester/releases/tag/v2.3.0
