# Contributing to WAFtester

Thank you for your interest in contributing to WAFtester! This document provides guidelines and information about contributing.

## Contributor License Agreement (CLA)

Before we can accept your contributions, you must sign our Contributor License Agreement. This is required because WAFtester uses a dual-licensing model (BSL 1.1 for the core + commercial licenses).

When you submit your first pull request, the CLA Assistant bot will guide you through the signing process.

## What Can I Contribute?

### Accepted Contributions

- **Bug fixes** - Fix issues in the core engine
- **Documentation** - Improve docs, examples, tutorials
- **Community payloads** - Add payloads to `payloads/community/` (MIT licensed)
- **New features** - Discuss in an issue first
- **Tests** - Improve test coverage
- **Performance** - Optimizations with benchmarks

### Community Payloads

Payloads in `payloads/community/` are MIT licensed and welcome contributions:

1. Create a JSON file following the existing format
2. Include diverse, well-documented test cases
3. Avoid duplicate payloads
4. Test against a local WAF before submitting

## Development Setup

```bash
# Clone the repository
git clone https://github.com/waftester/waftester.git
cd waftester

# Install dependencies
go mod download

# Build
go build -o waftester ./cmd/cli

# Run tests
go test ./...

# Run linter
golangci-lint run
```

### Enforcement Tests

These AST-based tests run automatically and **fail the build** if violations are detected:

| Test | Enforces |
|------|----------|
| `TestVersionConsistency` | `ui.Version == defaults.Version`, SECURITY.md, CHANGELOG.md |
| `TestNoHardcodedConcurrency` | Use `defaults.Concurrency*` |
| `TestNoHardcodedRetries` | Use `defaults.Retry*` |
| `TestNoHardcodedMaxDepth` | Use `defaults.Depth*` |
| `TestDispatcherWiringMinimumEmissions` | Minimum emission counts per hook method |
| `TestAllDispatcherContextsHaveEmitStart` | All 22 dispatchers call EmitStart |
| `TestErrorPathsHaveEmitError` | Error-prone commands emit EmitError |
| `TestNoHardcodedMaxRedirects` | Use `defaults.MaxRedirects` |
| `TestNoHardcodedContentType` | Use `defaults.ContentType*` |
| `TestNoHardcodedUserAgent` | Use `defaults.UA*` or `ui.UserAgentWithContext()` |
| `TestNoHardcodedTimeouts` | Use `duration.Timeout*` |
| `TestNoHardcodedIntervals` | Use `duration.Interval*` |
| `TestNoRawHTTPClient` | Use `httpclient.*` presets, not raw `&http.Client{}` |

## ⚠️ Configuration Constants Policy

**DO NOT use hardcoded configuration values.** All runtime defaults are centralized:

| Package | Use For |
|---------|---------|
| `pkg/defaults` | Concurrency, Retry, Buffer, Channel, ContentType, UserAgent, Depth, MaxRedirects, Version |
| `pkg/duration` | All `time.Duration` values (Timeout*, Interval*) |
| `pkg/httpclient` | HTTP client presets (NewScanner, NewProbing, NewAggressive) |
| `pkg/ui` | `UserAgentWithContext()` for component-specific UAs |

### ❌ Forbidden Patterns

```go
// WRONG - hardcoded values
config.Concurrency = 10
config.Timeout = 30 * time.Second
config.MaxRetries = 3
req.Header.Set("Content-Type", "application/json")
```

### ✅ Required Patterns

```go
// CORRECT - use centralized constants
config.Concurrency = defaults.ConcurrencyMedium
config.Timeout = duration.HTTPScan
config.MaxRetries = defaults.RetryMedium
req.Header.Set("Content-Type", defaults.ContentTypeJSON)
```

The CI will **fail** if hardcoded values are detected. The tests in `pkg/defaults/defaults_test.go` use AST parsing to detect violations.

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `go test ./...`
5. Run linter: `golangci-lint run`
6. Commit with clear messages
7. Push and create a Pull Request

## Code Style

- Follow standard Go conventions
- Run `gofmt` before committing
- Keep functions focused and small
- Add comments for exported functions
- Write tests for new functionality
- **Use `pkg/defaults` and `pkg/duration` for all configuration values**

## MCP Server Development

The MCP server lives in `pkg/mcpserver/` and follows specific patterns:

### Adding a New Tool

1. Add the tool registration in `tools.go` following existing patterns
2. Write an opinionated description that helps LLMs choose the right tool
3. Include complete `Annotations` (`ReadOnlyHint`, `IdempotentHint`, `OpenWorldHint`, `DestructiveHint`, `Title`)
4. Define a typed args struct with JSON tags
5. Use `parseArgs()`, `notifyProgress()`, `logToSession()`, `textResult()`/`jsonResult()`/`errorResult()` helpers
6. Use typed logging constants (`logInfo`, `logWarning`) instead of raw strings
7. Protect concurrent state with `sync/atomic` or `sync.Mutex`

### Adding a New Resource

1. Add the resource in `resources.go`
2. Static resources use `AddResource()`, parameterized resources use `AddResourceTemplate()`
3. For static JSON content, use a `const` string to avoid runtime allocation
4. Verify `total_*` counts match actual entries

### Running MCP Tests

```bash
# Run all MCP tests (42 tests)
go test -v ./pkg/mcpserver/...

# With race detector (requires CGO_ENABLED=1)
CGO_ENABLED=1 go test -race ./pkg/mcpserver/...
```

### Testing with Claude Desktop

1. Build: `go build -o waf-tester ./cmd/cli`
2. Add to `claude_desktop_config.json` (see README)
3. Restart Claude Desktop
4. Ask Claude to list tools to verify the connection

## Reporting Issues

- Check existing issues first
- Use the issue templates
- Provide reproduction steps
- Include version information: `waftester version`

## Security Vulnerabilities

Do NOT report security vulnerabilities as public issues. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Questions?

Open a Discussion on GitHub or reach out at security@waftester.com
