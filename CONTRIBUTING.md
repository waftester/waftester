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

# Hardcode checks run automatically with tests
# See pkg/defaults/defaults_test.go for TestNoHardcoded* tests
```

## ⚠️ Configuration Constants Policy

**DO NOT use hardcoded configuration values.** All runtime defaults are centralized:

| Package | Use For |
|---------|---------|
| `pkg/defaults` | Concurrency, Retry, Buffer, Channel, ContentType, Depth |
| `pkg/duration` | All `time.Duration` values |
| `pkg/httpclient` | HTTP timeout presets (Probing, Scanning, Fuzzing) |

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

## Reporting Issues

- Check existing issues first
- Use the issue templates
- Provide reproduction steps
- Include version information: `waftester version`

## Security Vulnerabilities

Do NOT report security vulnerabilities as public issues. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## Questions?

Open a Discussion on GitHub or reach out at security@waftester.com
