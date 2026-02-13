# WAFtester

The most comprehensive WAF security testing CLI.

[![Website](https://img.shields.io/badge/website-waftester.com-3b82f6)](https://waftester.com)
[![GitHub](https://img.shields.io/github/v/release/waftester/waftester)](https://github.com/waftester/waftester)

## Quick Start

```bash
docker pull qandil/waftester:latest
docker run --rm qandil/waftester --help
```

## MCP Server

Run as an MCP server for AI-powered WAF testing:

```bash
docker run --rm -p 8080:8080 qandil/waftester
```

Connect your AI client to `http://localhost:8080/mcp` for WAF testing via natural language.

## Run a Scan

```bash
docker run --rm qandil/waftester scan -u https://example.com --smart
```

## Features

- **2800+ payloads** across 20+ attack categories (SQLi, XSS, SSRF, SSTI, LFI, RCE, and more)
- **197 WAF signatures** for automatic WAF detection and fingerprinting
- **MCP server** for AI agent integration
- **Evasion engine** with encoding chains, case mutation, and bypass techniques
- **Multiple output formats**: JSON, SARIF, HTML, CSV, JUnit, SonarQube, GitLab SAST

## Supported Architectures

| Architecture | Tag |
|---|---|
| linux/amd64 | `qandil/waftester:latest` |
| linux/arm64 | `qandil/waftester:latest` |

Multi-platform manifest — Docker automatically pulls the correct image for your architecture.

## Documentation

- [Website](https://waftester.com)
- [Installation Guide](https://waftester.com/docs#installation)
- [Examples](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [GitHub](https://github.com/waftester/waftester)
