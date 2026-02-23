# WAFtester

[![Website](https://img.shields.io/badge/website-waftester.com-3b82f6)](https://waftester.com)
[![GitHub release](https://img.shields.io/github/v/release/waftester/waftester)](https://github.com/waftester/waftester/releases)
[![License](https://img.shields.io/badge/license-BSL--1.1-blue)](https://github.com/waftester/waftester/blob/main/LICENSE)

## What is WAFtester?

WAFtester is a WAF security testing platform with 2800+ attack payloads, 198 WAF vendor signatures, and a built-in [MCP server](https://modelcontextprotocol.io/) for AI agent integration (Claude, VS Code Copilot, Cursor).

**One image, two modes.** Starts as an MCP server by default. Override the command to use it as a CLI.

## Quick Start — MCP Server (default)

```bash
docker run -d -p 8080:8080 qandil/waftester
```

The MCP server starts on port 8080 with streamable HTTP transport. Connect any MCP-compatible client to `http://localhost:8080/mcp`.

### Claude Desktop

Add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "waf-tester": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### VS Code / Cursor

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "waf-tester": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

## Quick Start — CLI Mode

Override the default command to use any WAFtester CLI feature:

```bash
# Full automated scan (discover + learn + run + report)
docker run --rm qandil/waftester auto -u https://example.com

# Smart scan with WAF detection
docker run --rm qandil/waftester scan -u https://example.com --smart

# WAF detection and fingerprinting
docker run --rm qandil/waftester probe -u https://example.com

# Enterprise WAF assessment
docker run --rm qandil/waftester assess -u https://example.com
```

## ... via `docker compose`

Example `compose.yaml` for running the MCP server:

```yaml
services:
  waftester:
    image: qandil/waftester:latest
    ports:
      - "8080:8080"
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=64m
    security_opt:
      - no-new-privileges:true
```

Run `docker compose up -d` and connect your AI client to `http://localhost:8080/mcp`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WAF_TESTER_HTTP_ADDR` | `:8080` | HTTP listen address for MCP server |
| `WAF_TESTER_PAYLOAD_DIR` | `/app/payloads` | Path to payload JSON files |
| `WAF_TESTER_TEMPLATE_DIR` | `/app/templates/nuclei` | Path to Nuclei YAML templates |

Example:

```bash
docker run -d -p 9090:9090 \
  -e WAF_TESTER_HTTP_ADDR=:9090 \
  qandil/waftester
```

## Features

- **MCP server** built in — AI agents test WAFs via natural language
- **2800+ payloads** across 50+ attack categories (SQLi, XSS, SSRF, SSTI, LFI, RCE, and more)
- **198 WAF signatures** for automatic detection and fingerprinting
- **90+ evasion techniques** with encoding chains, case mutation, and bypass strategies
- **Automated bypass discovery** — test tamper combinations to find WAF bypasses with `--discover`
- **Custom tamper authoring** — write Tengo-based tamper scripts and load via `--tamper-dir`
- **SPA event crawling** — DOM event discovery for JavaScript-heavy targets with `--event-crawl`
- **Multi-protocol templates** — Nuclei-compatible templates support HTTP, DNS, TCP, and UDP
- **Smart mode** — auto-detects WAF vendor and optimizes payloads, rate limits, and encoders
- **API spec scanning** — OpenAPI, Swagger, Postman, HAR, AsyncAPI, gRPC, and GraphQL
- **Output formats**: JSON, JSONL, SARIF, HTML, Markdown, JUnit, CycloneDX, SonarQube, GitLab SAST, CSV

## Image Details

| Property | Value |
|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| User | nonroot (UID 65534) |
| Size | ~11 MB |
| Exposed port | 8080 |
| Entrypoint | `/app/waf-tester` |
| Default command | `mcp --http :8080` |

The image is read-only safe — no shell, no package manager, minimal attack surface.

## Supported Architectures

| Architecture | Available |
|---|---|
| `linux/amd64` | Yes |
| `linux/arm64` | Yes |

Multi-platform manifest — Docker pulls the correct image for your architecture.

## Documentation

- [Website](https://waftester.com)
- [Documentation](https://waftester.com/docs)
- [Command Reference](https://waftester.com/commands)
- [Cheat Sheet](https://waftester.com/cheat-sheet)
- [Examples](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [GitHub](https://github.com/waftester/waftester)

## License

[Business Source License 1.1](https://github.com/waftester/waftester/blob/main/LICENSE) (core). Community payloads under [MIT](https://github.com/waftester/waftester/blob/main/LICENSE-COMMUNITY).
