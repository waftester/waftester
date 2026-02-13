# WAFtester

WAF security testing with 2800+ payloads, 197 WAF signatures, and a built-in MCP server for AI agents.

[![Website](https://img.shields.io/badge/website-waftester.com-3b82f6)](https://waftester.com)
[![GitHub](https://img.shields.io/github/v/release/waftester/waftester)](https://github.com/waftester/waftester)

**One image, two modes.** Starts as an MCP server by default. Override the command to use as a CLI.

## MCP Server (default)

```bash
docker run -p 8080:8080 qandil/waftester
```

The server starts on port 8080. Connect your AI client to `http://localhost:8080/mcp`.

### Claude Desktop

Add to `claude_desktop_config.json`:

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

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "waf-tester": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

## CLI Mode

Override the default command to use any WAFtester CLI feature:

```bash
# Show help
docker run --rm qandil/waftester --help

# Scan a target
docker run --rm qandil/waftester scan -u https://example.com --smart

# Full automated workflow
docker run --rm qandil/waftester auto -u https://example.com

# WAF detection
docker run --rm qandil/waftester probe -u https://example.com
```

## Features

- **MCP server** built in — AI agents (Claude, Copilot, Cursor) can test WAFs via natural language
- **2800+ payloads** across 20+ attack categories (SQLi, XSS, SSRF, SSTI, LFI, RCE, and more)
- **197 WAF signatures** for automatic detection and fingerprinting
- **Evasion engine** with encoding chains, case mutation, and bypass techniques
- **Multiple output formats**: JSON, SARIF, HTML, CSV, JUnit, SonarQube, GitLab SAST

## Supported Architectures

| Architecture | Tag |
|---|---|
| linux/amd64 | `qandil/waftester:latest` |
| linux/arm64 | `qandil/waftester:latest` |

Multi-platform manifest — Docker pulls the correct image for your architecture.

## Documentation

- [Website](https://waftester.com)
- [Docs](https://waftester.com/docs)
- [Examples](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [GitHub](https://github.com/waftester/waftester)
