# @waftester/cli

[![npm](https://img.shields.io/npm/v/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![downloads](https://img.shields.io/npm/dw/@waftester/cli)](https://npmjs.com/package/@waftester/cli)
[![license](https://img.shields.io/npm/l/@waftester/cli)](https://github.com/waftester/waftester/blob/main/LICENSE)

The most comprehensive WAF testing CLI & MCP server. Detect, fingerprint, and bypass Web Application Firewalls with 2,800+ payloads and quantitative security metrics.

## Quick Start

```bash
# Run without installing
npx -y @waftester/cli scan --target https://example.com

# Or install globally
npm install -g @waftester/cli
waf-tester scan --target https://example.com
```

## MCP Server Setup

WAFtester includes a built-in [Model Context Protocol](https://modelcontextprotocol.io/) server for AI-powered security testing from Claude Desktop, VS Code, Cursor, and other MCP clients.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

### VS Code

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "waf-tester": {
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

### Cursor

Add to Cursor MCP settings:

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

## CLI Usage

```bash
# Full automated assessment
waf-tester auto -u https://target.com --smart

# WAF vendor detection
waf-tester vendor -u https://target.com

# XSS payload testing
waf-tester run -u https://target.com -category xss

# Bypass discovery with tamper chains
waf-tester bypass -u https://target.com --smart --tamper-auto

# Version check
waf-tester version
```

## Platform Support

| Platform | Architecture | Package |
|---|---|---|
| macOS | x64 (Intel) | `@waftester/darwin-x64` |
| macOS | arm64 (Apple Silicon) | `@waftester/darwin-arm64` |
| Linux | x64 | `@waftester/linux-x64` |
| Linux | arm64 | `@waftester/linux-arm64` |
| Windows | x64 | `@waftester/win32-x64` |
| Windows | arm64 | `@waftester/win32-arm64` |

ARM64 platforms with x64 emulation (Rosetta 2, Windows WoW) are supported as fallback.

## Environment Variables

| Variable | Description |
|---|---|
| `WAF_TESTER_BINARY_PATH` | Override binary path (skip platform resolution) |
| `WAF_TESTER_PAYLOAD_DIR` | Override bundled payload directory |
| `WAF_TESTER_TEMPLATE_DIR` | Override bundled template directory |

## License

[Business Source License 1.1](https://github.com/waftester/waftester/blob/main/LICENSE) — converts to open source after the change date. See [LICENSE](https://github.com/waftester/waftester/blob/main/LICENSE) for full terms.

Community payloads are licensed under [MIT](https://github.com/waftester/waftester/blob/main/LICENSE-COMMUNITY).

## Links

- [GitHub](https://github.com/waftester/waftester)
- [Documentation](https://github.com/waftester/waftester/blob/main/docs/EXAMPLES.md)
- [Installation Guide](https://github.com/waftester/waftester/blob/main/docs/INSTALLATION.md)
- [Changelog](https://github.com/waftester/waftester/blob/main/CHANGELOG.md)
- [Issues](https://github.com/waftester/waftester/issues)
