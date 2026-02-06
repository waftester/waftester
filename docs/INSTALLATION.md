# Installation

## Homebrew (macOS/Linux)

```bash
brew tap waftester/tap
brew install waftester
```

## Binary Download

Download the latest release from [GitHub Releases](https://github.com/waftester/waftester/releases).

## Go Install

```bash
go install github.com/waftester/waftester/cmd/cli@latest
```

## Docker

```bash
docker pull ghcr.io/waftester/waftester:latest
docker run --rm waftester scan https://example.com
```

## Building from Source

```bash
git clone https://github.com/waftester/waftester.git
cd waftester
go build -o waftester ./cmd/cli
```

## MCP Server Setup

The MCP server is built into the `waf-tester` binary. No additional installation is required.

### Stdio Mode (IDE Integrations)

For Claude Desktop, VS Code, or Cursor:

```bash
waf-tester mcp
```

#### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "waf-tester": {
      "command": "waf-tester",
      "args": ["mcp"]
    }
  }
}
```

#### VS Code

Add to `.vscode/mcp.json` in your workspace:

```json
{
  "servers": {
    "waf-tester": {
      "command": "waf-tester",
      "args": ["mcp"]
    }
  }
}
```

### HTTP Mode (Remote / Docker / n8n)

```bash
# Start on port 8080
waf-tester mcp --http :8080

# Verify
curl http://localhost:8080/health
```

#### Docker (MCP)

```bash
docker run -p 8080:8080 ghcr.io/waftester/waftester:latest mcp --http :8080
```

#### n8n

1. Start the MCP server: `waf-tester mcp --http :8080`
2. In n8n, add an MCP Client node
3. Set transport to SSE Endpoint
4. URL: `http://localhost:8080/sse`
5. Connect to an AI Agent node

For detailed MCP examples, see [docs/EXAMPLES.md](EXAMPLES.md#mcp-server-integration).
