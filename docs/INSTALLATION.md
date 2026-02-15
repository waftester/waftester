# Installation

## npm / npx (Recommended)

The easiest way to install WAFtester. Downloads the correct platform binary automatically.

```bash
# Run directly without installing
npx -y @waftester/cli version

# Or install globally
npm install -g @waftester/cli
waf-tester version
```

Requires Node.js >= 16. Works on macOS, Linux, and Windows (x64 and arm64).

### Platform Packages

npm automatically installs only the binary for your platform via `optionalDependencies`:

| Package | Platform |
|---------|----------|
| `@waftester/darwin-x64` | macOS Intel |
| `@waftester/darwin-arm64` | macOS Apple Silicon |
| `@waftester/linux-x64` | Linux x64 |
| `@waftester/linux-arm64` | Linux arm64 |
| `@waftester/win32-x64` | Windows x64 |
| `@waftester/win32-arm64` | Windows arm64 |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `WAF_TESTER_BINARY_PATH` | Override binary path (dev/debug) |
| `WAF_TESTER_PAYLOAD_DIR` | Override payload directory |
| `WAF_TESTER_TEMPLATE_DIR` | Override Nuclei template directory |

## Homebrew (macOS/Linux)

```bash
brew tap waftester/tap
brew install waftester
```

## Scoop (Windows)

```powershell
scoop bucket add waftester https://github.com/waftester/scoop-waftester
scoop install waftester
```

## AUR (Arch Linux)

```bash
yay -S waftester-bin
```

## Binary Download

Download the latest release from [GitHub Releases](https://github.com/waftester/waftester/releases).

## Docker

Multi-architecture images (`linux/amd64`, `linux/arm64`) are published
to GitHub Container Registry and Docker Hub on every
release and `main` branch push.

| Registry | Image |
|----------|-------|
| GHCR | `ghcr.io/waftester/waftester` |
| Docker Hub | `docker.io/qandil/waftester` |

Examples below use GHCR; replace with the Docker Hub
image if preferred.

The image is built on `distroless/static-debian12:nonroot` (~5 MB),
runs as a non-root user with a read-only filesystem.

### Pull and Run

```bash
# Pull the latest stable release
docker pull ghcr.io/waftester/waftester:latest

# Start the MCP server (default command)
docker run -p 8080:8080 ghcr.io/waftester/waftester

# Run a scan directly
docker run --rm ghcr.io/waftester/waftester scan -u https://example.com

# Run with custom payloads mounted
docker run -p 8080:8080 \
  -v /path/to/payloads:/app/payloads:ro \
  ghcr.io/waftester/waftester
```

### Available Tags

| Tag | Description | Example |
|-----|-------------|---------|
| `latest` | Latest stable release | `ghcr.io/waftester/waftester:latest` |
| `2.9.5` | Exact version | `ghcr.io/waftester/waftester:2.9.5` |
| `2.7` | Latest patch in minor | `ghcr.io/waftester/waftester:2.7` |
| `2` | Latest in major | `ghcr.io/waftester/waftester:2` |
| `edge` | Latest `main` build | `ghcr.io/waftester/waftester:edge` |
| `sha-abc1234` | Specific commit | `ghcr.io/waftester/waftester:sha-abc1234` |

### Docker Compose

A `docker-compose.yml` is included in the repository for local
development:

```bash
# Build and start
docker compose up --build

# With version info from your environment
VERSION=2.9.5 COMMIT=$(git rev-parse --short HEAD) \
  docker compose up --build

# Detached mode
docker compose up -d

# View logs
docker compose logs -f waftester

# Stop
docker compose down
```

The compose file sets `read_only: true`, `no-new-privileges`, and a
64 MB `tmpfs` at `/tmp` for security hardening.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAF_TESTER_PAYLOAD_DIR` | Override payload directory path | `/app/payloads` |
| `WAF_TESTER_HTTP_ADDR` | HTTP listen address | `:8080` |

### Security Notes

- **Non-root**: Runs as uid 65532 (distroless `nonroot`)
- **Read-only filesystem**: No writable layers at runtime
- **tmpfs**: `/tmp` mounted `noexec,nosuid` (64 MB)
- **No shell**: Distroless base has no shell, package manager,
  or debugging tools — minimal attack surface
- **SBOM + Provenance**: Release images include SBOM attestation
  and provenance metadata

### Verify the Image

```bash
# Check health
curl -s http://localhost:8080/health
# → {"status":"ok","service":"waf-tester-mcp"}

# Inspect labels
docker inspect ghcr.io/waftester/waftester:latest \
  --format '{{json .Config.Labels}}' | jq
```

## Building from Source

```bash
git clone https://github.com/waftester/waftester.git
cd waftester
go build -o waf-tester ./cmd/cli
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
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
    }
  }
}
```

Or if installed via Go or binary download:

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
      "command": "npx",
      "args": ["-y", "@waftester/cli", "mcp"]
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
# Using the published image (recommended)
docker run -p 8080:8080 ghcr.io/waftester/waftester

# Override the default command if needed
docker run -p 8080:8080 ghcr.io/waftester/waftester \
  mcp --http :8080 --payloads /app/payloads
```

#### n8n

1. Start the MCP server: `docker run -p 8080:8080 ghcr.io/waftester/waftester`
2. In n8n, add an MCP Client node
3. Set transport to SSE Endpoint
4. URL: `http://localhost:8080/sse`
5. Connect to an AI Agent node

For detailed MCP examples, see [docs/EXAMPLES.md](EXAMPLES.md#mcp-server-integration).
