# ===========================================================================
# WAFtester — Multi-stage Dockerfile
# Produces a minimal, non-root container running the MCP server.
#
# Usage:
#   docker build -t ghcr.io/waftester/waftester .
#   docker run -p 8080:8080 ghcr.io/waftester/waftester
#
# Override the default MCP server mode:
#   docker run ghcr.io/waftester/waftester scan --target https://example.com
# ===========================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build — compile a static Go binary
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build

ARG TARGETARCH
ARG TARGETOS=linux
ARG VERSION="dev"
ARG COMMIT=""
ARG BUILD_DATE=""

WORKDIR /build

# Cache go modules separately for faster rebuilds
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Cross-compile for target arch — no QEMU emulation needed, 10x faster
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w \
      -X github.com/waftester/waftester/pkg/ui.Version=${VERSION} \
      -X github.com/waftester/waftester/pkg/ui.Commit=${COMMIT} \
      -X github.com/waftester/waftester/pkg/ui.BuildDate=${BUILD_DATE}" \
    -o /bin/waf-tester ./cmd/cli

# ---------------------------------------------------------------------------
# Stage 2: Runtime — distroless, non-root, ~5 MB total
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# OCI standard labels — populated at build time by CI
LABEL org.opencontainers.image.title="waf-tester" \
      org.opencontainers.image.description="Comprehensive WAF security testing platform with MCP server, 2800+ attack payloads, and enterprise-grade assessment" \
      org.opencontainers.image.vendor="WAFtester" \
      org.opencontainers.image.licenses="BUSL-1.1" \
      org.opencontainers.image.source="https://github.com/waftester/waftester" \
      org.opencontainers.image.documentation="https://github.com/waftester/waftester/blob/main/README.md" \
      io.modelcontextprotocol.server="true" \
      io.modelcontextprotocol.server.name="waf-tester" \
      io.modelcontextprotocol.server.transport="streamable-http"

WORKDIR /app

# Binary from build stage
COPY --from=build /bin/waf-tester .

# Attack payload files — self-contained image
COPY payloads/ ./payloads/

# MCP server listens on 8080 by default
EXPOSE 8080

# Default: start MCP server in HTTP transport mode
ENTRYPOINT ["/app/waf-tester"]
CMD ["mcp", "--http", ":8080", "--payloads", "/app/payloads"]
