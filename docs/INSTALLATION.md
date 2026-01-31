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
