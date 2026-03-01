# WAFtester Platform Binary

[![npm](https://img.shields.io/npm/v/@waftester/cli)](https://npmjs.com/package/@waftester/cli)

This package contains the pre-built WAFtester binary for a specific OS/architecture combination. It is automatically installed as part of [`@waftester/cli`](https://npmjs.com/package/@waftester/cli) via `optionalDependencies`.

## Do Not Install Directly

Install the main package instead — it selects the correct binary for your platform automatically:

```bash
# Run without installing
npx -y @waftester/cli scan -u https://example.com

# Or install globally
npm install -g @waftester/cli
```

## How It Works

`@waftester/cli` declares all 6 platform packages as `optionalDependencies` with `os` and `cpu` constraints. npm installs only the package matching your system:

| Package | Platform |
|---|---|
| `@waftester/darwin-x64` | macOS Intel |
| `@waftester/darwin-arm64` | macOS Apple Silicon |
| `@waftester/linux-x64` | Linux x64 |
| `@waftester/linux-arm64` | Linux arm64 |
| `@waftester/win32-x64` | Windows x64 |
| `@waftester/win32-arm64` | Windows arm64 |

## What Is WAFtester?

The most comprehensive WAF testing CLI — detect, fingerprint, and bypass Web Application Firewalls with 2,800+ payloads, 96 tamper scripts, and quantitative security metrics.

- [Website](https://waftester.com)
- [GitHub](https://github.com/waftester/waftester)
- [Main npm package](https://npmjs.com/package/@waftester/cli)
- [Documentation](https://waftester.com/docs)
