#!/usr/bin/env node

"use strict";

// — Runtime Node.js version check (engines field is advisory only) —
const major = parseInt(process.versions.node.split(".")[0], 10);
if (major < 16) {
  console.error(
    `WAFtester requires Node.js >= 16 (found ${process.version}).`
  );
  process.exit(1);
}

const { execFileSync } = require("child_process");
const { existsSync } = require("fs");
const path = require("path");

const PLATFORMS = {
  "darwin-x64": "@waftester/darwin-x64",
  "darwin-arm64": "@waftester/darwin-arm64",
  "linux-x64": "@waftester/linux-x64",
  "linux-arm64": "@waftester/linux-arm64",
  "win32-x64": "@waftester/win32-x64",
  "win32-arm64": "@waftester/win32-arm64",
};

// ARM64 → x64 emulation fallback (Rosetta 2 / Windows ARM emulation)
const EMULATION_FALLBACK = {
  "darwin-arm64": "@waftester/darwin-x64",
  "win32-arm64": "@waftester/win32-x64",
};

function resolvePkgBinary(packageName) {
  const binaryName =
    process.platform === "win32" ? "waf-tester.exe" : "waf-tester";
  const pkgJsonPath = require.resolve(`${packageName}/package.json`);

  // Yarn PnP: detect if resolved path is inside a .zip archive
  if (pkgJsonPath.includes(".zip/")) {
    console.error(
      `WAFtester: binary resolved inside a zip archive (Yarn PnP).\n` +
        `Set preferUnplugged: true for ${packageName} in .yarnrc.yml,\n` +
        `or run: yarn unplug ${packageName}`
    );
    process.exit(1);
  }

  return path.join(path.dirname(pkgJsonPath), "bin", binaryName);
}

function getBinaryPath() {
  // 1. Environment variable override (for development/debugging)
  const envPath = process.env.WAF_TESTER_BINARY_PATH;
  if (envPath) {
    if (!existsSync(envPath)) {
      console.error(
        `WAFtester: WAF_TESTER_BINARY_PATH does not exist: ${envPath}\n` +
          `Unset WAF_TESTER_BINARY_PATH to use the bundled binary.`
      );
      process.exit(1);
    }
    return envPath;
  }

  const platformKey = `${process.platform}-${process.arch}`;

  // 2. Exact platform match
  const packageName = PLATFORMS[platformKey];
  if (packageName) {
    try {
      return resolvePkgBinary(packageName);
    } catch {
      // Fall through to emulation fallback
    }
  }

  // 3. Emulation fallback (ARM64 → x64 via Rosetta 2 / WoW)
  const fallbackPkg = EMULATION_FALLBACK[platformKey];
  if (fallbackPkg) {
    try {
      const fallbackPath = resolvePkgBinary(fallbackPkg);
      console.error(
        `WAFtester: native binary for ${platformKey} not found.\n` +
          `Falling back to x64 binary under emulation.`
      );
      return fallbackPath;
    } catch {
      // Fall through to error
    }
  }

  // 4. Unsupported or missing — actionable error message
  if (!packageName) {
    console.error(
      `WAFtester: unsupported platform ${platformKey}\n` +
        `Supported: ${Object.keys(PLATFORMS).join(", ")}\n` +
        `Download a binary from: ` +
        `https://github.com/waftester/waftester/releases`
    );
  } else {
    console.error(
      `WAFtester: ${packageName} is not installed.\n\n` +
        `Try reinstalling:\n` +
        `  npm install @waftester/cli\n\n` +
        `If --no-optional was used:\n` +
        `  npm install @waftester/cli --include=optional\n\n` +
        `Or download a binary from:\n` +
        `  https://github.com/waftester/waftester/releases`
    );
  }
  process.exit(1);
}

// — Set payload/template directories (user env vars take precedence) —
const cliDir = path.resolve(__dirname, "..");
if (!process.env.WAF_TESTER_PAYLOAD_DIR) {
  process.env.WAF_TESTER_PAYLOAD_DIR = path.join(cliDir, "payloads");
}
if (!process.env.WAF_TESTER_TEMPLATE_DIR) {
  process.env.WAF_TESTER_TEMPLATE_DIR = path.join(
    cliDir,
    "templates",
    "nuclei"
  );
}

// — Execute the Go binary (esbuild + Turbo pattern) —
// execFileSync inherits stdio and throws on non-zero exit.
// The thrown error's .status property contains the exit code.
try {
  execFileSync(getBinaryPath(), process.argv.slice(2), {
    stdio: "inherit",
    env: process.env,
  });
} catch (e) {
  // execFileSync throws for non-zero exit OR spawn failure.
  // Forward the child's exit code if available.
  if (e && e.status != null) {
    process.exit(e.status);
  }
  // Spawn failure (ENOENT, EACCES, etc.)
  if (e && e.code === "ENOENT") {
    console.error(`WAFtester: binary not found.`);
    console.error(`Try reinstalling: npm install @waftester/cli`);
  } else if (e && e.code === "EACCES") {
    console.error(`WAFtester: permission denied.`);
    console.error(`Try: chmod +x <binary path>`);
  } else {
    console.error(`WAFtester: ${(e && e.message) || e}`);
  }
  process.exit(1);
}
