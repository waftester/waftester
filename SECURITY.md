# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.9.x   | :white_check_mark: |
| 2.8.x   | :white_check_mark: |
| 2.7.x   | :white_check_mark: |
| 2.6.x   | :white_check_mark: |
| 2.5.x   | :warning: Security fixes only |
| 2.4.x   | :x: |
| 2.3.x   | :x: |
| 2.0.x - 2.2.x | :x: |
| 1.x.x   | :x:                |
| < 1.0   | :x:                |

**Current stable release: 2.9.31**

## Reporting a Vulnerability

We take security seriously at WAFtester. If you discover a security vulnerability, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email us at: **security@waftester.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Regular updates** on progress
- **Credit** in the security advisory (unless you prefer anonymity)

### Scope

In scope:
- WAFtester CLI vulnerabilities
- Authentication/authorization bypasses
- Injection vulnerabilities
- Information disclosure
- Denial of service

Out of scope:
- Vulnerabilities in dependencies (report to upstream)
- Social engineering attacks
- Physical security

## Security Best Practices

When using WAFtester:

1. **Never commit license keys** - Use environment variables
2. **Scan only authorized targets** - Get written permission
3. **Protect scan results** - May contain sensitive findings
4. **Keep updated** - Run `waftester update` regularly

## Spec File Security

When scanning from API specifications (`--spec`), WAFtester applies these protections:

### SSRF Prevention

Server URLs extracted from specs (OpenAPI `servers`, Postman `baseUrl`) are validated against a blocklist of internal addresses. Private IPs (`10.x`, `172.16-31.x`, `192.168.x`), loopback (`127.0.0.1`, `::1`), link-local, and metadata endpoints (`169.254.169.254`) are blocked by default.

To explicitly allow internal targets (e.g., staging environments):

```bash
waftester scan --spec openapi.yaml -u https://internal-api.local --allow-internal
```

### $ref Path Traversal

JSON `$ref` references in OpenAPI specs are resolved with path traversal prevention. References like `../../etc/passwd` or absolute file paths are rejected. Only same-document references (`#/components/schemas/User`) and relative sibling references are allowed.

### Credential Detection

Specs are scanned for credential-like patterns before processing. If API keys, tokens, or passwords appear in default values, example fields, or server variables, WAFtester warns and redacts them from correlation records. Payloads are stored as SHA-256 hashes, never as plaintext.

### Variable Injection

Postman environment variables and OpenAPI server variables are validated before substitution. Variable values containing injection characters (`{{`, `}}`, control characters) are rejected.
