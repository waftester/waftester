# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.5.x   | :white_check_mark: |
| 2.4.x   | :white_check_mark: |
| 2.3.x   | :warning: Security fixes only |
| 2.0.x - 2.2.x | :x: |
| 1.x.x   | :x:                |
| < 1.0   | :x:                |

**Current stable release: 2.5.2**

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
