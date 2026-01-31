# WAF Validation Test Suite

## Overview

Enterprise-grade security testing payloads specifically designed to validate nginx + ModSecurity WAF configurations. These tests ensure your WAF is properly configured, blocks malicious requests, and doesn't create false positives on legitimate traffic.

## Test Categories

### 1. `modsecurity-core.json` (15 payloads)
Tests for OWASP Core Rule Set (CRS) categories:
- CRS 941: Cross-Site Scripting (XSS)
- CRS 942: SQL Injection
- CRS 930: Local File Inclusion (LFI)
- CRS 934: Server-Side Request Forgery (SSRF)
- CRS 932: Remote Code Execution (RCE)
- CRS 931: XML External Entities (XXE)
- CRS 944: Server-Side Template Injection (SSTI)
- CRS 913: Scanner Detection

### 2. `custom-rules.json` (23 payloads)
Tests for custom ModSecurity rules (9999001-9999006):
- **9999001**: Path traversal patterns (`../`)
- **9999002**: Command injection (`; | \` $()`)
- **9999003**: Null bytes in webhooks (`%00`)
- **9999004**: Immich asset path traversal
- **9999005**: Static asset logging (skip logging)
- **9999006**: DNS rebinding / host header attacks

### 3. `bypass-techniques.json` (30 payloads)
Common WAF bypass techniques:
- Case variation (sElEcT, SCRIPT)
- URL encoding (single, double)
- Unicode encoding (fullwidth, homoglyphs)
- Null byte injection
- Comment insertion (SQL, HTML)
- HTTP Parameter Pollution
- Protocol handler abuse

### 4. `evasion-techniques.json` (30 payloads)
Advanced evasion techniques:
- Chunked transfer encoding
- Multiline header injection
- String concatenation
- Scientific notation
- Buffer overflow attempts
- Content-Length mismatch
- JSON/NoSQL injection
- Multipart form abuse
- Charset encoding tricks (UTF-7, overlong UTF-8)
- HTTP method override
- Path confusion
- Request smuggling

### 5. `owasp-top10.json` (26 payloads)
OWASP Top 10 2021 coverage:
- A01: Broken Access Control
- A02: Cryptographic Failures (info)
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Software Data Integrity
- A09: Logging Failures (Log4Shell)
- A10: SSRF

### 6. `regression-tests.json` (25 payloads)
Legitimate traffic validation (should NOT be blocked):
- API health checks
- Normal login requests
- Pagination queries
- Search with SQL-like words
- Apostrophe in names (O'Brien)
- HTML content in JSON
- Email addresses
- Code/formula content
- Service-specific endpoints (n8n, Immich, Authentik, AgreementPulse)

## Usage

### Quick Validation
```powershell
# Test WAF with quick profile
.\Run-SecurityTests.ps1 test -Quick -TargetUrl https://your-waf.example.com
```

### Full WAF Validation
```powershell
# Test all WAF validation payloads
.\Run-SecurityTests.ps1 test -Category WAF-Validation -TargetUrl https://your-waf.example.com
```

### Regression Testing
```powershell
# Ensure WAF doesn't block legitimate requests
.\Run-SecurityTests.ps1 test -Category Regression -TargetUrl https://your-waf.example.com
```

### OWASP Top 10 Coverage
```powershell
# Full OWASP Top 10 coverage test
.\Run-SecurityTests.ps1 test -Category OWASP-Top10 -TargetUrl https://your-waf.example.com
```

## Expected Results

### For Security Payloads
- **Expected**: HTTP 403 (Blocked)
- **Failure**: HTTP 200/other (WAF bypass)

### For Regression Tests
- **Expected**: HTTP 200 (Allowed)
- **Failure**: HTTP 403 (False positive)

## CI/CD Integration

Add to your pipeline:
```yaml
- name: WAF Validation
  run: |
    cd tests
    ./Run-SecurityTests.ps1 test -Category WAF-Validation -OutputFormat JUnit -OutputPath results.xml
    ./Run-SecurityTests.ps1 test -Category Regression -OutputFormat JUnit -OutputPath regression.xml
```

## Adding New Tests

### Payload Schema
```json
{
  "id": "UNIQUE-ID-001",
  "payload": "GET /path?param=<attack-vector>",
  "tags": ["category", "subcategory", "quick"],
  "expected_block": true,
  "severity_hint": "Critical|High|Medium|Low",
  "notes": "Description of what this tests",
  "category": "WAF-Validation|WAF-Bypass|Regression|OWASP-Top10"
}
```

### Naming Convention
- `CRS-{rule}-{variant}`: OWASP CRS rule tests
- `RULE-{id}-{variant}`: Custom rule tests
- `BYPASS-{technique}-{variant}`: Bypass technique tests
- `EVASION-{technique}-{variant}`: Evasion technique tests
- `OWASP-{category}-{variant}`: OWASP Top 10 tests
- `LEGIT-{service}-{variant}`: Regression/legitimate tests

## Coverage Matrix

| Attack Category | CRS Rules | Custom Rules | Bypass Tests | Total |
|-----------------|-----------|--------------|--------------|-------|
| SQL Injection   | 942       | -            | 8+           | 15+   |
| XSS             | 941       | -            | 6+           | 12+   |
| Path Traversal  | 930       | 9999001,4    | 4+           | 10+   |
| Command Injection| 932      | 9999002      | 4+           | 8+    |
| SSRF            | 934       | -            | 6+           | 10+   |
| XXE             | 931       | -            | 2+           | 4+    |
| SSTI            | 944       | -            | 2+           | 4+    |
| DNS Rebinding   | -         | 9999006      | 2+           | 4+    |
| Request Smuggling| -        | -            | 4+           | 4+    |

## Total Payload Count

- **modsecurity-core.json**: 15 payloads
- **custom-rules.json**: 23 payloads
- **bypass-techniques.json**: 30 payloads
- **evasion-techniques.json**: 30 payloads
- **owasp-top10.json**: 26 payloads
- **regression-tests.json**: 25 payloads

**Total: 149 enterprise-grade WAF validation payloads**
