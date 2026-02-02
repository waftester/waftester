# WAFtester

<p align="center">
  <strong>The WAF testing tool that security professionals actually use.</strong><br>
  Detect. Fingerprint. Bypass. Assess. Report. — All in one command.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSL%201.1-blue.svg" alt="License"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.22+-00ADD8.svg" alt="Go"></a>
  <a href="https://github.com/waftester/waftester/releases"><img src="https://img.shields.io/github/v/release/waftester/waftester" alt="Release"></a>
</p>

---

## One Command. Full Assessment.

```bash
waf-tester auto -u https://target.com --smart
```

That's it. WAFtester discovers endpoints, identifies the WAF vendor, selects optimal bypass techniques, runs 2,800+ payloads, and generates a quantitative security report — automatically.

**No YAML templates to write. No signature updates to download. No manual chaining of tools.**

---

## What Makes WAFtester Different

### vs. Manual Testing with sqlmap + wafw00f + nuclei

| You'd normally do... | WAFtester does... |
|---------------------|-------------------|
| Run wafw00f to detect WAF | Integrated: 197 vendor signatures |
| Manually pick sqlmap tampers | Auto-selects from 70+ tampers based on detected WAF |
| Write nuclei templates per vulnerability | 2,800+ payloads across 50+ categories, built-in |
| Parse outputs and correlate manually | Unified JSON/SARIF/HTML with metrics |
| Repeat for GraphQL, gRPC, WebSocket | Native multi-protocol support |

### What you get that other tools don't

| Feature | sqlmap | nuclei | Burp | WAFtester |
|---------|--------|--------|------|-----------|
| WAF-aware tamper selection | Manual | N/A | Manual | Automatic |
| False positive measurement | No | No | Limited | Full (FPR, precision) |
| Statistical metrics (MCC, F1) | No | No | No | Yes |
| Multi-protocol (GraphQL, gRPC) | No | Limited | Yes | Native |
| Mutation engine | 60 tampers | N/A | Intruder | 49 mutators × payloads |
| CI/CD native (SARIF, streaming) | No | Yes | No | Yes |

---

## Install in Seconds

```bash
go install github.com/waftester/waftester/cmd/cli@latest
```

Or: `brew install waftester` | `docker pull ghcr.io/waftester/waftester`

---

## See It In Action

### Detect the WAF — Know What You're Attacking

```
$ waf-tester vendor -u https://protected.example.com

WAF Detection Results
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Vendor         Cloudflare
  Confidence     98%
  Evidence       cf-ray header, __cfduid cookie, 1020 error page
  
Recommended tampers for Cloudflare:
  charunicodeencode, space2morecomment, randomcase
```

### Find Bypasses — Automatically

```
$ waf-tester bypass -u https://target.com --smart --tamper-auto

Bypass Discovery
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Payload Variants Tested     2,847
  Blocked by WAF              2,728 (95.8%)
  Bypassed WAF                119 (4.2%)
  
Top Bypass Chains:
  1. charunicodeencode + space2morecomment    (42 bypasses)
  2. modsecurityversioned + randomcase        (31 bypasses)  
  3. between + equaltolike                    (19 bypasses)

Bypass evidence exported to: bypasses.json
```

### Quantitative Assessment — Numbers That Matter

```
$ waf-tester assess -u https://target.com -fp -o assessment.json

Enterprise WAF Assessment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Metric                  Score
  ─────────────────────────────
  Detection Rate (TPR)    94.2%
  False Positive Rate     0.3%
  Precision               99.7%
  Recall                  94.2%
  F1 Score                0.969
  MCC                     0.942

Payload Categories: sqli, xss, traversal, rce, ssrf, xxe
Benign Corpus:       1,200 requests (Leipzig + builtin)
```

---

## Power Features

### WAF Intelligence Matrix

Stop guessing which tampers work. WAFtester maintains a tested matrix:

```
$ waf-tester tampers --for-waf=cloudflare

Tampers Ranked by Effectiveness for Cloudflare
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  #  TAMPER                    SUCCESS RATE
  1  charunicodeencode         ████████░░ 85%
  2  space2morecomment         ████████░░ 82%
  3  randomcase                ███████░░░ 75%
  4  between                   ██████░░░░ 68%
  5  modsecurityversioned      █████░░░░░ 55%
```

16+ WAF vendors mapped: Cloudflare, AWS WAF, Akamai, Imperva, Azure WAF, F5, Fortinet, ModSecurity, Barracuda, Sucuri, Radware, Citrix ADC, Palo Alto, Sophos, Wallarm, and more.

### Multi-Protocol Native

```bash
# HTTP endpoints
waf-tester scan -u https://api.example.com

# GraphQL introspection + injection
waf-tester scan -u https://api.example.com/graphql -types graphql

# gRPC reflection + message fuzzing  
waf-tester scan -u grpc://service:50051 -types grpc

# SOAP/WSDL enumeration + XXE
waf-tester scan -u https://api.example.com/service.wsdl -types soap

# WebSocket message injection
waf-tester scan -u wss://api.example.com/socket -types websocket
```

### Mutation Engine (Not Just Static Payloads)

49 mutators × 2,800 payloads = comprehensive coverage:

```bash
# Generate 490,000+ variants from base payloads
waf-tester mutate -payloads payloads/sqli/ -full

# Targeted bypass attempts
waf-tester bypass -u https://target.com \
  -encoders url,double_url,unicode,hex \
  -evasions case_swap,sql_comment,whitespace \
  -locations query,body,headers
```

### Structured JSON Output

Every finding is machine-readable. No parsing nightmares:

```json
{
  "finding": {
    "id": "sqli-001",
    "type": "sql_injection",
    "severity": "Critical",
    "confidence": 0.95,
    "url": "https://target.com/api/users",
    "parameter": "id",
    "payload": "1' OR '1'='1",
    "tampers_used": ["charunicodeencode", "space2comment"],
    "waf_bypassed": true,
    "evidence": {
      "request": "GET /api/users?id=1%27%20OR...",
      "response_code": 200,
      "response_time_ms": 847,
      "indicators": ["SQL syntax in response", "5 rows returned vs 1 expected"]
    }
  },
  "context": {
    "waf_vendor": "Cloudflare",
    "waf_confidence": 0.98,
    "scan_id": "a1b2c3d4",
    "timestamp": "2026-02-02T14:23:01Z"
  }
}
```

**Real problems this solves:**

| Problem | How JSON Output Fixes It |
|---------|-------------------------|
| "Which findings are real vs noise?" | `confidence` score + `evidence` block with proof |
| "Did we actually bypass the WAF?" | `waf_bypassed` boolean + `tampers_used` array |
| "What exactly was sent/received?" | Full `request`/`response` in evidence |
| "How do I correlate across scans?" | `scan_id` + `timestamp` for tracking |
| "My SIEM can't parse this" | Flat JSON, one finding per line with `-stream` |

### CI/CD Integration

```bash
# Stream findings as they happen (JSONL format)
waf-tester scan -u $TARGET -stream -json | \
  jq 'select(.severity == "Critical")'

# GitHub Security tab (SARIF)
waf-tester scan -u $TARGET -format sarif -o results.sarif

# Fail pipeline on critical findings
waf-tester scan -u $TARGET -json | \
  jq -e '[.vulnerabilities[] | select(.severity=="Critical")] | length == 0'

# Slack/Teams webhook on bypass found
waf-tester bypass -u $TARGET -json | \
  jq 'select(.waf_bypassed==true)' | \
  while read finding; do curl -X POST $WEBHOOK -d "$finding"; done

# Aggregate metrics for dashboards
waf-tester assess -u $TARGET -json | \
  jq '{tpr: .metrics.detection_rate, fpr: .metrics.false_positive_rate, f1: .metrics.f1_score}'
```

**Output formats for every workflow:**

| Format | Use Case | Flag |
|--------|----------|------|
| JSON | Automation, APIs, scripting | `-json` or `-format json` |
| JSONL | Streaming, real-time processing | `-stream -json` |
| SARIF | GitHub/GitLab Security, VS Code | `-format sarif` |
| HTML | Reports for stakeholders | `-format html` |
| CSV | Excel, data analysis | `-format csv` |
| Markdown | Documentation, wikis | `-format md` |

---

## Full Command Reference

| Command | What It Does | Example |
|---------|--------------|---------|
| `auto` | Complete automated assessment | `waf-tester auto -u https://target.com` |
| `scan` | Vulnerability scanning (50+ categories) | `waf-tester scan -u https://target.com -types sqli,xss` |
| `bypass` | WAF bypass discovery | `waf-tester bypass -u https://target.com --smart` |
| `assess` | Enterprise metrics (F1, MCC, FPR) | `waf-tester assess -u https://target.com -fp` |
| `tampers` | List/test/recommend tampers | `waf-tester tampers --for-waf=cloudflare` |
| `vendor` | WAF fingerprinting (197 signatures) | `waf-tester vendor -u https://target.com` |
| `probe` | Protocol detection (httpx-compatible) | `waf-tester probe -l urls.txt` |
| `fuzz` | Directory/content fuzzing (ffuf-compatible) | `waf-tester fuzz -u https://target.com/FUZZ` |
| `smuggle` | HTTP request smuggling detection | `waf-tester smuggle -u https://target.com` |
| `race` | Race condition testing | `waf-tester race -u https://target.com/checkout` |
| `discover` | Endpoint crawling | `waf-tester discover -u https://target.com` |
| `workflow` | YAML workflow execution | `waf-tester workflow -f recon.yaml` |

---

## Key Options

| Flag | Purpose | Default |
|------|---------|---------|
| `-u` | Target URL | required |
| `-l` | File with targets (one per line) | - |
| `-c` | Concurrent workers | 25 |
| `-rl` | Rate limit (requests/second) | 150 |
| `--smart` | WAF-aware adaptive mode | false |
| `--tamper` | Tamper list (comma-separated) | - |
| `--tamper-auto` | Auto-select for detected WAF | false |
| `--tamper-profile` | Preset: stealth, standard, aggressive, bypass | - |
| `-format` | Output: json, sarif, html, csv, md | json |
| `-o` | Output file | - |
| `-x` | Proxy (HTTP/SOCKS5) | - |
| `-H` | Custom headers | - |
| `-types` | Test categories | all |

---

## The Numbers

| Metric | Value |
|--------|-------|
| WAF signatures | 197 vendors |
| Attack payloads | 2,800+ |
| Tamper scripts | 70+ |
| Mutator functions | 49 |
| Attack categories | 50+ (SQLi, XSS, RCE, SSRF, XXE, traversal...) |
| Protocols | HTTP, GraphQL, gRPC, SOAP, WebSocket |
| Output formats | JSON, SARIF, HTML, CSV, Markdown |

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Examples Guide](docs/EXAMPLES.md) | 2,200+ lines of usage examples |
| [Installation](docs/INSTALLATION.md) | All installation methods |
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history |
| [Security](SECURITY.md) | Security policy |

---

## License

**Core:** [Business Source License 1.1](LICENSE) (Apache 2.0 after Jan 31, 2030)  
**Community Payloads:** [MIT](LICENSE-COMMUNITY)
