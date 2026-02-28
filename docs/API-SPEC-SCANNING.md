# API Spec Scanning

> Document Version: 2.8.9

WAFtester can drive security scans from API specifications instead of blind URL fuzzing. Provide an OpenAPI, Swagger, Postman, HAR, GraphQL, gRPC, or AsyncAPI spec and WAFtester generates targeted attacks against every documented endpoint, parameter, and schema constraint.

## Supported Formats

| Format | Extensions | Detection |
|--------|-----------|-----------|
| OpenAPI 3.x | `.yaml`, `.json` | `openapi:` key |
| Swagger 2.0 | `.yaml`, `.json` | `swagger:` key |
| Postman Collection v2.x | `.json` | `info.schema` URL |
| HAR 1.2 | `.har`, `.json` | `log.version` key |
| GraphQL | Introspection | `__schema` response |
| gRPC | Reflection | gRPC reflection API |
| AsyncAPI 2.x | `.yaml`, `.json` | `asyncapi:` key |

## Quick Start

```bash
# Scan from OpenAPI spec (target derived from spec's servers/host field)
waftester scan --spec openapi.yaml

# Explicit target overrides spec's server URL
waftester scan --spec openapi.yaml -u https://api.example.com

# Auto mode with Postman collection + environment
waftester auto --spec collection.json --spec-env environment.json

# Dry-run to preview the scan plan without sending requests
waftester scan --spec openapi.yaml --dry-run

# Validate a spec without scanning
waftester validate --spec openapi.yaml

# Scan specific endpoint groups only
waftester scan --spec openapi.yaml -u https://api.example.com --groups users,auth
```

> **Note:** The `-u` flag is optional when the spec contains server URLs (OpenAPI `servers`, Swagger `host`, Postman `baseUrl`). WAFtester resolves the target from the spec automatically. Use `-u` to override.

## How It Works

1. **Parse** — WAFtester reads the spec and extracts endpoints, parameters, request bodies, and schema constraints.
2. **Plan** — The intelligence engine generates a scan plan: which endpoints to test, which attack categories apply, which parameters to inject into, and in what order.
3. **Execute** — Requests are sent with adaptive rate limiting, WAF detection, and escalation. Each request carries an `X-Correlation-ID` header for log matching.
4. **Report** — Results are grouped by endpoint and include schema-aware context (what the spec says vs. what happened).

## Scan Plan

The scan plan is the ordered list of test cases. View it before scanning:

```bash
# Show the plan as a table
waftester scan --spec openapi.yaml --dry-run

# Export the plan as JSON for CI/CD pipelines
waftester scan --spec openapi.yaml --dry-run -format json
```

Each plan entry includes:
- **Endpoint** — method + path (e.g., `POST /api/users`)
- **Attack category** — sqli, xss, ssti, etc.
- **Injection target** — which parameter or body field
- **Priority** — derived from endpoint sensitivity (auth endpoints first, public read-only last)

### Priority and Ordering

Endpoints are prioritized by authentication impact, data sensitivity, and write operations:

| Priority | Criteria | Examples |
|----------|----------|---------|
| Critical | Auth endpoints, admin paths | `POST /login`, `PUT /admin/config` |
| High | Write operations with body params | `POST /users`, `PUT /orders/{id}` |
| Medium | Read with query params | `GET /search?q=`, `GET /users/{id}` |
| Low | Read-only, no params | `GET /health`, `GET /version` |

## Intelligence Engine

The intelligence engine selects attacks based on spec metadata:

| Signal | Attack Selection |
|--------|-----------------|
| `format: email` | Email header injection, SSTI in email templates |
| `format: uri` | SSRF, open redirect |
| `format: date` / `format: date-time` | Format string attacks |
| `type: integer` with `minimum`/`maximum` | Boundary value attacks, integer overflow |
| `pattern: regex` | ReDoS, regex bypass |
| Content-Type `multipart/form-data` | File upload attacks, path traversal in filenames |
| `in: header` | Header injection, CRLF |
| Path with `{id}` | IDOR with ID manipulation |

### Schema Constraint Attacks

When the spec defines constraints (`minLength`, `maxLength`, `minimum`, `maximum`, `pattern`, `enum`), WAFtester generates attacks that violate those constraints:

```bash
# The spec says: name: { type: string, maxLength: 50 }
# WAFtester sends: a 51-char payload, a 10000-char payload, boundary values

# The spec says: age: { type: integer, minimum: 0, maximum: 150 }
# WAFtester sends: -1, 151, 0, 150, MAX_INT, negative overflow
```

### Content-Type Mutation

WAFtester probes endpoints with unexpected content types to find parsing bypasses:

- `application/json` → `application/xml`, `text/plain`, `application/x-www-form-urlencoded`
- `multipart/form-data` → `application/json`, `application/octet-stream`
- Missing `Content-Type` header entirely

### Method Confusion

For each documented endpoint, WAFtester also tries undocumented HTTP methods:

```
# Spec documents: GET /users, POST /users
# WAFtester also tries: PUT /users, DELETE /users, PATCH /users, OPTIONS /users
# Plus method override headers: X-HTTP-Method-Override, X-Method-Override
```

## Validation

Validate a spec file without running a scan:

```bash
# Validate from file
waftester validate --spec openapi.yaml

# Validate from URL
waftester validate --spec-url https://api.example.com/openapi.yaml

# Allow internal/private network server URLs
waftester validate --spec openapi.yaml --allow-internal

# JSON output for CI pipelines
waftester validate --spec openapi.yaml -format json

# Verbose: list all parsed endpoints
waftester validate --spec openapi.yaml -v
```

The validator checks for parse errors, schema warnings, endpoint extraction, and server URL reachability.

## Comparison Mode

Compare scan results against a saved baseline to track regressions:

```bash
# Save a baseline
waftester scan --spec openapi.yaml -u https://api.example.com -format json -o baseline.json

# Run a new scan
waftester scan --spec openapi.yaml -u https://api.example.com -format json -o current.json

# Compare the two results
waftester compare baseline.json current.json
```

The comparison report shows severity deltas, new/fixed categories, WAF vendor changes, and a severity-weighted verdict. Exits with code 1 on regression for CI/CD gating.

## Correlation IDs

Every HTTP request includes an `X-Correlation-ID` header for matching WAFtester requests against WAF logs:

```
X-Correlation-ID: waftester-a3f8c21e-post-users-sqli-body.email-0042
```

Format: `waftester-{session}-{endpoint}-{attack}-{param}-{seq}`

Export all correlation records:

```bash
waftester scan --spec openapi.yaml -u https://api.example.com --export-correlations correlations.json
```

Each record includes: session ID, correlation ID, endpoint tag, attack category, injection point, payload hash (not plaintext), blocked status, and WAF response.

## Checkpointing and Resume

Long scans can be resumed after interruption:

```bash
# Start a scan (checkpoints are saved automatically)
waftester scan --spec openapi.yaml -u https://api.example.com

# Resume after interruption
waftester scan --spec openapi.yaml -u https://api.example.com --resume
```

Checkpoint data is stored in `~/.waftester/checkpoints/` and includes completed endpoints, findings so far, and the scan plan hash for validation.

## Format-Specific Examples

### OpenAPI 3.x

```bash
waftester scan --spec openapi.yaml -u https://api.example.com
waftester scan --spec openapi.json -u https://api.example.com --groups users
```

### Swagger 2.0

```bash
waftester scan --spec swagger.json -u https://api.example.com
```

### Postman Collection

```bash
# Collection only
waftester scan --spec collection.json -u https://api.example.com

# Collection with environment variables
waftester auto --spec collection.json --spec-env production.json -u https://api.example.com
```

Postman environment variables (`{{baseUrl}}`, `{{apiKey}}`) are substituted before parsing.

### HAR (HTTP Archive)

```bash
# Recorded browser session
waftester scan --spec recording.har -u https://api.example.com
```

HAR files captured from browser DevTools or Burp Suite are parsed into endpoint definitions.

### GraphQL

```bash
# Introspection-based scanning
waftester scan -u https://api.example.com/graphql -types graphql
```

GraphQL introspection extracts queries, mutations, and input types.

### gRPC

```bash
# Reflection-based scanning
waftester scan -u grpc://service:50051 -types grpc
```

gRPC reflection extracts services, methods, and message types.

## MCP Tools

The MCP server exposes spec scanning tools for AI agent integration. Tools accept spec input via `spec_content` (inline), `spec_path` (file path), or `spec_url` (HTTP URL) — provide exactly one.

| Tool | Purpose |
|------|--------|
| `validate_spec` | Parse and validate a spec without scanning |
| `list_spec_endpoints` | Extract and list all endpoints from a spec |
| `plan_spec` | Generate a scan plan from a spec |
| `scan_spec` | Execute a spec-driven scan |
| `preview_spec_scan` | Preview scan configuration without executing |
| `spec_intelligence` | Analyze attack surface and recommended scan types |
| `describe_spec_auth` | Extract authentication schemes and per-endpoint requirements |
| `export_spec` | Export normalized internal representation |
| `compare_baselines` | Diff two sets of findings for regressions |

```bash
# Start MCP server
waftester mcp

# Or over HTTP
waftester mcp --http :8080
```

## CI/CD Integration

### GitHub Actions

```yaml
- uses: waftester/waftester-action@v1
  with:
    target: https://api.example.com
    spec: openapi.yaml
    format: sarif
    output: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  image: qandil/waftester:latest
  script:
    - waftester scan --spec openapi.yaml -u $API_URL -format junit -o results.xml
  artifacts:
    reports:
      junit: results.xml
```

## Troubleshooting

### "no endpoints found"

The spec parsed but contains no testable endpoints. Check:
- OpenAPI: `paths` section is not empty
- Postman: collection has at least one request
- HAR: log entries exist with URLs

### "format not recognized"

WAFtester could not detect the spec format. Ensure the file is valid YAML or JSON and contains format-specific markers (`openapi:`, `swagger:`, `info.schema`, `log.version`).

### "resume validation failed"

The spec or scan plan changed since the checkpoint was saved. Delete the checkpoint and restart:

```bash
rm -rf ~/.waftester/checkpoints/
waftester scan --spec openapi.yaml -u https://api.example.com
```
