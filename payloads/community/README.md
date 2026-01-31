# Community Payloads

Free, open-source attack payloads for WAF testing. Licensed under MIT.

## Categories

| Category | Description | Files |
|----------|-------------|-------|
| `auth/` | Authentication bypass payloads | JWT, OAuth, session attacks |
| `injection/` | SQL, NoSQL, Command injection | SQLi, CMDi, LDAP |
| `traversal/` | Path traversal attacks | LFI, directory traversal |
| `xss/` | Cross-site scripting | Reflected, stored, DOM XSS |

## Usage

```bash
# Run all community payloads
waftester -u https://example.com -payloads community

# Run specific category
waftester -u https://example.com -payloads community/xss
```

## Contributing

We welcome payload contributions! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

### Payload Format

```json
{
  "id": "unique-id",
  "name": "Human readable name",
  "category": "xss|sqli|injection|traversal|auth",
  "payload": "actual attack string",
  "encoding": "none|url|base64|html",
  "expected_block": true,
  "cwe": "CWE-79",
  "severity": "high|medium|low"
}
```

## License

MIT - See [LICENSE-COMMUNITY](../../LICENSE-COMMUNITY)
