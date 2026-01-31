# Mutation Engine

The mutation engine provides comprehensive payload transformation capabilities for WAF bypass testing. It uses a plugin-based architecture with self-registering mutators organized into four categories.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Mutation Registry                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐│
│  │  Encoders   │ │  Locations  │ │  Evasions   │ │Protocol ││
│  │    (18)     │ │    (13)     │ │    (10)     │ │   (8)   ││
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘│
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Pipeline Executor                         │
│  payload → encode → place in location → apply evasion →     │
│           → protocol mutation → output                       │
└─────────────────────────────────────────────────────────────┘
```

## Mutator Categories

### Encoders (18 mutators)
Transform payload encoding to bypass pattern matching:

| Mutator | Description |
|---------|-------------|
| `raw` | Original payload unchanged |
| `url` | URL encoding (%xx) |
| `double_url` | Double URL encoding (%25xx) |
| `triple_url` | Triple URL encoding (%2525xx) |
| `html_decimal` | HTML decimal entities (`&#60;` for `<`) |
| `html_hex` | HTML hex entities (`&#x3c;`) |
| `html_named` | Named entities (`&lt;`) |
| `unicode` | Unicode escapes (\uXXXX) |
| `utf7` | UTF-7 encoding (+ADw-) |
| `utf16le` | UTF-16 Little Endian |
| `utf16be` | UTF-16 Big Endian |
| `overlong_utf8` | Overlong UTF-8 sequences (%c0%bc) |
| `wide_gbk` | GBK wide-byte injection (%bf%27) |
| `wide_sjis` | SJIS wide-byte injection |
| `base64` | Base64 encoding |
| `hex` | Hex encoding |
| `octal` | Octal encoding |
| `mixed` | Random mix of encodings |

### Locations (13 mutators)
Place payloads in different HTTP request parts:

| Mutator | Description |
|---------|-------------|
| `query_param` | URL query string (?param=payload) |
| `post_form` | Form body (param=payload) |
| `post_json` | JSON body ({"key":"payload"}) |
| `post_xml` | XML body |
| `header_xforward` | X-Forwarded-For header |
| `header_referer` | Referer header |
| `header_useragent` | User-Agent header |
| `header_custom` | Custom headers |
| `cookie` | Cookie header |
| `path_segment` | URL path (/path/payload/rest) |
| `multipart` | Multipart form data |
| `fragment` | URL fragment (#payload) |
| `matrix_param` | Matrix parameters (;param=payload) |

### Evasions (10 mutators)
Apply obfuscation techniques:

| Mutator | Description |
|---------|-------------|
| `case_swap` | Mixed case (SeLeCt) |
| `sql_comment` | SQL comments (SEL/**/ECT) |
| `whitespace_alt` | Alternative whitespace (tabs, %0a) |
| `null_byte` | Null byte injection (%00) |
| `hpp` | HTTP Parameter Pollution |
| `chunked` | Chunked transfer encoding |
| `unicode_norm` | Unicode normalization |
| `comment_wrap` | Comment wrapping |
| `concat` | String concatenation |
| `newline` | Newline injection |

### Protocol (8 mutators)
HTTP protocol-level attacks:

| Mutator | Description |
|---------|-------------|
| `smuggle_clte` | CL.TE request smuggling |
| `smuggle_tecl` | TE.CL request smuggling |
| `smuggle_tete` | TE.TE obfuscation |
| `h2_downgrade` | HTTP/2 to HTTP/1.1 downgrade |
| `websocket` | WebSocket upgrade attacks |
| `request_line` | Request line manipulation |
| `header_fold` | Header folding |
| `te_obfuscate` | Transfer-Encoding obfuscation |

## Usage

### CLI Commands

#### View Available Mutators
```bash
# Show statistics
waf-tester mutate -stats

# List all mutators
waf-tester mutate -list

# Filter by category
waf-tester mutate -list -category encoder
```

#### Generate Mutations
```bash
# Mutate all payloads
waf-tester mutate -payloads payloads/sqli/ -output mutations.json

# Specific encodings only
waf-tester mutate -payloads payloads/xss/ -encoders url,double_url,html_hex

# With evasion techniques
waf-tester mutate -payloads payloads/ -evasions case_swap,sql_comment

# Dry run (show count without generating)
waf-tester mutate -payloads payloads/ -dry-run
```

#### Full Bypass Testing
```bash
# Test WAF with mutations
waf-tester bypass -target https://example.com -payloads payloads/sqli/ -full

# Quick test (default mutators)
waf-tester bypass -target https://example.com -payloads payloads/xss/

# Specific mutations
waf-tester bypass -target https://example.com -payloads payloads/ \
  -encoders url,double_url \
  -locations query_param,post_json \
  -evasions case_swap
```

### Programmatic API

```go
import (
    "github.com/waftester/waftester/pkg/mutation"
    _ "github.com/waftester/waftester/pkg/mutation/encoder"
    _ "github.com/waftester/waftester/pkg/mutation/location"
    _ "github.com/waftester/waftester/pkg/mutation/evasion"
    _ "github.com/waftester/waftester/pkg/mutation/protocol"
)

// Get default registry (auto-populated via init())
registry := mutation.DefaultRegistry

// List all mutators
for _, name := range registry.Names() {
    fmt.Println(name)
}

// Get mutators by category
encoders := registry.GetByCategory("encoder")
locations := registry.GetByCategory("location")
evasions := registry.GetByCategory("evasion")
protocols := registry.GetByCategory("protocol")

// Apply single mutator
urlEncoder := encoders[0] // or find by name
results := urlEncoder.Mutate("' OR 1=1--")
for _, r := range results {
    fmt.Printf("Original: %s, Mutated: %s\n", r.Original, r.Mutated)
}

// Apply all mutators
allMutations := registry.MutateWithAll("payload")

// Chain mutators (encode then evade)
chained := registry.ChainMutate("payload", []string{"url", "case_swap"})
```

### Pipeline Configuration

```go
// Default configuration (fast)
cfg := mutation.DefaultPipelineConfig()
// Encoders: all, Locations: query_param/post_form/post_json
// Evasions: none, ChainEncodings: false

// Full coverage configuration
cfg := mutation.FullCoveragePipelineConfig()
// All 49 mutators enabled, chaining enabled

// Custom configuration
cfg := &mutation.PipelineConfig{
    Encoders:       []string{"url", "double_url", "html_hex"},
    Locations:      []string{"query_param", "post_json", "header_xforward"},
    Evasions:       []string{"case_swap", "sql_comment"},
    ChainEncodings: true,
    MaxChainDepth:  3,
    IncludeRaw:     true,
}
```

## Adding Custom Mutators

Create a new mutator by implementing the `Mutator` interface:

```go
package custom

import "github.com/waftester/waftester/pkg/mutation"

type MyEncoder struct{}

func (e *MyEncoder) Name() string        { return "my_encoder" }
func (e *MyEncoder) Category() string    { return "encoder" }
func (e *MyEncoder) Description() string { return "My custom encoding" }

func (e *MyEncoder) Mutate(payload string) []mutation.MutatedPayload {
    return []mutation.MutatedPayload{{
        Original:    payload,
        Mutated:     customTransform(payload),
        MutatorName: e.Name(),
        Category:    e.Category(),
    }}
}

func init() {
    mutation.DefaultRegistry.Register(&MyEncoder{})
}
```

## MutatedPayload Structure

```go
type MutatedPayload struct {
    Original    string   // Original input
    Mutated     string   // Transformed output
    MutatorName string   // Name of mutator that produced this
    Category    string   // encoder, location, evasion, protocol
    Chain       []string // Mutator chain (for chained mutations)
}
```

## Performance

| Mode | Payloads | Mutations | Time |
|------|----------|-----------|------|
| Default (3 locations, all encoders) | 100 | ~5,400 | <1s |
| Full coverage (all 49 mutators) | 100 | ~490,000 | ~5s |
| Full + chaining (depth 3) | 100 | ~10M+ | ~1min |

Use `-dry-run` to estimate mutation count before generating.

## Testing

```bash
# Run all mutation tests
go test ./pkg/mutation/... -v

# Test specific category
go test ./pkg/mutation/encoder/... -v
```

## Related Files

- `pkg/mutation/registry.go` - Core registry and pipeline
- `pkg/mutation/executor.go` - Execution engine
- `pkg/mutation/encoder/` - Encoding mutators
- `pkg/mutation/location/` - Location mutators
- `pkg/mutation/evasion/` - Evasion mutators
- `pkg/mutation/protocol/` - Protocol mutators
- `cmd/waf-tester/mutate.go` - CLI mutate command
- `cmd/waf-tester/bypass.go` - CLI bypass command
