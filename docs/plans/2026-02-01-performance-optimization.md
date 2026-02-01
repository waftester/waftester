# Performance Optimization Implementation Plan

> **For Copilot:** Follow this plan task-by-task using TDD discipline. Each task is designed to be safe, isolated, and easily reversible.

**Goal:** Improve WAFtester performance across all 5 dimensions: throughput, latency, memory efficiency, startup time, and CPU efficiency — without breaking existing functionality.

**Architecture:** Introduce a shared HTTP client pool, buffer pools via sync.Pool, lazy initialization patterns, and connection reuse optimizations. All changes are additive with fallback to existing behavior.

**Tech Stack:** Go stdlib (sync.Pool, sync.Once), existing pkg/runner and pkg/core infrastructure

**Safety Philosophy:** 
- Every change must be behind an interface allowing easy rollback
- Tests run after each task — if ANY fail, stop and investigate
- Changes affect internals only — no CLI flag or API changes
- Each phase is independently useful — can stop at any phase

---

## Phase 1: Shared HTTP Client Pool (HIGHEST IMPACT)

**Problem:** 50+ independent `http.Client` creations across the codebase. Each creates its own connection pool, causing:
- Wasted connections (no sharing between packages)
- Memory overhead (each transport maintains idle connections)
- Slower warmup (each package warms up independently)

**Solution:** Create a centralized HTTP client factory in a new `pkg/httpclient` package.

---

### Task 1.1: Create httpclient package with factory

**Files:**
- Create: `pkg/httpclient/httpclient.go`
- Create: `pkg/httpclient/httpclient_test.go`

**Step 1: Write the failing test**

```go
// pkg/httpclient/httpclient_test.go
package httpclient

import (
	"net/http"
	"testing"
	"time"
)

func TestDefaultClient_ReturnsHTTPClient(t *testing.T) {
	client := Default()
	if client == nil {
		t.Fatal("Default() returned nil")
	}
	if _, ok := interface{}(client).(*http.Client); !ok {
		t.Fatal("Default() did not return *http.Client")
	}
}

func TestDefaultClient_IsSingleton(t *testing.T) {
	c1 := Default()
	c2 := Default()
	if c1 != c2 {
		t.Error("Default() should return same instance")
	}
}

func TestNewClient_RespectsTimeout(t *testing.T) {
	client := New(Config{Timeout: 5 * time.Second})
	if client == nil {
		t.Fatal("New() returned nil")
	}
	if client.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", client.Timeout)
	}
}

func TestNewClient_RespectsInsecureSkipVerify(t *testing.T) {
	client := New(Config{InsecureSkipVerify: true})
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not set")
	}
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./pkg/httpclient/... -v
```
Expected: FAIL (package doesn't exist)

**Step 3: Write minimal implementation**

```go
// pkg/httpclient/httpclient.go
package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Config holds HTTP client configuration
type Config struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
	Proxy              string
	MaxIdleConns       int
	MaxConnsPerHost    int
	IdleConnTimeout    time.Duration
	DisableKeepAlives  bool
}

// DefaultConfig returns sensible defaults optimized for security scanning
func DefaultConfig() Config {
	return Config{
		Timeout:            30 * time.Second,
		InsecureSkipVerify: true, // Security scanners often need this
		MaxIdleConns:       100,
		MaxConnsPerHost:    25,
		IdleConnTimeout:    90 * time.Second,
		DisableKeepAlives:  false,
	}
}

var (
	defaultClient *http.Client
	defaultOnce   sync.Once
)

// Default returns a shared, pre-configured HTTP client
// Safe for concurrent use. Uses connection pooling.
func Default() *http.Client {
	defaultOnce.Do(func() {
		defaultClient = New(DefaultConfig())
	})
	return defaultClient
}

// New creates a new HTTP client with the given configuration
func New(cfg Config) *http.Client {
	// Apply defaults for zero values
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 100
	}
	if cfg.MaxConnsPerHost == 0 {
		cfg.MaxConnsPerHost = 25
	}
	if cfg.IdleConnTimeout == 0 {
		cfg.IdleConnTimeout = 90 * time.Second
	}

	transport := &http.Transport{
		// Connection pooling
		MaxIdleConns:        cfg.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.MaxConnsPerHost,
		MaxConnsPerHost:     cfg.MaxConnsPerHost,
		IdleConnTimeout:     cfg.IdleConnTimeout,
		DisableKeepAlives:   cfg.DisableKeepAlives,

		// Performance tuning
		ForceAttemptHTTP2:     true,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.Timeout,

		// Dialer with timeouts
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,

		// TLS
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
	}

	// Proxy support
	if cfg.Proxy != "" {
		if proxyURL, err := url.Parse(cfg.Proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./pkg/httpclient/... -v
```
Expected: PASS

**Step 5: Commit**

```bash
git add pkg/httpclient/
git commit -m "feat(httpclient): add shared HTTP client factory

- Singleton Default() for shared connection pooling
- Configurable New() for custom needs
- Optimized defaults for security scanning (25 conns/host, 90s idle)
- HTTP/2 enabled, proper timeouts, no redirect following"
```

---

### Task 1.2: Add benchmark tests for client factory

**Files:**
- Modify: `pkg/httpclient/httpclient_test.go`

**Step 1: Add benchmark tests**

```go
func BenchmarkDefaultClient(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Default()
	}
}

func BenchmarkNewClient(b *testing.B) {
	cfg := DefaultConfig()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = New(cfg)
	}
}
```

**Step 2: Run benchmarks to establish baseline**

```bash
go test ./pkg/httpclient/... -bench=. -benchmem
```

**Step 3: Commit**

```bash
git add pkg/httpclient/
git commit -m "test(httpclient): add allocation benchmarks"
```

---

## Phase 2: Buffer Pool (MEDIUM IMPACT)

**Problem:** `bytes.Buffer` and `strings.Builder` allocated repeatedly in hot paths.

**Solution:** Create `pkg/bufpool` with sync.Pool-backed buffer acquisition.

---

### Task 2.1: Create bufpool package

**Files:**
- Create: `pkg/bufpool/bufpool.go`
- Create: `pkg/bufpool/bufpool_test.go`

**Step 1: Write the failing test**

```go
// pkg/bufpool/bufpool_test.go
package bufpool

import (
	"bytes"
	"testing"
)

func TestGet_ReturnsBuffer(t *testing.T) {
	buf := Get()
	if buf == nil {
		t.Fatal("Get() returned nil")
	}
	defer Put(buf)
}

func TestGet_ReturnsEmptyBuffer(t *testing.T) {
	buf := Get()
	defer Put(buf)
	if buf.Len() != 0 {
		t.Errorf("Expected empty buffer, got len=%d", buf.Len())
	}
}

func TestPut_ResetsBuffer(t *testing.T) {
	buf := Get()
	buf.WriteString("test data")
	Put(buf)
	
	// Get another buffer - it should be reset
	buf2 := Get()
	defer Put(buf2)
	if buf2.Len() != 0 {
		t.Error("Buffer not reset after Put")
	}
}

func TestPool_ConcurrentSafe(t *testing.T) {
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			buf := Get()
			buf.WriteString("concurrent test")
			Put(buf)
			done <- true
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL (package doesn't exist)

**Step 3: Write minimal implementation**

```go
// pkg/bufpool/bufpool.go
package bufpool

import (
	"bytes"
	"sync"
)

// bufferPool is the global buffer pool
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Get retrieves a buffer from the pool
// The buffer is guaranteed to be empty
func Get() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// Put returns a buffer to the pool
// The buffer is reset before being returned
func Put(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	// Don't return huge buffers to pool (prevent memory bloat)
	if buf.Cap() > 64*1024 { // 64KB threshold
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
}

// GetSized retrieves a buffer with at least the given capacity
func GetSized(size int) *bytes.Buffer {
	buf := Get()
	buf.Grow(size)
	return buf
}
```

**Step 4: Run test to verify it passes**

```bash
go test ./pkg/bufpool/... -v
```

**Step 5: Commit**

```bash
git add pkg/bufpool/
git commit -m "feat(bufpool): add sync.Pool-backed buffer pool

- Get/Put for zero-alloc buffer reuse
- GetSized for pre-allocated buffers
- 64KB cap limit prevents memory bloat
- Concurrent-safe via sync.Pool"
```

---

### Task 2.2: Add benchmarks for buffer pool

**Files:**
- Modify: `pkg/bufpool/bufpool_test.go`

```go
func BenchmarkGet(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := Get()
		buf.WriteString("test data for benchmarking buffer pool performance")
		Put(buf)
	}
}

func BenchmarkNewBuffer(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := new(bytes.Buffer)
		buf.WriteString("test data for benchmarking buffer pool performance")
		_ = buf
	}
}
```

Run: `go test ./pkg/bufpool/... -bench=. -benchmem`

---

## Phase 3: Lazy Initialization (MEDIUM IMPACT)

**Problem:** Packages initialize resources at package load time or function entry even when not needed.

**Solution:** Use sync.Once for deferred initialization of heavy resources.

---

### Task 3.1: Add lazy init to pkg/waf/vendors

The WAF vendor signatures (197 vendors, ~2000 rules) load eagerly. Defer until first use.

**Files:**
- Modify: `pkg/waf/vendors/vendors.go`

**Step 1: Read current implementation**

```bash
# Read the initialization code to understand current pattern
```

**Step 2: Add sync.Once wrapper**

```go
var (
	vendorSignatures []VendorSignature
	signaturesOnce   sync.Once
)

func getSignatures() []VendorSignature {
	signaturesOnce.Do(func() {
		vendorSignatures = loadAllSignatures()
	})
	return vendorSignatures
}
```

**Safety:** Keep old direct access working as fallback.

---

## Phase 4: Connection Reuse in Core Executor (HIGH IMPACT)

**Problem:** pkg/core/executor.go creates optimal HTTP client but each Executor instance gets its own.

**Solution:** Allow executor to accept external HTTP client, defaulting to shared pool.

---

### Task 4.1: Update ExecutorConfig to accept shared client

**Files:**
- Modify: `pkg/core/executor.go`

The config already has `HTTPClient *http.Client` field. Ensure it falls back to shared Default() if nil.

---

## Phase 5: Response Body Streaming (MEDIUM IMPACT)

**Problem:** Many io.ReadAll calls load entire response bodies into memory.

**Solution:** For large responses, use io.LimitReader consistently (already in some places, needs standardization).

---

### Task 5.1: Audit and standardize io.ReadAll usage

**Files to audit:**
- All files with `io.ReadAll` without `io.LimitReader` wrapper

**Standard pattern:**
```go
body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
defer resp.Body.Close()
```

---

## Verification Checkpoints

After each phase:

1. **Run full test suite:**
   ```bash
   go test ./... -count=1
   ```
   Expected: ALL PASS (same as baseline)

2. **Run benchmarks:**
   ```bash
   go test ./pkg/httpclient/... ./pkg/bufpool/... -bench=. -benchmem
   ```
   Record results.

3. **Build check:**
   ```bash
   go build ./...
   ```
   Expected: No errors

4. **Memory profiling (optional):**
   ```bash
   go test -run=XXX -bench=BenchmarkScan -memprofile=mem.out ./cmd/cli/
   go tool pprof mem.out
   ```

---

## Rollback Plan

Each phase is isolated. If issues found:

1. **Phase 1 (httpclient):** Packages can still create their own clients
2. **Phase 2 (bufpool):** Pool usage is opt-in, old code still works
3. **Phase 3 (lazy init):** Can revert sync.Once to eager init
4. **Phase 4 (core):** HTTPClient field is optional
5. **Phase 5 (streaming):** Already mostly using io.LimitReader

---

## Success Metrics

| Metric | Current (Baseline) | Target |
|--------|-------------------|--------|
| Startup time | TBD | -20% |
| Memory per 1000 requests | TBD | -30% |
| Allocations per request | TBD | -40% |
| RPS on benchmark | TBD | +15% |

---

## Execution Order

1. ✅ Create branch: `perf/comprehensive-optimization`
2. ⬜ Task 1.1: Create httpclient package
3. ⬜ Task 1.2: Add httpclient benchmarks
4. ⬜ Task 2.1: Create bufpool package
5. ⬜ Task 2.2: Add bufpool benchmarks
6. ⬜ Task 3.1: Add lazy init to vendors
7. ⬜ Task 4.1: Update core executor
8. ⬜ Task 5.1: Audit io.ReadAll usage
9. ⬜ Final verification
10. ⬜ Commit and prepare for merge

---

**Total estimated time:** 2-3 hours with careful verification between steps.
