package tampers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTamper is a simple tamper for testing
type mockTamper struct {
	BaseTamper
	transformFunc func(string) string
}

func (m *mockTamper) Transform(payload string) string {
	if m.transformFunc != nil {
		return m.transformFunc(payload)
	}
	return payload + "_transformed"
}

func newMockTamper(name string, category Category, priority Priority, tags ...string) *mockTamper {
	return &mockTamper{
		BaseTamper: NewBaseTamper(name, "Mock tamper for testing", category, priority, tags...),
	}
}

// saveRegistry saves the current registry and returns a restore function
func saveRegistry() func() {
	mu.Lock()
	savedRegistry := make(map[string]Tamper, len(registry))
	for k, v := range registry {
		savedRegistry[k] = v
	}
	mu.Unlock()
	return func() {
		mu.Lock()
		registry = savedRegistry
		mu.Unlock()
	}
}

func TestRegisterAndGet(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	mock := newMockTamper("test_tamper", CategoryEncoding, PriorityNormal)
	Register(mock)

	got := Get("test_tamper")
	require.NotNil(t, got)
	assert.Equal(t, "test_tamper", got.Name())
	assert.Equal(t, CategoryEncoding, got.Category())
	assert.Equal(t, PriorityNormal, got.Priority())
}

func TestGetNonExistent(t *testing.T) {
	got := Get("nonexistent_tamper_xyz")
	assert.Nil(t, got)
}

func TestList(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	Register(newMockTamper("zebra", CategoryEncoding, PriorityNormal))
	Register(newMockTamper("alpha", CategorySpace, PriorityNormal))
	Register(newMockTamper("beta", CategorySQL, PriorityNormal))

	names := List()
	assert.Equal(t, []string{"alpha", "beta", "zebra"}, names) // Should be sorted
}

func TestByCategory(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	Register(newMockTamper("enc1", CategoryEncoding, PriorityNormal))
	Register(newMockTamper("enc2", CategoryEncoding, PriorityNormal))
	Register(newMockTamper("space1", CategorySpace, PriorityNormal))

	encoding := ByCategory(CategoryEncoding)
	assert.Len(t, encoding, 2)

	space := ByCategory(CategorySpace)
	assert.Len(t, space, 1)

	mysql := ByCategory(CategoryMySQL)
	assert.Len(t, mysql, 0)
}

func TestByTag(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	Register(newMockTamper("mysql1", CategoryMySQL, PriorityNormal, "mysql", "modsecurity"))
	Register(newMockTamper("mysql2", CategoryMySQL, PriorityNormal, "mysql"))
	Register(newMockTamper("mssql1", CategoryMSSQL, PriorityNormal, "mssql"))

	mysql := ByTag("mysql")
	assert.Len(t, mysql, 2)

	modsecurity := ByTag("modsecurity")
	assert.Len(t, modsecurity, 1)

	nonexistent := ByTag("oracle")
	assert.Len(t, nonexistent, 0)
}

func TestChain(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Create tampers that append their name
	t1 := newMockTamper("first", CategoryEncoding, PriorityNormal)
	t1.transformFunc = func(p string) string { return p + "_first" }

	t2 := newMockTamper("second", CategoryEncoding, PriorityNormal)
	t2.transformFunc = func(p string) string { return p + "_second" }

	Register(t1)
	Register(t2)

	result := Chain("payload", "first", "second")
	assert.Equal(t, "payload_first_second", result)

	// Non-existent tamper should be skipped
	result = Chain("payload", "first", "nonexistent", "second")
	assert.Equal(t, "payload_first_second", result)
}

func TestChainByPriority(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	// Create tampers with different priorities
	low := newMockTamper("low", CategoryEncoding, PriorityLow)
	low.transformFunc = func(p string) string { return p + "_low" }

	high := newMockTamper("high", CategoryEncoding, PriorityHigh)
	high.transformFunc = func(p string) string { return p + "_high" }

	normal := newMockTamper("normal", CategoryEncoding, PriorityNormal)
	normal.transformFunc = func(p string) string { return p + "_normal" }

	Register(low)
	Register(high)
	Register(normal)

	// Even though passed in low, normal, high order, should execute high, normal, low
	result := ChainByPriority("payload", "low", "normal", "high")
	assert.Equal(t, "payload_high_normal_low", result)
}

func TestBaseTamper(t *testing.T) {
	base := NewBaseTamper("test", "Test description", CategorySQL, PriorityHigh, "mysql", "postgres")

	assert.Equal(t, "test", base.Name())
	assert.Equal(t, "Test description", base.Description())
	assert.Equal(t, CategorySQL, base.Category())
	assert.Equal(t, PriorityHigh, base.Priority())
	assert.Equal(t, []string{"mysql", "postgres"}, base.Tags())

	// Default TransformRequest returns nil
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	assert.Nil(t, base.TransformRequest(req))
}

func TestCount(t *testing.T) {
	restore := saveRegistry()
	defer restore()

	// Clear registry for test
	mu.Lock()
	registry = make(map[string]Tamper)
	mu.Unlock()

	assert.Equal(t, 0, Count())

	Register(newMockTamper("one", CategoryEncoding, PriorityNormal))
	assert.Equal(t, 1, Count())

	Register(newMockTamper("two", CategoryEncoding, PriorityNormal))
	assert.Equal(t, 2, Count())
}

func TestCategories(t *testing.T) {
	cats := Categories()
	assert.Len(t, cats, 8)
	assert.Contains(t, cats, CategoryEncoding)
	assert.Contains(t, cats, CategorySpace)
	assert.Contains(t, cats, CategorySQL)
	assert.Contains(t, cats, CategoryMySQL)
	assert.Contains(t, cats, CategoryMSSQL)
	assert.Contains(t, cats, CategoryWAF)
	assert.Contains(t, cats, CategoryHTTP)
	assert.Contains(t, cats, CategoryObfuscation)
}
