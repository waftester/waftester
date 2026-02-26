package scanner

import (
	"context"
	"testing"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestDispatcher_RegisterAndGet(t *testing.T) {
	d := NewDispatcher()

	fn := func(ctx context.Context, target string, cfg *attackconfig.Base) *Result {
		return &Result{
			Category: "test",
			Vulnerabilities: []Vulnerability{
				{Category: "test", Severity: finding.High, Type: "test-vuln"},
			},
		}
	}

	d.Register("test", fn)

	if !d.Has("test") {
		t.Fatal("expected dispatcher to have 'test' scanner")
	}
	if d.Count() != 1 {
		t.Fatalf("expected 1 scanner, got %d", d.Count())
	}
	if got := d.Get("test"); got == nil {
		t.Fatal("expected non-nil ScanFunc")
	}
	if got := d.Get("nonexistent"); got != nil {
		t.Fatal("expected nil for nonexistent scanner")
	}
}

func TestDispatcher_NamesPreservesOrder(t *testing.T) {
	d := NewDispatcher()

	for _, name := range []string{"sqli", "xss", "cmdi", "ssrf"} {
		name := name
		d.Register(name, func(ctx context.Context, target string, cfg *attackconfig.Base) *Result {
			return &Result{Category: name}
		})
	}

	names := d.Names()
	expected := []string{"sqli", "xss", "cmdi", "ssrf"}
	if len(names) != len(expected) {
		t.Fatalf("expected %d names, got %d", len(expected), len(names))
	}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("names[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestDispatcher_DuplicateRegisterOverwrites(t *testing.T) {
	d := NewDispatcher()

	d.Register("test", func(ctx context.Context, target string, cfg *attackconfig.Base) *Result {
		return &Result{Category: "v1"}
	})
	d.Register("test", func(ctx context.Context, target string, cfg *attackconfig.Base) *Result {
		return &Result{Category: "v2"}
	})

	if d.Count() != 1 {
		t.Fatalf("expected 1 scanner after duplicate register, got %d", d.Count())
	}

	result := d.Get("test")(context.Background(), "http://example.com", &attackconfig.Base{})
	if result.Category != "v2" {
		t.Errorf("expected v2 after overwrite, got %q", result.Category)
	}
}

func TestScanFunc_ReturnsResult(t *testing.T) {
	fn := func(ctx context.Context, target string, cfg *attackconfig.Base) *Result {
		return &Result{
			Category: "sqli",
			Vulnerabilities: []Vulnerability{
				{
					Category:  "sqli",
					Severity:  finding.Critical,
					Type:      "sql-injection",
					Parameter: "id",
					Payload:   "' OR 1=1--",
				},
			},
		}
	}

	result := fn(context.Background(), "http://example.com", &attackconfig.Base{})
	if result.Category != "sqli" {
		t.Errorf("expected category sqli, got %q", result.Category)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
	}
	if result.Vulnerabilities[0].Severity != finding.Critical {
		t.Errorf("expected Critical severity, got %v", result.Vulnerabilities[0].Severity)
	}
}
