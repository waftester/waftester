// pkg/input/flags_test.go
package input

import (
	"flag"
	"testing"
)

func TestStringSliceFlag_SingleValue(t *testing.T) {
	var urls StringSliceFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&urls, "u", "target URLs")

	err := fs.Parse([]string{"-u", "https://example.com"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(urls) != 1 || urls[0] != "https://example.com" {
		t.Errorf("expected [https://example.com], got %v", urls)
	}
}

func TestStringSliceFlag_RepeatedFlag(t *testing.T) {
	var urls StringSliceFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&urls, "u", "target URLs")

	err := fs.Parse([]string{"-u", "https://a.com", "-u", "https://b.com"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(urls) != 2 {
		t.Errorf("expected 2 urls, got %d: %v", len(urls), urls)
	}
}

func TestStringSliceFlag_CommaSeparated(t *testing.T) {
	var urls StringSliceFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&urls, "u", "target URLs")

	err := fs.Parse([]string{"-u", "https://a.com,https://b.com,https://c.com"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(urls) != 3 {
		t.Errorf("expected 3 urls, got %d: %v", len(urls), urls)
	}
}

func TestStringSliceFlag_Mixed(t *testing.T) {
	var urls StringSliceFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&urls, "u", "target URLs")

	err := fs.Parse([]string{"-u", "https://a.com,https://b.com", "-u", "https://c.com"})
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(urls) != 3 {
		t.Errorf("expected 3 urls, got %d: %v", len(urls), urls)
	}
}
