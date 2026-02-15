package params

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContainsPosition(t *testing.T) {
	positions := []string{"query", "body", "json"}

	if !containsPosition(positions, "json") {
		t.Error("expected json to be found")
	}
	if containsPosition(positions, "header") {
		t.Error("expected header to not be found")
	}
	if containsPosition(nil, "query") {
		t.Error("expected nil slice to return false")
	}
}

func TestDefaultConfig_HasPositions(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.Positions) == 0 {
		t.Fatal("DefaultConfig should have Positions")
	}

	expected := map[string]bool{"query": true, "body": true, "json": true, "header": true, "cookie": true}
	for _, p := range cfg.Positions {
		if !expected[p] {
			t.Errorf("unexpected position %q in defaults", p)
		}
	}
}

func TestJSONBodyDiscovery(t *testing.T) {
	t.Run("discovers JSON body param", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				w.WriteHeader(200)
				w.Write([]byte("baseline"))
				return
			}
			body, _ := io.ReadAll(r.Body)
			var obj map[string]interface{}
			if err := json.Unmarshal(body, &obj); err != nil {
				w.WriteHeader(200)
				w.Write([]byte("baseline"))
				return
			}
			if _, ok := obj["debug"]; ok {
				w.WriteHeader(200)
				w.Write([]byte("debug mode enabled - different response"))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("baseline"))
		}))
		defer srv.Close()

		cfg := DefaultConfig()
		cfg.Timeout = 5 * time.Second
		cfg.Concurrency = 2
		cfg.HTTPClient = srv.Client()
		d := NewDiscoverer(cfg)

		baseline, err := d.getBaseline(context.Background(), srv.URL, "GET")
		if err != nil {
			t.Fatal(err)
		}

		params := d.jsonBodyDiscovery(context.Background(), srv.URL, baseline)

		found := false
		for _, p := range params {
			if p.Name == "debug" && p.Type == "json" {
				found = true
			}
		}
		if !found {
			t.Error("expected to discover 'debug' as JSON body param")
		}
	})

	t.Run("returns empty when no params match", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte("always same"))
		}))
		defer srv.Close()

		cfg := DefaultConfig()
		cfg.Timeout = 5 * time.Second
		cfg.HTTPClient = srv.Client()
		d := NewDiscoverer(cfg)

		baseline, _ := d.getBaseline(context.Background(), srv.URL, "GET")
		params := d.jsonBodyDiscovery(context.Background(), srv.URL, baseline)

		if len(params) != 0 {
			t.Errorf("expected 0 params, got %d", len(params))
		}
	})
}

func TestHeaderDiscovery(t *testing.T) {
	t.Run("discovers header param", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Debug") != "" {
				w.WriteHeader(200)
				w.Write([]byte("debug header detected - different"))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("baseline"))
		}))
		defer srv.Close()

		cfg := DefaultConfig()
		cfg.Timeout = 5 * time.Second
		cfg.HTTPClient = srv.Client()
		d := NewDiscoverer(cfg)

		baseline, _ := d.getBaseline(context.Background(), srv.URL, "GET")
		params := d.headerDiscovery(context.Background(), srv.URL, baseline)

		found := false
		for _, p := range params {
			if p.Name == "X-Debug" && p.Type == "header" {
				found = true
			}
		}
		if !found {
			t.Error("expected to discover 'X-Debug' as header param")
		}
	})
}

func TestCookieDiscovery(t *testing.T) {
	t.Run("discovers cookie param", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := r.Cookie("admin"); err == nil {
				w.WriteHeader(200)
				w.Write([]byte("admin cookie detected - different"))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte("baseline"))
		}))
		defer srv.Close()

		cfg := DefaultConfig()
		cfg.Timeout = 5 * time.Second
		cfg.HTTPClient = srv.Client()
		d := NewDiscoverer(cfg)

		baseline, _ := d.getBaseline(context.Background(), srv.URL, "GET")
		params := d.cookieDiscovery(context.Background(), srv.URL, baseline)

		found := false
		for _, p := range params {
			if p.Name == "admin" && p.Type == "cookie" {
				found = true
			}
		}
		if !found {
			t.Error("expected to discover 'admin' as cookie param")
		}
	})
}

func TestDiscover_MultiPosition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond differently to JSON body "debug" key
		if r.Method == "POST" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			body, _ := io.ReadAll(r.Body)
			var obj map[string]interface{}
			if err := json.Unmarshal(body, &obj); err == nil {
				if _, ok := obj["debug"]; ok {
					w.WriteHeader(200)
					w.Write([]byte("debug json body"))
					return
				}
			}
		}

		// Respond differently to X-Debug header
		if r.Header.Get("X-Debug") != "" {
			w.WriteHeader(200)
			w.Write([]byte("debug header present"))
			return
		}

		// Respond differently to admin cookie
		if _, err := r.Cookie("admin"); err == nil {
			w.WriteHeader(200)
			w.Write([]byte("admin cookie present"))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte("baseline response"))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Timeout = 5 * time.Second
	cfg.Concurrency = 2
	cfg.Positions = []string{"json", "header", "cookie"}
	cfg.HTTPClient = srv.Client()
	d := NewDiscoverer(cfg)

	result, err := d.Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	types := make(map[string]bool)
	for _, p := range result.Parameters {
		types[p.Type] = true
	}
	if !types["json"] {
		t.Error("expected to discover JSON body param")
	}
	if !types["header"] {
		t.Error("expected to discover header param")
	}
	if !types["cookie"] {
		t.Error("expected to discover cookie param")
	}
}

func TestCommonHeaders(t *testing.T) {
	headers := commonHeaders()
	if len(headers) < 20 {
		t.Errorf("expected at least 20 common headers, got %d", len(headers))
	}

	// Verify key headers are present
	found := map[string]bool{}
	for _, h := range headers {
		found[h] = true
	}
	for _, expected := range []string{"X-Forwarded-For", "X-Real-IP", "X-Debug"} {
		if !found[expected] {
			t.Errorf("expected %q in common headers", expected)
		}
	}
}
