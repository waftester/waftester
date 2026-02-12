package attackconfig

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestDefaultBase_HasSaneDefaults(t *testing.T) {
	t.Parallel()
	b := DefaultBase()
	if b.Timeout <= 0 {
		t.Error("Timeout must be positive")
	}
	if b.Concurrency <= 0 {
		t.Error("Concurrency must be positive")
	}
}

func TestValidate_FillsZeroValues(t *testing.T) {
	t.Parallel()
	b := Base{}
	b.Validate()
	if b.Timeout <= 0 {
		t.Error("Validate should fill Timeout")
	}
	if b.Concurrency <= 0 {
		t.Error("Validate should fill Concurrency")
	}
}

func TestValidate_PreservesCustomValues(t *testing.T) {
	t.Parallel()
	b := Base{
		Timeout:     30 * time.Second,
		Concurrency: 50,
		UserAgent:   "Custom/1.0",
	}
	b.Validate()
	if b.Timeout != 30*time.Second {
		t.Error("custom Timeout was clobbered")
	}
	if b.Concurrency != 50 {
		t.Error("custom Concurrency was clobbered")
	}
	if b.UserAgent != "Custom/1.0" {
		t.Error("custom UserAgent was clobbered")
	}
}

func TestBase_EmbeddingPattern(t *testing.T) {
	t.Parallel()
	type SQLiConfig struct {
		Base
		DBMS          string
		TimeThreshold time.Duration
	}
	cfg := SQLiConfig{
		Base: DefaultBase(),
		DBMS: "MySQL",
	}
	// Access base fields directly via promotion
	if cfg.Timeout <= 0 {
		t.Error("embedded Timeout not accessible")
	}
	if cfg.DBMS != "MySQL" {
		t.Error("extension field not accessible")
	}
	cfg.Client = &http.Client{Timeout: 5 * time.Second}
	if cfg.Client == nil {
		t.Error("Client not set via base")
	}
}

func TestBase_JSONRoundtrip(t *testing.T) {
	t.Parallel()
	b := Base{
		Timeout:     10 * time.Second,
		UserAgent:   "WAFtester/2.0",
		MaxPayloads: 100,
		MaxParams:   5,
		Concurrency: 20,
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Base
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Timeout != b.Timeout {
		t.Errorf("Timeout: got %v, want %v", decoded.Timeout, b.Timeout)
	}
	if decoded.UserAgent != b.UserAgent {
		t.Errorf("UserAgent: got %q, want %q", decoded.UserAgent, b.UserAgent)
	}
	if decoded.MaxPayloads != b.MaxPayloads {
		t.Errorf("MaxPayloads: got %d, want %d", decoded.MaxPayloads, b.MaxPayloads)
	}
	if decoded.Concurrency != b.Concurrency {
		t.Errorf("Concurrency: got %d, want %d", decoded.Concurrency, b.Concurrency)
	}
}

func TestBase_JSONOmitEmpty(t *testing.T) {
	t.Parallel()
	b := Base{}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	if s != "{}" {
		t.Errorf("zero value should marshal to {}, got %s", s)
	}
}

func TestBase_ClientNotSerialized(t *testing.T) {
	t.Parallel()
	b := Base{
		Client: &http.Client{Timeout: time.Second},
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if s != "{}" {
		t.Errorf("Client should not appear in JSON, got %s", s)
	}
}
