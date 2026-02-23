package payloads

import (
	"strings"
	"testing"
)

func TestPayload_Validate_RequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		payload Payload
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty payload string",
			payload: Payload{Category: "sqli"},
			wantErr: true,
			errMsg:  "payload string is required",
		},
		{
			name:    "empty category",
			payload: Payload{Payload: "' OR 1=1--"},
			wantErr: true,
			errMsg:  "category is required",
		},
		{
			name:    "both empty",
			payload: Payload{},
			wantErr: true,
			errMsg:  "payload string is required",
		},
		{
			name:    "valid minimal",
			payload: Payload{Payload: "' OR 1=1--", Category: "sqli"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.payload.Validate()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPayload_Validate_Severity(t *testing.T) {
	tests := []struct {
		severity string
		wantErr  bool
	}{
		{"info", false},
		{"low", false},
		{"medium", false},
		{"high", false},
		{"critical", false},
		{"", false},         // empty is allowed
		{"CRITICAL", false}, // case-insensitive check
		{"urgent", true},    // invalid
		{"10", true},        // invalid
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			p := Payload{Payload: "test", Category: "sqli", SeverityHint: tt.severity}
			err := p.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error for invalid severity")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPayload_Validate_Method(t *testing.T) {
	tests := []struct {
		method  string
		wantErr bool
	}{
		{"GET", false},
		{"POST", false},
		{"PUT", false},
		{"DELETE", false},
		{"", false},       // empty is allowed
		{"TRACE", true},   // not in valid set
		{"CONNECT", true}, // not in valid set
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			p := Payload{Payload: "test", Category: "sqli", Method: tt.method}
			err := p.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for method %q", tt.method)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for method %q: %v", tt.method, err)
			}
		})
	}
}

func TestPayload_Normalize(t *testing.T) {
	t.Run("trims whitespace", func(t *testing.T) {
		p := Payload{
			Payload:  "  ' OR 1=1--  ",
			Category: "  sqli  ",
			ID:       "  test-001  ",
		}
		p.Normalize()
		if p.Payload != "' OR 1=1--" {
			t.Errorf("payload not trimmed: %q", p.Payload)
		}
		if p.Category != "sqli" {
			t.Errorf("category not trimmed/lowered: %q", p.Category)
		}
		if p.ID != "test-001" {
			t.Errorf("id not trimmed: %q", p.ID)
		}
	})

	t.Run("normalizes severity to lowercase", func(t *testing.T) {
		p := Payload{Payload: "test", Category: "sqli", SeverityHint: "HIGH"}
		p.Normalize()
		if p.SeverityHint != "high" {
			t.Errorf("severity not lowered: %q", p.SeverityHint)
		}
	})

	t.Run("normalizes method to uppercase", func(t *testing.T) {
		p := Payload{Payload: "test", Category: "sqli", Method: "post"}
		p.Normalize()
		if p.Method != "POST" {
			t.Errorf("method not uppercased: %q", p.Method)
		}
	})

	t.Run("defaults method to GET", func(t *testing.T) {
		p := Payload{Payload: "test", Category: "sqli"}
		p.Normalize()
		if p.Method != "GET" {
			t.Errorf("method not defaulted to GET: %q", p.Method)
		}
	})

	t.Run("migrates AttackCategory to Category", func(t *testing.T) {
		p := Payload{Payload: "test", AttackCategory: "XSS"}
		p.Normalize()
		if p.Category != "xss" {
			t.Errorf("category not migrated: %q", p.Category)
		}
	})

	t.Run("deduplicates tags", func(t *testing.T) {
		p := Payload{
			Payload:  "test",
			Category: "sqli",
			Tags:     []string{"bypass", "BYPASS", "evasion", "bypass"},
		}
		p.Normalize()
		if len(p.Tags) != 2 {
			t.Errorf("expected 2 unique tags, got %d: %v", len(p.Tags), p.Tags)
		}
	})

	t.Run("generates ID from hash", func(t *testing.T) {
		p := Payload{Payload: "' OR 1=1--", Category: "sqli"}
		p.Normalize()
		if p.ID == "" {
			t.Fatal("expected auto-generated ID")
		}
		if !strings.HasPrefix(p.ID, "auto-") {
			t.Errorf("expected auto- prefix, got %q", p.ID)
		}
	})

	t.Run("preserves existing ID", func(t *testing.T) {
		p := Payload{Payload: "test", Category: "sqli", ID: "my-id"}
		p.Normalize()
		if p.ID != "my-id" {
			t.Errorf("expected preserved ID, got %q", p.ID)
		}
	})
}

func TestPayload_UpdateEffectiveness(t *testing.T) {
	p := Payload{Payload: "test", Category: "sqli"}

	// First observation — bypassed
	p.UpdateEffectiveness(true, "cloudflare")
	if p.Effectiveness == nil {
		t.Fatal("effectiveness should be initialized")
	}
	if p.Effectiveness.SampleCount != 1 {
		t.Errorf("expected 1 sample, got %d", p.Effectiveness.SampleCount)
	}
	if p.Effectiveness.Overall < 0.09 || p.Effectiveness.Overall > 0.11 {
		t.Errorf("expected ~0.1 overall after first bypass, got %f", p.Effectiveness.Overall)
	}

	// Second observation — blocked
	p.UpdateEffectiveness(false, "cloudflare")
	if p.Effectiveness.SampleCount != 2 {
		t.Errorf("expected 2 samples, got %d", p.Effectiveness.SampleCount)
	}

	// Verify vendor tracking
	cf := p.GetEffectivenessByVendor("cloudflare")
	if cf <= 0 || cf >= 1 {
		t.Errorf("expected cf score between 0 and 1, got %f", cf)
	}

	// Unknown vendor should return 0.5
	unknown := p.GetEffectivenessByVendor("unknown-vendor")
	if unknown != 0.5 {
		t.Errorf("expected 0.5 for unknown vendor, got %f", unknown)
	}
}

func TestPayload_GetEffectivenessByVendor_NilEffectiveness(t *testing.T) {
	p := Payload{Payload: "test", Category: "sqli"}
	score := p.GetEffectivenessByVendor("cloudflare")
	if score != 0.5 {
		t.Errorf("expected 0.5 for nil effectiveness, got %f", score)
	}
}
