package jsonutil

import (
	"bytes"
	"strings"
	"testing"
)

// TestUnmarshal verifies Unmarshal works correctly.
func TestUnmarshal(t *testing.T) {
	t.Run("valid object", func(t *testing.T) {
		var result map[string]interface{}
		err := Unmarshal([]byte(`{"name":"test","value":42}`), &result)
		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
		}
		if result["name"] != "test" {
			t.Errorf("expected name=test, got %v", result["name"])
		}
	})

	t.Run("valid array", func(t *testing.T) {
		var result []int
		err := Unmarshal([]byte(`[1,2,3,4,5]`), &result)
		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
		}
		if len(result) != 5 {
			t.Errorf("expected 5 elements, got %d", len(result))
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		var result map[string]interface{}
		err := Unmarshal([]byte(`{invalid}`), &result)
		if err == nil {
			t.Error("Unmarshal() expected error for invalid JSON")
		}
	})

	t.Run("empty object", func(t *testing.T) {
		var result map[string]interface{}
		err := Unmarshal([]byte(`{}`), &result)
		if err != nil {
			t.Errorf("Unmarshal() error = %v", err)
		}
	})
}

// TestMarshal verifies Marshal produces valid JSON.
func TestMarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		contains string
		wantErr  bool
	}{
		{
			name:     "simple map",
			input:    map[string]string{"key": "value"},
			contains: `"key"`,
			wantErr:  false,
		},
		{
			name:     "struct",
			input:    struct{ Name string }{Name: "test"},
			contains: `"Name"`,
			wantErr:  false,
		},
		{
			name:     "slice",
			input:    []int{1, 2, 3},
			contains: `[1,2,3]`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !bytes.Contains(got, []byte(tt.contains)) {
				t.Errorf("Marshal() = %s, want to contain %s", got, tt.contains)
			}
		})
	}
}

// TestMarshalIndent verifies MarshalIndent produces indented JSON.
func TestMarshalIndent(t *testing.T) {
	input := map[string]int{"a": 1, "b": 2}
	got, err := MarshalIndent(input, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}

	// Should contain newlines and indentation
	result := string(got)
	if !strings.Contains(result, "\n") {
		t.Error("MarshalIndent() should contain newlines")
	}
	if !strings.Contains(result, "  ") {
		t.Error("MarshalIndent() should contain indentation")
	}
}

// TestEncoder verifies the streaming encoder works correctly.
func TestEncoder(t *testing.T) {
	t.Run("basic encode", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewStreamEncoder(&buf)

		err := enc.Encode(map[string]int{"x": 1})
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}

		// Should end with newline (matching encoding/json behavior)
		result := buf.String()
		if !strings.HasSuffix(result, "\n") {
			t.Error("Encode() should append newline")
		}
	})

	t.Run("multiple encodes", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewStreamEncoder(&buf)

		enc.Encode(1)
		enc.Encode(2)
		enc.Encode(3)

		result := buf.String()
		lines := strings.Split(strings.TrimSpace(result), "\n")
		if len(lines) != 3 {
			t.Errorf("expected 3 lines, got %d: %q", len(lines), result)
		}
	})

	t.Run("with indentation", func(t *testing.T) {
		var buf bytes.Buffer
		enc := NewStreamEncoder(&buf)
		enc.SetIndent("", "    ")

		err := enc.Encode(map[string]int{"key": 42})
		if err != nil {
			t.Fatalf("Encode() error = %v", err)
		}

		result := buf.String()
		if !strings.Contains(result, "    ") {
			t.Error("Encode() with SetIndent() should produce indented output")
		}
	})
}

// TestDecoder verifies the streaming decoder works correctly.
func TestDecoder(t *testing.T) {
	input := `{"name":"test"}`
	dec := NewStreamDecoder(strings.NewReader(input))

	var result map[string]string
	err := dec.Decode(&result)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if result["name"] != "test" {
		t.Errorf("Decode() got %v, want name=test", result)
	}
}

// TestValid verifies JSON validation.
func TestValid(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{`{}`, true},
		{`[]`, true},
		{`{"key":"value"}`, true},
		{`[1,2,3]`, true},
		{`null`, true},
		{`{invalid}`, false},
		{``, false},
		{`{`, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := Valid([]byte(tt.input)); got != tt.want {
				t.Errorf("Valid(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestRoundTrip verifies Marshal/Unmarshal round-trip consistency.
func TestRoundTrip(t *testing.T) {
	type TestStruct struct {
		Name    string   `json:"name"`
		Count   int      `json:"count"`
		Tags    []string `json:"tags"`
		Enabled bool     `json:"enabled"`
	}

	original := TestStruct{
		Name:    "test",
		Count:   42,
		Tags:    []string{"a", "b", "c"},
		Enabled: true,
	}

	// Marshal
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal
	var result TestStruct
	err = Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Verify
	if result.Name != original.Name {
		t.Errorf("Name = %q, want %q", result.Name, original.Name)
	}
	if result.Count != original.Count {
		t.Errorf("Count = %d, want %d", result.Count, original.Count)
	}
	if len(result.Tags) != len(original.Tags) {
		t.Errorf("Tags length = %d, want %d", len(result.Tags), len(original.Tags))
	}
	if result.Enabled != original.Enabled {
		t.Errorf("Enabled = %v, want %v", result.Enabled, original.Enabled)
	}
}

// BenchmarkMarshal compares jsonutil performance.
func BenchmarkMarshal(b *testing.B) {
	data := map[string]interface{}{
		"name":    "benchmark",
		"count":   1000,
		"enabled": true,
		"tags":    []string{"perf", "test", "json"},
		"nested": map[string]int{
			"a": 1, "b": 2, "c": 3,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Marshal(data)
	}
}

// BenchmarkUnmarshal compares jsonutil performance.
func BenchmarkUnmarshal(b *testing.B) {
	data := []byte(`{"name":"benchmark","count":1000,"enabled":true,"tags":["perf","test","json"],"nested":{"a":1,"b":2,"c":3}}`)
	var result map[string]interface{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Unmarshal(data, &result)
	}
}
