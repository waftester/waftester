package tampers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewEngine(t *testing.T) {
	// Test default config
	engine := NewEngine(nil)
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
	if engine.profile != ProfileStandard {
		t.Errorf("expected ProfileStandard, got %s", engine.profile)
	}
}

func TestEngineProfiles(t *testing.T) {
	tests := []struct {
		name       string
		profile    Profile
		wafVendor  string
		minTampers int
		maxTampers int
	}{
		{
			name:       "stealth profile",
			profile:    ProfileStealth,
			wafVendor:  "cloudflare",
			minTampers: 2,
			maxTampers: 3,
		},
		{
			name:       "standard profile",
			profile:    ProfileStandard,
			wafVendor:  "cloudflare",
			minTampers: 5,
			maxTampers: 5,
		},
		{
			name:       "aggressive profile",
			profile:    ProfileAggressive,
			wafVendor:  "cloudflare",
			minTampers: 10,
			maxTampers: 20,
		},
		{
			name:       "bypass profile",
			profile:    ProfileBypass,
			wafVendor:  "modsecurity",
			minTampers: 10,
			maxTampers: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(&EngineConfig{
				Profile:   tt.profile,
				WAFVendor: tt.wafVendor,
			})

			tampers := engine.GetSelectedTampers()
			if len(tampers) < tt.minTampers {
				t.Errorf("expected at least %d tampers, got %d: %v", tt.minTampers, len(tampers), tampers)
			}
			if len(tampers) > tt.maxTampers {
				t.Errorf("expected at most %d tampers, got %d: %v", tt.maxTampers, len(tampers), tampers)
			}
		})
	}
}

func TestEngineCustomTampers(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment", "randomcase"},
	})

	tampers := engine.GetSelectedTampers()
	if len(tampers) != 2 {
		t.Errorf("expected 2 custom tampers, got %d", len(tampers))
	}
	if tampers[0] != "space2comment" || tampers[1] != "randomcase" {
		t.Errorf("unexpected tampers: %v", tampers)
	}
}

func TestEngineTransform(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"randomcase"},
	})

	payload := "SELECT * FROM users"
	transformed := engine.Transform(payload)

	// randomcase should change case of some characters
	if transformed == payload {
		// It's random, so this might occasionally be equal, but very unlikely
		t.Log("Warning: transformed payload equals original (randomcase may have left unchanged)")
	}

	// Should still contain the same words
	if len(transformed) != len(payload) {
		t.Errorf("randomcase should not change length, got %d vs %d", len(transformed), len(payload))
	}
}

func TestEngineTransformWith(t *testing.T) {
	engine := NewEngine(nil)

	payload := "SELECT * FROM users WHERE id=1"
	transformed := engine.TransformWith(payload, "space2comment")

	// space2comment replaces spaces with /**/
	if transformed == payload {
		t.Error("expected transformed payload to differ from original")
	}
}

func TestEngineSetWAFVendor(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile: ProfileStandard,
	})

	// Initially no vendor
	tampersNoVendor := engine.GetSelectedTampers()

	// Set vendor
	engine.SetWAFVendor("cloudflare")
	tampersWithVendor := engine.GetSelectedTampers()

	// Should get WAF-specific tampers
	t.Logf("No vendor: %v", tampersNoVendor)
	t.Logf("With Cloudflare: %v", tampersWithVendor)
}

func TestEngineAdaptiveLearning(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		EnableMetrics: true,
	})

	// Record some successes
	engine.RecordSuccess([]string{"space2comment", "randomcase"})
	engine.RecordSuccess([]string{"space2comment"})
	engine.RecordFailure([]string{"charencode"})

	// Check adaptive scores
	scores := engine.GetAdaptiveScores()
	if scores["space2comment"] <= 0 {
		t.Error("expected positive score for space2comment")
	}
	if scores["charencode"] >= 0.1 {
		t.Error("expected low score for charencode after failure")
	}
}

func TestEngineTransformRequest(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment"},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com?q=test", nil)
	result := engine.TransformRequest(req)

	// space2comment doesn't modify HTTP requests, so should return same request
	if result != req {
		t.Error("expected same request back when tamper doesn't modify HTTP")
	}
}

func TestParseTamperList(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"space2comment", []string{"space2comment"}},
		{"space2comment,randomcase", []string{"space2comment", "randomcase"}},
		{"space2comment, randomcase, charencode", []string{"space2comment", "randomcase", "charencode"}},
		{"  space2comment , randomcase  ", []string{"space2comment", "randomcase"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseTamperList(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d items, got %d", len(tt.expected), len(result))
				return
			}
			for i, v := range tt.expected {
				if result[i] != v {
					t.Errorf("expected %s at position %d, got %s", v, i, result[i])
				}
			}
		})
	}
}

func TestValidateTamperNames(t *testing.T) {
	valid, invalid := ValidateTamperNames([]string{"space2comment", "randomcase", "invalid_tamper", "fake"})

	if len(valid) < 2 {
		t.Errorf("expected at least 2 valid tampers, got %d", len(valid))
	}
	if len(invalid) != 2 {
		t.Errorf("expected 2 invalid tampers, got %d: %v", len(invalid), invalid)
	}
}

func TestDescribeTampers(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment", "randomcase"},
	})

	infos := engine.DescribeTampers()
	if len(infos) != 2 {
		t.Errorf("expected 2 tamper infos, got %d", len(infos))
	}

	for _, info := range infos {
		if info.Name == "" {
			t.Error("expected non-empty tamper name")
		}
		if info.Description == "" {
			t.Error("expected non-empty tamper description")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Negative / edge-case tests for tamper Engine
// ─────────────────────────────────────────────────────────────────────────────

func TestNewEngine_NilConfig(t *testing.T) {
	engine := NewEngine(nil)
	if engine == nil {
		t.Fatal("NewEngine(nil) should return a valid engine")
	}
	if engine.profile != ProfileStandard {
		t.Errorf("nil config should default to ProfileStandard, got %s", engine.profile)
	}
}

func TestNewEngine_UnknownProfile(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile: "nonexistent-profile",
	})
	// Unknown profile should fall through to the default case in GetSelectedTampers
	tampers := engine.GetSelectedTampers()
	// Default case is ProfileStandard, so should return standard tampers
	if len(tampers) == 0 {
		t.Error("unknown profile should fall through to standard and return tampers")
	}
}

func TestEngineCustomTampers_EmptyList(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{},
	})
	tampers := engine.GetSelectedTampers()
	if len(tampers) != 0 {
		t.Errorf("custom profile with no tampers should return empty list, got %d", len(tampers))
	}
}

func TestEngineCustomTampers_NilList(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: nil,
	})
	tampers := engine.GetSelectedTampers()
	if tampers != nil {
		t.Errorf("custom profile with nil tampers should return nil, got %v", tampers)
	}
}

func TestEngineTransform_EmptyInput(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment"},
	})
	result := engine.Transform("")
	if result != "" {
		t.Errorf("transforming empty string should return empty, got %q", result)
	}
}

func TestEngineTransformWith_UnknownTamper(t *testing.T) {
	engine := NewEngine(nil)
	payload := "SELECT * FROM users"
	result := engine.TransformWith(payload, "nonexistent_tamper_xyz")
	// Unknown tamper should return payload unchanged
	if result != payload {
		t.Errorf("unknown tamper should return original payload, got %q", result)
	}
}

func TestEngineSetWAFVendor_Empty(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:   ProfileStandard,
		WAFVendor: "cloudflare",
	})
	engine.SetWAFVendor("")
	// Should clear vendor
	engine.mu.RLock()
	v := engine.wafVendor
	engine.mu.RUnlock()
	if v != "" {
		t.Errorf("SetWAFVendor('') should clear vendor, got %q", v)
	}
}

func TestValidateTamperNames_Nil(t *testing.T) {
	valid, invalid := ValidateTamperNames(nil)
	if len(valid) != 0 || len(invalid) != 0 {
		t.Errorf("nil input: got valid=%d, invalid=%d", len(valid), len(invalid))
	}
}

func TestValidateTamperNames_EmptyStrings(t *testing.T) {
	valid, invalid := ValidateTamperNames([]string{""})
	if len(valid) != 0 {
		t.Errorf("empty string should not be valid, got %v", valid)
	}
	if len(invalid) != 1 {
		t.Errorf("empty string should be invalid, got %v", invalid)
	}
}

func TestValidateTamperNames_AllInvalid(t *testing.T) {
	valid, invalid := ValidateTamperNames([]string{"fake1", "fake2", "fake3"})
	if len(valid) != 0 {
		t.Errorf("all-invalid input should have 0 valid, got %v", valid)
	}
	if len(invalid) != 3 {
		t.Errorf("all-invalid input should have 3 invalid, got %v", invalid)
	}
}

func TestParseTamperList_CommasOnly(t *testing.T) {
	result := ParseTamperList(",,,")
	if len(result) != 0 {
		t.Errorf("commas-only should return empty list, got %v", result)
	}
}

func TestParseTamperList_WhitespaceOnly(t *testing.T) {
	result := ParseTamperList("   ")
	if len(result) != 0 {
		t.Errorf("whitespace-only should return empty list, got %v", result)
	}
}

func TestEngineRecordSuccess_EmptyList(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		EnableMetrics: true,
	})
	// Should not panic
	engine.RecordSuccess(nil)
	engine.RecordSuccess([]string{})
}

func TestEngineRecordFailure_EmptyList(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileStandard,
		EnableMetrics: true,
	})
	// Should not panic
	engine.RecordFailure(nil)
	engine.RecordFailure([]string{})
}

func TestEngineGetAdaptiveScores_EmptyEngine(t *testing.T) {
	engine := NewEngine(nil)
	scores := engine.GetAdaptiveScores()
	if scores == nil {
		t.Error("GetAdaptiveScores should return non-nil map")
	}
	if len(scores) != 0 {
		t.Errorf("new engine should have no scores, got %d", len(scores))
	}
}

func TestEngineTransformRequest_NilRequest(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{"space2comment"},
	})
	result := engine.TransformRequest(nil)
	if result != nil {
		t.Error("TransformRequest(nil) should return nil")
	}
}

func TestEngineSetProfile(t *testing.T) {
	engine := NewEngine(nil)

	engine.SetProfile(ProfileAggressive)
	engine.mu.RLock()
	p := engine.profile
	engine.mu.RUnlock()
	if p != ProfileAggressive {
		t.Errorf("expected ProfileAggressive, got %s", p)
	}
}

func TestEngineDescribeTampers_EmptyCustom(t *testing.T) {
	engine := NewEngine(&EngineConfig{
		Profile:       ProfileCustom,
		CustomTampers: []string{},
	})
	infos := engine.DescribeTampers()
	if len(infos) != 0 {
		t.Errorf("empty custom tampers should describe 0 tampers, got %d", len(infos))
	}
}
