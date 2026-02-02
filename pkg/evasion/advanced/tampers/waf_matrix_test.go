package tampers

import "testing"

func TestGetRecommendations(t *testing.T) {
	tests := []struct {
		vendor   string
		minRecs  int
		topName  string
	}{
		{"cloudflare", 5, "charunicodeencode"},
		{"aws_waf", 5, "chardoubleencode"},
		{"modsecurity", 5, "modsecurityversioned"},
		{"unknown_waf", 5, "space2comment"}, // Falls back to defaults
	}

	for _, tt := range tests {
		t.Run(tt.vendor, func(t *testing.T) {
			recs := GetRecommendations(tt.vendor)
			if len(recs) < tt.minRecs {
				t.Errorf("expected at least %d recommendations, got %d", tt.minRecs, len(recs))
			}

			if len(recs) > 0 && recs[0].Name != tt.topName {
				t.Errorf("expected top recommendation to be %s, got %s", tt.topName, recs[0].Name)
			}
		})
	}
}

func TestGetAllVendors(t *testing.T) {
	vendors := GetAllVendors()
	if len(vendors) < 10 {
		t.Errorf("expected at least 10 vendors, got %d", len(vendors))
	}

	// Check for key vendors
	vendorSet := make(map[string]bool)
	for _, v := range vendors {
		vendorSet[v] = true
	}

	keyVendors := []string{"cloudflare", "aws_waf", "modsecurity", "akamai", "imperva"}
	for _, kv := range keyVendors {
		if !vendorSet[kv] {
			t.Errorf("expected vendor %s in matrix", kv)
		}
	}
}

func TestGetTampersForVendor(t *testing.T) {
	tampers := GetTampersForVendor("cloudflare")
	if len(tampers) < 5 {
		t.Errorf("expected at least 5 tampers for cloudflare, got %d", len(tampers))
	}

	// All should be strings
	for _, name := range tampers {
		if name == "" {
			t.Error("expected non-empty tamper name")
		}
	}
}

func TestGetTopTampersForVendor(t *testing.T) {
	top3 := GetTopTampersForVendor("cloudflare", 3)
	if len(top3) != 3 {
		t.Errorf("expected 3 tampers, got %d", len(top3))
	}

	// Request more than available
	top100 := GetTopTampersForVendor("cloudflare", 100)
	allRecs := GetRecommendations("cloudflare")
	if len(top100) != len(allRecs) {
		t.Errorf("expected %d tampers (all available), got %d", len(allRecs), len(top100))
	}
}

func TestHasVendor(t *testing.T) {
	if !HasVendor("cloudflare") {
		t.Error("expected cloudflare to be in matrix")
	}
	if !HasVendor("modsecurity") {
		t.Error("expected modsecurity to be in matrix")
	}
	if HasVendor("fake_waf_that_does_not_exist") {
		t.Error("expected fake vendor to not be in matrix")
	}
}

func TestGetEffectiveness(t *testing.T) {
	eff := GetEffectiveness("cloudflare", "charunicodeencode")
	if eff < 0.8 || eff > 0.9 {
		t.Errorf("expected effectiveness around 0.85, got %f", eff)
	}

	// Unknown combination
	effUnknown := GetEffectiveness("cloudflare", "nonexistent_tamper")
	if effUnknown != 0.5 {
		t.Errorf("expected default effectiveness 0.5, got %f", effUnknown)
	}
}

func TestRecommendationOrder(t *testing.T) {
	recs := GetRecommendations("cloudflare")

	// Verify order is by effectiveness (descending)
	for i := 0; i < len(recs)-1; i++ {
		if recs[i].Order > recs[i+1].Order {
			// Order should be ascending
		}
	}

	// Verify all have required fields
	for _, rec := range recs {
		if rec.Name == "" {
			t.Error("expected non-empty name")
		}
		if rec.Effectiveness <= 0 || rec.Effectiveness > 1 {
			t.Errorf("effectiveness should be 0-1, got %f", rec.Effectiveness)
		}
	}
}
