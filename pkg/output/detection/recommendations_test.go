package detection

import (
	"testing"
)

// TestRecommendationsForDrops verifies drop-related recommendations
func TestRecommendationsForDrops(t *testing.T) {
	stats := Stats{DropsDetected: 10}

	recs := stats.Recommendations()

	if len(recs) == 0 {
		t.Fatal("Should have recommendations for drops")
	}

	// Should recommend reducing concurrency
	found := false
	for _, rec := range recs {
		if containsAny(rec, "concurrency", "rate", "-c", "-rate") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Recommendations should mention concurrency/rate for drops: %v", recs)
	}
}

// TestRecommendationsForBans verifies ban-related recommendations
func TestRecommendationsForBans(t *testing.T) {
	stats := Stats{BansDetected: 5}

	recs := stats.Recommendations()

	if len(recs) == 0 {
		t.Fatal("Should have recommendations for bans")
	}

	// Should recommend rate limiting or delays
	found := false
	for _, rec := range recs {
		if containsAny(rec, "rate", "limit", "delay", "ban", "block") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Recommendations should mention rate limiting for bans: %v", recs)
	}
}

// TestRecommendationsForSkipped verifies skipped-related recommendations
func TestRecommendationsForSkipped(t *testing.T) {
	stats := Stats{HostsSkipped: 3}

	recs := stats.Recommendations()

	if len(recs) == 0 {
		t.Fatal("Should have recommendations for skipped hosts")
	}

	// Should mention connectivity or --no-detect
	found := false
	for _, rec := range recs {
		if containsAny(rec, "network", "connectivity", "no-detect", "skip") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Recommendations should mention connectivity for skipped: %v", recs)
	}
}

// TestNoRecommendationsForEmptyStats verifies empty stats get no recommendations
func TestNoRecommendationsForEmptyStats(t *testing.T) {
	stats := Stats{}

	recs := stats.Recommendations()

	if len(recs) != 0 {
		t.Errorf("Empty stats should have no recommendations, got: %v", recs)
	}
}

// TestRecommendationsAreDeduplicated verifies no duplicate recommendations
func TestRecommendationsAreDeduplicated(t *testing.T) {
	stats := Stats{
		DropsDetected: 10,
		BansDetected:  5,
		HostsSkipped:  3,
	}

	recs := stats.Recommendations()

	seen := make(map[string]bool)
	for _, rec := range recs {
		if seen[rec] {
			t.Errorf("Duplicate recommendation found: %s", rec)
		}
		seen[rec] = true
	}
}

// containsAny checks if s contains any of the substrings
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
