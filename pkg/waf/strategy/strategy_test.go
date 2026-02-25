package strategy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/evasion/advanced/tampers"
	_ "github.com/waftester/waftester/pkg/mutation/encoder"
	_ "github.com/waftester/waftester/pkg/mutation/evasion"
	_ "github.com/waftester/waftester/pkg/mutation/location"
	"github.com/waftester/waftester/pkg/strutil"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

// =============================================================================
// StrategyEngine Tests
// =============================================================================

func TestNewStrategyEngine(t *testing.T) {
	t.Run("with custom timeout", func(t *testing.T) {
		engine := NewStrategyEngine(30 * time.Second)
		if engine == nil {
			t.Fatal("NewStrategyEngine returned nil")
		}
		if engine.timeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", engine.timeout)
		}
		if engine.cache == nil {
			t.Error("Cache should not be nil")
		}
		if engine.detector == nil {
			t.Error("Detector should not be nil")
		}
	})

	t.Run("with zero timeout uses default", func(t *testing.T) {
		engine := NewStrategyEngine(0)
		if engine == nil {
			t.Fatal("NewStrategyEngine returned nil")
		}
		if engine.timeout == 0 {
			t.Error("Timeout should not be zero when default is used")
		}
	})
}

func TestGetStrategy_CacheHit(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)

	// Pre-populate cache
	cachedStrategy := &Strategy{
		Vendor:        vendors.VendorCloudflare,
		VendorName:    "Cloudflare",
		Confidence:    0.95,
		SafeRateLimit: 100,
	}
	engine.cache["https://example.com"] = cachedStrategy

	// Should return cached strategy without making network request
	strategy, err := engine.GetStrategy(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if strategy != cachedStrategy {
		t.Error("Expected cached strategy to be returned")
	}
	if strategy.Vendor != vendors.VendorCloudflare {
		t.Errorf("Expected Cloudflare vendor, got %s", strategy.Vendor)
	}
}

func TestGetStrategy_DetectsCloudflare(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "abc123-IAD")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	engine := NewStrategyEngine(5 * time.Second)
	strategy, err := engine.GetStrategy(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if strategy.Vendor != vendors.VendorCloudflare {
		t.Errorf("Expected Cloudflare, got %s", strategy.Vendor)
	}
	if len(strategy.Encoders) == 0 {
		t.Error("Expected encoders to be populated")
	}
	if strategy.SafeRateLimit == 0 {
		t.Error("Expected SafeRateLimit to be set")
	}
}

func TestGetStrategy_NoWAF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Plain server response"))
	}))
	defer server.Close()

	engine := NewStrategyEngine(5 * time.Second)
	strategy, err := engine.GetStrategy(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should return default strategy
	if strategy.Vendor != vendors.VendorUnknown {
		t.Errorf("Expected Unknown vendor for plain server, got %s", strategy.Vendor)
	}
	if strategy.VendorName != "Unknown/Generic WAF" {
		t.Errorf("Expected 'Unknown/Generic WAF', got %s", strategy.VendorName)
	}
}

func TestGetStrategy_CachesResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	engine := NewStrategyEngine(5 * time.Second)

	// First call
	strategy1, err := engine.GetStrategy(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Second call should return cached result
	strategy2, err := engine.GetStrategy(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if strategy1 != strategy2 {
		t.Error("Expected same strategy instance from cache")
	}
}

func TestGetStrategy_DetectionErrorReturnsDefault(t *testing.T) {
	engine := NewStrategyEngine(1 * time.Millisecond) // Very short timeout

	// Invalid URL that will fail
	strategy, err := engine.GetStrategy(context.Background(), "http://invalid.nonexistent.example:12345")
	if err != nil {
		t.Fatalf("Should not return error, got: %v", err)
	}

	// Should get default strategy
	if strategy == nil {
		t.Fatal("Strategy should not be nil")
	}
	if strategy.Vendor != vendors.VendorUnknown {
		t.Errorf("Expected Unknown vendor on error, got %s", strategy.Vendor)
	}
}

// =============================================================================
// buildStrategy Tests
// =============================================================================

func TestBuildStrategy_AllVendors(t *testing.T) {
	tests := []struct {
		name          string
		vendor        vendors.WAFVendor
		vendorName    string
		wantEncoders  bool
		wantEvasions  bool
		wantRateLimit bool
		minRateLimit  int
		maxRateLimit  int
		mutationDepth int
	}{
		{
			name:          "Cloudflare",
			vendor:        vendors.VendorCloudflare,
			vendorName:    "Cloudflare",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  100,
			maxRateLimit:  100,
			mutationDepth: 2,
		},
		{
			name:          "AWS WAF",
			vendor:        vendors.VendorAWSWAF,
			vendorName:    "AWS WAF",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  200,
			maxRateLimit:  200,
			mutationDepth: 2,
		},
		{
			name:          "Azure WAF",
			vendor:        vendors.VendorAzureWAF,
			vendorName:    "Azure WAF",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  150,
			maxRateLimit:  150,
			mutationDepth: 2,
		},
		{
			name:          "Akamai",
			vendor:        vendors.VendorAkamai,
			vendorName:    "Akamai",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  80,
			maxRateLimit:  80,
			mutationDepth: 3,
		},
		{
			name:          "ModSecurity",
			vendor:        vendors.VendorModSecurity,
			vendorName:    "ModSecurity",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  300,
			maxRateLimit:  300,
			mutationDepth: 2,
		},
		{
			name:          "Imperva",
			vendor:        vendors.VendorImperva,
			vendorName:    "Imperva",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  50,
			maxRateLimit:  50,
			mutationDepth: 3,
		},
		{
			name:          "F5 BigIP",
			vendor:        vendors.VendorF5BigIP,
			vendorName:    "F5 BigIP",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  100,
			maxRateLimit:  100,
			mutationDepth: 2,
		},
		{
			name:          "Fastly",
			vendor:        vendors.VendorFastly,
			vendorName:    "Fastly",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  150,
			maxRateLimit:  150,
			mutationDepth: 2,
		},
		{
			name:          "Cloud Armor",
			vendor:        vendors.VendorCloudArmor,
			vendorName:    "Cloud Armor",
			wantEncoders:  true,
			wantEvasions:  true,
			wantRateLimit: true,
			minRateLimit:  120,
			maxRateLimit:  120,
			mutationDepth: 2,
		},
	}

	engine := NewStrategyEngine(10 * time.Second)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &vendors.DetectionResult{
				Detected:   true,
				Vendor:     tt.vendor,
				VendorName: tt.vendorName,
				Confidence: 0.9,
			}

			strategy := engine.buildStrategy(result)

			if strategy.Vendor != tt.vendor {
				t.Errorf("Expected vendor %s, got %s", tt.vendor, strategy.Vendor)
			}

			if tt.wantEncoders && len(strategy.Encoders) == 0 {
				t.Error("Expected encoders to be populated")
			}

			if tt.wantEvasions && len(strategy.Evasions) == 0 {
				t.Error("Expected evasions to be populated")
			}

			if tt.wantRateLimit && strategy.SafeRateLimit < tt.minRateLimit {
				t.Errorf("SafeRateLimit %d below minimum %d", strategy.SafeRateLimit, tt.minRateLimit)
			}

			if tt.wantRateLimit && strategy.SafeRateLimit > tt.maxRateLimit {
				t.Errorf("SafeRateLimit %d above maximum %d", strategy.SafeRateLimit, tt.maxRateLimit)
			}

			if strategy.RecommendedMutationDepth != tt.mutationDepth {
				t.Errorf("Expected mutation depth %d, got %d", tt.mutationDepth, strategy.RecommendedMutationDepth)
			}

			if len(strategy.BlockStatusCodes) == 0 {
				t.Error("Expected block status codes to be populated")
			}

			if len(strategy.BlockPatterns) == 0 {
				t.Error("Expected block patterns to be populated")
			}
		})
	}
}

func TestBuildStrategy_UndetectedWAF(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)

	result := &vendors.DetectionResult{
		Detected: false,
	}

	strategy := engine.buildStrategy(result)

	if strategy.Vendor != vendors.VendorUnknown {
		t.Errorf("Expected Unknown vendor, got %s", strategy.Vendor)
	}
	if strategy.VendorName != "Unknown/Generic WAF" {
		t.Errorf("Expected 'Unknown/Generic WAF', got %s", strategy.VendorName)
	}
}

func TestBuildStrategy_UnknownVendor(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)

	result := &vendors.DetectionResult{
		Detected:            true,
		Vendor:              vendors.VendorUnknown,
		VendorName:          "Unknown Vendor",
		Confidence:          0.5,
		RecommendedEncoders: []string{"custom_encoder1", "custom_encoder2"},
		RecommendedEvasions: []string{"custom_evasion1"},
	}

	strategy := engine.buildStrategy(result)

	// Should use recommended encoders from detection result
	if len(strategy.Encoders) != 2 || strategy.Encoders[0] != "custom_encoder1" {
		t.Errorf("Expected custom encoders, got %v", strategy.Encoders)
	}
	if len(strategy.Evasions) != 1 || strategy.Evasions[0] != "custom_evasion1" {
		t.Errorf("Expected custom evasions, got %v", strategy.Evasions)
	}
}

func TestBuildStrategy_UnknownVendorNoRecommendations(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)

	result := &vendors.DetectionResult{
		Detected:   true,
		Vendor:     vendors.VendorUnknown,
		VendorName: "Unknown Vendor",
		Confidence: 0.5,
		// No recommended encoders/evasions
	}

	strategy := engine.buildStrategy(result)

	// Should use default fallback encoders
	if len(strategy.Encoders) == 0 {
		t.Error("Expected default encoders for unknown vendor")
	}
	if len(strategy.Evasions) == 0 {
		t.Error("Expected default evasions for unknown vendor")
	}
}

// =============================================================================
// getDefaultStrategy Tests
// =============================================================================

func TestGetDefaultStrategy(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)
	strategy := engine.getDefaultStrategy()

	if strategy.Vendor != vendors.VendorUnknown {
		t.Errorf("Expected Unknown vendor, got %s", strategy.Vendor)
	}

	if strategy.VendorName != "Unknown/Generic WAF" {
		t.Errorf("Expected 'Unknown/Generic WAF', got %s", strategy.VendorName)
	}

	if strategy.Confidence != 0 {
		t.Errorf("Expected 0 confidence, got %f", strategy.Confidence)
	}

	if len(strategy.Encoders) == 0 {
		t.Error("Default strategy should have encoders")
	}

	if len(strategy.Evasions) == 0 {
		t.Error("Default strategy should have evasions")
	}

	if len(strategy.Locations) == 0 {
		t.Error("Default strategy should have locations")
	}

	if strategy.SafeRateLimit == 0 {
		t.Error("Default strategy should have rate limit")
	}

	if len(strategy.BlockStatusCodes) == 0 {
		t.Error("Default strategy should have block status codes")
	}

	if len(strategy.BlockPatterns) == 0 {
		t.Error("Default strategy should have block patterns")
	}
}

// =============================================================================
// Strategy Method Tests
// =============================================================================

func TestStrategy_ToPipelineConfig(t *testing.T) {
	strategy := &Strategy{
		Encoders:                 []string{"url", "double_url", "unicode", "html_hex", "base64"},
		Evasions:                 []string{"case_swap", "sql_comment", "whitespace_alt", "null_byte"},
		Locations:                []string{"query", "body_json", "body_form", "path", "cookie"},
		RecommendedMutationDepth: 2,
	}

	tests := []struct {
		name         string
		depth        int
		wantEncoders int
		wantEvasions int
	}{
		{
			name:         "Depth 0 uses recommended",
			depth:        0,
			wantEncoders: 5,
			wantEvasions: 3, // prioritize(4, 3) = 3
		},
		{
			name:         "Depth 1 quick mode",
			depth:        1,
			wantEncoders: 3, // prioritize(5, 3) = 3
			wantEvasions: 0, // No evasions in quick mode
		},
		{
			name:         "Depth 2 standard mode",
			depth:        2,
			wantEncoders: 5,
			wantEvasions: 3,
		},
		{
			name:         "Depth 3 full mode",
			depth:        3,
			wantEncoders: 5, // Plus chained encodings
			wantEvasions: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := strategy.ToPipelineConfig(tt.depth)
			if config == nil {
				t.Fatal("ToPipelineConfig returned nil")
			}

			// Check encoders count (might be more with expanded encoders in depth 3)
			if tt.depth == 3 {
				if len(config.Encoders) < tt.wantEncoders {
					t.Errorf("Expected at least %d encoders, got %d", tt.wantEncoders, len(config.Encoders))
				}
			} else {
				if len(config.Encoders) != tt.wantEncoders {
					t.Errorf("Expected %d encoders, got %d", tt.wantEncoders, len(config.Encoders))
				}
			}

			if len(config.Evasions) != tt.wantEvasions {
				t.Errorf("Expected %d evasions, got %d", tt.wantEvasions, len(config.Evasions))
			}

			if config.MaxDepth != tt.depth && tt.depth != 0 {
				t.Errorf("Expected MaxDepth %d, got %d", tt.depth, config.MaxDepth)
			}
		})
	}
}

func TestStrategy_GetRateLimitConfig(t *testing.T) {
	strategy := &Strategy{
		SafeRateLimit:   100,
		BurstRateLimit:  500,
		CooldownSeconds: 10,
	}

	rate, burst, cooldown := strategy.GetRateLimitConfig()

	if rate != 100 {
		t.Errorf("Expected rate 100, got %d", rate)
	}
	if burst != 500 {
		t.Errorf("Expected burst 500, got %d", burst)
	}
	if cooldown != 10 {
		t.Errorf("Expected cooldown 10, got %d", cooldown)
	}
}

func TestStrategy_IsBlocked(t *testing.T) {
	strategy := &Strategy{
		BlockStatusCodes: []int{403, 503, 1020},
		BlockPatterns:    []string{"cloudflare", "blocked", "waf"},
	}

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
	}{
		{
			name:       "403 with matching pattern",
			statusCode: 403,
			body:       "Access denied by Cloudflare WAF",
			want:       true,
		},
		{
			name:       "403 with blocked pattern",
			statusCode: 403,
			body:       "Request blocked",
			want:       true,
		},
		{
			name:       "403 short response no pattern",
			statusCode: 403,
			body:       "Forbidden",
			want:       true, // Short 403 responses are treated as WAF blocks
		},
		{
			name:       "503 with pattern",
			statusCode: 503,
			body:       "Service blocked by WAF",
			want:       true,
		},
		{
			name:       "1020 custom code",
			statusCode: 1020,
			body:       "Custom error",
			want:       true,
		},
		{
			name:       "200 OK",
			statusCode: 200,
			body:       "OK",
			want:       false,
		},
		{
			name:       "404 not found",
			statusCode: 404,
			body:       "Not found",
			want:       false,
		},
		{
			name:       "403 long response no pattern - not blocked",
			statusCode: 403,
			body:       strings.Repeat("Lorem ipsum dolor sit amet, ", 400), // > 10000 chars
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strategy.IsBlocked(tt.statusCode, tt.body)
			if got != tt.want {
				t.Errorf("IsBlocked(%d, %q) = %v, want %v", tt.statusCode, strutil.Truncate(tt.body, 50), got, tt.want)
			}
		})
	}
}

func TestStrategy_GetBypassHints(t *testing.T) {
	strategy := &Strategy{
		BypassTips: []string{"Try unicode encoding", "Use case variation"},
	}

	hints := strategy.GetBypassHints()

	if len(hints) != 2 {
		t.Errorf("Expected 2 hints, got %d", len(hints))
	}
	if hints[0] != "Try unicode encoding" {
		t.Errorf("Unexpected first hint: %s", hints[0])
	}
}

func TestStrategy_String(t *testing.T) {
	strategy := &Strategy{
		VendorName:     "Cloudflare",
		Confidence:     0.95,
		Encoders:       []string{"url", "unicode"},
		Evasions:       []string{"case_swap"},
		Locations:      []string{"query", "body"},
		SafeRateLimit:  100,
		BurstRateLimit: 500,
	}

	str := strategy.String()

	if !strings.Contains(str, "Cloudflare") {
		t.Error("String should contain vendor name")
	}
	if !strings.Contains(str, "95%") {
		t.Error("String should contain confidence percentage")
	}
	if !strings.Contains(str, "url") {
		t.Error("String should contain encoders")
	}
	if !strings.Contains(str, "100") {
		t.Error("String should contain rate limit")
	}
}

func TestStrategy_StrategySummary(t *testing.T) {
	tests := []struct {
		name     string
		strategy *Strategy
		contains string
	}{
		{
			name: "Known vendor",
			strategy: &Strategy{
				Vendor:        vendors.VendorCloudflare,
				VendorName:    "Cloudflare",
				Encoders:      []string{"a", "b", "c"},
				Evasions:      []string{"x", "y"},
				SafeRateLimit: 100,
			},
			contains: "Cloudflare-optimized",
		},
		{
			name: "Unknown vendor",
			strategy: &Strategy{
				Vendor: vendors.VendorUnknown,
			},
			contains: "Generic WAF Testing Strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := tt.strategy.StrategySummary()
			if !strings.Contains(summary, tt.contains) {
				t.Errorf("Expected summary to contain %q, got %q", tt.contains, summary)
			}
		})
	}
}

func TestStrategy_Prioritize(t *testing.T) {
	strategy := &Strategy{
		Encoders: []string{"a", "b", "c", "d", "e"},
	}

	tests := []struct {
		name  string
		items []string
		n     int
		want  int
	}{
		{
			name:  "N less than length",
			items: []string{"a", "b", "c", "d", "e"},
			n:     3,
			want:  3,
		},
		{
			name:  "N equals length",
			items: []string{"a", "b", "c"},
			n:     3,
			want:  3,
		},
		{
			name:  "N greater than length",
			items: []string{"a", "b"},
			n:     5,
			want:  2,
		},
		{
			name:  "Empty slice",
			items: []string{},
			n:     3,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strategy.prioritize(tt.items, tt.n)
			if len(result) != tt.want {
				t.Errorf("Expected %d items, got %d", tt.want, len(result))
			}
		})
	}
}

func TestStrategy_ExpandEncoders(t *testing.T) {
	strategy := &Strategy{
		Encoders: []string{"url", "unicode", "base64"},
	}

	expanded := strategy.expandEncoders()

	if len(expanded) < len(strategy.Encoders) {
		t.Errorf("Expanded encoders should be >= original, got %d < %d", len(expanded), len(strategy.Encoders))
	}

	// Check that original encoders are included
	for _, enc := range strategy.Encoders {
		found := false
		for _, e := range expanded {
			if e == enc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Original encoder %s should be in expanded list", enc)
		}
	}

	// Check that chained encodings are added
	hasChained := false
	for _, e := range expanded {
		if strings.Contains(e, "double") || strings.Contains(e, "triple") {
			hasChained = true
			break
		}
	}
	if !hasChained {
		t.Error("Expanded encoders should include chained encodings")
	}
}

// =============================================================================
// MergeStrategies Tests
// =============================================================================

func TestMergeStrategies_Empty(t *testing.T) {
	result := MergeStrategies()
	if result != nil {
		t.Error("Merging empty strategies should return nil")
	}
}

func TestMergeStrategies_Single(t *testing.T) {
	strategy := &Strategy{
		Vendor:        vendors.VendorCloudflare,
		SafeRateLimit: 100,
	}

	result := MergeStrategies(strategy)
	if result != strategy {
		t.Error("Merging single strategy should return same strategy")
	}
}

func TestMergeStrategies_Multiple(t *testing.T) {
	s1 := &Strategy{
		Vendor:                   vendors.VendorCloudflare,
		SafeRateLimit:            100,
		BurstRateLimit:           1000,
		CooldownSeconds:          10,
		RecommendedMutationDepth: 2,
		Encoders:                 []string{"url", "unicode"},
		Evasions:                 []string{"case_swap"},
		Locations:                []string{"query", "body"},
		BlockStatusCodes:         []int{403},
		BlockPatterns:            []string{"cloudflare"},
		BypassTips:               []string{"tip1"},
	}

	s2 := &Strategy{
		Vendor:                   vendors.VendorImperva,
		SafeRateLimit:            50, // More restrictive
		BurstRateLimit:           300,
		CooldownSeconds:          20,                            // Longer cooldown
		RecommendedMutationDepth: 3,                             // Higher depth
		Encoders:                 []string{"unicode", "base64"}, // unicode overlaps
		Evasions:                 []string{"sql_comment"},
		Locations:                []string{"query", "cookie"}, // query overlaps
		BlockStatusCodes:         []int{403, 406},
		BlockPatterns:            []string{"imperva"},
		BypassTips:               []string{"tip2"},
	}

	result := MergeStrategies(s1, s2)

	if result.Vendor != vendors.VendorUnknown {
		t.Errorf("Merged vendor should be Unknown, got %s", result.Vendor)
	}

	if result.VendorName != "Multi-WAF" {
		t.Errorf("Merged vendor name should be 'Multi-WAF', got %s", result.VendorName)
	}

	// Should use most restrictive rate limit
	if result.SafeRateLimit != 50 {
		t.Errorf("Expected SafeRateLimit 50, got %d", result.SafeRateLimit)
	}

	if result.BurstRateLimit != 300 {
		t.Errorf("Expected BurstRateLimit 300, got %d", result.BurstRateLimit)
	}

	// Should use longest cooldown
	if result.CooldownSeconds != 20 {
		t.Errorf("Expected CooldownSeconds 20, got %d", result.CooldownSeconds)
	}

	// Should use highest mutation depth
	if result.RecommendedMutationDepth != 3 {
		t.Errorf("Expected RecommendedMutationDepth 3, got %d", result.RecommendedMutationDepth)
	}

	// Should merge unique encoders
	if len(result.Encoders) < 3 {
		t.Errorf("Expected at least 3 unique encoders, got %d", len(result.Encoders))
	}

	// Should merge block codes
	if len(result.BlockStatusCodes) < 2 {
		t.Errorf("Expected at least 2 block codes, got %d", len(result.BlockStatusCodes))
	}

	// Should merge tips
	if len(result.BypassTips) < 2 {
		t.Errorf("Expected at least 2 bypass tips, got %d", len(result.BypassTips))
	}
}

// =============================================================================
// Pipeline Integration Tests
// =============================================================================

func TestWAFOptimizedPipeline_NilStrategy(t *testing.T) {
	config := WAFOptimizedPipeline(nil, "standard")
	if config == nil {
		t.Fatal("Should return default config for nil strategy")
	}
}

func TestWAFOptimizedPipeline_Modes(t *testing.T) {
	strategy := &Strategy{
		Encoders:  []string{"url", "unicode", "base64", "html_hex"},
		Evasions:  []string{"case_swap", "sql_comment", "whitespace_alt"},
		Locations: []string{"query", "body_json", "path"},
	}

	tests := []struct {
		mode           string
		wantRaw        bool
		wantChaining   bool
		minEncoders    int
		minLocations   int
		expectEvasions bool
	}{
		{
			mode:           "quick",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    3,
			minLocations:   2,
			expectEvasions: false,
		},
		{
			mode:           "fast",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    3,
			minLocations:   2,
			expectEvasions: false,
		},
		{
			mode:           "standard",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
		{
			mode:           "default",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
		{
			mode:           "",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
		{
			mode:           "full",
			wantRaw:        true,
			wantChaining:   true,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
		{
			mode:           "comprehensive",
			wantRaw:        true,
			wantChaining:   true,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
		{
			mode:           "bypass",
			wantRaw:        true,
			wantChaining:   true,
			minEncoders:    10, // All encoders
			minLocations:   10, // All locations
			expectEvasions: true,
		},
		{
			mode:           "aggressive",
			wantRaw:        true,
			wantChaining:   true,
			minEncoders:    10,
			minLocations:   10,
			expectEvasions: true,
		},
		{
			mode:           "stealth",
			wantRaw:        true,
			wantChaining:   false,
			minEncoders:    4,
			minLocations:   3,
			expectEvasions: true,
		},
	}

	for _, tt := range tests {
		t.Run("mode_"+tt.mode, func(t *testing.T) {
			config := WAFOptimizedPipeline(strategy, tt.mode)
			if config == nil {
				t.Fatal("WAFOptimizedPipeline returned nil")
			}

			if config.IncludeRaw != tt.wantRaw {
				t.Errorf("IncludeRaw = %v, want %v", config.IncludeRaw, tt.wantRaw)
			}

			if config.ChainEncodings != tt.wantChaining {
				t.Errorf("ChainEncodings = %v, want %v", config.ChainEncodings, tt.wantChaining)
			}

			if len(config.Encoders) < tt.minEncoders {
				t.Errorf("Expected at least %d encoders, got %d", tt.minEncoders, len(config.Encoders))
			}

			if len(config.Locations) < tt.minLocations {
				t.Errorf("Expected at least %d locations, got %d", tt.minLocations, len(config.Locations))
			}

			hasEvasions := len(config.Evasions) > 0
			if hasEvasions != tt.expectEvasions {
				t.Errorf("Evasions presence = %v, want %v", hasEvasions, tt.expectEvasions)
			}
		})
	}
}

func TestMapLocationsToMutation(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "Maps query",
			input:  []string{"query"},
			expect: []string{"query_param"},
		},
		{
			name:   "Maps body_json",
			input:  []string{"body_json"},
			expect: []string{"post_json"},
		},
		{
			name:   "Maps body_form",
			input:  []string{"body_form"},
			expect: []string{"post_form"},
		},
		{
			name:   "Maps body_xml",
			input:  []string{"body_xml"},
			expect: []string{"post_xml"},
		},
		{
			name:   "Maps path",
			input:  []string{"path"},
			expect: []string{"path_segment"},
		},
		{
			name:   "Maps header",
			input:  []string{"header"},
			expect: []string{"header_custom"},
		},
		{
			name:   "Passes through cookie",
			input:  []string{"cookie"},
			expect: []string{"cookie"},
		},
		{
			name:   "Empty input returns defaults",
			input:  []string{},
			expect: []string{"query_param", "post_form", "post_json"},
		},
		{
			name:   "Passes through unknown",
			input:  []string{"unknown_location"},
			expect: []string{"unknown_location"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapLocationsToMutation(tt.input)

			if len(tt.input) == 0 {
				// Check defaults
				if len(result) < 3 {
					t.Errorf("Expected at least 3 default locations, got %d", len(result))
				}
			} else {
				if len(result) != len(tt.expect) {
					t.Errorf("Expected %d locations, got %d", len(tt.expect), len(result))
				}
				for i, e := range tt.expect {
					if i < len(result) && result[i] != e {
						t.Errorf("Expected location[%d] = %s, got %s", i, e, result[i])
					}
				}
			}
		})
	}
}

func TestMapEvasionsToMutation(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "Maps legacy names",
			input:  []string{"unicode_normalization"},
			expect: []string{"unicode_normalize"},
		},
		{
			name:   "Maps comment_wrapping",
			input:  []string{"comment_wrapping"},
			expect: []string{"comment_wrap"},
		},
		{
			name:   "Maps content_type",
			input:  []string{"content_type"},
			expect: []string{"content_type_mismatch"},
		},
		{
			name:   "Passes through standard names",
			input:  []string{"case_swap", "sql_comment"},
			expect: []string{"case_swap", "sql_comment"},
		},
		{
			name:   "Deduplicates",
			input:  []string{"case_swap", "case_swap"},
			expect: []string{"case_swap"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapEvasionsToMutation(tt.input)

			if len(result) != len(tt.expect) {
				t.Errorf("Expected %d evasions, got %d: %v", len(tt.expect), len(result), result)
			}
			for i, e := range tt.expect {
				if i < len(result) && result[i] != e {
					t.Errorf("Expected evasion[%d] = %s, got %s", i, e, result[i])
				}
			}
		})
	}
}

func TestExpandEncoders(t *testing.T) {
	base := []string{"url", "unicode"}

	result := expandEncoders(base)

	if len(result) < len(base) {
		t.Errorf("Expanded should be >= base, got %d < %d", len(result), len(base))
	}

	// Check that base encoders are present
	for _, b := range base {
		found := false
		for _, r := range result {
			if r == b {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Base encoder %s should be in expanded result", b)
		}
	}

	// Should include related encoders
	hasRelated := len(result) > len(base)
	if !hasRelated {
		t.Log("No related encoders found, check relatedEncoders mapping")
	}
}

func TestRelatedEncoders(t *testing.T) {
	tests := []struct {
		encoder string
		hasAny  bool
	}{
		{"url", true},
		{"double_url", true},
		{"unicode", true},
		{"html_entities", true},
		{"html_decimal", true},
		{"base64", true},
		{"hex", true},
		{"unknown_encoder", false},
	}

	for _, tt := range tests {
		t.Run(tt.encoder, func(t *testing.T) {
			result := relatedEncoders(tt.encoder)
			hasRelated := len(result) > 0
			if hasRelated != tt.hasAny {
				t.Errorf("relatedEncoders(%s) has related = %v, want %v", tt.encoder, hasRelated, tt.hasAny)
			}
		})
	}
}

func TestGetAllEncoders(t *testing.T) {
	encoders := getAllEncoders()

	if len(encoders) < 10 {
		t.Errorf("Expected at least 10 encoders, got %d", len(encoders))
	}

	// Check for essential encoders
	essential := []string{"raw", "url", "unicode", "base64", "html_hex"}
	for _, e := range essential {
		found := false
		for _, enc := range encoders {
			if enc == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential encoder %s not found", e)
		}
	}
}

func TestGetAllLocations(t *testing.T) {
	locations := getAllLocations()

	if len(locations) < 8 {
		t.Errorf("Expected at least 8 locations, got %d", len(locations))
	}

	// Check for essential locations
	essential := []string{"query_param", "post_form", "post_json", "cookie"}
	for _, l := range essential {
		found := false
		for _, loc := range locations {
			if loc == l {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential location %s not found", l)
		}
	}
}

func TestGetAllEvasions(t *testing.T) {
	evasions := getAllEvasions()

	if len(evasions) < 5 {
		t.Errorf("Expected at least 5 evasions, got %d", len(evasions))
	}

	// Check for essential evasions
	essential := []string{"case_swap", "sql_comment", "null_byte"}
	for _, e := range essential {
		found := false
		for _, ev := range evasions {
			if ev == e {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential evasion %s not found", e)
		}
	}
}

// =============================================================================
// Strategy Rate Limit and Concurrency Tests
// =============================================================================

func TestStrategy_GetOptimalRateLimit(t *testing.T) {
	strategy := &Strategy{
		SafeRateLimit:  100,
		BurstRateLimit: 500,
	}

	tests := []struct {
		mode          string
		wantRate      float64
		wantBurst     int
		rateAssertion func(float64) bool
	}{
		{
			mode:      "stealth",
			wantRate:  50,
			wantBurst: 100,
		},
		{
			mode:      "slow",
			wantRate:  50,
			wantBurst: 100,
		},
		{
			mode:      "fast",
			wantRate:  500,
			wantBurst: 1000,
		},
		{
			mode:      "aggressive",
			wantRate:  500,
			wantBurst: 1000,
		},
		{
			mode:      "standard",
			wantRate:  100,
			wantBurst: 500,
		},
		{
			mode:      "",
			wantRate:  100,
			wantBurst: 500,
		},
	}

	for _, tt := range tests {
		t.Run("mode_"+tt.mode, func(t *testing.T) {
			rate, burst := strategy.GetOptimalRateLimit(tt.mode)

			if rate != tt.wantRate {
				t.Errorf("Rate = %f, want %f", rate, tt.wantRate)
			}
			if burst != tt.wantBurst {
				t.Errorf("Burst = %d, want %d", burst, tt.wantBurst)
			}
		})
	}
}

func TestStrategy_GetRecommendedConcurrency(t *testing.T) {
	strategy := &Strategy{}

	tests := []struct {
		mode            string
		wantConcurrency int
	}{
		{"stealth", 5},
		{"slow", 5},
		{"fast", 100},
		{"aggressive", 100},
		{"full", 50},
		{"standard", 20},
		{"", 20},
	}

	for _, tt := range tests {
		t.Run("mode_"+tt.mode, func(t *testing.T) {
			concurrency := strategy.GetRecommendedConcurrency(tt.mode)
			if concurrency != tt.wantConcurrency {
				t.Errorf("Concurrency = %d, want %d", concurrency, tt.wantConcurrency)
			}
		})
	}
}

func TestCreateOptimizedConfig(t *testing.T) {
	strategy := &Strategy{
		Vendor:        vendors.VendorCloudflare,
		SafeRateLimit: 100,
		Encoders:      []string{"url", "unicode"},
		Evasions:      []string{"case_swap"},
		Locations:     []string{"query", "body_json"},
	}

	config := CreateOptimizedConfig(strategy, "standard", "https://example.com")
	if config == nil {
		t.Fatal("CreateOptimizedConfig returned nil")
	}

	if config.TargetURL != "https://example.com" {
		t.Errorf("Expected target URL 'https://example.com', got %s", config.TargetURL)
	}

	if config.Concurrency != 20 { // Standard mode default
		t.Errorf("Expected concurrency 20, got %d", config.Concurrency)
	}

	if config.RateLimit != 100 {
		t.Errorf("Expected rate limit 100, got %f", config.RateLimit)
	}

	if config.Pipeline == nil {
		t.Error("Pipeline should not be nil")
	}

	if !config.AnalyzeResponses {
		t.Error("AnalyzeResponses should be true")
	}

	if !config.CollectFingerprint {
		t.Error("CollectFingerprint should be true")
	}

	if !config.AutoCalibrate {
		t.Error("AutoCalibrate should be true")
	}

	if !config.RealisticMode {
		t.Error("RealisticMode should be true for standard mode")
	}
}

func TestCreateOptimizedConfig_AggressiveMode(t *testing.T) {
	strategy := &Strategy{
		SafeRateLimit:  100,
		BurstRateLimit: 500,
	}

	config := CreateOptimizedConfig(strategy, "aggressive", "https://example.com")

	if config.RealisticMode {
		t.Error("RealisticMode should be false for aggressive mode")
	}

	if config.Concurrency != 100 {
		t.Errorf("Expected concurrency 100 for aggressive mode, got %d", config.Concurrency)
	}
}

// =============================================================================
// Payload Prioritization Tests
// =============================================================================

func TestStrategy_ShouldSkipPayload(t *testing.T) {
	strategy := &Strategy{}

	// Currently returns false for all - test the interface
	if strategy.ShouldSkipPayload("sqli") {
		t.Error("ShouldSkipPayload should return false by default")
	}
	if strategy.ShouldSkipPayload("xss") {
		t.Error("ShouldSkipPayload should return false by default")
	}
}

func TestStrategy_PrioritizePayloads(t *testing.T) {
	strategy := &Strategy{}

	categories := []string{"xss", "sqli", "traversal", "ssrf", "ssti"}

	result := strategy.PrioritizePayloads(categories)

	if len(result) != len(categories) {
		t.Errorf("Expected %d categories, got %d", len(categories), len(result))
	}

	// SQLi should be first (priority 1)
	if result[0] != "sqli" {
		t.Errorf("Expected 'sqli' first, got %s", result[0])
	}

	// XSS should be before traversal
	sqliIdx := indexOf(result, "sqli")
	xssIdx := indexOf(result, "xss")
	traversalIdx := indexOf(result, "traversal")

	if sqliIdx > xssIdx {
		t.Error("sqli should come before xss")
	}
	if xssIdx > traversalIdx {
		t.Error("xss should come before traversal")
	}
}

func TestStrategy_PrioritizePayloads_Unknown(t *testing.T) {
	strategy := &Strategy{}

	// Unknown categories should be sorted to the end
	categories := []string{"unknown1", "sqli", "unknown2", "xss"}

	result := strategy.PrioritizePayloads(categories)

	sqliIdx := indexOf(result, "sqli")
	unknown1Idx := indexOf(result, "unknown1")
	unknown2Idx := indexOf(result, "unknown2")

	if sqliIdx > unknown1Idx || sqliIdx > unknown2Idx {
		t.Error("Known categories should come before unknown ones")
	}
}

// =============================================================================
// Tamper Integration Tests
// =============================================================================

func TestStrategy_GetTamperEngine(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	engine := strategy.GetTamperEngine(tampers.ProfileStandard)
	if engine == nil {
		t.Fatal("GetTamperEngine returned nil")
	}
}

func TestStrategy_GetRecommendedTampers(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	tamperList := strategy.GetRecommendedTampers()

	// Should return at least some tampers for known WAF
	if len(tamperList) == 0 {
		t.Log("No tampers returned for Cloudflare - this may be expected if matrix is empty")
	}
}

func TestStrategy_GetTopTampers(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	topTampers := strategy.GetTopTampers(3)

	if len(topTampers) > 3 {
		t.Errorf("Expected at most 3 tampers, got %d", len(topTampers))
	}
}

func TestStrategy_GetTamperRecommendations(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	recommendations := strategy.GetTamperRecommendations()

	// Just verify it doesn't panic and returns a slice
	if recommendations == nil {
		t.Log("Recommendations returned nil - initializing as empty slice might be preferred")
	}
}

func TestStrategy_TamperAwareTransform(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	payload := "SELECT * FROM users"
	transformed := strategy.TamperAwareTransform(payload, tampers.ProfileStandard)

	// Should return something (may be same or modified)
	if transformed == "" {
		t.Error("TamperAwareTransform returned empty string")
	}
}

func TestStrategy_TamperChain(t *testing.T) {
	strategy := &Strategy{
		Vendor: vendors.VendorCloudflare,
	}

	chain := strategy.TamperChain(tampers.ProfileStandard)

	// Should return a slice (may be empty)
	if chain == nil {
		t.Error("TamperChain returned nil")
	}
}

// =============================================================================
// Helper Functions Tests
// =============================================================================

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name   string
		slice  []int
		items  []int
		expect []int
	}{
		{
			name:   "Add new items",
			slice:  []int{1, 2, 3},
			items:  []int{4, 5},
			expect: []int{1, 2, 3, 4, 5},
		},
		{
			name:   "Skip duplicates",
			slice:  []int{1, 2, 3},
			items:  []int{2, 3, 4},
			expect: []int{1, 2, 3, 4},
		},
		{
			name:   "Empty slice",
			slice:  []int{},
			items:  []int{1, 2},
			expect: []int{1, 2},
		},
		{
			name:   "No items to add",
			slice:  []int{1, 2},
			items:  []int{},
			expect: []int{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUnique(tt.slice, tt.items...)

			if len(result) != len(tt.expect) {
				t.Errorf("Expected length %d, got %d", len(tt.expect), len(result))
			}
		})
	}
}

func TestAppendUniqueStr(t *testing.T) {
	tests := []struct {
		name   string
		slice  []string
		items  []string
		expect []string
	}{
		{
			name:   "Add new items",
			slice:  []string{"a", "b"},
			items:  []string{"c"},
			expect: []string{"a", "b", "c"},
		},
		{
			name:   "Skip duplicates",
			slice:  []string{"a", "b"},
			items:  []string{"b", "c"},
			expect: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUniqueStr(tt.slice, tt.items...)

			if len(result) != len(tt.expect) {
				t.Errorf("Expected length %d, got %d", len(tt.expect), len(result))
			}
		})
	}
}

func TestSortByFrequency(t *testing.T) {
	freqMap := map[string]int{
		"low":    1,
		"medium": 5,
		"high":   10,
	}

	result := sortByFrequency(freqMap)

	if len(result) != 3 {
		t.Errorf("Expected 3 items, got %d", len(result))
	}

	// Should be sorted by frequency descending
	if result[0] != "high" {
		t.Errorf("Expected 'high' first, got %s", result[0])
	}
	if result[1] != "medium" {
		t.Errorf("Expected 'medium' second, got %s", result[1])
	}
	if result[2] != "low" {
		t.Errorf("Expected 'low' third, got %s", result[2])
	}
}

func TestSortByFrequency_Empty(t *testing.T) {
	freqMap := map[string]int{}
	result := sortByFrequency(freqMap)

	if len(result) != 0 {
		t.Errorf("Expected empty result, got %d items", len(result))
	}
}

// =============================================================================
// Test Helpers
// =============================================================================



func indexOf(slice []string, item string) int {
	for i, s := range slice {
		if s == item {
			return i
		}
	}
	return -1
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestStrategyEngine_ConcurrentAccess(t *testing.T) {
	engine := NewStrategyEngine(10 * time.Second)

	// Pre-populate with a cached strategy
	engine.cache["https://cached.example.com"] = &Strategy{
		Vendor:     vendors.VendorCloudflare,
		VendorName: "Cloudflare",
	}

	// Concurrent reads should not race
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := engine.GetStrategy(context.Background(), "https://cached.example.com")
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestStrategy_ThreadSafe(t *testing.T) {
	strategy := &Strategy{
		Encoders:         []string{"url", "unicode"},
		Evasions:         []string{"case_swap"},
		Locations:        []string{"query"},
		BlockStatusCodes: []int{403},
		BlockPatterns:    []string{"blocked"},
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_ = strategy.String()
			_ = strategy.StrategySummary()
			_ = strategy.IsBlocked(403, "blocked")
			_ = strategy.GetBypassHints()
			_, _, _ = strategy.GetRateLimitConfig()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}
