package vendors

import (
	"testing"
)

func TestGetAutoTuneConfig(t *testing.T) {
	result := &DetectionResult{
		Vendor:   VendorCloudflare,
		Detected: true, // Must be detected to get vendor-specific config
	}

	config := GetAutoTuneConfig(result)
	if config == nil {
		t.Fatal("GetAutoTuneConfig returned nil")
	}
	if config.Vendor != VendorCloudflare {
		t.Errorf("Expected vendor Cloudflare, got '%s'", config.Vendor)
	}
}

func TestGetAutoTuneConfigAllVendors(t *testing.T) {
	vendors := []WAFVendor{
		VendorCloudflare,
		VendorAWSWAF,
		VendorAzureWAF,
		VendorAkamai,
		VendorModSecurity,
		VendorImperva,
		VendorF5BigIP,
		VendorFortinet,
		VendorBarracuda,
		VendorSucuri,
		VendorWordfence,
		VendorFastly,
		VendorCloudArmor,
		VendorUnknown,
	}

	for _, vendor := range vendors {
		result := &DetectionResult{Vendor: vendor, Detected: true}
		config := GetAutoTuneConfig(result)

		if config == nil {
			t.Errorf("GetAutoTuneConfig returned nil for vendor %s", vendor)
			continue
		}

		// All configs should have reasonable defaults
		if config.RateLimitRPS <= 0 {
			t.Errorf("Vendor %s should have positive rate limit", vendor)
		}
		if config.ConcurrencyLimit <= 0 {
			t.Errorf("Vendor %s should have positive concurrency limit", vendor)
		}
	}
}

func TestAutoTuneConfigStruct(t *testing.T) {
	config := &AutoTuneConfig{
		Vendor:             VendorCloudflare,
		MutationStrategy:   "aggressive",
		EnabledMutations:   []string{"unicode", "case_swap"},
		DisabledMutations:  []string{"null_byte"},
		PreferredEncodings: []string{"unicode", "double_url"},
		ConcurrencyLimit:   10,
		RateLimitRPS:       50,
		RequestDelayMs:     100,
		RetryOnBlock:       true,
		BypassMode:         true,
		Notes:              []string{"Test note"},
	}

	if config.Vendor != VendorCloudflare {
		t.Errorf("Expected Cloudflare vendor")
	}
	if config.RateLimitRPS != 50 {
		t.Errorf("Expected rate limit 50, got %f", config.RateLimitRPS)
	}
	if len(config.EnabledMutations) != 2 {
		t.Errorf("Expected 2 enabled mutations, got %d", len(config.EnabledMutations))
	}
}

func TestFormatAutoTuneReport(t *testing.T) {
	result := &DetectionResult{
		Detected:   true,
		Vendor:     VendorCloudflare,
		VendorName: "Cloudflare",
	}
	config := GetAutoTuneConfig(result)

	report := FormatAutoTuneReport(result, config)
	if report == "" {
		t.Error("Report should not be empty")
	}
	if len(report) < 100 {
		t.Error("Report seems too short")
	}
}

func TestFormatAutoTuneReportUndetected(t *testing.T) {
	result := &DetectionResult{
		Detected: false,
		Vendor:   VendorUnknown,
	}
	config := GetAutoTuneConfig(result)

	report := FormatAutoTuneReport(result, config)
	if report == "" {
		t.Error("Report should not be empty even for undetected WAF")
	}
}

func TestCloudflareConfig(t *testing.T) {
	result := &DetectionResult{Vendor: VendorCloudflare, Detected: true}
	config := GetAutoTuneConfig(result)

	// Cloudflare-specific checks
	hasUnicode := false
	for _, m := range config.EnabledMutations {
		if m == "unicode" || m == "utf8" {
			hasUnicode = true
			break
		}
	}
	if !hasUnicode {
		t.Log("Cloudflare config may recommend unicode mutations")
	}
}

func TestModSecurityConfig(t *testing.T) {
	result := &DetectionResult{Vendor: VendorModSecurity, Detected: true}
	config := GetAutoTuneConfig(result)

	// ModSecurity is usually more flexible on rate limits
	if config.RateLimitRPS < 10 {
		t.Error("ModSecurity config should allow reasonable rate limits")
	}
}

func TestAWSWAFConfig(t *testing.T) {
	result := &DetectionResult{Vendor: VendorAWSWAF, Detected: true}
	config := GetAutoTuneConfig(result)

	if config.Vendor != VendorAWSWAF {
		t.Errorf("Expected AWS WAF vendor, got '%s'", config.Vendor)
	}
}

func TestAzureWAFConfig(t *testing.T) {
	result := &DetectionResult{Vendor: VendorAzureWAF, Detected: true}
	config := GetAutoTuneConfig(result)

	if config.Vendor != VendorAzureWAF {
		t.Errorf("Expected Azure WAF vendor, got '%s'", config.Vendor)
	}
}
