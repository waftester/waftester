package main

import (
	"testing"

	"github.com/waftester/waftester/pkg/waf/vendors"
)

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 8, "hello..."},
		{"very short max", "hello", 3, "..."},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateStr(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("truncateStr(%q, %d) = %q, expected %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}

func TestDisplayVendorResultsNoPanic(t *testing.T) {
	// Test that displayVendorResults doesn't panic with valid input
	result := &vendors.DetectionResult{
		Detected:   true,
		Vendor:     vendors.VendorCloudflare,
		Confidence: 0.95,
		Evidence:   []string{"cf-ray header", "cloudflare cookie"},
	}

	// Should not panic - we're just verifying it runs
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayVendorResults panicked: %v", r)
		}
	}()

	displayVendorResults(result, true)
}

func TestDisplayVendorResultsNoWAF(t *testing.T) {
	// Test with no WAF detected
	result := &vendors.DetectionResult{
		Detected:   false,
		Vendor:     "",
		Confidence: 0,
		Evidence:   []string{},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayVendorResults panicked with no WAF: %v", r)
		}
	}()

	displayVendorResults(result, false)
}

func TestDisplayVendorResultsWithHints(t *testing.T) {
	result := &vendors.DetectionResult{
		Detected:    true,
		Vendor:      vendors.VendorAWSWAF,
		Confidence:  0.85,
		Evidence:    []string{"x-amzn-waf header"},
		BypassHints: []string{"Try unicode encoding", "Use HTTP/2"},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayVendorResults panicked with hints: %v", r)
		}
	}()

	displayVendorResults(result, true)
}

func TestDisplayVendorResultsWithoutHints(t *testing.T) {
	result := &vendors.DetectionResult{
		Detected:    true,
		Vendor:      vendors.VendorModSecurity,
		Confidence:  0.90,
		Evidence:    []string{"mod_security header"},
		BypassHints: []string{"Test paranoia levels"},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayVendorResults panicked without hints: %v", r)
		}
	}()

	// showHints = false, should not show hints
	displayVendorResults(result, false)
}

func TestVendorDetectionResultTypes(t *testing.T) {
	// Test all known vendor types don't cause issues
	vendorTypes := []vendors.WAFVendor{
		vendors.VendorCloudflare,
		vendors.VendorAWSWAF,
		vendors.VendorAzureWAF,
		vendors.VendorAkamai,
		vendors.VendorImperva,
		vendors.VendorF5BigIP,
		vendors.VendorFortinet,
		vendors.VendorBarracuda,
		vendors.VendorSucuri,
		vendors.VendorModSecurity,
		vendors.VendorWordfence,
		vendors.VendorFastly,
		vendors.VendorCloudArmor,
	}

	for _, vendor := range vendorTypes {
		t.Run(string(vendor), func(t *testing.T) {
			result := &vendors.DetectionResult{
				Detected:   true,
				Vendor:     vendor,
				Confidence: 0.80,
				Evidence:   []string{"test evidence"},
			}

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("displayVendorResults panicked for vendor %s: %v", vendor, r)
				}
			}()

			displayVendorResults(result, true)
		})
	}
}

func TestLowConfidenceResult(t *testing.T) {
	result := &vendors.DetectionResult{
		Detected:   true,
		Vendor:     vendors.VendorUnknown,
		Confidence: 0.30, // Low confidence
		Evidence:   []string{"uncertain indicator"},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("displayVendorResults panicked with low confidence: %v", r)
		}
	}()

	displayVendorResults(result, true)
}

// Note: runVendorDetect and runProtocolDetect use os.Args and external HTTP calls,
// so they are better tested via integration tests. The helper functions above
// test the display logic that can be unit tested.
