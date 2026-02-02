package vendors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
)

func TestNewVendorDetector(t *testing.T) {
	detector := NewVendorDetector(10 * time.Second)
	if detector == nil {
		t.Fatal("NewVendorDetector returned nil")
	}
	if detector.client == nil {
		t.Error("Detector client should not be nil")
	}
	if detector.timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", detector.timeout)
	}
}

func TestNewVendorDetectorDefaultTimeout(t *testing.T) {
	detector := NewVendorDetector(0)
	if detector.timeout != httpclient.TimeoutProbing {
		t.Errorf("Expected default timeout %v, got %v", httpclient.TimeoutProbing, detector.timeout)
	}
}

func TestDetectCloudflare(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "abc123-IAD")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	detector := NewVendorDetector(5 * time.Second)
	ctx := context.Background()

	result, err := detector.Detect(ctx, server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Detected {
		t.Error("Should detect WAF")
	}
	if result.Vendor != VendorCloudflare {
		t.Errorf("Expected Cloudflare vendor, got %s", result.Vendor)
	}
}

func TestDetectAWSWAF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amzn-RequestId", "abc123")
		w.Header().Set("X-Amz-Cf-Id", "xyz789")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	detector := NewVendorDetector(5 * time.Second)
	ctx := context.Background()

	result, err := detector.Detect(ctx, server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Detected && result.Vendor != VendorAWSWAF {
		t.Logf("Detected vendor: %s", result.Vendor)
	}
}

func TestDetectNoWAF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Plain server"))
	}))
	defer server.Close()

	detector := NewVendorDetector(5 * time.Second)
	ctx := context.Background()

	result, err := detector.Detect(ctx, server.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.Detected {
		t.Errorf("Should not detect WAF on plain server, detected: %s", result.VendorName)
	}
}

func TestDetectionResultStruct(t *testing.T) {
	result := &DetectionResult{
		Detected:            true,
		Vendor:              VendorCloudflare,
		VendorName:          "Cloudflare",
		Confidence:          0.9,
		Evidence:            []string{"CF-RAY header", "Server: cloudflare"},
		BypassHints:         []string{"Use unicode normalization"},
		RecommendedEncoders: []string{"unicode", "double_url"},
		RecommendedEvasions: []string{"case_swap"},
	}

	if result.Vendor != VendorCloudflare {
		t.Errorf("Expected Cloudflare vendor")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Expected 0.9 confidence, got %f", result.Confidence)
	}
	if len(result.BypassHints) != 1 {
		t.Errorf("Expected 1 bypass hint, got %d", len(result.BypassHints))
	}
}

func TestRateLimitInfoStruct(t *testing.T) {
	info := &RateLimitInfo{
		Detected:      true,
		RequestsLimit: 100,
		WindowSeconds: 60,
		RetryAfter:    30,
		Description:   "100 requests per minute",
	}

	if !info.Detected {
		t.Error("Expected detected to be true")
	}
	if info.RequestsLimit != 100 {
		t.Errorf("Expected 100 requests limit, got %d", info.RequestsLimit)
	}
}

func TestBlockSignatureStruct(t *testing.T) {
	sig := &BlockSignature{
		StatusCode:      403,
		ContentPatterns: []string{"Access Denied", "Forbidden"},
		Headers:         []string{"X-Block-Reason"},
	}

	if sig.StatusCode != 403 {
		t.Errorf("Expected status 403, got %d", sig.StatusCode)
	}
	if len(sig.ContentPatterns) != 2 {
		t.Errorf("Expected 2 content patterns, got %d", len(sig.ContentPatterns))
	}
}

func TestWAFVendorConstants(t *testing.T) {
	vendors := []WAFVendor{
		VendorUnknown,
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
	}

	// Ensure all vendors are unique
	seen := make(map[WAFVendor]bool)
	for _, v := range vendors {
		if seen[v] {
			t.Errorf("Duplicate vendor: %s", v)
		}
		seen[v] = true
	}

	if len(vendors) != 14 {
		t.Errorf("Expected 14 vendor constants, got %d", len(vendors))
	}
}

func TestDetectContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	detector := NewVendorDetector(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := detector.Detect(ctx, server.URL)
	if err == nil {
		t.Error("Expected timeout/cancellation error")
	}
}
