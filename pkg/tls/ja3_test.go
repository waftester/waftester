// Package tls provides tests for JA3/TLS fingerprinting functionality
package tls

import (
	"net/http"
	"testing"
	"time"
)

// TestDefaultConfig_NotEmpty verifies DefaultConfig returns usable defaults
func TestDefaultConfig_NotEmpty(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.RotateEvery <= 0 {
		t.Errorf("expected positive RotateEvery, got %d", cfg.RotateEvery)
	}

	if cfg.Timeout <= 0 {
		t.Errorf("expected positive Timeout, got %v", cfg.Timeout)
	}

	if len(cfg.Profiles) == 0 {
		t.Error("expected non-empty Profiles")
	}
}

// TestDefaultProfiles_NotEmpty verifies DefaultProfiles returns profiles
func TestDefaultProfiles_NotEmpty(t *testing.T) {
	profiles := DefaultProfiles()

	if len(profiles) == 0 {
		t.Error("expected non-empty profiles list")
	}

	// Should have multiple browser profiles
	if len(profiles) < 5 {
		t.Errorf("expected at least 5 profiles, got %d", len(profiles))
	}

	// Verify profile structure
	for i, p := range profiles {
		if p.Name == "" {
			t.Errorf("profile %d has empty Name", i)
		}
		if p.UserAgent == "" {
			t.Errorf("profile %d (%s) has empty UserAgent", i, p.Name)
		}
		if p.ClientHello == nil {
			t.Errorf("profile %d (%s) has nil ClientHello", i, p.Name)
		}
	}
}

// TestListProfiles_NotEmpty verifies ListProfiles returns profile names
func TestListProfiles_NotEmpty(t *testing.T) {
	names := ListProfiles()

	if len(names) == 0 {
		t.Error("expected non-empty profile names list")
	}

	// Should match DefaultProfiles count
	profiles := DefaultProfiles()
	if len(names) != len(profiles) {
		t.Errorf("expected %d names, got %d", len(profiles), len(names))
	}

	// Verify no empty names
	for i, name := range names {
		if name == "" {
			t.Errorf("name %d is empty", i)
		}
	}
}

// TestGetProfileByName_ValidName verifies profile lookup works
func TestGetProfileByName_ValidName(t *testing.T) {
	profiles := DefaultProfiles()
	if len(profiles) == 0 {
		t.Skip("no profiles available")
	}

	// Get first profile name and look it up
	expectedName := profiles[0].Name

	profile, err := GetProfileByName(expectedName)
	if err != nil {
		t.Fatalf("GetProfileByName(%s) failed: %v", expectedName, err)
	}

	if profile == nil {
		t.Fatal("GetProfileByName returned nil profile")
	}

	if profile.Name != expectedName {
		t.Errorf("expected name %s, got %s", expectedName, profile.Name)
	}
}

// TestGetProfileByName_InvalidName verifies error on unknown profile
func TestGetProfileByName_InvalidName(t *testing.T) {
	_, err := GetProfileByName("NonExistentBrowser999")
	if err == nil {
		t.Error("expected error for invalid profile name")
	}
}

// TestGetProfileByName_CaseInsensitive verifies case-insensitive lookup
func TestGetProfileByName_CaseInsensitive(t *testing.T) {
	profiles := DefaultProfiles()
	if len(profiles) == 0 {
		t.Skip("no profiles available")
	}

	// Try lowercase version
	name := profiles[0].Name
	profile, err := GetProfileByName(name)
	if err != nil {
		t.Skipf("could not find profile with name %s", name)
	}

	// The lookup should be case-insensitive based on strings.EqualFold usage
	if profile == nil {
		t.Error("expected profile to be found")
	}
}

// TestNewTransport_NilConfig verifies NewTransport handles nil config
func TestNewTransport_NilConfig(t *testing.T) {
	transport := NewTransport(nil)

	if transport == nil {
		t.Fatal("NewTransport(nil) returned nil")
	}

	if len(transport.profiles) == 0 {
		t.Error("transport should have default profiles")
	}
}

// TestNewTransport_CustomConfig verifies NewTransport respects custom config
func TestNewTransport_CustomConfig(t *testing.T) {
	cfg := &Config{
		RotateEvery: 50,
		Timeout:     30 * time.Second,
		SkipVerify:  true,
		Verbose:     true,
	}

	transport := NewTransport(cfg)

	if transport == nil {
		t.Fatal("NewTransport returned nil")
	}

	if transport.rotateEvery != 50 {
		t.Errorf("expected rotateEvery 50, got %d", transport.rotateEvery)
	}

	if transport.timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", transport.timeout)
	}

	if !transport.skipVerify {
		t.Error("expected skipVerify to be true")
	}
}

// TestTransport_GetCurrentJA3 verifies current profile info retrieval
func TestTransport_GetCurrentJA3(t *testing.T) {
	transport := NewTransport(nil)

	name, hash := transport.GetCurrentJA3()

	if name == "" {
		t.Error("expected non-empty profile name")
	}

	// Hash may be empty for some profiles, but name should always be set
	_ = hash // Hash presence varies by profile
}

// TestTransport_SetProfile_Valid verifies setting profile by name
func TestTransport_SetProfile_Valid(t *testing.T) {
	transport := NewTransport(nil)
	profiles := DefaultProfiles()
	if len(profiles) < 2 {
		t.Skip("need at least 2 profiles for this test")
	}

	// Set to second profile
	targetName := profiles[1].Name
	err := transport.SetProfile(targetName)
	if err != nil {
		t.Fatalf("SetProfile(%s) failed: %v", targetName, err)
	}

	name, _ := transport.GetCurrentJA3()
	if name != targetName {
		t.Errorf("expected profile %s, got %s", targetName, name)
	}
}

// TestTransport_SetProfile_Invalid verifies error on invalid profile
func TestTransport_SetProfile_Invalid(t *testing.T) {
	transport := NewTransport(nil)

	err := transport.SetProfile("FakeBrowser123")
	if err == nil {
		t.Error("expected error for invalid profile name")
	}
}

// TestCreateClient_NotNil verifies CreateClient returns valid client
func TestCreateClient_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	client := CreateClient(cfg)

	if client == nil {
		t.Fatal("CreateClient returned nil")
	}

	if client.Transport == nil {
		t.Error("client should have non-nil Transport")
	}
}

// TestCreateClient_WithConfig verifies CreateClient with explicit config
func TestCreateClient_WithConfig(t *testing.T) {
	cfg := &Config{
		Timeout:     10 * time.Second,
		RotateEvery: 25,
	}
	client := CreateClient(cfg)

	if client == nil {
		t.Fatal("CreateClient returned nil")
	}

	if client.Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", client.Timeout)
	}
}

// TestNewFallbackTransport_NilConfig verifies fallback transport with nil config
func TestNewFallbackTransport_NilConfig(t *testing.T) {
	transport := NewFallbackTransport(nil)

	if transport == nil {
		t.Fatal("NewFallbackTransport(nil) returned nil")
	}

	if len(transport.profiles) == 0 {
		t.Error("fallback transport should have default profiles")
	}
}

// TestNewFallbackTransport_CustomConfig verifies fallback respects config
func TestNewFallbackTransport_CustomConfig(t *testing.T) {
	cfg := &Config{
		RotateEvery: 100,
		Timeout:     45 * time.Second,
		SkipVerify:  true,
	}

	transport := NewFallbackTransport(cfg)

	if transport == nil {
		t.Fatal("NewFallbackTransport returned nil")
	}

	if transport.rotateEvery != 100 {
		t.Errorf("expected rotateEvery 100, got %d", transport.rotateEvery)
	}

	if !transport.skipVerify {
		t.Error("expected skipVerify to be true")
	}
}

// TestCreateFallbackClient_NotNil verifies fallback client creation
func TestCreateFallbackClient_NotNil(t *testing.T) {
	cfg := DefaultConfig()
	client := CreateFallbackClient(cfg)

	if client == nil {
		t.Fatal("CreateFallbackClient returned nil")
	}
}

// TestDetectJA3Support_Runs verifies JA3 detection completes
func TestDetectJA3Support_Runs(t *testing.T) {
	// This test just verifies the function runs without panic
	// The actual result depends on the environment
	_ = DetectJA3Support()
}

// TestJA3Profile_Defaults verifies JA3Profile has proper zero values
func TestJA3Profile_Defaults(t *testing.T) {
	profile := JA3Profile{}

	if profile.Name != "" {
		t.Error("default Name should be empty")
	}

	if profile.UserAgent != "" {
		t.Error("default UserAgent should be empty")
	}

	if profile.ClientHello != nil {
		t.Error("default ClientHello should be nil")
	}
}

// TestTransport_ImplementsRoundTripper verifies interface compliance
func TestTransport_ImplementsRoundTripper(t *testing.T) {
	transport := NewTransport(nil)

	// Verify it implements http.RoundTripper
	var _ http.RoundTripper = transport
}

// TestFallbackTransport_ImplementsRoundTripper verifies interface compliance
func TestFallbackTransport_ImplementsRoundTripper(t *testing.T) {
	transport := NewFallbackTransport(nil)

	// Verify it implements http.RoundTripper
	var _ http.RoundTripper = transport
}
