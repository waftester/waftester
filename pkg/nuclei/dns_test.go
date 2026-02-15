package nuclei

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSRequest_LookupA(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-a",
		Name: "example.com",
		Type: "A",
		Matchers: []Matcher{
			{Type: "regex", Regex: []string{`\d+\.\d+\.\d+\.\d+`}},
		},
	}

	vars := map[string]string{}
	matched, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.True(t, matched, "example.com should resolve to an IPv4 address")
}

func TestDNSRequest_LookupTXT(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-txt",
		Name: "example.com",
		Type: "TXT",
	}

	vars := map[string]string{}
	_, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	// TXT lookup may or may not have records, but should not error
	assert.NoError(t, err)
}

func TestDNSRequest_LookupCNAME(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-cname",
		Name: "example.com",
		Type: "CNAME",
	}

	vars := map[string]string{}
	_, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	assert.NoError(t, err)
}

func TestDNSRequest_UnsupportedType(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-bad",
		Name: "example.com",
		Type: "INVALID",
	}

	vars := map[string]string{}
	_, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported DNS type")
}

func TestDNSRequest_VariableExpansion(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-var",
		Name: "{{domain}}",
		Type: "A",
	}

	vars := map[string]string{"domain": "example.com"}
	_, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	assert.NoError(t, err)
}

func TestDNSRequest_Extractor(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-extract",
		Name: "example.com",
		Type: "A",
		Extractors: []Extractor{
			{
				Type:  "regex",
				Name:  "ip",
				Regex: []string{`(\d+\.\d+\.\d+\.\d+)`},
				Group: 1,
			},
		},
	}

	vars := map[string]string{}
	_, extracted, err := engine.executeDNSRequest(context.Background(), req, vars)
	require.NoError(t, err)
	assert.NotEmpty(t, extracted["ip"], "should extract an IP address")
}

func TestDNSRequest_DefaultType(t *testing.T) {
	engine := NewEngine()
	req := &DNSRequest{
		ID:   "dns-default",
		Name: "example.com",
		// Type intentionally empty — should default to A
	}

	vars := map[string]string{}
	_, _, err := engine.executeDNSRequest(context.Background(), req, vars)
	assert.NoError(t, err)
}
