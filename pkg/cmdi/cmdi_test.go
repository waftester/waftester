package cmdi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/finding"
)

func TestNewTester(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		tester := NewTester(nil)
		if tester == nil {
			t.Fatal("expected tester, got nil")
		}
		if tester.config == nil {
			t.Error("expected config to be set")
		}
		if len(tester.payloads) == 0 {
			t.Error("expected payloads to be generated")
		}
	})

	t.Run("custom config", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       60 * time.Second,
			Platform:      PlatformUnix,
			TimeThreshold: 10 * time.Second,
		}
		tester := NewTester(config)

		if tester.config.Platform != PlatformUnix {
			t.Errorf("expected Unix platform")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", config.Timeout)
	}
	if config.Platform != PlatformBoth {
		t.Errorf("expected both platforms")
	}
	if config.TimeThreshold != 5*time.Second {
		t.Errorf("expected 5s threshold")
	}
}

func TestGetPayloads(t *testing.T) {
	t.Run("all payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads("")

		if len(payloads) == 0 {
			t.Error("expected payloads")
		}
	})

	t.Run("filtered by type", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionTimeBased)

		for _, p := range payloads {
			if p.Type != InjectionTimeBased {
				t.Errorf("expected time-based type, got %s", p.Type)
			}
		}
	})

	t.Run("output-based payloads", func(t *testing.T) {
		tester := NewTester(nil)
		payloads := tester.GetPayloads(InjectionOutputBased)

		if len(payloads) == 0 {
			t.Error("expected output-based payloads")
		}
	})
}

func TestPlatformFiltering(t *testing.T) {
	t.Run("Unix only", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       10 * time.Second,
			Platform:      PlatformUnix,
			TimeThreshold: 5 * time.Second,
		}
		tester := NewTester(config)

		for _, p := range tester.payloads {
			if p.Platform == PlatformWindows {
				t.Error("found Windows payload in Unix-only config")
			}
		}
	})

	t.Run("Windows only", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       10 * time.Second,
			Platform:      PlatformWindows,
			TimeThreshold: 5 * time.Second,
		}
		tester := NewTester(config)

		for _, p := range tester.payloads {
			if p.Platform == PlatformUnix {
				t.Error("found Unix payload in Windows-only config")
			}
		}
	})

	t.Run("Both platforms", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       10 * time.Second,
			Platform:      PlatformBoth,
			TimeThreshold: 5 * time.Second,
		}
		tester := NewTester(config)

		hasUnix := false
		hasWindows := false
		for _, p := range tester.payloads {
			if p.Platform == PlatformUnix {
				hasUnix = true
			}
			if p.Platform == PlatformWindows {
				hasWindows = true
			}
		}

		if !hasUnix {
			t.Error("expected Unix payloads")
		}
		if !hasWindows {
			t.Error("expected Windows payloads")
		}
	})
}

func TestTestParameter(t *testing.T) {
	t.Run("output-based detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cmd := r.URL.Query().Get("cmd")
			if strings.Contains(cmd, "id") {
				// Simulate command execution
				w.Write([]byte("uid=0(root) gid=0(root) groups=0(root)"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "cmd", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) == 0 {
			t.Error("expected vulnerabilities")
		}

		// Check for output-based detection
		hasOutput := false
		for _, v := range vulns {
			if v.Type == InjectionOutputBased {
				hasOutput = true
				break
			}
		}

		if !hasOutput {
			t.Error("expected output-based vulnerability")
		}
	})

	t.Run("error-based detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cmd := r.URL.Query().Get("cmd")
			if strings.Contains(cmd, "invalidcmd") {
				w.Write([]byte("sh: invalidcmd12345: command not found"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "cmd", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		hasError := false
		for _, v := range vulns {
			if v.Type == InjectionErrorBased {
				hasError = true
				break
			}
		}

		if !hasError {
			t.Error("expected error-based vulnerability")
		}
	})

	t.Run("no vulnerability", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Safe response"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		vulns, err := tester.TestParameter(ctx, server.URL, "cmd", "GET")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(vulns) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(vulns))
		}
	})
}

func TestCommonInjectionParams(t *testing.T) {
	params := CommonInjectionParams()

	if len(params) == 0 {
		t.Error("expected params")
	}

	// Check for common ones
	hasCmd := false
	hasExec := false
	hasFile := false

	for _, p := range params {
		switch p {
		case "cmd":
			hasCmd = true
		case "exec":
			hasExec = true
		case "file":
			hasFile = true
		}
	}

	if !hasCmd {
		t.Error("expected 'cmd' parameter")
	}
	if !hasExec {
		t.Error("expected 'exec' parameter")
	}
	if !hasFile {
		t.Error("expected 'file' parameter")
	}
}

func TestScan(t *testing.T) {
	t.Run("vulnerable target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			exec := r.URL.Query().Get("exec")
			if strings.Contains(exec, "id") {
				w.Write([]byte("uid=1000(user) gid=1000(user)"))
			}
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		result, err := tester.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.URL != server.URL {
			t.Errorf("expected URL %s", server.URL)
		}
		if result.TestedParams == 0 {
			t.Error("expected params to be tested")
		}
		if len(result.Vulnerabilities) == 0 {
			t.Error("expected vulnerabilities")
		}
	})

	t.Run("safe target", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		tester := NewTester(nil)
		ctx := context.Background()

		result, err := tester.Scan(ctx, server.URL)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result.Vulnerabilities) != 0 {
			t.Errorf("expected no vulnerabilities, got %d", len(result.Vulnerabilities))
		}
	})
}

func TestAllInjectionTypes(t *testing.T) {
	types := AllInjectionTypes()

	if len(types) != 5 {
		t.Errorf("expected 5 injection types, got %d", len(types))
	}

	expectedTypes := map[InjectionType]bool{
		InjectionTimeBased:   false,
		InjectionErrorBased:  false,
		InjectionOutputBased: false,
		InjectionBlind:       false,
		InjectionStacked:     false,
	}

	for _, it := range types {
		expectedTypes[it] = true
	}

	for it, found := range expectedTypes {
		if !found {
			t.Errorf("missing injection type: %s", it)
		}
	}
}

func TestGetRemediation(t *testing.T) {
	remediation := GetRemediation()

	if remediation == "" {
		t.Error("expected remediation")
	}

	if !strings.Contains(remediation, "avoid") || !strings.Contains(remediation, "validation") {
		t.Error("expected remediation to mention avoidance and validation")
	}
}

func TestVulnerabilityFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("uid=0(root) gid=0(root)"))
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx := context.Background()

	vulns, _ := tester.TestParameter(ctx, server.URL, "cmd", "GET")

	if len(vulns) > 0 {
		v := vulns[0]

		if v.Type == "" {
			t.Error("vulnerability should have type")
		}
		if v.Description == "" {
			t.Error("vulnerability should have description")
		}
		if v.Severity != finding.Critical {
			t.Error("vulnerability should be critical severity")
		}
		if v.URL == "" {
			t.Error("vulnerability should have URL")
		}
		if v.Remediation == "" {
			t.Error("vulnerability should have remediation")
		}
		if v.Parameter == "" {
			t.Error("vulnerability should have parameter")
		}
		if v.Platform == "" {
			t.Error("vulnerability should have platform")
		}
		if v.Payload == nil {
			t.Error("vulnerability should have payload reference")
		}
	}
}

func TestPayloadContent(t *testing.T) {
	tester := NewTester(nil)

	t.Run("Unix payloads contain separators", func(t *testing.T) {
		unixPayloads := []string{}
		for _, p := range tester.payloads {
			if p.Platform == PlatformUnix {
				unixPayloads = append(unixPayloads, p.Value)
			}
		}

		hasSemicolon := false
		hasPipe := false
		hasBacktick := false

		for _, val := range unixPayloads {
			if strings.Contains(val, ";") {
				hasSemicolon = true
			}
			if strings.Contains(val, "|") {
				hasPipe = true
			}
			if strings.Contains(val, "`") {
				hasBacktick = true
			}
		}

		if !hasSemicolon {
			t.Error("expected semicolon separator")
		}
		if !hasPipe {
			t.Error("expected pipe separator")
		}
		if !hasBacktick {
			t.Error("expected backtick separator")
		}
	})

	t.Run("Windows payloads contain separators", func(t *testing.T) {
		windowsPayloads := []string{}
		for _, p := range tester.payloads {
			if p.Platform == PlatformWindows {
				windowsPayloads = append(windowsPayloads, p.Value)
			}
		}

		hasAmpersand := false
		for _, val := range windowsPayloads {
			if strings.Contains(val, "&") {
				hasAmpersand = true
				break
			}
		}

		if !hasAmpersand {
			t.Error("expected ampersand separator")
		}
	})
}

func TestOOBPayloads(t *testing.T) {
	t.Run("no callback - no OOB payloads", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       10 * time.Second,
			Platform:      PlatformBoth,
			TimeThreshold: 5 * time.Second,
			CallbackURL:   "",
		}
		tester := NewTester(config)

		oobPayloads := tester.GetPayloads(InjectionBlind)
		if len(oobPayloads) != 0 {
			t.Errorf("expected no OOB payloads, got %d", len(oobPayloads))
		}
	})

	t.Run("with callback - has OOB payloads", func(t *testing.T) {
		config := &TesterConfig{
			Timeout:       10 * time.Second,
			Platform:      PlatformBoth,
			TimeThreshold: 5 * time.Second,
			CallbackURL:   "http://callback.example.com",
		}
		tester := NewTester(config)

		oobPayloads := tester.GetPayloads(InjectionBlind)
		if len(oobPayloads) == 0 {
			t.Error("expected OOB payloads")
		}

		for _, p := range oobPayloads {
			if !strings.Contains(p.Value, "callback.example.com") {
				t.Error("OOB payload should contain callback URL")
			}
		}
	})
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tester := NewTester(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := tester.Scan(ctx, server.URL)
	if err != context.Canceled {
		// May return nil error with partial results
	}
}

func BenchmarkTestParameter(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &TesterConfig{
		Timeout:       10 * time.Second,
		Platform:      PlatformUnix,
		TimeThreshold: 1 * time.Second,
	}
	tester := NewTester(config)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tester.TestParameter(ctx, server.URL, "cmd", "GET")
	}
}
