package writers

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/output/events"
)

// TestCycloneDXWriter tests CycloneDX VEX output.
func TestCycloneDXWriter(t *testing.T) {
	t.Run("writes valid CycloneDX VEX document", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{
			ToolVersion: "1.0.0",
		})

		e := makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		if err := w.Write(e); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		// Parse output as CycloneDX document
		var doc map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		// Verify required CycloneDX fields
		if doc["bomFormat"] != "CycloneDX" {
			t.Errorf("expected bomFormat=CycloneDX, got %v", doc["bomFormat"])
		}
		if doc["specVersion"] != "1.5" {
			t.Errorf("expected specVersion=1.5, got %v", doc["specVersion"])
		}
		if doc["version"].(float64) != 1 {
			t.Errorf("expected version=1, got %v", doc["version"])
		}

		// Verify metadata
		metadata, ok := doc["metadata"].(map[string]interface{})
		if !ok {
			t.Fatal("metadata field missing or invalid")
		}
		if metadata["timestamp"] == nil {
			t.Error("timestamp missing from metadata")
		}

		tools, ok := metadata["tools"].([]interface{})
		if !ok || len(tools) == 0 {
			t.Fatal("tools field missing or empty")
		}

		tool := tools[0].(map[string]interface{})
		if tool["vendor"] != "WAFtester" {
			t.Errorf("expected vendor=WAFtester, got %v", tool["vendor"])
		}
		if tool["name"] != "waftester" {
			t.Errorf("expected name=waftester, got %v", tool["name"])
		}

		// Verify vulnerabilities
		vulns, ok := doc["vulnerabilities"].([]interface{})
		if !ok || len(vulns) != 1 {
			t.Fatalf("expected 1 vulnerability, got %v", len(vulns))
		}
	})

	t.Run("empty results produces empty vulnerabilities", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		vulns, ok := doc["vulnerabilities"].([]interface{})
		if ok && len(vulns) != 0 {
			t.Errorf("expected 0 vulnerabilities for empty result, got %d", len(vulns))
		}
	})

	t.Run("only bypasses are included", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		// Write multiple events with different outcomes
		bypass := makeTestResultEvent("bypass-1", "sqli", events.SeverityCritical, events.OutcomeBypass)
		blocked := makeTestResultEvent("blocked-1", "xss", events.SeverityHigh, events.OutcomeBlocked)
		pass := makeTestResultEvent("pass-1", "rce", events.SeverityHigh, events.OutcomePass)
		error := makeTestResultEvent("error-1", "ssrf", events.SeverityMedium, events.OutcomeError)

		if err := w.Write(bypass); err != nil {
			t.Fatalf("write bypass failed: %v", err)
		}
		if err := w.Write(blocked); err != nil {
			t.Fatalf("write blocked failed: %v", err)
		}
		if err := w.Write(pass); err != nil {
			t.Fatalf("write pass failed: %v", err)
		}
		if err := w.Write(error); err != nil {
			t.Fatalf("write error failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		vulns := doc["vulnerabilities"].([]interface{})
		// Should only include bypass and error outcomes
		if len(vulns) != 2 {
			t.Errorf("expected 2 vulnerabilities (bypass+error), got %d", len(vulns))
		}
	})

	t.Run("multiple bypasses create multiple vulnerabilities", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		events := []*events.ResultEvent{
			makeTestResultEvent("sqli-001", "sqli", events.SeverityCritical, events.OutcomeBypass),
			makeTestResultEvent("xss-001", "xss", events.SeverityHigh, events.OutcomeBypass),
			makeTestResultEvent("ssrf-001", "ssrf", events.SeverityHigh, events.OutcomeBypass),
		}

		for _, e := range events {
			if err := w.Write(e); err != nil {
				t.Fatalf("write failed: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		vulns := doc["vulnerabilities"].([]interface{})
		if len(vulns) != 3 {
			t.Errorf("expected 3 vulnerabilities, got %d", len(vulns))
		}

		// Verify each has unique ID
		ids := make(map[string]bool)
		for _, v := range vulns {
			vuln := v.(map[string]interface{})
			id := vuln["id"].(string)
			if ids[id] {
				t.Errorf("duplicate vulnerability ID: %s", id)
			}
			ids[id] = true
		}
	})

	t.Run("severity mapping", func(t *testing.T) {
		testCases := []struct {
			severity events.Severity
			expected string
		}{
			{events.SeverityCritical, "critical"},
			{events.SeverityHigh, "high"},
			{events.SeverityMedium, "medium"},
			{events.SeverityLow, "low"},
			{events.SeverityInfo, "info"},
			{events.Severity("unknown"), "unknown"},
		}

		for _, tc := range testCases {
			t.Run(string(tc.severity), func(t *testing.T) {
				buf := &bytes.Buffer{}
				w := NewCycloneDXWriter(buf, CycloneDXOptions{})

				e := makeTestResultEvent("test-1", "sqli", tc.severity, events.OutcomeBypass)
				w.Write(e)
				w.Close()

				var doc map[string]interface{}
				json.Unmarshal(buf.Bytes(), &doc)

				vulns := doc["vulnerabilities"].([]interface{})
				vuln := vulns[0].(map[string]interface{})
				ratings := vuln["ratings"].([]interface{})
				rating := ratings[0].(map[string]interface{})

				if rating["severity"] != tc.expected {
					t.Errorf("expected severity=%s, got %v", tc.expected, rating["severity"])
				}
				if rating["method"] != "other" {
					t.Errorf("expected method=other, got %v", rating["method"])
				}
			})
		}
	})

	t.Run("CWE mapping", func(t *testing.T) {
		testCases := []struct {
			category    string
			expectedCWE int
		}{
			{"sqli", 89},
			{"xss", 79},
			{"traversal", 22},
			{"path", 22},
			{"rce", 78},
			{"cmdi", 78},
			{"ssrf", 918},
			{"xxe", 611},
			{"ldap", 90},
			{"nosqli", 943},
			{"crlf", 93},
		}

		for _, tc := range testCases {
			t.Run(tc.category, func(t *testing.T) {
				buf := &bytes.Buffer{}
				w := NewCycloneDXWriter(buf, CycloneDXOptions{})

				e := makeTestResultEvent("test-1", tc.category, events.SeverityHigh, events.OutcomeBypass)
				w.Write(e)
				w.Close()

				var doc map[string]interface{}
				json.Unmarshal(buf.Bytes(), &doc)

				vulns := doc["vulnerabilities"].([]interface{})
				vuln := vulns[0].(map[string]interface{})
				cwes := vuln["cwes"].([]interface{})

				found := false
				for _, cwe := range cwes {
					if int(cwe.(float64)) == tc.expectedCWE {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected CWE-%d in %v", tc.expectedCWE, cwes)
				}
			})
		}
	})

	t.Run("unknown category has no CWEs", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		e := makeTestResultEvent("test-1", "unknown-category", events.SeverityMedium, events.OutcomeBypass)
		w.Write(e)
		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		vulns := doc["vulnerabilities"].([]interface{})
		vuln := vulns[0].(map[string]interface{})

		// cwes should be nil or empty for unknown categories
		if cwes, ok := vuln["cwes"]; ok && cwes != nil {
			cweArr := cwes.([]interface{})
			if len(cweArr) > 0 {
				t.Errorf("expected no CWEs for unknown category, got %v", cweArr)
			}
		}
	})

	t.Run("uses test CWEs when provided", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		e := &events.ResultEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeResult,
				Time: time.Now(),
				Scan: "test-scan",
			},
			Test: events.TestInfo{
				ID:       "custom-test",
				Category: "custom",
				Severity: events.SeverityHigh,
				CWE:      []int{123, 456},
			},
			Target: events.TargetInfo{
				URL:    "https://example.com",
				Method: "POST",
			},
			Result: events.ResultInfo{
				Outcome:    events.OutcomeBypass,
				StatusCode: 200,
			},
		}

		w.Write(e)
		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		vulns := doc["vulnerabilities"].([]interface{})
		vuln := vulns[0].(map[string]interface{})
		cwes := vuln["cwes"].([]interface{})

		if len(cwes) != 2 {
			t.Errorf("expected 2 CWEs, got %d", len(cwes))
		}
		if int(cwes[0].(float64)) != 123 {
			t.Errorf("expected first CWE=123, got %v", cwes[0])
		}
		if int(cwes[1].(float64)) != 456 {
			t.Errorf("expected second CWE=456, got %v", cwes[1])
		}
	})

	t.Run("vulnerability structure", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{
			ToolName:    "waftester",
			ToolVersion: "2.0.0",
			ToolURL:     "https://example.com/waftester",
		})

		e := makeTestResultEvent("sqli-inject-001", "sqli", events.SeverityCritical, events.OutcomeBypass)
		w.Write(e)
		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		vulns := doc["vulnerabilities"].([]interface{})
		vuln := vulns[0].(map[string]interface{})

		// Check source
		source := vuln["source"].(map[string]interface{})
		if source["name"] != "waftester" {
			t.Errorf("expected source.name=waftester, got %v", source["name"])
		}
		if source["url"] != "https://example.com/waftester" {
			t.Errorf("expected source.url=https://example.com/waftester, got %v", source["url"])
		}

		// Check analysis
		analysis := vuln["analysis"].(map[string]interface{})
		if analysis["state"] != "exploitable" {
			t.Errorf("expected analysis.state=exploitable, got %v", analysis["state"])
		}
		if analysis["detail"] == nil || analysis["detail"] == "" {
			t.Error("expected analysis.detail to be set")
		}

		// Check affects
		affects := vuln["affects"].([]interface{})
		if len(affects) != 1 {
			t.Errorf("expected 1 affects entry, got %d", len(affects))
		}
		affect := affects[0].(map[string]interface{})
		if affect["ref"] != "https://example.com/api" {
			t.Errorf("expected affects.ref=https://example.com/api, got %v", affect["ref"])
		}

		// Check description and recommendation exist
		if vuln["description"] == nil || vuln["description"] == "" {
			t.Error("description should not be empty")
		}
		if vuln["recommendation"] == nil || vuln["recommendation"] == "" {
			t.Error("recommendation should not be empty")
		}
	})

	t.Run("custom options", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{
			ToolName:    "custom-tool",
			ToolVersion: "3.0.0",
			BOMVersion:  5,
			ToolURL:     "https://custom.example.com",
		})

		e := makeTestResultEvent("test-1", "xss", events.SeverityHigh, events.OutcomeBypass)
		w.Write(e)
		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		if int(doc["version"].(float64)) != 5 {
			t.Errorf("expected version=5, got %v", doc["version"])
		}

		metadata := doc["metadata"].(map[string]interface{})
		tools := metadata["tools"].([]interface{})
		tool := tools[0].(map[string]interface{})

		if tool["name"] != "custom-tool" {
			t.Errorf("expected name=custom-tool, got %v", tool["name"])
		}
		if tool["version"] != "3.0.0" {
			t.Errorf("expected version=3.0.0, got %v", tool["version"])
		}
	})

	t.Run("default options", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		if int(doc["version"].(float64)) != 1 {
			t.Errorf("expected default version=1, got %v", doc["version"])
		}

		metadata := doc["metadata"].(map[string]interface{})
		tools := metadata["tools"].([]interface{})
		tool := tools[0].(map[string]interface{})

		if tool["name"] != "waftester" {
			t.Errorf("expected default name=waftester, got %v", tool["name"])
		}
	})

	t.Run("RFC3339 timestamp format", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})
		w.Close()

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		metadata := doc["metadata"].(map[string]interface{})
		timestamp := metadata["timestamp"].(string)

		// Verify it parses as RFC3339
		_, err := time.Parse(time.RFC3339, timestamp)
		if err != nil {
			t.Errorf("timestamp not in RFC3339 format: %s, error: %v", timestamp, err)
		}
	})

	t.Run("SupportsEvent returns correct values", func(t *testing.T) {
		w := NewCycloneDXWriter(&bytes.Buffer{}, CycloneDXOptions{})

		if !w.SupportsEvent(events.EventTypeResult) {
			t.Error("should support result events")
		}
		if !w.SupportsEvent(events.EventTypeBypass) {
			t.Error("should support bypass events")
		}
		if w.SupportsEvent(events.EventTypeProgress) {
			t.Error("should not support progress events")
		}
		if w.SupportsEvent(events.EventTypeSummary) {
			t.Error("should not support summary events")
		}
		if w.SupportsEvent(events.EventTypeStart) {
			t.Error("should not support start events")
		}
	})

	t.Run("Flush is no-op", func(t *testing.T) {
		w := NewCycloneDXWriter(&bytes.Buffer{}, CycloneDXOptions{})
		if err := w.Flush(); err != nil {
			t.Errorf("Flush should not fail: %v", err)
		}
	})

	t.Run("skips non-result events", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		// Write a summary event (should be skipped)
		summary := &events.SummaryEvent{
			BaseEvent: events.BaseEvent{
				Type: events.EventTypeSummary,
				Time: time.Now(),
				Scan: "test-scan",
			},
		}

		if err := w.Write(summary); err != nil {
			t.Fatalf("write summary failed: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc map[string]interface{}
		json.Unmarshal(buf.Bytes(), &doc)

		// Should have no vulnerabilities
		vulns, ok := doc["vulnerabilities"].([]interface{})
		if ok && len(vulns) != 0 {
			t.Errorf("expected 0 vulnerabilities when only summary event, got %d", len(vulns))
		}
	})

	t.Run("concurrent writes are safe", func(t *testing.T) {
		buf := &bytes.Buffer{}
		w := NewCycloneDXWriter(buf, CycloneDXOptions{})

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(n int) {
				e := makeTestResultEvent("test-"+string(rune('0'+n)), "sqli", events.SeverityHigh, events.OutcomeBypass)
				w.Write(e)
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		if err := w.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}

		var doc map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}

		vulns := doc["vulnerabilities"].([]interface{})
		if len(vulns) != 10 {
			t.Errorf("expected 10 vulnerabilities, got %d", len(vulns))
		}
	})
}

// TestCategoryToCWEs tests the CWE mapping function.
func TestCategoryToCWEs(t *testing.T) {
	testCases := []struct {
		category string
		expected []int
	}{
		{"sqli", []int{89}},
		{"xss", []int{79}},
		{"traversal", []int{22}},
		{"path", []int{22}},
		{"lfi", []int{22, 98}},
		{"rfi", []int{98}},
		{"rce", []int{78, 94}},
		{"cmdi", []int{78}},
		{"ssrf", []int{918}},
		{"xxe", []int{611}},
		{"ssti", []int{94}},
		{"ldap", []int{90}},
		{"nosqli", []int{943}},
		{"crlf", []int{93}},
		{"idor", []int{639}},
		{"jwt", []int{347}},
		{"cors", []int{346}},
		{"csrf", []int{352}},
		{"clickjack", []int{1021}},
		{"open_redirect", []int{601}},
		{"redirect", []int{601}},
		{"deserialize", []int{502}},
		{"upload", []int{434}},
		{"smuggling", []int{444}},
		{"unknown", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.category, func(t *testing.T) {
			result := categoryToCWEs(tc.category)
			if len(result) != len(tc.expected) {
				t.Errorf("expected %v, got %v", tc.expected, result)
				return
			}
			for i, cwe := range result {
				if cwe != tc.expected[i] {
					t.Errorf("expected CWE %d at position %d, got %d", tc.expected[i], i, cwe)
				}
			}
		})
	}
}

// TestSeverityToCycloneDX tests severity mapping.
func TestSeverityToCycloneDX(t *testing.T) {
	testCases := []struct {
		input    events.Severity
		expected string
	}{
		{events.SeverityCritical, "critical"},
		{events.SeverityHigh, "high"},
		{events.SeverityMedium, "medium"},
		{events.SeverityLow, "low"},
		{events.SeverityInfo, "info"},
		{events.Severity(""), "unknown"},
		{events.Severity("invalid"), "unknown"},
	}

	for _, tc := range testCases {
		t.Run(string(tc.input), func(t *testing.T) {
			result := severityToCycloneDX(tc.input)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}
