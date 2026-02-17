package ui

import (
	"bytes"
	"testing"
)

func TestNewExecutionManifest(t *testing.T) {
	m := NewExecutionManifest("Test Manifest")

	if m == nil {
		t.Fatal("NewExecutionManifest returned nil")
	}

	if m.Title != "Test Manifest" {
		t.Errorf("Expected Title 'Test Manifest', got '%s'", m.Title)
	}

	if !m.BoxStyle {
		t.Error("Expected BoxStyle to be true by default")
	}
}

func TestExecutionManifestAdd(t *testing.T) {
	m := NewExecutionManifest("Test")

	m.Add("Label1", "Value1")
	m.Add("Label2", 42)

	if len(m.Items) != 2 {
		t.Errorf("Expected 2 items, got %d", len(m.Items))
	}

	if m.Items[0].Label != "Label1" {
		t.Errorf("Expected Label 'Label1', got '%s'", m.Items[0].Label)
	}

	if m.Items[1].Value != 42 {
		t.Errorf("Expected Value 42, got %v", m.Items[1].Value)
	}
}

func TestExecutionManifestAddWithIcon(t *testing.T) {
	m := NewExecutionManifest("Test")

	m.AddWithIcon("🎯", "Target", "https://example.com")

	if len(m.Items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(m.Items))
	}

	// Icon is sanitized for the current terminal capability.
	// In test (piped stderr), emoji are stripped.
	expected := SanitizeString("🎯")
	if m.Items[0].Icon != expected {
		t.Errorf("Expected Icon %q, got %q", expected, m.Items[0].Icon)
	}

	if m.Items[0].Label != "Target" {
		t.Errorf("Expected Label 'Target', got '%s'", m.Items[0].Label)
	}
}

func TestExecutionManifestAddEmphasis(t *testing.T) {
	m := NewExecutionManifest("Test")

	m.AddEmphasis("📦", "Payloads", "1500 loaded")

	if len(m.Items) != 1 {
		t.Fatalf("Expected 1 item, got %d", len(m.Items))
	}

	if !m.Items[0].Emphasis {
		t.Error("Expected Emphasis to be true")
	}
}

func TestExecutionManifestFluentAPI(t *testing.T) {
	m := NewExecutionManifest("Bypass Finder").
		SetDescription("WAF bypass testing").
		AddWithIcon("🎯", "Target", "https://example.com").
		AddEmphasis("📦", "Payloads", "500 loaded").
		Add("Concurrency", 50)

	if m.Description != "WAF bypass testing" {
		t.Errorf("Expected Description, got '%s'", m.Description)
	}

	if len(m.Items) != 3 {
		t.Errorf("Expected 3 items, got %d", len(m.Items))
	}
}

func TestExecutionManifestAddPayloadInfo(t *testing.T) {
	m := NewExecutionManifest("Test")

	m.AddPayloadInfo(1500, []string{"sqli", "xss", "traversal"})

	if len(m.Items) != 2 {
		t.Errorf("Expected 2 items (payloads + categories), got %d", len(m.Items))
	}

	// First item should be payload count with emphasis
	if !m.Items[0].Emphasis {
		t.Error("Payload count should have emphasis")
	}
}

func TestExecutionManifestAddTargetInfo(t *testing.T) {
	// Single target
	m1 := NewExecutionManifest("Test")
	m1.AddTargetInfo(1, "https://example.com")

	if len(m1.Items) != 1 {
		t.Errorf("Expected 1 item for single target, got %d", len(m1.Items))
	}

	// Multiple targets
	m2 := NewExecutionManifest("Test")
	m2.AddTargetInfo(10, "https://example.com")

	if len(m2.Items) != 2 {
		t.Errorf("Expected 2 items for multiple targets (count + first), got %d", len(m2.Items))
	}
}

func TestExecutionManifestPrint(t *testing.T) {
	var buf bytes.Buffer

	m := NewExecutionManifest("Test Manifest")
	m.Writer = &buf
	m.AddWithIcon("🎯", "Target", "https://example.com")
	m.AddEmphasis("📦", "Payloads", "100 loaded")

	m.Print()

	output := buf.String()

	// Should contain the title
	if !bytes.Contains(buf.Bytes(), []byte("Test Manifest")) {
		t.Error("Output should contain manifest title")
	}

	// Should contain the target
	if !bytes.Contains(buf.Bytes(), []byte("Target")) {
		t.Error("Output should contain 'Target' label")
	}

	if len(output) == 0 {
		t.Error("Print should produce output")
	}
}

func TestExecutionManifestNoBoxStyle(t *testing.T) {
	var buf bytes.Buffer

	m := NewExecutionManifest("Test")
	m.Writer = &buf
	m.BoxStyle = false
	m.Add("Key", "Value")

	m.Print()

	// Non-box style should still produce output
	if buf.Len() == 0 {
		t.Error("Non-box style should produce output")
	}
}
