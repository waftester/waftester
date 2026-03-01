package history

import (
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestStoreSaveAndGet(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	record := &ScanRecord{
		ID:        "test-123",
		TargetURL: "https://example.com",
		Timestamp: time.Now(),
	}

	if err := store.Save(record); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Get("test-123")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if loaded.TargetURL != "https://example.com" {
		t.Errorf("expected target https://example.com, got %s", loaded.TargetURL)
	}
}
