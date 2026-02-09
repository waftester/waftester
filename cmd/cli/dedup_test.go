package main

import (
	"testing"
)

type testVuln struct {
	Param       string
	Type        string
	ConfirmedBy int
}

func TestDeduplicateFindings_NoDuplicates(t *testing.T) {
	findings := []testVuln{
		{Param: "id", Type: "error-based"},
		{Param: "name", Type: "boolean-based"},
	}

	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param + "|" + v.Type },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result))
	}
	if result[0].ConfirmedBy != 1 {
		t.Errorf("expected ConfirmedBy=1, got %d", result[0].ConfirmedBy)
	}
}

func TestDeduplicateFindings_WithDuplicates(t *testing.T) {
	findings := []testVuln{
		{Param: "id", Type: "boolean-based"},
		{Param: "id", Type: "boolean-based"},
		{Param: "id", Type: "boolean-based"},
		{Param: "name", Type: "error-based"},
		{Param: "id", Type: "error-based"},
		{Param: "name", Type: "error-based"},
	}

	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param + "|" + v.Type },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)

	if len(result) != 3 {
		t.Fatalf("expected 3 unique findings, got %d", len(result))
	}

	// First: id|boolean-based (3 confirming)
	if result[0].Param != "id" || result[0].Type != "boolean-based" {
		t.Errorf("unexpected first finding: %+v", result[0])
	}
	if result[0].ConfirmedBy != 3 {
		t.Errorf("expected ConfirmedBy=3 for id|boolean-based, got %d", result[0].ConfirmedBy)
	}

	// Second: name|error-based (2 confirming)
	if result[1].Param != "name" || result[1].Type != "error-based" {
		t.Errorf("unexpected second finding: %+v", result[1])
	}
	if result[1].ConfirmedBy != 2 {
		t.Errorf("expected ConfirmedBy=2 for name|error-based, got %d", result[1].ConfirmedBy)
	}

	// Third: id|error-based (1 confirming)
	if result[2].ConfirmedBy != 1 {
		t.Errorf("expected ConfirmedBy=1 for id|error-based, got %d", result[2].ConfirmedBy)
	}
}

func TestDeduplicateFindings_Empty(t *testing.T) {
	var findings []testVuln
	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)
	if len(result) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result))
	}
}

func TestDeduplicateFindings_Single(t *testing.T) {
	findings := []testVuln{{Param: "id", Type: "sqli"}}
	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)
	if len(result) != 1 || result[0].ConfirmedBy != 1 {
		t.Fatalf("expected 1 finding with ConfirmedBy=1, got %+v", result)
	}
}

func TestDeduplicateFindings_AllDuplicates(t *testing.T) {
	findings := make([]testVuln, 250)
	for i := range findings {
		findings[i] = testVuln{Param: "id", Type: "boolean-based"}
	}

	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param + "|" + v.Type },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 unique finding, got %d", len(result))
	}
	if result[0].ConfirmedBy != 250 {
		t.Errorf("expected ConfirmedBy=250, got %d", result[0].ConfirmedBy)
	}
}

func TestDeduplicateFindings_PointerSlice(t *testing.T) {
	findings := []*testVuln{
		{Param: "id", Type: "sqli"},
		{Param: "id", Type: "sqli"},
		{Param: "name", Type: "xss"},
	}

	result := DeduplicateFindings(findings,
		func(v *testVuln) string { return v.Param + "|" + v.Type },
		func(v **testVuln, n int) { (*v).ConfirmedBy = n },
	)

	if len(result) != 2 {
		t.Fatalf("expected 2 unique findings, got %d", len(result))
	}
	if result[0].ConfirmedBy != 2 {
		t.Errorf("expected ConfirmedBy=2, got %d", result[0].ConfirmedBy)
	}
	if result[1].ConfirmedBy != 1 {
		t.Errorf("expected ConfirmedBy=1, got %d", result[1].ConfirmedBy)
	}
}

func TestDeduplicateFindings_PreservesOrder(t *testing.T) {
	findings := []testVuln{
		{Param: "z", Type: "c"},
		{Param: "a", Type: "b"},
		{Param: "m", Type: "a"},
		{Param: "z", Type: "c"},
		{Param: "a", Type: "b"},
	}

	result := DeduplicateFindings(findings,
		func(v testVuln) string { return v.Param + "|" + v.Type },
		func(v *testVuln, n int) { v.ConfirmedBy = n },
	)

	if len(result) != 3 {
		t.Fatalf("expected 3, got %d", len(result))
	}
	if result[0].Param != "z" || result[1].Param != "a" || result[2].Param != "m" {
		t.Errorf("order not preserved: %+v", result)
	}
}
