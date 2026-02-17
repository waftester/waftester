// Regression tests for GraphQL input validation.
//
// Bug: TestBatchAttack accepted negative batchSize, causing
// make([]Request, -1) to panic. TestDepthAttack had the same issue.
//
// Fix: Guard both methods with `if size/depth <= 0 { return nil, nil }`.
package graphql

import (
	"context"
	"testing"
)

func TestTestBatchAttack_NegativeSize_NoPanic(t *testing.T) {
	t.Parallel()

	tester := NewTester("http://localhost:0", nil) // no real server needed

	vuln, err := tester.TestBatchAttack(context.Background(), -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln != nil {
		t.Fatal("expected nil vulnerability for negative batch size")
	}
}

func TestTestBatchAttack_ZeroSize_NoPanic(t *testing.T) {
	t.Parallel()

	tester := NewTester("http://localhost:0", nil)

	vuln, err := tester.TestBatchAttack(context.Background(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln != nil {
		t.Fatal("expected nil vulnerability for zero batch size")
	}
}

func TestTestDepthAttack_NegativeDepth_NoPanic(t *testing.T) {
	t.Parallel()

	tester := NewTester("http://localhost:0", nil)

	vuln, err := tester.TestDepthAttack(context.Background(), "field", -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln != nil {
		t.Fatal("expected nil vulnerability for negative depth")
	}
}

func TestTestDepthAttack_ZeroDepth_NoPanic(t *testing.T) {
	t.Parallel()

	tester := NewTester("http://localhost:0", nil)

	vuln, err := tester.TestDepthAttack(context.Background(), "field", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vuln != nil {
		t.Fatal("expected nil vulnerability for zero depth")
	}
}
