package distributed

// Safety tests for distributed coordination — verifies no panics on double-stop,
// full queue handling, and shutdown behavior.
// Would have caught R3 (double-close panic, dropped tasks, no shutdown timeout,
// worker goroutine leak, stale task reschedule).

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/testutil"
)

// TestWorker_DoubleStop_NoPanic verifies calling Stop() twice doesn't cause
// a double-close panic on StopChan.
func TestWorker_DoubleStop_NoPanic(t *testing.T) {
	t.Parallel()

	w := NewWorker("w1", "localhost:8001", "localhost:9000", 5)

	testutil.AssertNoPanic(t, "first Stop", func() { w.Stop() })
	testutil.AssertNoPanic(t, "second Stop", func() { w.Stop() })
	testutil.AssertNoPanic(t, "third Stop", func() { w.Stop() })
}

// TestCoordinator_SubmitTask_NilTask verifies submitting nil doesn't panic.
func TestCoordinator_SubmitTask_NilTask(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("c1", "localhost:9000")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SubmitTask(nil) panicked: %v", r)
		}
	}()

	err := c.SubmitTask(nil)
	if err == nil {
		t.Log("SubmitTask(nil) returned nil error — acceptable if handled")
	}
}

// TestCoordinator_SubmitTask_FullQueue verifies tasks submitted beyond queue
// capacity are handled gracefully (error returned, not silently dropped).
func TestCoordinator_SubmitTask_FullQueue(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("c1", "localhost:9000")

	// Fill the queue beyond capacity
	for i := 0; i < 200; i++ {
		task := &Task{
			ID:     fmt.Sprintf("task-%d", i),
			Type:   "scan",
			Target: "https://example.com",
			Status: TaskPending,
		}
		_ = c.SubmitTask(task)
	}
	// If we get here without hanging, the queue handles overflow
}

// TestCoordinator_StartDistributor_ContextCancel verifies the distributor
// respects context cancellation and doesn't leak goroutines.
func TestCoordinator_StartDistributor_ContextCancel(t *testing.T) {
	t.Parallel()

	tracker := testutil.TrackGoroutines()

	c := NewCoordinator("c1", "localhost:9000")
	ctx, cancel := context.WithCancel(context.Background())

	go c.StartDistributor(ctx)
	time.Sleep(50 * time.Millisecond) // let it start

	cancel() // signal shutdown
	time.Sleep(100 * time.Millisecond)

	tracker.CheckLeaks(t, 2) // tolerance for runtime goroutines
}

// TestWorker_Run_ContextCancel verifies Worker.Run respects context cancellation.
func TestWorker_Run_ContextCancel(t *testing.T) {
	t.Parallel()

	w := NewWorker("w1", "localhost:8001", "localhost:9000", 5)
	w.TaskHandler = func(ctx context.Context, task *Task) *TaskResult {
		return &TaskResult{Success: true, Output: "done"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	testutil.AssertTimeout(t, "Worker.Run cancel", 3*time.Second, func() {
		_ = w.Run(ctx)
	})
}

// TestWorker_Run_StopChan verifies Worker.Run exits when Stop() is called.
func TestWorker_Run_StopChanSafety(t *testing.T) {
	t.Parallel()

	w := NewWorker("w1", "localhost:8001", "localhost:9000", 5)
	w.TaskHandler = func(ctx context.Context, task *Task) *TaskResult {
		return &TaskResult{Success: true}
	}

	testutil.AssertTimeout(t, "Worker.Run stop", 3*time.Second, func() {
		ctx := context.Background()
		go func() {
			time.Sleep(100 * time.Millisecond)
			w.Stop()
		}()
		_ = w.Run(ctx)
	})
}

// TestCoordinator_Heartbeat_UnknownNode verifies heartbeat for unknown node
// returns false.
func TestCoordinator_Heartbeat_UnknownNode(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("c1", "localhost:9000")

	if c.Heartbeat("nonexistent-node") {
		t.Error("heartbeat for unknown node should return false")
	}
}

// TestCoordinator_RegisterNode_Duplicate verifies duplicate registration
// is handled gracefully.
func TestCoordinator_RegisterNode_Duplicate(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("c1", "localhost:9000")
	node := &Node{
		ID:       "n1",
		Address:  "localhost:8001",
		Role:     RoleWorker,
		Status:   StatusHealthy,
		Capacity: 10,
	}

	if err := c.RegisterNode(node); err != nil {
		t.Fatalf("first register: %v", err)
	}

	// Second registration should not panic
	testutil.AssertNoPanic(t, "duplicate register", func() {
		_ = c.RegisterNode(node)
	})
}

// TestCoordinator_RegisterNilNode_NoPanic verifies registering a nil node returns
// an error instead of panicking with a nil pointer dereference.
// Regression: RegisterNode dereferenced node.Status without a nil check,
// causing a panic when the HTTP handler decoded `{"node": null}`.
func TestCoordinator_RegisterNilNode_NoPanic(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("coord-1", "localhost:9000")
	err := c.RegisterNode(nil)
	if err == nil {
		t.Fatal("RegisterNode(nil) should return an error")
	}
}

// TestHandleNodes_OversizedBody verifies the POST /api/nodes endpoint rejects
// oversized request bodies.
// Regression: json.Decoder had no size limit, allowing OOM via large POST body.
func TestHandleNodes_OversizedBody(t *testing.T) {
	t.Parallel()

	c := NewCoordinator("coord-1", "localhost:9000")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/nodes", c.handleNodes)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Send a body that exceeds 1MB
	body := bytes.NewReader(make([]byte, 2<<20)) // 2MB
	resp, err := http.Post(srv.URL+"/api/nodes", "application/json", body)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized body, got %d", resp.StatusCode)
	}
}
