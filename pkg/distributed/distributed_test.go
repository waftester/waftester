package distributed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewCoordinator(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	if c.ID != "coord-1" {
		t.Errorf("expected id 'coord-1', got %s", c.ID)
	}
	if c.Address != ":8080" {
		t.Errorf("expected address ':8080', got %s", c.Address)
	}
}

func TestCoordinator_RegisterNode(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	var mu sync.Mutex
	var joinedNode *Node
	c.OnNodeJoin = func(n *Node) {
		mu.Lock()
		joinedNode = n
		mu.Unlock()
	}

	node := &Node{
		ID:       "worker-1",
		Address:  ":9001",
		Role:     RoleWorker,
		Capacity: 10,
	}

	err := c.RegisterNode(node)
	if err != nil {
		t.Fatalf("failed to register node: %v", err)
	}

	// Wait for callback
	time.Sleep(50 * time.Millisecond)

	nodes := c.GetNodes()
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}

	mu.Lock()
	nodeJoined := joinedNode
	mu.Unlock()
	if nodeJoined == nil || nodeJoined.ID != "worker-1" {
		t.Error("OnNodeJoin callback not called")
	}
}

func TestCoordinator_UnregisterNode(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	var mu sync.Mutex
	var leftNode *Node
	c.OnNodeLeave = func(n *Node) {
		mu.Lock()
		leftNode = n
		mu.Unlock()
	}

	node := &Node{ID: "worker-1", Role: RoleWorker}
	c.RegisterNode(node)

	c.UnregisterNode("worker-1")

	// Wait for callback
	time.Sleep(50 * time.Millisecond)

	nodes := c.GetNodes()
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}

	mu.Lock()
	nodeLeft := leftNode
	mu.Unlock()
	if nodeLeft == nil || nodeLeft.ID != "worker-1" {
		t.Error("OnNodeLeave callback not called")
	}
}

func TestCoordinator_SubmitTask(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	task := &Task{
		Type:   "scan",
		Target: "https://example.com",
	}

	err := c.SubmitTask(task)
	if err != nil {
		t.Fatalf("failed to submit task: %v", err)
	}

	if task.ID == "" {
		t.Error("expected task ID to be generated")
	}
	if task.Status != TaskPending {
		t.Errorf("expected status 'pending', got %s", task.Status)
	}

	tasks := c.GetTasks()
	if len(tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(tasks))
	}
}

func TestCoordinator_GetAvailableNode(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	// No nodes - should return nil
	node := c.GetAvailableNode()
	if node != nil {
		t.Error("expected nil when no nodes available")
	}

	// Add a healthy node
	c.RegisterNode(&Node{
		ID:       "worker-1",
		Role:     RoleWorker,
		Capacity: 5,
	})

	node = c.GetAvailableNode()
	if node == nil {
		t.Fatal("expected to get available node")
	}
	if node.ID != "worker-1" {
		t.Errorf("expected worker-1, got %s", node.ID)
	}

	// Add node with more capacity
	c.RegisterNode(&Node{
		ID:       "worker-2",
		Role:     RoleWorker,
		Capacity: 10,
	})

	node = c.GetAvailableNode()
	if node.ID != "worker-2" {
		t.Errorf("expected worker-2 (higher capacity), got %s", node.ID)
	}
}

func TestCoordinator_AssignTask(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	node := &Node{ID: "worker-1", Role: RoleWorker, Capacity: 5}
	c.RegisterNode(node)

	task := &Task{ID: "task-1", Type: "scan"}
	c.SubmitTask(task)

	c.AssignTask(task, node)

	if task.Status != TaskAssigned {
		t.Errorf("expected status 'assigned', got %s", task.Status)
	}
	if task.AssignedTo != "worker-1" {
		t.Errorf("expected assigned to 'worker-1', got %s", task.AssignedTo)
	}
	if task.StartedAt == nil {
		t.Error("expected StartedAt to be set")
	}

	// Check node active tasks incremented
	nodes := c.GetNodes()
	if nodes[0].ActiveTasks != 1 {
		t.Errorf("expected 1 active task, got %d", nodes[0].ActiveTasks)
	}
}

func TestCoordinator_CompleteTask(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	var mu sync.Mutex
	var completedTask *Task
	c.OnTaskComplete = func(task *Task) {
		mu.Lock()
		completedTask = task
		mu.Unlock()
	}

	node := &Node{ID: "worker-1", Role: RoleWorker, Capacity: 5}
	c.RegisterNode(node)

	task := &Task{ID: "task-1", Type: "scan"}
	c.SubmitTask(task)
	c.AssignTask(task, node)

	result := &TaskResult{
		Success: true,
		Output:  "completed successfully",
	}
	c.CompleteTask("task-1", result)

	// Wait for callback
	time.Sleep(50 * time.Millisecond)

	got, ok := c.GetTask("task-1")
	if !ok {
		t.Fatal("expected to find task")
	}

	if got.Status != TaskCompleted {
		t.Errorf("expected status 'completed', got %s", got.Status)
	}
	if got.Result == nil || !got.Result.Success {
		t.Error("expected successful result")
	}

	// Check callback
	mu.Lock()
	taskCompleted := completedTask
	mu.Unlock()
	if taskCompleted == nil {
		t.Error("OnTaskComplete callback not called")
	}
}

func TestCoordinator_CompleteTask_Failed(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	node := &Node{ID: "worker-1", Role: RoleWorker, Capacity: 5}
	c.RegisterNode(node)

	task := &Task{ID: "task-1", Type: "scan"}
	c.SubmitTask(task)
	c.AssignTask(task, node)

	result := &TaskResult{
		Success: false,
		Error:   "connection timeout",
	}
	c.CompleteTask("task-1", result)

	got, _ := c.GetTask("task-1")
	if got.Status != TaskFailed {
		t.Errorf("expected status 'failed', got %s", got.Status)
	}
}

func TestCoordinator_Stats(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	// Add nodes
	c.RegisterNode(&Node{ID: "w1", Capacity: 5})
	c.RegisterNode(&Node{ID: "w2", Capacity: 5})

	// Manually mark one node unhealthy via internal state (not through GetNodes copy)
	c.mu.Lock()
	c.nodes["w2"].Status = StatusUnhealthy
	c.mu.Unlock()

	// Add tasks
	c.SubmitTask(&Task{ID: "t1"})
	c.SubmitTask(&Task{ID: "t2"})

	stats := c.Stats()

	if stats.TotalNodes != 2 {
		t.Errorf("expected 2 total nodes, got %d", stats.TotalNodes)
	}
	if stats.HealthyNodes != 1 {
		t.Errorf("expected 1 healthy node, got %d", stats.HealthyNodes)
	}
	if stats.TotalTasks != 2 {
		t.Errorf("expected 2 total tasks, got %d", stats.TotalTasks)
	}
	if stats.PendingTasks != 2 {
		t.Errorf("expected 2 pending tasks, got %d", stats.PendingTasks)
	}
}

func TestCoordinator_Heartbeat(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	// Heartbeat for unknown node
	if c.Heartbeat("unknown") {
		t.Error("expected false for unknown node")
	}

	// Register and heartbeat
	c.RegisterNode(&Node{ID: "worker-1", Capacity: 5})
	if !c.Heartbeat("worker-1") {
		t.Error("expected true for known node")
	}
}

func TestCoordinator_HTTP_Stats(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")
	c.RegisterNode(&Node{ID: "w1", Capacity: 5})

	req := httptest.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()

	c.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCoordinator_HTTP_Nodes(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")
	c.RegisterNode(&Node{ID: "w1", Capacity: 5})

	req := httptest.NewRequest("GET", "/api/nodes", nil)
	w := httptest.NewRecorder()

	c.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestCoordinator_HTTP_Tasks(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")
	c.SubmitTask(&Task{ID: "t1", Type: "scan"})

	req := httptest.NewRequest("GET", "/api/tasks", nil)
	w := httptest.NewRecorder()

	c.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestNewWorker(t *testing.T) {
	w := NewWorker("worker-1", ":9001", "localhost:8080", 10)

	if w.Node.ID != "worker-1" {
		t.Errorf("expected id 'worker-1', got %s", w.Node.ID)
	}
	if w.Node.Capacity != 10 {
		t.Errorf("expected capacity 10, got %d", w.Node.Capacity)
	}
	if w.Coordinator != "localhost:8080" {
		t.Errorf("expected coordinator 'localhost:8080', got %s", w.Coordinator)
	}
}

func TestWorker_Stop(t *testing.T) {
	w := NewWorker("worker-1", ":9001", "localhost:8080", 10)

	w.Stop()

	if w.Node.Status != StatusDraining {
		t.Errorf("expected status 'draining', got %s", w.Node.Status)
	}
}

func TestNewTaskSplitter(t *testing.T) {
	splitter := NewTaskSplitter(100)
	if splitter.MaxTargetsPerTask != 100 {
		t.Errorf("expected 100, got %d", splitter.MaxTargetsPerTask)
	}

	// Default value
	splitter = NewTaskSplitter(0)
	if splitter.MaxTargetsPerTask != 100 {
		t.Errorf("expected default 100, got %d", splitter.MaxTargetsPerTask)
	}
}

func TestTaskSplitter_Split(t *testing.T) {
	splitter := NewTaskSplitter(3)

	targets := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	tasks := splitter.Split("scan", targets, nil)

	if len(tasks) != 2 {
		t.Errorf("expected 2 tasks, got %d", len(tasks))
	}
}

func TestTaskSplitter_Split_Small(t *testing.T) {
	splitter := NewTaskSplitter(10)

	targets := []string{"a.com", "b.com"}
	tasks := splitter.Split("scan", targets, nil)

	if len(tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(tasks))
	}
}

func TestResultAggregator(t *testing.T) {
	agg := NewResultAggregator()

	agg.Add("task-1", &TaskResult{Success: true, Duration: time.Second})
	agg.Add("task-2", &TaskResult{Success: false, Duration: 2 * time.Second})
	agg.Add("task-3", &TaskResult{Success: true, Duration: 3 * time.Second})

	results := agg.GetAll()
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	summary := agg.Summary()
	if summary.TotalTasks != 3 {
		t.Errorf("expected 3 total tasks, got %d", summary.TotalTasks)
	}
	if summary.SuccessfulTasks != 2 {
		t.Errorf("expected 2 successful, got %d", summary.SuccessfulTasks)
	}
	if summary.FailedTasks != 1 {
		t.Errorf("expected 1 failed, got %d", summary.FailedTasks)
	}
	if summary.TotalDuration != 6*time.Second {
		t.Errorf("expected 6s total duration, got %v", summary.TotalDuration)
	}
	if summary.AverageDuration != 2*time.Second {
		t.Errorf("expected 2s average duration, got %v", summary.AverageDuration)
	}
}

func TestNode_Status(t *testing.T) {
	statuses := []NodeStatus{StatusHealthy, StatusUnhealthy, StatusDraining, StatusOffline}
	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
	}
}

func TestTask_Status(t *testing.T) {
	statuses := []TaskStatus{TaskPending, TaskAssigned, TaskRunning, TaskCompleted, TaskFailed, TaskCancelled}
	for _, s := range statuses {
		if s == "" {
			t.Error("status should not be empty")
		}
	}
}

func TestRole(t *testing.T) {
	if RoleCoordinator != "coordinator" {
		t.Error("unexpected coordinator role value")
	}
	if RoleWorker != "worker" {
		t.Error("unexpected worker role value")
	}
}

func TestCoordinator_StartDistributor(t *testing.T) {
	c := NewCoordinator("coord-1", ":8080")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	c.StartDistributor(ctx)

	// Register a node and submit a task
	node := &Node{ID: "w1", Capacity: 5}
	c.RegisterNode(node)

	task := &Task{Type: "scan", Target: "example.com"}
	c.SubmitTask(task)

	// Wait for task to be assigned
	time.Sleep(150 * time.Millisecond)

	got, _ := c.GetTask(task.ID)
	if got.Status != TaskAssigned {
		t.Errorf("expected task to be assigned, got %s", got.Status)
	}
}
