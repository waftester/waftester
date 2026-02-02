// Package distributed provides multi-node scanning coordination
package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
)

// Role defines the node role in the distributed system
type Role string

const (
	RoleCoordinator Role = "coordinator"
	RoleWorker      Role = "worker"
)

// NodeStatus defines the node health status
type NodeStatus string

const (
	StatusHealthy   NodeStatus = "healthy"
	StatusUnhealthy NodeStatus = "unhealthy"
	StatusDraining  NodeStatus = "draining"
	StatusOffline   NodeStatus = "offline"
)

// Node represents a worker node in the distributed system
type Node struct {
	ID          string            `json:"id"`
	Address     string            `json:"address"`
	Role        Role              `json:"role"`
	Status      NodeStatus        `json:"status"`
	Capacity    int               `json:"capacity"`     // Max concurrent tasks
	ActiveTasks int               `json:"active_tasks"` // Current tasks
	LastSeen    time.Time         `json:"last_seen"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Task represents a unit of work
type Task struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // scan, probe, fuzz
	Target      string                 `json:"target"`
	Config      map[string]interface{} `json:"config,omitempty"`
	Priority    int                    `json:"priority"`
	Status      TaskStatus             `json:"status"`
	AssignedTo  string                 `json:"assigned_to,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      *TaskResult            `json:"result,omitempty"`
	RetryCount  int                    `json:"retry_count"`
	MaxRetries  int                    `json:"max_retries"`
}

// TaskStatus represents task state
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskAssigned  TaskStatus = "assigned"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskCancelled TaskStatus = "cancelled"
)

// TaskResult represents the output of a completed task
type TaskResult struct {
	Success  bool                   `json:"success"`
	Output   string                 `json:"output,omitempty"`
	Error    string                 `json:"error,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
	Duration time.Duration          `json:"duration"`
}

// Coordinator manages worker nodes and task distribution
type Coordinator struct {
	ID         string
	Address    string
	nodes      map[string]*Node
	tasks      map[string]*Task
	taskQueue  chan *Task
	mu         sync.RWMutex
	httpServer *http.Server

	// Callbacks
	OnNodeJoin     func(*Node)
	OnNodeLeave    func(*Node)
	OnTaskComplete func(*Task)
}

// NewCoordinator creates a new coordinator
func NewCoordinator(id, address string) *Coordinator {
	return &Coordinator{
		ID:        id,
		Address:   address,
		nodes:     make(map[string]*Node),
		tasks:     make(map[string]*Task),
		taskQueue: make(chan *Task, 10000),
	}
}

// RegisterNode registers a worker node
func (c *Coordinator) RegisterNode(node *Node) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	node.Status = StatusHealthy
	node.LastSeen = time.Now()
	c.nodes[node.ID] = node

	if c.OnNodeJoin != nil {
		go c.OnNodeJoin(node)
	}

	return nil
}

// UnregisterNode removes a worker node
func (c *Coordinator) UnregisterNode(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if node, ok := c.nodes[nodeID]; ok {
		node.Status = StatusOffline
		delete(c.nodes, nodeID)

		if c.OnNodeLeave != nil {
			go c.OnNodeLeave(node)
		}
	}
}

// SubmitTask adds a task to the queue
func (c *Coordinator) SubmitTask(task *Task) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if task.ID == "" {
		task.ID = fmt.Sprintf("task-%d", time.Now().UnixNano())
	}
	task.Status = TaskPending
	task.CreatedAt = time.Now()

	c.tasks[task.ID] = task

	select {
	case c.taskQueue <- task:
		return nil
	default:
		return fmt.Errorf("task queue full")
	}
}

// GetAvailableNode finds a healthy node with capacity
func (c *Coordinator) GetAvailableNode() *Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var best *Node
	for _, node := range c.nodes {
		if node.Status != StatusHealthy {
			continue
		}
		if node.ActiveTasks >= node.Capacity {
			continue
		}
		if best == nil || (node.Capacity-node.ActiveTasks) > (best.Capacity-best.ActiveTasks) {
			best = node
		}
	}
	return best
}

// AssignTask assigns a task to a node
func (c *Coordinator) AssignTask(task *Task, node *Node) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	task.Status = TaskAssigned
	task.AssignedTo = node.ID
	task.StartedAt = &now

	if n, ok := c.nodes[node.ID]; ok {
		n.ActiveTasks++
	}
}

// CompleteTask marks a task as completed
func (c *Coordinator) CompleteTask(taskID string, result *TaskResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	task, ok := c.tasks[taskID]
	if !ok {
		return
	}

	now := time.Now()
	task.CompletedAt = &now
	task.Result = result

	if result.Success {
		task.Status = TaskCompleted
	} else {
		task.Status = TaskFailed
	}

	// Decrement node active tasks
	if node, ok := c.nodes[task.AssignedTo]; ok {
		if node.ActiveTasks > 0 {
			node.ActiveTasks--
		}
	}

	if c.OnTaskComplete != nil {
		go c.OnTaskComplete(task)
	}
}

// GetNodes returns all registered nodes
func (c *Coordinator) GetNodes() []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()

	nodes := make([]*Node, 0, len(c.nodes))
	for _, node := range c.nodes {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetTasks returns all tasks
func (c *Coordinator) GetTasks() []*Task {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tasks := make([]*Task, 0, len(c.tasks))
	for _, task := range c.tasks {
		tasks = append(tasks, task)
	}
	return tasks
}

// GetTask returns a specific task
func (c *Coordinator) GetTask(taskID string) (*Task, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	task, ok := c.tasks[taskID]
	return task, ok
}

// Stats returns coordinator statistics
func (c *Coordinator) Stats() *CoordinatorStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CoordinatorStats{
		TotalNodes:     len(c.nodes),
		HealthyNodes:   0,
		TotalTasks:     len(c.tasks),
		PendingTasks:   0,
		RunningTasks:   0,
		CompletedTasks: 0,
		FailedTasks:    0,
	}

	for _, node := range c.nodes {
		if node.Status == StatusHealthy {
			stats.HealthyNodes++
		}
	}

	for _, task := range c.tasks {
		switch task.Status {
		case TaskPending:
			stats.PendingTasks++
		case TaskRunning, TaskAssigned:
			stats.RunningTasks++
		case TaskCompleted:
			stats.CompletedTasks++
		case TaskFailed:
			stats.FailedTasks++
		}
	}

	return stats
}

// CoordinatorStats contains coordinator metrics
type CoordinatorStats struct {
	TotalNodes     int `json:"total_nodes"`
	HealthyNodes   int `json:"healthy_nodes"`
	TotalTasks     int `json:"total_tasks"`
	PendingTasks   int `json:"pending_tasks"`
	RunningTasks   int `json:"running_tasks"`
	CompletedTasks int `json:"completed_tasks"`
	FailedTasks    int `json:"failed_tasks"`
}

// StartDistributor starts the task distribution loop
func (c *Coordinator) StartDistributor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case task := <-c.taskQueue:
				node := c.GetAvailableNode()
				if node != nil {
					c.AssignTask(task, node)
				} else {
					// Re-queue task
					select {
					case c.taskQueue <- task:
					default:
					}
				}
			case <-ticker.C:
				c.checkNodeHealth()
			}
		}
	}()
}

func (c *Coordinator) checkNodeHealth() {
	c.mu.Lock()
	defer c.mu.Unlock()

	staleThreshold := time.Now().Add(-duration.WorkerStale)
	for _, node := range c.nodes {
		if node.LastSeen.Before(staleThreshold) && node.Status == StatusHealthy {
			node.Status = StatusUnhealthy
		}
	}
}

// Heartbeat updates the last seen time for a node
func (c *Coordinator) Heartbeat(nodeID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	node, ok := c.nodes[nodeID]
	if !ok {
		return false
	}

	node.LastSeen = time.Now()
	if node.Status == StatusUnhealthy {
		node.Status = StatusHealthy
	}
	return true
}

// Worker represents a worker node that executes tasks
type Worker struct {
	Node        *Node
	Coordinator string // Coordinator address
	TaskHandler func(context.Context, *Task) *TaskResult
	StopChan    chan struct{}
	httpClient  *http.Client
}

// NewWorker creates a new worker
func NewWorker(id, address, coordinator string, capacity int) *Worker {
	return &Worker{
		Node: &Node{
			ID:       id,
			Address:  address,
			Role:     RoleWorker,
			Capacity: capacity,
			Status:   StatusHealthy,
		},
		Coordinator: coordinator,
		StopChan:    make(chan struct{}),
		httpClient:  httpclient.Default(),
	}
}

// Run starts the worker loop
func (w *Worker) Run(ctx context.Context) error {
	// Register with coordinator
	if err := w.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Start heartbeat
	go w.heartbeatLoop(ctx)

	// Start task polling
	go w.pollTasks(ctx)

	<-ctx.Done()
	return nil
}

func (w *Worker) register() error {
	// In a real implementation, this would HTTP POST to coordinator
	return nil
}

func (w *Worker) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(duration.WorkerHeartbeat)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.StopChan:
			return
		case <-ticker.C:
			w.sendHeartbeat()
		}
	}
}

func (w *Worker) sendHeartbeat() {
	// In a real implementation, this would HTTP POST to coordinator
}

func (w *Worker) pollTasks(ctx context.Context) {
	ticker := time.NewTicker(duration.RetryFast)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.StopChan:
			return
		case <-ticker.C:
			w.fetchAndExecuteTask(ctx)
		}
	}
}

func (w *Worker) fetchAndExecuteTask(ctx context.Context) {
	// In a real implementation, this would:
	// 1. HTTP GET task from coordinator
	// 2. Execute task using TaskHandler
	// 3. HTTP POST result to coordinator
}

// Stop gracefully stops the worker
func (w *Worker) Stop() {
	close(w.StopChan)
	w.Node.Status = StatusDraining
}

// API handlers for coordinator HTTP server

// RegisterHandler handles node registration
type RegisterRequest struct {
	Node *Node `json:"node"`
}

type RegisterResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// TaskRequest is for task submission
type TaskRequest struct {
	Tasks []*Task `json:"tasks"`
}

type TaskResponse struct {
	TaskIDs []string `json:"task_ids"`
}

// ServeHTTP implements http.Handler for the coordinator API
func (c *Coordinator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/nodes":
		c.handleNodes(w, r)
	case "/api/tasks":
		c.handleTasks(w, r)
	case "/api/stats":
		c.handleStats(w, r)
	case "/api/heartbeat":
		c.handleHeartbeat(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (c *Coordinator) handleNodes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		nodes := c.GetNodes()
		json.NewEncoder(w).Encode(nodes)
	case http.MethodPost:
		var req RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := c.RegisterNode(req.Node); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(RegisterResponse{Success: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *Coordinator) handleTasks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tasks := c.GetTasks()
		json.NewEncoder(w).Encode(tasks)
	case http.MethodPost:
		var req TaskRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var taskIDs []string
		for _, task := range req.Tasks {
			if err := c.SubmitTask(task); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			taskIDs = append(taskIDs, task.ID)
		}
		json.NewEncoder(w).Encode(TaskResponse{TaskIDs: taskIDs})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (c *Coordinator) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stats := c.Stats()
	json.NewEncoder(w).Encode(stats)
}

func (c *Coordinator) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	if !c.Heartbeat(nodeID) {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Start starts the coordinator HTTP server
func (c *Coordinator) Start(ctx context.Context) error {
	c.httpServer = &http.Server{
		Addr:    c.Address,
		Handler: c,
	}

	// Start distributor
	c.StartDistributor(ctx)

	// Start HTTP server
	go func() {
		<-ctx.Done()
		c.httpServer.Shutdown(context.Background())
	}()

	return c.httpServer.ListenAndServe()
}

// TaskSplitter splits a large task into smaller subtasks
type TaskSplitter struct {
	MaxTargetsPerTask int
}

// NewTaskSplitter creates a new task splitter
func NewTaskSplitter(maxTargets int) *TaskSplitter {
	if maxTargets <= 0 {
		maxTargets = 100
	}
	return &TaskSplitter{MaxTargetsPerTask: maxTargets}
}

// Split divides targets into multiple tasks
func (s *TaskSplitter) Split(taskType string, targets []string, config map[string]interface{}) []*Task {
	if len(targets) <= s.MaxTargetsPerTask {
		return []*Task{{
			Type:   taskType,
			Target: targets[0],
			Config: config,
		}}
	}

	var tasks []*Task
	for i := 0; i < len(targets); i += s.MaxTargetsPerTask {
		end := i + s.MaxTargetsPerTask
		if end > len(targets) {
			end = len(targets)
		}

		batch := targets[i:end]
		task := &Task{
			Type:   taskType,
			Target: batch[0], // First target
			Config: map[string]interface{}{
				"targets": batch,
			},
		}
		if config != nil {
			for k, v := range config {
				task.Config[k] = v
			}
		}
		tasks = append(tasks, task)
	}

	return tasks
}

// ResultAggregator aggregates results from distributed tasks
type ResultAggregator struct {
	results map[string]*TaskResult
	mu      sync.RWMutex
}

// NewResultAggregator creates a new result aggregator
func NewResultAggregator() *ResultAggregator {
	return &ResultAggregator{
		results: make(map[string]*TaskResult),
	}
}

// Add adds a task result
func (a *ResultAggregator) Add(taskID string, result *TaskResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results[taskID] = result
}

// GetAll returns all results
func (a *ResultAggregator) GetAll() map[string]*TaskResult {
	a.mu.RLock()
	defer a.mu.RUnlock()

	results := make(map[string]*TaskResult, len(a.results))
	for k, v := range a.results {
		results[k] = v
	}
	return results
}

// Summary returns aggregated statistics
func (a *ResultAggregator) Summary() *AggregatedSummary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	summary := &AggregatedSummary{
		TotalTasks: len(a.results),
	}

	for _, result := range a.results {
		if result.Success {
			summary.SuccessfulTasks++
		} else {
			summary.FailedTasks++
		}
		summary.TotalDuration += result.Duration
	}

	if summary.TotalTasks > 0 {
		summary.AverageDuration = summary.TotalDuration / time.Duration(summary.TotalTasks)
	}

	return summary
}

// AggregatedSummary contains summary statistics
type AggregatedSummary struct {
	TotalTasks      int           `json:"total_tasks"`
	SuccessfulTasks int           `json:"successful_tasks"`
	FailedTasks     int           `json:"failed_tasks"`
	TotalDuration   time.Duration `json:"total_duration"`
	AverageDuration time.Duration `json:"average_duration"`
}
