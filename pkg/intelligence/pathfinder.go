// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file implements Attack Path Optimizer - finding optimal attack paths
package intelligence

import (
	"fmt"
	"sort"
	"sync"
)

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK PATH OPTIMIZER - Graph-based attack path modeling
// Finds optimal paths through vulnerability chains, prioritizing high-value targets
// ══════════════════════════════════════════════════════════════════════════════

// AttackPathOptimizer finds optimal attack paths through the target
type AttackPathOptimizer struct {
	mu sync.RWMutex

	// Attack graph nodes and edges
	nodes map[string]*AttackNode
	edges []AttackEdge

	// Learned value scores
	nodeValues map[string]float64

	// Attack paths
	paths       []*AttackPath
	optimalPath *AttackPath

	// Dirty flag: set when graph changes, cleared after recalculation
	dirty bool

	// Configuration
	config *PathfinderConfig
}

// AttackNode represents a point in the attack graph
type AttackNode struct {
	ID          string
	Type        NodeType
	Path        string // Endpoint path if applicable
	Category    string // Attack category if applicable
	Description string
	Value       float64  // Security value (higher = more valuable target)
	Reachable   bool     // Can be reached from current position
	Exploited   bool     // Already successfully exploited
	BlockedBy   []string // What's blocking access to this node
	RequiredFor []string // What this node enables access to
}

// NodeType categorizes attack nodes
type NodeType string

const (
	NodeEndpoint   NodeType = "endpoint"      // A testable endpoint
	NodeVulnerable NodeType = "vulnerability" // A confirmed vulnerability
	NodePrivilege  NodeType = "privilege"     // An escalated privilege level
	NodeData       NodeType = "data"          // Sensitive data access
	NodeRCE        NodeType = "rce"           // Remote code execution
	NodeAuth       NodeType = "auth"          // Authentication bypass
	NodeInjection  NodeType = "injection"     // Code/SQL/Command injection
)

// AttackEdge connects two nodes
type AttackEdge struct {
	From          string
	To            string
	SuccessProb   float64 // Probability of successful traversal
	RequiredSkill string  // What attack category is needed
	Payload       string  // If known, the payload that works
	Blocked       bool    // Is this edge blocked by WAF?
}

// AttackPath represents a chain of attacks
type AttackPath struct {
	Nodes       []string
	TotalValue  float64
	SuccessProb float64
	Length      int
	Description string
	Steps       []PathStep
}

// PathStep describes one step in an attack path
type PathStep struct {
	From        string
	To          string
	Action      string
	Payload     string
	SuccessProb float64
}

// NewAttackPathOptimizer creates a new optimizer
func NewAttackPathOptimizer() *AttackPathOptimizer {
	return NewAttackPathOptimizerWithConfig(DefaultPathfinderConfig())
}

// NewAttackPathOptimizerWithConfig creates a new optimizer with custom config
func NewAttackPathOptimizerWithConfig(config *PathfinderConfig) *AttackPathOptimizer {
	if config == nil {
		config = DefaultPathfinderConfig()
	}
	return &AttackPathOptimizer{
		nodes:      make(map[string]*AttackNode),
		edges:      make([]AttackEdge, 0),
		nodeValues: make(map[string]float64),
		paths:      make([]*AttackPath, 0),
		config:     config,
	}
}

// AddNode adds a node to the attack graph
func (apo *AttackPathOptimizer) AddNode(node *AttackNode) {
	if node == nil {
		return
	}
	apo.mu.Lock()
	defer apo.mu.Unlock()

	apo.nodes[node.ID] = node
	apo.nodeValues[node.ID] = node.Value
}

// AddEdge adds an edge between nodes
func (apo *AttackPathOptimizer) AddEdge(from, to string, successProb float64, requiredSkill, payload string) {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	apo.edges = append(apo.edges, AttackEdge{
		From:          from,
		To:            to,
		SuccessProb:   successProb,
		RequiredSkill: requiredSkill,
		Payload:       payload,
	})
}

// LearnFromBypass updates the graph when a bypass is found
func (apo *AttackPathOptimizer) LearnFromBypass(path string, category string, payload string) {
	// Check if pruning needed BEFORE acquiring lock (read-only check is safe)
	// This avoids the complexity of unlock/prune/relock mid-function
	apo.mu.RLock()
	edgeCount := len(apo.edges)
	maxEdges := 5000
	if apo.config != nil && apo.config.MaxEdgesBeforePrune > 0 {
		maxEdges = apo.config.MaxEdgesBeforePrune
	}
	apo.mu.RUnlock()

	// Prune first if needed (PruneNodes acquires its own lock)
	if edgeCount >= maxEdges {
		apo.PruneNodes()
	}

	// Now acquire write lock for the actual update
	apo.mu.Lock()
	defer apo.mu.Unlock()

	// Create/update endpoint node
	endpointID := "endpoint:" + path
	if _, exists := apo.nodes[endpointID]; !exists {
		apo.nodes[endpointID] = &AttackNode{
			ID:        endpointID,
			Type:      NodeEndpoint,
			Path:      path,
			Reachable: true,
		}
	}
	apo.nodes[endpointID].Reachable = true

	// Create vulnerability node
	vulnID := fmt.Sprintf("vuln:%s:%s", category, path)
	value := apo.getCategoryValue(category)
	apo.nodes[vulnID] = &AttackNode{
		ID:        vulnID,
		Type:      NodeVulnerable,
		Path:      path,
		Category:  category,
		Value:     value,
		Exploited: true,
		Reachable: true,
	}

	// Create edge from endpoint to vulnerability
	apo.edges = append(apo.edges, AttackEdge{
		From:          endpointID,
		To:            vulnID,
		SuccessProb:   1.0, // Already confirmed
		RequiredSkill: category,
		Payload:       payload,
	})

	// Create edges to potential escalation targets
	apo.createEscalationEdges(vulnID, category)

	// Mark dirty instead of recalculating on every bypass.
	// Call RecalculateIfDirty() at phase boundaries for batch efficiency.
	apo.dirty = true
}

// LearnFromBlock updates the graph when an attack is blocked
func (apo *AttackPathOptimizer) LearnFromBlock(path string, category string) {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	endpointID := "endpoint:" + path
	vulnID := fmt.Sprintf("vuln:%s:%s", category, path)

	// Mark edge as blocked
	for i := range apo.edges {
		if apo.edges[i].From == endpointID && apo.edges[i].To == vulnID {
			apo.edges[i].Blocked = true
			apo.edges[i].SuccessProb *= 0.5 // Reduce probability
		}
	}
}

// getCategoryValue returns the security value of a category
func (apo *AttackPathOptimizer) getCategoryValue(category string) float64 {
	// Use config values if available
	if apo.config != nil && apo.config.CategoryValues != nil {
		if v, ok := apo.config.CategoryValues[category]; ok {
			return v * 100 // Config uses 0-1 scale, internal uses 0-100
		}
		if v, ok := apo.config.CategoryValues["default"]; ok {
			return v * 100
		}
	}
	// Fallback to hardcoded values
	values := map[string]float64{
		"rce":             100.0,
		"sqli":            80.0,
		"cmdi":            85.0,
		"ssrf":            70.0,
		"xxe":             65.0,
		"ssti":            75.0,
		"lfi":             60.0,
		"rfi":             70.0,
		"xss":             40.0,
		"idor":            50.0,
		"auth-bypass":     90.0,
		"jwt":             55.0,
		"deserialization": 80.0,
		"traversal":       55.0,
	}
	if v, ok := values[category]; ok {
		return v
	}
	return 30.0
}

// createEscalationEdges creates edges to potential escalation targets
func (apo *AttackPathOptimizer) createEscalationEdges(fromID string, category string) {
	// Define escalation paths based on vulnerability type
	escalations := map[string][]struct {
		targetType NodeType
		prob       float64
		desc       string
	}{
		"sqli": {
			{NodeData, 0.8, "Extract sensitive data"},
			{NodeAuth, 0.6, "Bypass authentication"},
			{NodeRCE, 0.3, "Escalate to RCE via SQLi"},
		},
		"rce": {
			{NodePrivilege, 0.9, "Gain shell access"},
			{NodeData, 0.95, "Access all data"},
		},
		"cmdi": {
			{NodePrivilege, 0.85, "Execute system commands"},
			{NodeRCE, 0.9, "Full RCE achieved"},
		},
		"ssrf": {
			{NodeData, 0.7, "Access internal services"},
			{NodePrivilege, 0.4, "Access cloud metadata"},
		},
		"lfi": {
			{NodeData, 0.6, "Read sensitive files"},
			{NodeRCE, 0.2, "LFI to RCE via log poisoning"},
		},
		"ssti": {
			{NodeRCE, 0.8, "Template injection to RCE"},
		},
		"auth-bypass": {
			{NodePrivilege, 0.9, "Elevated privileges"},
			{NodeData, 0.8, "Access protected data"},
		},
		"xss": {
			{NodeAuth, 0.4, "Session hijacking"},
			{NodeData, 0.3, "Exfiltrate user data"},
		},
	}

	if targets, ok := escalations[category]; ok {
		for _, target := range targets {
			targetID := fmt.Sprintf("%s:%s", target.targetType, fromID)
			if _, exists := apo.nodes[targetID]; !exists {
				apo.nodes[targetID] = &AttackNode{
					ID:    targetID,
					Type:  target.targetType,
					Value: apo.getNodeTypeValue(target.targetType),
				}
			}
			apo.edges = append(apo.edges, AttackEdge{
				From:        fromID,
				To:          targetID,
				SuccessProb: target.prob,
			})
		}
	}
}

// Node value constants for attack path scoring.
const (
	NodeValueEndpoint   = 10.0
	NodeValueVulnerable = 50.0
	NodeValuePrivilege  = 80.0
	NodeValueData       = 70.0
	NodeValueRCE        = 100.0
	NodeValueAuth       = 60.0
	NodeValueInjection  = 65.0
	NodeValueDefault    = 20.0
)

// getNodeTypeValue returns the value of a node type.
func (apo *AttackPathOptimizer) getNodeTypeValue(nodeType NodeType) float64 {
	values := map[NodeType]float64{
		NodeEndpoint:   NodeValueEndpoint,
		NodeVulnerable: NodeValueVulnerable,
		NodePrivilege:  NodeValuePrivilege,
		NodeData:       NodeValueData,
		NodeRCE:        NodeValueRCE,
		NodeAuth:       NodeValueAuth,
		NodeInjection:  NodeValueInjection,
	}
	if v, ok := values[nodeType]; ok {
		return v
	}
	return NodeValueDefault
}

// RecalculateIfDirty recalculates paths only if the graph has changed since the last calculation.
// Call at phase boundaries (e.g., after waf-testing completes) instead of on every bypass.
func (apo *AttackPathOptimizer) RecalculateIfDirty() {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	if !apo.dirty {
		return
	}
	apo.recalculatePaths()
	apo.dirty = false
}

// recalculatePaths recalculates optimal attack paths
func (apo *AttackPathOptimizer) recalculatePaths() {
	// Find all high-value target nodes
	targets := make([]string, 0)
	for id, node := range apo.nodes {
		if node.Value >= 70.0 {
			targets = append(targets, id)
		}
	}

	// Find starting nodes (reachable endpoints)
	starts := make([]string, 0)
	for id, node := range apo.nodes {
		if node.Type == NodeEndpoint && node.Reachable {
			starts = append(starts, id)
		}
	}

	// Also include exploited vulnerabilities as starting points
	for id, node := range apo.nodes {
		if node.Exploited {
			starts = append(starts, id)
		}
	}

	// Find paths using BFS
	apo.paths = make([]*AttackPath, 0)
	for _, start := range starts {
		for _, target := range targets {
			if path := apo.findPath(start, target); path != nil {
				apo.paths = append(apo.paths, path)
			}
		}
	}

	// Sort paths by value/length ratio (efficiency)
	sort.Slice(apo.paths, func(i, j int) bool {
		effI := apo.paths[i].TotalValue / float64(apo.paths[i].Length+1)
		effJ := apo.paths[j].TotalValue / float64(apo.paths[j].Length+1)
		return effI > effJ
	})

	if len(apo.paths) > 0 {
		apo.optimalPath = apo.paths[0]
	}
}

// findPath finds a path between two nodes using BFS with depth limit
func (apo *AttackPathOptimizer) findPath(from, to string) *AttackPath {
	if from == to {
		return nil
	}

	// Get max depth from config
	maxDepth := 10 // default
	if apo.config != nil && apo.config.MaxBFSDepth > 0 {
		maxDepth = apo.config.MaxBFSDepth
	}

	// Max queue size to prevent unbounded memory growth
	const maxQueueSize = 10000

	// Build adjacency list
	adj := make(map[string][]AttackEdge)
	for _, edge := range apo.edges {
		if !edge.Blocked {
			adj[edge.From] = append(adj[edge.From], edge)
		}
	}

	// BFS with depth limit
	type queueItem struct {
		node  string
		path  []string
		edges []AttackEdge
		prob  float64
		depth int
	}

	visited := make(map[string]bool)
	queue := []queueItem{{node: from, path: []string{from}, edges: nil, prob: 1.0, depth: 0}}

	for len(queue) > 0 {
		// Prevent unbounded queue growth
		if len(queue) > maxQueueSize {
			break
		}

		current := queue[0]
		queue = queue[1:]

		if current.node == to {
			// Found path
			path := &AttackPath{
				Nodes:       current.path,
				Length:      len(current.path) - 1,
				SuccessProb: current.prob,
				TotalValue:  0,
				Steps:       make([]PathStep, 0),
			}

			// Calculate total value and build steps
			for _, nodeID := range current.path {
				if node, ok := apo.nodes[nodeID]; ok {
					path.TotalValue += node.Value
				}
			}

			for _, edge := range current.edges {
				path.Steps = append(path.Steps, PathStep{
					From:        edge.From,
					To:          edge.To,
					Action:      edge.RequiredSkill,
					Payload:     edge.Payload,
					SuccessProb: edge.SuccessProb,
				})
			}

			return path
		}

		if visited[current.node] {
			continue
		}
		visited[current.node] = true

		// Skip if we've exceeded max depth
		if current.depth >= maxDepth {
			continue
		}

		for _, edge := range adj[current.node] {
			if !visited[edge.To] {
				newPath := make([]string, len(current.path))
				copy(newPath, current.path)
				newPath = append(newPath, edge.To)

				newEdges := make([]AttackEdge, len(current.edges))
				copy(newEdges, current.edges)
				newEdges = append(newEdges, edge)

				queue = append(queue, queueItem{
					node:  edge.To,
					path:  newPath,
					edges: newEdges,
					prob:  current.prob * edge.SuccessProb,
					depth: current.depth + 1,
				})
			}
		}
	}

	return nil
}

// GetOptimalPath returns the current optimal attack path
func (apo *AttackPathOptimizer) GetOptimalPath() *AttackPath {
	apo.mu.RLock()
	defer apo.mu.RUnlock()
	return apo.optimalPath
}

// GetTopPaths returns the top N attack paths by efficiency
func (apo *AttackPathOptimizer) GetTopPaths(n int) []*AttackPath {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	if n <= 0 {
		return nil
	}
	if len(apo.paths) <= n {
		return apo.paths
	}
	return apo.paths[:n]
}

// GetNextTarget returns the next highest-value target to pursue
func (apo *AttackPathOptimizer) GetNextTarget() *AttackNode {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	if apo.optimalPath == nil || len(apo.optimalPath.Nodes) < 2 {
		return nil
	}

	// Find the first unexploited node in the optimal path
	for _, nodeID := range apo.optimalPath.Nodes {
		// Check both key existence AND nil value (map can store nil pointers)
		if node, ok := apo.nodes[nodeID]; ok && node != nil {
			if !node.Exploited && node.Type != NodeEndpoint {
				return node
			}
		}
	}

	return nil
}

// GetPriorityEndpoints returns endpoints prioritized by their path value
func (apo *AttackPathOptimizer) GetPriorityEndpoints() []EndpointPriority {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	// Calculate endpoint values based on paths they enable
	endpointValues := make(map[string]float64)
	endpointPaths := make(map[string]int)

	for _, path := range apo.paths {
		if len(path.Nodes) > 0 {
			endpoint := path.Nodes[0]
			if node, ok := apo.nodes[endpoint]; ok && node.Type == NodeEndpoint {
				endpointValues[endpoint] += path.TotalValue * path.SuccessProb
				endpointPaths[endpoint]++
			}
		}
	}

	// Build priority list
	priorities := make([]EndpointPriority, 0)
	for id, value := range endpointValues {
		if node, ok := apo.nodes[id]; ok {
			priorities = append(priorities, EndpointPriority{
				Path:      node.Path,
				Value:     value,
				PathCount: endpointPaths[id],
				Reachable: node.Reachable,
			})
		}
	}

	// Sort by value
	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i].Value > priorities[j].Value
	})

	return priorities
}

// EndpointPriority represents an endpoint's priority
type EndpointPriority struct {
	Path      string
	Value     float64
	PathCount int
	Reachable bool
}

// GetAttackCategories returns categories to focus on based on graph analysis
func (apo *AttackPathOptimizer) GetAttackCategories() []CategoryPriority {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	categoryValues := make(map[string]float64)
	categorySuccess := make(map[string]int)
	categoryTotal := make(map[string]int)

	for _, edge := range apo.edges {
		if edge.RequiredSkill != "" {
			categoryTotal[edge.RequiredSkill]++
			if !edge.Blocked {
				categoryValues[edge.RequiredSkill] += edge.SuccessProb
				if edge.SuccessProb > 0.5 {
					categorySuccess[edge.RequiredSkill]++
				}
			}
		}
	}

	priorities := make([]CategoryPriority, 0)
	for cat, value := range categoryValues {
		priorities = append(priorities, CategoryPriority{
			Category:    cat,
			TotalValue:  value,
			SuccessRate: float64(categorySuccess[cat]) / float64(maxInt(1, categoryTotal[cat])),
			EdgeCount:   categoryTotal[cat],
		})
	}

	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i].TotalValue > priorities[j].TotalValue
	})

	return priorities
}

// CategoryPriority represents an attack category's priority
type CategoryPriority struct {
	Category    string
	TotalValue  float64
	SuccessRate float64
	EdgeCount   int
}

// GetStats returns optimizer statistics
func (apo *AttackPathOptimizer) GetStats() AttackPathStats {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	stats := AttackPathStats{
		TotalNodes:     len(apo.nodes),
		TotalEdges:     len(apo.edges),
		TotalPaths:     len(apo.paths),
		NodesByType:    make(map[NodeType]int),
		ExploitedNodes: 0,
		ReachableNodes: 0,
		BlockedEdges:   0,
	}

	for _, node := range apo.nodes {
		stats.NodesByType[node.Type]++
		if node.Exploited {
			stats.ExploitedNodes++
		}
		if node.Reachable {
			stats.ReachableNodes++
		}
	}

	for _, edge := range apo.edges {
		if edge.Blocked {
			stats.BlockedEdges++
		}
	}

	if apo.optimalPath != nil {
		stats.OptimalPathLength = apo.optimalPath.Length
		stats.OptimalPathValue = apo.optimalPath.TotalValue
		stats.OptimalPathProb = apo.optimalPath.SuccessProb
	}

	return stats
}

// AttackPathStats contains optimizer statistics
type AttackPathStats struct {
	TotalNodes        int
	TotalEdges        int
	TotalPaths        int
	NodesByType       map[NodeType]int
	ExploitedNodes    int
	ReachableNodes    int
	BlockedEdges      int
	OptimalPathLength int
	OptimalPathValue  float64
	OptimalPathProb   float64
}

// ExportGraph exports the attack graph in DOT format for visualization
func (apo *AttackPathOptimizer) ExportGraph() string {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	var result string
	result = "digraph AttackGraph {\n"
	result += "  rankdir=LR;\n"
	result += "  node [shape=box];\n\n"

	// Add nodes with styling
	for id, node := range apo.nodes {
		color := "white"
		if node.Exploited {
			color = "lightgreen"
		} else if !node.Reachable {
			color = "lightgray"
		}

		shape := "box"
		switch node.Type {
		case NodeRCE:
			shape = "doubleoctagon"
			if !node.Exploited {
				color = "red"
			}
		case NodeData:
			shape = "cylinder"
		case NodePrivilege:
			shape = "diamond"
		case NodeAuth:
			shape = "hexagon"
		}

		result += fmt.Sprintf("  \"%s\" [label=\"%s\\n(%.0f)\" shape=%s fillcolor=%s style=filled];\n",
			id, node.Type, node.Value, shape, color)
	}

	result += "\n"

	// Add edges
	for _, edge := range apo.edges {
		style := "solid"
		color := "black"
		if edge.Blocked {
			style = "dashed"
			color = "red"
		} else if edge.SuccessProb > 0.7 {
			color = "green"
		}
		result += fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%.0f%%\" style=%s color=%s];\n",
			edge.From, edge.To, edge.SuccessProb*100, style, color)
	}

	result += "}\n"
	return result
}

// PruneNodes removes low-value nodes when the graph grows too large
func (apo *AttackPathOptimizer) PruneNodes() int {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	// Get thresholds from config
	maxNodes := 1000
	pruneThreshold := 0.1
	if apo.config != nil {
		if apo.config.MaxNodesBeforePrune > 0 {
			maxNodes = apo.config.MaxNodesBeforePrune
		}
		if apo.config.PruneThreshold > 0 {
			pruneThreshold = apo.config.PruneThreshold
		}
	}

	// Only prune if we exceed max nodes
	if len(apo.nodes) <= maxNodes {
		return 0
	}

	// Find nodes to prune (low value, not exploited, not in optimal path)
	optimalNodes := make(map[string]bool)
	if apo.optimalPath != nil {
		for _, nodeID := range apo.optimalPath.Nodes {
			optimalNodes[nodeID] = true
		}
	}

	toPrune := make([]string, 0)
	for id, node := range apo.nodes {
		// Don't prune exploited nodes or nodes in optimal path
		if node.Exploited || optimalNodes[id] {
			continue
		}
		// Prune low-value nodes
		if node.Value < pruneThreshold*100 { // Config uses 0-1 scale
			toPrune = append(toPrune, id)
		}
	}

	// Remove pruned nodes
	for _, id := range toPrune {
		delete(apo.nodes, id)
		delete(apo.nodeValues, id)
	}

	// Remove edges referencing pruned nodes
	prunedSet := make(map[string]bool)
	for _, id := range toPrune {
		prunedSet[id] = true
	}

	newEdges := make([]AttackEdge, 0, len(apo.edges))
	for _, edge := range apo.edges {
		if !prunedSet[edge.From] && !prunedSet[edge.To] {
			newEdges = append(newEdges, edge)
		}
	}
	apo.edges = newEdges

	// Also prune edges if they exceed max (independent of node pruning)
	maxEdges := 5000
	if apo.config != nil && apo.config.MaxEdgesBeforePrune > 0 {
		maxEdges = apo.config.MaxEdgesBeforePrune
	}
	if len(apo.edges) > maxEdges {
		// Sort edges by success probability (keep high-value edges)
		sort.Slice(apo.edges, func(i, j int) bool {
			return apo.edges[i].SuccessProb > apo.edges[j].SuccessProb
		})
		// Keep only the top edges
		apo.edges = apo.edges[:maxEdges]
	}

	// Recalculate paths after pruning
	if len(toPrune) > 0 {
		apo.recalculatePaths()
	}

	return len(toPrune)
}

// SetConfig updates the pathfinder configuration
func (apo *AttackPathOptimizer) SetConfig(config *PathfinderConfig) {
	apo.mu.Lock()
	defer apo.mu.Unlock()
	apo.config = config
}

// NodeCount returns the number of nodes in the graph
func (apo *AttackPathOptimizer) NodeCount() int {
	apo.mu.RLock()
	defer apo.mu.RUnlock()
	return len(apo.nodes)
}

// EdgeCount returns the number of edges in the graph
func (apo *AttackPathOptimizer) EdgeCount() int {
	apo.mu.RLock()
	defer apo.mu.RUnlock()
	return len(apo.edges)
}
