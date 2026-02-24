// Package intelligence provides advanced cognitive capabilities for WAFtester.
// This file implements an influence graph for dynamic cross-phase correlation.
// Replaces the hardcoded 5-case switch in correlatePhase() with a data-driven
// graph where nodes are phases/categories/techniques and edges carry weighted
// influence that adapts through reinforcement and decay.
package intelligence

import (
	"sort"
	"sync"
)

// InfluenceNode represents a phase, category, or finding type in the graph.
type InfluenceNode struct {
	ID       string            // e.g., "phase:sqli", "category:xss", "finding:bypass"
	Type     string            // "phase", "category", "finding", "technique"
	Weight   float64           // Current accumulated influence score
	Metadata map[string]string // Arbitrary metadata
}

// InfluenceEdge represents a directional influence between nodes.
type InfluenceEdge struct {
	Source       string  // Source node ID
	Target       string  // Target node ID
	Weight       float64 // Influence strength (0.0-1.0)
	Observations int     // How many times this edge was reinforced
}

// InfluenceGraph manages cross-phase influence propagation.
type InfluenceGraph struct {
	mu    sync.RWMutex
	nodes map[string]*InfluenceNode
	edges map[string]map[string]*InfluenceEdge // source → target → edge
}

// NewInfluenceGraph creates an empty influence graph.
func NewInfluenceGraph() *InfluenceGraph {
	return &InfluenceGraph{
		nodes: make(map[string]*InfluenceNode),
		edges: make(map[string]map[string]*InfluenceEdge),
	}
}

// AddNode creates or updates a node in the graph.
func (g *InfluenceGraph) AddNode(id, nodeType string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[id]; !ok {
		g.nodes[id] = &InfluenceNode{
			ID:       id,
			Type:     nodeType,
			Metadata: make(map[string]string),
		}
	}
}

// AddEdge creates or strengthens a directional edge.
// If the edge exists, weight is updated to the max of current and new.
func (g *InfluenceGraph) AddEdge(source, target string, weight float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.ensureNode(source, "")
	g.ensureNode(target, "")

	if _, ok := g.edges[source]; !ok {
		g.edges[source] = make(map[string]*InfluenceEdge)
	}

	if edge, ok := g.edges[source][target]; ok {
		if weight > edge.Weight {
			edge.Weight = weight
		}
		edge.Observations++
	} else {
		g.edges[source][target] = &InfluenceEdge{
			Source:       source,
			Target:       target,
			Weight:       weight,
			Observations: 1,
		}
	}
}

// Propagate sends a signal from sourceID through the graph using BFS.
// Each hop multiplies the signal by the edge weight (decay).
// Accumulated influence is stored on each reached node's Weight field.
func (g *InfluenceGraph) Propagate(sourceID string, signal float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.nodes[sourceID]; !ok {
		return
	}

	// BFS with signal decay
	type bfsItem struct {
		nodeID string
		signal float64
	}

	visited := make(map[string]bool)
	visited[sourceID] = true
	queue := []bfsItem{{nodeID: sourceID, signal: signal}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		neighbors, ok := g.edges[current.nodeID]
		if !ok {
			continue
		}

		for targetID, edge := range neighbors {
			if visited[targetID] {
				continue
			}
			visited[targetID] = true

			propagatedSignal := current.signal * edge.Weight
			if propagatedSignal < 0.01 {
				continue // Signal too weak to propagate further
			}

			if node, ok := g.nodes[targetID]; ok {
				node.Weight += propagatedSignal
			}

			queue = append(queue, bfsItem{nodeID: targetID, signal: propagatedSignal})
		}
	}
}

// ReinforceEdge increases edge weight when a correlation is confirmed.
// Weight is capped at 1.0.
func (g *InfluenceGraph) ReinforceEdge(source, target string, amount float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if edges, ok := g.edges[source]; ok {
		if edge, ok := edges[target]; ok {
			edge.Weight += amount
			if edge.Weight > 1.0 {
				edge.Weight = 1.0
			}
			edge.Observations++
		}
	}
}

// DecayEdge decreases edge weight when a correlation is not confirmed.
// Weight is floored at 0.0.
func (g *InfluenceGraph) DecayEdge(source, target string, factor float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if edges, ok := g.edges[source]; ok {
		if edge, ok := edges[target]; ok {
			edge.Weight *= factor
			if edge.Weight < 0.0 {
				edge.Weight = 0.0
			}
		}
	}
}

// GetInfluenced returns nodes influenced above a minimum weight threshold.
// Sorted by weight descending.
func (g *InfluenceGraph) GetInfluenced(sourceID string, minWeight float64) []InfluenceNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var result []InfluenceNode
	for _, node := range g.nodes {
		if node.ID == sourceID {
			continue
		}
		if node.Weight >= minWeight {
			result = append(result, *node)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Weight > result[j].Weight
	})

	return result
}

// TopInfluencers returns the top N edges pointing to targetID, sorted by weight.
func (g *InfluenceGraph) TopInfluencers(targetID string, n int) []InfluenceEdge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var influencers []InfluenceEdge
	for _, targets := range g.edges {
		if edge, ok := targets[targetID]; ok {
			influencers = append(influencers, *edge)
		}
	}

	sort.Slice(influencers, func(i, j int) bool {
		return influencers[i].Weight > influencers[j].Weight
	})

	if n > 0 && len(influencers) > n {
		influencers = influencers[:n]
	}

	return influencers
}

// NodeCount returns the number of nodes in the graph.
func (g *InfluenceGraph) NodeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes)
}

// EdgeCount returns the total number of edges in the graph.
func (g *InfluenceGraph) EdgeCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	count := 0
	for _, targets := range g.edges {
		count += len(targets)
	}
	return count
}

// ResetWeights zeros all node weights (between propagation rounds).
func (g *InfluenceGraph) ResetWeights() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, node := range g.nodes {
		node.Weight = 0
	}
}

// SeedKnownCorrelations initializes the graph with correlations
// extracted from the original hardcoded correlatePhase() switch.
// These are starting points; the graph adapts via reinforcement.
func SeedKnownCorrelations(graph *InfluenceGraph) {
	// Phase nodes
	phases := []string{
		"discovery", "js-analysis", "leaky-paths", "params", "waf-testing",
	}
	for _, p := range phases {
		graph.AddNode("phase:"+p, "phase")
	}

	// Category nodes
	categories := []string{
		"sqli", "xss", "ssrf", "lfi", "ssti", "rce", "cmdi",
		"idor", "redirect", "xxe", "auth", "jwt", "secret",
	}
	for _, c := range categories {
		graph.AddNode("category:"+c, "category")
	}

	// Correlation: discovery → js-analysis (prepareJSAnalysis)
	graph.AddEdge("phase:discovery", "phase:js-analysis", 0.8)

	// Correlation: js-analysis → discovery (correlateJSWithDiscovery)
	graph.AddEdge("phase:js-analysis", "phase:discovery", 0.6)

	// Correlation: leaky-paths → auth/jwt/secret (prioritizeFromLeakyPaths)
	graph.AddEdge("phase:leaky-paths", "category:auth", 0.7)
	graph.AddEdge("phase:leaky-paths", "category:jwt", 0.7)
	graph.AddEdge("phase:leaky-paths", "category:secret", 0.8)

	// Correlation: params → attack categories (enhancePayloadTargeting)
	graph.AddEdge("phase:params", "category:sqli", 0.7)
	graph.AddEdge("phase:params", "category:idor", 0.6)
	graph.AddEdge("phase:params", "category:ssrf", 0.7)
	graph.AddEdge("phase:params", "category:redirect", 0.6)
	graph.AddEdge("phase:params", "category:lfi", 0.7)
	graph.AddEdge("phase:params", "category:ssti", 0.7)
	graph.AddEdge("phase:params", "category:cmdi", 0.8)
	graph.AddEdge("phase:params", "category:rce", 0.8)
	graph.AddEdge("phase:params", "category:xss", 0.6)

	// Cross-category correlations (common in real WAFs)
	graph.AddEdge("category:sqli", "category:lfi", 0.5)
	graph.AddEdge("category:xss", "category:ssti", 0.5)
	graph.AddEdge("category:ssrf", "category:rce", 0.4)
	graph.AddEdge("category:lfi", "category:rce", 0.4)
	graph.AddEdge("category:cmdi", "category:rce", 0.7)
}

// Export serializes the influence graph for persistence.
func (g *InfluenceGraph) Export() *InfluenceGraphState {
	g.mu.RLock()
	defer g.mu.RUnlock()

	nodes := make(map[string]*InfluenceNodeState, len(g.nodes))
	for id, node := range g.nodes {
		nodes[id] = &InfluenceNodeState{
			Type:   node.Type,
			Weight: node.Weight,
		}
	}

	var edges []InfluenceEdgeState
	for _, targets := range g.edges {
		for _, edge := range targets {
			edges = append(edges, InfluenceEdgeState{
				Source: edge.Source,
				Target: edge.Target,
				Weight: edge.Weight,
				Obs:    edge.Observations,
			})
		}
	}

	return &InfluenceGraphState{
		Nodes: nodes,
		Edges: edges,
	}
}

// Import restores the influence graph from persistence.
func (g *InfluenceGraph) Import(state *InfluenceGraphState) {
	if state == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	g.nodes = make(map[string]*InfluenceNode, len(state.Nodes))
	for id, ns := range state.Nodes {
		g.nodes[id] = &InfluenceNode{
			ID:       id,
			Type:     ns.Type,
			Weight:   ns.Weight,
			Metadata: make(map[string]string),
		}
	}

	g.edges = make(map[string]map[string]*InfluenceEdge)
	for _, es := range state.Edges {
		if _, ok := g.edges[es.Source]; !ok {
			g.edges[es.Source] = make(map[string]*InfluenceEdge)
		}
		g.edges[es.Source][es.Target] = &InfluenceEdge{
			Source:       es.Source,
			Target:       es.Target,
			Weight:       es.Weight,
			Observations: es.Obs,
		}
	}
}

// Reset clears all nodes and edges, returning the graph to its initial state.
func (g *InfluenceGraph) Reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes = make(map[string]*InfluenceNode)
	g.edges = make(map[string]map[string]*InfluenceEdge)
}

// ensureNode creates a node if it doesn't exist (must hold lock).
func (g *InfluenceGraph) ensureNode(id, nodeType string) {
	if _, ok := g.nodes[id]; !ok {
		g.nodes[id] = &InfluenceNode{
			ID:       id,
			Type:     nodeType,
			Metadata: make(map[string]string),
		}
	}
}
