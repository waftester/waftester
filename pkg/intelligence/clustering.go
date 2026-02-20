// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file implements Endpoint Clustering - grouping similar endpoints for efficient testing
package intelligence

import (
	"math"
	"sort"
	"strings"
	"sync"
)

// ══════════════════════════════════════════════════════════════════════════════
// ENDPOINT CLUSTERING - Group similar endpoints, test representatives
// Reduces testing time by inferring results for similar endpoints
// ══════════════════════════════════════════════════════════════════════════════

// EndpointClusterer groups similar endpoints and tracks their behavior
type EndpointClusterer struct {
	mu sync.RWMutex

	// Clusters of similar endpoints
	clusters map[string]*EndpointCluster // cluster ID → cluster

	// Endpoint to cluster mapping
	endpointCluster map[string]string // endpoint path → cluster ID

	// Endpoint behaviors
	endpointBehaviors map[string]*EndpointBehavior

	// Similarity threshold (0.0-1.0)
	similarityThreshold float64

	// Limits to prevent unbounded growth
	maxClusters  int
	maxEndpoints int
}

// EndpointCluster represents a group of similar endpoints
type EndpointCluster struct {
	ID             string
	Representative string           // The representative endpoint to test
	Members        []string         // All endpoints in the cluster
	Pattern        string           // Common pattern (e.g., "/api/v1/users/{id}")
	Technology     string           // Detected technology
	Behavior       *ClusterBehavior // Aggregate behavior
	Confidence     float64          // Confidence that members behave similarly
}

// EndpointBehavior tracks observed behavior for an endpoint
type EndpointBehavior struct {
	Path            string
	StatusCodes     map[int]int        // status code → count
	BlockRates      map[string]float64 // category → block rate
	AvgLatency      float64            // Average response latency in ms
	Characteristics []string           // Observed characteristics
	TotalRequests   int
	BlockedRequests int
}

// ClusterBehavior aggregates behavior across cluster members
type ClusterBehavior struct {
	AvgBlockRate        float64 // Average block rate across members
	CommonStatusCodes   []int   // Most common status codes
	BlockRateByCategory map[string]float64
	Variance            float64 // How much members differ
}

// Clustering constants.
const (
	// DefaultSimilarityThreshold is the default similarity threshold for clustering endpoints.
	DefaultSimilarityThreshold = 0.7

	// DefaultLatencyEMAAlpha is the EMA alpha for latency smoothing.
	DefaultLatencyEMAAlpha = 0.1

	// DefaultBlockRateEMAAlpha is the EMA alpha for block rate smoothing.
	DefaultBlockRateEMAAlpha = 0.1
)

// NewEndpointClusterer creates a new EndpointClusterer.
func NewEndpointClusterer() *EndpointClusterer {
	return NewEndpointClustererWithConfig(DefaultClustererConfig())
}

// NewEndpointClustererWithConfig creates a new EndpointClusterer with custom configuration.
func NewEndpointClustererWithConfig(cfg *ClustererConfig) *EndpointClusterer {
	if cfg == nil {
		cfg = DefaultClustererConfig()
	}
	return &EndpointClusterer{
		clusters:            make(map[string]*EndpointCluster),
		endpointCluster:     make(map[string]string),
		endpointBehaviors:   make(map[string]*EndpointBehavior),
		similarityThreshold: cfg.SimilarityThreshold,
		maxClusters:         cfg.MaxClusters,
		maxEndpoints:        cfg.MaxEndpoints,
	}
}

// AddEndpoint adds an endpoint and automatically clusters it.
// If method is provided, endpoints with different methods are treated as distinct.
func (ec *EndpointClusterer) AddEndpoint(path string, method ...string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	// Use method:path as key when method is known, so GET and POST cluster separately
	key := path
	if len(method) > 0 && method[0] != "" {
		key = strings.ToUpper(method[0]) + ":" + path
	}

	// Skip if already added
	if _, ok := ec.endpointCluster[key]; ok {
		return
	}

	// Enforce endpoint limit to prevent unbounded behavior map growth
	if ec.maxEndpoints > 0 && len(ec.endpointBehaviors) >= ec.maxEndpoints {
		return // At capacity, don't add more endpoints
	}

	// Initialize behavior tracking
	ec.endpointBehaviors[key] = &EndpointBehavior{
		Path:        path,
		StatusCodes: make(map[int]int),
		BlockRates:  make(map[string]float64),
	}

	// Try to find matching cluster (cluster on path similarity, ignoring method)
	for clusterID, cluster := range ec.clusters {
		if ec.calculateSimilarity(path, cluster.Pattern) >= ec.similarityThreshold {
			// Add to existing cluster
			cluster.Members = append(cluster.Members, key)
			ec.endpointCluster[key] = clusterID
			return
		}
	}

	// Enforce cluster limit to prevent unbounded cluster growth
	if ec.maxClusters > 0 && len(ec.clusters) >= ec.maxClusters {
		// Can't create new cluster, try to find closest match (best-effort)
		bestClusterID := ""
		bestSimilarity := 0.0
		for clusterID, cluster := range ec.clusters {
			sim := ec.calculateSimilarity(path, cluster.Pattern)
			if sim > bestSimilarity {
				bestSimilarity = sim
				bestClusterID = clusterID
			}
		}
		if bestClusterID != "" {
			ec.clusters[bestClusterID].Members = append(ec.clusters[bestClusterID].Members, key)
			ec.endpointCluster[key] = bestClusterID
		}
		return
	}

	// Create new cluster
	pattern := ec.extractPattern(path)
	clusterID := "cluster_" + pattern
	ec.clusters[clusterID] = &EndpointCluster{
		ID:             clusterID,
		Representative: key, // First endpoint is representative
		Members:        []string{key},
		Pattern:        pattern,
		Confidence:     1.0,
	}
	ec.endpointCluster[key] = clusterID
}

// RecordBehavior records an observation for an endpoint.
// If method is provided, the composite key METHOD:path is used (matching AddEndpoint).
func (ec *EndpointClusterer) RecordBehavior(path string, statusCode int, blocked bool, category string, latencyMs float64, method ...string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	key := path
	if len(method) > 0 && method[0] != "" {
		key = strings.ToUpper(method[0]) + ":" + path
	}

	behavior, ok := ec.endpointBehaviors[key]
	if !ok {
		behavior = &EndpointBehavior{
			Path:        path,
			StatusCodes: make(map[int]int),
			BlockRates:  make(map[string]float64),
		}
		ec.endpointBehaviors[key] = behavior
	}

	behavior.StatusCodes[statusCode]++
	behavior.TotalRequests++
	if blocked {
		behavior.BlockedRequests++
	}

	// Update block rate for category
	if category != "" {
		current := behavior.BlockRates[category]
		if behavior.TotalRequests == 1 {
			behavior.BlockRates[category] = boolToFloat(blocked)
		} else {
			behavior.BlockRates[category] = current*0.9 + boolToFloat(blocked)*0.1
		}
	}

	// Update average latency
	if latencyMs > 0 {
		behavior.AvgLatency = behavior.AvgLatency*0.9 + latencyMs*0.1
	}

	// Update cluster behavior
	ec.updateClusterBehavior(key)
}

// GetRepresentatives returns representative endpoints for testing
func (ec *EndpointClusterer) GetRepresentatives() []string {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	reps := make([]string, 0, len(ec.clusters))
	for _, cluster := range ec.clusters {
		reps = append(reps, cluster.Representative)
	}
	return reps
}

// GetClusterForEndpoint returns the cluster ID for an endpoint
func (ec *EndpointClusterer) GetClusterForEndpoint(path string) string {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return ec.endpointCluster[path]
}

// InferBehavior infers behavior for an untested endpoint based on its cluster
func (ec *EndpointClusterer) InferBehavior(path string) *InferredBehavior {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	clusterID, ok := ec.endpointCluster[path]
	if !ok {
		return nil
	}

	cluster, ok := ec.clusters[clusterID]
	if !ok || cluster.Behavior == nil {
		return nil
	}

	// Find the representative's behavior
	repBehavior := ec.endpointBehaviors[cluster.Representative]
	if repBehavior == nil {
		return nil
	}

	return &InferredBehavior{
		Path:            path,
		InferredFrom:    cluster.Representative,
		ClusterSize:     len(cluster.Members),
		BlockRate:       cluster.Behavior.AvgBlockRate,
		BlockByCategory: cluster.Behavior.BlockRateByCategory,
		Confidence:      cluster.Confidence * (1 - cluster.Behavior.Variance),
		Reasoning:       "Inferred from cluster '" + cluster.Pattern + "' based on " + cluster.Representative,
	}
}

// InferredBehavior represents inferred behavior for an untested endpoint
type InferredBehavior struct {
	Path            string
	InferredFrom    string
	ClusterSize     int
	BlockRate       float64
	BlockByCategory map[string]float64
	Confidence      float64
	Reasoning       string
}

// GetSimilarEndpoints returns endpoints similar to the given one
func (ec *EndpointClusterer) GetSimilarEndpoints(path string, n int) []SimilarEndpoint {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	clusterID := ec.endpointCluster[path]
	if clusterID == "" {
		return nil
	}

	cluster := ec.clusters[clusterID]
	if cluster == nil {
		return nil
	}

	similar := make([]SimilarEndpoint, 0)
	for _, member := range cluster.Members {
		if member != path {
			similarity := ec.calculateSimilarity(path, member)
			similar = append(similar, SimilarEndpoint{
				Path:       member,
				Similarity: similarity,
				Behavior:   ec.endpointBehaviors[member],
			})
		}
	}

	// Sort by similarity
	sort.Slice(similar, func(i, j int) bool {
		return similar[i].Similarity > similar[j].Similarity
	})

	if len(similar) > n {
		return similar[:n]
	}
	return similar
}

// SimilarEndpoint represents a similar endpoint
type SimilarEndpoint struct {
	Path       string
	Similarity float64
	Behavior   *EndpointBehavior
}

// OptimizeTestOrder returns endpoints ordered by testing priority
func (ec *EndpointClusterer) OptimizeTestOrder(paths []string) []PrioritizedEndpoint {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	prioritized := make([]PrioritizedEndpoint, len(paths))

	for i, path := range paths {
		priority := 0.5 // Default priority
		reason := "No clustering data"

		// Check if this is a representative
		clusterID := ec.endpointCluster[path]
		if clusterID != "" {
			cluster := ec.clusters[clusterID]
			if cluster != nil {
				if cluster.Representative == path {
					// Representatives get highest priority
					priority = 1.0
					reason = "Cluster representative for " + cluster.Pattern
				} else {
					// Non-representatives get lower priority (can be inferred)
					priority = 0.3
					reason = "Can infer from representative " + cluster.Representative
				}
			}
		}

		prioritized[i] = PrioritizedEndpoint{
			Path:     path,
			Priority: priority,
			Reason:   reason,
		}
	}

	// Sort by priority descending
	sort.Slice(prioritized, func(i, j int) bool {
		return prioritized[i].Priority > prioritized[j].Priority
	})

	return prioritized
}

// PrioritizedEndpoint is an endpoint with testing priority
type PrioritizedEndpoint struct {
	Path     string
	Priority float64
	Reason   string
}

// calculateSimilarity calculates similarity between two paths
func (ec *EndpointClusterer) calculateSimilarity(path1, path2 string) float64 {
	// Normalize paths
	p1 := ec.normalizePath(path1)
	p2 := ec.normalizePath(path2)

	if p1 == p2 {
		return 1.0
	}

	// Split into segments
	seg1 := strings.Split(p1, "/")
	seg2 := strings.Split(p2, "/")

	// Compare segments
	if len(seg1) != len(seg2) {
		// Different depths - lower similarity
		minLen := len(seg1)
		if len(seg2) < minLen {
			minLen = len(seg2)
		}
		depthPenalty := 0.2 * float64(absInt(len(seg1)-len(seg2)))

		matches := 0
		for i := 0; i < minLen; i++ {
			if ec.segmentMatch(seg1[i], seg2[i]) {
				matches++
			}
		}
		return float64(matches)/float64(maxInt(len(seg1), len(seg2))) - depthPenalty
	}

	// Same depth - compare segments
	matches := 0
	for i := range seg1 {
		if ec.segmentMatch(seg1[i], seg2[i]) {
			matches++
		}
	}

	return float64(matches) / float64(len(seg1))
}

// segmentMatch checks if two path segments match (including patterns)
func (ec *EndpointClusterer) segmentMatch(s1, s2 string) bool {
	if s1 == s2 {
		return true
	}

	// Check if either is a parameter placeholder
	if ec.isParameter(s1) || ec.isParameter(s2) {
		return true
	}

	return false
}

// isParameter checks if a segment is a parameter (ID, UUID, number)
func (ec *EndpointClusterer) isParameter(segment string) bool {
	// Check for common patterns
	if segment == "" {
		return false
	}

	// Numeric ID
	isNumeric := true
	for _, c := range segment {
		if c < '0' || c > '9' {
			isNumeric = false
			break
		}
	}
	if isNumeric {
		return true
	}

	// UUID pattern
	if len(segment) == 36 && strings.Count(segment, "-") == 4 {
		return true
	}

	// Hash-like pattern (hex string)
	if len(segment) >= 8 && len(segment) <= 64 {
		isHex := true
		for _, c := range strings.ToLower(segment) {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				isHex = false
				break
			}
		}
		if isHex {
			return true
		}
	}

	return false
}

// normalizePath normalizes a path for comparison
func (ec *EndpointClusterer) normalizePath(path string) string {
	// Remove query string
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Remove trailing slash
	path = strings.TrimSuffix(path, "/")

	// Lowercase
	return strings.ToLower(path)
}

// extractPattern extracts a pattern from a path
func (ec *EndpointClusterer) extractPattern(path string) string {
	segments := strings.Split(ec.normalizePath(path), "/")
	result := make([]string, len(segments))

	for i, seg := range segments {
		if ec.isParameter(seg) {
			result[i] = "{id}"
		} else {
			result[i] = seg
		}
	}

	return strings.Join(result, "/")
}

// updateClusterBehavior updates aggregate behavior for a cluster
func (ec *EndpointClusterer) updateClusterBehavior(path string) {
	clusterID := ec.endpointCluster[path]
	if clusterID == "" {
		return
	}

	cluster := ec.clusters[clusterID]
	if cluster == nil {
		return
	}

	// Calculate aggregate behavior
	behavior := &ClusterBehavior{
		BlockRateByCategory: make(map[string]float64),
	}

	totalBlockRate := 0.0
	memberCount := 0
	statusCounts := make(map[int]int)
	categoryBlockRates := make(map[string][]float64)

	for _, member := range cluster.Members {
		if mb := ec.endpointBehaviors[member]; mb != nil && mb.TotalRequests > 0 {
			blockRate := float64(mb.BlockedRequests) / float64(mb.TotalRequests)
			totalBlockRate += blockRate
			memberCount++

			for code, count := range mb.StatusCodes {
				statusCounts[code] += count
			}

			for cat, rate := range mb.BlockRates {
				categoryBlockRates[cat] = append(categoryBlockRates[cat], rate)
			}
		}
	}

	if memberCount > 0 {
		behavior.AvgBlockRate = totalBlockRate / float64(memberCount)
	}

	// Find common status codes
	type codeCount struct {
		code  int
		count int
	}
	codes := make([]codeCount, 0)
	for code, count := range statusCounts {
		codes = append(codes, codeCount{code, count})
	}
	sort.Slice(codes, func(i, j int) bool {
		return codes[i].count > codes[j].count
	})
	for i := 0; i < minInt(3, len(codes)); i++ {
		behavior.CommonStatusCodes = append(behavior.CommonStatusCodes, codes[i].code)
	}

	// Average category block rates
	for cat, rates := range categoryBlockRates {
		sum := 0.0
		for _, r := range rates {
			sum += r
		}
		behavior.BlockRateByCategory[cat] = sum / float64(len(rates))
	}

	// Calculate variance
	if memberCount > 1 {
		variance := 0.0
		for _, member := range cluster.Members {
			if mb := ec.endpointBehaviors[member]; mb != nil && mb.TotalRequests > 0 {
				blockRate := float64(mb.BlockedRequests) / float64(mb.TotalRequests)
				diff := blockRate - behavior.AvgBlockRate
				variance += diff * diff
			}
		}
		behavior.Variance = variance / float64(memberCount)
		// Guard against NaN propagation from corrupted data
		if math.IsNaN(behavior.Variance) || math.IsInf(behavior.Variance, 0) {
			behavior.Variance = 0
		}
	}

	cluster.Behavior = behavior

	// Update cluster confidence based on variance, clamped to [0, 1]
	confidence := 1.0 - behavior.Variance
	if confidence < 0 {
		confidence = 0
	} else if confidence > 1.0 {
		confidence = 1.0
	}
	cluster.Confidence = confidence
}

// GetStats returns clustering statistics
func (ec *EndpointClusterer) GetStats() ClusteringStats {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	stats := ClusteringStats{
		TotalEndpoints:  len(ec.endpointBehaviors),
		TotalClusters:   len(ec.clusters),
		ClusterSizes:    make(map[string]int),
		Representatives: make([]string, 0),
	}

	for id, cluster := range ec.clusters {
		stats.ClusterSizes[id] = len(cluster.Members)
		stats.Representatives = append(stats.Representatives, cluster.Representative)
	}

	// Calculate average cluster size
	if stats.TotalClusters > 0 {
		totalSize := 0
		for _, size := range stats.ClusterSizes {
			totalSize += size
		}
		stats.AvgClusterSize = float64(totalSize) / float64(stats.TotalClusters)
	}

	// Calculate reduction (% of endpoints that don't need testing)
	if stats.TotalEndpoints > 0 {
		stats.TestingReduction = 1.0 - float64(stats.TotalClusters)/float64(stats.TotalEndpoints)
	}

	return stats
}

// ClusteringStats contains clustering statistics
type ClusteringStats struct {
	TotalEndpoints   int
	TotalClusters    int
	AvgClusterSize   float64
	TestingReduction float64 // % of endpoints that can be skipped
	ClusterSizes     map[string]int
	Representatives  []string
}

// Helper functions
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
