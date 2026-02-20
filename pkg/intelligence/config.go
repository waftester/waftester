// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file defines configuration for all intelligence modules
package intelligence

// ══════════════════════════════════════════════════════════════════════════════
// MODULE CONFIGURATION - Centralized configuration for all modules
// Extract hardcoded values to make them tunable without code changes
// ══════════════════════════════════════════════════════════════════════════════

// PredictorConfig contains configuration for the Predictor module
type PredictorConfig struct {
	// EMA alpha for rate updates (0.0-1.0, higher = faster adaptation)
	EMAAlpha float64

	// Latency EMA alpha (slower than general to smooth out network jitter)
	LatencyEMAAlpha float64

	// Factor weights for prediction scoring (must sum to ~1.0)
	CategoryWeight   float64
	EncodingWeight   float64
	PayloadWeight    float64
	EndpointWeight   float64
	StatusCodeWeight float64
	LatencyWeight    float64
	TechStackWeight  float64

	// UCB1 exploration weight (0.0 = pure exploitation, higher = more exploration)
	ExplorationWeight float64

	// Minimum observations before factor contributes to prediction
	MinObservationsForFactor int

	// Threshold for "high confidence" predictions
	HighConfidenceThreshold float64
}

// DefaultPredictorConfig returns sensible defaults for Predictor
func DefaultPredictorConfig() *PredictorConfig {
	return &PredictorConfig{
		EMAAlpha:                 0.1,
		LatencyEMAAlpha:          0.2,
		CategoryWeight:           0.30,
		EncodingWeight:           0.20,
		PayloadWeight:            0.25,
		EndpointWeight:           0.15,
		StatusCodeWeight:         0.05,
		LatencyWeight:            0.03,
		TechStackWeight:          0.02,
		ExplorationWeight:        0.15,
		MinObservationsForFactor: 3,
		HighConfidenceThreshold:  0.7,
	}
}

// MutatorConfig contains configuration for the MutationStrategist
type MutatorConfig struct {
	// EMA alpha for encoding effectiveness
	EncodingEMAAlpha float64

	// Minimum patterns to consider for mutation suggestions
	MinPatternsForSuggestion int

	// Maximum mutations to return per request
	MaxMutationsPerRequest int

	// Confidence thresholds
	HighConfidenceThreshold float64
	MinConfidenceThreshold  float64
}

// DefaultMutatorConfig returns sensible defaults for MutationStrategist
func DefaultMutatorConfig() *MutatorConfig {
	return &MutatorConfig{
		EncodingEMAAlpha:         0.2,
		MinPatternsForSuggestion: 2,
		MaxMutationsPerRequest:   5,
		HighConfidenceThreshold:  0.8,
		MinConfidenceThreshold:   0.3,
	}
}

// ClustererConfig contains configuration for EndpointClusterer
type ClustererConfig struct {
	// Similarity threshold for clustering (0.0-1.0)
	SimilarityThreshold float64

	// Minimum endpoints in cluster for valid analysis
	MinEndpointsPerCluster int

	// Maximum clusters to maintain
	MaxClusters int

	// Maximum endpoints to track (prevents unbounded behavior map growth)
	MaxEndpoints int
}

// DefaultClustererConfig returns sensible defaults for EndpointClusterer
func DefaultClustererConfig() *ClustererConfig {
	return &ClustererConfig{
		SimilarityThreshold:    0.8,
		MinEndpointsPerCluster: 2,
		MaxClusters:            100,
		MaxEndpoints:           10000,
	}
}

// AnomalyConfig contains configuration for AnomalyDetector
type AnomalyConfig struct {
	// Rolling window size for statistics
	WindowSize int

	// Z-score threshold for anomaly detection
	ZScoreThreshold float64

	// EMA alpha for smoothing
	EMAAlpha float64

	// Minimum samples before calculating anomalies
	MinSamplesForAnomaly int

	// Confidence thresholds
	HighConfidenceThreshold   float64
	MediumConfidenceThreshold float64
	LowConfidenceThreshold    float64
}

// DefaultAnomalyConfig returns sensible defaults for AnomalyDetector
func DefaultAnomalyConfig() *AnomalyConfig {
	return &AnomalyConfig{
		WindowSize:                100,
		ZScoreThreshold:           2.0,
		EMAAlpha:                  0.1,
		MinSamplesForAnomaly:      10,
		HighConfidenceThreshold:   0.9,
		MediumConfidenceThreshold: 0.7,
		LowConfidenceThreshold:    0.5,
	}
}

// PathfinderConfig contains configuration for AttackPathOptimizer
type PathfinderConfig struct {
	// Category values for path scoring
	CategoryValues map[string]float64

	// Maximum BFS depth for path finding
	MaxBFSDepth int

	// Maximum paths to return
	MaxPaths int

	// Node pruning threshold (nodes with value below this are pruned)
	PruneThreshold float64

	// Maximum nodes before pruning kicks in
	MaxNodesBeforePrune int

	// Maximum edges before edge pruning kicks in
	MaxEdgesBeforePrune int
}

// DefaultPathfinderConfig returns sensible defaults for AttackPathOptimizer
func DefaultPathfinderConfig() *PathfinderConfig {
	return &PathfinderConfig{
		CategoryValues: map[string]float64{
			"sqli":    1.0,
			"xss":     0.9,
			"rce":     1.0,
			"lfi":     0.8,
			"ssrf":    0.85,
			"xxe":     0.9,
			"ssti":    0.95,
			"idor":    0.7,
			"default": 0.5,
		},
		MaxBFSDepth:         10,
		MaxPaths:            20,
		PruneThreshold:      0.1,
		MaxNodesBeforePrune: 1000,
		MaxEdgesBeforePrune: 5000,
	}
}

// MemoryConfig contains configuration for Memory module
type MemoryConfig struct {
	// Maximum findings to store before eviction
	MaxFindings int

	// Eviction percentage when capacity reached (0.0-1.0)
	EvictionPercentage float64
}

// DefaultMemoryConfig returns sensible defaults for Memory
func DefaultMemoryConfig() *MemoryConfig {
	return &MemoryConfig{
		MaxFindings:        10000,
		EvictionPercentage: 0.1,
	}
}

// WAFModelConfig contains configuration for WAFBehaviorModel
type WAFModelConfig struct {
	// Minimum observations before generating insights
	MinObservationsForInsight int

	// Bypass rate threshold for identifying weakness
	WeaknessThreshold float64

	// Block rate threshold for identifying strength
	StrengthThreshold float64

	// Confidence thresholds
	HighConfidenceThreshold float64
	LowConfidenceThreshold  float64
}

// DefaultWAFModelConfig returns sensible defaults for WAFBehaviorModel
func DefaultWAFModelConfig() *WAFModelConfig {
	return &WAFModelConfig{
		MinObservationsForInsight: 5,
		WeaknessThreshold:         0.5,
		StrengthThreshold:         0.1,
		HighConfidenceThreshold:   0.7,
		LowConfidenceThreshold:    0.6,
	}
}

// TechProfileConfig contains configuration for TechProfile
type TechProfileConfig struct {
	// Confidence threshold for detection
	DetectionConfidenceThreshold float64

	// Score threshold for considering technology "detected"
	DetectedScoreThreshold float64
}

// DefaultTechProfileConfig returns sensible defaults for TechProfile
func DefaultTechProfileConfig() *TechProfileConfig {
	return &TechProfileConfig{
		DetectionConfidenceThreshold: 0.7,
		DetectedScoreThreshold:       0.5,
	}
}
