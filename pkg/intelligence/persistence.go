// Package intelligence provides advanced cognitive capabilities for WAFtester
// This file implements Persistence - saving and loading brain state
package intelligence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PERSISTENCE - Save and load brain state to survive restarts
// Without persistence, all learning is lost when process exits
// ══════════════════════════════════════════════════════════════════════════════

// BrainState represents the complete serializable state of the Intelligence Engine
type BrainState struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target,omitempty"`

	// Core learning state
	Memory      *MemoryState      `json:"memory"`
	WAFModel    *WAFModelState    `json:"waf_model"`
	TechProfile *TechProfileState `json:"tech_profile"`

	// Advanced cognitive module states
	Predictor   *PredictorState   `json:"predictor"`
	Mutator     *MutatorState     `json:"mutator"`
	Clusterer   *ClustererState   `json:"clusterer"`
	Pathfinder  *PathfinderState  `json:"pathfinder"`
	WAFProfiler *WAFProfilerState `json:"waf_profiler,omitempty"`
	// Note: Anomaly detector is intentionally NOT persisted (runtime-only)
	// Note: Metrics are runtime-only observability counters, not persisted

	// Master Brain module states (omitempty for backward compatibility)
	BanditCategory    *BanditState            `json:"bandit_category,omitempty"`
	BanditEncoding    *BanditState            `json:"bandit_encoding,omitempty"`
	BanditPattern     *BanditState            `json:"bandit_pattern,omitempty"`
	PhaseController   *PhaseControllerState   `json:"phase_controller,omitempty"`
	Calibrator        *CalibratorState        `json:"calibrator,omitempty"`
	InfluenceGraph    *InfluenceGraphState    `json:"influence_graph,omitempty"`
	MutationGenerator *MutationGeneratorState `json:"mutation_generator,omitempty"`

	// Statistics
	Stats *StatsState `json:"stats"`
}

// MemoryState is the serializable form of Memory
type MemoryState struct {
	Findings         []*Finding        `json:"findings"`
	MaxFindings      int               `json:"max_findings,omitempty"`
	CategoryPriority map[string]string `json:"category_priority,omitempty"`
}

// WAFModelState is the serializable form of WAFBehaviorModel
type WAFModelState struct {
	BlockPatterns     map[string]int `json:"block_patterns"`
	BypassPatterns    map[string]int `json:"bypass_patterns"`
	CategoryBlock     map[string]int `json:"category_block"`
	CategoryBypass    map[string]int `json:"category_bypass"`
	StatusCodes       map[int]int    `json:"status_codes"`
	AvgBlockedLatency int64          `json:"avg_blocked_latency_ns"`
	AvgBypassLatency  int64          `json:"avg_bypass_latency_ns"`
	BlockedCount      int            `json:"blocked_count"`
	BypassCount       int            `json:"bypass_count"`
	Weaknesses        []Weakness     `json:"weaknesses"`
	Strengths         []string       `json:"strengths"`
}

// TechProfileState is the serializable form of TechProfile
type TechProfileState struct {
	Frameworks []TechInfo         `json:"frameworks"`
	Databases  []TechInfo         `json:"databases"`
	Servers    []TechInfo         `json:"servers"`
	Languages  []TechInfo         `json:"languages"`
	Scores     map[string]float64 `json:"scores"`
}

// PredictorState is the serializable form of Predictor
type PredictorState struct {
	CategorySuccessRate  map[string]float64 `json:"category_success_rate"`
	CategoryObservations map[string]int     `json:"category_observations"`
	EncodingSuccessRate  map[string]float64 `json:"encoding_success_rate"`
	EncodingObservations map[string]int     `json:"encoding_observations"`
	PatternSuccessRate   map[string]float64 `json:"pattern_success_rate"`
	PatternObservations  map[string]int     `json:"pattern_observations"`
	EndpointSuccessRate  map[string]float64 `json:"endpoint_success_rate"`
	StatusCodePatterns   map[int]float64    `json:"status_code_patterns"`
	LatencyThresholds    map[string]float64 `json:"latency_thresholds"`
	TechVulnerabilities  map[string]float64 `json:"tech_vulnerabilities"`
	TotalObservations    int                `json:"total_observations"`
}

// MutatorState is the serializable form of MutationStrategist
type MutatorState struct {
	BlockPatternMutations map[string][]MutationRecord `json:"block_pattern_mutations"`
	CategoryMutations     map[string][]MutationRecord `json:"category_mutations"`
	EncodingEffectiveness map[string]float64          `json:"encoding_effectiveness"`
	Observations          int                         `json:"observations"`
}

// ClustererState is the serializable form of EndpointClusterer
type ClustererState struct {
	Clusters          map[string]*EndpointCluster  `json:"clusters"`
	EndpointCluster   map[string]string            `json:"endpoint_cluster"`
	EndpointBehaviors map[string]*EndpointBehavior `json:"endpoint_behaviors"`
}

// PathfinderState is the serializable form of AttackPathOptimizer
type PathfinderState struct {
	Nodes      map[string]*AttackNode `json:"nodes"`
	Edges      []AttackEdge           `json:"edges"`
	NodeValues map[string]float64     `json:"node_values"`
}

// ══════════════════════════════════════════════════════════════════════════════
// MASTER BRAIN STATE TYPES
// ══════════════════════════════════════════════════════════════════════════════

// BanditState is the serializable form of BanditSelector.
type BanditState struct {
	Arms map[string]*BetaArmState `json:"arms"`
}

// BetaArmState is the serializable form of BetaArm.
type BetaArmState struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
	Pulls int     `json:"pulls"`
}

// PhaseControllerState is the serializable form of PhaseController.
type PhaseControllerState struct {
	QTable  map[string]map[string]float64 `json:"q_table"`
	Epsilon float64                       `json:"epsilon"`
}

// CalibratorState is the serializable form of ChangePointDetector.
type CalibratorState struct {
	Metrics map[string]*CUSUMMetricState `json:"metrics"`
}

// CUSUMMetricState is the serializable form of a single CUSUM metric.
type CUSUMMetricState struct {
	Baseline float64 `json:"baseline"`
	Count    int     `json:"count"`
}

// InfluenceGraphState is the serializable form of InfluenceGraph.
type InfluenceGraphState struct {
	Nodes map[string]*InfluenceNodeState `json:"nodes"`
	Edges []InfluenceEdgeState           `json:"edges"`
}

// InfluenceNodeState is the serializable form of InfluenceNode.
type InfluenceNodeState struct {
	Type   string  `json:"type"`
	Weight float64 `json:"weight"`
}

// InfluenceEdgeState is the serializable form of InfluenceEdge.
type InfluenceEdgeState struct {
	Source string  `json:"source"`
	Target string  `json:"target"`
	Weight float64 `json:"weight"`
	Obs    int     `json:"observations"`
}

// MutationGeneratorState is the serializable form of MutationGenerator.
type MutationGeneratorState struct {
	BestChromosomes []MutationChromosomeState `json:"best_chromosomes"`
	Generation      int                       `json:"generation"`
}

// MutationChromosomeState is the serializable form of MutationChromosome.
type MutationChromosomeState struct {
	Genes   []MutationGeneState `json:"genes"`
	Fitness float64             `json:"fitness"`
}

// MutationGeneState is the serializable form of MutationGene.
type MutationGeneState struct {
	Transform string `json:"transform"`
	Position  string `json:"position"`
	Param     string `json:"param,omitempty"`
}

// StatsState is the serializable form of Stats
type StatsState struct {
	FindingsByCategory map[string]int   `json:"findings_by_category"`
	FindingsByPhase    map[string]int   `json:"findings_by_phase"`
	FindingsBySeverity map[string]int   `json:"findings_by_severity"`
	BypassesByCategory map[string]int   `json:"bypasses_by_category"`
	BlocksByCategory   map[string]int   `json:"blocks_by_category"`
	PhaseDuration      map[string]int64 `json:"phase_duration_ns"`
	PhaseOrder         []string         `json:"phase_order"`
	StartTime          time.Time        `json:"start_time"`
	TotalTime          int64            `json:"total_time_ns"`
}

// ══════════════════════════════════════════════════════════════════════════════
// SAVE OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

// Save persists the entire brain state to a file
func (e *Engine) Save(path string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	state := e.exportState()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// Write atomically via temp file
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		os.Remove(tmpPath) // Clean up partial file on failure
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// ExportJSON returns the brain state as JSON bytes
func (e *Engine) ExportJSON() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	state := e.exportState()
	return json.Marshal(state)
}

// exportState creates a BrainState from current engine state
func (e *Engine) exportState() *BrainState {
	state := &BrainState{
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	// Export memory
	state.Memory = e.memory.Export()

	// Export WAF model
	state.WAFModel = e.wafModel.Export()

	// Export tech profile
	state.TechProfile = e.techProfile.Export()

	// Export predictor
	state.Predictor = e.predictor.Export()

	// Export mutator
	state.Mutator = e.mutator.Export()

	// Export clusterer
	state.Clusterer = e.clusterer.Export()

	// Export pathfinder
	state.Pathfinder = e.pathfinder.Export()

	// Export WAF profiler
	if e.wafProfiler != nil {
		state.WAFProfiler = e.wafProfiler.Export()
	}

	// Export stats
	state.Stats = e.stats.Export()

	// Export Master Brain modules
	if e.banditCategory != nil {
		state.BanditCategory = e.banditCategory.Export()
	}
	if e.banditEncoding != nil {
		state.BanditEncoding = e.banditEncoding.Export()
	}
	if e.banditPattern != nil {
		state.BanditPattern = e.banditPattern.Export()
	}
	if e.phaseCtrl != nil {
		state.PhaseController = e.phaseCtrl.Export()
	}
	if e.calibrator != nil {
		state.Calibrator = e.calibrator.Export()
	}
	if e.influenceGraph != nil {
		state.InfluenceGraph = e.influenceGraph.Export()
	}
	if e.mutationGen != nil {
		state.MutationGenerator = e.mutationGen.Export()
	}

	return state
}

// ══════════════════════════════════════════════════════════════════════════════
// LOAD OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

// Load restores brain state from a file
func (e *Engine) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	return e.ImportJSON(data)
}

// ImportJSON restores brain state from JSON bytes
func (e *Engine) ImportJSON(data []byte) error {
	var state BrainState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("unmarshal state: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Import to each module
	if state.Memory != nil {
		e.memory.Import(state.Memory)
	}
	if state.WAFModel != nil {
		e.wafModel.Import(state.WAFModel)
	}
	if state.TechProfile != nil {
		e.techProfile.Import(state.TechProfile)
	}
	if state.Predictor != nil {
		e.predictor.Import(state.Predictor)
	}
	if state.Mutator != nil {
		e.mutator.Import(state.Mutator)
	}
	if state.Clusterer != nil {
		e.clusterer.Import(state.Clusterer)
	}
	if state.Pathfinder != nil {
		e.pathfinder.Import(state.Pathfinder)
	}
	if state.WAFProfiler != nil && e.wafProfiler != nil {
		e.wafProfiler.Import(state.WAFProfiler)
	}
	if state.Stats != nil {
		e.stats.Import(state.Stats)
	}

	// Import Master Brain modules (nil-safe for backward compatibility)
	if state.BanditCategory != nil && e.banditCategory != nil {
		e.banditCategory.Import(state.BanditCategory)
	}
	if state.BanditEncoding != nil && e.banditEncoding != nil {
		e.banditEncoding.Import(state.BanditEncoding)
	}
	if state.BanditPattern != nil && e.banditPattern != nil {
		e.banditPattern.Import(state.BanditPattern)
	}
	if state.PhaseController != nil && e.phaseCtrl != nil {
		e.phaseCtrl.Import(state.PhaseController)
	}
	if state.Calibrator != nil && e.calibrator != nil {
		e.calibrator.Import(state.Calibrator)
	}
	if state.InfluenceGraph != nil && e.influenceGraph != nil {
		e.influenceGraph.Import(state.InfluenceGraph)
	}
	if state.MutationGenerator != nil && e.mutationGen != nil {
		e.mutationGen.Import(state.MutationGenerator)
	}

	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// RESET OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

// Reset clears all brain state
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.memory != nil {
		e.memory.Reset()
	}
	if e.wafModel != nil {
		e.wafModel.Reset()
	}
	if e.techProfile != nil {
		e.techProfile.Reset()
	}
	if e.predictor != nil {
		e.predictor.Reset()
	}
	if e.mutator != nil {
		e.mutator.Reset()
	}
	if e.clusterer != nil {
		e.clusterer.Reset()
	}
	if e.anomaly != nil {
		e.anomaly.Reset()
	}
	if e.pathfinder != nil {
		e.pathfinder.Reset()
	}
	if e.wafProfiler != nil {
		e.wafProfiler.Reset()
	}
	if e.stats != nil {
		e.stats.Reset()
	}
	e.attackChains = make([]*AttackChain, 0)

	// Reset Master Brain modules
	if e.banditCategory != nil {
		e.banditCategory.Reset()
	}
	if e.banditEncoding != nil {
		e.banditEncoding.Reset()
	}
	if e.banditPattern != nil {
		e.banditPattern.Reset()
	}
	if e.phaseCtrl != nil {
		e.phaseCtrl.Reset()
	}
	if e.calibrator != nil {
		e.calibrator.Reset()
	}
	if e.influenceGraph != nil {
		e.influenceGraph.Reset()
	}
	if e.mutationGen != nil {
		e.mutationGen.Reset()
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// MODULE EXPORT/IMPORT METHODS
// ══════════════════════════════════════════════════════════════════════════════

// Export returns serializable Memory state
func (m *Memory) Export() *MemoryState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	findings := make([]*Finding, len(m.findings))
	for i, f := range m.findings {
		fCopy := *f
		findings[i] = &fCopy
	}

	// Copy category priorities
	categoryPriority := make(map[string]string, len(m.categoryPriority))
	for k, v := range m.categoryPriority {
		categoryPriority[k] = v
	}

	return &MemoryState{
		Findings:         findings,
		MaxFindings:      m.maxFindings,
		CategoryPriority: categoryPriority,
	}
}

// Import restores Memory from state
func (m *Memory) Import(state *MemoryState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.findings = make([]*Finding, len(state.Findings))
	copy(m.findings, state.Findings)

	// Restore max findings setting
	if state.MaxFindings > 0 {
		m.maxFindings = state.MaxFindings
	}

	// Restore category priorities
	m.categoryPriority = make(map[string]string)
	for k, v := range state.CategoryPriority {
		m.categoryPriority[k] = v
	}

	// Rebuild indexes
	m.byPhase = make(map[string][]*Finding)
	m.byCategory = make(map[string][]*Finding)
	m.bySeverity = make(map[string][]*Finding)
	m.byPath = make(map[string][]*Finding)
	m.bypasses = make([]*Finding, 0)

	for _, f := range m.findings {
		m.byPhase[f.Phase] = append(m.byPhase[f.Phase], f)
		m.byCategory[f.Category] = append(m.byCategory[f.Category], f)
		m.bySeverity[f.Severity] = append(m.bySeverity[f.Severity], f)
		m.byPath[f.Path] = append(m.byPath[f.Path], f)
		if !f.Blocked && f.IsTestingPhase() && f.StatusCode > 0 {
			m.bypasses = append(m.bypasses, f)
		}
	}
}

// Reset clears Memory state
func (m *Memory) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.findings = make([]*Finding, 0)
	m.byPhase = make(map[string][]*Finding)
	m.byCategory = make(map[string][]*Finding)
	m.bySeverity = make(map[string][]*Finding)
	m.byPath = make(map[string][]*Finding)
	m.bypasses = make([]*Finding, 0)
	// Note: maxFindings is not reset - it's a configuration, not state
}

// Export returns serializable WAFBehaviorModel state
func (w *WAFBehaviorModel) Export() *WAFModelState {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return &WAFModelState{
		BlockPatterns:     copyStringIntMap(w.blockPatterns),
		BypassPatterns:    copyStringIntMap(w.bypassPatterns),
		CategoryBlock:     copyStringIntMap(w.categoryBlock),
		CategoryBypass:    copyStringIntMap(w.categoryBypass),
		StatusCodes:       copyIntIntMap(w.statusCodes),
		AvgBlockedLatency: int64(w.avgBlockedLatency),
		AvgBypassLatency:  int64(w.avgBypassLatency),
		BlockedCount:      w.blockedCount,
		BypassCount:       w.bypassCount,
		Weaknesses:        append([]Weakness{}, w.weaknesses...),
		Strengths:         append([]string{}, w.strengths...),
	}
}

// Import restores WAFBehaviorModel from state
func (w *WAFBehaviorModel) Import(state *WAFModelState) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.blockPatterns = copyStringIntMap(state.BlockPatterns)
	w.bypassPatterns = copyStringIntMap(state.BypassPatterns)
	w.categoryBlock = copyStringIntMap(state.CategoryBlock)
	w.categoryBypass = copyStringIntMap(state.CategoryBypass)
	w.statusCodes = copyIntIntMap(state.StatusCodes)
	w.avgBlockedLatency = time.Duration(state.AvgBlockedLatency)
	w.avgBypassLatency = time.Duration(state.AvgBypassLatency)
	w.blockedCount = state.BlockedCount
	w.bypassCount = state.BypassCount
	w.weaknesses = append([]Weakness{}, state.Weaknesses...)
	w.strengths = append([]string{}, state.Strengths...)
}

// Reset clears WAFBehaviorModel state
func (w *WAFBehaviorModel) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.blockPatterns = make(map[string]int)
	w.bypassPatterns = make(map[string]int)
	w.categoryBlock = make(map[string]int)
	w.categoryBypass = make(map[string]int)
	w.statusCodes = make(map[int]int)
	w.avgBlockedLatency = 0
	w.avgBypassLatency = 0
	w.blockedCount = 0
	w.bypassCount = 0
	w.weaknesses = make([]Weakness, 0)
	w.strengths = make([]string, 0)
}

// Export returns serializable TechProfile state
func (t *TechProfile) Export() *TechProfileState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return &TechProfileState{
		Frameworks: append([]TechInfo{}, t.frameworks...),
		Databases:  append([]TechInfo{}, t.databases...),
		Servers:    append([]TechInfo{}, t.servers...),
		Languages:  append([]TechInfo{}, t.languages...),
		Scores:     copyStringFloatMap(t.scores),
	}
}

// Import restores TechProfile from state
func (t *TechProfile) Import(state *TechProfileState) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.frameworks = append([]TechInfo{}, state.Frameworks...)
	t.databases = append([]TechInfo{}, state.Databases...)
	t.servers = append([]TechInfo{}, state.Servers...)
	t.languages = append([]TechInfo{}, state.Languages...)
	t.scores = copyStringFloatMap(state.Scores)
}

// Reset clears TechProfile state
func (t *TechProfile) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.frameworks = make([]TechInfo, 0)
	t.databases = make([]TechInfo, 0)
	t.servers = make([]TechInfo, 0)
	t.languages = make([]TechInfo, 0)
	t.scores = make(map[string]float64)
}

// Export returns serializable Predictor state
func (p *Predictor) Export() *PredictorState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Copy status code patterns (int keys)
	statusCodes := make(map[int]float64, len(p.statusCodePatterns))
	for k, v := range p.statusCodePatterns {
		statusCodes[k] = v
	}

	return &PredictorState{
		CategorySuccessRate:  copyStringFloatMap(p.categorySuccessRate),
		CategoryObservations: copyStringIntMap(p.categoryObservations),
		EncodingSuccessRate:  copyStringFloatMap(p.encodingSuccessRate),
		EncodingObservations: copyStringIntMap(p.encodingObservations),
		PatternSuccessRate:   copyStringFloatMap(p.patternSuccessRate),
		PatternObservations:  copyStringIntMap(p.patternObservations),
		EndpointSuccessRate:  copyStringFloatMap(p.endpointSuccessRate),
		StatusCodePatterns:   statusCodes,
		LatencyThresholds:    copyStringFloatMap(p.latencyThresholds),
		TechVulnerabilities:  copyStringFloatMap(p.techVulnerabilities),
		TotalObservations:    p.totalObservations,
	}
}

// Import restores Predictor from state
func (p *Predictor) Import(state *PredictorState) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.categorySuccessRate = copyStringFloatMap(state.CategorySuccessRate)
	p.categoryObservations = copyStringIntMap(state.CategoryObservations)
	p.encodingSuccessRate = copyStringFloatMap(state.EncodingSuccessRate)
	p.encodingObservations = copyStringIntMap(state.EncodingObservations)
	p.patternSuccessRate = copyStringFloatMap(state.PatternSuccessRate)
	p.patternObservations = copyStringIntMap(state.PatternObservations)
	p.endpointSuccessRate = copyStringFloatMap(state.EndpointSuccessRate)
	p.latencyThresholds = copyStringFloatMap(state.LatencyThresholds)
	p.techVulnerabilities = copyStringFloatMap(state.TechVulnerabilities)

	// Copy status code patterns
	p.statusCodePatterns = make(map[int]float64, len(state.StatusCodePatterns))
	for k, v := range state.StatusCodePatterns {
		p.statusCodePatterns[k] = v
	}

	p.totalObservations = state.TotalObservations
}

// Reset clears Predictor state
func (p *Predictor) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.categorySuccessRate = make(map[string]float64)
	p.categoryObservations = make(map[string]int)
	p.encodingSuccessRate = make(map[string]float64)
	p.encodingObservations = make(map[string]int)
	p.patternSuccessRate = make(map[string]float64)
	p.patternObservations = make(map[string]int)
	p.endpointSuccessRate = make(map[string]float64)
	p.statusCodePatterns = make(map[int]float64)
	p.latencyThresholds = make(map[string]float64)
	p.techVulnerabilities = make(map[string]float64)
	p.categoryTechCorr = make(map[string]map[string]float64)
}

// Export returns serializable MutationStrategist state
func (ms *MutationStrategist) Export() *MutatorState {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	blockPatternMutations := make(map[string][]MutationRecord)
	for k, v := range ms.blockPatternMutations {
		blockPatternMutations[k] = append([]MutationRecord{}, v...)
	}

	categoryMutations := make(map[string][]MutationRecord)
	for k, v := range ms.categoryMutations {
		categoryMutations[k] = append([]MutationRecord{}, v...)
	}

	return &MutatorState{
		BlockPatternMutations: blockPatternMutations,
		CategoryMutations:     categoryMutations,
		EncodingEffectiveness: copyStringFloatMap(ms.encodingEffectiveness),
		Observations:          ms.observations,
	}
}

// Import restores MutationStrategist from state
func (ms *MutationStrategist) Import(state *MutatorState) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.blockPatternMutations = make(map[string][]MutationRecord)
	for k, v := range state.BlockPatternMutations {
		ms.blockPatternMutations[k] = append([]MutationRecord{}, v...)
	}

	ms.categoryMutations = make(map[string][]MutationRecord)
	for k, v := range state.CategoryMutations {
		ms.categoryMutations[k] = append([]MutationRecord{}, v...)
	}

	ms.encodingEffectiveness = copyStringFloatMap(state.EncodingEffectiveness)
	ms.observations = state.Observations
}

// Reset clears MutationStrategist state
func (ms *MutationStrategist) Reset() {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.blockPatternMutations = make(map[string][]MutationRecord)
	ms.categoryMutations = make(map[string][]MutationRecord)
	ms.encodingEffectiveness = make(map[string]float64)
	ms.observations = 0
	// Re-initialize WAF knowledge
	ms.initWAFKnowledge()
}

// Export returns serializable EndpointClusterer state
func (ec *EndpointClusterer) Export() *ClustererState {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	// Deep copy clusters to avoid shared state
	clusters := make(map[string]*EndpointCluster)
	for k, v := range ec.clusters {
		var behaviorCopy *ClusterBehavior
		if v.Behavior != nil {
			behaviorCopy = &ClusterBehavior{
				AvgBlockRate:        v.Behavior.AvgBlockRate,
				CommonStatusCodes:   append([]int{}, v.Behavior.CommonStatusCodes...),
				BlockRateByCategory: copyStringFloatMap(v.Behavior.BlockRateByCategory),
				Variance:            v.Behavior.Variance,
			}
		}
		clusterCopy := &EndpointCluster{
			ID:             v.ID,
			Representative: v.Representative,
			Members:        append([]string{}, v.Members...),
			Pattern:        v.Pattern,
			Technology:     v.Technology,
			Behavior:       behaviorCopy,
			Confidence:     v.Confidence,
		}
		clusters[k] = clusterCopy
	}

	endpointCluster := make(map[string]string)
	for k, v := range ec.endpointCluster {
		endpointCluster[k] = v
	}

	// Deep copy endpoint behaviors
	endpointBehaviors := make(map[string]*EndpointBehavior)
	for k, v := range ec.endpointBehaviors {
		behaviorCopy := &EndpointBehavior{
			Path:            v.Path,
			StatusCodes:     copyIntIntMap(v.StatusCodes),
			BlockRates:      copyStringFloatMap(v.BlockRates),
			AvgLatency:      v.AvgLatency,
			Characteristics: append([]string{}, v.Characteristics...),
			TotalRequests:   v.TotalRequests,
			BlockedRequests: v.BlockedRequests,
		}
		endpointBehaviors[k] = behaviorCopy
	}

	return &ClustererState{
		Clusters:          clusters,
		EndpointCluster:   endpointCluster,
		EndpointBehaviors: endpointBehaviors,
	}
}

// Import restores EndpointClusterer from state
func (ec *EndpointClusterer) Import(state *ClustererState) {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	ec.clusters = make(map[string]*EndpointCluster)
	for k, v := range state.Clusters {
		ec.clusters[k] = v
	}

	ec.endpointCluster = make(map[string]string)
	for k, v := range state.EndpointCluster {
		ec.endpointCluster[k] = v
	}

	ec.endpointBehaviors = make(map[string]*EndpointBehavior)
	for k, v := range state.EndpointBehaviors {
		ec.endpointBehaviors[k] = v
	}
}

// Reset clears EndpointClusterer state
func (ec *EndpointClusterer) Reset() {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	ec.clusters = make(map[string]*EndpointCluster)
	ec.endpointCluster = make(map[string]string)
	ec.endpointBehaviors = make(map[string]*EndpointBehavior)
}

// Export returns serializable AttackPathOptimizer state
func (apo *AttackPathOptimizer) Export() *PathfinderState {
	apo.mu.RLock()
	defer apo.mu.RUnlock()

	// Deep copy nodes to avoid shared state
	nodes := make(map[string]*AttackNode)
	for k, v := range apo.nodes {
		nodeCopy := &AttackNode{
			ID:          v.ID,
			Type:        v.Type,
			Path:        v.Path,
			Category:    v.Category,
			Description: v.Description,
			Value:       v.Value,
			Reachable:   v.Reachable,
			Exploited:   v.Exploited,
			BlockedBy:   append([]string{}, v.BlockedBy...),
			RequiredFor: append([]string{}, v.RequiredFor...),
		}
		nodes[k] = nodeCopy
	}

	edges := make([]AttackEdge, len(apo.edges))
	copy(edges, apo.edges)

	nodeValues := make(map[string]float64)
	for k, v := range apo.nodeValues {
		nodeValues[k] = v
	}

	return &PathfinderState{
		Nodes:      nodes,
		Edges:      edges,
		NodeValues: nodeValues,
	}
}

// Import restores AttackPathOptimizer from state
func (apo *AttackPathOptimizer) Import(state *PathfinderState) {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	apo.nodes = make(map[string]*AttackNode)
	for k, v := range state.Nodes {
		apo.nodes[k] = v
	}

	apo.edges = make([]AttackEdge, len(state.Edges))
	copy(apo.edges, state.Edges)

	apo.nodeValues = make(map[string]float64)
	for k, v := range state.NodeValues {
		apo.nodeValues[k] = v
	}

	// Recalculate paths after import
	apo.recalculatePaths()
}

// Reset clears AttackPathOptimizer state
func (apo *AttackPathOptimizer) Reset() {
	apo.mu.Lock()
	defer apo.mu.Unlock()

	apo.nodes = make(map[string]*AttackNode)
	apo.edges = make([]AttackEdge, 0)
	apo.nodeValues = make(map[string]float64)
	apo.paths = make([]*AttackPath, 0)
	apo.optimalPath = nil
}

// Export returns serializable Stats state
func (s *Stats) Export() *StatsState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Convert duration map to int64 nanoseconds
	phaseDuration := make(map[string]int64, len(s.phaseDuration))
	for k, v := range s.phaseDuration {
		phaseDuration[k] = int64(v)
	}

	return &StatsState{
		FindingsByCategory: copyStringIntMap(s.findingsByCategory),
		FindingsByPhase:    copyStringIntMap(s.findingsByPhase),
		FindingsBySeverity: copyStringIntMap(s.findingsBySeverity),
		BypassesByCategory: copyStringIntMap(s.bypassesByCategory),
		BlocksByCategory:   copyStringIntMap(s.blocksByCategory),
		PhaseDuration:      phaseDuration,
		PhaseOrder:         append([]string{}, s.phaseOrder...),
		StartTime:          s.startTime,
		TotalTime:          int64(s.totalTime),
	}
}

// Import restores Stats from state
func (s *Stats) Import(state *StatsState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.findingsByCategory = copyStringIntMap(state.FindingsByCategory)
	s.findingsByPhase = copyStringIntMap(state.FindingsByPhase)
	s.findingsBySeverity = copyStringIntMap(state.FindingsBySeverity)
	s.bypassesByCategory = copyStringIntMap(state.BypassesByCategory)
	s.blocksByCategory = copyStringIntMap(state.BlocksByCategory)
	s.phaseOrder = append([]string{}, state.PhaseOrder...)
	s.startTime = state.StartTime
	s.totalTime = time.Duration(state.TotalTime)

	// Convert int64 nanoseconds back to Duration
	s.phaseDuration = make(map[string]time.Duration, len(state.PhaseDuration))
	for k, v := range state.PhaseDuration {
		s.phaseDuration[k] = time.Duration(v)
	}
}

// Reset clears Stats state
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.phaseStart = make(map[string]time.Time)
	s.phaseDuration = make(map[string]time.Duration)
	s.findingsByCategory = make(map[string]int)
	s.findingsByPhase = make(map[string]int)
	s.findingsBySeverity = make(map[string]int)
	s.bypassesByCategory = make(map[string]int)
	s.blocksByCategory = make(map[string]int)
	s.phaseOrder = make([]string, 0)
	s.startTime = time.Now()
	s.totalTime = 0
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func copyStringIntMap(m map[string]int) map[string]int {
	if m == nil {
		return make(map[string]int)
	}
	result := make(map[string]int, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyIntIntMap(m map[int]int) map[int]int {
	if m == nil {
		return make(map[int]int)
	}
	result := make(map[int]int, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyStringFloatMap(m map[string]float64) map[string]float64 {
	if m == nil {
		return make(map[string]float64)
	}
	result := make(map[string]float64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
