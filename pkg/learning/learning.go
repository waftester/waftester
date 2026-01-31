// Package learning analyzes discovered endpoints and generates contextual test plans
package learning

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/payloads"
)

// TestPlan represents a contextual testing plan based on discovered endpoints
type TestPlan struct {
	Target           string            `json:"target"`
	Service          string            `json:"service,omitempty"`
	GeneratedAt      string            `json:"generated_at"`
	DiscoveryFile    string            `json:"discovery_file,omitempty"`
	TotalTests       int               `json:"total_tests"`
	EstimatedTime    string            `json:"estimated_time"`
	TestGroups       []TestGroup       `json:"test_groups"`
	EndpointTests    []EndpointTestSet `json:"endpoint_tests"`
	RecommendedFlags RecommendedConfig `json:"recommended_config"`
}

// TestGroup represents a category of tests to run
type TestGroup struct {
	Category    string   `json:"category"`
	Priority    int      `json:"priority"` // 1-5, 1 being highest
	PayloadDirs []string `json:"payload_dirs"`
	Reason      string   `json:"reason"`
	TestCount   int      `json:"test_count,omitempty"`
}

// EndpointTestSet maps an endpoint to specific attack payloads
type EndpointTestSet struct {
	Endpoint         discovery.Endpoint `json:"endpoint"`
	AttackCategories []string           `json:"attack_categories"`
	InjectPoints     []InjectPoint      `json:"inject_points"`
	CustomPayloads   []payloads.Payload `json:"custom_payloads,omitempty"`
}

// InjectPoint represents where to inject attack payloads
type InjectPoint struct {
	Type     string `json:"type"`     // query, body, header, path
	Name     string `json:"name"`     // Parameter name
	Original string `json:"original"` // Original value if any
}

// NOTE: Custom payloads use payloads.Payload type from the payloads package
// This ensures a single source of truth for payload structure

// RecommendedConfig provides optimal test configuration
type RecommendedConfig struct {
	Concurrency int      `json:"concurrency"`
	RateLimit   int      `json:"rate_limit"`
	Timeout     int      `json:"timeout_seconds"`
	Categories  []string `json:"categories"`
	SkipStatic  bool     `json:"skip_static"`
	SkipHealth  bool     `json:"skip_health"`
	FocusAreas  []string `json:"focus_areas"`
}

// Learner analyzes discovery results and generates test plans
type Learner struct {
	discovery  *discovery.DiscoveryResult
	payloadDir string
}

// NewLearner creates a new learning engine
func NewLearner(disc *discovery.DiscoveryResult, payloadDir string) *Learner {
	return &Learner{
		discovery:  disc,
		payloadDir: payloadDir,
	}
}

// GenerateTestPlan creates a contextual test plan
func (l *Learner) GenerateTestPlan() *TestPlan {
	plan := &TestPlan{
		Target:        l.discovery.Target,
		Service:       l.discovery.Service,
		GeneratedAt:   l.discovery.DiscoveredAt.Format("2006-01-02T15:04:05Z"),
		TestGroups:    make([]TestGroup, 0),
		EndpointTests: make([]EndpointTestSet, 0),
	}

	// Step 1: Determine which payload categories to use based on attack surface
	plan.TestGroups = l.determineTestGroups()

	// Step 2: Map endpoints to specific tests
	plan.EndpointTests = l.mapEndpointsToTests()

	// Step 3: Generate custom payloads for discovered parameters
	l.generateCustomPayloads(plan)

	// Step 4: Calculate recommended configuration
	plan.RecommendedFlags = l.calculateRecommendedConfig()

	// Step 5: Calculate totals
	plan.TotalTests = l.countTotalTests(plan)
	plan.EstimatedTime = l.estimateTime(plan.TotalTests)

	return plan
}

// determineTestGroups selects which payload categories are relevant
func (l *Learner) determineTestGroups() []TestGroup {
	groups := make([]TestGroup, 0)
	surface := l.discovery.AttackSurface

	// High priority - always run these
	groups = append(groups, TestGroup{
		Category:    "waf-validation",
		Priority:    1,
		PayloadDirs: []string{"waf-validation"},
		Reason:      "Baseline WAF detection and bypass testing",
	})

	// XSS - relevant for any web application
	groups = append(groups, TestGroup{
		Category:    "xss",
		Priority:    1,
		PayloadDirs: []string{"xss"},
		Reason:      "Universal XSS testing for all web endpoints",
	})

	// Injection - high priority for API endpoints
	if surface.HasAPIEndpoints || surface.AcceptsJSON || surface.AcceptsFormData {
		groups = append(groups, TestGroup{
			Category:    "injection",
			Priority:    1,
			PayloadDirs: []string{"injection"},
			Reason:      "API endpoints detected - SQL/NoSQL/Command injection testing",
		})
	}

	// Auth-specific tests
	if surface.HasAuthEndpoints {
		groups = append(groups, TestGroup{
			Category:    "auth",
			Priority:    2,
			PayloadDirs: []string{"auth"},
			Reason:      "Authentication endpoints detected - testing auth bypass",
		})
	}

	// OAuth-specific tests
	if surface.HasOAuth {
		groups = append(groups, TestGroup{
			Category:    "oauth",
			Priority:    2,
			PayloadDirs: []string{"auth"},
			Reason:      "OAuth endpoints detected - testing redirect/token attacks",
		})
	}

	// SAML-specific tests
	if surface.HasSAML {
		groups = append(groups, TestGroup{
			Category:    "saml",
			Priority:    2,
			PayloadDirs: []string{"auth"},
			Reason:      "SAML endpoints detected - testing XXE/signature attacks",
		})
	}

	// File upload tests
	if surface.HasFileUpload {
		groups = append(groups, TestGroup{
			Category:    "media",
			Priority:    2,
			PayloadDirs: []string{"media"},
			Reason:      "File upload detected - testing malicious file uploads",
		})

		groups = append(groups, TestGroup{
			Category:    "traversal",
			Priority:    2,
			PayloadDirs: []string{"traversal"},
			Reason:      "File handling detected - testing path traversal",
		})
	}

	// GraphQL-specific tests
	if surface.HasGraphQL {
		groups = append(groups, TestGroup{
			Category:    "graphql",
			Priority:    2,
			PayloadDirs: []string{"graphql"},
			Reason:      "GraphQL endpoint detected - testing introspection/batching attacks",
		})
	}

	// XML-specific tests
	if surface.AcceptsXML {
		groups = append(groups, TestGroup{
			Category:    "xxe",
			Priority:    2,
			PayloadDirs: []string{"injection"},
			Reason:      "XML accepted - testing XXE attacks",
		})
	}

	// SSRF - for any endpoint with URL parameters
	if l.hasRedirectParameters() {
		groups = append(groups, TestGroup{
			Category:    "ssrf",
			Priority:    3,
			PayloadDirs: []string{"ssrf"},
			Reason:      "URL parameters detected - testing SSRF attacks",
		})
	}

	// WebSocket tests
	if surface.HasWebSockets {
		groups = append(groups, TestGroup{
			Category:    "websocket",
			Priority:    3,
			PayloadDirs: []string{"protocol"},
			Reason:      "WebSocket endpoints detected",
		})
	}

	// Service-specific tests
	if l.discovery.Service != "" {
		groups = append(groups, TestGroup{
			Category:    "service-specific",
			Priority:    2,
			PayloadDirs: []string{"services"},
			Reason:      fmt.Sprintf("Service-specific tests for %s", l.discovery.Service),
		})
	}

	// Protocol-level tests
	groups = append(groups, TestGroup{
		Category:    "protocol",
		Priority:    3,
		PayloadDirs: []string{"protocol"},
		Reason:      "HTTP protocol-level attacks (smuggling, method tampering)",
	})

	// WAF bypass techniques
	groups = append(groups, TestGroup{
		Category:    "waf-bypass",
		Priority:    4,
		PayloadDirs: []string{"waf-bypass"},
		Reason:      "Advanced WAF evasion techniques",
	})

	// Fuzzing - lowest priority
	groups = append(groups, TestGroup{
		Category:    "fuzz",
		Priority:    5,
		PayloadDirs: []string{"fuzz"},
		Reason:      "Boundary testing and edge cases",
	})

	// Sort by priority
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Priority < groups[j].Priority
	})

	return groups
}

// mapEndpointsToTests creates endpoint-specific test mappings
func (l *Learner) mapEndpointsToTests() []EndpointTestSet {
	sets := make([]EndpointTestSet, 0)

	for _, ep := range l.discovery.Endpoints {
		// Skip static assets and health endpoints
		if ep.Category == "static" || ep.Category == "health" {
			continue
		}

		set := EndpointTestSet{
			Endpoint:         ep,
			AttackCategories: l.categorizeEndpointAttacks(ep),
			InjectPoints:     l.findInjectPoints(ep),
		}

		sets = append(sets, set)
	}

	return sets
}

// categorizeEndpointAttacks determines which attacks apply to an endpoint
func (l *Learner) categorizeEndpointAttacks(ep discovery.Endpoint) []string {
	categories := make([]string, 0)

	// Always test XSS
	categories = append(categories, "xss")

	// Check path patterns
	path := strings.ToLower(ep.Path)

	if strings.Contains(path, "oauth") || strings.Contains(path, "authorize") {
		categories = append(categories, "oauth-attacks")
	}

	if strings.Contains(path, "saml") {
		categories = append(categories, "saml-attacks", "xxe")
	}

	if strings.Contains(path, "api") {
		categories = append(categories, "injection", "idor")
	}

	if strings.Contains(path, "upload") || strings.Contains(path, "import") {
		categories = append(categories, "file-upload", "traversal")
	}

	if strings.Contains(path, "search") || strings.Contains(path, "query") {
		categories = append(categories, "injection", "nosql")
	}

	if strings.Contains(path, "exec") || strings.Contains(path, "command") {
		categories = append(categories, "rce")
	}

	if strings.Contains(path, "webhook") {
		categories = append(categories, "ssrf", "injection")
	}

	// Check for parameters
	if len(ep.Parameters) > 0 {
		for _, p := range ep.Parameters {
			if strings.Contains(strings.ToLower(p.Name), "url") ||
				strings.Contains(strings.ToLower(p.Name), "redirect") ||
				strings.Contains(strings.ToLower(p.Name), "callback") {
				categories = append(categories, "ssrf", "open-redirect")
			}
			if strings.Contains(strings.ToLower(p.Name), "id") ||
				strings.Contains(strings.ToLower(p.Name), "user") {
				categories = append(categories, "idor")
			}
			if strings.Contains(strings.ToLower(p.Name), "file") ||
				strings.Contains(strings.ToLower(p.Name), "path") {
				categories = append(categories, "traversal", "lfi")
			}
		}
	}

	return unique(categories)
}

// findInjectPoints identifies where to inject payloads
func (l *Learner) findInjectPoints(ep discovery.Endpoint) []InjectPoint {
	points := make([]InjectPoint, 0)

	// URL path segments with dynamic parts
	segments := strings.Split(ep.Path, "/")
	for i, seg := range segments {
		if strings.HasPrefix(seg, "<") || strings.HasPrefix(seg, "{") ||
			strings.HasPrefix(seg, ":") || isUUID(seg) || isNumeric(seg) {
			points = append(points, InjectPoint{
				Type:     "path",
				Name:     fmt.Sprintf("segment_%d", i),
				Original: seg,
			})
		}
	}

	// Query parameters
	for _, p := range ep.Parameters {
		if p.Location == "query" {
			points = append(points, InjectPoint{
				Type:     "query",
				Name:     p.Name,
				Original: p.Example,
			})
		}
	}

	// Body parameters
	for _, p := range ep.Parameters {
		if p.Location == "body" {
			points = append(points, InjectPoint{
				Type:     "body",
				Name:     p.Name,
				Original: p.Example,
			})
		}
	}

	// Common headers
	if ep.Category == "api" {
		points = append(points, InjectPoint{
			Type: "header",
			Name: "X-Forwarded-For",
		})
		points = append(points, InjectPoint{
			Type: "header",
			Name: "X-Original-URL",
		})
	}

	return points
}

// generateCustomPayloads creates endpoint-specific payloads
func (l *Learner) generateCustomPayloads(plan *TestPlan) {
	payloadID := 1

	for i := range plan.EndpointTests {
		set := &plan.EndpointTests[i]

		for _, point := range set.InjectPoints {
			// Generate injection payloads for this inject point
			set.CustomPayloads = append(set.CustomPayloads, l.generateInjectPayloads(
				set.Endpoint, point, &payloadID,
			)...)
		}
	}
}

// generateInjectPayloads creates payloads for a specific injection point
// Uses payloads.Payload as the single source of truth for payload structure
func (l *Learner) generateInjectPayloads(ep discovery.Endpoint, point InjectPoint, idCounter *int) []payloads.Payload {
	result := make([]payloads.Payload, 0)

	// SQL Injection payloads
	sqlPayloads := []string{
		"' OR '1'='1",
		"1; DROP TABLE users--",
		"' UNION SELECT NULL,NULL,NULL--",
		"1' AND SLEEP(5)--",
	}

	for _, p := range sqlPayloads {
		payload := payloads.Payload{
			ID:            fmt.Sprintf("LEARN-SQLI-%04d", *idCounter),
			Payload:       buildPayloadURL(ep.Path, point, p),
			Method:        ep.Method,
			TargetPath:    ep.Path,
			ExpectedBlock: true,
			SeverityHint:  "Critical",
			Category:      "injection",
			Tags:          []string{"sqli", "learned", point.Type},
			Notes:         fmt.Sprintf("Auto-generated SQLi for %s in %s", point.Name, ep.Path),
		}
		if point.Type == "body" {
			payload.ContentType = "application/json"
		}
		result = append(result, payload)
		*idCounter++
	}

	// XSS payloads
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"javascript:alert(1)",
		"<svg/onload=alert(1)>",
	}

	for _, p := range xssPayloads {
		payload := payloads.Payload{
			ID:            fmt.Sprintf("LEARN-XSS-%04d", *idCounter),
			Payload:       buildPayloadURL(ep.Path, point, p),
			Method:        ep.Method,
			TargetPath:    ep.Path,
			ExpectedBlock: true,
			SeverityHint:  "High",
			Category:      "xss",
			Tags:          []string{"xss", "learned", point.Type},
			Notes:         fmt.Sprintf("Auto-generated XSS for %s in %s", point.Name, ep.Path),
		}
		if point.Type == "body" {
			payload.ContentType = "application/json"
		}
		result = append(result, payload)
		*idCounter++
	}

	// Path traversal payloads (for file-related parameters)
	if strings.Contains(strings.ToLower(point.Name), "file") ||
		strings.Contains(strings.ToLower(point.Name), "path") {
		traversalPayloads := []string{
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\config\\sam",
			"....//....//....//etc/passwd",
			"/etc/passwd%00.jpg",
		}

		for _, p := range traversalPayloads {
			payload := payloads.Payload{
				ID:            fmt.Sprintf("LEARN-TRAV-%04d", *idCounter),
				Payload:       buildPayloadURL(ep.Path, point, p),
				Method:        ep.Method,
				TargetPath:    ep.Path,
				ExpectedBlock: true,
				SeverityHint:  "Critical",
				Category:      "traversal",
				Tags:          []string{"traversal", "lfi", "learned", point.Type},
				Notes:         fmt.Sprintf("Auto-generated traversal for %s in %s", point.Name, ep.Path),
			}
			if point.Type == "body" {
				payload.ContentType = "application/json"
			}
			result = append(result, payload)
			*idCounter++
		}
	}

	// SSRF payloads (for URL-related parameters)
	if strings.Contains(strings.ToLower(point.Name), "url") ||
		strings.Contains(strings.ToLower(point.Name), "redirect") {
		ssrfPayloads := []string{
			"http://169.254.169.254/latest/meta-data/",
			"http://localhost:22",
			"http://127.0.0.1:3306",
			"file:///etc/passwd",
		}

		for _, p := range ssrfPayloads {
			payload := payloads.Payload{
				ID:            fmt.Sprintf("LEARN-SSRF-%04d", *idCounter),
				Payload:       buildPayloadURL(ep.Path, point, p),
				Method:        ep.Method,
				TargetPath:    ep.Path,
				ExpectedBlock: true,
				SeverityHint:  "Critical",
				Category:      "ssrf",
				Tags:          []string{"ssrf", "learned", point.Type},
				Notes:         fmt.Sprintf("Auto-generated SSRF for %s in %s", point.Name, ep.Path),
			}
			if point.Type == "body" {
				payload.ContentType = "application/json"
			}
			result = append(result, payload)
			*idCounter++
		}
	}

	return result
}

// calculateRecommendedConfig determines optimal test settings
func (l *Learner) calculateRecommendedConfig() RecommendedConfig {
	cfg := RecommendedConfig{
		Concurrency: 25,
		RateLimit:   100,
		Timeout:     10,
		SkipStatic:  true,
		SkipHealth:  true,
	}

	// Adjust based on number of endpoints
	numEndpoints := len(l.discovery.Endpoints)
	if numEndpoints > 50 {
		cfg.Concurrency = 50
		cfg.RateLimit = 200
	} else if numEndpoints < 10 {
		cfg.Concurrency = 10
		cfg.RateLimit = 50
	}

	// Build categories list from relevant categories
	cfg.Categories = l.discovery.AttackSurface.RelevantCategories

	// Determine focus areas
	if l.discovery.AttackSurface.HasAuthEndpoints {
		cfg.FocusAreas = append(cfg.FocusAreas, "authentication")
	}
	if l.discovery.AttackSurface.HasFileUpload {
		cfg.FocusAreas = append(cfg.FocusAreas, "file-upload")
	}
	if l.discovery.AttackSurface.HasOAuth {
		cfg.FocusAreas = append(cfg.FocusAreas, "oauth-security")
	}
	if l.discovery.AttackSurface.HasGraphQL {
		cfg.FocusAreas = append(cfg.FocusAreas, "graphql")
	}

	return cfg
}

// hasRedirectParameters checks if any endpoint has redirect-like parameters
func (l *Learner) hasRedirectParameters() bool {
	for _, ep := range l.discovery.Endpoints {
		for _, p := range ep.Parameters {
			name := strings.ToLower(p.Name)
			if strings.Contains(name, "url") || strings.Contains(name, "redirect") ||
				strings.Contains(name, "callback") || strings.Contains(name, "next") ||
				strings.Contains(name, "return") || strings.Contains(name, "goto") {
				return true
			}
		}
	}
	return false
}

// countTotalTests estimates total number of tests
func (l *Learner) countTotalTests(plan *TestPlan) int {
	total := 0

	// Count from endpoint tests
	for _, set := range plan.EndpointTests {
		total += len(set.CustomPayloads)
	}

	// Add estimated payload counts from directories
	payloadCounts := map[string]int{
		"waf-validation": 50,
		"xss":            250,
		"injection":      450,
		"auth":           100,
		"traversal":      100,
		"ssrf":           50,
		"graphql":        30,
		"media":          50,
		"protocol":       30,
		"waf-bypass":     100,
		"fuzz":           200,
		"services":       150,
	}

	for _, group := range plan.TestGroups {
		for _, dir := range group.PayloadDirs {
			if count, ok := payloadCounts[dir]; ok {
				total += count
			}
		}
	}

	return total
}

// estimateTime estimates test duration
func (l *Learner) estimateTime(totalTests int) string {
	// Assuming 100 tests/second with rate limiting
	seconds := totalTests / 100
	if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	}
	minutes := seconds / 60
	if minutes < 60 {
		return fmt.Sprintf("%d minutes", minutes)
	}
	return fmt.Sprintf("%d hours %d minutes", minutes/60, minutes%60)
}

// SavePlan saves the test plan to a JSON file
func (p *TestPlan) SavePlan(filename string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// LoadPlan loads a test plan from a JSON file
func LoadPlan(filename string) (*TestPlan, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var plan TestPlan
	err = json.Unmarshal(data, &plan)
	return &plan, err
}

// GeneratePayloadFile exports custom payloads to a JSON file for the tester
func (p *TestPlan) GeneratePayloadFile(filename string) error {
	allPayloads := make([]payloads.Payload, 0)

	for _, set := range p.EndpointTests {
		allPayloads = append(allPayloads, set.CustomPayloads...)
	}

	data, err := json.MarshalIndent(allPayloads, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// Helper functions

func buildPayloadURL(basePath string, point InjectPoint, payload string) string {
	switch point.Type {
	case "query":
		if strings.Contains(basePath, "?") {
			return fmt.Sprintf("%s&%s=%s", basePath, point.Name, payload)
		}
		return fmt.Sprintf("%s?%s=%s", basePath, point.Name, payload)
	case "path":
		// Replace the segment
		return strings.Replace(basePath, point.Original, payload, 1)
	case "body":
		return fmt.Sprintf(`{"%s": "%s"}`, point.Name, payload)
	default:
		return payload
	}
}

func unique(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func isUUID(s string) bool {
	// Simple UUID pattern check
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
