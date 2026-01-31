package learning

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/discovery"
)

// TestGenerateInjectPayloadsHasRequiredFields verifies generated payloads have all fields
func TestGenerateInjectPayloadsHasRequiredFields(t *testing.T) {
	// Create mock discovery result
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		Service:      "test",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/users",
				Method: "POST",
				Parameters: []discovery.Parameter{
					{Name: "username", Location: "body"},
					{Name: "password", Location: "body"},
				},
			},
		},
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
			AcceptsJSON:     true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	// Should have endpoint tests
	if len(plan.EndpointTests) == 0 {
		t.Fatal("Expected endpoint tests to be generated")
	}

	// Check custom payloads have required fields
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			if p.ID == "" {
				t.Error("Payload missing ID")
			}
			if p.Payload == "" {
				t.Error("Payload missing Payload content")
			}
			if p.Category == "" {
				t.Error("Payload missing Category")
			}
			if p.Method == "" {
				t.Error("Payload missing Method")
			}
			if p.TargetPath == "" {
				t.Error("Payload missing TargetPath")
			}
			if p.SeverityHint == "" {
				t.Error("Payload missing SeverityHint")
			}
		}
	}
}

// TestGenerateInjectPayloadsForBodyParams verifies body params get ContentType
func TestGenerateInjectPayloadsForBodyParams(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/login",
				Method: "POST",
				Parameters: []discovery.Parameter{
					{Name: "email", Location: "body"},
				},
			},
		},
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
			AcceptsJSON:     true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	// Find payloads for body injection - body payloads are JSON formatted
	foundBodyPayload := false
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			// Body payloads should have JSON format and ContentType
			if strings.Contains(p.Payload, "{\"email\"") {
				foundBodyPayload = true
				if p.ContentType == "" {
					t.Errorf("Body payload %s missing ContentType", p.ID)
				}
				if p.Method != "POST" {
					t.Errorf("Body payload %s should be POST, got %s", p.ID, p.Method)
				}
			}
		}
	}

	if !foundBodyPayload {
		t.Error("No body payloads generated for body parameter")
	}
}

// TestGenerateInjectPayloadsCategories verifies correct categories are assigned
func TestGenerateInjectPayloadsCategories(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/data",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "id", Location: "query"},
				},
			},
		},
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	categories := make(map[string]bool)
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			categories[p.Category] = true
		}
	}

	// Should generate at least sqli and xss
	if !categories["injection"] {
		t.Error("Expected injection category payloads")
	}
	if !categories["xss"] {
		t.Error("Expected xss category payloads")
	}
}

// TestGenerateInjectPayloadsForFileParams verifies file params get traversal payloads
func TestGenerateInjectPayloadsForFileParams(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/download",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "filepath", Location: "query"},
				},
			},
		},
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundTraversal := false
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			if p.Category == "traversal" {
				foundTraversal = true
				// Payload should contain traversal patterns or passwd/etc
				if !strings.Contains(p.Payload, "passwd") && !strings.Contains(p.Payload, "windows") {
					t.Errorf("Traversal payload should target system files: %s", p.Payload)
				}
			}
		}
	}

	if !foundTraversal {
		t.Error("Expected traversal payloads for 'filepath' parameter")
	}
}

// TestGenerateInjectPayloadsForURLParams verifies URL params get SSRF payloads
func TestGenerateInjectPayloadsForURLParams(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/fetch",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "redirect_url", Location: "query"},
				},
			},
		},
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundSSRF := false
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			if p.Category == "ssrf" {
				foundSSRF = true
				// Payload should contain SSRF targets (localhost, 169.254, file://)
				hasSSRFTarget := strings.Contains(p.Payload, "169.254") ||
					strings.Contains(p.Payload, "localhost") ||
					strings.Contains(p.Payload, "127.0.0.1") ||
					strings.Contains(p.Payload, "file://")
				if !hasSSRFTarget {
					t.Errorf("SSRF payload should contain internal URL target: %s", p.Payload)
				}
			}
		}
	}

	if !foundSSRF {
		t.Error("Expected SSRF payloads for 'redirect_url' parameter")
	}
}

// TestDetermineTestGroupsForAPIEndpoints verifies API detection
func TestDetermineTestGroupsForAPIEndpoints(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://api.example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasAPIEndpoints: true,
			AcceptsJSON:     true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundInjection := false
	for _, g := range plan.TestGroups {
		if g.Category == "injection" {
			foundInjection = true
			if g.Priority > 2 {
				t.Error("Injection should be high priority for API endpoints")
			}
		}
	}

	if !foundInjection {
		t.Error("API endpoints should trigger injection test group")
	}
}

// TestDetermineTestGroupsForAuth verifies auth detection
func TestDetermineTestGroupsForAuth(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://auth.example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasAuthEndpoints: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundAuth := false
	for _, g := range plan.TestGroups {
		if g.Category == "auth" {
			foundAuth = true
		}
	}

	if !foundAuth {
		t.Error("Auth endpoints should trigger auth test group")
	}
}

// TestDetermineTestGroupsForFileUpload verifies file upload detection
func TestDetermineTestGroupsForFileUpload(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasFileUpload: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundMedia := false
	foundTraversal := false
	for _, g := range plan.TestGroups {
		if g.Category == "media" {
			foundMedia = true
		}
		if g.Category == "traversal" {
			foundTraversal = true
		}
	}

	if !foundMedia {
		t.Error("File upload should trigger media test group")
	}
	if !foundTraversal {
		t.Error("File upload should trigger traversal test group")
	}
}

// TestDetermineTestGroupsForGraphQL verifies GraphQL detection
func TestDetermineTestGroupsForGraphQL(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasGraphQL: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundGraphQL := false
	for _, g := range plan.TestGroups {
		if g.Category == "graphql" {
			foundGraphQL = true
		}
	}

	if !foundGraphQL {
		t.Error("GraphQL endpoints should trigger graphql test group")
	}
}

// TestDetermineTestGroupsForOAuth verifies OAuth detection
func TestDetermineTestGroupsForOAuth(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasOAuth: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundOAuth := false
	for _, g := range plan.TestGroups {
		if g.Category == "oauth" {
			foundOAuth = true
		}
	}

	if !foundOAuth {
		t.Error("OAuth endpoints should trigger oauth test group")
	}
}

// TestDetermineTestGroupsForSAML verifies SAML detection
func TestDetermineTestGroupsForSAML(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasSAML: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundSAML := false
	for _, g := range plan.TestGroups {
		if g.Category == "saml" {
			foundSAML = true
		}
	}

	if !foundSAML {
		t.Error("SAML endpoints should trigger saml test group")
	}
}

// TestDetermineTestGroupsForXML verifies XML detection
func TestDetermineTestGroupsForXML(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			AcceptsXML: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundXXE := false
	for _, g := range plan.TestGroups {
		if g.Category == "xxe" {
			foundXXE = true
		}
	}

	if !foundXXE {
		t.Error("XML accepting endpoints should trigger xxe test group")
	}
}

// TestDetermineTestGroupsForWebSocket verifies WebSocket detection
func TestDetermineTestGroupsForWebSocket(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		AttackSurface: discovery.AttackSurface{
			HasWebSockets: true,
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundWebSocket := false
	for _, g := range plan.TestGroups {
		if g.Category == "websocket" {
			foundWebSocket = true
		}
	}

	if !foundWebSocket {
		t.Error("WebSocket endpoints should trigger websocket test group")
	}
}

// TestMapEndpointsToTestsSkipsStatic verifies static assets are skipped
func TestMapEndpointsToTestsSkipsStatic(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{Path: "/api/users", Category: "api"},
			{Path: "/static/style.css", Category: "static"},
			{Path: "/health", Category: "health"},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	for _, et := range plan.EndpointTests {
		if et.Endpoint.Category == "static" || et.Endpoint.Category == "health" {
			t.Errorf("Should skip %s endpoints", et.Endpoint.Category)
		}
	}
}

// TestCategorizeEndpointAttacksForOAuth verifies OAuth path detection
func TestCategorizeEndpointAttacksForOAuth(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{Path: "/oauth/authorize", Method: "GET"},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if len(plan.EndpointTests) == 0 {
		t.Fatal("Expected endpoint tests")
	}

	found := false
	for _, cat := range plan.EndpointTests[0].AttackCategories {
		if cat == "oauth-attacks" {
			found = true
			break
		}
	}

	if !found {
		t.Error("OAuth path should have oauth-attacks category")
	}
}

// TestCategorizeEndpointAttacksForWebhook verifies webhook path detection
func TestCategorizeEndpointAttacksForWebhook(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{Path: "/api/webhook", Method: "POST"},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if len(plan.EndpointTests) == 0 {
		t.Fatal("Expected endpoint tests")
	}

	foundSSRF := false
	for _, cat := range plan.EndpointTests[0].AttackCategories {
		if cat == "ssrf" {
			foundSSRF = true
			break
		}
	}

	if !foundSSRF {
		t.Error("Webhook path should have ssrf category")
	}
}

// TestFindInjectPointsForQueryParams verifies query parameter detection
func TestFindInjectPointsForQueryParams(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/search",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "q", Location: "query", Example: "test"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if len(plan.EndpointTests) == 0 {
		t.Fatal("Expected endpoint tests")
	}

	foundQuery := false
	for _, point := range plan.EndpointTests[0].InjectPoints {
		if point.Type == "query" && point.Name == "q" {
			foundQuery = true
		}
	}

	if !foundQuery {
		t.Error("Should detect query inject point")
	}
}

// TestFindInjectPointsForDynamicPath verifies dynamic path detection
func TestFindInjectPointsForDynamicPath(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/users/123",
				Method: "GET",
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if len(plan.EndpointTests) == 0 {
		t.Fatal("Expected endpoint tests")
	}

	foundPath := false
	for _, point := range plan.EndpointTests[0].InjectPoints {
		if point.Type == "path" && point.Original == "123" {
			foundPath = true
		}
	}

	if !foundPath {
		t.Error("Should detect numeric path segment as inject point")
	}
}

// TestCalculateRecommendedConfigForManyEndpoints verifies config for large apps
func TestCalculateRecommendedConfigForManyEndpoints(t *testing.T) {
	endpoints := make([]discovery.Endpoint, 100)
	for i := 0; i < 100; i++ {
		endpoints[i] = discovery.Endpoint{Path: "/api/endpoint" + string(rune(i))}
	}

	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints:    endpoints,
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if plan.RecommendedFlags.Concurrency != 50 {
		t.Errorf("Expected concurrency 50 for large apps, got %d", plan.RecommendedFlags.Concurrency)
	}
	if plan.RecommendedFlags.RateLimit != 200 {
		t.Errorf("Expected rate limit 200 for large apps, got %d", plan.RecommendedFlags.RateLimit)
	}
}

// TestCalculateRecommendedConfigForFewEndpoints verifies config for small apps
func TestCalculateRecommendedConfigForFewEndpoints(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{Path: "/api/one"},
			{Path: "/api/two"},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	if plan.RecommendedFlags.Concurrency != 10 {
		t.Errorf("Expected concurrency 10 for small apps, got %d", plan.RecommendedFlags.Concurrency)
	}
}

// TestHasRedirectParameters verifies redirect parameter detection
func TestHasRedirectParameters(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path: "/redirect",
				Parameters: []discovery.Parameter{
					{Name: "next_url", Location: "query"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	// Should have SSRF group due to redirect parameter
	foundSSRF := false
	for _, g := range plan.TestGroups {
		if g.Category == "ssrf" {
			foundSSRF = true
		}
	}

	if !foundSSRF {
		t.Error("Redirect parameters should trigger SSRF test group")
	}
}

// TestEstimateTimeShort verifies time estimation for small tests
func TestEstimateTimeShort(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
	}

	learner := NewLearner(disc, "")

	// The private estimateTime function is used internally
	// We can test it via the plan
	plan := learner.GenerateTestPlan()

	if plan.EstimatedTime == "" {
		t.Error("Expected estimated time")
	}
}

// TestSaveAndLoadPlan verifies plan persistence
func TestSaveAndLoadPlan(t *testing.T) {
	tmpDir := t.TempDir()
	planFile := tmpDir + "/test-plan.json"

	plan := &TestPlan{
		Target:      "https://example.com",
		Service:     "test",
		GeneratedAt: "2025-01-01T00:00:00Z",
		TotalTests:  100,
		TestGroups: []TestGroup{
			{Category: "xss", Priority: 1},
		},
	}

	err := plan.SavePlan(planFile)
	if err != nil {
		t.Fatalf("Failed to save plan: %v", err)
	}

	loaded, err := LoadPlan(planFile)
	if err != nil {
		t.Fatalf("Failed to load plan: %v", err)
	}

	if loaded.Target != plan.Target {
		t.Error("Target mismatch")
	}
	if loaded.Service != plan.Service {
		t.Error("Service mismatch")
	}
	if loaded.TotalTests != plan.TotalTests {
		t.Error("TotalTests mismatch")
	}
}

// TestLoadPlanNotFound verifies error for missing file
func TestLoadPlanNotFound(t *testing.T) {
	_, err := LoadPlan("/nonexistent/path.json")
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

// TestGeneratePayloadFile verifies payload export
func TestGeneratePayloadFile(t *testing.T) {
	tmpDir := t.TempDir()
	payloadFile := tmpDir + "/payloads.json"

	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/test",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "id", Location: "query"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	err := plan.GeneratePayloadFile(payloadFile)
	if err != nil {
		t.Fatalf("Failed to generate payload file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(payloadFile); os.IsNotExist(err) {
		t.Error("Payload file should exist")
	}
}

// TestBuildPayloadURLQuery verifies query string building
func TestBuildPayloadURLQuery(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/search",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "q", Location: "query"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	// Check that payloads contain query string format
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			if strings.Contains(p.Notes, "q in") {
				if !strings.Contains(p.Payload, "?q=") && !strings.Contains(p.Payload, "&q=") {
					t.Errorf("Query payload should have proper format: %s", p.Payload)
				}
			}
		}
	}
}

// TestBuildPayloadURLBody verifies body JSON building
func TestBuildPayloadURLBody(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/login",
				Method: "POST",
				Parameters: []discovery.Parameter{
					{Name: "user", Location: "body"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundJSON := false
	for _, et := range plan.EndpointTests {
		for _, p := range et.CustomPayloads {
			if strings.Contains(p.Payload, "{\"user\"") {
				foundJSON = true
			}
		}
	}

	if !foundJSON {
		t.Error("Body payloads should have JSON format")
	}
}

// TestTestPlanStructFields tests TestPlan struct
func TestTestPlanStructFields(t *testing.T) {
	plan := TestPlan{
		Target:        "https://example.com",
		Service:       "test",
		GeneratedAt:   "2025-01-01",
		DiscoveryFile: "discovery.json",
		TotalTests:    100,
		EstimatedTime: "5 minutes",
	}

	if plan.Target != "https://example.com" {
		t.Error("Target mismatch")
	}
	if plan.Service != "test" {
		t.Error("Service mismatch")
	}
}

// TestTestGroupStruct tests TestGroup struct
func TestTestGroupStruct(t *testing.T) {
	group := TestGroup{
		Category:    "xss",
		Priority:    1,
		PayloadDirs: []string{"xss", "waf-bypass"},
		Reason:      "XSS testing",
		TestCount:   100,
	}

	if group.Category != "xss" {
		t.Error("Category mismatch")
	}
	if group.Priority != 1 {
		t.Error("Priority mismatch")
	}
	if len(group.PayloadDirs) != 2 {
		t.Error("PayloadDirs length mismatch")
	}
}

// TestEndpointTestSetStruct tests EndpointTestSet struct
func TestEndpointTestSetStruct(t *testing.T) {
	set := EndpointTestSet{
		Endpoint: discovery.Endpoint{
			Path:   "/api/test",
			Method: "GET",
		},
		AttackCategories: []string{"sqli", "xss"},
		InjectPoints: []InjectPoint{
			{Type: "query", Name: "id"},
		},
	}

	if set.Endpoint.Path != "/api/test" {
		t.Error("Endpoint path mismatch")
	}
	if len(set.AttackCategories) != 2 {
		t.Error("AttackCategories length mismatch")
	}
}

// TestInjectPointStruct tests InjectPoint struct
func TestInjectPointStruct(t *testing.T) {
	point := InjectPoint{
		Type:     "query",
		Name:     "id",
		Original: "123",
	}

	if point.Type != "query" {
		t.Error("Type mismatch")
	}
	if point.Name != "id" {
		t.Error("Name mismatch")
	}
	if point.Original != "123" {
		t.Error("Original mismatch")
	}
}

// TestRecommendedConfigStruct tests RecommendedConfig struct
func TestRecommendedConfigStruct(t *testing.T) {
	cfg := RecommendedConfig{
		Concurrency: 25,
		RateLimit:   100,
		Timeout:     10,
		Categories:  []string{"sqli", "xss"},
		SkipStatic:  true,
		SkipHealth:  true,
		FocusAreas:  []string{"auth"},
	}

	if cfg.Concurrency != 25 {
		t.Error("Concurrency mismatch")
	}
	if cfg.RateLimit != 100 {
		t.Error("RateLimit mismatch")
	}
	if !cfg.SkipStatic {
		t.Error("SkipStatic should be true")
	}
}

// TestUnique tests unique helper function
func TestUnique(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		DiscoveredAt: time.Now(),
		Endpoints: []discovery.Endpoint{
			{
				Path:   "/api/test",
				Method: "GET",
				Parameters: []discovery.Parameter{
					{Name: "redirect_url", Location: "query"},
					{Name: "callback_url", Location: "query"},
				},
			},
		},
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	// Check that categories are unique
	if len(plan.EndpointTests) > 0 {
		categories := plan.EndpointTests[0].AttackCategories
		seen := make(map[string]bool)
		for _, cat := range categories {
			if seen[cat] {
				t.Errorf("Duplicate category found: %s", cat)
			}
			seen[cat] = true
		}
	}
}

// TestServiceSpecificTestGroup tests service detection
func TestServiceSpecificTestGroup(t *testing.T) {
	disc := &discovery.DiscoveryResult{
		Target:       "https://example.com",
		Service:      "authentik",
		DiscoveredAt: time.Now(),
	}

	learner := NewLearner(disc, "")
	plan := learner.GenerateTestPlan()

	foundService := false
	for _, g := range plan.TestGroups {
		if g.Category == "service-specific" {
			foundService = true
			if !strings.Contains(g.Reason, "authentik") {
				t.Error("Should mention service name in reason")
			}
		}
	}

	if !foundService {
		t.Error("Named service should trigger service-specific test group")
	}
}
