package location

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/mutation"
)

func TestQueryParamLocation(t *testing.T) {
	loc := &QueryParamLocation{}

	if loc.Name() != "query_param" {
		t.Errorf("Expected name 'query_param', got '%s'", loc.Name())
	}
	if loc.Category() != "location" {
		t.Error("Wrong category")
	}

	results := loc.Mutate("test_payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce query string format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "=test_payload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Query param location should produce ?param=payload format")
	}
}

func TestPostFormLocation(t *testing.T) {
	loc := &PostFormLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce form body format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "=payload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST form location should produce field=payload format")
	}
}

func TestPostJSONLocation(t *testing.T) {
	loc := &PostJSONLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce JSON format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "{") && strings.Contains(r.Mutated, "}") {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST JSON location should produce JSON format")
	}
}

func TestPostXMLLocation(t *testing.T) {
	loc := &PostXMLLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce XML format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "<") && strings.Contains(r.Mutated, ">") {
			found = true
			break
		}
	}
	if !found {
		t.Error("POST XML location should produce XML format")
	}
}

func TestHeaderXForwardLocation(t *testing.T) {
	loc := &HeaderXForwardLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}
}

func TestCookieLocation(t *testing.T) {
	loc := &CookieLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce cookie format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "=payload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Cookie location should produce name=payload format")
	}
}

func TestPathSegmentLocation(t *testing.T) {
	loc := &PathSegmentLocation{}

	results := loc.Mutate("payload")
	if len(results) == 0 {
		t.Fatal("Expected at least 1 result")
	}

	// Should produce path format
	found := false
	for _, r := range results {
		if strings.Contains(r.Mutated, "/payload") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Path segment location should produce /payload format")
	}
}

func TestAllLocationsRegistered(t *testing.T) {
	locations := mutation.DefaultRegistry.GetByCategory("location")

	expectedLocations := []string{
		"query_param", "post_form", "post_json", "post_xml",
		"header_xforward", "header_referer", "header_useragent",
		"header_custom", "cookie", "path_segment",
		"multipart", "fragment", "basic_auth",
	}

	registered := make(map[string]bool)
	for _, loc := range locations {
		registered[loc.Name()] = true
	}

	for _, name := range expectedLocations {
		if !registered[name] {
			t.Errorf("Location '%s' not registered", name)
		}
	}
}

func TestLocationCategoryCorrect(t *testing.T) {
	locations := mutation.DefaultRegistry.GetByCategory("location")

	for _, loc := range locations {
		if loc.Category() != "location" {
			t.Errorf("Location '%s' has wrong category: %v", loc.Name(), loc.Category())
		}
	}
}
