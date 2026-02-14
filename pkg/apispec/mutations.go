package apispec

import (
	"fmt"
	"strings"
)

// ContentTypeMutation describes a content-type transformation to test.
type ContentTypeMutation struct {
	// OriginalContentType is the content type declared in the spec.
	OriginalContentType string `json:"original_content_type"`

	// MutatedContentType is the content type to send instead.
	MutatedContentType string `json:"mutated_content_type"`

	// Purpose explains what this mutation tests.
	Purpose string `json:"purpose"`

	// Category maps to the scan type.
	Category string `json:"category"`
}

// MethodConfusionTest describes an undocumented HTTP method to try.
type MethodConfusionTest struct {
	// DocumentedMethod is the method declared in the spec.
	DocumentedMethod string `json:"documented_method"`

	// TestedMethod is the undocumented method to try.
	TestedMethod string `json:"tested_method"`

	// Path is the endpoint path.
	Path string `json:"path"`

	// Purpose explains what this test checks.
	Purpose string `json:"purpose"`

	// UseOverrideHeader indicates X-HTTP-Method-Override should be used
	// instead of changing the actual HTTP method.
	UseOverrideHeader bool `json:"use_override_header,omitempty"`

	// OverrideHeaders maps header names to values for method override testing.
	OverrideHeaders map[string]string `json:"override_headers,omitempty"`
}

// GenerateContentTypeMutations produces content-type mutations for an endpoint.
// It only generates mutations for endpoints that have request bodies.
// Returns nil when there are no request bodies.
func GenerateContentTypeMutations(ep Endpoint) []ContentTypeMutation {
	if len(ep.RequestBodies) == 0 {
		return nil
	}

	var mutations []ContentTypeMutation

	for ct := range ep.RequestBodies {
		lower := strings.ToLower(ct)

		switch {
		case strings.Contains(lower, "json"):
			mutations = append(mutations,
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/xml",
					Purpose:             "JSON->XML mutation: test for XXE via content-type confusion",
					Category:            "xxe",
				},
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/x-www-form-urlencoded",
					Purpose:             "JSON->form mutation: test for HPP via content-type confusion",
					Category:            "hpp",
				},
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "text/plain",
					Purpose:             "JSON->text mutation: test for CORS preflight bypass",
					Category:            "cors",
				},
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/json; charset=utf-7",
					Purpose:             "charset confusion: UTF-7 encoding bypass",
					Category:            "xss",
				},
			)

		case strings.Contains(lower, "xml"):
			mutations = append(mutations,
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/json",
					Purpose:             "XML->JSON mutation: test for parser confusion",
					Category:            "nosqli",
				},
			)

		case strings.Contains(lower, "multipart"):
			mutations = append(mutations,
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/json",
					Purpose:             "multipart->JSON mutation: test for parser bypass",
					Category:            "inputvalidation",
				},
			)

		case strings.Contains(lower, "form"):
			mutations = append(mutations,
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/json",
					Purpose:             "form->JSON mutation: test for NoSQLi via content-type confusion",
					Category:            "nosqli",
				},
				ContentTypeMutation{
					OriginalContentType: ct,
					MutatedContentType:  "application/xml",
					Purpose:             "form->XML mutation: test for XXE via content-type confusion",
					Category:            "xxe",
				},
			)
		}
	}

	return mutations
}

// allHTTPMethods is the set of HTTP methods to test for method confusion.
var allHTTPMethods = []string{
	"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
}

// methodOverrideHeaders are headers that some frameworks honor for method overriding.
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// GenerateMethodConfusionTests produces method confusion tests for an endpoint.
// It tests undocumented HTTP methods and X-HTTP-Method-Override headers.
func GenerateMethodConfusionTests(ep Endpoint, documentedMethods []string) []MethodConfusionTest {
	documented := make(map[string]bool, len(documentedMethods))
	for _, m := range documentedMethods {
		documented[strings.ToUpper(m)] = true
	}
	// The endpoint's own method is always documented.
	documented[strings.ToUpper(ep.Method)] = true

	var tests []MethodConfusionTest

	// Test undocumented methods directly.
	for _, method := range allHTTPMethods {
		if documented[method] {
			continue
		}

		// Skip safe methods that are usually uninteresting.
		if method == "HEAD" || method == "OPTIONS" {
			continue
		}

		purpose := fmt.Sprintf("method confusion: %s accepts undocumented %s",
			ep.Path, method)

		// Destructive/write methods are more interesting.
		if method == "DELETE" || method == "PUT" || method == "PATCH" {
			purpose = fmt.Sprintf("method confusion: %s may accept dangerous undocumented %s",
				ep.Path, method)
		}

		tests = append(tests, MethodConfusionTest{
			DocumentedMethod: ep.Method,
			TestedMethod:     method,
			Path:             ep.Path,
			Purpose:          purpose,
		})
	}

	// Test method override headers: send a safe method (POST) with override to dangerous.
	dangerousMethods := []string{"DELETE", "PUT", "PATCH"}
	for _, method := range dangerousMethods {
		if documented[method] {
			continue
		}

		for _, header := range methodOverrideHeaders {
			tests = append(tests, MethodConfusionTest{
				DocumentedMethod:  ep.Method,
				TestedMethod:      "POST",
				Path:              ep.Path,
				Purpose:           fmt.Sprintf("method override: POST with %s: %s on %s", header, method, ep.Path),
				UseOverrideHeader: true,
				OverrideHeaders:   map[string]string{header: method},
			})
		}
	}

	return tests
}

// GenerateEndpointMethodConfusionTests is a convenience wrapper that generates
// method confusion tests for a single endpoint with no other documented methods.
func GenerateEndpointMethodConfusionTests(ep Endpoint) []MethodConfusionTest {
	return GenerateMethodConfusionTests(ep, nil)
}
