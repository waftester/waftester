package main

import (
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/params"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/waf/strategy"
)

// =============================================================================
// Fix 3: ShouldSkipPayload filtering tests
// =============================================================================

// filterPayloadsWithStrategy simulates the filtering logic added to cmd_autoscan.go.
// Extracted here for testability without running the full autoscan command.
func filterPayloadsWithStrategy(all []payloads.Payload, strat *strategy.Strategy) []payloads.Payload {
	if strat == nil || len(strat.SkipIneffectiveMutators) == 0 {
		return all
	}
	filtered := make([]payloads.Payload, 0, len(all))
	for _, p := range all {
		if strat.ShouldSkipPayload(p.EncodingUsed) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestFilterPayloads_SkipsIneffective(t *testing.T) {
	strat := &strategy.Strategy{
		SkipIneffectiveMutators: []string{"base64_simple"},
	}
	input := []payloads.Payload{
		{Payload: "test1", EncodingUsed: "base64_simple"},
		{Payload: "test2", EncodingUsed: "unicode"},
		{Payload: "test3", EncodingUsed: ""},
		{Payload: "test4", EncodingUsed: "base64_simple"},
	}

	result := filterPayloadsWithStrategy(input, strat)
	if len(result) != 2 {
		t.Fatalf("expected 2 payloads after filtering, got %d", len(result))
	}
	if result[0].Payload != "test2" {
		t.Errorf("expected test2 first, got %s", result[0].Payload)
	}
	if result[1].Payload != "test3" {
		t.Errorf("expected test3 second, got %s", result[1].Payload)
	}
}

func TestFilterPayloads_NilStrategy(t *testing.T) {
	input := []payloads.Payload{
		{Payload: "test1", EncodingUsed: "base64_simple"},
		{Payload: "test2", EncodingUsed: "unicode"},
	}

	result := filterPayloadsWithStrategy(input, nil)
	if len(result) != 2 {
		t.Errorf("nil strategy should preserve all payloads, got %d", len(result))
	}
}

func TestFilterPayloads_EmptySkipList(t *testing.T) {
	strat := &strategy.Strategy{
		SkipIneffectiveMutators: []string{},
	}
	input := []payloads.Payload{
		{Payload: "test1", EncodingUsed: "base64_simple"},
	}

	result := filterPayloadsWithStrategy(input, strat)
	if len(result) != 1 {
		t.Errorf("empty skip list should preserve all payloads, got %d", len(result))
	}
}

func TestFilterPayloads_AllFiltered(t *testing.T) {
	strat := &strategy.Strategy{
		SkipIneffectiveMutators: []string{"base64_simple"},
	}
	input := []payloads.Payload{
		{Payload: "test1", EncodingUsed: "base64_simple"},
		{Payload: "test2", EncodingUsed: "base64_simple"},
	}

	result := filterPayloadsWithStrategy(input, strat)
	if len(result) != 0 {
		t.Errorf("expected all payloads filtered, got %d", len(result))
	}
}

func TestFilterPayloads_NoneFiltered(t *testing.T) {
	strat := &strategy.Strategy{
		SkipIneffectiveMutators: []string{"nonexistent_encoding"},
	}
	input := []payloads.Payload{
		{Payload: "test1", EncodingUsed: "unicode"},
		{Payload: "test2", EncodingUsed: "double_url"},
	}

	result := filterPayloadsWithStrategy(input, strat)
	if len(result) != 2 {
		t.Errorf("expected no filtering, got %d payloads", len(result))
	}
}

// =============================================================================
// Fix 5: Body param injection tests
// =============================================================================

// generateParamPayloads simulates the param injection logic from cmd_autoscan.go.
func generateParamPayloads(paramResult *params.DiscoveryResult, existing []payloads.Payload, maxPayloads int) []payloads.Payload {
	if paramResult == nil || paramResult.FoundParams == 0 {
		return nil
	}

	var result []payloads.Payload
	for _, p := range paramResult.Parameters {
		if len(result) >= maxPayloads {
			break
		}

		switch p.Type {
		case "query":
			for _, ex := range existing {
				if len(result) >= maxPayloads {
					break
				}
				clone := ex
				separator := "?"
				if strings.Contains(clone.TargetPath, "?") {
					separator = "&"
				}
				clone.TargetPath = clone.TargetPath + separator + p.Name + "=" + clone.Payload
				result = append(result, clone)
			}

		case "body":
			for _, ex := range existing {
				if len(result) >= maxPayloads {
					break
				}
				clone := ex
				clone.Method = "POST"
				clone.ContentType = defaults.ContentTypeForm
				clone.Payload = p.Name + "=" + ex.Payload
				result = append(result, clone)
			}
		}
	}
	return result
}

func TestParamInjection_QueryParams(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 1,
		Parameters: []params.DiscoveredParam{
			{Name: "debug", Type: "query"},
		},
	}
	existing := []payloads.Payload{
		{Payload: "<script>alert(1)</script>", TargetPath: "/api/test"},
	}

	result := generateParamPayloads(paramResult, existing, 200)
	if len(result) != 1 {
		t.Fatalf("expected 1 param payload, got %d", len(result))
	}
	if !strings.Contains(result[0].TargetPath, "debug=") {
		t.Errorf("expected query param in target path, got %s", result[0].TargetPath)
	}
	if result[0].Method == "POST" {
		t.Error("query param should not set POST method")
	}
}

func TestParamInjection_BodyParams(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 1,
		Parameters: []params.DiscoveredParam{
			{Name: "secret_field", Type: "body"},
		},
	}
	existing := []payloads.Payload{
		{Payload: "' OR 1=1--", Category: "sqli"},
	}

	result := generateParamPayloads(paramResult, existing, 200)
	if len(result) != 1 {
		t.Fatalf("expected 1 body param payload, got %d", len(result))
	}
	if result[0].Method != "POST" {
		t.Errorf("body param should use POST method, got %s", result[0].Method)
	}
	if result[0].ContentType != defaults.ContentTypeForm {
		t.Errorf("expected form content type, got %s", result[0].ContentType)
	}
	if !strings.HasPrefix(result[0].Payload, "secret_field=") {
		t.Errorf("expected payload to start with param name, got %s", result[0].Payload)
	}
}

func TestParamInjection_HeaderParamsSkipped(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 1,
		Parameters: []params.DiscoveredParam{
			{Name: "X-Custom", Type: "header"},
		},
	}
	existing := []payloads.Payload{
		{Payload: "test"},
	}

	result := generateParamPayloads(paramResult, existing, 200)
	if len(result) != 0 {
		t.Errorf("header params should be skipped, got %d payloads", len(result))
	}
}

func TestParamInjection_MaxCap(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 2,
		Parameters: []params.DiscoveredParam{
			{Name: "p1", Type: "query"},
			{Name: "p2", Type: "body"},
		},
	}
	existing := make([]payloads.Payload, 100)
	for i := range existing {
		existing[i] = payloads.Payload{Payload: "test", TargetPath: "/api"}
	}

	result := generateParamPayloads(paramResult, existing, 5)
	if len(result) > 5 {
		t.Errorf("expected max 5 payloads, got %d", len(result))
	}
}

func TestParamInjection_NoParams(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 0,
		Parameters:  []params.DiscoveredParam{},
	}
	existing := []payloads.Payload{{Payload: "test"}}

	result := generateParamPayloads(paramResult, existing, 200)
	if result != nil {
		t.Errorf("expected nil result for no params, got %v", result)
	}
}

func TestParamInjection_NilResult(t *testing.T) {
	existing := []payloads.Payload{{Payload: "test"}}
	result := generateParamPayloads(nil, existing, 200)
	if result != nil {
		t.Errorf("expected nil result for nil paramResult, got %v", result)
	}
}

func TestParamInjection_MixedTypes(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 3,
		Parameters: []params.DiscoveredParam{
			{Name: "q", Type: "query"},
			{Name: "csrf", Type: "body"},
			{Name: "X-Auth", Type: "header"}, // should be skipped
		},
	}
	existing := []payloads.Payload{
		{Payload: "test_payload", TargetPath: "/page"},
	}

	result := generateParamPayloads(paramResult, existing, 200)
	// Should get 1 query + 1 body = 2, header skipped
	if len(result) != 2 {
		t.Fatalf("expected 2 payloads (query + body), got %d", len(result))
	}

	queryCount := 0
	postCount := 0
	for _, p := range result {
		if p.Method == "POST" {
			postCount++
		} else {
			queryCount++
		}
	}
	if queryCount != 1 {
		t.Errorf("expected 1 query payload, got %d", queryCount)
	}
	if postCount != 1 {
		t.Errorf("expected 1 POST payload, got %d", postCount)
	}
}

func TestParamInjection_QueryWithExistingQueryString(t *testing.T) {
	paramResult := &params.DiscoveryResult{
		FoundParams: 1,
		Parameters: []params.DiscoveredParam{
			{Name: "debug", Type: "query"},
		},
	}
	existing := []payloads.Payload{
		{Payload: "test", TargetPath: "/api?existing=1"},
	}

	result := generateParamPayloads(paramResult, existing, 200)
	if len(result) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(result))
	}
	// Should use & separator since ? already exists
	if !strings.Contains(result[0].TargetPath, "&debug=") {
		t.Errorf("expected & separator for existing query string, got %s", result[0].TargetPath)
	}
}
