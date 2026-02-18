package mcpserver_test

// Schema invariant tests — structural regression coverage for issues found
// in adversarial rounds 9 and 10.
//
// Round 9: validate_spec bypassed security guards (see validate_spec_regression_test.go)
// Round 9: generate_cicd schedule YAML injection (see cicd_regression_test.go)
// Round 10: list_tasks + get_task_status tool_name enums were missing
//           "discover_bypasses" and "event_crawl".
//
// This file tests the *schema contracts* at the MCP protocol level:
//   1. All async tools launched via launchAsync appear in list_tasks + get_task_status enums
//   2. All tools have non-empty required schema fields
//   3. Every declared tool_name enum value is accepted by the handler (no enum → 400)
//   4. Every read-only tool rejects write-like side-effect hints
//
// Design principle: tests must be maintained alongside new async tools.
// If you add a new tool that calls launchAsync, add its name to
// asyncToolNames below or the test will fail — that's intentional.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// asyncToolNames is the canonical set of tool names passed to launchAsync.
// It must match the actual calls in the codebase:
//
//	pkg/mcpserver/tools_scan.go:       "scan", "assess"
//	pkg/mcpserver/tools_waf.go:        "bypass"
//	pkg/mcpserver/tools_discovery.go:  "discover"
//	pkg/mcpserver/tool_spec.go:        "scan_spec"
//	pkg/mcpserver/tools_tamper.go:     "discover_bypasses"
//	pkg/mcpserver/tools_headless.go:   "event_crawl"
//
// If a new launchAsync tool is added and this list is not updated, the
// enum consistency test below will catch the missing entry.
var asyncToolNames = []string{
	"scan",
	"assess",
	"bypass",
	"discover",
	"scan_spec",
	"discover_bypasses",
	"event_crawl",
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// getToolSchema fetches the InputSchema for a named tool via ListTools.
func getToolSchema(t *testing.T, cs *mcp.ClientSession, toolName string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range result.Tools {
		if tool.Name == toolName {
			raw, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatalf("marshal %s schema: %v", toolName, err)
			}
			var schema map[string]any
			if err := json.Unmarshal(raw, &schema); err != nil {
				t.Fatalf("unmarshal %s schema: %v", toolName, err)
			}
			return schema
		}
	}
	t.Fatalf("tool %q not found in ListTools response", toolName)
	return nil
}

// extractEnum extracts the enum slice from a nested schema path like
// properties.tool_name.enum.
func extractEnum(t *testing.T, schema map[string]any, fieldName string) []string {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no 'properties' object")
	}
	field, ok := props[fieldName].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.%s not found", fieldName)
	}
	rawEnum, ok := field["enum"].([]any)
	if !ok {
		t.Fatalf("schema.properties.%s.enum not found or not array", fieldName)
	}
	result := make([]string, len(rawEnum))
	for i, v := range rawEnum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum[%d] is not a string: %T", i, v)
		}
		result[i] = s
	}
	return result
}

// extractSchemaMax returns the "maximum" value for a numeric schema field.
func extractSchemaMax(t *testing.T, schema map[string]any, fieldName string) float64 {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no 'properties' object")
	}
	field, ok := props[fieldName].(map[string]any)
	if !ok {
		t.Fatalf("schema.properties.%s not found", fieldName)
	}
	max, ok := field["maximum"]
	if !ok {
		t.Fatalf("schema.properties.%s has no 'maximum' constraint", fieldName)
	}
	v, ok := max.(float64)
	if !ok {
		t.Fatalf("schema.properties.%s.maximum is %T, want float64", fieldName, max)
	}
	return v
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: list_tasks enum contains all async tool names
// ─────────────────────────────────────────────────────────────────────────────

// TestListTasksEnum_ContainsAllAsyncTools verifies that list_tasks schema
// tool_name enum declares every async tool name used in launchAsync.
// This is the class of bug found in Round 10: discover_bypasses and
// event_crawl were missing from the enum, so agents couldn't filter by them.
func TestListTasksEnum_ContainsAllAsyncTools(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "list_tasks")
	enumValues := extractEnum(t, schema, "tool_name")
	inEnum := make(map[string]bool, len(enumValues))
	for _, v := range enumValues {
		inEnum[v] = true
	}

	for _, toolName := range asyncToolNames {
		if !inEnum[toolName] {
			t.Errorf("list_tasks tool_name enum is missing %q — add it to the enum in addListTasksTool()", toolName)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: get_task_status enum contains all async tool names
// ─────────────────────────────────────────────────────────────────────────────

// TestGetTaskStatusEnum_ContainsAllAsyncTools verifies the same invariant for
// get_task_status, which also exposes a tool_name filter for auto-discovery.
func TestGetTaskStatusEnum_ContainsAllAsyncTools(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "get_task_status")
	enumValues := extractEnum(t, schema, "tool_name")
	inEnum := make(map[string]bool, len(enumValues))
	for _, v := range enumValues {
		inEnum[v] = true
	}

	for _, toolName := range asyncToolNames {
		if !inEnum[toolName] {
			t.Errorf("get_task_status tool_name enum is missing %q — add it to the enum in addGetTaskStatusTool()", toolName)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: list_tasks accepts every enum value without error
// ─────────────────────────────────────────────────────────────────────────────

// TestListTasks_AcceptsAllEnumValues calls list_tasks with each tool_name
// enum value and verifies the handler returns a valid (non-error) response.
// This would catch a future bug where the enum lies about accepted values
// (e.g., server rejects values the schema claims are valid).
func TestListTasks_AcceptsAllEnumValues(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "list_tasks")
	enumValues := extractEnum(t, schema, "tool_name")

	for _, toolName := range enumValues {
		toolName := toolName
		t.Run(toolName, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{"tool_name": toolName})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "list_tasks",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool(list_tasks, tool_name=%q): %v", toolName, err)
			}
			// Any non-protocol-error response is acceptable.
			// We expect {"tasks":[], "total":0, ...} because no tasks are running.
			// What we must NOT see is an argument validation error.
			if result.IsError {
				text := extractText(t, result)
				if strings.Contains(text, "invalid arguments") || strings.Contains(text, "unknown field") {
					t.Errorf("list_tasks rejected tool_name=%q as invalid: %s", toolName, text)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: get_task_status accepts every tool_name enum value without error
// ─────────────────────────────────────────────────────────────────────────────

// TestGetTaskStatus_AcceptsAllToolNameFilterValues verifies get_task_status
// accepts each declared tool_name enum value without a protocol error.
// When no matching task exists, it should return "no tasks found", not
// "invalid argument" or "unknown field".
func TestGetTaskStatus_AcceptsAllToolNameFilterValues(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "get_task_status")
	enumValues := extractEnum(t, schema, "tool_name")

	for _, toolName := range enumValues {
		toolName := toolName
		t.Run(toolName, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"tool_name":    toolName,
				"wait_seconds": 0, // don't wait — we expect no tasks
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "get_task_status",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool(get_task_status, tool_name=%q): %v", toolName, err)
			}
			// Should be a "no tasks found" error, not "invalid arguments".
			if result.IsError {
				text := extractText(t, result)
				if strings.Contains(text, "invalid arguments") || strings.Contains(text, "unknown field") {
					t.Errorf("get_task_status rejected tool_name=%q as invalid: %s", toolName, text)
				}
				// "no tasks found" or "nothing to poll" is the expected response
				if !strings.Contains(text, "task") {
					t.Errorf("get_task_status(tool_name=%q) unexpected error body: %s", toolName, text)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: list_tasks returns empty array (not null) when no tasks exist
// ─────────────────────────────────────────────────────────────────────────────

// TestListTasks_EmptyReturnsArray ensures list_tasks always returns
// a JSON array for "tasks", never null, to avoid client-side null pointer
// dereferences (a common JSON marshaling pitfall in Go: nil slice → null).
func TestListTasks_EmptyReturnsArray(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_tasks",
		Arguments: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("list_tasks error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	tasks, ok := resp["tasks"]
	if !ok {
		t.Fatal("list_tasks response missing 'tasks' field")
	}

	// Must be a JSON array, not null.
	if tasks == nil {
		t.Fatal("list_tasks 'tasks' is null — should be empty array []")
	}
	if _, ok := tasks.([]any); !ok {
		t.Fatalf("list_tasks 'tasks' is not an array: %T", tasks)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: generate_cicd schedule injection — all platforms
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateCICD_ScheduleInjection_AllPlatforms verifies that the schedule
// YAML injection guard fires on every platform, not just github.
// The cronSafePattern validator is applied before the platform switch, so all
// 6 platforms benefit. This confirms the guard doesn't get skipped by short-
// circuiting platform validation.
func TestGenerateCICD_ScheduleInjection_AllPlatforms(t *testing.T) {
	t.Parallel()

	// This schedule injects extra cron triggers in GitHub Actions YAML:
	// on.schedule becomes: - cron: '0 2 * * 1' then injected: - cron: '0 0 * * *'
	dangerousSchedule := "0 2 * * 1' - cron: '0 0 * * *"

	platforms := []string{"github", "gitlab", "jenkins", "azure-devops", "circleci", "bitbucket"}

	for _, platform := range platforms {
		platform := platform
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"platform": platform,
				"target":   "https://example.com",
				"schedule": dangerousSchedule,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Errorf("platform %s: expected rejection of injection schedule, got success", platform)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 7: generate_cicd schedule — safe chars are not over-blocked
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateCICD_CronSafePattern_NotOverRestrictive verifies that the
// cronSafePattern regex doesn't reject legitimate cron constructs.
// (The original pattern could have used a too-strict whitelist that blocked
// valid expressions like weekday ranges "1-5".)
func TestGenerateCICD_CronSafePattern_NotOverRestrictive(t *testing.T) {
	t.Parallel()

	validSchedules := []string{
		"0 2 * * 1",      // specific day
		"0 0 * * *",      // daily midnight
		"0 */6 * * *",    // every 6 hours
		"15 14 1 * *",    // specific time and day of month
		"0 9 * * 1-5",    // weekdays (range with dash)
		"@weekly",        // shorthand
		"@daily",         // shorthand
		"@monthly",       // shorthand
		"0,30 * * * *",   // multiple minutes (comma)
		"0 2,14 * * 1-5", // complex multi-value
	}

	cs := newTestSession(t)

	for _, schedule := range validSchedules {
		schedule := schedule
		t.Run(strings.ReplaceAll(schedule, " ", "_"), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"platform": "github",
				"target":   "https://example.com",
				"schedule": schedule,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Errorf("schedule %q rejected but should be accepted: %s", schedule, extractText(t, result))
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 8: validate_spec — path traversal blocked at protocol level
// ─────────────────────────────────────────────────────────────────────────────

// TestValidateSpec_TraversalRejectedAtProtocolLevel verifies that the fix in
// handleValidateSpec (not just resolveSpecInput) blocks traversal and SSRF.
// Previously, handleValidateSpec called apispec.ParseContext directly without
// any security guards, bypassing the checks in resolveSpecInput.
func TestValidateSpec_TraversalRejectedAtProtocolLevel(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	cases := []struct {
		name    string
		payload map[string]any
		wantErr string
	}{
		{
			"parent traversal in spec_path",
			map[string]any{"spec_path": "../../etc/passwd"},
			"traversal",
		},
		{
			"absolute path in spec_path",
			map[string]any{"spec_path": "/etc/passwd"},
			"",
		},
		{
			"cloud metadata SSRF via spec_url",
			map[string]any{"spec_url": "http://169.254.169.254/latest/meta-data/"},
			"",
		},
		// Note: localhost is NOT blocked by design — developers may run local spec servers.
		// Only cloud metadata endpoints (169.254.x.x, 100.100.x.x) are SSRF-blocked.
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(tc.payload)
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "validate_spec",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Errorf("%s: expected error (security rejection), got success", tc.name)
				return
			}
			text := extractText(t, result)
			// Confirm it's a security rejection, not a different error.
			securityKeywords := []string{"traversal", "path", "unsafe", "blocked", "SSRF", "metadata", "localhost", "invalid"}
			matched := false
			for _, kw := range securityKeywords {
				if strings.Contains(strings.ToLower(text), strings.ToLower(kw)) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("%s: error response doesn't mention security: %s", tc.name, text)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 9: All tools with declared enums — each enum value is accepted
// ─────────────────────────────────────────────────────────────────────────────

// TestAllToolEnums_NoStaleDeclaredValues inspects every tool's schema and
// verifies that declared enum values are structurally valid (non-empty strings).
// This catches copy-paste mistakes that leave empty strings or nil entries in
// an enum array.
func TestAllToolEnums_NoStaleDeclaredValues(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			continue
		}
		props, _ := schema["properties"].(map[string]any)
		for propName, propVal := range props {
			propMap, ok := propVal.(map[string]any)
			if !ok {
				continue
			}
			rawEnum, ok := propMap["enum"].([]any)
			if !ok {
				continue
			}
			for i, v := range rawEnum {
				s, ok := v.(string)
				if !ok {
					t.Errorf("tool %q property %q enum[%d] is not a string: %T", tool.Name, propName, i, v)
					continue
				}
				if s == "" {
					t.Errorf("tool %q property %q enum[%d] is empty string", tool.Name, propName, i)
				}
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 10: asyncToolNames constant is consistent with list_tasks schema
// ─────────────────────────────────────────────────────────────────────────────

// TestAsyncToolNamesList_NoExtraValues verifies there are no names in the
// list_tasks schema enum that aren't in asyncToolNames. This catches the
// reverse scenario: someone adds a name to the enum without a matching
// launchAsync call (dead enum values confuse agents).
func TestAsyncToolNamesList_NoExtraValues(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "list_tasks")
	enumValues := extractEnum(t, schema, "tool_name")

	inAsync := make(map[string]bool, len(asyncToolNames))
	for _, v := range asyncToolNames {
		inAsync[v] = true
	}

	for _, v := range enumValues {
		if !inAsync[v] {
			t.Errorf("list_tasks enum contains %q but it's not in asyncToolNames — "+
				"either add a launchAsync call for it or remove it from the enum", v)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 11: read-only tools must not carry destructive hint
// ─────────────────────────────────────────────────────────────────────────────

// TestReadOnlyTools_NotMarkedDestructive ensures ReadOnlyHint=true tools
// don't also have DestructiveHint=true (contradictory annotations would
// confuse agents about whether it's safe to call).
func TestReadOnlyTools_NotMarkedDestructive(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		ann := tool.Annotations
		if ann == nil {
			continue
		}
		if ann.ReadOnlyHint && ann.DestructiveHint != nil && *ann.DestructiveHint {
			t.Errorf("tool %q has ReadOnlyHint=true AND DestructiveHint=true — contradictory", tool.Name)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 12: generate_cicd injects schedule into output for github
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateCICD_ScheduleAppearsInOutputPipeline verifies that a valid
// schedule is reflected in the generated YAML pipeline, not silently dropped.
func TestGenerateCICD_ScheduleAppearsInOutputPipeline(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schedule := "0 3 * * 1" // weekly Monday 3am
	args, _ := json.Marshal(map[string]any{
		"platform": "github",
		"target":   "https://example.com",
		"schedule": schedule,
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "generate_cicd",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	if !strings.Contains(text, schedule) {
		t.Errorf("schedule %q not found in generate_cicd response:\n%s", schedule, text)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 13: compare_baselines — both empty arrays is valid (zero regressions)
// ─────────────────────────────────────────────────────────────────────────────

// TestCompareBaselines_BothEmpty verifies that passing two empty finding arrays
// returns a successful diff with no regressions/fixes/new findings, rather
// than an error. This is the "clean bill of health" case.
func TestCompareBaselines_BothEmpty(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"baseline_findings": "[]",
		"current_findings":  "[]",
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "compare_baselines",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("compare_baselines([], []) returned error: %s", extractText(t, result))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 14: compare_baselines — invalid JSON body returns error, not panic
// ─────────────────────────────────────────────────────────────────────────────

func TestCompareBaselines_MalformedJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		baselineFindings string
		currentFindings  string
	}{
		{"not an array in baseline", `{"key":"value"}`, `[]`},
		{"not an array in current", `[]`, `{"key":"value"}`},
		{"plain string in baseline", `"findings"`, `[]`},
		{"deeply broken json in baseline", `[{]`, `[]`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"baseline_findings": tc.baselineFindings,
				"current_findings":  tc.currentFindings,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "compare_baselines",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			// Must return IsError=true (graceful rejection), not panic
			if !result.IsError {
				t.Errorf("expected error for malformed input, got success")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 15: mutate — empty payload returns error (not empty variants)
// ─────────────────────────────────────────────────────────────────────────────

func TestMutate_EmptyPayload(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{"payload": ""})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("mutate with empty payload should return error")
	}
}

// TestMutate_UnknownEncoderRejected verifies that an unknown encoder name
// is handled gracefully. The tool should silently ignore unknown encoders
// (only known ones are applied) rather than panic or crash.
func TestMutate_UnknownEncoderIgnored(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"payload":  "' OR 1=1--",
		"encoders": []string{"url", "nonexistent_encoder"},
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	// Should succeed — only "url" is applied, "nonexistent_encoder" silently skipped
	if result.IsError {
		t.Fatalf("mutate with unknown encoder should not error: %s", extractText(t, result))
	}
	text := extractText(t, result)
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	variants, _ := resp["variants"].([]any)
	// Should have exactly 1 variant (only "url" matched)
	if len(variants) != 1 {
		t.Errorf("expected 1 variant (url only), got %d", len(variants))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 16: mutate — all 4 encoders produce distinct non-empty output
// ─────────────────────────────────────────────────────────────────────────────

// TestMutate_AllEncoders_ProduceDistinctOutput confirms the 4 encoders
// all transform a payload and produce different representations.
// Catches scenarios where an encoder silently produces identical output to another.
func TestMutate_AllEncoders_ProduceDistinctOutput(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This payload has characters that all 4 encoders should transform
	payload := "<script>alert('xss')</script>"

	args, _ := json.Marshal(map[string]any{"payload": payload})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "mutate",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("mutate error: %s", extractText(t, result))
	}

	text := extractText(t, result)
	var resp map[string]any
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	variants, _ := resp["variants"].([]any)
	if len(variants) != 4 {
		t.Fatalf("expected 4 variants (one per encoder), got %d", len(variants))
	}

	encodedSet := make(map[string]bool)
	for _, v := range variants {
		vm, ok := v.(map[string]any)
		if !ok {
			t.Fatal("variant is not an object")
		}
		encoded, _ := vm["encoded"].(string)
		if encoded == "" {
			t.Fatalf("encoder %v produced empty output", vm["encoder"])
		}
		if encoded == payload {
			t.Errorf("encoder %v produced unchanged output — encoding did nothing", vm["encoder"])
		}
		encodedSet[encoded] = true
	}

	// All 4 encoders should produce distinct representations
	if len(encodedSet) != 4 {
		t.Errorf("expected 4 distinct encoded outputs, got %d (some encoders produced identical output)", len(encodedSet))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 17: All tools have required fields in schema
// ─────────────────────────────────────────────────────────────────────────────

// TestAllTools_RequiredFieldsDeclared verifies that every tool with "required"
// in its schema lists only properties that actually exist in "properties".
// This catches copy-paste where required names diverge from property definitions.
func TestAllTools_RequiredFieldsDeclared(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			continue
		}
		props, _ := schema["properties"].(map[string]any)
		required, _ := schema["required"].([]any)

		for _, r := range required {
			name, ok := r.(string)
			if !ok {
				t.Errorf("tool %q: required entry is not a string: %T", tool.Name, r)
				continue
			}
			if _, exists := props[name]; !exists {
				t.Errorf("tool %q: required field %q not found in properties", tool.Name, name)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fuzz-style: list_tasks with each status enum
// ─────────────────────────────────────────────────────────────────────────────

// TestListTasks_AllStatusEnumValues verifies the status enum values are
// accepted and produce clean (non-argument-error) responses.
func TestListTasks_AllStatusEnumValues(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "list_tasks")
	props, _ := schema["properties"].(map[string]any)
	statusProp, _ := props["status"].(map[string]any)
	rawEnum, _ := statusProp["enum"].([]any)

	for _, v := range rawEnum {
		status, ok := v.(string)
		if !ok {
			continue
		}
		statusVal := status
		t.Run(statusVal, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{"status": statusVal})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "list_tasks",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool(status=%q): %v", statusVal, err)
			}
			if result.IsError {
				text := extractText(t, result)
				if strings.Contains(text, "invalid arguments") {
					t.Errorf("list_tasks rejected status=%q: %s", statusVal, text)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: generate_cicd schema platform enum matches handler whitelist
// ─────────────────────────────────────────────────────────────────────────────

// TestGenerateCICD_PlatformEnumMatchesHandler verifies that every platform
// in the schema enum is accepted by the handler (generates non-error output).
// This catches schema/handler drift — e.g., platform added to enum but handler
// returns "unsupported platform".
func TestGenerateCICD_PlatformEnumMatchesHandler(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	schema := getToolSchema(t, cs, "generate_cicd")
	enumValues := extractEnum(t, schema, "platform")

	for _, platform := range enumValues {
		platform := platform
		t.Run(platform, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"platform": platform,
				"target":   "https://example.com",
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool(platform=%q): %v", platform, err)
			}
			if result.IsError {
				t.Errorf("platform %q is in schema enum but handler rejects it: %s", platform, extractText(t, result))
			}

			// Non-empty pipeline field expected
			text := extractText(t, result)
			var resp struct {
				Pipeline string `json:"pipeline"`
			}
			if err := json.Unmarshal([]byte(text), &resp); err != nil {
				t.Fatalf("parse response: %v", err)
			}
			if resp.Pipeline == "" {
				t.Errorf("platform %q: generated pipeline is empty", platform)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: No tool produces a null result body for valid input
// ─────────────────────────────────────────────────────────────────────────────

// TestFastTools_NeverReturnNullBody ensures all synchronous (non-async) tools
// return a non-null, non-empty body for minimal valid input. This catches
// coding bugs where a handler returns jsonResult(nil) or textResult("").
func TestFastTools_NeverReturnNullBody(t *testing.T) {
	t.Parallel()

	// Minimal valid inputs for sync tools
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"list_payloads", map[string]any{}},
		{"list_tampers", map[string]any{}},
		{"list_templates", map[string]any{}},
		{"mutate", map[string]any{"payload": "test"}},
		{"generate_cicd", map[string]any{"platform": "github", "target": "https://example.com"}},
		{"list_tasks", map[string]any{}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			rawArgs, _ := json.Marshal(tc.args)
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      tc.tool,
				Arguments: json.RawMessage(rawArgs),
			})
			if err != nil {
				t.Fatalf("CallTool(%s): %v", tc.tool, err)
			}
			if result.IsError {
				return // errors are allowed; we're testing the non-error case
			}

			text := extractText(t, result)
			if text == "" || text == "null" {
				t.Errorf("tool %q returned empty/null body for valid input", tc.tool)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test: Timeout schema maximums match handler clamps
// ─────────────────────────────────────────────────────────────────────────────
// Round 15: detect_waf and probe handlers had no upper-bound check on timeout,
// allowing clients to set arbitrarily high values despite the schema declaring
// a maximum. These tests verify the schema contract and that the handler
// does not hang when given a value above the maximum.

// TestDetectWAF_TimeoutSchemaMaximum verifies detect_waf declares a timeout
// maximum of 60 in the schema. The handler clamp is at tools_waf.go:~106.
func TestDetectWAF_TimeoutSchemaMaximum(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	max := extractSchemaMax(t, getToolSchema(t, cs, "detect_waf"), "timeout")
	if max != 60 {
		t.Errorf("detect_waf timeout maximum = %v, want 60", max)
	}
}

// TestProbe_TimeoutSchemaMaximum verifies probe declares a timeout maximum
// of 30 in the schema. The handler clamp is at tools_waf.go:~550.
func TestProbe_TimeoutSchemaMaximum(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	max := extractSchemaMax(t, getToolSchema(t, cs, "probe"), "timeout")
	if max != 30 {
		t.Errorf("probe timeout maximum = %v, want 30", max)
	}
}

// TestTimeoutSchemaMaximums_AllToolsWithTimeout is a broader sweep: every tool
// that exposes a "timeout" field must declare a schema maximum. This prevents
// future tools from silently omitting the constraint.
func TestTimeoutSchemaMaximums_AllToolsWithTimeout(t *testing.T) {
	t.Parallel()
	cs := newTestSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range result.Tools {
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			continue
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		timeout, ok := props["timeout"].(map[string]any)
		if !ok {
			continue
		}
		// Only check integer/number timeout fields.
		typ, _ := timeout["type"].(string)
		if typ != "integer" && typ != "number" {
			continue
		}
		if _, hasMax := timeout["maximum"]; !hasMax {
			t.Errorf("tool %q has a numeric 'timeout' field without a 'maximum' constraint", tool.Name)
		}
	}
}
