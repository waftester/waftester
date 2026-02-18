package mcpserver_test

// Regression tests for generate_cicd bugs found in adversarial round 9.
//
// Bug: args.Schedule was not validated before YAML embedding.
//   A schedule like "0 2 * * 1'\n    - cron: '0 0 * * *" would inject extra
//   cron triggers into GitHub Actions YAML. Fixed: added cronSafePattern
//   validator that rejects newlines, quotes, and other YAML-breaking chars.
//
// Note on binary name: the released binary IS "waf-tester" (per .goreleaser.yaml
//   binary: waf-tester). All generated pipelines correctly use "./waf-tester".

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------------------------------------------------------------------------
// Schedule YAML injection must be blocked
// ---------------------------------------------------------------------------

func TestGenerateCICD_Schedule_InjectionBlocked(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		schedule string
	}{
		{"single-quote breaks YAML", "0 2 * * 1' - cron: '0 0 * * *"},
		{"newline injection", "0 2 * * 1\n    - cron: '0 0 * * *"},
		{"backslash injection", `0 2 * * 1\n    - cron: '0 0'`},
		{"double-quote injection", `0 2 * * 1" - cron: "0 0 * * *`},
		{"shell injection", "0 2 * * 1; rm -rf /"},
		{"null bytes", "0 2 * * 1\x00extra"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"platform": "github",
				"target":   "https://example.com",
				"schedule": tc.schedule,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				// Extra check: confirm YAML injection didn't succeed
				text := extractText(t, result)
				if strings.Count(text, "- cron:") > 1 {
					t.Fatalf("schedule YAML injection succeeded — got multiple cron entries for schedule %q\n%s",
						tc.schedule, text)
				}
				t.Fatalf("generate_cicd accepted dangerous schedule %q without rejection", tc.schedule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Schedule with valid cron expression must still work
// ---------------------------------------------------------------------------

func TestGenerateCICD_ValidSchedule_Accepted(t *testing.T) {
	t.Parallel()

	validSchedules := []struct {
		name     string
		schedule string
	}{
		{"weekly monday 2am", "0 2 * * 1"},
		{"daily midnight", "0 0 * * *"},
		{"every 6 hours", "0 */6 * * *"},
		{"weekdays only", "0 9 * * 1-5"},
		{"at-weekly shorthand", "@weekly"},
		{"at-monthly shorthand", "@monthly"},
		{"empty schedule", ""},
	}

	for _, tc := range validSchedules {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cs := newTestSession(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			args, _ := json.Marshal(map[string]any{
				"platform": "github",
				"target":   "https://example.com",
				"schedule": tc.schedule,
			})
			result, err := cs.CallTool(ctx, &mcp.CallToolParams{
				Name:      "generate_cicd",
				Arguments: json.RawMessage(args),
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("generate_cicd rejected valid schedule %q: %s",
					tc.schedule, extractText(t, result))
			}

			// When schedule is set, it must appear in the pipeline or next_steps
			if tc.schedule != "" {
				text := extractText(t, result)
				if !strings.Contains(text, tc.schedule) {
					t.Errorf("schedule %q not reflected in response", tc.schedule)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Existing injection tests extended with schedule field
// ---------------------------------------------------------------------------

func TestGenerateCICD_ScheduleValidation_ExistsForAllPlatforms(t *testing.T) {
	t.Parallel()

	// GitLab embeds schedule in a YAML comment, which is less dangerous,
	// but the validator should reject injection attempts there too.
	cs := newTestSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"platform": "gitlab",
		"target":   "https://example.com",
		"schedule": "'; yaml: injection",
	})
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "generate_cicd",
		Arguments: json.RawMessage(args),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("generate_cicd should reject schedule with quote on gitlab platform too")
	}
}
