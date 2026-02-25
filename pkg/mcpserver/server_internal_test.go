package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/waftester/waftester/pkg/waf/vendors"
)

func TestIsCloudMetadataHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		// Direct IPv4 metadata endpoints
		{"169.254.169.254", true},
		{"100.100.100.200", true},
		{"metadata.google.internal", true},

		// Cloud provider metadata IPs added in security review
		{"192.0.0.192", true},   // Oracle Cloud IMDS
		{"168.63.129.16", true}, // Azure Wire Server
		{"fd00:ec2::254", true}, // AWS IMDSv2 IPv6

		// Link-local range (169.254.0.0/16) — not just .169.254
		{"169.254.0.1", true},
		{"169.254.1.1", true},
		{"169.254.255.255", true},

		// ULA range (fd00::/8) — covers all fd** addresses
		{"fd00::1", true},
		{"fdff::1", true},
		{"fd12:3456:789a::1", true},

		// IPv6-mapped IPv4 bypass attempts
		{"::ffff:169.254.169.254", true},
		{"::ffff:a9fe:a9fe", true},
		{"0:0:0:0:0:ffff:169.254.169.254", true},
		{"::ffff:100.100.100.200", true},

		// Safe hosts
		{"example.com", false},
		{"10.0.0.1", false},
		{"localhost", false},
		{"", false},
		{"192.168.1.1", false},
		{"172.16.0.1", false},
		{"fc00::1", false}, // fc00::/7 but NOT fd00::/8
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := isCloudMetadataHost(tt.host); got != tt.want {
				t.Errorf("isCloudMetadataHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestValidateTargetURL_CloudMetadata(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"direct metadata", "http://169.254.169.254/latest/meta-data/", true},
		{"ipv6-mapped metadata", "http://[::ffff:169.254.169.254]/latest/meta-data/", true},
		{"google metadata", "http://metadata.google.internal/computeMetadata/v1/", true},
		{"alibaba metadata", "http://100.100.100.200/latest/meta-data/", true},
		{"oracle cloud IMDS", "http://192.0.0.192/opc/v2/", true},
		{"azure wire server", "http://168.63.129.16/metadata/instance", true},
		{"link-local other", "http://169.254.1.1/anything", true},
		{"ula address", "http://[fd12:3456::1]/path", true},
		{"normal target", "https://example.com/", false},
		{"empty URL", "", true},
		{"no scheme", "example.com", true},
		{"ftp scheme", "ftp://example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTargetURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestIsLocalhostOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"http://localhost:3000", true},
		{"http://127.0.0.1:8080", true},
		{"http://[::1]:5173", true},
		{"https://localhost", true},
		{"https://evil.example.com", false},
		{"http://localhost.evil.com:3000", false},
		{"", false},
		{"not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.origin, func(t *testing.T) {
			if got := isLocalhostOrigin(tt.origin); got != tt.want {
				t.Errorf("isLocalhostOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

func TestParseArgs_RejectsUnknownFields(t *testing.T) {
	t.Parallel()

	type args struct {
		Target string `json:"target"`
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"target":"https://example.com","typo_flag":true}`),
		},
	}

	var got args
	err := parseArgs(req, &got)
	if err == nil {
		t.Fatal("expected parseArgs to reject unknown fields")
	}
}

func TestParseArgs_AllowsKnownFields(t *testing.T) {
	t.Parallel()

	type args struct {
		Target string `json:"target"`
	}

	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Arguments: json.RawMessage(`{"target":"https://example.com"}`),
		},
	}

	var got args
	err := parseArgs(req, &got)
	if err != nil {
		t.Fatalf("unexpected parseArgs error: %v", err)
	}
	if got.Target != "https://example.com" {
		t.Fatalf("target mismatch: got %q", got.Target)
	}
}

// ---------------------------------------------------------------------------
// serverInstructions drift detection
// Catches: stale tool count, missing tools from FAST/ASYNC lists,
// missing resources from READING RESOURCES, incomplete TOOL SELECTION GUIDE.
// ---------------------------------------------------------------------------

// newInternalTestSession creates a connected MCP session for internal tests.
// Registers event_crawl so all conditional tools are present.
func newInternalTestSession(t *testing.T) *mcp.ClientSession {
	t.Helper()

	srv := New(&Config{
		PayloadDir: "../../payloads",
		EventCrawlFn: func(_ context.Context, _ string, _, _ int) ([]EventCrawlResult, []string, error) {
			return nil, nil, nil
		},
	})
	t.Cleanup(func() { srv.Stop() })

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	client := mcp.NewClient(&mcp.Implementation{
		Name: "test-client", Version: "0.0.1",
	}, nil)

	ctx := context.Background()
	go func() { _ = srv.MCPServer().Run(ctx, serverTransport) }()

	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// instructionLine returns the first line containing prefix.
func instructionLine(prefix string) string {
	for _, line := range strings.Split(serverInstructions, "\n") {
		if strings.Contains(line, prefix) {
			return line
		}
	}
	return ""
}

// parseToolList extracts comma-separated tool names after a prefix.
func parseToolList(line, prefix string) []string {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(line[idx+len(prefix):])
	parts := strings.Split(rest, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func TestServerInstructions_ToolCount(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// The instructions list every tool under FAST TOOLS and ASYNC TOOLS.
	// Verify the sum matches the actual registered tool count.
	fastLine := instructionLine("FAST TOOLS (return immediately):")
	asyncLine := instructionLine("ASYNC TOOLS (return task_id):")

	fast := parseToolList(fastLine, "FAST TOOLS (return immediately):")
	async := parseToolList(asyncLine, "ASYNC TOOLS (return task_id):")

	listed := len(fast) + len(async)
	if listed != len(tools.Tools) {
		t.Errorf("instructions list %d tools (fast=%d + async=%d), but %d are registered",
			listed, len(fast), len(async), len(tools.Tools))
	}
}

func TestServerInstructions_AsyncToolsRegistered(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	registered := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		registered[tool.Name] = true
	}

	line := instructionLine("ASYNC TOOLS (return task_id):")
	if line == "" {
		t.Fatal("ASYNC TOOLS line not found in serverInstructions")
	}
	claimed := parseToolList(line, "ASYNC TOOLS (return task_id):")
	for _, name := range claimed {
		if !registered[name] {
			t.Errorf("ASYNC TOOLS lists %q but it is not a registered tool", name)
		}
	}
}

func TestServerInstructions_FastPlusAsyncCoversAllTools(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	registered := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		registered[tool.Name] = true
	}

	fastLine := instructionLine("FAST TOOLS (return immediately):")
	asyncLine := instructionLine("ASYNC TOOLS (return task_id):")

	fast := parseToolList(fastLine, "FAST TOOLS (return immediately):")
	async := parseToolList(asyncLine, "ASYNC TOOLS (return task_id):")

	mentioned := make(map[string]bool)
	for _, n := range fast {
		mentioned[n] = true
	}
	for _, n := range async {
		mentioned[n] = true
	}

	// Every registered tool must appear in FAST or ASYNC
	for name := range registered {
		if !mentioned[name] {
			t.Errorf("registered tool %q missing from both FAST TOOLS and ASYNC TOOLS lists", name)
		}
	}
	// Every mentioned tool must be registered
	for name := range mentioned {
		if !registered[name] {
			t.Errorf("serverInstructions mentions %q but it is not a registered tool", name)
		}
	}
}

func TestServerInstructions_ToolSelectionGuide(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	for _, tool := range tools.Tools {
		needle := "| " + tool.Name + " |"
		if !strings.Contains(serverInstructions, needle) {
			t.Errorf("TOOL SELECTION GUIDE missing row for registered tool %q", tool.Name)
		}
	}
}

func TestServerInstructions_ReadingResources(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)
	ctx := context.Background()

	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	templates, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}

	for _, r := range resources.Resources {
		if !strings.Contains(serverInstructions, r.URI) {
			t.Errorf("READING RESOURCES missing registered resource %q", r.URI)
		}
	}
	for _, tmpl := range templates.ResourceTemplates {
		uri := string(tmpl.URITemplate)
		if !strings.Contains(serverInstructions, uri) {
			t.Errorf("READING RESOURCES missing registered resource template %q", uri)
		}
	}
}

func TestServerInstructions_VendorCounts(t *testing.T) {
	t.Parallel()

	wafCount := len(vendors.GetVendorNamesByCategory(vendors.WAFCategories()...))
	cdnCount := len(vendors.GetVendorNamesByCategory(vendors.CDNCategories()...))

	if wafCount == 0 {
		t.Fatal("WAF vendor registry returned 0 entries; check category names in GetVendorNamesByCategory call")
	}
	if cdnCount == 0 {
		t.Fatal("CDN vendor registry returned 0 entries; check category names in GetVendorNamesByCategory call")
	}

	wafClaim := fmt.Sprintf("%d WAF", wafCount)
	if !strings.Contains(serverInstructions, wafClaim) {
		t.Errorf("serverInstructions does not contain %q; WAF signature count may be stale", wafClaim)
	}

	cdnClaim := fmt.Sprintf("%d CDN", cdnCount)
	if !strings.Contains(serverInstructions, cdnClaim) {
		t.Errorf("serverInstructions does not contain %q; CDN signature count may be stale", cdnClaim)
	}
}

func TestVersionResource_CountsMatchReality(t *testing.T) {
	t.Parallel()
	cs := newInternalTestSession(t)
	ctx := context.Background()

	// Read the version resource
	result, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "waftester://version"})
	if err != nil {
		t.Fatalf("ReadResource(version): %v", err)
	}
	if len(result.Contents) == 0 {
		t.Fatal("version resource returned no contents")
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &info); err != nil {
		t.Fatalf("parse version JSON: %v", err)
	}

	caps, ok := info["capabilities"].(map[string]any)
	if !ok {
		t.Fatal("capabilities field missing or wrong type")
	}

	// Check resource count
	claimedResources := int(caps["resources"].(float64))
	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	templates, err := cs.ListResourceTemplates(ctx, nil)
	if err != nil {
		t.Fatalf("ListResourceTemplates: %v", err)
	}
	actualResources := len(resources.Resources) + len(templates.ResourceTemplates)
	if claimedResources != actualResources {
		t.Errorf("version resource claims %d resources, but %d are registered (static=%d, templates=%d)",
			claimedResources, actualResources, len(resources.Resources), len(templates.ResourceTemplates))
	}

	// Check prompt count
	claimedPrompts := int(caps["prompts"].(float64))
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	if claimedPrompts != len(prompts.Prompts) {
		t.Errorf("version resource claims %d prompts, but %d are registered",
			claimedPrompts, len(prompts.Prompts))
	}

	// Check tool count
	claimedTools := int(caps["tools"].(float64))
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if claimedTools != len(tools.Tools) {
		t.Errorf("version resource claims %d tools, but %d are registered",
			claimedTools, len(tools.Tools))
	}

	// Verify tool list in version resource matches registered tools
	toolList, ok := info["tools"].([]any)
	if !ok {
		t.Fatal("tools field missing or wrong type in version resource")
	}
	registered := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		registered[tool.Name] = true
	}
	for _, v := range toolList {
		name := v.(string)
		if !registered[name] {
			t.Errorf("version resource lists tool %q but it is not registered", name)
		}
	}
	for name := range registered {
		found := false
		for _, v := range toolList {
			if v.(string) == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("registered tool %q missing from version resource tool list", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Round 14: Concurrency + state audit — edge cases in launchAsync lifecycle
// ---------------------------------------------------------------------------

// newInternalServer creates a Server for internal concurrency tests.
// Does NOT start the MCP transport — tests call launchAsync directly.
func newInternalServer(t *testing.T) *Server {
	t.Helper()
	srv := New(&Config{
		PayloadDir: "../../payloads",
		EventCrawlFn: func(_ context.Context, _ string, _, _ int) ([]EventCrawlResult, []string, error) {
			return nil, nil, nil
		},
	})
	t.Cleanup(func() { srv.Stop() })
	return srv
}

// TestLaunchAsync_WorkFnPanic_FailsTask verifies that if a workFn panics,
// the task transitions to "failed" with a panic message instead of leaving
// it permanently stuck in "running" status.
func TestLaunchAsync_WorkFnPanic_FailsTask(t *testing.T) {
	srv := newInternalServer(t)
	ctx := context.Background()

	result, err := srv.launchAsync(ctx, "test_panic", "1s", func(_ context.Context, _ *Task) {
		panic("boom")
	})
	if err != nil {
		t.Fatalf("launchAsync error: %v", err)
	}

	// Parse the task_id from the immediate response.
	var resp asyncTaskResponse
	text := result.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	// Wait for the goroutine to finish (panic → recovery → Fail).
	task := srv.tasks.Get(resp.TaskID)
	if task == nil {
		t.Fatalf("task %s not found after launchAsync", resp.TaskID)
	}
	task.WaitFor(ctx, 5)

	snap := task.Snapshot()
	if snap.Status != TaskStatusFailed {
		t.Errorf("panicking workFn: status = %q, want %q", snap.Status, TaskStatusFailed)
	}
	if !strings.Contains(snap.Error, "panic") {
		t.Errorf("error should mention panic, got: %q", snap.Error)
	}
}

// TestLaunchAsync_WorkFnNoCompletion_FailsTask verifies the defensive
// check: if a workFn returns without calling Complete or Fail, the task
// is automatically failed so it doesn't permanently consume an active slot.
func TestLaunchAsync_WorkFnNoCompletion_FailsTask(t *testing.T) {
	srv := newInternalServer(t)
	ctx := context.Background()

	result, err := srv.launchAsync(ctx, "test_no_complete", "1s", func(_ context.Context, _ *Task) {
		// Intentionally return without calling Complete or Fail.
	})
	if err != nil {
		t.Fatalf("launchAsync error: %v", err)
	}

	var resp asyncTaskResponse
	text := result.Content[0].(*mcp.TextContent).Text
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}

	task := srv.tasks.Get(resp.TaskID)
	if task == nil {
		t.Fatalf("task %s not found", resp.TaskID)
	}
	task.WaitFor(ctx, 5)

	snap := task.Snapshot()
	if snap.Status != TaskStatusFailed {
		t.Errorf("no-completion workFn: status = %q, want %q", snap.Status, TaskStatusFailed)
	}
	if !strings.Contains(snap.Error, "without reporting") {
		t.Errorf("error should mention missing completion, got: %q", snap.Error)
	}
}

// TestLaunchAsync_StopDuringLaunch verifies that if Stop() is called before
// launchAsync, the server returns "shutting down" instead of starting a task.
func TestLaunchAsync_StopDuringLaunch(t *testing.T) {
	srv := New(&Config{
		PayloadDir: "../../payloads",
		EventCrawlFn: func(_ context.Context, _ string, _, _ int) ([]EventCrawlResult, []string, error) {
			return nil, nil, nil
		},
	})

	// Stop the server first, then try to launch.
	srv.Stop()
	ctx := context.Background()

	result, err := srv.launchAsync(ctx, "test_after_stop", "1s", func(_ context.Context, task *Task) {
		task.Complete(json.RawMessage(`{}`))
	})
	if err != nil {
		t.Fatalf("launchAsync error: %v", err)
	}

	text := result.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(text, "shutting down") {
		t.Errorf("expected 'shutting down' after Stop, got: %s", text)
	}
}

// TestWaitFor_CompletionDuringPoll verifies that WaitFor returns promptly
// when a task completes while the caller is waiting, rather than blocking
// for the full waitSeconds duration.
func TestWaitFor_CompletionDuringPoll(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	task, _, err := tm.Create(context.Background(), "test_tool")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Complete the task from another goroutine after a short delay.
	go func() {
		time.Sleep(50 * time.Millisecond)
		task.Complete(json.RawMessage(`{"ok":true}`))
	}()

	start := time.Now()
	task.WaitFor(context.Background(), 30) // 30s timeout
	elapsed := time.Since(start)

	// WaitFor should return well before the 30s timeout (within ~1s).
	if elapsed > 2*time.Second {
		t.Errorf("WaitFor took %v — should have returned promptly after completion", elapsed)
	}

	snap := task.Snapshot()
	if snap.Status != TaskStatusCompleted {
		t.Errorf("status = %q, want completed", snap.Status)
	}
}

// TestConcurrentLaunchAsync_NoSlotLeak verifies that concurrent launchAsync
// calls properly track and release active task slots, with no leaked slots
// after all tasks complete.
func TestConcurrentLaunchAsync_NoSlotLeak(t *testing.T) {
	srv := newInternalServer(t)
	ctx := context.Background()

	const n = 20
	var wg sync.WaitGroup
	taskIDs := make(chan string, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := srv.launchAsync(ctx, fmt.Sprintf("test_%d", i), "1s",
				func(_ context.Context, task *Task) {
					time.Sleep(10 * time.Millisecond) // Simulate brief work.
					task.Complete(json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)))
				})
			if err != nil {
				t.Errorf("launchAsync(%d): %v", i, err)
				return
			}
			var resp asyncTaskResponse
			text := result.Content[0].(*mcp.TextContent).Text
			if err := json.Unmarshal([]byte(text), &resp); err != nil {
				t.Errorf("parse(%d): %v", i, err)
				return
			}
			taskIDs <- resp.TaskID
		}(i)
	}
	wg.Wait()
	close(taskIDs)

	// Wait for all tasks to complete.
	for id := range taskIDs {
		task := srv.tasks.Get(id)
		if task != nil {
			task.WaitFor(ctx, 5)
		}
	}

	// All tasks should have reached terminal state — zero active slots.
	active := srv.tasks.ActiveCount()
	if active != 0 {
		t.Errorf("active tasks after all complete = %d, want 0 (slot leak)", active)
	}
}

// TestSlotExhaustion_RecoverAfterCompletion verifies that after hitting
// maxActiveTasks, completing a task frees a slot for a new one.
func TestSlotExhaustion_RecoverAfterCompletion(t *testing.T) {
	tm := NewTaskManager()
	defer tm.Stop()

	// Fill to capacity.
	tasks := make([]*Task, maxActiveTasks)
	for i := 0; i < maxActiveTasks; i++ {
		task, _, err := tm.Create(context.Background(), "filler")
		if err != nil {
			t.Fatalf("Create(%d): %v", i, err)
		}
		tasks[i] = task
	}

	// Next create should fail.
	_, _, err := tm.Create(context.Background(), "overflow")
	if err == nil {
		t.Fatal("expected error at maxActiveTasks, got nil")
	}

	// Complete one task to free a slot.
	tasks[0].Complete(json.RawMessage(`{}`))

	// Now create should succeed.
	_, _, err = tm.Create(context.Background(), "recovered")
	if err != nil {
		t.Fatalf("Create after completing one task: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// isWindowsAbsPath — cross-platform drive-letter detection
// ═══════════════════════════════════════════════════════════════════════════

func TestIsWindowsAbsPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		// Windows absolute paths — must be detected on all platforms.
		{`C:\Windows\System32`, true},
		{`D:\file.yaml`, true},
		{`c:\lower`, true},
		{`Z:/forward/slash`, true},

		// Not Windows absolute paths.
		{"", false},
		{"a", false},
		{"ab", false},
		{"../etc/passwd", false},
		{"/etc/passwd", false},
		{"specs/api.yaml", false},
		{"C:", false},  // no separator after colon
		{"C:a", false}, // no separator after colon
		{"1:\\digit", false},
		{"CC:\\double", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isWindowsAbsPath(tt.path); got != tt.want {
				t.Errorf("isWindowsAbsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
