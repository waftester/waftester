package main

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/defaults"
)

// =============================================================================
// HELP TEXT SYNC TESTS
// =============================================================================
//
// These tests catch drift between the CLI dispatch logic and help/docs text.
// They replace manual audits with automated checks that run on every build.
//
// Three layers of verification:
//   1. Every command/alias from main.go's switch is mentioned in printUsage()
//   2. Default values in help text match actual code defaults
//   3. Docs topics in the index match the switch cases in printDetailedDocs

// TestHelpListsAllDispatchCommands verifies every command and alias from
// main.go's dispatch switch appears in cmd_docs.go. Catches the common drift
// where a command is added to main.go but not documented in help text.
func TestHelpListsAllDispatchCommands(t *testing.T) {
	mainSrc := readSourceFile(t, "main.go")
	docsSrc := readSourceFile(t, "cmd_docs.go")

	commands := extractDispatchCommands(mainSrc)
	if len(commands) == 0 {
		t.Fatal("extractDispatchCommands returned 0 commands — parser broken")
	}

	// Meta-commands: dispatched but not listed in COMMANDS section
	skip := map[string]bool{
		"-h": true, "--help": true, "help": true,
		"-v": true, "--version": true, "version": true,
		"docs": true, "doc": true, "man": true, "manual": true,
	}

	var missing []string
	for _, cmd := range commands {
		if skip[cmd] {
			continue
		}
		if !strings.Contains(docsSrc, cmd) {
			missing = append(missing, cmd)
		}
	}

	if len(missing) > 0 {
		t.Errorf("commands dispatched in main.go but missing from cmd_docs.go:\n  %s\n\nAdd to printUsage() in cmd_docs.go.",
			strings.Join(missing, "\n  "))
	}
}

// TestHelpDefaultsNotStale guards against known-incorrect default values.
// Each entry is a regression test for a previously discovered mismatch.
// Extend these lists when fixing a new default value issue.
func TestHelpDefaultsNotStale(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	// Strings that must NOT appear (regression guards)
	forbidden := []struct{ bad, reason string }{
		{"../payloads", "payload dir default must be " + defaults.PayloadDir},
	}
	for _, f := range forbidden {
		if strings.Contains(docsSrc, f.bad) {
			t.Errorf("found %q in cmd_docs.go — %s", f.bad, f.reason)
		}
	}

	// Strings that MUST appear
	required := []struct{ pattern, reason string }{
		{defaults.PayloadDir, "correct PayloadDir default must be documented"},
	}
	for _, r := range required {
		if !strings.Contains(docsSrc, r.pattern) {
			t.Errorf("missing %q in cmd_docs.go — %s", r.pattern, r.reason)
		}
	}
}

// TestFlagDefaultsCrossCheck verifies documented defaults match actual code.
// Two categories: defaults from the defaults package, and defaults from
// individual flag registrations in command files.
func TestFlagDefaultsCrossCheck(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	// Defaults from the defaults package — checked against help text patterns.
	// The regex must be specific enough to match only the intended section.
	pkgChecks := []struct {
		name        string
		codeDefault int
		docsRegex   string // capture group 1 = documented default
	}{
		{
			"run/concurrency",
			defaults.DefaultConfigConcurrency,
			`Concurrent workers \(default:\s*(\d+)\)`,
		},
		{
			"run/rate-limit",
			defaults.DefaultConfigRateLimit,
			`Requests per second \(default:\s*(\d+)\)`,
		},
		{
			"run/timeout",
			defaults.DefaultConfigTimeoutSec,
			`HTTP timeout \(default:\s*(\d+)\)`,
		},
	}

	for _, check := range pkgChecks {
		t.Run(check.name, func(t *testing.T) {
			re := regexp.MustCompile(check.docsRegex)
			matches := re.FindAllStringSubmatch(docsSrc, -1)
			if len(matches) == 0 {
				t.Fatalf("pattern %q not found in cmd_docs.go", check.docsRegex)
			}
			for _, m := range matches {
				docVal, _ := strconv.Atoi(m[1])
				if docVal != check.codeDefault {
					t.Errorf("docs say default=%d, code says default=%d", docVal, check.codeDefault)
				}
			}
		})
	}

	// Defaults from flag registrations in command files.
	// The cmdRegex extracts the default from the flag.NewFlagSet call.
	// The docsRegex extracts the documented default using surrounding text for context.
	fileChecks := []struct {
		name      string
		cmdFile   string
		cmdRegex  string // group 1 = code default
		docsRegex string // group 1 = docs default
	}{
		{
			"crawl/concurrency",
			"cmd_crawl.go",
			`Int\("concurrency",\s*(\d+)`,
			`Parallel crawlers? \(default:\s*(\d+)\)`,
		},
		{
			"discover/concurrency",
			"cmd_discover.go",
			`Int\("concurrency",\s*(\d+)`,
			`Parallel workers \(default:\s*(\d+)\)`,
		},
	}

	for _, check := range fileChecks {
		t.Run(check.name, func(t *testing.T) {
			cmdSrc := readSourceFile(t, check.cmdFile)

			cmdRe := regexp.MustCompile(check.cmdRegex)
			cmdMatch := cmdRe.FindStringSubmatch(cmdSrc)
			if cmdMatch == nil {
				t.Fatalf("pattern %q not found in %s", check.cmdRegex, check.cmdFile)
			}

			docsRe := regexp.MustCompile(check.docsRegex)
			docsMatch := docsRe.FindStringSubmatch(docsSrc)
			if docsMatch == nil {
				t.Fatalf("pattern %q not found in cmd_docs.go", check.docsRegex)
			}

			if cmdMatch[1] != docsMatch[1] {
				t.Errorf("code default=%s (%s), docs default=%s (cmd_docs.go)",
					cmdMatch[1], check.cmdFile, docsMatch[1])
			}
		})
	}
}

// TestDocsTopicsInSync verifies that the topic index in printDocsIndex()
// matches the switch cases in printDetailedDocs(). Catches topics listed
// in the index that have no handler, or handlers with no index entry.
func TestDocsTopicsInSync(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	// Extract primary topics from the index.
	indexTopics := extractDocsIndexTopics(docsSrc)
	if len(indexTopics) == 0 {
		t.Fatal("extractDocsIndexTopics returned 0 topics — parser broken")
	}

	// Extract all case clauses from printDetailedDocs switch.
	// Each clause is a group of aliases (e.g., ["template", "templates"]).
	switchClauses := extractDocsSwitchClauses(docsSrc)
	if len(switchClauses) == 0 {
		t.Fatal("extractDocsSwitchClauses returned 0 clauses — parser broken")
	}

	// Build a set of ALL handled topic strings
	allHandled := make(map[string]bool)
	for _, clause := range switchClauses {
		for _, alias := range clause {
			allHandled[alias] = true
		}
	}

	// Every index topic must have a handler (can be primary or alias)
	for _, topic := range indexTopics {
		if !allHandled[topic] {
			t.Errorf("topic %q is in docs index but has no handler in printDetailedDocs", topic)
		}
	}

	// Every switch clause must have at least one value shown in the index
	indexSet := make(map[string]bool)
	for _, topic := range indexTopics {
		indexSet[topic] = true
	}
	for _, clause := range switchClauses {
		found := false
		for _, alias := range clause {
			if indexSet[alias] {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("switch clause %v has no topic listed in docs index", clause)
		}
	}
}

// =============================================================================
// HELPERS
// =============================================================================

// readSourceFile reads a file relative to the test's working directory.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// extractDispatchCommands returns all command names and aliases from the
// os.Args[1] switch statement in main.go source.
func extractDispatchCommands(src string) []string {
	var cmds []string
	re := regexp.MustCompile(`"([^"]+)"`)
	inSwitch := false
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "switch os.Args[1]") {
			inSwitch = true
			continue
		}
		if !inSwitch {
			continue
		}
		if strings.HasPrefix(trimmed, "case ") {
			for _, m := range re.FindAllStringSubmatch(trimmed, -1) {
				cmds = append(cmds, m[1])
			}
		}
		if strings.HasPrefix(trimmed, "default:") {
			break
		}
	}
	return cmds
}

// extractDocsIndexTopics returns topic names from printDocsIndex().
// Parses StatValueStyle.Render("topic") calls that are not empty padding.
func extractDocsIndexTopics(src string) []string {
	var topics []string

	// Find the printDocsIndex function body by locating the next function
	funcStart := strings.Index(src, "func printDocsIndex()")
	if funcStart < 0 {
		return nil
	}
	remaining := src[funcStart:]
	// Find the end: next top-level "func " declaration
	nextFunc := strings.Index(remaining[1:], "\nfunc ")
	var body string
	if nextFunc < 0 {
		body = remaining
	} else {
		body = remaining[:nextFunc+1]
	}

	re := regexp.MustCompile(`StatValueStyle\.Render\("(\w[\w-]*)`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		topics = append(topics, strings.TrimSpace(m[1]))
	}
	return topics
}

// extractDocsSwitchClauses returns each case clause from the printDetailedDocs
// switch as a slice of aliases. E.g., ["template", "templates"] for one clause.
func extractDocsSwitchClauses(src string) [][]string {
	var clauses [][]string

	// Find the printDetailedDocs function and its switch statement
	funcStart := strings.Index(src, "func printDetailedDocs()")
	if funcStart < 0 {
		return nil
	}
	body := src[funcStart:]

	switchIdx := strings.Index(body, "switch topic {")
	if switchIdx < 0 {
		switchIdx = strings.Index(body, "switch topicArg {")
		if switchIdx < 0 {
			return nil
		}
	}

	// Parse case lines from the switch
	allQuoted := regexp.MustCompile(`"([^"]+)"`)
	for _, line := range strings.Split(body[switchIdx:], "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "case ") {
			var aliases []string
			for _, m := range allQuoted.FindAllStringSubmatch(trimmed, -1) {
				aliases = append(aliases, m[1])
			}
			if len(aliases) > 0 {
				clauses = append(clauses, aliases)
			}
		}
		if strings.HasPrefix(trimmed, "default:") {
			break
		}
	}
	return clauses
}

// =============================================================================
// DOCUMENTATION
// =============================================================================
//
// These tests catch three categories of drift:
//
// 1. MISSING COMMANDS: New command added to main.go switch but not to help text.
//    Fix: Add the command to printUsage() in cmd_docs.go.
//
// 2. STALE DEFAULTS: Help text shows a default value that no longer matches code.
//    Fix: Update the default in cmd_docs.go, then add a cross-check entry in
//    TestFlagDefaultsCrossCheck to prevent regression.
//
// 3. DOCS TOPIC MISMATCH: Index lists a topic with no handler, or vice versa.
//    Fix: Add the missing topic to the index or the handler switch.
//
// HOW TO EXTEND:
//
// - New command: After adding to main.go switch, run tests. They fail with the
//   exact command name that needs to be added to cmd_docs.go.
//
// - New anti-pattern: After fixing a stale default, add it to the "forbidden"
//   list in TestHelpDefaultsNotStale. This prevents the same mistake recurring.
//
// - New default cross-check: Add an entry to pkgChecks (for defaults package
//   constants) or fileChecks (for flag registrations in cmd_*.go files).
