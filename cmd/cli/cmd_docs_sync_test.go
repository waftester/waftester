package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/waftester/waftester/pkg/defaults"
)

// =============================================================================
// HELP TEXT SYNC TESTS
// =============================================================================
//
// Self-maintaining tests that catch drift between CLI code and help text.
// Zero manual upkeep: tests auto-discover commands, flags, and defaults
// by parsing source files directly. Adding a new command or flag with a
// wrong default in help text will fail the next test run automatically.
//
// Nine layers:
//   1. Every command/alias from main.go dispatch appears in printUsage()
//   2. Every flag.NewFlagSet command is documented
//   3. Numeric defaults documented in help text match code registrations
//   4. String defaults (paths, modes) match code via regression guards
//   5. Docs topics in the index match printDetailedDocs switch handlers
//   6. Every command in main.go has a ### section in docs/COMMANDS.md
//   7. Aliases in COMMANDS.md match main.go dispatch
//   8. Numeric flag defaults in COMMANDS.md tables match code
//   9. COMMANDS.md ToC lists every command section

// ---------------------------------------------------------------------------
// Layer 1: Dispatch → Help command listing
// ---------------------------------------------------------------------------

// TestHelpListsAllDispatchCommands verifies every command from main.go's
// dispatch switch appears in cmd_docs.go.
func TestHelpListsAllDispatchCommands(t *testing.T) {
	mainSrc := readSourceFile(t, "main.go")
	docsSrc := readSourceFile(t, "cmd_docs.go")

	clauses := extractDispatchClauses(mainSrc)
	if len(clauses) == 0 {
		t.Fatal("extractDispatchClauses returned 0 — parser broken")
	}

	// Meta-commands are dispatched but intentionally not in COMMANDS listing
	meta := map[string]bool{
		"-h": true, "--help": true, "help": true,
		"-v": true, "--version": true, "version": true,
		"docs": true, "doc": true, "man": true, "manual": true,
	}

	for _, clause := range clauses {
		primary := clause[0]
		if meta[primary] {
			continue
		}

		// Primary command must appear
		if !strings.Contains(docsSrc, primary) {
			t.Errorf("primary command %q dispatched in main.go but missing from cmd_docs.go", primary)
		}

		// Every alias must appear somewhere (in an "Alias:" line, or as a case string)
		for _, alias := range clause[1:] {
			if meta[alias] {
				continue
			}
			if !strings.Contains(docsSrc, alias) {
				t.Errorf("alias %q (of %q) dispatched in main.go but missing from cmd_docs.go", alias, primary)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 2: FlagSet completeness — every flag.NewFlagSet command is documented
// ---------------------------------------------------------------------------

// TestEveryFlagSetCommandDocumented verifies that every flag.NewFlagSet("cmd",...)
// in cmd_*.go has a corresponding mention in cmd_docs.go.
func TestEveryFlagSetCommandDocumented(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	flagSets := extractAllFlagSets(t)
	if len(flagSets) == 0 {
		t.Fatal("no FlagSets found — parser broken")
	}

	for _, fs := range flagSets {
		if !strings.Contains(docsSrc, fs.command) {
			t.Errorf("flag.NewFlagSet(%q) in %s but %q not found in cmd_docs.go",
				fs.command, fs.file, fs.command)
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 3: Numeric default cross-check (fully automatic)
// ---------------------------------------------------------------------------

// TestDocumentedNumericDefaultsMatchCode auto-discovers every flag with a
// numeric default across all cmd_*.go files, finds matching "(default: N)"
// patterns in the corresponding printDocs*() function in cmd_docs.go, and
// verifies the values match.
//
// Two strategies:
//   - Scoped: flags checked within their command's printDocs*() function body
//   - Global: defaults package constants checked against all of cmd_docs.go
//
// Zero maintenance for scoped checks. Adding a new flag or wrong default
// in a docs function fails the next test run.
func TestDocumentedNumericDefaultsMatchCode(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	allFlags := extractAllIntFlags(t)
	if len(allFlags) == 0 {
		t.Fatal("no Int flags found — parser broken")
	}

	// Extract per-command doc sections from cmd_docs.go.
	// Each printDocs*() function is command-scoped, plus printUsage() has
	// inline sections (DISCOVER COMMAND, LEARN COMMAND, RUN COMMAND).
	cmdSections := extractCommandDocSections(docsSrc)

	// For each flag, check within its command's doc section only.
	checked := 0
	for _, fl := range allFlags {
		section, ok := cmdSections[fl.command]
		if !ok {
			continue // no dedicated docs section for this command
		}

		pattern := fmt.Sprintf(`-{1,2}%s\b[^(]*\(default:\s*(\d+)\)`, regexp.QuoteMeta(fl.name))
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(section, -1)
		if len(matches) == 0 {
			continue // flag not documented with a default in its section
		}
		checked++
		for _, m := range matches {
			docVal, _ := strconv.Atoi(m[1])
			if docVal != fl.defaultVal {
				t.Errorf("%s/%s: docs say (default: %d), code says %d [%s]",
					fl.command, fl.name, docVal, fl.defaultVal, fl.file)
			}
		}
	}

	// Cross-check defaults package constants (used by the run command,
	// which reads from config rather than flag registrations).
	pkgChecks := []struct {
		name        string
		codeDefault int
		docsPattern string
	}{
		{"run/concurrency", defaults.DefaultConfigConcurrency, `Concurrent workers \(default:\s*(\d+)\)`},
		{"run/rate-limit", defaults.DefaultConfigRateLimit, `Requests per second \(default:\s*(\d+)\)`},
		{"run/timeout", defaults.DefaultConfigTimeoutSec, `HTTP timeout \(default:\s*(\d+)\)`},
	}
	runSection := cmdSections["run"]
	for _, check := range pkgChecks {
		t.Run(check.name, func(t *testing.T) {
			src := runSection
			if src == "" {
				src = docsSrc // fallback to global
			}
			re := regexp.MustCompile(check.docsPattern)
			matches := re.FindAllStringSubmatch(src, -1)
			if len(matches) == 0 {
				t.Fatalf("pattern %q not found in run section", check.docsPattern)
			}
			for _, m := range matches {
				docVal, _ := strconv.Atoi(m[1])
				if docVal != check.codeDefault {
					t.Errorf("docs say default=%d, code says default=%d (defaults.go)", docVal, check.codeDefault)
				}
			}
		})
	}

	t.Logf("scoped cross-check: %d documented defaults across %d flag registrations, %d command sections",
		checked, len(allFlags), len(cmdSections))
}

// ---------------------------------------------------------------------------
// Layer 4: String/path default regression guards
// ---------------------------------------------------------------------------

// TestHelpDefaultsNotStale guards against known-incorrect defaults.
// Each entry is a regression test for a previously discovered mismatch.
func TestHelpDefaultsNotStale(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	// Patterns that must NOT appear (known-wrong values)
	forbidden := []struct{ bad, reason string }{
		{"../payloads", "payload dir default must be " + defaults.PayloadDir},
		{`mode: aggressive`, "smart-mode has no 'aggressive' value — valid: quick, standard, full, bypass, stealth"},
	}
	for _, f := range forbidden {
		if strings.Contains(docsSrc, f.bad) {
			t.Errorf("found %q in cmd_docs.go — %s", f.bad, f.reason)
		}
	}

	// Patterns that MUST appear
	required := []struct{ pattern, reason string }{
		{defaults.PayloadDir, "correct PayloadDir default must be documented"},
	}
	for _, r := range required {
		if !strings.Contains(docsSrc, r.pattern) {
			t.Errorf("missing %q in cmd_docs.go — %s", r.pattern, r.reason)
		}
	}
}

// TestSmartModeValuesMatchCode extracts the valid smart-mode values from
// flag help strings in code and verifies cmd_docs.go uses the same set.
func TestSmartModeValuesMatchCode(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")
	allSrc := readAllNonTestGoSources(t)

	// Extract smart-mode values from flag registration help text.
	// Pattern: .String("smart-mode", "default", "...quick, standard, full, bypass, stealth")
	valuesRe := regexp.MustCompile(`\.String\("smart-mode",\s*"[^"]*",\s*"[^"]*:\s*([^"]+)"`)
	match := valuesRe.FindStringSubmatch(allSrc)
	if match == nil {
		t.Skip("no smart-mode flag registration found")
	}
	codeValues := parseCommaSeparated(match[1])
	if len(codeValues) == 0 {
		t.Fatal("parsed 0 smart-mode values from code")
	}

	// Every code value must appear in cmd_docs.go
	for _, val := range codeValues {
		if !strings.Contains(docsSrc, val) {
			t.Errorf("smart-mode value %q exists in code but not in cmd_docs.go", val)
		}
	}

	// cmd_docs.go must not list values that don't exist in code
	codeSet := make(map[string]bool)
	for _, v := range codeValues {
		codeSet[v] = true
	}
	docsSmartRe := regexp.MustCompile(`(?i)smart.mode[^:]*:\s*([^\n"]+)`)
	for _, dm := range docsSmartRe.FindAllStringSubmatch(docsSrc, -1) {
		for _, dv := range parseCommaSeparated(dm[1]) {
			if !codeSet[dv] {
				t.Errorf("smart-mode value %q in cmd_docs.go but not in code", dv)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 5: Docs topics
// ---------------------------------------------------------------------------

// TestDocsTopicsInSync verifies the topic index matches printDetailedDocs handlers.
func TestDocsTopicsInSync(t *testing.T) {
	docsSrc := readSourceFile(t, "cmd_docs.go")

	indexTopics := extractDocsIndexTopics(docsSrc)
	if len(indexTopics) == 0 {
		t.Fatal("extractDocsIndexTopics returned 0 — parser broken")
	}

	switchClauses := extractDocsSwitchClauses(docsSrc)
	if len(switchClauses) == 0 {
		t.Fatal("extractDocsSwitchClauses returned 0 — parser broken")
	}

	// Every index topic must have a handler
	allHandled := make(map[string]bool)
	for _, clause := range switchClauses {
		for _, alias := range clause {
			allHandled[alias] = true
		}
	}
	for _, topic := range indexTopics {
		if !allHandled[topic] {
			t.Errorf("topic %q is in docs index but has no handler in printDetailedDocs", topic)
		}
	}

	// Every handler clause must have at least one topic in the index
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
			t.Errorf("handler clause %v has no topic in docs index", clause)
		}
	}
}

// =============================================================================
// COMMANDS.MD SYNC TESTS
// =============================================================================
//
// Ensures docs/COMMANDS.md stays in sync with CLI code. Same auto-discovery
// approach: parse the markdown and Go sources, cross-reference, flag drift.
//
// Layer 6: Every command in main.go has a section in COMMANDS.md
// Layer 7: Aliases in COMMANDS.md match main.go dispatch
// Layer 8: Numeric flag defaults in COMMANDS.md tables match code
// Layer 9: COMMANDS.md ToC lists every command section

// ---------------------------------------------------------------------------
// Layer 6: Dispatch → COMMANDS.md command sections
// ---------------------------------------------------------------------------

// TestCommandsMdHasEveryCommand verifies every command from main.go's dispatch
// has a ### `command` section in docs/COMMANDS.md.
func TestCommandsMdHasEveryCommand(t *testing.T) {
	mainSrc := readSourceFile(t, "main.go")
	cmdsMd := readRepoFile(t, "docs/COMMANDS.md")

	clauses := extractDispatchClauses(mainSrc)
	if len(clauses) == 0 {
		t.Fatal("extractDispatchClauses returned 0 — parser broken")
	}

	// Meta-commands are not in COMMANDS.md
	meta := map[string]bool{
		"-h": true, "--help": true, "help": true,
		"-v": true, "--version": true, "version": true,
		"docs": true, "doc": true, "man": true, "manual": true,
	}

	// Extract all ### `command` headings from COMMANDS.md
	mdCmds := extractCommandsMdSections(cmdsMd)

	for _, clause := range clauses {
		primary := clause[0]
		if meta[primary] {
			continue
		}
		if _, ok := mdCmds[primary]; !ok {
			t.Errorf("command %q dispatched in main.go but has no ### `%s` section in COMMANDS.md",
				primary, primary)
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 7: COMMANDS.md aliases match main.go dispatch
// ---------------------------------------------------------------------------

// TestCommandsMdAliasesMatchCode verifies aliases documented in COMMANDS.md
// match the case clauses in main.go's dispatch switch.
func TestCommandsMdAliasesMatchCode(t *testing.T) {
	mainSrc := readSourceFile(t, "main.go")
	cmdsMd := readRepoFile(t, "docs/COMMANDS.md")

	// Build map: primary command → set of aliases from main.go
	clauses := extractDispatchClauses(mainSrc)
	codeAliases := make(map[string]map[string]bool)
	for _, clause := range clauses {
		primary := clause[0]
		aliases := make(map[string]bool)
		for _, a := range clause[1:] {
			aliases[a] = true
		}
		codeAliases[primary] = aliases
	}

	// Parse **Aliases:** lines from COMMANDS.md, keyed to the command they follow.
	mdAliases := extractCommandsMdAliases(cmdsMd)

	// Commands that have aliases in code must document them in COMMANDS.md
	meta := map[string]bool{
		"-h": true, "--help": true, "help": true,
		"-v": true, "--version": true, "version": true,
		"docs": true, "doc": true, "man": true, "manual": true,
	}
	for _, clause := range clauses {
		primary := clause[0]
		if meta[primary] || len(clause) < 2 {
			continue
		}
		docAliases := mdAliases[primary]
		for _, alias := range clause[1:] {
			if meta[alias] {
				continue
			}
			if !docAliases[alias] {
				t.Errorf("alias %q of command %q exists in main.go but not documented in COMMANDS.md",
					alias, primary)
			}
		}
	}

	// Aliases documented in COMMANDS.md must exist in code
	for cmd, aliases := range mdAliases {
		codeSet := codeAliases[cmd]
		for alias := range aliases {
			if !codeSet[alias] {
				t.Errorf("COMMANDS.md documents alias %q for %q but main.go dispatch doesn't have it",
					alias, cmd)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Layer 8: COMMANDS.md flag table defaults match code
// ---------------------------------------------------------------------------

// TestCommandsMdFlagDefaultsMatchCode parses flag tables in COMMANDS.md
// and cross-checks numeric defaults against code registrations.
func TestCommandsMdFlagDefaultsMatchCode(t *testing.T) {
	cmdsMd := readRepoFile(t, "docs/COMMANDS.md")
	allFlags := extractAllIntFlags(t)
	if len(allFlags) == 0 {
		t.Fatal("extractAllIntFlags returned 0 — parser broken")
	}

	// Parse COMMANDS.md into per-command sections
	cmdSections := extractCommandsMdSections(cmdsMd)

	// Build code flags lookup: command/flagname → default
	codeLookup := make(map[string]int)
	for _, fl := range allFlags {
		key := fl.command + "/" + fl.name
		codeLookup[key] = fl.defaultVal
	}

	// Parse flag tables from each COMMANDS.md section, match defaults
	checked := 0
	for mdCmd, section := range cmdSections {
		mdFlags := extractMarkdownTableIntDefaults(section)
		for _, mf := range mdFlags {
			codeVal, exists := codeLookup[mdCmd+"/"+mf.name]
			if !exists {
				continue // flag name mismatch or not a registered Int flag
			}
			checked++
			if mf.defaultVal != codeVal {
				t.Errorf("COMMANDS.md %s/%s: docs say default=%d, code says %d",
					mdCmd, mf.name, mf.defaultVal, codeVal)
			}
		}
	}

	t.Logf("COMMANDS.md cross-check: %d flag defaults verified across %d sections",
		checked, len(cmdSections))
}

// ---------------------------------------------------------------------------
// Layer 9: COMMANDS.md ToC → Section sync
// ---------------------------------------------------------------------------

// TestCommandsMdTocMatchesSections verifies the Table of Contents in
// COMMANDS.md lists every command that has a ### section (and vice versa).
func TestCommandsMdTocMatchesSections(t *testing.T) {
	cmdsMd := readRepoFile(t, "docs/COMMANDS.md")

	tocCmds := extractCommandsMdTocEntries(cmdsMd)
	sectionCmds := extractCommandsMdSections(cmdsMd)

	if len(tocCmds) == 0 {
		t.Fatal("no ToC command entries found in COMMANDS.md")
	}
	if len(sectionCmds) == 0 {
		t.Fatal("no command sections found in COMMANDS.md")
	}

	// Every ToC entry should have a section
	for _, cmd := range tocCmds {
		if _, ok := sectionCmds[cmd]; !ok {
			t.Errorf("COMMANDS.md ToC lists %q but no ### `%s` section exists", cmd, cmd)
		}
	}

	// Every section should be in the ToC
	tocSet := make(map[string]bool)
	for _, cmd := range tocCmds {
		tocSet[cmd] = true
	}
	for cmd := range sectionCmds {
		if !tocSet[cmd] {
			t.Errorf("COMMANDS.md has ### `%s` section but it's missing from Table of Contents", cmd)
		}
	}
}

// =============================================================================
// DATA TYPES
// =============================================================================

type flagSetInfo struct {
	file    string
	command string
}

type intFlagInfo struct {
	file       string
	command    string
	name       string
	defaultVal int
}

// =============================================================================
// EXTRACTORS
// =============================================================================

// extractCommandDocSections splits cmd_docs.go into per-command text blocks.
// Sources: printDocs*() function bodies + inline "XXX COMMAND" sections in printUsage().
// Returns map[commandName]docText where commandName matches FlagSet names.
func extractCommandDocSections(docsSrc string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(docsSrc, "\n")

	// 1. Find all top-level func declarations and their line positions.
	type funcPos struct {
		name  string
		start int // line index (0-based)
	}
	var funcs []funcPos
	funcRe := regexp.MustCompile(`^func (\w+)\(`)
	for i, line := range lines {
		if m := funcRe.FindStringSubmatch(line); m != nil {
			funcs = append(funcs, funcPos{name: m[1], start: i})
		}
	}

	// 2. Extract printDocs*() function bodies.
	docsNameRe := regexp.MustCompile(`^printDocs(\w+)$`)
	for i, f := range funcs {
		m := docsNameRe.FindStringSubmatch(f.name)
		if m == nil {
			continue
		}
		end := len(lines)
		if i+1 < len(funcs) {
			end = funcs[i+1].start
		}
		cmd := strings.ToLower(m[1])
		switch cmd {
		case "index":
			continue // topic index, not a command
		case "mutation":
			cmd = "mutate"
		case "templates":
			cmd = "template"
		}
		sections[cmd] = strings.Join(lines[f.start:end], "\n")
	}

	// 3. Extract inline "XXX COMMAND" sections from printUsage().
	// Find printUsage function boundaries.
	var usageStart, usageEnd int
	for i, f := range funcs {
		if f.name == "printUsage" {
			usageStart = f.start
			usageEnd = len(lines)
			if i+1 < len(funcs) {
				usageEnd = funcs[i+1].start
			}
			break
		}
	}

	if usageStart > 0 || usageEnd > 0 {
		sectionHeaderRe := regexp.MustCompile(`SectionStyle\.Render\([^"]*"([^"]+)"\)`)
		type sectionRange struct {
			cmd   string
			start int
		}
		var cmdSections []sectionRange
		for i := usageStart; i < usageEnd; i++ {
			if m := sectionHeaderRe.FindStringSubmatch(lines[i]); m != nil {
				title := m[1]
				if strings.HasSuffix(title, " COMMAND") {
					cmd := strings.ToLower(strings.TrimSuffix(title, " COMMAND"))
					cmdSections = append(cmdSections, sectionRange{cmd: cmd, start: i})
				}
			}
		}
		for i, cs := range cmdSections {
			end := usageEnd
			// Find the next SectionStyle.Render in printUsage after this one
			nextStart := usageEnd
			for j := cs.start + 1; j < usageEnd; j++ {
				if sectionHeaderRe.MatchString(lines[j]) {
					nextStart = j
					break
				}
			}
			if i+1 < len(cmdSections) && cmdSections[i+1].start < nextStart {
				end = cmdSections[i+1].start
			} else {
				end = nextStart
			}
			text := strings.Join(lines[cs.start:end], "\n")
			if existing, ok := sections[cs.cmd]; ok {
				sections[cs.cmd] = existing + "\n" + text
			} else {
				sections[cs.cmd] = text
			}
		}
	}

	return sections
}

// readSourceFile reads a single file relative to the test's working directory.
func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// readAllNonTestGoSources concatenates all non-test .go files in cmd/cli.
func readAllNonTestGoSources(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		sb.Write(data)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// extractDispatchClauses parses main.go's switch and returns each case clause
// as a slice of command names (first = primary, rest = aliases).
func extractDispatchClauses(src string) [][]string {
	var clauses [][]string
	quoted := regexp.MustCompile(`"([^"]+)"`)
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
			var names []string
			for _, m := range quoted.FindAllStringSubmatch(trimmed, -1) {
				names = append(names, m[1])
			}
			if len(names) > 0 {
				clauses = append(clauses, names)
			}
		}
		if strings.HasPrefix(trimmed, "default:") {
			break
		}
	}
	return clauses
}

// extractAllFlagSets finds every flag.NewFlagSet("name", ...) in cmd_*.go files.
func extractAllFlagSets(t *testing.T) []flagSetInfo {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	re := regexp.MustCompile(`flag\.NewFlagSet\("([^"]+)"`)
	var result []flagSetInfo
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cmd_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			result = append(result, flagSetInfo{file: name, command: m[1]})
		}
	}
	return result
}

// extractAllIntFlags finds every .Int("name", N, ...) and .IntVar(&v, "name", N, ...)
// in cmd_*.go files, paired with the FlagSet command name from that file.
func extractAllIntFlags(t *testing.T) []intFlagInfo {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	flagSetRe := regexp.MustCompile(`(\w+)\s*:?=\s*flag\.NewFlagSet\("([^"]+)"`)
	intFlagRe := regexp.MustCompile(`(\w+)\.Int\("([^"]+)",\s*(\d+)`)
	intVarRe := regexp.MustCompile(`(\w+)\.IntVar\(&\w+,\s*"([^"]+)",\s*(\d+)`)

	var result []intFlagInfo
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cmd_") || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(data)

		// Map FlagSet variable names to command names in this file
		fsMap := make(map[string]string)
		for _, m := range flagSetRe.FindAllStringSubmatch(src, -1) {
			fsMap[m[1]] = m[2]
		}

		for _, m := range intFlagRe.FindAllStringSubmatch(src, -1) {
			cmd := fsMap[m[1]]
			if cmd == "" {
				cmd = m[1]
			}
			val, _ := strconv.Atoi(m[3])
			result = append(result, intFlagInfo{file: name, command: cmd, name: m[2], defaultVal: val})
		}

		for _, m := range intVarRe.FindAllStringSubmatch(src, -1) {
			cmd := fsMap[m[1]]
			if cmd == "" {
				cmd = m[1]
			}
			val, _ := strconv.Atoi(m[3])
			result = append(result, intFlagInfo{file: name, command: cmd, name: m[2], defaultVal: val})
		}
	}
	return result
}

// extractDocsIndexTopics returns topic names from printDocsIndex().
func extractDocsIndexTopics(src string) []string {
	var topics []string
	funcStart := strings.Index(src, "func printDocsIndex()")
	if funcStart < 0 {
		return nil
	}
	remaining := src[funcStart:]
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

// extractDocsSwitchClauses returns each case clause from printDetailedDocs.
func extractDocsSwitchClauses(src string) [][]string {
	var clauses [][]string
	funcStart := strings.Index(src, "func printDetailedDocs()")
	if funcStart < 0 {
		return nil
	}
	body := src[funcStart:]
	switchIdx := strings.Index(body, "switch topic {")
	if switchIdx < 0 {
		return nil
	}

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

// parseCommaSeparated splits "quick, standard, full" into ["quick","standard","full"].
func parseCommaSeparated(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		v := strings.TrimSpace(part)
		v = strings.Trim(v, `"'()`)
		if v != "" && !strings.ContainsAny(v, " \t{}[]") {
			result = append(result, v)
		}
	}
	return result
}

// readRepoFile reads a file relative to the repository root (two dirs up from cmd/cli).
func readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	path := filepath.Join("..", "..", relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return string(data)
}

// =============================================================================
// COMMANDS.MD EXTRACTORS
// =============================================================================

// extractCommandsMdSections returns a map of command name → section text
// by splitting COMMANDS.md at ### `command` headings.
func extractCommandsMdSections(md string) map[string]string {
	sections := make(map[string]string)
	lines := strings.Split(md, "\n")
	headerRe := regexp.MustCompile("^### `([\\w-]+)`")

	type sectionPos struct {
		name  string
		start int
	}
	var headers []sectionPos
	for i, line := range lines {
		if m := headerRe.FindStringSubmatch(line); m != nil {
			headers = append(headers, sectionPos{name: m[1], start: i})
		}
	}

	for i, h := range headers {
		end := len(lines)
		if i+1 < len(headers) {
			end = headers[i+1].start
		}
		sections[h.name] = strings.Join(lines[h.start:end], "\n")
	}
	return sections
}

// extractCommandsMdAliases returns map[primaryCommand]set(aliases) by parsing
// **Aliases:** lines and associating them with the preceding ### `command` section.
func extractCommandsMdAliases(md string) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	lines := strings.Split(md, "\n")
	headerRe := regexp.MustCompile("^### `([\\w-]+)`")
	aliasRe := regexp.MustCompile(`\*\*Alias(?:es)?:\*\*\s*(.+)`)

	currentCmd := ""
	for _, line := range lines {
		if m := headerRe.FindStringSubmatch(line); m != nil {
			currentCmd = m[1]
			continue
		}
		if currentCmd != "" {
			if m := aliasRe.FindStringSubmatch(line); m != nil {
				aliases := make(map[string]bool)
				// Parse "alias1, alias2" or "`alias1`, `alias2`"
				for _, part := range strings.Split(m[1], ",") {
					v := strings.TrimSpace(part)
					v = strings.Trim(v, "`\"' ")
					if v != "" {
						aliases[v] = true
					}
				}
				result[currentCmd] = aliases
			}
		}
	}
	return result
}

// extractCommandsMdTocEntries returns command names from the Table of Contents.
// Matches lines like: "  - [auto](#auto)" or "  - [`auto`](#auto)"
func extractCommandsMdTocEntries(md string) []string {
	var cmds []string
	tocRe := regexp.MustCompile(`^\s+-\s+\[` + "`?" + `([\w-]+)` + "`?" + `\]\(#[\w-]+\)`)
	inToc := false
	for _, line := range strings.Split(md, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "## Table of Contents" {
			inToc = true
			continue
		}
		if inToc && strings.HasPrefix(trimmed, "## ") {
			break // end of ToC
		}
		if inToc {
			if m := tocRe.FindStringSubmatch(line); m != nil {
				cmds = append(cmds, m[1])
			}
		}
	}
	return cmds
}

// markdownTableFlagDefault holds a flag name and its numeric default from a markdown table.
type markdownTableFlagDefault struct {
	name       string
	defaultVal int
}

// extractMarkdownTableIntDefaults parses markdown tables within a section
// and extracts flag names with numeric defaults.
// Handles table formats:
//
//	| `-flag` | int | 50 | description |
//	| `-flag` | `-f` | int | 50 | description |
//	| `-flag` | type | `50` | description |
func extractMarkdownTableIntDefaults(section string) []markdownTableFlagDefault {
	var result []markdownTableFlagDefault

	// Match table rows that have a flag name and a numeric value in the default column
	flagCellRe := regexp.MustCompile("`-([\\w-]+)`")
	numericRe := regexp.MustCompile("^`?(\\d+)`?$")

	for _, line := range strings.Split(section, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}

		// Find the first cell with a flag name
		var flagName string
		for _, cell := range cells[1:] {
			trimmed := strings.TrimSpace(cell)
			if m := flagCellRe.FindStringSubmatch(trimmed); m != nil {
				flagName = m[1]
				break
			}
		}
		if flagName == "" {
			continue
		}

		// Find a cell that looks like a type (int, string, bool, etc.)
		// and then the next cell is the default
		for i := 1; i < len(cells)-1; i++ {
			trimmed := strings.TrimSpace(cells[i])
			if trimmed == "int" || trimmed == "duration" {
				if i+1 < len(cells) {
					defCell := strings.TrimSpace(cells[i+1])
					if m := numericRe.FindStringSubmatch(defCell); m != nil {
						val, _ := strconv.Atoi(m[1])
						result = append(result, markdownTableFlagDefault{name: flagName, defaultVal: val})
					}
				}
				break
			}
		}
	}
	return result
}

// =============================================================================
// SELF-TEST: Verify extractors find reasonable data
// =============================================================================

// TestExtractorsNotBroken ensures the parsers find expected amounts of data.
// If these thresholds break, the extractor logic needs updating.
func TestExtractorsNotBroken(t *testing.T) {
	mainSrc := readSourceFile(t, "main.go")

	clauses := extractDispatchClauses(mainSrc)
	if len(clauses) < 25 {
		t.Errorf("extractDispatchClauses: got %d, want >=25", len(clauses))
	}

	flagSets := extractAllFlagSets(t)
	if len(flagSets) < 20 {
		t.Errorf("extractAllFlagSets: got %d, want >=20", len(flagSets))
	}

	intFlags := extractAllIntFlags(t)
	if len(intFlags) < 40 {
		t.Errorf("extractAllIntFlags: got %d, want >=40", len(intFlags))
	}

	cmds := make(map[string]bool)
	for _, fs := range flagSets {
		cmds[fs.command] = true
	}
	sortedCmds := make([]string, 0, len(cmds))
	for c := range cmds {
		sortedCmds = append(sortedCmds, c)
	}
	sort.Strings(sortedCmds)
	t.Logf("dispatch clauses: %d, flagSets: %d (%v), intFlags: %d",
		len(clauses), len(flagSets), sortedCmds, len(intFlags))

	docsSrc := readSourceFile(t, "cmd_docs.go")
	cmdSections := extractCommandDocSections(docsSrc)
	if len(cmdSections) < 10 {
		t.Errorf("extractCommandDocSections: got %d, want >=10", len(cmdSections))
	}
	sectionNames := make([]string, 0, len(cmdSections))
	for name := range cmdSections {
		sectionNames = append(sectionNames, name)
	}
	sort.Strings(sectionNames)
	t.Logf("commandDocSections: %d (%v)", len(cmdSections), sectionNames)

	// COMMANDS.md extractors
	cmdsMd := readRepoFile(t, "docs/COMMANDS.md")
	mdSections := extractCommandsMdSections(cmdsMd)
	if len(mdSections) < 25 {
		t.Errorf("extractCommandsMdSections: got %d, want >=25", len(mdSections))
	}
	mdAliases := extractCommandsMdAliases(cmdsMd)
	if len(mdAliases) < 5 {
		t.Errorf("extractCommandsMdAliases: got %d, want >=5", len(mdAliases))
	}
	tocCmds := extractCommandsMdTocEntries(cmdsMd)
	if len(tocCmds) < 25 {
		t.Errorf("extractCommandsMdTocEntries: got %d, want >=25", len(tocCmds))
	}
	mdSectionNames := make([]string, 0, len(mdSections))
	for name := range mdSections {
		mdSectionNames = append(mdSectionNames, name)
	}
	sort.Strings(mdSectionNames)
	t.Logf("COMMANDS.md sections: %d (%v), aliases: %d, toc: %d",
		len(mdSections), mdSectionNames, len(mdAliases), len(tocCmds))
}
