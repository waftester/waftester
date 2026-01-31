package logcorrelation

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ModSecParser parses ModSecurity audit logs
type ModSecParser struct {
	logFile string
	file    *os.File
	mu      sync.Mutex
	cache   map[string][]LogEntry
}

// NewModSecParser creates a new ModSecurity log parser
func NewModSecParser(logFile string) (*ModSecParser, error) {
	f, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}

	return &ModSecParser{
		logFile: logFile,
		file:    f,
		cache:   make(map[string][]LogEntry),
	}, nil
}

// FindByMarker finds log entries with the given marker header
func (p *ModSecParser) FindByMarker(marker string) ([]LogEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check cache
	if entries, ok := p.cache[marker]; ok {
		return entries, nil
	}

	// Seek to beginning
	if _, err := p.file.Seek(0, 0); err != nil {
		return nil, err
	}

	var entries []LogEntry
	var currentContent strings.Builder
	var allRules []uint
	var allMessages []string
	var severity string
	var ruleFile string
	inMatchingEntry := false

	scanner := bufio.NewScanner(p.file)
	// Increase buffer size for large log entries
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for marker in line
		if strings.Contains(line, marker) && !inMatchingEntry {
			inMatchingEntry = true
			currentContent.Reset()
			allRules = []uint{}
			allMessages = []string{}
			severity = ""
			ruleFile = ""
		}

		if inMatchingEntry {
			currentContent.WriteString(line)
			currentContent.WriteString("\n")

			// Extract rule IDs
			ruleIDs := p.extractRuleIDs(line)
			for _, id := range ruleIDs {
				// Avoid duplicates
				found := false
				for _, existing := range allRules {
					if existing == id {
						found = true
						break
					}
				}
				if !found {
					allRules = append(allRules, id)
				}
			}

			// Extract messages
			msgs := msgRegex.FindAllStringSubmatch(line, -1)
			for _, match := range msgs {
				if len(match) > 1 {
					allMessages = append(allMessages, match[1])
				}
			}

			// Extract severity
			sevMatches := severityRegex.FindStringSubmatch(line)
			if len(sevMatches) > 1 && severity == "" {
				severity = sevMatches[1]
			}

			// Extract rule file
			fileMatches := fileRegex.FindStringSubmatch(line)
			if len(fileMatches) > 1 && ruleFile == "" {
				ruleFile = fileMatches[1]
			}
		}

		// End of entry marker (ModSecurity uses --XXXXX-Z--)
		if strings.HasPrefix(line, "--") && strings.HasSuffix(line, "-Z--") {
			if inMatchingEntry {
				entry := LogEntry{
					Marker:         marker,
					TriggeredRules: allRules,
					Messages:       allMessages,
					Severity:       severity,
					RuleFile:       ruleFile,
					RawContent:     currentContent.String(),
				}
				entries = append(entries, entry)
				inMatchingEntry = false
				currentContent.Reset()
			}
		}
	}

	// Handle case where file doesn't end with -Z-- marker
	if inMatchingEntry && len(allRules) > 0 {
		entry := LogEntry{
			Marker:         marker,
			TriggeredRules: allRules,
			Messages:       allMessages,
			Severity:       severity,
			RuleFile:       ruleFile,
			RawContent:     currentContent.String(),
		}
		entries = append(entries, entry)
	}

	// Cache result
	p.cache[marker] = entries

	return entries, scanner.Err()
}

// extractRuleIDs finds all rule IDs in a log line
func (p *ModSecParser) extractRuleIDs(line string) []uint {
	var ids []uint
	matches := ruleIDRegex.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			if id, err := strconv.ParseUint(match[1], 10, 32); err == nil {
				ids = append(ids, uint(id))
			}
		}
	}
	return ids
}

// FindByTimeRange finds entries in a time window
func (p *ModSecParser) FindByTimeRange(start, end time.Time) ([]LogEntry, error) {
	// TODO: Implement time-based search
	return nil, nil
}

// Tail watches for new entries
func (p *ModSecParser) Tail() <-chan LogEntry {
	ch := make(chan LogEntry)
	// TODO: Implement tail -f functionality
	close(ch)
	return ch
}

// Close releases resources
func (p *ModSecParser) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

// ClearCache clears the entry cache
func (p *ModSecParser) ClearCache() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache = make(map[string][]LogEntry)
}
