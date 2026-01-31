// pkg/input/targets.go
package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// TargetSource consolidates all target input methods
type TargetSource struct {
	URLs     []string // From -u flags (repeated or comma-separated via StringSliceFlag)
	ListFile string   // From -l flag
	Stdin    bool     // Pipe input detection
}

// GetTargets returns deduplicated, normalized target list
func (ts *TargetSource) GetTargets() ([]string, error) {
	var targets []string
	seen := make(map[string]bool)

	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || strings.HasPrefix(t, "#") {
			return
		}
		// Normalize: add https:// if no scheme
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "https://" + t
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}

	// 1. From URLs slice
	for _, u := range ts.URLs {
		add(u)
	}

	// 2. From file
	if ts.ListFile != "" {
		lines, err := readLines(ts.ListFile)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			add(line)
		}
	}

	// 3. From stdin (if enabled and stdin is a pipe)
	if ts.Stdin {
		lines, err := readStdin()
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			add(line)
		}
	}

	return targets, nil
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readStdin() ([]string, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		// Not a pipe, return empty
		return nil, nil
	}

	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// GetSingleTarget returns the first target or an error if none provided
// Use this for commands that don't yet support multi-target
func (ts *TargetSource) GetSingleTarget() (string, error) {
	targets, err := ts.GetTargets()
	if err != nil {
		return "", err
	}
	if len(targets) == 0 {
		return "", fmt.Errorf("no targets specified")
	}
	if len(targets) > 1 {
		fmt.Fprintf(os.Stderr, "[WARN] Multiple targets provided, using first: %s\n", targets[0])
	}
	return targets[0], nil
}
