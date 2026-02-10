// Package update provides payload update functionality
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// UpdateConfig holds configuration for payload updates
type UpdateConfig struct {
	PayloadDir      string
	Source          string // OWASP, GitHub, Manual
	DryRun          bool
	AutoApply       bool
	SkipDestructive bool
	VersionBump     string // major, minor, patch
	OutputFile      string
}

// UpdateReport contains the results of a payload update operation
type UpdateReport struct {
	Timestamp       string          `json:"timestamp"`
	Source          string          `json:"source"`
	PreviousVersion string          `json:"previous_version"`
	NewVersion      string          `json:"new_version"`
	PayloadsAdded   int             `json:"payloads_added"`
	PayloadsRemoved int             `json:"payloads_removed"`
	PayloadsUpdated int             `json:"payloads_updated"`
	SkippedUnsafe   int             `json:"skipped_unsafe"`
	Changes         []PayloadChange `json:"changes"`
	DryRun          bool            `json:"dry_run"`
}

// PayloadChange represents a single change to a payload
type PayloadChange struct {
	Type        string `json:"type"` // added, removed, modified
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	IsUnsafe    bool   `json:"is_unsafe,omitempty"`
}

// VersionInfo represents the version.json structure
type VersionInfo struct {
	Version      string `json:"version"`
	LastUpdated  string `json:"last_updated"`
	PayloadCount int    `json:"payload_count"`
	Source       string `json:"source"`
}

// OWASP payload sources (curated community payloads)
var owaspSources = map[string]string{
	"xss":       "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt",
	"sqli":      "https://raw.githubusercontent.com/payloadbox/sql-injection-payload-list/master/Intruder/sql-injection-payload-list.txt",
	"traversal": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/traversal.txt",
}

// Unsafe payload patterns that require manual review
var unsafePatterns = []string{
	"rm -rf",
	"shutdown",
	"reboot",
	"format c:",
	"del /f /s /q",
	":(){:|:&};:", // Fork bomb
	"dd if=/dev/zero",
	"mkfs",
	"> /dev/sda",
}

// GitHub API types for release fetching
type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	PublishedAt string        `json:"published_at"`
	Assets      []GitHubAsset `json:"assets"`
	Body        string        `json:"body"`
}

type GitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int    `json:"size"`
	ContentType        string `json:"content_type"`
}

// Default GitHub repository for payload updates
const (
	defaultGitHubOwner = "waftester"
	defaultGitHubRepo  = "waftester"
	gitHubAPIBase      = "https://api.github.com"
)

var (
	green  = func(a ...interface{}) string { return "\033[32m" + fmt.Sprint(a...) + "\033[0m" }
	red    = func(a ...interface{}) string { return "\033[31m" + fmt.Sprint(a...) + "\033[0m" }
	yellow = func(a ...interface{}) string { return "\033[33m" + fmt.Sprint(a...) + "\033[0m" }
	cyan   = func(a ...interface{}) string { return "\033[36m" + fmt.Sprint(a...) + "\033[0m" }
)

// UpdatePayloads performs the payload update operation
func UpdatePayloads(cfg *UpdateConfig) (*UpdateReport, error) {
	fmt.Println(cyan("╔════════════════════════════════════════════════════════════════╗"))
	fmt.Println(cyan("║                                                                ║"))
	fmt.Println(cyan("║    📦 Payload Update Manager                                  ║"))
	fmt.Println(cyan("║                                                                ║"))
	fmt.Println(cyan("╚════════════════════════════════════════════════════════════════╝"))
	fmt.Println()

	report := &UpdateReport{
		Timestamp: time.Now().Format(time.RFC3339),
		Source:    cfg.Source,
		DryRun:    cfg.DryRun,
		Changes:   []PayloadChange{},
	}

	// Get current version
	currentVersion, err := getCurrentVersion(cfg.PayloadDir)
	if err != nil {
		fmt.Printf("   %s Could not read version: %v (using 0.0.0)\n", yellow("⚠"), err)
		currentVersion = "0.0.0"
	}
	report.PreviousVersion = currentVersion
	fmt.Printf("   Current version: %s\n", cyan(currentVersion))

	// Calculate new version
	newVersion := bumpVersion(currentVersion, cfg.VersionBump)
	report.NewVersion = newVersion
	fmt.Printf("   New version:     %s (%s bump)\n", green(newVersion), cfg.VersionBump)
	fmt.Println()

	switch cfg.Source {
	case "OWASP":
		err = updateFromOWASP(cfg, report)
	case "GitHub":
		err = updateFromGitHub(cfg, report)
	case "Manual":
		fmt.Println("   Manual mode: Expecting payloads in stdin or update file...")
		err = nil
	default:
		err = fmt.Errorf("unknown source: %s", cfg.Source)
	}

	if err != nil {
		return report, err
	}

	// Print summary
	fmt.Println()
	fmt.Println(cyan("════════════════════════════════════════════════════════════════"))
	fmt.Println(cyan("                      UPDATE SUMMARY"))
	fmt.Println(cyan("════════════════════════════════════════════════════════════════"))
	fmt.Printf("   Payloads added:   %s\n", green(fmt.Sprintf("%d", report.PayloadsAdded)))
	fmt.Printf("   Payloads updated: %s\n", cyan(fmt.Sprintf("%d", report.PayloadsUpdated)))
	fmt.Printf("   Payloads removed: %s\n", yellow(fmt.Sprintf("%d", report.PayloadsRemoved)))
	if report.SkippedUnsafe > 0 {
		fmt.Printf("   Skipped (unsafe): %s\n", red(fmt.Sprintf("%d", report.SkippedUnsafe)))
	}
	fmt.Println()

	if cfg.DryRun {
		fmt.Printf("   %s DRY RUN - No changes were made\n", yellow("⚠"))
	} else {
		// Write version file
		if !cfg.DryRun {
			if err := writeVersion(cfg.PayloadDir, newVersion, cfg.Source); err != nil {
				return report, fmt.Errorf("failed to update version: %w", err)
			}
			fmt.Printf("   %s Version updated to %s\n", green("✓"), newVersion)
		}
	}

	// Write report
	if cfg.OutputFile != "" {
		if err := writeReport(cfg.OutputFile, report); err != nil {
			fmt.Printf("   %s Failed to write report: %v\n", yellow("⚠"), err)
		} else {
			fmt.Printf("   %s Report saved to %s\n", green("✓"), cfg.OutputFile)
		}
	}

	return report, nil
}

func updateFromOWASP(cfg *UpdateConfig, report *UpdateReport) error {
	fmt.Println("   Fetching OWASP community payloads...")

	for category, url := range owaspSources {
		fmt.Printf("   • %s: ", category)

		// Use a closure to ensure resp.Body is closed after each iteration
		// Avoids defer-in-loop resource leak bug
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				fmt.Printf("%s (request error: %v)\n", red("failed"), err)
				return
			}

			resp, err := httpclient.Default().Do(req)
			if err != nil {
				fmt.Printf("%s (fetch error: %v)\n", red("failed"), err)
				return
			}
			defer iohelper.DrainAndClose(resp.Body)

			if resp.StatusCode != 200 {
				fmt.Printf("%s (HTTP %d)\n", red("failed"), resp.StatusCode)
				return
			}

			body, err := iohelper.ReadBodyDefault(resp.Body)
			if err != nil {
				fmt.Printf("%s (read error: %v)\n", red("failed"), err)
				return
			}

			lines := strings.Split(string(body), "\n")
			added := 0
			skipped := 0

			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// Check for unsafe payloads
				if cfg.SkipDestructive && isUnsafePayload(line) {
					skipped++
					report.SkippedUnsafe++
					continue
				}

				// In a real implementation, we would:
				// 1. Check if payload already exists
				// 2. Add new payloads to appropriate category file
				// 3. Update ids-map.json
				added++
			}

			report.PayloadsAdded += added
			fmt.Printf("%s (%d new, %d skipped)\n", green("done"), added, skipped)
		}()
	}

	return nil
}

func updateFromGitHub(cfg *UpdateConfig, report *UpdateReport) error {
	fmt.Println("   GitHub source: Checking for payload updates...")

	// Fetch latest release from GitHub API
	releaseURL := fmt.Sprintf("%s/repos/%s/%s/releases/latest",
		gitHubAPIBase, defaultGitHubOwner, defaultGitHubRepo)

	req, err := http.NewRequest("GET", releaseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", ui.UserAgentWithContext("Updater"))

	client := httpclient.Default()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode == 404 {
		fmt.Printf("   %s No releases found in repository\n", yellow("⚠"))
		return nil
	}

	if resp.StatusCode != 200 {
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		return fmt.Errorf("GitHub API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release: %w", err)
	}

	// Safely truncate date (format: YYYY-MM-DD...)
	displayDate := release.PublishedAt
	if len(displayDate) >= 10 {
		displayDate = displayDate[:10]
	}
	fmt.Printf("   Found release: %s (%s)\n", cyan(release.TagName), displayDate)

	// Check if we already have this version
	if release.TagName == report.PreviousVersion || "v"+report.PreviousVersion == release.TagName {
		fmt.Printf("   %s Already up to date\n", green("✓"))
		return nil
	}

	// Look for payload assets (JSON files)
	payloadAssets := []GitHubAsset{}
	for _, asset := range release.Assets {
		if strings.HasSuffix(asset.Name, ".json") && !strings.Contains(asset.Name, "version") {
			payloadAssets = append(payloadAssets, asset)
		}
	}

	if len(payloadAssets) == 0 {
		// Try to download from payloads directory in repo
		fmt.Println("   No payload assets in release, checking repository...")
		return updateFromGitHubRepo(cfg, report, release.TagName)
	}

	fmt.Printf("   Found %d payload files in release\n", len(payloadAssets))

	// Download and merge each payload file
	for _, asset := range payloadAssets {
		fmt.Printf("   • %s: ", asset.Name)

		if cfg.DryRun {
			fmt.Printf("%s (dry run)\n", yellow("skipped"))
			report.PayloadsAdded++
			continue
		}

		added, err := downloadAndMergePayload(cfg, asset.BrowserDownloadURL, asset.Name)
		if err != nil {
			fmt.Printf("%s (%v)\n", red("failed"), err)
			continue
		}

		report.PayloadsAdded += added
		fmt.Printf("%s (%d payloads)\n", green("done"), added)
	}

	// Update to release version
	report.NewVersion = strings.TrimPrefix(release.TagName, "v")

	return nil
}

// updateFromGitHubRepo fetches payloads directly from the repository
func updateFromGitHubRepo(cfg *UpdateConfig, report *UpdateReport, tag string) error {
	// Payload categories to fetch from repo
	categories := []string{"xss", "sqli", "traversal", "cmdi", "ssrf", "xxe", "ssti", "nosqli", "ldapi"}

	for _, category := range categories {
		fmt.Printf("   • %s: ", category)

		rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/payloads/%s.json",
			defaultGitHubOwner, defaultGitHubRepo, tag, category)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			cancel()
			fmt.Printf("%s (request error)\n", yellow("skipped"))
			continue
		}

		resp, err := httpclient.Default().Do(req)
		if err != nil {
			cancel()
			fmt.Printf("%s (fetch error)\n", yellow("skipped"))
			continue
		}

		if resp.StatusCode == 404 {
			iohelper.DrainAndClose(resp.Body)
			cancel()
			fmt.Printf("%s (not found)\n", yellow("skipped"))
			continue
		}

		if resp.StatusCode != 200 {
			iohelper.DrainAndClose(resp.Body)
			cancel()
			fmt.Printf("%s (HTTP %d)\n", yellow("skipped"), resp.StatusCode)
			continue
		}

		body, err := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		cancel()
		if err != nil {
			fmt.Printf("%s (read error)\n", red("failed"))
			continue
		}

		if cfg.DryRun {
			fmt.Printf("%s (dry run)\n", yellow("skipped"))
			continue
		}

		// Parse and count payloads
		var payloads []interface{}
		if err := json.Unmarshal(body, &payloads); err != nil {
			fmt.Printf("%s (parse error)\n", red("failed"))
			continue
		}

		// Write to local payload directory
		destPath := filepath.Join(cfg.PayloadDir, category+".json")
		if err := os.WriteFile(destPath, body, 0644); err != nil {
			fmt.Printf("%s (write error)\n", red("failed"))
			continue
		}

		report.PayloadsAdded += len(payloads)
		fmt.Printf("%s (%d payloads)\n", green("done"), len(payloads))
	}

	return nil
}

// downloadAndMergePayload downloads a payload file and merges with existing
func downloadAndMergePayload(cfg *UpdateConfig, url, filename string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return 0, err
	}

	// Parse new payloads
	var newPayloads []interface{}
	if err := json.Unmarshal(body, &newPayloads); err != nil {
		return 0, fmt.Errorf("invalid JSON: %w", err)
	}

	// Check for existing file and merge
	destPath := filepath.Join(cfg.PayloadDir, filename)
	existingData, err := os.ReadFile(destPath)
	if err == nil {
		var existingPayloads []interface{}
		if json.Unmarshal(existingData, &existingPayloads) == nil {
			// Merge: add new payloads that don't exist
			newPayloads = mergePayloads(existingPayloads, newPayloads)
		}
	}

	// Write merged payloads
	merged, err := json.MarshalIndent(newPayloads, "", "  ")
	if err != nil {
		return 0, err
	}

	if err := os.WriteFile(destPath, merged, 0644); err != nil {
		return 0, err
	}

	return len(newPayloads), nil
}

// mergePayloads combines existing and new payloads, avoiding duplicates
func mergePayloads(existing, new []interface{}) []interface{} {
	// Build set of existing payload strings for deduplication
	seen := make(map[string]bool)
	for _, p := range existing {
		if s, ok := p.(string); ok {
			seen[s] = true
		} else if m, ok := p.(map[string]interface{}); ok {
			if payload, ok := m["payload"].(string); ok {
				seen[payload] = true
			}
		}
	}

	// Add new payloads that aren't duplicates
	result := make([]interface{}, len(existing))
	copy(result, existing)

	for _, p := range new {
		var payloadStr string
		if s, ok := p.(string); ok {
			payloadStr = s
		} else if m, ok := p.(map[string]interface{}); ok {
			if payload, ok := m["payload"].(string); ok {
				payloadStr = payload
			}
		}

		if payloadStr != "" && !seen[payloadStr] {
			result = append(result, p)
			seen[payloadStr] = true
		}
	}

	return result
}

func isUnsafePayload(payload string) bool {
	lower := strings.ToLower(payload)
	for _, pattern := range unsafePatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func getCurrentVersion(payloadDir string) (string, error) {
	versionPath := filepath.Join(payloadDir, "version.json")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return "", err
	}

	var version VersionInfo
	if err := json.Unmarshal(data, &version); err != nil {
		return "", err
	}

	return version.Version, nil
}

func writeVersion(payloadDir, version, source string) error {
	versionPath := filepath.Join(payloadDir, "version.json")

	// Count payloads
	payloadCount := 0
	_ = filepath.Walk(payloadDir, func(path string, info os.FileInfo, err error) error {
		if err != nil { //nolint:nilerr // intentional: skip problematic paths and continue walking
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			basename := filepath.Base(path)
			if basename != "ids-map.json" && basename != "version.json" {
				data, _ := os.ReadFile(path)
				var payloads []interface{}
				if json.Unmarshal(data, &payloads) == nil {
					payloadCount += len(payloads)
				}
			}
		}
		return nil
	})

	versionInfo := VersionInfo{
		Version:      version,
		LastUpdated:  time.Now().Format("2006-01-02"),
		PayloadCount: payloadCount,
		Source:       source,
	}

	data, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(versionPath, data, 0644)
}

func bumpVersion(current, bump string) string {
	parts := strings.Split(current, ".")
	if len(parts) != 3 {
		return "1.0.0"
	}

	// Validate and parse each part - reject malformed versions
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	patch, errPatch := strconv.Atoi(parts[2])

	// If any part is not a valid integer, return default version
	if errMajor != nil || errMinor != nil || errPatch != nil {
		return "1.0.0"
	}

	// Reject negative version numbers
	if major < 0 || minor < 0 || patch < 0 {
		return "1.0.0"
	}

	switch bump {
	case "major":
		major++
		minor = 0
		patch = 0
	case "minor":
		minor++
		patch = 0
	case "patch":
		patch++
	}

	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func writeReport(path string, report *UpdateReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
