// Package wordlists provides embedded framework-specific route wordlists
// for active endpoint discovery. Routes are organized by web framework
// and auto-selected based on detected technologies.
package wordlists

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed *.txt
var embedded embed.FS

// Frameworks lists all available framework wordlists.
var Frameworks = []string{
	"rails", "spring", "express", "django", "laravel",
	"flask", "aspnet", "fastapi", "nextjs", "wordpress", "generic-api",
}

// Load returns routes for a single framework.
func Load(framework string) ([]string, error) {
	data, err := embedded.ReadFile(framework + ".txt")
	if err != nil {
		return nil, fmt.Errorf("unknown framework %q: %w", framework, err)
	}
	return parseLines(string(data)), nil
}

// LoadMultiple loads and merges routes from multiple frameworks, deduplicated.
func LoadMultiple(frameworks []string) ([]string, error) {
	seen := make(map[string]bool)
	var routes []string
	for _, fw := range frameworks {
		fwRoutes, err := Load(fw)
		if err != nil {
			return nil, err
		}
		for _, r := range fwRoutes {
			if !seen[r] {
				seen[r] = true
				routes = append(routes, r)
			}
		}
	}
	return routes, nil
}

// LoadAll loads and merges routes from all frameworks, deduplicated.
func LoadAll() []string {
	routes, _ := LoadMultiple(Frameworks)
	return routes
}

// DetectFrameworks maps technology fingerprint strings to framework wordlist names.
// Takes output from ActiveDiscoverer.fingerprintTechnology() and returns matching frameworks.
func DetectFrameworks(technologies []string) []string {
	mapping := map[string]string{
		"ruby":        "rails",
		"rails":       "rails",
		"sinatra":     "rails",
		"java":        "spring",
		"spring":      "spring",
		"spring boot": "spring",
		"tomcat":      "spring",
		"node":        "express",
		"express":     "express",
		"koa":         "express",
		"python":      "django",
		"django":      "django",
		"flask":       "flask",
		"fastapi":     "fastapi",
		"uvicorn":     "fastapi",
		"starlette":   "fastapi",
		"php":         "laravel",
		"laravel":     "laravel",
		"asp.net":     "aspnet",
		"aspnet":      "aspnet",
		"iis":         "aspnet",
		"next.js":     "nextjs",
		"nextjs":      "nextjs",
		"vercel":      "nextjs",
		"wordpress":   "wordpress",
		"wp-":         "wordpress",
	}

	seen := make(map[string]bool)
	var frameworks []string
	for _, tech := range technologies {
		lower := strings.ToLower(tech)
		for keyword, fw := range mapping {
			if strings.Contains(lower, keyword) && !seen[fw] {
				seen[fw] = true
				frameworks = append(frameworks, fw)
			}
		}
	}

	// Always include generic-api as fallback
	if !seen["generic-api"] {
		frameworks = append(frameworks, "generic-api")
	}
	return frameworks
}

func parseLines(content string) []string {
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
