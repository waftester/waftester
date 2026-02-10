package main

import (
	"strings"

	"github.com/waftester/waftester/pkg/ratelimit"
)

// handleAdaptiveRate processes adaptive rate limiting based on response.
// On HTTP 429, it triggers the limiter's error backoff and escalates.
// On successful non-error outcomes, it signals recovery to the limiter.
func handleAdaptiveRate(statusCode int, outcome string, limiter *ratelimit.Limiter, escalate func(string)) {
	if limiter == nil {
		return
	}
	if statusCode == 429 {
		limiter.OnError()
		escalate("HTTP 429 Too Many Requests")
	} else if outcome != "Error" {
		limiter.OnSuccess()
	}
}

// inferHTTPMethod tries to determine the HTTP method from path and source.
// It inspects path segments for REST-like keywords (create, update, delete)
// and falls back to examining the source string for explicit method hints.
func inferHTTPMethod(path, source string) string {
	pathLower := strings.ToLower(path)

	// POST indicators
	if strings.Contains(pathLower, "create") ||
		strings.Contains(pathLower, "add") ||
		strings.Contains(pathLower, "new") ||
		strings.Contains(pathLower, "upload") ||
		strings.Contains(pathLower, "submit") ||
		strings.Contains(pathLower, "login") ||
		strings.Contains(pathLower, "register") ||
		strings.Contains(pathLower, "signup") {
		return "POST"
	}

	// PUT/PATCH indicators
	if strings.Contains(pathLower, "update") ||
		strings.Contains(pathLower, "edit") ||
		strings.Contains(pathLower, "modify") ||
		strings.Contains(pathLower, "save") {
		return "PUT"
	}

	// DELETE indicators
	if strings.Contains(pathLower, "delete") ||
		strings.Contains(pathLower, "remove") ||
		strings.Contains(pathLower, "destroy") {
		return "DELETE"
	}

	// Check source for method hints
	sourceLower := strings.ToLower(source)
	if strings.Contains(sourceLower, "post") {
		return "POST"
	}
	if strings.Contains(sourceLower, "put") {
		return "PUT"
	}
	if strings.Contains(sourceLower, "delete") {
		return "DELETE"
	}
	if strings.Contains(sourceLower, "patch") {
		return "PATCH"
	}

	return "GET"
}

// truncateString truncates a string to max length with ellipsis.
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// severityToScore converts severity string to CVSS-like score string.
func severityToScore(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low":
		return "3.0"
	default:
		return "1.0"
	}
}
