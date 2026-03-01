// Package urlutil provides shared URL manipulation helpers.
package urlutil

import "strings"

// IsHTTPURL returns true if s starts with "http://" or "https://".
func IsHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// StripScheme removes the "https://" or "http://" prefix from a URL string.
// Returns the input unchanged if no scheme prefix is present.
func StripScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	return s
}

// JoinPath joins a base URL with a path, ensuring exactly one slash between them.
// It trims trailing slashes from base and ensures path starts with a slash.
func JoinPath(base, path string) string {
	base = strings.TrimSuffix(base, "/")
	if path != "" && path[0] != '/' {
		path = "/" + path
	}
	return base + path
}
