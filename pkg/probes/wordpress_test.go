package probes

import (
	"testing"
)

func TestDetectWordPress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantDetect bool
		wantPlugin string
		wantTheme  string
	}{
		{
			name:       "wp-content in HTML",
			body:       `<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">`,
			wantDetect: true,
			wantTheme:  "flavor",
		},
		{
			name:       "wp-includes in HTML",
			body:       `<script src="/wp-includes/js/jquery.js"></script>`,
			wantDetect: true,
		},
		{
			name:       "xmlrpc endpoint",
			body:       `<link rel="pingback" href="https://example.com/xmlrpc.php">WordPress site`,
			wantDetect: true,
		},
		{
			name:       "not WordPress plain HTML",
			body:       `<html><body><h1>Hello World</h1></body></html>`,
			wantDetect: false,
		},
		{
			name:       "empty body",
			body:       "",
			wantDetect: false,
		},
		{
			name:       "plugin extraction",
			body:       `<link href="/wp-content/plugins/akismet/style.css"><link href="/wp-content/plugins/jetpack/main.js">`,
			wantDetect: true,
			wantPlugin: "akismet",
		},
		{
			name:       "meta generator tag",
			body:       `<meta name="generator" content="WordPress 6.4.2">`,
			wantDetect: true,
		},
		{
			name:       "wp-json API",
			body:       `<link rel="alternate" type="application/json" href="https://example.com/wp-json/wp/v2/posts">`,
			wantDetect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := DetectWordPress(tt.body)
			if result.Detected != tt.wantDetect {
				t.Errorf("DetectWordPress() detected = %v, want %v", result.Detected, tt.wantDetect)
			}
			if tt.wantPlugin != "" {
				found := false
				for _, p := range result.Plugins {
					if p == tt.wantPlugin {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected plugin %q in %v", tt.wantPlugin, result.Plugins)
				}
			}
			if tt.wantTheme != "" {
				found := false
				for _, th := range result.Themes {
					if th == tt.wantTheme {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected theme %q in %v", tt.wantTheme, result.Themes)
				}
			}
		})
	}
}
