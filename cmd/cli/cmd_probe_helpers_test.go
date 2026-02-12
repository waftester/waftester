package main

import (
	"testing"
	"time"

	"github.com/waftester/waftester/pkg/probes"
)

func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name     string
		tech     *probes.TechResult
		wantLen  int
		contains string
	}{
		{
			name:    "nil tech",
			tech:    nil,
			wantLen: 0,
		},
		{
			name: "single technology",
			tech: &probes.TechResult{
				Technologies: []probes.Technology{
					{Name: "Apache", Version: "2.4.52"},
				},
			},
			wantLen:  1,
			contains: "cpe:2.3:a:apache:apache:2.4.52:*:*:*:*:*:*:*",
		},
		{
			name: "technology without version",
			tech: &probes.TechResult{
				Technologies: []probes.Technology{
					{Name: "nginx"},
				},
			},
			wantLen:  1,
			contains: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
		},
		{
			name: "generator adds extra CPE",
			tech: &probes.TechResult{
				Technologies: []probes.Technology{
					{Name: "WordPress", Version: "6.4"},
				},
				Generator: "nginx/1.25.3",
			},
			wantLen: 2,
		},
		{
			name: "technology with spaces",
			tech: &probes.TechResult{
				Technologies: []probes.Technology{
					{Name: "Apache Tomcat", Version: "9.0"},
				},
			},
			wantLen:  1,
			contains: "cpe:2.3:a:apache_tomcat:apache_tomcat:9.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := generateCPE(tt.tech)
			if tt.wantLen == 0 {
				if len(cpes) != 0 {
					t.Errorf("expected empty, got %v", cpes)
				}
				return
			}
			if len(cpes) != tt.wantLen {
				t.Errorf("expected %d CPEs, got %d: %v", tt.wantLen, len(cpes), cpes)
			}
			if tt.contains != "" {
				found := false
				for _, cpe := range cpes {
					if cpe == tt.contains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected CPE containing %q, got %v", tt.contains, cpes)
				}
			}
		})
	}
}

func TestStripHTMLTags(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain text",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "simple tags",
			input: "<p>hello</p>",
			want:  "hello",
		},
		{
			name:  "script removal",
			input: "before<script>alert(1)</script>after",
			want:  "beforeafter",
		},
		{
			name:  "style removal",
			input: "text<style>body{color:red}</style>more",
			want:  "textmore",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "nested tags",
			input: "<div><p>text</p></div>",
			want:  "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripHTMLTags(tt.input)
			if got != tt.want {
				t.Errorf("stripHTMLTags(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMatchRange(t *testing.T) {
	tests := []struct {
		name      string
		value     int
		rangeSpec string
		want      bool
	}{
		{"empty spec", 200, "", true},
		{"exact match", 200, "200", true},
		{"no match", 404, "200", false},
		{"range match", 250, "200-300", true},
		{"range no match", 100, "200-300", false},
		{"comma separated", 404, "200,404,500", true},
		{"comma separated no match", 301, "200,404,500", false},
		{"mixed range and exact", 250, "200-300,404", true},
		{"range boundary low", 200, "200-300", true},
		{"range boundary high", 300, "200-300", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchRange(tt.value, tt.rangeSpec)
			if got != tt.want {
				t.Errorf("matchRange(%d, %q) = %v, want %v", tt.value, tt.rangeSpec, got, tt.want)
			}
		})
	}
}

func TestMatchTimeCondition(t *testing.T) {
	tests := []struct {
		name      string
		duration  time.Duration
		condition string
		want      bool
	}{
		{"empty condition", time.Second, "", true},
		{"less than true", 500 * time.Millisecond, "<1s", true},
		{"less than false", 2 * time.Second, "<1s", false},
		{"greater than true", 2 * time.Second, ">1s", true},
		{"greater than false", 500 * time.Millisecond, ">1s", false},
		{"less equal", time.Second, "<=1s", true},
		{"greater equal", time.Second, ">=1s", true},
		{"invalid operator", time.Second, "1s", true},
		{"invalid duration", time.Second, "<xyz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTimeCondition(tt.duration, tt.condition)
			if got != tt.want {
				t.Errorf("matchTimeCondition(%v, %q) = %v, want %v", tt.duration, tt.condition, got, tt.want)
			}
		})
	}
}

func TestParseProbePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantLen int
	}{
		{"single port", "80", 1},
		{"multiple ports", "80,443,8080", 3},
		{"port range", "8080-8085", 6},
		{"scheme prefix", "http:80,https:443", 2},
		{"mixed", "http:80,8080-8082", 4},
		{"empty", "", 0},
		{"scheme range", "http:8000-8002", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseProbePorts(tt.spec)
			if len(result) != tt.wantLen {
				t.Errorf("parseProbePorts(%q) returned %d specs, want %d", tt.spec, len(result), tt.wantLen)
			}
		})
	}
}

func TestExpandProbeTargetPorts(t *testing.T) {
	specs := parseProbePorts("http:80,https:443")
	targets := []string{"https://example.com"}
	expanded := expandProbeTargetPorts(targets, specs)
	if len(expanded) != 2 {
		t.Fatalf("expected 2 expanded targets, got %d", len(expanded))
	}
	if expanded[0] != "http://example.com:80" {
		t.Errorf("expected http://example.com:80, got %s", expanded[0])
	}
	if expanded[1] != "https://example.com:443" {
		t.Errorf("expected https://example.com:443, got %s", expanded[1])
	}
}
