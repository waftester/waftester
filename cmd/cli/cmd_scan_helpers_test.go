package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDetectTechStack(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		cookies  []*http.Cookie
		body     string
		want     []string
		wantNone bool
	}{
		{
			name:    "nginx server",
			headers: map[string]string{"Server": "nginx/1.18.0"},
			want:    []string{"nginx"},
		},
		{
			name:    "apache server",
			headers: map[string]string{"Server": "Apache/2.4.41"},
			want:    []string{"apache"},
		},
		{
			name:    "iis server",
			headers: map[string]string{"Server": "Microsoft-IIS/10.0"},
			want:    []string{"iis"},
		},
		{
			name:    "php powered",
			headers: map[string]string{"X-Powered-By": "PHP/8.1.2"},
			want:    []string{"php"},
		},
		{
			name:    "asp.net powered",
			headers: map[string]string{"X-Powered-By": "ASP.NET"},
			want:    []string{"asp.net"},
		},
		{
			name:    "express powered",
			headers: map[string]string{"X-Powered-By": "Express"},
			want:    []string{"express"},
		},
		{
			name:    "generator header",
			headers: map[string]string{"X-Generator": "Hugo 0.92"},
			want:    []string{"hugo 0.92"},
		},
		{
			name:    "php session cookie",
			cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "abc123"}},
			want:    []string{"php"},
		},
		{
			name:    "java session cookie",
			cookies: []*http.Cookie{{Name: "JSESSIONID", Value: "abc123"}},
			want:    []string{"java"},
		},
		{
			name:    "django csrf cookie",
			cookies: []*http.Cookie{{Name: "csrftoken", Value: "abc123"}},
			want:    []string{"django"},
		},
		{
			name:    "rails cookie",
			cookies: []*http.Cookie{{Name: "_rails_session", Value: "abc123"}},
			want:    []string{"rails"},
		},
		{
			name: "wordpress body",
			body: `<link rel="stylesheet" href="/wp-content/themes/test/style.css">`,
			want: []string{"wordpress"},
		},
		{
			name: "next.js body",
			body: `<div id="__next"><script src="/_next/static/chunks/main.js"></script></div>`,
			want: []string{"next.js"},
		},
		{
			name: "angular body",
			body: `<div ng-app="myApp"><div ng-controller="myCtrl"></div></div>`,
			want: []string{"angular"},
		},
		{
			name: "vue.js body",
			body: `<div id="app" v-bind:title="message">{{ message }}</div>`,
			want: []string{"vue.js"},
		},
		{
			name: "laravel body",
			body: `<meta name="csrf-token" content="abc"><!-- Laravel v10.0 -->`,
			want: []string{"laravel"},
		},
		{
			name: "drupal body",
			body: `<script src="/sites/default/files/js/drupal.js"></script>`,
			want: []string{"drupal"},
		},
		{
			name: "joomla body",
			body: `<meta name="generator" content="Joomla! - Open Source CMS">`,
			want: []string{"joomla"},
		},
		{
			name:    "multiple technologies",
			headers: map[string]string{"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1"},
			cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "abc"}},
			body:    `<link href="/wp-content/themes/test/style.css">`,
			want:    []string{"nginx", "php", "wordpress"},
		},
		{
			name:    "deduplicates php from header and cookie",
			headers: map[string]string{"X-Powered-By": "PHP/8.1"},
			cookies: []*http.Cookie{{Name: "PHPSESSID", Value: "abc"}},
			want:    []string{"php"},
		},
		{
			name:     "no technologies detected",
			headers:  map[string]string{},
			body:     "<html><body>Hello</body></html>",
			wantNone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build mock response
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			// Add cookies via Set-Cookie headers
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c.String())
			}

			got := detectTechStack(resp, []byte(tt.body))

			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no technologies, got %v", got)
				}
				return
			}

			for _, w := range tt.want {
				found := false
				for _, g := range got {
					if g == w {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected %q in result, got %v", w, got)
				}
			}

			// Check deduplication: no duplicates in result
			seen := make(map[string]bool)
			for _, g := range got {
				if seen[g] {
					t.Errorf("duplicate technology in result: %q", g)
				}
				seen[g] = true
			}
		})
	}
}

func TestDnsReconTotalRecords(t *testing.T) {
	tests := []struct {
		name   string
		result *DNSReconResult
		want   int
	}{
		{
			name:   "nil result",
			result: nil,
			want:   0,
		},
		{
			name:   "empty result",
			result: &DNSReconResult{},
			want:   0,
		},
		{
			name: "mixed records",
			result: &DNSReconResult{
				CNAMEs:     []string{"cdn.example.com"},
				MXRecords:  []string{"mx1.example.com", "mx2.example.com"},
				TXTRecords: []string{"v=spf1 include:example.com ~all"},
				NSRecords:  []string{"ns1.example.com"},
			},
			want: 5,
		},
		{
			name: "only txt records",
			result: &DNSReconResult{
				TXTRecords: []string{"v=spf1", "google-site-verification=abc"},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dnsReconTotalRecords(tt.result)
			if got != tt.want {
				t.Errorf("dnsReconTotalRecords() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPrintScanCSV(t *testing.T) {
	result := &ScanResult{
		Target: "https://example.com",
		ByCategory: map[string]int{
			"sqli": 3,
			"xss":  2,
		},
	}

	var buf bytes.Buffer
	printScanCSV(&buf, "https://example.com", result)
	output := buf.String()

	if !strings.Contains(output, "target,category,severity,count") {
		t.Error("CSV output missing header row")
	}
	if !strings.Contains(output, "https://example.com,sqli,various,3") {
		t.Error("CSV output missing sqli row")
	}
	if !strings.Contains(output, "https://example.com,xss,various,2") {
		t.Error("CSV output missing xss row")
	}
}

func TestPrintScanMarkdown(t *testing.T) {
	result := &ScanResult{
		Target:       "https://example.com",
		ReportTitle:  "Test Report",
		ReportAuthor: "Tester",
		StartTime:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Duration:     5 * time.Second,
		TotalVulns:   3,
		BySeverity:   map[string]int{"High": 2, "Medium": 1},
		ByCategory:   map[string]int{"sqli": 2, "xss": 1},
	}

	var buf bytes.Buffer
	printScanMarkdown(&buf, result)
	output := buf.String()

	checks := []string{
		"# Vulnerability Scan Report",
		"**Report:** Test Report",
		"**Author:** Tester",
		"**Target:** https://example.com",
		"**Total Vulnerabilities:** 3",
		"## By Severity",
		"## By Category",
		"| Severity | Count |",
		"| Category | Count |",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("Markdown output missing: %q", check)
		}
	}
}

func TestPrintScanHTML(t *testing.T) {
	result := &ScanResult{
		Target:       "https://example.com",
		ReportTitle:  "HTML Test",
		ReportAuthor: "Author",
		StartTime:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		TotalVulns:   1,
		BySeverity:   map[string]int{"Critical": 1},
		ByCategory:   map[string]int{"sqli": 1},
	}

	var buf bytes.Buffer
	printScanHTML(&buf, result)
	output := buf.String()

	checks := []string{
		"<!DOCTYPE html>",
		"<h1>HTML Test</h1>",
		"<p><strong>Author:</strong> Author</p>",
		"<p><strong>Target:</strong> https://example.com</p>",
		"</table></body></html>",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("HTML output missing: %q", check)
		}
	}
}

func TestPrintScanHTMLDefaultTitle(t *testing.T) {
	result := &ScanResult{
		Target:     "https://example.com",
		StartTime:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		TotalVulns: 0,
		BySeverity: map[string]int{},
		ByCategory: map[string]int{},
	}

	var buf bytes.Buffer
	printScanHTML(&buf, result)
	output := buf.String()

	if !strings.Contains(output, "<h1>Vulnerability Scan Report</h1>") {
		t.Error("HTML output should use default title when ReportTitle is empty")
	}
}

func TestPrintScanSARIF(t *testing.T) {
	result := &ScanResult{
		ByCategory: map[string]int{"sqli": 3, "xss": 1},
	}

	var buf bytes.Buffer
	printScanSARIF(&buf, "https://example.com", result)
	output := buf.String()

	checks := []string{
		"sarif-schema-2.1.0.json",
		`"version": "2.1.0"`,
		"waf-tester",
		"waftester/waftester",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("SARIF output missing: %q", check)
		}
	}
}

func TestPrintScanJSONL(t *testing.T) {
	result := &ScanResult{
		ByCategory: map[string]int{"sqli": 2},
	}

	var buf bytes.Buffer
	printScanJSONL(&buf, "https://example.com", result)
	output := buf.String()

	if !strings.Contains(output, `"category":"sqli"`) {
		t.Error("JSONL output missing sqli category")
	}
	if !strings.Contains(output, `"count":2`) {
		t.Error("JSONL output missing count")
	}
	if !strings.Contains(output, `"target":"https://example.com"`) {
		t.Error("JSONL output missing target")
	}
}
