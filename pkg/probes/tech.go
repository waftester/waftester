// Package probes - Technology detection (Wappalyzer-style)
package probes

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// TechResult contains technology detection results
type TechResult struct {
	Title        string       `json:"title,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	BodyHash     BodyHash     `json:"body_hash,omitempty"`
	ContentType  string       `json:"content_type,omitempty"`
	PoweredBy    string       `json:"powered_by,omitempty"`
	Generator    string       `json:"generator,omitempty"`
	Framework    string       `json:"framework,omitempty"`
}

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Confidence int      `json:"confidence"` // 0-100
}

// BodyHash contains response body hashes
type BodyHash struct {
	MD5     string `json:"md5,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Simhash uint64 `json:"simhash,omitempty"`
	BodyLen int    `json:"body_length"`
}

// TechDetector detects technologies from HTTP responses
type TechDetector struct {
	signatures []techSignature
}

type techSignature struct {
	name       string
	categories []string
	headers    map[string]*regexp.Regexp
	cookies    []string
	meta       map[string]*regexp.Regexp
	scripts    []*regexp.Regexp
	html       []*regexp.Regexp
	implies    []string
}

// NewTechDetector creates a new technology detector
func NewTechDetector() *TechDetector {
	return &TechDetector{
		signatures: getSignatures(),
	}
}

// Detect analyzes response and detects technologies
func (t *TechDetector) Detect(resp *http.Response, body []byte) *TechResult {
	result := &TechResult{
		ContentType: resp.Header.Get("Content-Type"),
	}

	bodyStr := string(body)

	// Extract title
	result.Title = techExtractTitle(bodyStr)

	// Extract powered-by, generator, framework from headers
	result.PoweredBy = resp.Header.Get("X-Powered-By")
	result.Generator = techExtractMeta(bodyStr, "generator")
	result.Framework = resp.Header.Get("X-AspNet-Version")
	if result.Framework == "" {
		result.Framework = resp.Header.Get("X-AspNetMvc-Version")
	}

	// Calculate body hashes
	result.BodyHash = BodyHash{
		MD5:     md5Hash(body),
		SHA256:  sha256Hash(body),
		BodyLen: len(body),
	}

	// Detect technologies
	techs := make(map[string]*Technology)

	for _, sig := range t.signatures {
		confidence := 0

		// Check headers
		for header, pattern := range sig.headers {
			if val := resp.Header.Get(header); val != "" {
				if pattern == nil || pattern.MatchString(val) {
					confidence += 30
				}
			}
		}

		// Check cookies
		for _, cookie := range sig.cookies {
			for _, c := range resp.Cookies() {
				if strings.EqualFold(c.Name, cookie) {
					confidence += 20
				}
			}
		}

		// Check HTML patterns
		for _, pattern := range sig.html {
			if pattern.MatchString(bodyStr) {
				confidence += 25
			}
		}

		// Check script patterns
		for _, pattern := range sig.scripts {
			if pattern.MatchString(bodyStr) {
				confidence += 25
			}
		}

		// Check meta tags
		for name, pattern := range sig.meta {
			metaVal := techExtractMeta(bodyStr, name)
			if metaVal != "" && (pattern == nil || pattern.MatchString(metaVal)) {
				confidence += 20
			}
		}

		if confidence > 0 {
			if confidence > 100 {
				confidence = 100
			}
			techs[sig.name] = &Technology{
				Name:       sig.name,
				Categories: sig.categories,
				Confidence: confidence,
			}
		}
	}

	// Add detected techs from headers directly
	if server := resp.Header.Get("Server"); server != "" {
		addServerTech(techs, server)
	}
	if poweredBy := result.PoweredBy; poweredBy != "" {
		addPoweredByTech(techs, poweredBy)
	}

	for _, tech := range techs {
		result.Technologies = append(result.Technologies, *tech)
	}

	return result
}

func techExtractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		title := strings.TrimSpace(matches[1])
		// Limit length
		if len(title) > 100 {
			title = title[:100] + "..."
		}
		return title
	}
	return ""
}

func techExtractMeta(html, name string) string {
	// Match both name= and property= attributes
	patterns := []string{
		`(?i)<meta[^>]+name=["']?` + regexp.QuoteMeta(name) + `["']?[^>]+content=["']([^"']+)["']`,
		`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']?` + regexp.QuoteMeta(name) + `["']?`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(html)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	return ""
}

func md5Hash(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func sha256Hash(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func addServerTech(techs map[string]*Technology, server string) {
	server = strings.ToLower(server)
	mapping := map[string][]string{
		"nginx":      {"nginx", "Web Server"},
		"apache":     {"Apache", "Web Server"},
		"iis":        {"IIS", "Web Server"},
		"cloudflare": {"Cloudflare", "CDN"},
		"caddy":      {"Caddy", "Web Server"},
		"litespeed":  {"LiteSpeed", "Web Server"},
		"gunicorn":   {"Gunicorn", "Web Server"},
		"express":    {"Express", "Web Framework"},
		"railway":    {"Railway", "PaaS"},
		"vercel":     {"Vercel", "PaaS"},
		"heroku":     {"Heroku", "PaaS"},
	}
	for key, val := range mapping {
		if strings.Contains(server, key) {
			techs[val[0]] = &Technology{
				Name:       val[0],
				Categories: []string{val[1]},
				Confidence: 100,
			}
		}
	}
}

func addPoweredByTech(techs map[string]*Technology, poweredBy string) {
	pb := strings.ToLower(poweredBy)
	mapping := map[string][]string{
		"php":       {"PHP", "Programming Language"},
		"asp.net":   {"ASP.NET", "Web Framework"},
		"express":   {"Express", "Web Framework"},
		"next.js":   {"Next.js", "Web Framework"},
		"nuxt":      {"Nuxt.js", "Web Framework"},
		"django":    {"Django", "Web Framework"},
		"flask":     {"Flask", "Web Framework"},
		"rails":     {"Ruby on Rails", "Web Framework"},
		"laravel":   {"Laravel", "Web Framework"},
		"wordpress": {"WordPress", "CMS"},
		"drupal":    {"Drupal", "CMS"},
	}
	for key, val := range mapping {
		if strings.Contains(pb, key) {
			techs[val[0]] = &Technology{
				Name:       val[0],
				Categories: []string{val[1]},
				Confidence: 90,
			}
		}
	}
}

func getSignatures() []techSignature {
	return []techSignature{
		{
			name:       "WordPress",
			categories: []string{"CMS"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)wp-content|wp-includes|wordpress`)},
			meta:       map[string]*regexp.Regexp{"generator": regexp.MustCompile(`(?i)wordpress`)},
		},
		{
			name:       "React",
			categories: []string{"JavaScript Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)react|_reactRootContainer|data-reactroot`)},
			scripts:    []*regexp.Regexp{regexp.MustCompile(`(?i)react\.production\.min\.js|react-dom`)},
		},
		{
			name:       "Vue.js",
			categories: []string{"JavaScript Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)v-cloak|v-if|v-for|data-v-`)},
			scripts:    []*regexp.Regexp{regexp.MustCompile(`(?i)vue\.min\.js|vue\.js|vue@`)},
		},
		{
			name:       "Angular",
			categories: []string{"JavaScript Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)ng-app|ng-controller|ng-model|\[ngClass\]`)},
			scripts:    []*regexp.Regexp{regexp.MustCompile(`(?i)angular\.min\.js|angular\.js`)},
		},
		{
			name:       "jQuery",
			categories: []string{"JavaScript Library"},
			scripts:    []*regexp.Regexp{regexp.MustCompile(`(?i)jquery[.-]?\d|jquery\.min\.js`)},
		},
		{
			name:       "Bootstrap",
			categories: []string{"CSS Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)class="[^"]*\b(container|row|col-|btn-|navbar)[^"]*"`)},
			scripts:    []*regexp.Regexp{regexp.MustCompile(`(?i)bootstrap\.min\.js|bootstrap\.bundle`)},
		},
		{
			name:       "Tailwind CSS",
			categories: []string{"CSS Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)class="[^"]*\b(flex|grid|p-\d|m-\d|text-|bg-|hover:)[^"]*"`)},
		},
		{
			name:       "Next.js",
			categories: []string{"Web Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)__NEXT_DATA__|_next/static|next/dist`)},
		},
		{
			name:       "Nuxt.js",
			categories: []string{"Web Framework"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)__NUXT__|_nuxt/|nuxt\.js`)},
		},
		{
			name:       "Laravel",
			categories: []string{"Web Framework"},
			cookies:    []string{"laravel_session", "XSRF-TOKEN"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)csrf-token.*content="[a-zA-Z0-9]{40}"`)},
		},
		{
			name:       "Django",
			categories: []string{"Web Framework"},
			cookies:    []string{"csrftoken", "django_language"},
			headers:    map[string]*regexp.Regexp{"X-Frame-Options": nil},
		},
		{
			name:       "Express",
			categories: []string{"Web Framework"},
			headers:    map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)express`)},
		},
		{
			name:       "nginx",
			categories: []string{"Web Server"},
			headers:    map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nginx`)},
		},
		{
			name:       "Apache",
			categories: []string{"Web Server"},
			headers:    map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)apache`)},
		},
		{
			name:       "Cloudflare",
			categories: []string{"CDN", "WAF"},
			headers:    map[string]*regexp.Regexp{"CF-Ray": nil, "CF-Cache-Status": nil},
			cookies:    []string{"__cfduid", "__cf_bm"},
		},
		{
			name:       "AWS",
			categories: []string{"Cloud", "PaaS"},
			headers:    map[string]*regexp.Regexp{"X-Amz-Cf-Id": nil, "X-Amzn-Trace-Id": nil},
		},
		{
			name:       "Google Cloud",
			categories: []string{"Cloud", "PaaS"},
			headers:    map[string]*regexp.Regexp{"X-Cloud-Trace-Context": nil},
		},
		{
			name:       "Varnish",
			categories: []string{"Cache"},
			headers:    map[string]*regexp.Regexp{"Via": regexp.MustCompile(`(?i)varnish`), "X-Varnish": nil},
		},
		{
			name:       "PHP",
			categories: []string{"Programming Language"},
			headers:    map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)php`)},
			cookies:    []string{"PHPSESSID"},
		},
		{
			name:       "ASP.NET",
			categories: []string{"Web Framework"},
			headers:    map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)asp\.net`), "X-AspNet-Version": nil},
			cookies:    []string{"ASP.NET_SessionId", ".ASPXAUTH"},
		},
		{
			name:       "Ruby on Rails",
			categories: []string{"Web Framework"},
			headers:    map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)phusion|rails`)},
			cookies:    []string{"_session_id"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)csrf-token.*content="[a-zA-Z0-9+/=]{44}"`)},
		},
		{
			name:       "n8n",
			categories: []string{"Automation"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)n8n|workflow automation`)},
		},
		{
			name:       "Authentik",
			categories: []string{"Identity Provider"},
			html:       []*regexp.Regexp{regexp.MustCompile(`(?i)authentik|goauthentik`)},
		},
	}
}

// CustomFingerprint represents a user-defined fingerprint
type CustomFingerprint struct {
	Name       string            `json:"name"`
	Categories []string          `json:"categories,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"` // header name -> regex pattern
	HTML       []string          `json:"html,omitempty"`    // regex patterns to match in HTML
	Scripts    []string          `json:"scripts,omitempty"` // regex patterns for script src
	Cookies    []string          `json:"cookies,omitempty"` // cookie names
	Meta       map[string]string `json:"meta,omitempty"`    // meta tag name -> regex
	Implies    []string          `json:"implies,omitempty"` // other technologies this implies
}

// LoadCustomFingerprints loads fingerprints from a JSON file
func (t *TechDetector) LoadCustomFingerprints(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	var fingerprints []CustomFingerprint
	if err := json.Unmarshal(data, &fingerprints); err != nil {
		return fmt.Errorf("failed to parse fingerprint file: %w", err)
	}

	for _, fp := range fingerprints {
		t.AddCustomFingerprint(fp)
	}

	return nil
}

// AddCustomFingerprint adds a single custom fingerprint
func (t *TechDetector) AddCustomFingerprint(fp CustomFingerprint) {
	sig := techSignature{
		name:       fp.Name,
		categories: fp.Categories,
		headers:    make(map[string]*regexp.Regexp),
		html:       make([]*regexp.Regexp, 0),
		scripts:    make([]*regexp.Regexp, 0),
		cookies:    fp.Cookies,
		meta:       make(map[string]*regexp.Regexp),
		implies:    fp.Implies,
	}

	for k, v := range fp.Headers {
		if re, err := regexp.Compile(v); err == nil {
			sig.headers[k] = re
		}
	}

	for _, pattern := range fp.HTML {
		if re, err := regexp.Compile(pattern); err == nil {
			sig.html = append(sig.html, re)
		}
	}

	for _, pattern := range fp.Scripts {
		if re, err := regexp.Compile(pattern); err == nil {
			sig.scripts = append(sig.scripts, re)
		}
	}

	for k, v := range fp.Meta {
		if re, err := regexp.Compile(v); err == nil {
			sig.meta[k] = re
		}
	}

	t.signatures = append(t.signatures, sig)
}

// ReadBody reads response body with size limit
func ReadBody(resp *http.Response, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = 2 * 1024 * 1024 // 2MB default
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSize))
}
