// Package js provides JavaScript analysis capabilities
// Based on JSLuice's static analysis for extracting endpoints, secrets, and sensitive data
package js

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/waftester/waftester/pkg/bufpool"
	"github.com/waftester/waftester/pkg/regexcache"
)

// ExtractedData represents all data extracted from JavaScript
type ExtractedData struct {
	URLs       []URLInfo      `json:"urls,omitempty"`
	Endpoints  []EndpointInfo `json:"endpoints,omitempty"`
	Secrets    []SecretInfo   `json:"secrets,omitempty"`
	Variables  []VariableInfo `json:"variables,omitempty"`
	DOMSinks   []DOMSinkInfo  `json:"dom_sinks,omitempty"`
	CloudURLs  []CloudURL     `json:"cloud_urls,omitempty"`
	Subdomains []string       `json:"subdomains,omitempty"`
}

// URLInfo represents a URL found in JavaScript
type URLInfo struct {
	URL        string   `json:"url"`
	Type       string   `json:"type"` // absolute, relative, protocol-relative
	Line       int      `json:"line,omitempty"`
	Context    string   `json:"context,omitempty"` // Surrounding code
	Method     string   `json:"method,omitempty"`  // GET, POST, etc.
	Parameters []string `json:"parameters,omitempty"`
}

// EndpointInfo represents an API endpoint
type EndpointInfo struct {
	Path       string            `json:"path"`
	Method     string            `json:"method,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Parameters []string          `json:"parameters,omitempty"`
	Source     string            `json:"source"` // fetch, axios, xhr, jquery
}

// SecretInfo represents a potential secret
type SecretInfo struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Entropy    float64 `json:"entropy,omitempty"`
	Line       int     `json:"line,omitempty"`
	Confidence string  `json:"confidence"` // high, medium, low
}

// VariableInfo represents an interesting variable
type VariableInfo struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type"` // api_key, token, config, etc.
	Line  int    `json:"line,omitempty"`
}

// DOMSinkInfo represents a DOM XSS sink
type DOMSinkInfo struct {
	Sink     string `json:"sink"`
	Context  string `json:"context"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"` // high, medium, low
}

// CloudURL represents cloud service URLs
type CloudURL struct {
	URL      string `json:"url"`
	Service  string `json:"service"` // aws, gcp, azure, etc.
	Resource string `json:"resource,omitempty"`
	Region   string `json:"region,omitempty"`
}

// Analyzer performs JavaScript static analysis
type Analyzer struct {
	// Regex patterns for extraction
	URLPatterns      []*regexp.Regexp
	SecretPatterns   map[string]*regexp.Regexp
	EndpointPatterns []*regexp.Regexp
	DOMSinkPatterns  []*regexp.Regexp
	CloudPatterns    map[string]*regexp.Regexp

	// Configuration
	MinSecretLength int
	MaxSecretLength int
	MinEntropy      float64
}

// NewAnalyzer creates a new JavaScript analyzer with default patterns
func NewAnalyzer() *Analyzer {
	a := &Analyzer{
		MinSecretLength: 8,
		MaxSecretLength: 500,
		MinEntropy:      3.0,
		SecretPatterns:  make(map[string]*regexp.Regexp),
		CloudPatterns:   make(map[string]*regexp.Regexp),
	}

	a.initURLPatterns()
	a.initSecretPatterns()
	a.initEndpointPatterns()
	a.initDOMSinkPatterns()
	a.initCloudPatterns()

	return a
}

func (a *Analyzer) initURLPatterns() {
	a.URLPatterns = []*regexp.Regexp{
		// Absolute URLs
		regexp.MustCompile(`https?://[^\s"'\` + "`" + `<>\[\]{}()|\\^]+`),
		// Protocol-relative URLs
		regexp.MustCompile(`//[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}[^\s"'` + "`" + `<>\[\]{}()|\\^]*`),
		// Relative paths starting with /
		regexp.MustCompile(`["'\` + "`" + `](/[a-zA-Z0-9_/-]+(?:\.[a-zA-Z0-9]+)?(?:\?[^"'` + "`" + `\s]*)?)`),
		// API paths
		regexp.MustCompile(`["'\` + "`" + `](/api/v?\d*/[a-zA-Z0-9/_-]+)`),
		regexp.MustCompile(`["'\` + "`" + `](/v\d+/[a-zA-Z0-9/_-]+)`),
	}
}

func (a *Analyzer) initSecretPatterns() {
	patterns := map[string]string{
		// API Keys
		"aws_access_key": `AKIA[0-9A-Z]{16}`,
		"aws_secret_key": `(?i)aws[_\-]?secret[_\-]?(?:access)?[_\-]?key["'\s:=]+([A-Za-z0-9/+=]{40})`,
		"google_api_key": `AIza[0-9A-Za-z_-]{35}`,
		"google_oauth":   `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
		"github_token":   `gh[pousr]_[A-Za-z0-9_]{36,}`,
		"github_oauth":   `gho_[A-Za-z0-9_]{36,}`,
		"slack_token":    `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
		"slack_webhook":  `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`,
		"stripe_key":     `(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}`,
		"twilio_sid":     `AC[a-z0-9]{32}`,
		"twilio_token":   `SK[a-z0-9]{32}`,
		"mailgun_key":    `key-[0-9a-zA-Z]{32}`,
		"mailchimp_key":  `[0-9a-f]{32}-us[0-9]{1,2}`,
		"facebook_token": `EAACEdEose0cBA[0-9A-Za-z]+`,
		"twitter_token":  `(?i)twitter[_\-]?(?:api)?[_\-]?(?:secret)?[_\-]?key["'\s:=]+([A-Za-z0-9]{25,50})`,
		"heroku_key":     `[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
		"firebase_key":   `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
		"sendgrid_key":   `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,

		// Generic patterns
		"private_key":          `-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----`,
		"jwt_token":            `eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,
		"basic_auth":           `(?i)basic\s+[A-Za-z0-9+/=]{10,}`,
		"bearer_token":         `(?i)bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		"api_key_generic":      `(?i)(?:api[_\-]?key|apikey|api_secret)["'\s:=]+["']?([A-Za-z0-9_-]{20,})["']?`,
		"password_field":       `(?i)(?:password|passwd|pwd)["'\s:=]+["']?([^"'\s]{8,})["']?`,
		"authorization_header": `(?i)authorization["'\s:=]+["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9_.-]+)["']?`,

		// Database connection strings
		"mongodb_uri":  `mongodb(?:\+srv)?://[^\s"'` + "`" + `]+`,
		"postgres_uri": `postgres(?:ql)?://[^\s"'` + "`" + `]+`,
		"mysql_uri":    `mysql://[^\s"'` + "`" + `]+`,
		"redis_uri":    `redis://[^\s"'` + "`" + `]+`,
	}

	for name, pattern := range patterns {
		a.SecretPatterns[name] = regexp.MustCompile(pattern)
	}
}

func (a *Analyzer) initEndpointPatterns() {
	a.EndpointPatterns = []*regexp.Regexp{
		// fetch API
		regexp.MustCompile(`fetch\s*\(\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`fetch\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[,)]`),

		// axios
		regexp.MustCompile(`axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`axios\s*\(\s*\{[^}]*url\s*:\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),

		// jQuery AJAX
		regexp.MustCompile(`\$\s*\.\s*(?:ajax|get|post|getJSON)\s*\(\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),
		regexp.MustCompile(`\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),

		// XMLHttpRequest
		regexp.MustCompile(`\.open\s*\(\s*["'](\w+)["']\s*,\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),

		// Angular HttpClient
		regexp.MustCompile(`this\s*\.\s*http\s*\.\s*(get|post|put|patch|delete)\s*[<(]\s*["'\` + "`" + `]([^"'` + "`" + `]+)["'\` + "`" + `]`),
	}
}

func (a *Analyzer) initDOMSinkPatterns() {
	a.DOMSinkPatterns = []*regexp.Regexp{
		// innerHTML and similar
		regexp.MustCompile(`\.innerHTML\s*=`),
		regexp.MustCompile(`\.outerHTML\s*=`),
		regexp.MustCompile(`\.insertAdjacentHTML\s*\(`),

		// document.write
		regexp.MustCompile(`document\.write\s*\(`),
		regexp.MustCompile(`document\.writeln\s*\(`),

		// eval and similar
		regexp.MustCompile(`\beval\s*\(`),
		regexp.MustCompile(`\bnew\s+Function\s*\(`),
		regexp.MustCompile(`setTimeout\s*\(\s*["'` + "`" + `]`),
		regexp.MustCompile(`setInterval\s*\(\s*["'` + "`" + `]`),

		// URL manipulation
		regexp.MustCompile(`location\s*=`),
		regexp.MustCompile(`location\.href\s*=`),
		regexp.MustCompile(`location\.replace\s*\(`),
		regexp.MustCompile(`location\.assign\s*\(`),

		// jQuery sinks
		regexp.MustCompile(`\$\s*\([^)]*\)\s*\.\s*(?:html|append|prepend|after|before)\s*\(`),
	}
}

func (a *Analyzer) initCloudPatterns() {
	a.CloudPatterns = map[string]*regexp.Regexp{
		// AWS - multiple S3 URL formats
		"s3":          regexp.MustCompile(`(?:https?://)?[a-zA-Z0-9.-]+\.s3(?:[.-][a-zA-Z0-9.-]+)?\.amazonaws\.com`),
		"s3_path":     regexp.MustCompile(`(?:https?://)?s3[.-][a-zA-Z0-9.-]+\.amazonaws\.com/[a-zA-Z0-9._/-]+`),
		"cloudfront":  regexp.MustCompile(`[a-zA-Z0-9]+\.cloudfront\.net`),
		"api_gateway": regexp.MustCompile(`[a-zA-Z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com`),
		"lambda":      regexp.MustCompile(`[a-zA-Z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws`),
		"cognito":     regexp.MustCompile(`[a-zA-Z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com`),

		// GCP
		"gcs":            regexp.MustCompile(`(?:https?://)?storage\.googleapis\.com(?:/[a-zA-Z0-9._/-]+)?`),
		"firebase":       regexp.MustCompile(`[a-zA-Z0-9-]+\.firebaseio\.com`),
		"firebase_stor":  regexp.MustCompile(`[a-zA-Z0-9-]+\.appspot\.com`),
		"cloud_run":      regexp.MustCompile(`[a-zA-Z0-9-]+\.run\.app`),
		"cloud_function": regexp.MustCompile(`[a-z0-9-]+\.cloudfunctions\.net`),

		// Azure
		"azure_blob": regexp.MustCompile(`[a-zA-Z0-9]+\.blob\.core\.windows\.net`),
		"azure_web":  regexp.MustCompile(`[a-zA-Z0-9-]+\.azurewebsites\.net`),
		"azure_cdn":  regexp.MustCompile(`[a-zA-Z0-9-]+\.azureedge\.net`),

		// Other cloud services
		"digitalocean": regexp.MustCompile(`[a-zA-Z0-9-]+\.digitaloceanspaces\.com`),
		"heroku":       regexp.MustCompile(`[a-zA-Z0-9-]+\.herokuapp\.com`),
		"netlify":      regexp.MustCompile(`[a-zA-Z0-9-]+\.netlify\.app`),
		"vercel":       regexp.MustCompile(`[a-zA-Z0-9-]+\.vercel\.app`),
	}
}

// Analyze performs full analysis on JavaScript code
func (a *Analyzer) Analyze(code string) *ExtractedData {
	data := &ExtractedData{}

	// Extract URLs
	data.URLs = a.ExtractURLs(code)

	// Extract endpoints
	data.Endpoints = a.ExtractEndpoints(code)

	// Extract secrets
	data.Secrets = a.ExtractSecrets(code)

	// Extract interesting variables
	data.Variables = a.ExtractVariables(code)

	// Find DOM sinks
	data.DOMSinks = a.FindDOMSinks(code)

	// Extract cloud URLs
	data.CloudURLs = a.ExtractCloudURLs(code)

	// Extract subdomains
	data.Subdomains = a.ExtractSubdomains(code)

	return data
}

// ExtractURLs extracts all URLs from JavaScript
func (a *Analyzer) ExtractURLs(code string) []URLInfo {
	seen := make(map[string]bool)
	var urls []URLInfo

	for _, pattern := range a.URLPatterns {
		matches := pattern.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			url := match[0]
			if len(match) > 1 && match[1] != "" {
				url = match[1]
			}

			// Clean up the URL
			url = strings.Trim(url, `"'`+"`")
			url = strings.TrimSpace(url)

			// Skip if already seen or too short
			if seen[url] || len(url) < 3 {
				continue
			}
			seen[url] = true

			// Determine type
			urlType := "relative"
			if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
				urlType = "absolute"
			} else if strings.HasPrefix(url, "//") {
				urlType = "protocol-relative"
			}

			// Extract method from context
			method := a.inferMethod(code, url)

			// Extract parameters
			params := a.extractParams(url)

			urls = append(urls, URLInfo{
				URL:        url,
				Type:       urlType,
				Method:     method,
				Parameters: params,
			})
		}
	}

	return urls
}

// ExtractEndpoints extracts API endpoints
func (a *Analyzer) ExtractEndpoints(code string) []EndpointInfo {
	seen := make(map[string]bool)
	var endpoints []EndpointInfo

	for _, pattern := range a.EndpointPatterns {
		matches := pattern.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			var path, method, source string

			// Determine source and extract info based on pattern
			patternStr := pattern.String()
			if strings.Contains(patternStr, "fetch") {
				source = "fetch"
				path = match[1]
				method = "GET" // Default for fetch
			} else if strings.Contains(patternStr, "axios") {
				source = "axios"
				if len(match) > 2 {
					method = strings.ToUpper(match[1])
					path = match[2]
				} else {
					path = match[1]
				}
			} else if strings.Contains(patternStr, `\$`) {
				source = "jquery"
				path = match[1]
				if strings.Contains(patternStr, "post") {
					method = "POST"
				} else {
					method = "GET"
				}
			} else if strings.Contains(patternStr, "open") {
				source = "xhr"
				if len(match) > 2 {
					method = strings.ToUpper(match[1])
					path = match[2]
				}
			} else if strings.Contains(patternStr, "http") {
				source = "angular"
				if len(match) > 2 {
					method = strings.ToUpper(match[1])
					path = match[2]
				}
			}

			if path == "" {
				continue
			}

			key := method + ":" + path
			if seen[key] {
				continue
			}
			seen[key] = true

			endpoints = append(endpoints, EndpointInfo{
				Path:       path,
				Method:     method,
				Source:     source,
				Parameters: a.extractParams(path),
			})
		}
	}

	return endpoints
}

// ExtractSecrets extracts potential secrets
func (a *Analyzer) ExtractSecrets(code string) []SecretInfo {
	var secrets []SecretInfo
	seen := make(map[string]bool)

	for secretType, pattern := range a.SecretPatterns {
		matches := pattern.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			value := match[0]
			if len(match) > 1 && match[1] != "" {
				value = match[1]
			}

			// Skip if too short/long
			if len(value) < a.MinSecretLength || len(value) > a.MaxSecretLength {
				continue
			}

			// Skip if already seen
			if seen[value] {
				continue
			}
			seen[value] = true

			// Calculate entropy
			entropy := calculateEntropy(value)

			// Determine confidence
			confidence := "low"
			if entropy > 4.0 {
				confidence = "high"
			} else if entropy > 3.0 {
				confidence = "medium"
			}

			// High confidence for known patterns
			if strings.HasPrefix(secretType, "aws_") ||
				strings.HasPrefix(secretType, "google_") ||
				strings.HasPrefix(secretType, "github_") ||
				strings.HasPrefix(secretType, "stripe_") ||
				secretType == "jwt_token" {
				confidence = "high"
			}

			secrets = append(secrets, SecretInfo{
				Type:       secretType,
				Value:      value,
				Entropy:    entropy,
				Confidence: confidence,
			})
		}
	}

	// Sort by confidence
	sort.Slice(secrets, func(i, j int) bool {
		order := map[string]int{"high": 0, "medium": 1, "low": 2}
		return order[secrets[i].Confidence] < order[secrets[j].Confidence]
	})

	return secrets
}

// ExtractVariables extracts interesting variable assignments
func (a *Analyzer) ExtractVariables(code string) []VariableInfo {
	var variables []VariableInfo
	seen := make(map[string]bool)

	// Patterns for interesting variable names
	varPatterns := map[string]*regexp.Regexp{
		"api_key":  regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*(?:api[_-]?key|apikey|api_secret))\s*=\s*["']([^"']+)["']`),
		"token":    regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*(?:token|auth|secret))\s*=\s*["']([^"']+)["']`),
		"endpoint": regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*(?:url|endpoint|api|base))\s*=\s*["']([^"']+)["']`),
		"config":   regexp.MustCompile(`(?i)(?:var|let|const)\s+(config|settings|options)\s*=\s*(\{[^}]+\})`),
		"password": regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*(?:password|passwd|pwd))\s*=\s*["']([^"']+)["']`),
	}

	for varType, pattern := range varPatterns {
		matches := pattern.FindAllStringSubmatch(code, -1)
		for _, match := range matches {
			if len(match) < 3 {
				continue
			}

			name := match[1]
			value := match[2]

			if seen[name] {
				continue
			}
			seen[name] = true

			variables = append(variables, VariableInfo{
				Name:  name,
				Value: value,
				Type:  varType,
			})
		}
	}

	return variables
}

// FindDOMSinks finds potential DOM XSS sinks
func (a *Analyzer) FindDOMSinks(code string) []DOMSinkInfo {
	var sinks []DOMSinkInfo
	lines := strings.Split(code, "\n")

	for lineNum, line := range lines {
		for _, pattern := range a.DOMSinkPatterns {
			if matches := pattern.FindStringSubmatch(line); len(matches) > 0 {
				sink := matches[0]

				// Determine severity
				severity := "medium"
				lowerSink := strings.ToLower(sink)
				if strings.Contains(lowerSink, "eval") ||
					strings.Contains(lowerSink, "function") ||
					strings.Contains(lowerSink, "innerhtml") {
					severity = "high"
				} else if strings.Contains(lowerSink, "location") {
					severity = "medium"
				}

				sinks = append(sinks, DOMSinkInfo{
					Sink:     sink,
					Context:  strings.TrimSpace(line),
					Line:     lineNum + 1,
					Severity: severity,
				})
			}
		}
	}

	return sinks
}

// ExtractCloudURLs extracts cloud service URLs
func (a *Analyzer) ExtractCloudURLs(code string) []CloudURL {
	var cloudURLs []CloudURL
	seen := make(map[string]bool)

	for service, pattern := range a.CloudPatterns {
		matches := pattern.FindAllString(code, -1)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true

			cloudURL := CloudURL{
				URL:     match,
				Service: serviceCategory(service),
			}

			// Extract region if present
			if regionMatch := regexcache.MustGet(`[a-z]{2}-[a-z]+-\d`).FindString(match); regionMatch != "" {
				cloudURL.Region = regionMatch
			}

			cloudURLs = append(cloudURLs, cloudURL)
		}
	}

	return cloudURLs
}

// jsArtifactPattern matches common JavaScript object property access patterns
// that look like subdomains but are actually JS code artifacts
var jsArtifactPattern = regexp.MustCompile(
	`^(?:window|document|this|console|Math|Array|Object|JSON|Promise|Date|String|Number|Boolean|Function|Symbol|RegExp|Error|self|global|globalThis|module|exports|require|process|Buffer|Event|Element|Node|HTMLElement)\.[a-zA-Z]+$`,
)

// invalidTLDs are common JS property suffixes that look like TLDs but aren't
var invalidTLDs = map[string]bool{
	"js": true, "json": true, "jsx": true, "ts": true, "tsx": true,
	"css": true, "scss": true, "less": true, "html": true, "htm": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"woff": true, "woff2": true, "ttf": true, "eot": true,
	"min": true, "map": true, "bundle": true, "chunk": true,
}

// ExtractSubdomains extracts subdomains from code with enhanced false positive filtering
func (a *Analyzer) ExtractSubdomains(code string) []string {
	// Require at least one subdomain part (2+ dots) to reduce false positives
	pattern := regexcache.MustGet(`(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}`)
	matches := pattern.FindAllString(code, -1)

	seen := make(map[string]bool)
	var subdomains []string

	for _, match := range matches {
		// Clean up
		clean := strings.TrimPrefix(match, "https://")
		clean = strings.TrimPrefix(clean, "http://")
		clean = strings.ToLower(clean)

		// Skip JS object property access patterns (window.leave, document.body, etc.)
		if jsArtifactPattern.MatchString(clean) {
			continue
		}

		// Skip if TLD is actually a file extension or JS artifact
		parts := strings.Split(clean, ".")
		if len(parts) > 0 {
			tld := parts[len(parts)-1]
			if invalidTLDs[tld] {
				continue
			}
		}

		// Skip common CDN domains
		if isCommonCDN(clean) {
			continue
		}

		// Skip if it looks like a JS method call (contains parentheses nearby in original code)
		idx := strings.Index(code, match)
		if idx >= 0 && idx+len(match) < len(code) {
			// Check if followed by ( which indicates a method call
			nextChars := code[idx+len(match):]
			if len(nextChars) > 0 && (nextChars[0] == '(' || nextChars[0] == '[') {
				continue
			}
		}

		// Skip very short potential false positives (e.g., "a.bc")
		if len(clean) < 5 {
			continue
		}

		if !seen[clean] {
			seen[clean] = true
			subdomains = append(subdomains, clean)
		}
	}

	sort.Strings(subdomains)
	return subdomains
}

// Method inference patterns (compiled once)
var (
	// Fetch API: fetch(url, { method: 'POST' })
	fetchMethodPattern = regexp.MustCompile(`fetch\s*\([^)]*["'\x60]([^"'\x60]+)["'\x60][^)]*method\s*:\s*["'\x60](\w+)["'\x60]`)
	// Axios: axios.post(url), axios({ method: 'post', url: ... })
	axiosMethodPattern = regexp.MustCompile(`axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(`)
	axiosConfigPattern = regexp.MustCompile(`axios\s*\(\s*\{[^}]*method\s*:\s*["'\x60](\w+)["'\x60]`)
	// jQuery: $.ajax({ type: 'POST', url: ... }), $.post(url)
	jqueryAjaxPattern      = regexp.MustCompile(`\$\s*\.\s*ajax\s*\(\s*\{[^}]*(?:type|method)\s*:\s*["'\x60](\w+)["'\x60]`)
	jqueryShorthandPattern = regexp.MustCompile(`\$\s*\.\s*(get|post|getJSON)\s*\(`)
	// XMLHttpRequest: xhr.open('POST', url)
	xhrOpenPattern = regexp.MustCompile(`\.open\s*\(\s*["'\x60](\w+)["'\x60]\s*,\s*["'\x60]([^"'\x60]+)["'\x60]`)
	// Angular HttpClient: http.post(url), this.http.get(url)
	angularHttpPattern = regexp.MustCompile(`\.http\s*\.\s*(get|post|put|patch|delete)\s*[<(]`)
	// Generic method assignment: method: 'POST', type: 'POST'
	methodAssignPattern = regexp.MustCompile(`(?:method|type)\s*[:=]\s*["'\x60](\w+)["'\x60]`)
)

// URL patterns that suggest specific methods
var urlMethodHints = map[string]string{
	// Create/Add operations -> POST
	"/create":      "POST",
	"/add":         "POST",
	"/new":         "POST",
	"/insert":      "POST",
	"/register":    "POST",
	"/signup":      "POST",
	"/signin":      "POST",
	"/login":       "POST",
	"/auth":        "POST",
	"/submit":      "POST",
	"/upload":      "POST",
	"/import":      "POST",
	"/send":        "POST",
	"/search":      "POST", // Often POST for complex search
	"/query":       "POST",
	"/filter":      "POST",
	"/validate":    "POST",
	"/verify":      "POST",
	"/check":       "POST",
	"/process":     "POST",
	"/execute":     "POST",
	"/run":         "POST",
	"/trigger":     "POST",
	"/invoke":      "POST",
	"/call":        "POST",
	"/batch":       "POST",
	"/bulk":        "POST",
	"/sync":        "POST",
	"/refresh":     "POST",
	"/regenerate":  "POST",
	"/reset":       "POST",
	"/revoke":      "POST",
	"/token":       "POST", // Token generation
	"/oauth":       "POST",
	"/authorize":   "POST",
	"/connect":     "POST",
	"/subscribe":   "POST",
	"/unsubscribe": "POST",
	"/notify":      "POST",
	"/publish":     "POST",
	"/message":     "POST",
	"/comment":     "POST",
	"/reply":       "POST",
	"/vote":        "POST",
	"/like":        "POST",
	"/share":       "POST",
	"/bookmark":    "POST",
	"/follow":      "POST",
	"/invite":      "POST",
	"/request":     "POST",
	"/approve":     "POST",
	"/reject":      "POST",
	"/cancel":      "POST",
	"/complete":    "POST",
	"/start":       "POST",
	"/stop":        "POST",
	"/enable":      "POST",
	"/disable":     "POST",
	"/activate":    "POST",
	"/deactivate":  "POST",
	"/archive":     "POST",
	"/restore":     "POST",
	"/clone":       "POST",
	"/copy":        "POST",
	"/move":        "POST",
	"/merge":       "POST",
	"/split":       "POST",
	"/export":      "POST",
	"/generate":    "POST",
	"/convert":     "POST",
	"/transform":   "POST",
	"/parse":       "POST",
	"/analyze":     "POST",
	"/calculate":   "POST",
	"/compute":     "POST",
	"/evaluate":    "POST",
	// GraphQL -> POST
	"/graphql": "POST",
	// Update operations -> PUT/PATCH
	"/update": "PUT",
	"/edit":   "PUT",
	"/modify": "PUT",
	"/save":   "PUT",
	"/set":    "PUT",
	"/patch":  "PATCH",
	// Delete operations -> DELETE
	"/delete":  "DELETE",
	"/remove":  "DELETE",
	"/destroy": "DELETE",
	"/clear":   "DELETE",
	"/purge":   "DELETE",
}

// Helper functions

func (a *Analyzer) inferMethod(code, url string) string {
	// 1. Try to find explicit method in fetch/axios/jQuery patterns near the URL
	if method := a.inferMethodFromContext(code, url); method != "" {
		return method
	}

	// 2. Try URL-based heuristics
	if method := a.inferMethodFromURL(url); method != "" {
		return method
	}

	// 3. Default to GET
	return "GET"
}

// inferMethodFromContext looks for HTTP method specifications near the URL
func (a *Analyzer) inferMethodFromContext(code, url string) string {
	// Find all occurrences of the URL
	urlIdx := strings.Index(code, url)
	if urlIdx == -1 {
		return ""
	}

	// Expand search window (300 chars before, 200 after for better coverage)
	start := urlIdx - 300
	if start < 0 {
		start = 0
	}
	end := urlIdx + len(url) + 200
	if end > len(code) {
		end = len(code)
	}

	context := code[start:end]
	contextLower := strings.ToLower(context)

	// Check for fetch with method option
	if matches := fetchMethodPattern.FindStringSubmatch(context); len(matches) > 2 {
		if strings.Contains(matches[1], url) || strings.Contains(url, matches[1]) {
			return strings.ToUpper(matches[2])
		}
	}

	// Check for axios.post(), axios.get(), etc.
	if matches := axiosMethodPattern.FindStringSubmatch(contextLower); len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}

	// Check for axios({ method: 'post' })
	if matches := axiosConfigPattern.FindStringSubmatch(context); len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}

	// Check for $.ajax({ type: 'POST' })
	if matches := jqueryAjaxPattern.FindStringSubmatch(context); len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}

	// Check for $.post(), $.get()
	if matches := jqueryShorthandPattern.FindStringSubmatch(contextLower); len(matches) > 1 {
		method := strings.ToUpper(matches[1])
		if method == "GETJSON" {
			return "GET"
		}
		return method
	}

	// Check for xhr.open('POST', url)
	if matches := xhrOpenPattern.FindStringSubmatch(context); len(matches) > 2 {
		if strings.Contains(matches[2], url) || strings.Contains(url, matches[2]) {
			return strings.ToUpper(matches[1])
		}
	}

	// Check for Angular http.post()
	if matches := angularHttpPattern.FindStringSubmatch(contextLower); len(matches) > 1 {
		return strings.ToUpper(matches[1])
	}

	// Look for generic method/type assignment near the URL
	if matches := methodAssignPattern.FindStringSubmatch(context); len(matches) > 1 {
		method := strings.ToUpper(matches[1])
		if isValidHTTPMethod(method) {
			return method
		}
	}

	// Final fallback: check for method keywords in context
	methodKeywords := []struct {
		keyword string
		method  string
	}{
		{"\"post\"", "POST"},
		{"'post'", "POST"},
		{"`post`", "POST"},
		{"\"put\"", "PUT"},
		{"'put'", "PUT"},
		{"`put`", "PUT"},
		{"\"patch\"", "PATCH"},
		{"'patch'", "PATCH"},
		{"`patch`", "PATCH"},
		{"\"delete\"", "DELETE"},
		{"'delete'", "DELETE"},
		{"`delete`", "DELETE"},
		{".post(", "POST"},
		{".put(", "PUT"},
		{".patch(", "PATCH"},
		{".delete(", "DELETE"},
	}

	for _, mk := range methodKeywords {
		if strings.Contains(contextLower, mk.keyword) {
			return mk.method
		}
	}

	return ""
}

// inferMethodFromURL uses URL patterns to guess the HTTP method
func (a *Analyzer) inferMethodFromURL(url string) string {
	urlLower := strings.ToLower(url)

	// Check for exact path segment matches
	for pattern, method := range urlMethodHints {
		patternWithoutSlash := strings.TrimPrefix(pattern, "/")
		// Check if URL contains the pattern as a path segment
		if strings.Contains(urlLower, pattern+"/") ||
			strings.Contains(urlLower, pattern+"?") ||
			strings.HasSuffix(urlLower, pattern) {
			return method
		}
		// Check for hyphenated patterns like "enterprise-search"
		if strings.HasSuffix(urlLower, "-"+patternWithoutSlash) ||
			strings.Contains(urlLower, "-"+patternWithoutSlash+"/") ||
			strings.Contains(urlLower, "-"+patternWithoutSlash+"?") {
			return method
		}
	}

	// Check for RESTful patterns
	// e.g., /api/users/{id} with context might be PUT/DELETE
	// /api/users might be GET (list) or POST (create)

	// Check for action verbs in the path
	pathParts := strings.Split(urlLower, "/")
	for _, part := range pathParts {
		// Remove query params if present
		if idx := strings.Index(part, "?"); idx != -1 {
			part = part[:idx]
		}

		for pattern, method := range urlMethodHints {
			patternWithoutSlash := strings.TrimPrefix(pattern, "/")
			// Match the pattern without leading slash
			if part == patternWithoutSlash {
				return method
			}
			// Also check if part ends with the pattern (e.g., "user-login", "api-search")
			if strings.HasSuffix(part, "-"+patternWithoutSlash) {
				return method
			}
		}
	}

	return ""
}

// isValidHTTPMethod checks if the string is a valid HTTP method
func isValidHTTPMethod(method string) bool {
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
		"CONNECT": true,
	}
	return validMethods[method]
}

func (a *Analyzer) extractParams(url string) []string {
	var params []string

	// Query parameters
	if idx := strings.Index(url, "?"); idx != -1 {
		query := url[idx+1:]
		pairs := strings.Split(query, "&")
		for _, pair := range pairs {
			if idx := strings.Index(pair, "="); idx != -1 {
				params = append(params, pair[:idx])
			} else if pair != "" {
				params = append(params, pair)
			}
		}
	}

	// Path parameters (e.g., :id, {id})
	pathParamRE := regexcache.MustGet(`[:{}]([a-zA-Z_][a-zA-Z0-9_]*)`)
	matches := pathParamRE.FindAllStringSubmatch(url, -1)
	for _, m := range matches {
		if len(m) > 1 {
			params = append(params, m[1])
		}
	}

	return params
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func serviceCategory(service string) string {
	awsServices := []string{"s3", "s3_path", "cloudfront", "api_gateway", "lambda", "cognito"}
	gcpServices := []string{"gcs", "firebase", "firebase_stor", "cloud_run", "cloud_function"}
	azureServices := []string{"azure_blob", "azure_web", "azure_cdn"}

	for _, s := range awsServices {
		if service == s {
			return "aws"
		}
	}
	for _, s := range gcpServices {
		if service == s {
			return "gcp"
		}
	}
	for _, s := range azureServices {
		if service == s {
			return "azure"
		}
	}

	return service
}

func isCommonCDN(domain string) bool {
	cdnDomains := []string{
		"googleapis.com", "gstatic.com", "cloudflare.com",
		"jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
		"bootstrapcdn.com", "jquery.com", "fontawesome.com",
		"fonts.googleapis.com", "ajax.googleapis.com",
	}

	for _, cdn := range cdnDomains {
		if strings.HasSuffix(domain, cdn) {
			return true
		}
	}
	return false
}

// ToJSON converts extracted data to JSON
func (d *ExtractedData) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// Summary returns a text summary of extracted data
func (d *ExtractedData) Summary() string {
	sb := bufpool.GetString()
	defer bufpool.PutString(sb)
	sb.WriteString("=== JavaScript Analysis Summary ===\n")
	sb.WriteString(fmt.Sprintf("URLs: %d\n", len(d.URLs)))
	sb.WriteString(fmt.Sprintf("Endpoints: %d\n", len(d.Endpoints)))
	sb.WriteString(fmt.Sprintf("Secrets: %d\n", len(d.Secrets)))
	sb.WriteString(fmt.Sprintf("DOM Sinks: %d\n", len(d.DOMSinks)))
	sb.WriteString(fmt.Sprintf("Cloud URLs: %d\n", len(d.CloudURLs)))
	sb.WriteString(fmt.Sprintf("Subdomains: %d\n", len(d.Subdomains)))
	return sb.String()
}

// Need fmt for Summary
var fmt = struct {
	Sprintf func(format string, a ...interface{}) string
}{
	Sprintf: func(format string, a ...interface{}) string {
		// Simple implementation for Summary
		result := format
		for _, arg := range a {
			switch v := arg.(type) {
			case int:
				idx := strings.Index(result, "%d")
				if idx >= 0 {
					numStr := intToString(v)
					result = result[:idx] + numStr + result[idx+2:]
				}
			case string:
				idx := strings.Index(result, "%s")
				if idx >= 0 {
					result = result[:idx] + v + result[idx+2:]
				}
			}
		}
		return result
	},
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + intToString(-n)
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
