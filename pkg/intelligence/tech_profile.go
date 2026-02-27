// Package intelligence provides adaptive learning capabilities for WAFtester.
// TechProfile detects and tracks the target's technology stack for vulnerability correlation.
package intelligence

import (
	"strings"
	"sync"
)

// TechProfile detects and tracks the target's technology stack
type TechProfile struct {
	mu sync.RWMutex

	// Detected technologies
	frameworks []TechInfo
	databases  []TechInfo
	servers    []TechInfo
	languages  []TechInfo

	// Confidence scores
	scores map[string]float64
}

// TechInfo represents a detected technology
type TechInfo struct {
	Name                  string
	Version               string
	Description           string
	TestingRecommendation string
	Confidence            float64
}

// NewTechProfile creates a new technology profile
func NewTechProfile() *TechProfile {
	return &TechProfile{
		frameworks: make([]TechInfo, 0),
		databases:  make([]TechInfo, 0),
		servers:    make([]TechInfo, 0),
		languages:  make([]TechInfo, 0),
		scores:     make(map[string]float64),
	}
}

// Update processes a finding for technology indicators.
// Safe to call with nil finding (no-op).
// Only uses Evidence (response headers/body) and Path for detection — NOT the
// Payload field, because attack payloads contain framework/database keywords
// (e.g., "mysql", "python", ".js") that would cause every technology to be
// falsely detected.
func (t *TechProfile) Update(f *Finding) {
	if f == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	// Only use evidence and path — payload is attacker-controlled content
	// and should not influence tech stack detection.
	content := strings.ToLower(f.Evidence + " " + f.Path)

	// Detect frameworks
	t.detectFrameworks(content)

	// Detect databases
	t.detectDatabases(content)

	// Detect servers
	t.detectServers(content)

	// Detect languages
	t.detectLanguages(content)
}

// Detect checks if a finding indicates a specific technology.
// Returns nil if f is nil or no technology detected.
// Only uses Evidence and Path — NOT Payload (see Update comment).
func (t *TechProfile) Detect(f *Finding) *TechInfo {
	if f == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	content := strings.ToLower(f.Evidence + " " + f.Path)

	// Check for new technology indicators
	for name, indicators := range frameworkIndicators {
		for _, ind := range indicators {
			if strings.Contains(content, ind) {
				existing := t.getScore(name)
				if existing < 0.5 { // Only return as new insight if not already detected
					tech := &TechInfo{
						Name:                  name,
						Description:           "Framework detected",
						TestingRecommendation: getFrameworkRecommendation(name),
						Confidence:            0.7,
					}
					t.addFramework(*tech)
					return tech
				}
			}
		}
	}

	return nil
}

// HasFramework checks if a framework is detected
func (t *TechProfile) HasFramework(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	nameLower := strings.ToLower(name)
	for _, fw := range t.frameworks {
		if strings.ToLower(fw.Name) == nameLower {
			return true
		}
	}
	return false
}

// HasDatabase checks if a database is detected
func (t *TechProfile) HasDatabase(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	nameLower := strings.ToLower(name)
	for _, db := range t.databases {
		if strings.ToLower(db.Name) == nameLower || strings.Contains(strings.ToLower(db.Name), nameLower) {
			return true
		}
	}
	return false
}

// GetDetected returns all detected technologies as strings
func (t *TechProfile) GetDetected() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]string, 0)
	for _, fw := range t.frameworks {
		result = append(result, "Framework: "+fw.Name)
	}
	for _, db := range t.databases {
		result = append(result, "Database: "+db.Name)
	}
	for _, srv := range t.servers {
		result = append(result, "Server: "+srv.Name)
	}
	for _, lang := range t.languages {
		result = append(result, "Language: "+lang.Name)
	}
	return result
}

func (t *TechProfile) detectFrameworks(content string) {
	for name, indicators := range frameworkIndicators {
		for _, ind := range indicators {
			if strings.Contains(content, ind) {
				t.addFramework(TechInfo{
					Name:                  name,
					Description:           "Detected via " + ind,
					TestingRecommendation: getFrameworkRecommendation(name),
					Confidence:            0.7,
				})
				break
			}
		}
	}
}

func (t *TechProfile) detectDatabases(content string) {
	for name, indicators := range databaseIndicators {
		for _, ind := range indicators {
			if strings.Contains(content, ind) {
				t.addDatabase(TechInfo{
					Name:                  name,
					Description:           "Detected via " + ind,
					TestingRecommendation: getDatabaseRecommendation(name),
					Confidence:            0.7,
				})
				break
			}
		}
	}
}

func (t *TechProfile) detectServers(content string) {
	for name, indicators := range serverIndicators {
		for _, ind := range indicators {
			if strings.Contains(content, ind) {
				t.addServer(TechInfo{
					Name:                  name,
					Description:           "Detected via " + ind,
					TestingRecommendation: getServerRecommendation(name),
					Confidence:            0.7,
				})
				break
			}
		}
	}
}

func (t *TechProfile) detectLanguages(content string) {
	for name, indicators := range languageIndicators {
		for _, ind := range indicators {
			if strings.Contains(content, ind) {
				t.addLanguage(TechInfo{
					Name:                  name,
					Description:           "Detected via " + ind,
					TestingRecommendation: getLanguageRecommendation(name),
					Confidence:            0.7,
				})
				break
			}
		}
	}
}

func (t *TechProfile) addFramework(tech TechInfo) {
	for _, existing := range t.frameworks {
		if existing.Name == tech.Name {
			return // Already exists
		}
	}
	t.frameworks = append(t.frameworks, tech)
	t.scores[tech.Name] = tech.Confidence
}

func (t *TechProfile) addDatabase(tech TechInfo) {
	for _, existing := range t.databases {
		if existing.Name == tech.Name {
			return
		}
	}
	t.databases = append(t.databases, tech)
	t.scores[tech.Name] = tech.Confidence
}

func (t *TechProfile) addServer(tech TechInfo) {
	for _, existing := range t.servers {
		if existing.Name == tech.Name {
			return
		}
	}
	t.servers = append(t.servers, tech)
	t.scores[tech.Name] = tech.Confidence
}

func (t *TechProfile) addLanguage(tech TechInfo) {
	for _, existing := range t.languages {
		if existing.Name == tech.Name {
			return
		}
	}
	t.languages = append(t.languages, tech)
	t.scores[tech.Name] = tech.Confidence
}

func (t *TechProfile) getScore(name string) float64 {
	if score, ok := t.scores[name]; ok {
		return score
	}
	return 0
}

// Technology indicators

var frameworkIndicators = map[string][]string{
	"django":    {"django", "csrfmiddlewaretoken", "wsgi", "__debug__"},
	"flask":     {"flask", "werkzeug", "jinja2"},
	"express":   {"express", "x-powered-by: express"},
	"node":      {"node", "nodejs", "__dirname"},
	"rails":     {"rails", "ruby on rails", "x-rails"},
	"laravel":   {"laravel", "x-powered-by: php", "csrf_token"},
	"spring":    {"spring", "springframework", "jsessionid"},
	"asp.net":   {"asp.net", "__viewstate", ".aspx"},
	"react":     {"react", "_reactroot", "data-reactid"},
	"angular":   {"angular", "ng-app", "ng-"},
	"vue":       {"vue", "v-for", "v-if", "v-model"},
	"nextjs":    {"next.js", "_next/", "__next"},
	"nuxt":      {"nuxt", "_nuxt/"},
	"fastapi":   {"fastapi", "starlette"},
	"graphql":   {"graphql", "__schema", "__typename"},
	"wordpress": {"wp-content", "wp-includes", "wordpress"},
	"drupal":    {"drupal", "sites/default"},
}

var databaseIndicators = map[string][]string{
	"mysql":         {"mysql", "mysqld", "mariadb"},
	"postgresql":    {"postgresql", "postgres", "pgsql"},
	"mongodb":       {"mongodb", "mongoose"},
	"redis":         {"redis-server", "redisdb"},
	"sqlite":        {"sqlite3", ".sqlite"},
	"oracle":        {"oracle", "ora-"},
	"mssql":         {"mssql", "sqlserver", "microsoft sql"},
	"elasticsearch": {"elasticsearch", "_search/scroll"},
	"dynamodb":      {"dynamodb", "aws.dynamodb"},
	"firebase":      {"firebase", "firestore"},
}

var serverIndicators = map[string][]string{
	"nginx":    {"nginx"},
	"apache":   {"apache", "httpd"},
	"iis":      {"iis", "microsoft-iis"},
	"tomcat":   {"tomcat", "catalina"},
	"gunicorn": {"gunicorn"},
	"caddy":    {"caddy"},
	"lighttpd": {"lighttpd"},
}

var languageIndicators = map[string][]string{
	"python": {"x-powered-by: python", "wsgi", "django", "flask"},
	"php":    {"x-powered-by: php", ".php"},
	"java":   {"x-powered-by: java", ".jsp", ".do", "jsessionid"},
	"ruby":   {"x-powered-by: ruby", ".rb", "x-rails"},
	"node":   {"x-powered-by: express", "x-powered-by: node"},
	"go":     {"x-powered-by: go", "x-powered-by: golang"},
	"dotnet": {"x-powered-by: asp.net", ".aspx", "__viewstate"},
}

func getFrameworkRecommendation(name string) string {
	recommendations := map[string]string{
		"django":    "Test for SSTI in Jinja2, Django debug pages, admin bypass",
		"flask":     "Test for SSTI, debug mode, Werkzeug debugger RCE",
		"express":   "Test for prototype pollution, path traversal, SSRF",
		"node":      "Test for prototype pollution, command injection",
		"rails":     "Test for mass assignment, deserialization, SSTI",
		"laravel":   "Test for insecure deserialization, debug mode info leak",
		"spring":    "Test for Spring4Shell, SpEL injection, actuator exposure",
		"graphql":   "Test for introspection, batching attacks, deeply nested queries",
		"wordpress": "Test for plugin vulnerabilities, xmlrpc, user enumeration",
	}
	if rec, ok := recommendations[name]; ok {
		return rec
	}
	return "Standard injection and bypass testing recommended"
}

func getDatabaseRecommendation(name string) string {
	recommendations := map[string]string{
		"mysql":      "Test for SQL injection with MySQL-specific syntax",
		"postgresql": "Test for SQL injection with PostgreSQL syntax, stacked queries",
		"mongodb":    "Test for NoSQL injection with $where, $regex operators",
		"redis":      "Test for Redis injection, SSRF to Redis",
		"mssql":      "Test for SQL injection with MSSQL syntax, xp_cmdshell",
	}
	if rec, ok := recommendations[name]; ok {
		return rec
	}
	return "Standard database injection testing recommended"
}

func getServerRecommendation(name string) string {
	recommendations := map[string]string{
		"nginx":  "Test for off-by-slash, alias misconfiguration, request smuggling",
		"apache": "Test for .htaccess bypass, mod_cgi, server-status exposure",
		"iis":    "Test for short filename disclosure, tilde enumeration",
		"tomcat": "Test for manager interface, AJP ghostcat",
	}
	if rec, ok := recommendations[name]; ok {
		return rec
	}
	return "Standard server misconfiguration testing recommended"
}

func getLanguageRecommendation(name string) string {
	recommendations := map[string]string{
		"python": "Test for SSTI (Jinja2), pickle deserialization, code injection",
		"php":    "Test for LFI/RFI, type juggling, deserialization",
		"java":   "Test for JNDI injection, deserialization, XXE",
		"ruby":   "Test for ERB SSTI, deserialization, command injection",
		"node":   "Test for prototype pollution, command injection, SSRF",
	}
	if rec, ok := recommendations[name]; ok {
		return rec
	}
	return "Standard language-specific injection testing recommended"
}
