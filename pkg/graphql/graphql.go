// Package graphql provides GraphQL security testing capabilities.
// It supports introspection, query depth attacks, batch query attacks,
// field/directive enumeration, injection testing, and DoS detection.
package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/ui"
)

// AttackType represents different GraphQL attack types
type AttackType string

const (
	AttackIntrospection     AttackType = "introspection"      // Schema introspection
	AttackDepth             AttackType = "query_depth"        // Deep nested queries
	AttackBatch             AttackType = "batch_query"        // Batched queries
	AttackFieldDuplication  AttackType = "field_duplication"  // Field duplication
	AttackCircularFragments AttackType = "circular_fragments" // Circular fragment references
	AttackDirectiveOverload AttackType = "directive_overload" // Directive abuse
	AttackAlias             AttackType = "alias_abuse"        // Alias-based attacks
	AttackInjection         AttackType = "injection"          // SQL/NoSQL injection via GraphQL
	AttackFieldSuggestion   AttackType = "field_suggestion"   // Field name enumeration
	AttackIDOR              AttackType = "idor"               // Insecure Direct Object Reference
)

// Severity represents the severity of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Request represents a GraphQL request
type Request struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

// Response represents a GraphQL response
type Response struct {
	Data   json.RawMessage `json:"data,omitempty"`
	Errors []Error         `json:"errors,omitempty"`
}

// Error represents a GraphQL error
type Error struct {
	Message    string                 `json:"message"`
	Locations  []Location             `json:"locations,omitempty"`
	Path       []interface{}          `json:"path,omitempty"`
	Extensions map[string]interface{} `json:"extensions,omitempty"`
}

// Location represents the location of an error
type Location struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Schema represents a GraphQL schema from introspection
type Schema struct {
	QueryType        *TypeRef    `json:"queryType"`
	MutationType     *TypeRef    `json:"mutationType"`
	SubscriptionType *TypeRef    `json:"subscriptionType"`
	Types            []Type      `json:"types"`
	Directives       []Directive `json:"directives"`
}

// TypeRef represents a reference to a type
type TypeRef struct {
	Name string `json:"name"`
}

// Type represents a GraphQL type
type Type struct {
	Kind          string       `json:"kind"`
	Name          string       `json:"name"`
	Description   string       `json:"description,omitempty"`
	Fields        []Field      `json:"fields,omitempty"`
	InputFields   []InputValue `json:"inputFields,omitempty"`
	Interfaces    []TypeRef    `json:"interfaces,omitempty"`
	EnumValues    []EnumValue  `json:"enumValues,omitempty"`
	PossibleTypes []TypeRef    `json:"possibleTypes,omitempty"`
}

// Field represents a GraphQL field
type Field struct {
	Name              string       `json:"name"`
	Description       string       `json:"description,omitempty"`
	Args              []InputValue `json:"args,omitempty"`
	Type              FieldType    `json:"type"`
	IsDeprecated      bool         `json:"isDeprecated"`
	DeprecationReason string       `json:"deprecationReason,omitempty"`
}

// FieldType represents a field's type information
type FieldType struct {
	Kind   string     `json:"kind"`
	Name   string     `json:"name,omitempty"`
	OfType *FieldType `json:"ofType,omitempty"`
}

// InputValue represents an input value
type InputValue struct {
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Type         FieldType `json:"type"`
	DefaultValue string    `json:"defaultValue,omitempty"`
}

// EnumValue represents an enum value
type EnumValue struct {
	Name              string `json:"name"`
	Description       string `json:"description,omitempty"`
	IsDeprecated      bool   `json:"isDeprecated"`
	DeprecationReason string `json:"deprecationReason,omitempty"`
}

// Directive represents a GraphQL directive
type Directive struct {
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Locations   []string     `json:"locations"`
	Args        []InputValue `json:"args,omitempty"`
}

// Vulnerability represents a detected GraphQL vulnerability
type Vulnerability struct {
	Type        AttackType `json:"type"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Query       string     `json:"query"`
	Evidence    string     `json:"evidence"`
	Remediation string     `json:"remediation"`
	ConfirmedBy int        `json:"confirmed_by,omitempty"`
}

// TesterConfig configures the GraphQL tester
type TesterConfig struct {
	Timeout         time.Duration
	Headers         http.Header
	Cookies         []*http.Cookie
	UserAgent       string
	MaxDepth        int  // Maximum query depth to test
	MaxBatchSize    int  // Maximum batch size to test
	SafeMode        bool // Only use safe detection methods
	FollowRedirects bool
	Proxy           string
}

// DefaultConfig returns a default tester configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:         duration.HTTPFuzzing,
		UserAgent:       ui.UserAgentWithContext("GraphQL Tester"),
		MaxDepth:        defaults.DepthGraphQL,
		MaxBatchSize:    100,
		SafeMode:        true,
		FollowRedirects: true,
	}
}

// Tester performs GraphQL security testing
type Tester struct {
	config   *TesterConfig
	client   *http.Client
	endpoint string
	schema   *Schema
}

// NewTester creates a new GraphQL tester
func NewTester(endpoint string, config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	client := httpclient.New(httpclient.WithTimeout(config.Timeout))

	if !config.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	return &Tester{
		config:   config,
		client:   client,
		endpoint: endpoint,
	}
}

// SendQuery sends a GraphQL query and returns the response
func (t *Tester) SendQuery(ctx context.Context, query string, variables map[string]interface{}) (*Response, int, error) {
	req := Request{
		Query:     query,
		Variables: variables,
	}

	return t.sendRequest(ctx, req)
}

// SendBatchQuery sends a batch of GraphQL queries
func (t *Tester) SendBatchQuery(ctx context.Context, queries []Request) ([]Response, int, error) {
	body, err := json.Marshal(queries)
	if err != nil {
		return nil, 0, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}

	t.setHeaders(httpReq)

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	respBody, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	var responses []Response
	if err := json.Unmarshal(respBody, &responses); err != nil {
		// Try single response
		var single Response
		if err2 := json.Unmarshal(respBody, &single); err2 != nil {
			return nil, resp.StatusCode, err
		}
		return []Response{single}, resp.StatusCode, nil
	}

	return responses, resp.StatusCode, nil
}

func (t *Tester) sendRequest(ctx context.Context, req Request) (*Response, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}

	t.setHeaders(httpReq)

	resp, err := t.client.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	respBody, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	var gqlResp Response
	if err := json.Unmarshal(respBody, &gqlResp); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("invalid GraphQL response: %s", string(respBody))
	}

	return &gqlResp, resp.StatusCode, nil
}

func (t *Tester) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", t.config.UserAgent)

	for key, values := range t.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	for _, cookie := range t.config.Cookies {
		req.AddCookie(cookie)
	}
}

// TestIntrospection tests if introspection is enabled
func (t *Tester) TestIntrospection(ctx context.Context) (*Vulnerability, *Schema, error) {
	// Full introspection query
	query := IntrospectionQuery()

	// Retry introspection with backoff for rate limiting / temporary errors
	var resp *Response
	var statusCode int
	var err error
	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt) * time.Second
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		resp, statusCode, err = t.SendQuery(ctx, query, nil)
		if err == nil && statusCode != http.StatusTooManyRequests && statusCode != http.StatusServiceUnavailable {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}

	if statusCode != 200 {
		return nil, nil, fmt.Errorf("introspection returned status %d", statusCode)
	}

	if len(resp.Errors) > 0 {
		// Check if introspection is disabled
		for _, e := range resp.Errors {
			if strings.Contains(strings.ToLower(e.Message), "introspection") {
				return nil, nil, nil // Introspection disabled - good!
			}
		}
		return nil, nil, fmt.Errorf("GraphQL errors: %v", resp.Errors)
	}

	// Parse schema from response
	var result struct {
		Schema *Schema `json:"__schema"`
	}

	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, nil, err
	}

	if result.Schema == nil {
		return nil, nil, nil
	}

	t.schema = result.Schema

	vuln := &Vulnerability{
		Type:        AttackIntrospection,
		Description: "GraphQL introspection is enabled, exposing the entire schema",
		Severity:    SeverityMedium,
		Query:       query,
		Evidence:    fmt.Sprintf("Schema contains %d types", len(result.Schema.Types)),
		Remediation: "Disable introspection in production. Use schema masking or access control.",
	}

	return vuln, result.Schema, nil
}

// IntrospectionQuery returns the full introspection query
func IntrospectionQuery() string {
	return `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
          defaultValue
        }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        defaultValue
      }
      interfaces { name }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { name }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type { kind name ofType { kind name ofType { kind name } } }
        defaultValue
      }
    }
  }
}`
}

// TestDepthAttack tests for query depth vulnerabilities
func (t *Tester) TestDepthAttack(ctx context.Context, fieldName string, depth int) (*Vulnerability, error) {
	if depth > t.config.MaxDepth {
		depth = t.config.MaxDepth
	}

	// Generate nested query
	query := generateDeepQuery(fieldName, depth)

	start := time.Now()
	resp, statusCode, err := t.SendQuery(ctx, query, nil)
	elapsed := time.Since(start)

	if err != nil {
		// Check if it's a timeout (potential DoS)
		if strings.Contains(err.Error(), "timeout") {
			return &Vulnerability{
				Type:        AttackDepth,
				Description: fmt.Sprintf("Server timed out on query with depth %d (potential DoS)", depth),
				Severity:    SeverityHigh,
				Query:       query,
				Evidence:    fmt.Sprintf("Request timed out after %v", elapsed),
				Remediation: "Implement query depth limiting and query cost analysis.",
			}, nil
		}
		return nil, err
	}

	// Check if deep query was accepted
	if statusCode == 200 && len(resp.Errors) == 0 {
		return &Vulnerability{
			Type:        AttackDepth,
			Description: fmt.Sprintf("Server accepted query with depth %d without rate limiting", depth),
			Severity:    SeverityMedium,
			Query:       query,
			Evidence:    fmt.Sprintf("Query executed in %v", elapsed),
			Remediation: "Implement query depth limiting. Reject queries exceeding maximum depth.",
		}, nil
	}

	// Check error messages for depth-related rejections
	for _, e := range resp.Errors {
		if strings.Contains(strings.ToLower(e.Message), "depth") ||
			strings.Contains(strings.ToLower(e.Message), "complexity") {
			return nil, nil // Good - depth limiting is in place
		}
	}

	return nil, nil
}

func generateDeepQuery(fieldName string, depth int) string {
	if fieldName == "" {
		fieldName = "node"
	}

	var sb strings.Builder
	sb.WriteString("query DepthTest { ")

	for i := 0; i < depth; i++ {
		sb.WriteString(fieldName)
		sb.WriteString(" { ")
	}

	sb.WriteString("id")

	for i := 0; i < depth; i++ {
		sb.WriteString(" }")
	}

	sb.WriteString(" }")

	return sb.String()
}

// TestBatchAttack tests for batch query vulnerabilities
func (t *Tester) TestBatchAttack(ctx context.Context, batchSize int) (*Vulnerability, error) {
	if batchSize > t.config.MaxBatchSize {
		batchSize = t.config.MaxBatchSize
	}

	// Create batch of queries
	queries := make([]Request, batchSize)
	for i := 0; i < batchSize; i++ {
		queries[i] = Request{
			Query:         fmt.Sprintf("query Batch%d { __typename }", i),
			OperationName: fmt.Sprintf("Batch%d", i),
		}
	}

	start := time.Now()
	responses, statusCode, err := t.SendBatchQuery(ctx, queries)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return &Vulnerability{
				Type:        AttackBatch,
				Description: fmt.Sprintf("Server timed out on batch of %d queries (potential DoS)", batchSize),
				Severity:    SeverityHigh,
				Query:       fmt.Sprintf("[%d queries]", batchSize),
				Evidence:    fmt.Sprintf("Request timed out after %v", elapsed),
				Remediation: "Implement batch query limiting. Reject batches exceeding maximum size.",
			}, nil
		}
		return nil, err
	}

	// Check if batch was accepted
	if statusCode == 200 && len(responses) == batchSize {
		return &Vulnerability{
			Type:        AttackBatch,
			Description: fmt.Sprintf("Server accepted batch of %d queries without limiting", batchSize),
			Severity:    SeverityMedium,
			Query:       fmt.Sprintf("[%d queries]", batchSize),
			Evidence:    fmt.Sprintf("All %d queries executed in %v", batchSize, elapsed),
			Remediation: "Implement batch query limiting and rate limiting.",
		}, nil
	}

	return nil, nil
}

// TestAliasAbuse tests for alias-based DoS attacks
func (t *Tester) TestAliasAbuse(ctx context.Context, fieldName string, aliasCount int) (*Vulnerability, error) {
	query := generateAliasQuery(fieldName, aliasCount)

	start := time.Now()
	resp, statusCode, err := t.SendQuery(ctx, query, nil)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return &Vulnerability{
				Type:        AttackAlias,
				Description: fmt.Sprintf("Server timed out with %d field aliases (potential DoS)", aliasCount),
				Severity:    SeverityHigh,
				Query:       query,
				Evidence:    fmt.Sprintf("Request timed out after %v", elapsed),
				Remediation: "Implement query complexity analysis that accounts for aliases.",
			}, nil
		}
		return nil, err
	}

	if statusCode == 200 && len(resp.Errors) == 0 {
		return &Vulnerability{
			Type:        AttackAlias,
			Description: fmt.Sprintf("Server executed query with %d aliases without limiting", aliasCount),
			Severity:    SeverityMedium,
			Query:       query,
			Evidence:    fmt.Sprintf("Query executed in %v", elapsed),
			Remediation: "Include alias count in query cost calculation.",
		}, nil
	}

	return nil, nil
}

func generateAliasQuery(fieldName string, count int) string {
	if fieldName == "" {
		fieldName = "__typename"
	}

	var sb strings.Builder
	sb.WriteString("query AliasTest { ")

	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "alias%d: %s ", i, fieldName)
	}

	sb.WriteString("}")

	return sb.String()
}

// TestFieldSuggestion tests for field name enumeration via suggestions
func (t *Tester) TestFieldSuggestion(ctx context.Context) (*Vulnerability, []string, error) {
	// Try various typos to trigger field suggestions
	testQueries := []string{
		"{ usr }", // user?
		"{ usr { nam } }",
		"{ passw }", // password?
		"{ admi }",  // admin?
		"{ secre }", // secret?
		"{ toke }",  // token?
	}

	var suggestions []string
	suggestionRegex := regexcache.MustGet(`(?i)did you mean ['"]([\w]+)['"]`)

	for _, query := range testQueries {
		resp, _, err := t.SendQuery(ctx, query, nil)
		if err != nil {
			continue
		}

		for _, e := range resp.Errors {
			matches := suggestionRegex.FindAllStringSubmatch(e.Message, -1)
			for _, match := range matches {
				if len(match) > 1 {
					suggestions = append(suggestions, match[1])
				}
			}
		}
	}

	if len(suggestions) > 0 {
		return &Vulnerability{
			Type:        AttackFieldSuggestion,
			Description: "GraphQL error messages reveal valid field names via suggestions",
			Severity:    SeverityLow,
			Query:       testQueries[0],
			Evidence:    fmt.Sprintf("Discovered fields: %v", suggestions),
			Remediation: "Disable field suggestions in production. Use generic error messages.",
		}, suggestions, nil
	}

	return nil, nil, nil
}

// TestInjection tests for injection vulnerabilities in variables
func (t *Tester) TestInjection(ctx context.Context, queryTemplate string, variableName string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	injectionPayloads := getInjectionPayloads()

	for _, payload := range injectionPayloads {
		variables := map[string]interface{}{
			variableName: payload.Value,
		}

		resp, _, err := t.SendQuery(ctx, queryTemplate, variables)
		if err != nil {
			continue
		}

		// Check for signs of injection
		if t.analyzeInjectionResponse(resp, payload) {
			vulns = append(vulns, &Vulnerability{
				Type:        AttackInjection,
				Description: fmt.Sprintf("Potential %s injection via GraphQL variable", payload.Type),
				Severity:    SeverityHigh,
				Query:       queryTemplate,
				Evidence:    fmt.Sprintf("Payload: %s, Response indicates injection", payload.Value),
				Remediation: "Sanitize and validate all input. Use parameterized queries for database operations.",
			})
		}
	}

	return vulns, nil
}

type injectionPayload struct {
	Type  string
	Value string
}

func getInjectionPayloads() []injectionPayload {
	return []injectionPayload{
		// SQL injection
		{Type: "SQL", Value: "' OR '1'='1"},
		{Type: "SQL", Value: "'; DROP TABLE users; --"},
		{Type: "SQL", Value: "1 UNION SELECT * FROM users"},
		{Type: "SQL", Value: "1; WAITFOR DELAY '0:0:5'--"},

		// NoSQL injection
		{Type: "NoSQL", Value: `{"$gt": ""}`},
		{Type: "NoSQL", Value: `{"$ne": null}`},
		{Type: "NoSQL", Value: `{"$regex": ".*"}`},

		// Command injection
		{Type: "Command", Value: "; id"},
		{Type: "Command", Value: "| cat /etc/passwd"},
		{Type: "Command", Value: "`id`"},
		{Type: "Command", Value: "$(whoami)"},

		// Path traversal
		{Type: "PathTraversal", Value: "../../../etc/passwd"},
		{Type: "PathTraversal", Value: "....//....//etc/passwd"},

		// LDAP injection
		{Type: "LDAP", Value: "*)(uid=*))(|(uid=*"},
		{Type: "LDAP", Value: "admin)(&)"},

		// XSS (if response is rendered)
		{Type: "XSS", Value: "<script>alert(1)</script>"},
		{Type: "XSS", Value: "javascript:alert(1)"},
	}
}

func (t *Tester) analyzeInjectionResponse(resp *Response, payload injectionPayload) bool {
	if resp == nil {
		return false
	}

	// Check for error messages that indicate injection
	for _, e := range resp.Errors {
		msg := strings.ToLower(e.Message)

		// SQL injection indicators
		if payload.Type == "SQL" {
			if strings.Contains(msg, "sql") ||
				strings.Contains(msg, "syntax") ||
				strings.Contains(msg, "query") ||
				strings.Contains(msg, "select") ||
				strings.Contains(msg, "table") {
				return true
			}
		}

		// NoSQL injection indicators
		if payload.Type == "NoSQL" {
			if strings.Contains(msg, "mongodb") ||
				strings.Contains(msg, "bson") ||
				strings.Contains(msg, "operator") {
				return true
			}
		}

		// Command injection indicators
		if payload.Type == "Command" {
			if strings.Contains(msg, "command") ||
				strings.Contains(msg, "exec") ||
				strings.Contains(msg, "shell") {
				return true
			}
		}
	}

	// Check response data for injection evidence
	if resp.Data != nil {
		dataStr := string(resp.Data)

		// Check for command output
		if strings.Contains(dataStr, "uid=") ||
			strings.Contains(dataStr, "root:") ||
			strings.Contains(dataStr, "/bin/") {
			return true
		}
	}

	return false
}

// TestIDOR tests for Insecure Direct Object Reference
func (t *Tester) TestIDOR(ctx context.Context, queryTemplate string, idParam string, testIDs []string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	for _, id := range testIDs {
		variables := map[string]interface{}{
			idParam: id,
		}

		resp, statusCode, err := t.SendQuery(ctx, queryTemplate, variables)
		if err != nil {
			continue
		}

		// Check if we got data for IDs we shouldn't have access to
		if statusCode == 200 && len(resp.Errors) == 0 && len(resp.Data) > 2 { // More than "{}"
			vulns = append(vulns, &Vulnerability{
				Type:        AttackIDOR,
				Description: fmt.Sprintf("Potential IDOR - able to access object with ID: %s", id),
				Severity:    SeverityHigh,
				Query:       queryTemplate,
				Evidence:    fmt.Sprintf("Successfully retrieved data for ID: %s", id),
				Remediation: "Implement proper authorization checks. Verify object ownership before returning data.",
			})
		}
	}

	return vulns, nil
}

// TestDirectiveOverload tests for directive-based DoS
func (t *Tester) TestDirectiveOverload(ctx context.Context, directiveCount int) (*Vulnerability, error) {
	query := generateDirectiveQuery(directiveCount)

	start := time.Now()
	resp, statusCode, err := t.SendQuery(ctx, query, nil)
	elapsed := time.Since(start)

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			return &Vulnerability{
				Type:        AttackDirectiveOverload,
				Description: fmt.Sprintf("Server timed out with %d directives (potential DoS)", directiveCount),
				Severity:    SeverityHigh,
				Query:       query,
				Evidence:    fmt.Sprintf("Request timed out after %v", elapsed),
				Remediation: "Limit directive usage per query. Implement query cost analysis.",
			}, nil
		}
		return nil, err
	}

	if statusCode == 200 && len(resp.Errors) == 0 {
		return &Vulnerability{
			Type:        AttackDirectiveOverload,
			Description: fmt.Sprintf("Server accepted query with %d directives", directiveCount),
			Severity:    SeverityLow,
			Query:       query,
			Evidence:    fmt.Sprintf("Query executed in %v", elapsed),
			Remediation: "Limit directive usage in queries.",
		}, nil
	}

	return nil, nil
}

func generateDirectiveQuery(count int) string {
	var sb strings.Builder
	sb.WriteString("query DirectiveTest { __typename ")

	for i := 0; i < count; i++ {
		sb.WriteString("@skip(if: false) ")
	}

	sb.WriteString("}")

	return sb.String()
}

// ScanResult represents the complete scan result
type ScanResult struct {
	Endpoint        string           `json:"endpoint"`
	Schema          *Schema          `json:"schema,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	Duration        time.Duration    `json:"duration"`
	QueriesSent     int              `json:"queries_sent"`
}

// FullScan performs a comprehensive security scan
func (t *Tester) FullScan(ctx context.Context) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{
		Endpoint: t.endpoint,
	}

	var queriesSent int

	// Test introspection
	if vuln, schema, err := t.TestIntrospection(ctx); err == nil {
		queriesSent++
		if vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
		result.Schema = schema
	}

	// Test depth attack
	for _, depth := range []int{10, 15, 20} {
		if vuln, err := t.TestDepthAttack(ctx, "node", depth); err == nil && vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			break // Found vulnerability, no need to test deeper
		}
		queriesSent++
	}

	// Test batch attack
	for _, size := range []int{10, 50, 100} {
		if vuln, err := t.TestBatchAttack(ctx, size); err == nil && vuln != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			break
		}
		queriesSent++
	}

	// Test alias abuse
	if vuln, err := t.TestAliasAbuse(ctx, "__typename", 100); err == nil && vuln != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}
	queriesSent++

	// Test field suggestion
	if vuln, _, err := t.TestFieldSuggestion(ctx); err == nil && vuln != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}
	queriesSent += 6 // Multiple queries in TestFieldSuggestion

	// Test directive overload
	if vuln, err := t.TestDirectiveOverload(ctx, 50); err == nil && vuln != nil {
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}
	queriesSent++

	result.Duration = time.Since(start)
	result.QueriesSent = queriesSent

	return result, nil
}

// Utilities

// ExtractTypesFromSchema extracts type names from a schema
func ExtractTypesFromSchema(schema *Schema) []string {
	var types []string
	for _, t := range schema.Types {
		if !strings.HasPrefix(t.Name, "__") { // Skip introspection types
			types = append(types, t.Name)
		}
	}
	return types
}

// ExtractFieldsFromType extracts field names from a type
func ExtractFieldsFromType(schema *Schema, typeName string) []string {
	var fields []string
	for _, t := range schema.Types {
		if t.Name == typeName {
			for _, f := range t.Fields {
				fields = append(fields, f.Name)
			}
			break
		}
	}
	return fields
}

// ExtractMutations extracts mutation names from a schema
func ExtractMutations(schema *Schema) []string {
	if schema.MutationType == nil {
		return nil
	}
	return ExtractFieldsFromType(schema, schema.MutationType.Name)
}

// ExtractQueries extracts query names from a schema
func ExtractQueries(schema *Schema) []string {
	if schema.QueryType == nil {
		return nil
	}
	return ExtractFieldsFromType(schema, schema.QueryType.Name)
}

// FindSensitiveFields finds potentially sensitive fields in the schema
func FindSensitiveFields(schema *Schema) []string {
	sensitivePatterns := []string{
		"password", "passwd", "secret", "token", "key", "api_key", "apikey",
		"credential", "auth", "private", "internal", "admin", "ssn",
		"credit_card", "creditcard", "bank", "salary", "social_security",
	}

	var sensitive []string

	for _, t := range schema.Types {
		for _, f := range t.Fields {
			fieldLower := strings.ToLower(f.Name)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(fieldLower, pattern) {
					sensitive = append(sensitive, fmt.Sprintf("%s.%s", t.Name, f.Name))
				}
			}
		}
	}

	return sensitive
}

// GenerateQueryForType generates a sample query for a type
func GenerateQueryForType(schema *Schema, typeName string, maxDepth int) string {
	var sb strings.Builder
	sb.WriteString("query { ")

	visited := make(map[string]bool)
	generateFieldQuery(&sb, schema, typeName, 0, maxDepth, visited)

	sb.WriteString(" }")

	return sb.String()
}

func generateFieldQuery(sb *strings.Builder, schema *Schema, typeName string, depth int, maxDepth int, visited map[string]bool) {
	if depth >= maxDepth || visited[typeName] {
		sb.WriteString("__typename")
		return
	}
	visited[typeName] = true

	for _, t := range schema.Types {
		if t.Name == typeName {
			for i, f := range t.Fields {
				if i > 0 {
					sb.WriteString(" ")
				}
				sb.WriteString(f.Name)

				// Get nested type
				nestedType := getBaseTypeName(f.Type)
				if nestedType != "" && !isScalarType(nestedType) {
					sb.WriteString(" { ")
					generateFieldQuery(sb, schema, nestedType, depth+1, maxDepth, visited)
					sb.WriteString(" }")
				}
			}
			break
		}
	}
}

func getBaseTypeName(ft FieldType) string {
	if ft.Name != "" {
		return ft.Name
	}
	if ft.OfType != nil {
		return getBaseTypeName(*ft.OfType)
	}
	return ""
}

func isScalarType(name string) bool {
	scalars := map[string]bool{
		"String": true, "Int": true, "Float": true, "Boolean": true, "ID": true,
		"DateTime": true, "Date": true, "Time": true, "JSON": true,
	}
	return scalars[name]
}
