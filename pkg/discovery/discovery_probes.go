// Package discovery - Form, WAF, API spec, and GraphQL probing
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

func (d *Discoverer) discoverForms(ctx context.Context, result *DiscoveryResult) {
	// Analyze HTML responses for forms
	for _, ep := range d.endpoints {
		if !strings.Contains(ep.ContentType, "html") {
			continue
		}

		fullURL := d.config.Target + ep.Path
		req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				iohelper.DrainAndClose(resp.Body)
			}
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, iohelper.DefaultMaxBodySize) // 1MB limit
		iohelper.DrainAndClose(resp.Body)

		forms := ExtractForms(string(body), d.config.Target)
		for _, form := range forms {
			// Add form action as an endpoint
			if form.Action != "" {
				formPath := extractPath(form.Action)
				if formPath != "" && !d.isExcluded(formPath) {
					// Create endpoint for form target
					formEndpoint := Endpoint{
						Path:       formPath,
						Method:     form.Method,
						StatusCode: 0, // Unknown until probed
						Service:    d.config.Service,
						Category:   "form",
					}

					// Add form fields as parameters
					for _, field := range form.Fields {
						formEndpoint.Parameters = append(formEndpoint.Parameters, Parameter{
							Name:     field.Name,
							Location: "body",
							Type:     field.Type,
							Required: field.Required,
						})
					}

					// Add risk factors
					if form.HasFile {
						formEndpoint.RiskFactors = append(formEndpoint.RiskFactors, "file_upload")
						result.AttackSurface.HasFileUpload = true
					}
					if form.IsLogin {
						formEndpoint.RiskFactors = append(formEndpoint.RiskFactors, "authentication")
						result.AttackSurface.HasAuthEndpoints = true
					}

					d.mu.Lock()
					d.endpoints = append(d.endpoints, formEndpoint)
					result.Statistics.ByCategory["form"]++
					d.mu.Unlock()
				}
			}
		}
	}
}

// detectWAF checks if a WAF is present
func (d *Discoverer) detectWAF(ctx context.Context, result *DiscoveryResult) {
	// Send a simple SQL injection to detect WAF
	testPayloads := []string{
		"?id=1' OR '1'='1",
		"?q=<script>alert(1)</script>",
		"?file=../../../etc/passwd",
	}

	for _, payload := range testPayloads {
		req, err := http.NewRequestWithContext(ctx, "GET", d.config.Target+payload, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}

		// Check for WAF signatures
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 418 || resp.StatusCode == 429 || resp.StatusCode == 503 {
			result.WAFDetected = true

			// Try to fingerprint
			server := resp.Header.Get("Server")
			if strings.Contains(strings.ToLower(server), "modsecurity") {
				result.WAFFingerprint = "ModSecurity"
			} else if strings.Contains(strings.ToLower(server), "coraza") {
				result.WAFFingerprint = "Coraza"
			} else if resp.Header.Get("X-CDN") != "" {
				result.WAFFingerprint = "CDN WAF (Cloudflare/AWS WAF)"
			}
			iohelper.DrainAndClose(resp.Body)
			break
		}
		iohelper.DrainAndClose(resp.Body)
	}
}

// probeKnownEndpoints tests service-specific endpoints
func (d *Discoverer) probeKnownEndpoints(ctx context.Context, result *DiscoveryResult) {
	var endpoints []string

	// Common endpoints for all services
	common := []string{
		"/",
		"/health",
		"/healthz",
		"/api/health",
		"/.well-known/security.txt",
		"/robots.txt",
		"/favicon.ico",
	}
	endpoints = append(endpoints, common...)

	// Service-specific endpoints
	switch strings.ToLower(d.config.Service) {
	case "authentik":
		endpoints = append(endpoints, getAuthentikEndpoints()...)
		result.AttackSurface.HasAuthEndpoints = true
		result.AttackSurface.HasOAuth = true
		result.AttackSurface.HasSAML = true
	case "n8n":
		endpoints = append(endpoints, getN8nEndpoints()...)
		result.AttackSurface.HasAPIEndpoints = true
		result.AttackSurface.HasWebSockets = true
	case "immich":
		endpoints = append(endpoints, getImmichEndpoints()...)
		result.AttackSurface.HasFileUpload = true
		result.AttackSurface.HasAPIEndpoints = true
	case "agreementpulse":
		endpoints = append(endpoints, getAgreementPulseEndpoints()...)
		result.AttackSurface.HasAPIEndpoints = true
	default:
		// Generic probing
		endpoints = append(endpoints, getGenericEndpoints()...)
	}

	// Probe each endpoint using worker pool pattern
	// (avoids goroutine leak from semaphore pattern)
	if len(endpoints) == 0 {
		return
	}

	concurrency := d.config.Concurrency
	if concurrency <= 0 {
		concurrency = defaults.ConcurrencyMedium
	}

	work := make(chan string, concurrency)
	var wg sync.WaitGroup

	// Start fixed number of workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case path, ok := <-work:
					if !ok {
						return
					}
					d.probeEndpoint(ctx, path, result)
				}
			}
		}()
	}

	// Send work to workers
sendLoop:
	for _, path := range endpoints {
		select {
		case <-ctx.Done():
			break sendLoop
		case work <- path:
		}
	}
	close(work)
	wg.Wait()
}

// probeEndpoint tests a single endpoint
func (d *Discoverer) probeEndpoint(ctx context.Context, path string, result *DiscoveryResult) {
	// Skip if already visited
	if _, exists := d.visited.LoadOrStore(path, true); exists {
		return
	}

	methods := []string{"GET", "POST", "OPTIONS"}

	for _, method := range methods {
		fullURL := d.config.Target + path
		req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)
		req.Header.Set("Accept", "application/json, text/html, */*")

		resp, err := d.httpClient.Do(req)
		if err != nil {
			continue
		}

		body, _ := iohelper.ReadBody(resp.Body, 4096)
		iohelper.DrainAndClose(resp.Body)

		// Skip 404s and errors
		if resp.StatusCode == 404 || resp.StatusCode >= 500 {
			continue
		}

		endpoint := Endpoint{
			Path:        path,
			Method:      method,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Service:     d.config.Service,
			Category:    categorizeEndpoint(path, method),
			Headers:     make(map[string]string),
		}

		// Extract parameters from response
		endpoint.Parameters = extractParameters(path, string(body), resp.Header.Get("Content-Type"))

		// Identify risk factors
		endpoint.RiskFactors = identifyRiskFactors(path, method, string(body))

		d.mu.Lock()
		d.endpoints = append(d.endpoints, endpoint)
		result.Statistics.ByMethod[method]++
		result.Statistics.ByCategory[endpoint.Category]++
		result.Statistics.RequestsMade++
		d.mu.Unlock()

		// Only continue with GET for now to avoid side effects
		if method == "GET" {
			break
		}
	}
}

// probeEndpointWithMethod probes an endpoint with a specific HTTP method (used for JS-inferred methods)
func (d *Discoverer) probeEndpointWithMethod(ctx context.Context, path, method string, result *DiscoveryResult) {
	// Create a unique key for method+path to avoid duplicates
	visitKey := method + ":" + path
	if _, exists := d.visited.LoadOrStore(visitKey, true); exists {
		return
	}

	fullURL := d.config.Target + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/json, text/html, */*")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return
	}

	body, _ := iohelper.ReadBody(resp.Body, 4096)
	iohelper.DrainAndClose(resp.Body)

	// Skip 404s and errors
	if resp.StatusCode == 404 || resp.StatusCode >= 500 {
		return
	}

	endpoint := Endpoint{
		Path:        path,
		Method:      method,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Service:     d.config.Service,
		Category:    categorizeEndpoint(path, method),
		Headers:     make(map[string]string),
	}

	// Extract parameters from response
	endpoint.Parameters = extractParameters(path, string(body), resp.Header.Get("Content-Type"))

	// Identify risk factors
	endpoint.RiskFactors = identifyRiskFactors(path, method, string(body))

	d.mu.Lock()
	d.endpoints = append(d.endpoints, endpoint)
	result.Statistics.ByMethod[method]++
	result.Statistics.ByCategory[endpoint.Category]++
	result.Statistics.RequestsMade++
	d.mu.Unlock()
}

// parseAPISpecs discovers endpoints from OpenAPI/Swagger specs and GraphQL introspection
func (d *Discoverer) parseAPISpecs(ctx context.Context, result *DiscoveryResult) {
	// Common OpenAPI/Swagger spec locations
	specPaths := []string{
		"/openapi.json",
		"/swagger.json",
		"/api/openapi.json",
		"/api/swagger.json",
		"/v1/openapi.json",
		"/v2/openapi.json",
		"/v3/openapi.json",
		"/api-docs",
		"/api-docs.json",
		"/docs/openapi.json",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/swagger/v1/swagger.json",
	}

	// Try to fetch and parse OpenAPI specs
	for _, specPath := range specPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoints := d.parseOpenAPISpec(ctx, specPath)
		for _, ep := range endpoints {
			d.addEndpointIfNew(ep, result)
		}
	}

	// GraphQL introspection
	graphqlPaths := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}
	for _, gqlPath := range graphqlPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		endpoints := d.introspectGraphQL(ctx, gqlPath)
		for _, ep := range endpoints {
			d.addEndpointIfNew(ep, result)
		}
	}
}

// parseOpenAPISpec fetches and parses an OpenAPI/Swagger specification
func (d *Discoverer) parseOpenAPISpec(ctx context.Context, specPath string) []Endpoint {
	var endpoints []Endpoint

	fullURL := d.config.Target + specPath
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return endpoints
	}
	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			iohelper.DrainAndClose(resp.Body)
		}
		return endpoints
	}

	// Check content-type - must be JSON, not HTML
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		iohelper.DrainAndClose(resp.Body)
		return endpoints
	}

	body, err := iohelper.ReadBody(resp.Body, 5*1024*1024) // 5MB limit
	iohelper.DrainAndClose(resp.Body)
	if err != nil {
		return endpoints
	}

	// Verify body looks like JSON (starts with { or [) - handles SPA 200 responses
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || (trimmedBody[0] != '{' && trimmedBody[0] != '[') {
		return endpoints
	}

	// Parse as JSON
	var spec map[string]interface{}
	if err := json.Unmarshal(body, &spec); err != nil {
		return endpoints
	}

	// Verify it's an OpenAPI/Swagger spec (has paths or openapi/swagger key)
	_, hasOpenAPI := spec["openapi"]
	_, hasSwagger := spec["swagger"]
	_, hasPaths := spec["paths"]
	if !hasOpenAPI && !hasSwagger && !hasPaths {
		return endpoints
	}

	// Check for OpenAPI 3.x or Swagger 2.x
	basePath := ""
	if bp, ok := spec["basePath"].(string); ok {
		basePath = bp
	}

	// Handle OpenAPI 3.x servers
	if servers, ok := spec["servers"].([]interface{}); ok && len(servers) > 0 {
		if server, ok := servers[0].(map[string]interface{}); ok {
			if serverURL, ok := server["url"].(string); ok {
				// Extract path from server URL if relative
				if strings.HasPrefix(serverURL, "/") {
					basePath = serverURL
				} else if u, err := url.Parse(serverURL); err == nil {
					basePath = u.Path
				}
			}
		}
	}

	// Extract paths
	paths, ok := spec["paths"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	for path, methods := range paths {
		methodMap, ok := methods.(map[string]interface{})
		if !ok {
			continue
		}

		fullPath := basePath + path
		// Normalize path - replace {param} with placeholder
		fullPath = regexcache.MustGet(`\{[^}]+\}`).ReplaceAllString(fullPath, "1")

		for method, details := range methodMap {
			method = strings.ToUpper(method)
			if method == "PARAMETERS" || method == "SERVERS" {
				continue // Skip non-HTTP method keys
			}

			ep := Endpoint{
				Path:     fullPath,
				Method:   method,
				Category: "api",
			}

			// Extract parameters
			if detailMap, ok := details.(map[string]interface{}); ok {
				ep.Parameters = d.extractOpenAPIParameters(detailMap)

				// Extract operation info for categorization
				if opID, ok := detailMap["operationId"].(string); ok {
					opLower := strings.ToLower(opID)
					if strings.Contains(opLower, "auth") || strings.Contains(opLower, "login") {
						ep.Category = "auth"
					} else if strings.Contains(opLower, "upload") || strings.Contains(opLower, "file") {
						ep.Category = "upload"
					} else if strings.Contains(opLower, "admin") {
						ep.Category = "admin"
					}
				}

				// Check for file upload (multipart/form-data)
				if requestBody, ok := detailMap["requestBody"].(map[string]interface{}); ok {
					if content, ok := requestBody["content"].(map[string]interface{}); ok {
						if _, hasMultipart := content["multipart/form-data"]; hasMultipart {
							ep.Category = "upload"
							ep.RiskFactors = append(ep.RiskFactors, "file_upload")
						}
					}
				}
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// extractOpenAPIParameters extracts parameters from an OpenAPI operation
func (d *Discoverer) extractOpenAPIParameters(operation map[string]interface{}) []Parameter {
	var params []Parameter

	// Extract from 'parameters' array
	if paramList, ok := operation["parameters"].([]interface{}); ok {
		for _, p := range paramList {
			paramMap, ok := p.(map[string]interface{})
			if !ok {
				continue
			}

			param := Parameter{}
			if name, ok := paramMap["name"].(string); ok {
				param.Name = name
			}
			if in, ok := paramMap["in"].(string); ok {
				param.Location = in
			}
			if required, ok := paramMap["required"].(bool); ok {
				param.Required = required
			}

			// Get type from schema
			if schema, ok := paramMap["schema"].(map[string]interface{}); ok {
				if t, ok := schema["type"].(string); ok {
					param.Type = t
				}
				if ex, ok := schema["example"]; ok {
					param.Example = fmt.Sprintf("%v", ex)
				}
			}

			if param.Name != "" {
				params = append(params, param)
			}
		}
	}

	// Extract from requestBody (for POST/PUT/PATCH)
	if requestBody, ok := operation["requestBody"].(map[string]interface{}); ok {
		if content, ok := requestBody["content"].(map[string]interface{}); ok {
			for contentType, mediaType := range content {
				mediaMap, ok := mediaType.(map[string]interface{})
				if !ok {
					continue
				}

				if schema, ok := mediaMap["schema"].(map[string]interface{}); ok {
					bodyParams := d.extractSchemaProperties(schema, contentType)
					params = append(params, bodyParams...)
				}
			}
		}
	}

	return params
}

// extractSchemaProperties extracts parameters from a JSON schema
func (d *Discoverer) extractSchemaProperties(schema map[string]interface{}, contentType string) []Parameter {
	var params []Parameter

	location := "body"
	if strings.Contains(contentType, "form") {
		location = "form"
	}

	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		requiredFields := make(map[string]bool)
		if req, ok := schema["required"].([]interface{}); ok {
			for _, r := range req {
				if name, ok := r.(string); ok {
					requiredFields[name] = true
				}
			}
		}

		for name, prop := range properties {
			propMap, ok := prop.(map[string]interface{})
			if !ok {
				continue
			}

			param := Parameter{
				Name:     name,
				Location: location,
				Required: requiredFields[name],
			}

			if t, ok := propMap["type"].(string); ok {
				param.Type = t
			}
			if ex, ok := propMap["example"]; ok {
				param.Example = fmt.Sprintf("%v", ex)
			}

			params = append(params, param)
		}
	}

	return params
}

// introspectGraphQL performs GraphQL schema introspection
func (d *Discoverer) introspectGraphQL(ctx context.Context, gqlPath string) []Endpoint {
	var endpoints []Endpoint

	fullURL := d.config.Target + gqlPath

	// Standard introspection query
	introspectionQuery := `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name kind } } } } } } }"}`

	req, err := http.NewRequestWithContext(ctx, "POST", fullURL, strings.NewReader(introspectionQuery))
	if err != nil {
		return endpoints
	}
	req.Header.Set("User-Agent", d.config.UserAgent)
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
	req.Header.Set("Accept", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil || (resp.StatusCode != 200 && resp.StatusCode != 400) {
		if resp != nil {
			iohelper.DrainAndClose(resp.Body)
		}
		return endpoints
	}

	// Check content-type - must be JSON, not HTML (handles SPAs)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		iohelper.DrainAndClose(resp.Body)
		return endpoints
	}

	body, err := iohelper.ReadBody(resp.Body, 2*1024*1024) // 2MB limit
	iohelper.DrainAndClose(resp.Body)
	if err != nil {
		return endpoints
	}

	// Verify body looks like JSON (starts with {)
	trimmedBody := bytes.TrimSpace(body)
	if len(trimmedBody) == 0 || trimmedBody[0] != '{' {
		return endpoints
	}

	// Parse the introspection response
	var gqlResp map[string]interface{}
	if err := json.Unmarshal(body, &gqlResp); err != nil {
		return endpoints
	}

	// Check for errors (introspection might be disabled)
	if _, hasErrors := gqlResp["errors"]; hasErrors {
		// Introspection disabled, but we know GraphQL exists
		// Add basic GraphQL endpoint
		endpoints = append(endpoints, Endpoint{
			Path:        gqlPath,
			Method:      "POST",
			Category:    "api",
			RiskFactors: []string{"graphql"},
		})
		return endpoints
	}

	data, ok := gqlResp["data"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	schema, ok := data["__schema"].(map[string]interface{})
	if !ok {
		return endpoints
	}

	// Extract query and mutation types
	types, ok := schema["types"].([]interface{})
	if !ok {
		return endpoints
	}

	for _, t := range types {
		typeMap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		typeName, _ := typeMap["name"].(string)
		// Skip internal types
		if strings.HasPrefix(typeName, "__") {
			continue
		}

		kind, _ := typeMap["kind"].(string)
		if kind != "OBJECT" {
			continue
		}

		// Only process Query and Mutation types
		if typeName != "Query" && typeName != "Mutation" && typeName != "Subscription" {
			continue
		}

		fields, ok := typeMap["fields"].([]interface{})
		if !ok {
			continue
		}

		for _, f := range fields {
			fieldMap, ok := f.(map[string]interface{})
			if !ok {
				continue
			}

			fieldName, _ := fieldMap["name"].(string)
			if fieldName == "" {
				continue
			}

			// Create endpoint for each field
			ep := Endpoint{
				Path:        gqlPath,
				Method:      "POST",
				Category:    "api",
				RiskFactors: []string{"graphql", strings.ToLower(typeName)},
			}

			// Add field name as a pseudo-parameter for testing
			ep.Parameters = append(ep.Parameters, Parameter{
				Name:     "operation",
				Location: "body",
				Type:     "string",
				Example:  fieldName,
			})

			// Extract arguments
			if args, ok := fieldMap["args"].([]interface{}); ok {
				for _, arg := range args {
					argMap, ok := arg.(map[string]interface{})
					if !ok {
						continue
					}

					argName, _ := argMap["name"].(string)
					if argName == "" {
						continue
					}

					param := Parameter{
						Name:     argName,
						Location: "body",
						Type:     "string", // Default type
					}

					// Try to get actual type
					if argType, ok := argMap["type"].(map[string]interface{}); ok {
						if typeName, ok := argType["name"].(string); ok && typeName != "" {
							param.Type = strings.ToLower(typeName)
						} else if kind, ok := argType["kind"].(string); ok {
							param.Type = strings.ToLower(kind)
						}
					}

					ep.Parameters = append(ep.Parameters, param)
				}
			}

			// Categorize based on field name
			fieldLower := strings.ToLower(fieldName)
			if strings.Contains(fieldLower, "login") || strings.Contains(fieldLower, "auth") ||
				strings.Contains(fieldLower, "register") || strings.Contains(fieldLower, "password") {
				ep.Category = "auth"
			} else if strings.Contains(fieldLower, "upload") || strings.Contains(fieldLower, "file") {
				ep.Category = "upload"
				ep.RiskFactors = append(ep.RiskFactors, "file_upload")
			} else if strings.Contains(fieldLower, "admin") || strings.Contains(fieldLower, "user") {
				ep.Category = "admin"
			}

			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}
