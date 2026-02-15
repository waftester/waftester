package apispec

import (
	"fmt"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"
)

// IntelligenceOptions controls the behavior of BuildIntelligentPlan.
type IntelligenceOptions struct {
	// ScanTypes limits the plan to these categories. Empty = auto-select.
	ScanTypes []string

	// SkipTypes excludes these categories from the plan.
	SkipTypes []string

	// AllScans overrides auto-selection and includes everything.
	AllScans bool

	// Intensity controls payload depth.
	Intensity Intensity

	// IncludeMetaScans adds wafdetect, cors, secheaders etc. to every endpoint.
	IncludeMetaScans bool
}

// metaScanTypes are always-present informational scans that don't depend
// on endpoint shape.
var metaScanTypes = []string{
	"cors", "secheaders", "httpprobe", "wafdetect",
}

// BuildIntelligentPlan analyzes a Spec and produces a ScanPlan with attack
// types auto-selected per endpoint using 8 analysis layers.
//
// Layers:
//  1. Parameter type analysis
//  2. Parameter name pattern matching
//  3. Endpoint path pattern matching
//  4. Auth context analysis
//  5. Schema constraint analysis
//  6. Content-type mutation
//  7. Method confusion
//  8. Cross-endpoint correlation (IDOR)
func BuildIntelligentPlan(spec *Spec, opts IntelligenceOptions) *ScanPlan {
	if spec == nil || len(spec.Endpoints) == 0 {
		return &ScanPlan{Intensity: opts.Intensity}
	}

	intensity := opts.Intensity
	if intensity == "" {
		intensity = IntensityNormal
	}

	// Build allowed/blocked category sets for filtering.
	allowSet := toSet(opts.ScanTypes)
	blockSet := toSet(opts.SkipTypes)

	// Collect all entries across all endpoints.
	var entries []ScanPlanEntry
	totalTests := 0

	// Build auth presence map for Layer 4.
	authMap := buildAuthMap(spec.Endpoints)

	// Build endpoint path set for Layer 8 (cross-endpoint).
	pathIndex := buildPathIndex(spec.Endpoints)

	for i := range spec.Endpoints {
		ep := &spec.Endpoints[i]

		// Assign priority.
		ep.Priority = assignPriority(ep)

		// Collect attack selections from all 8 layers.
		selections := make(map[string]*AttackSelection)

		// Layer 1: parameter type.
		layerParamType(ep, selections)

		// Layer 2: parameter name.
		layerParamName(ep, selections)

		// Layer 3: endpoint path.
		layerPathPattern(ep, selections)

		// Layer 4: auth context.
		layerAuthContext(ep, authMap, selections)

		// Layer 5: schema constraints.
		layerSchemaConstraints(ep, selections)

		// Layer 6: content-type mutation.
		layerContentTypeMutation(ep, selections)

		// Layer 7: method confusion.
		layerMethodConfusion(ep, selections)

		// Layer 8: cross-endpoint (IDOR).
		layerCrossEndpoint(ep, pathIndex, selections)

		// Always add meta scans.
		if opts.IncludeMetaScans || opts.AllScans {
			for _, meta := range metaScanTypes {
				addSelection(selections, meta, "meta", "always included for endpoint-level security posture")
			}
		}

		// Filter selections by user preferences.
		for cat := range selections {
			if !opts.AllScans {
				if len(allowSet) > 0 && !allowSet[cat] {
					delete(selections, cat)
					continue
				}
			}
			if blockSet[cat] {
				delete(selections, cat)
			}
		}

		// Build injection targets for this endpoint.
		targets := injectableTargets(*ep)

		// Create plan entries.
		for _, sel := range selections {
			count := estimatePayloads(sel.Category, intensity)
			sel.PayloadCount = count

			if len(targets) == 0 {
				// Meta-scan or no injectable params: one entry per scan type.
				entries = append(entries, ScanPlanEntry{
					Endpoint: *ep,
					Attack:   *sel,
				})
				totalTests += count
			} else {
				// One entry per target per scan type.
				for _, target := range targets {
					entries = append(entries, ScanPlanEntry{
						Endpoint:        *ep,
						Attack:          *sel,
						InjectionTarget: target,
					})
					totalTests += count
				}
			}
		}
	}

	// Sort by priority (critical first).
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Endpoint.Priority > entries[j].Endpoint.Priority
	})

	// Layer 9: Auth-first ordering — boost auth-related endpoints to scan
	// first. This ensures auth tokens/cookies are captured early so
	// downstream scans can use them.
	layerAuthFirstOrdering(entries)

	// Layer 10: Dependency graph — detect CRUD chains and set DependsOn
	// links between endpoints (e.g., POST /users before GET /users/{id}).
	// Run before entry creation so the DependsOn field is visible in plan entries.
	// NOTE: layerDependencyGraph mutates spec.Endpoints in-place. The entries
	// above were copied by value, so we must re-copy DependsOn from spec.
	layerDependencyGraph(spec.Endpoints)
	// Propagate DependsOn from mutated spec.Endpoints back into plan entries.
	epDeps := make(map[string][]Dependency)
	for _, ep := range spec.Endpoints {
		if len(ep.DependsOn) > 0 {
			key := strings.ToUpper(ep.Method) + " " + ep.Path
			epDeps[key] = ep.DependsOn
		}
	}
	for i := range entries {
		key := strings.ToUpper(entries[i].Endpoint.Method) + " " + entries[i].Endpoint.Path
		if deps, ok := epDeps[key]; ok {
			entries[i].Endpoint.DependsOn = deps
		}
	}

	// Layer 11: Business logic detection — identify multi-step flows
	// (signup → verify → login) and add bizlogic scan type.
	entries = layerBusinessLogic(spec.Endpoints, entries, &totalTests, intensity, allowSet, blockSet)

	// Layer 12: Composite risk scoring — refine coarse Priority into a
	// numeric score based on attack surface area and layer count.
	layerCompositeScoring(entries)

	return &ScanPlan{
		Entries:    entries,
		TotalTests: totalTests,
		Intensity:  intensity,
		SpecSource: spec.Source,
	}
}

// --- Layer 1: Parameter Type Analysis ---

func layerParamType(ep *Endpoint, sel map[string]*AttackSelection) {
	for _, p := range ep.Parameters {
		cats := categoriesByParamType(p)
		for _, cat := range cats {
			reason := p.Name + " (" + string(p.In) + " " + p.Schema.Type + ")"
			addSelection(sel, cat, "param_type", reason)
		}
	}

	// Request body fields.
	for ct, rb := range ep.RequestBodies {
		for name, schema := range rb.Schema.Properties {
			cats := categoriesBySchemaType(schema)
			for _, cat := range cats {
				reason := name + " (body " + ct + " " + schema.Type + ")"
				addSelection(sel, cat, "param_type", reason)
			}
		}
	}
}

func categoriesByParamType(p Parameter) []string {
	return categoriesBySchemaType(p.Schema)
}

func categoriesBySchemaType(s SchemaInfo) []string {
	switch s.Type {
	case "string":
		cats := []string{"sqli", "xss", "cmdi", "ssti", "lfi"}
		if s.Format == "uri" || s.Format == "url" {
			cats = append(cats, "ssrf", "redirect")
		}
		if s.Format == "email" {
			cats = append(cats, "xss") // already present, deduped by addSelection
		}
		if s.Format == "binary" || s.Format == "byte" {
			cats = append(cats, "upload", "deserialize")
		}
		return cats
	case "integer", "number":
		return []string{"sqli", "inputvalidation"}
	case "boolean":
		return []string{"inputvalidation"}
	case "array":
		return []string{"sqli", "nosqli", "hpp"}
	case "object":
		return []string{"nosqli", "prototype", "massassignment", "xxe"}
	default:
		// Unknown type — treat as string.
		if s.Type == "" {
			return []string{"sqli", "xss"}
		}
		return nil
	}
}

// --- Layer 2: Parameter Name Pattern Matching ---

func layerParamName(ep *Endpoint, sel map[string]*AttackSelection) {
	for _, p := range ep.Parameters {
		cats := MatchParamName(p.Name)
		for _, cat := range cats {
			reason := "param name '" + p.Name + "' matches " + cat + " pattern"
			addSelection(sel, cat, "param_name", reason)
		}
	}

	// Body field names.
	for _, rb := range ep.RequestBodies {
		for name := range rb.Schema.Properties {
			cats := MatchParamName(name)
			for _, cat := range cats {
				reason := "body field '" + name + "' matches " + cat + " pattern"
				addSelection(sel, cat, "param_name", reason)
			}
		}
	}
}

// --- Layer 3: Endpoint Path Pattern Matching ---

// pathPattern maps a path glob pattern to attack categories.
type pathPattern struct {
	Pattern    string
	Categories []string
	Priority   Priority
}

var pathPatterns = []pathPattern{
	// Auth / login endpoints.
	{"/login*", []string{"brokenauth", "jwt", "sessionfixation", "csrf", "xss", "sqli"}, PriorityHigh},
	{"/auth*", []string{"brokenauth", "jwt", "oauth", "xss"}, PriorityHigh},
	{"/signin*", []string{"brokenauth", "jwt", "csrf"}, PriorityHigh},
	{"/signup*", []string{"brokenauth", "massassignment", "xss", "sqli"}, PriorityHigh},
	{"/register*", []string{"brokenauth", "massassignment", "xss", "sqli"}, PriorityHigh},
	{"/password*", []string{"brokenauth", "csrf"}, PriorityCritical},
	{"/reset*", []string{"brokenauth", "csrf", "race"}, PriorityCritical},
	{"/oauth*", []string{"oauth", "ssrf", "redirect"}, PriorityHigh},
	{"/token*", []string{"jwt", "brokenauth", "sessionfixation"}, PriorityHigh},
	{"/session*", []string{"sessionfixation", "brokenauth"}, PriorityHigh},
	{"/logout*", []string{"csrf", "sessionfixation"}, PriorityMedium},

	// Admin / privileged endpoints.
	{"/admin*", []string{"accesscontrol", "brokenauth", "idor"}, PriorityCritical},
	{"/manage*", []string{"accesscontrol", "brokenauth"}, PriorityHigh},
	{"/settings*", []string{"accesscontrol", "csrf", "massassignment"}, PriorityHigh},
	{"/config*", []string{"accesscontrol", "sensitivedata"}, PriorityHigh},
	{"/internal*", []string{"accesscontrol", "ssrf"}, PriorityCritical},
	{"/debug*", []string{"sensitivedata", "accesscontrol"}, PriorityCritical},

	// User / account endpoints.
	{"/user*", []string{"idor", "accesscontrol", "massassignment", "xss"}, PriorityHigh},
	{"/account*", []string{"idor", "accesscontrol", "massassignment"}, PriorityHigh},
	{"/profile*", []string{"idor", "xss", "upload"}, PriorityHigh},

	// File-related endpoints.
	{"/upload*", []string{"upload", "lfi", "rfi", "rce", "xss"}, PriorityCritical},
	{"/download*", []string{"traversal", "lfi", "ssrf"}, PriorityHigh},
	{"/file*", []string{"traversal", "lfi", "upload"}, PriorityHigh},
	{"/export*", []string{"ssrf", "traversal", "cmdi"}, PriorityHigh},
	{"/import*", []string{"xxe", "ssrf", "deserialize", "upload"}, PriorityHigh},

	// API / data endpoints.
	{"/api*", []string{"sqli", "nosqli", "apifuzz"}, PriorityMedium},
	{"/graphql*", []string{"graphql", "nosqli"}, PriorityHigh},
	{"/webhook*", []string{"ssrf", "requestforgery"}, PriorityHigh},
	{"/callback*", []string{"ssrf", "redirect"}, PriorityHigh},

	// Search / query endpoints.
	{"/search*", []string{"sqli", "xss", "nosqli"}, PriorityMedium},
	{"/query*", []string{"sqli", "nosqli", "xss"}, PriorityMedium},

	// Payment / transaction endpoints.
	{"/pay*", []string{"race", "idor", "csrf", "inputvalidation"}, PriorityCritical},
	{"/checkout*", []string{"race", "idor", "csrf"}, PriorityCritical},
	{"/order*", []string{"idor", "race", "accesscontrol"}, PriorityHigh},
	{"/transaction*", []string{"race", "idor"}, PriorityCritical},
	{"/invoice*", []string{"idor", "accesscontrol"}, PriorityHigh},

	// Health / status (low priority).
	{"/health*", nil, PriorityLow},
	{"/status*", nil, PriorityLow},
	{"/ping*", nil, PriorityLow},
	{"/ready*", nil, PriorityLow},
	{"/alive*", nil, PriorityLow},
	{"/version*", nil, PriorityLow},
	{"/metrics*", []string{"sensitivedata"}, PriorityLow},
}

func layerPathPattern(ep *Endpoint, sel map[string]*AttackSelection) {
	path := strings.ToLower(ep.Path)
	if len(path) < 2 {
		return
	}

	// Strip version prefix for matching.
	if idx := strings.Index(path[1:], "/"); idx >= 0 {
		seg := path[1 : idx+1]
		if len(seg) > 0 && seg[0] == 'v' && (seg == "v1" || seg == "v2" || seg == "v3" || seg == "v4") {
			path = path[idx+1:]
		}
	}

	for _, pp := range pathPatterns {
		matched, err := pathpkg.Match(pp.Pattern, path)
		if err != nil {
			continue
		}
		if !matched {
			// Also try matching just the first path segment.
			segments := strings.SplitN(path, "/", 4) // ["", "segment", "rest", ...]
			if len(segments) >= 2 {
				firstSeg := "/" + segments[1]
				matched, _ = pathpkg.Match(pp.Pattern, firstSeg)
			}
		}
		if !matched {
			continue
		}

		if ep.Priority < pp.Priority {
			ep.Priority = pp.Priority
		}

		for _, cat := range pp.Categories {
			reason := "path '" + ep.Path + "' matches " + pp.Pattern
			addSelection(sel, cat, "path_pattern", reason)
		}
	}
}

// --- Layer 4: Auth Context Analysis ---

// authPresence tracks which endpoints require auth.
type authPresence struct {
	HasAuth bool
	Path    string // path prefix group
}

func buildAuthMap(endpoints []Endpoint) map[string][]authPresence {
	m := make(map[string][]authPresence)
	for _, ep := range endpoints {
		// Group by first path segment.
		group := pathGroup(ep.Path)
		hasAuth := len(ep.Auth) > 0
		m[group] = append(m[group], authPresence{HasAuth: hasAuth, Path: ep.Path})
	}
	return m
}

func pathGroup(path string) string {
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
	if len(parts) == 0 {
		return "/"
	}
	return "/" + parts[0]
}

func layerAuthContext(ep *Endpoint, authMap map[string][]authPresence, sel map[string]*AttackSelection) {
	group := pathGroup(ep.Path)
	siblings := authMap[group]

	hasAuth := len(ep.Auth) > 0
	if hasAuth {
		return // This endpoint requires auth — no anomaly.
	}

	// Count how many siblings require auth.
	totalSiblings := 0
	authSiblings := 0
	for _, s := range siblings {
		if s.Path == ep.Path {
			continue // Skip self.
		}
		totalSiblings++
		if s.HasAuth {
			authSiblings++
		}
	}

	// If most siblings require auth but this one doesn't, flag it.
	if totalSiblings > 0 && authSiblings > 0 {
		ratio := float64(authSiblings) / float64(totalSiblings)
		if ratio >= 0.5 {
			reason := "no auth while " + formatPercent(ratio) + " of sibling endpoints require auth"
			addSelection(sel, "accesscontrol", "auth_context", reason)
			addSelection(sel, "brokenauth", "auth_context", reason)

			if ep.Priority < PriorityHigh {
				ep.Priority = PriorityHigh
			}
		}
	}
}

func formatPercent(f float64) string {
	pct := int(f * 100)
	if pct >= 100 {
		return "100%"
	}
	return fmt.Sprintf("%d%%", pct)
}

// --- Layer 5: Schema Constraint Analysis ---

func layerSchemaConstraints(ep *Endpoint, sel map[string]*AttackSelection) {
	for _, p := range ep.Parameters {
		checkSchemaConstraints(p.Name, p.Schema, sel, 0)
	}
	for _, rb := range ep.RequestBodies {
		for name, schema := range rb.Schema.Properties {
			checkSchemaConstraints(name, schema, sel, 0)
		}
	}
}

const maxConstraintDepth = 5

func checkSchemaConstraints(paramName string, s SchemaInfo, sel map[string]*AttackSelection, depth int) {
	if depth > maxConstraintDepth {
		return
	}

	if s.MaxLength != nil {
		reason := paramName + " has maxLength=" + strconv.Itoa(*s.MaxLength) + " — overflow + padding attacks"
		addSelection(sel, "inputvalidation", "schema_constraint", reason)
	}
	if s.Minimum != nil || s.Maximum != nil {
		reason := paramName + " has numeric bounds — boundary value testing"
		addSelection(sel, "inputvalidation", "schema_constraint", reason)
	}
	if len(s.Enum) > 0 {
		reason := paramName + " has enum constraint — unlisted value + injection"
		addSelection(sel, "inputvalidation", "schema_constraint", reason)
		addSelection(sel, "sqli", "schema_constraint", reason)
	}
	if s.Pattern != "" {
		reason := paramName + " has pattern constraint — violation testing"
		addSelection(sel, "inputvalidation", "schema_constraint", reason)
	}
	if s.Format == "email" {
		reason := paramName + " is email format — XSS in email field"
		addSelection(sel, "xss", "schema_constraint", reason)
	}
	if s.Format == "uri" || s.Format == "url" {
		reason := paramName + " is URI format — SSRF payloads"
		addSelection(sel, "ssrf", "schema_constraint", reason)
		addSelection(sel, "redirect", "schema_constraint", reason)
	}

	// Recurse into nested object properties.
	for name, prop := range s.Properties {
		checkSchemaConstraints(paramName+"."+name, prop, sel, depth+1)
	}
	// Recurse into array items.
	if s.Items != nil {
		checkSchemaConstraints(paramName+"[]", *s.Items, sel, depth+1)
	}
}

// --- Layer 6: Content-Type Mutation ---

func layerContentTypeMutation(ep *Endpoint, sel map[string]*AttackSelection) {
	if len(ep.RequestBodies) == 0 {
		return
	}

	hasJSON := false
	hasXML := false
	hasForm := false
	for ct := range ep.RequestBodies {
		lower := strings.ToLower(ct)
		if strings.Contains(lower, "json") {
			hasJSON = true
		}
		if strings.Contains(lower, "xml") {
			hasXML = true
		}
		if strings.Contains(lower, "form") {
			hasForm = true
		}
	}

	// Plan mutations between content types.
	if hasJSON && !hasXML {
		addSelection(sel, "xxe", "content_mutation", "JSON endpoint may accept XML — XXE via content-type mutation")
	}
	if hasJSON && !hasForm {
		addSelection(sel, "hpp", "content_mutation", "JSON endpoint may accept form — HPP via content-type mutation")
	}
	if hasForm && !hasJSON {
		addSelection(sel, "nosqli", "content_mutation", "form endpoint may accept JSON — NoSQLi via content-type mutation")
	}
}

// --- Layer 7: Method Confusion ---

func layerMethodConfusion(ep *Endpoint, sel map[string]*AttackSelection) {
	// Plan to test undocumented methods.
	method := strings.ToUpper(ep.Method)

	// Dangerous methods for data mutation/deletion.
	dangerousMethods := []string{"DELETE", "PUT", "PATCH"}
	for _, m := range dangerousMethods {
		if m != method {
			addSelection(sel, "httpprobe", "method_confusion", ep.Path+" documents "+method+" — test "+m)
		}
	}

	// Diagnostic methods that may leak info or bypass access control.
	infoMethods := []string{"HEAD", "OPTIONS", "TRACE"}
	for _, m := range infoMethods {
		if m != method {
			addSelection(sel, "httpprobe", "method_confusion", ep.Path+" — test "+m+" for info leak or access bypass")
		}
	}
}

// --- Layer 8: Cross-Endpoint Correlation ---

type pathIndexEntry struct {
	Methods []string
	HasID   bool // path contains {id}-like parameter
}

func buildPathIndex(endpoints []Endpoint) map[string]*pathIndexEntry {
	idx := make(map[string]*pathIndexEntry)
	for _, ep := range endpoints {
		// Normalize path by removing path param names.
		normalized := normalizePath(ep.Path)
		entry, ok := idx[normalized]
		if !ok {
			entry = &pathIndexEntry{}
			idx[normalized] = entry
		}
		entry.Methods = append(entry.Methods, strings.ToUpper(ep.Method))
		if strings.Contains(ep.Path, "{") {
			entry.HasID = true
		}
	}
	return idx
}

func normalizePath(path string) string {
	// Replace {anything} with {_} for grouping.
	var b strings.Builder
	b.Grow(len(path))
	i := 0
	for i < len(path) {
		start := strings.Index(path[i:], "{")
		if start < 0 {
			b.WriteString(path[i:])
			break
		}
		b.WriteString(path[i : i+start])
		end := strings.Index(path[i+start:], "}")
		if end < 0 {
			b.WriteString(path[i+start:])
			break
		}
		b.WriteString("{_}")
		i = i + start + end + 1
	}
	return b.String()
}

func layerCrossEndpoint(ep *Endpoint, pathIndex map[string]*pathIndexEntry, sel map[string]*AttackSelection) {
	normalized := normalizePath(ep.Path)
	entry, ok := pathIndex[normalized]
	if !ok {
		return
	}

	method := strings.ToUpper(ep.Method)

	// IDOR: if endpoint has both read (GET) and write (POST/PUT), and path has ID param.
	if entry.HasID {
		hasRead := false
		hasWrite := false
		for _, m := range entry.Methods {
			switch m {
			case "GET":
				hasRead = true
			case "POST", "PUT", "PATCH":
				hasWrite = true
			}
		}
		if hasRead && hasWrite {
			addSelection(sel, "idor", "cross_endpoint", ep.Path+" has both read and write operations with ID parameter")
			addSelection(sel, "accesscontrol", "cross_endpoint", ep.Path+" multi-method with ID — access control check")
		}
	}

	// Race condition: POST/PUT on same resource from multiple endpoints.
	if method == "POST" || method == "PUT" {
		writeCount := 0
		for _, m := range entry.Methods {
			if m == "POST" || m == "PUT" || m == "PATCH" {
				writeCount++
			}
		}
		if writeCount > 1 {
			addSelection(sel, "race", "cross_endpoint", ep.Path+" has multiple write methods — race condition candidate")
		}
	}
}

// --- Priority Assignment ---

func assignPriority(ep *Endpoint) Priority {
	if ep.Deprecated {
		return PriorityCritical
	}

	// Check for admin-like paths.
	lower := strings.ToLower(ep.Path)
	if strings.Contains(lower, "/admin") || strings.Contains(lower, "/internal") ||
		strings.Contains(lower, "/debug") {
		return PriorityCritical
	}

	// Check for health/status (low priority).
	for _, p := range []string{"/health", "/status", "/ping", "/ready", "/alive", "/version"} {
		if strings.HasPrefix(lower, p) || strings.Contains(lower, p) {
			return PriorityLow
		}
	}

	// Auth-related endpoints get high priority.
	if strings.Contains(lower, "/login") || strings.Contains(lower, "/auth") ||
		strings.Contains(lower, "/password") || strings.Contains(lower, "/reset") {
		return PriorityHigh
	}

	// Default.
	return PriorityMedium
}

// --- Helpers ---

func addSelection(sel map[string]*AttackSelection, category, layer, reason string) {
	existing, ok := sel[category]
	if ok {
		// Add the layer if not already present.
		for _, l := range existing.Layers {
			if l == layer {
				return
			}
		}
		existing.Layers = append(existing.Layers, layer)
		if reason != "" {
			existing.Reason += "; " + reason
		}
		return
	}
	sel[category] = &AttackSelection{
		Category: category,
		Reason:   reason,
		Layers:   []string{layer},
	}
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

// --- Layer 9: Auth-First Ordering ---
// Moves auth-related endpoints (login, token, OAuth) to the front of the
// plan. This ensures tokens/cookies are established before testing
// downstream endpoints that depend on authentication.

func layerAuthFirstOrdering(entries []ScanPlanEntry) {
	authPaths := []string{"/login", "/auth", "/signin", "/token", "/oauth", "/session"}

	sort.SliceStable(entries, func(i, j int) bool {
		iAuth := isAuthPath(entries[i].Endpoint.Path, authPaths)
		jAuth := isAuthPath(entries[j].Endpoint.Path, authPaths)
		if iAuth != jAuth {
			return iAuth // auth endpoints first
		}
		// Within the same group, preserve priority ordering.
		return entries[i].Endpoint.Priority > entries[j].Endpoint.Priority
	})
}

func isAuthPath(path string, authPaths []string) bool {
	lower := strings.ToLower(path)
	for _, ap := range authPaths {
		if strings.Contains(lower, ap) {
			return true
		}
	}
	return false
}

// --- Layer 10: Dependency Graph ---
// Detects CRUD chains across endpoints and sets DependsOn links.
// e.g., GET /users/{id} depends on POST /users (create before read).

func layerDependencyGraph(endpoints []Endpoint) {
	// Group endpoints by normalized base path (without ID params).
	type pathGroup struct {
		create *Endpoint // POST without {id}
		read   *Endpoint // GET with {id}
		update *Endpoint // PUT/PATCH with {id}
		del    *Endpoint // DELETE with {id}
	}

	groups := make(map[string]*pathGroup)

	for i := range endpoints {
		ep := &endpoints[i]
		base := crudBasePath(ep.Path)
		hasID := strings.Contains(ep.Path, "{")

		pg, ok := groups[base]
		if !ok {
			pg = &pathGroup{}
			groups[base] = pg
		}

		method := strings.ToUpper(ep.Method)
		switch {
		case method == "POST" && !hasID:
			pg.create = ep
		case method == "GET" && hasID:
			pg.read = ep
		case (method == "PUT" || method == "PATCH") && hasID:
			pg.update = ep
		case method == "DELETE" && hasID:
			pg.del = ep
		}
	}

	// Set dependencies: read → create, update → create, delete → create.
	for _, pg := range groups {
		if pg.create == nil {
			continue
		}
		createRef := Dependency{
			OperationID: depID(pg.create),
			Description: pg.create.Method + " " + pg.create.Path,
		}
		if pg.read != nil {
			pg.read.DependsOn = appendDep(pg.read.DependsOn, createRef)
		}
		if pg.update != nil {
			pg.update.DependsOn = appendDep(pg.update.DependsOn, createRef)
		}
		if pg.del != nil {
			pg.del.DependsOn = appendDep(pg.del.DependsOn, createRef)
		}
	}
}

// depID returns the OperationID for dependency linking.
// Falls back to "METHOD /path" if OperationID is empty.
func depID(ep *Endpoint) string {
	if ep.OperationID != "" {
		return ep.OperationID
	}
	return strings.ToUpper(ep.Method) + " " + ep.Path
}

// crudBasePath strips the trailing {id} segment for CRUD grouping.
// /users/{id} → /users, /api/v1/items/{itemId} → /api/v1/items
func crudBasePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var base []string
	for _, p := range parts {
		if strings.HasPrefix(p, "{") {
			break
		}
		base = append(base, p)
	}
	if len(base) == 0 {
		return "/"
	}
	return "/" + strings.Join(base, "/")
}

func appendDep(deps []Dependency, d Dependency) []Dependency {
	for _, existing := range deps {
		if existing.OperationID == d.OperationID {
			return deps
		}
	}
	return append(deps, d)
}

// --- Layer 11: Business Logic Detection ---
// Identifies multi-step flows (signup → verify → login, create → pay →
// confirm) and adds the "bizlogic" scan type to participating endpoints.

// bizFlow defines a recognized business logic flow pattern.
type bizFlow struct {
	Name  string
	Steps []string // path substrings that form the flow
}

var bizFlows = []bizFlow{
	{"registration", []string{"signup", "register", "verify", "confirm", "login"}},
	{"password_reset", []string{"forgot", "reset", "verify", "confirm"}},
	{"checkout", []string{"cart", "checkout", "pay", "confirm", "order"}},
	{"onboarding", []string{"invite", "accept", "setup", "complete"}},
	{"two_factor", []string{"login", "2fa", "verify", "totp", "mfa"}},
}

func layerBusinessLogic(endpoints []Endpoint, entries []ScanPlanEntry, totalTests *int, intensity Intensity, allowSet, blockSet map[string]bool) []ScanPlanEntry {
	// Build a set of path substrings present in the spec.
	pathSet := make(map[string]bool)
	for _, ep := range endpoints {
		lower := strings.ToLower(ep.Path)
		segments := strings.Split(strings.Trim(lower, "/"), "/")
		for _, seg := range segments {
			pathSet[seg] = true
		}
	}

	// Check which flows have 2+ matching steps.
	for _, flow := range bizFlows {
		matched := 0
		for _, step := range flow.Steps {
			if pathSet[step] {
				matched++
			}
		}
		if matched < 2 {
			continue
		}

		// Add bizlogic scan type to endpoints that participate in this flow.
		for i := range entries {
			ep := &entries[i].Endpoint
			lower := strings.ToLower(ep.Path)
			for _, step := range flow.Steps {
				if strings.Contains(lower, step) {
					// Check filters.
					cat := "bizlogic"
					if len(allowSet) > 0 && !allowSet[cat] {
						break
					}
					if blockSet[cat] {
						break
					}
					reason := "part of " + flow.Name + " flow (matched '" + step + "')"
					if entries[i].Attack.Category != cat {
						// Add a new bizlogic entry rather than overwriting the
						// existing attack category (which was set by layers 1-8).
						newEntry := ScanPlanEntry{
							Endpoint:        *ep,
							InjectionTarget: entries[i].InjectionTarget,
							Attack: AttackSelection{
								Category:     cat,
								Reason:       reason,
								Layers:       []string{"business_logic"},
								PayloadCount: estimatePayloads(cat, intensity),
							},
						}
						entries = append(entries, newEntry)
						*totalTests += newEntry.Attack.PayloadCount
					}
					break
				}
			}
		}
	}
	return entries
}

// --- Layer 12: Composite Risk Scoring ---
// Converts coarse Priority (Low/Medium/High/Critical) into an
// EstimatedDuration-based numeric score. Entries with more attack layers
// and higher priority get proportionally more test time allocated.

func layerCompositeScoring(entries []ScanPlanEntry) {
	authPaths := []string{"/login", "/auth", "/signin", "/token", "/oauth", "/session"}

	for i := range entries {
		e := &entries[i]
		// Base score from priority.
		base := 0
		switch e.Endpoint.Priority {
		case PriorityCritical:
			base = 100
		case PriorityHigh:
			base = 75
		case PriorityMedium:
			base = 50
		case PriorityLow:
			base = 25
		default:
			base = 50
		}
		// Bonus from layer count (each layer adds 5 points).
		layerBonus := len(e.Attack.Layers) * 5
		if layerBonus > 25 {
			layerBonus = 25
		}
		e.Attack.RiskScore = base + layerBonus
	}

	// Re-sort by risk score descending, preserving auth-first ordering
	// from Layer 9 as a tiebreaker within equal scores.
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Attack.RiskScore != entries[j].Attack.RiskScore {
			return entries[i].Attack.RiskScore > entries[j].Attack.RiskScore
		}
		// Preserve auth-first: auth endpoints come before non-auth at equal score.
		iAuth := isAuthPath(entries[i].Endpoint.Path, authPaths)
		jAuth := isAuthPath(entries[j].Endpoint.Path, authPaths)
		if iAuth != jAuth {
			return iAuth
		}
		return false
	})
}
