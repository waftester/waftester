package apispec

import (
	"fmt"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/discovery"
)

// ReconcileResult holds the outcome of merging spec endpoints with
// live discovery data.
type ReconcileResult struct {
	// LiveEndpoints are spec endpoints confirmed reachable.
	LiveEndpoints []Endpoint

	// DeadEndpoints are spec endpoints that failed liveness probes.
	DeadEndpoints []DeadEndpoint

	// UnlistedEndpoints are endpoints found by discovery but not in the spec.
	UnlistedEndpoints []Endpoint

	// Technologies discovered on the target.
	Technologies []string

	// WAFDetected indicates a WAF was found during discovery.
	WAFDetected bool

	// WAFFingerprint is the WAF vendor/product string.
	WAFFingerprint string

	// ReconciledAt is when the reconciliation ran.
	ReconciledAt time.Time
}

// DeadEndpoint wraps a spec endpoint that failed liveness checks.
type DeadEndpoint struct {
	Endpoint   Endpoint `json:"endpoint"`
	StatusCode int      `json:"status_code"`
	Reason     string   `json:"reason"`
}

// Reconcile merges spec endpoints with live discovery results.
//
// It performs three operations:
//  1. Validates spec endpoints against discovered endpoints (liveness).
//  2. Adds unlisted endpoints found by discovery but absent from the spec.
//  3. Attaches discovered technologies as metadata.
//
// livenessCheck controls whether endpoints not found in discovery are
// marked dead. When false, all spec endpoints are treated as live.
func Reconcile(spec *Spec, disc *discovery.DiscoveryResult, livenessCheck bool) *ReconcileResult {
	result := &ReconcileResult{
		ReconciledAt: time.Now(),
	}

	if spec == nil {
		return result
	}

	if disc == nil {
		// No discovery data — all spec endpoints are live by default.
		result.LiveEndpoints = append(result.LiveEndpoints, spec.Endpoints...)
		return result
	}

	// Attach discovery metadata.
	result.Technologies = disc.Technologies
	result.WAFDetected = disc.WAFDetected
	result.WAFFingerprint = disc.WAFFingerprint

	// Build index of discovered endpoints by normalized key.
	discoveredIndex := buildDiscoveredIndex(disc.Endpoints)

	// Check each spec endpoint against discovery results.
	for _, ep := range spec.Endpoints {
		key := endpointKey(ep.Method, ep.Path)
		if _, found := discoveredIndex[key]; found {
			result.LiveEndpoints = append(result.LiveEndpoints, ep)
			delete(discoveredIndex, key)
		} else if livenessCheck {
			result.DeadEndpoints = append(result.DeadEndpoints, DeadEndpoint{
				Endpoint: ep,
				Reason:   "not found in discovery results",
			})
		} else {
			result.LiveEndpoints = append(result.LiveEndpoints, ep)
		}
	}

	// Remaining discovered endpoints are unlisted.
	for _, dep := range discoveredIndex {
		result.UnlistedEndpoints = append(result.UnlistedEndpoints, convertDiscoveredEndpoint(dep))
	}

	return result
}

// InjectTechnologies adds technology-specific attack categories to existing
// plan entries based on discovered technologies. For example, if "nginx" is
// detected, request smuggling tests get higher priority.
func InjectTechnologies(plan *ScanPlan, technologies []string) {
	if plan == nil || len(technologies) == 0 {
		return
	}

	techSet := make(map[string]bool, len(technologies))
	for _, t := range technologies {
		techSet[strings.ToLower(t)] = true
	}

	for i := range plan.Entries {
		entry := &plan.Entries[i]

		// Boost priority for technology-specific attacks.
		if techSet["nginx"] || techSet["apache"] {
			if entry.Attack.Category == "smuggling" || entry.Attack.Category == "responsesplit" {
				entry.Attack.Reason += "; server technology detected"
			}
		}
		if techSet["graphql"] {
			if entry.Attack.Category == "graphql" {
				entry.Attack.Reason += "; GraphQL confirmed by discovery"
			}
		}
		if techSet["websocket"] || techSet["ws"] {
			if entry.Attack.Category == "websocket" {
				entry.Attack.Reason += "; WebSocket confirmed by discovery"
			}
		}
	}
}

// buildDiscoveredIndex creates a lookup map from discovery endpoints.
// Key format: "METHOD /normalized/path".
func buildDiscoveredIndex(endpoints []discovery.Endpoint) map[string]discovery.Endpoint {
	index := make(map[string]discovery.Endpoint, len(endpoints))
	for _, ep := range endpoints {
		key := endpointKey(ep.Method, ep.Path)
		index[key] = ep
	}
	return index
}

// endpointKey produces a normalized key for matching spec and discovery
// endpoints. Path template parameters like {id} are collapsed to {_}
// for fuzzy matching.
func endpointKey(method, path string) string {
	method = strings.ToUpper(method)
	if method == "" {
		method = "GET"
	}
	return method + " " + normalizePath(path)
}

// convertDiscoveredEndpoint converts a discovery.Endpoint to an
// apispec.Endpoint with best-effort field mapping.
func convertDiscoveredEndpoint(dep discovery.Endpoint) Endpoint {
	ep := Endpoint{
		Method:         strings.ToUpper(dep.Method),
		Path:           dep.Path,
		ContentTypes:   contentTypesFromDiscovery(dep.ContentType),
		Tags:           tagsFromCategory(dep.Category),
		Group:          dep.Category,
		CorrelationTag: CorrelationTag(dep.Method, dep.Path),
	}

	for _, dp := range dep.Parameters {
		ep.Parameters = append(ep.Parameters, Parameter{
			Name:     dp.Name,
			In:       locationFromString(dp.Location),
			Required: dp.Required,
			Schema:   SchemaInfo{Type: dp.Type},
			Example:  dp.Example,
		})
	}

	if dep.StatusCode > 0 {
		ep.Responses = map[string]Response{
			fmt.Sprintf("%d", dep.StatusCode): {Description: "discovered response"},
		}
	}

	return ep
}

// locationFromString maps discovery location strings to typed Location values.
func locationFromString(loc string) Location {
	switch strings.ToLower(loc) {
	case "query":
		return LocationQuery
	case "path":
		return LocationPath
	case "header":
		return LocationHeader
	case "cookie":
		return LocationCookie
	case "body":
		return LocationBody
	default:
		return LocationQuery
	}
}

// contentTypesFromDiscovery converts a single content-type string
// into a slice, filtering empty values.
func contentTypesFromDiscovery(ct string) []string {
	if ct == "" {
		return nil
	}
	return []string{ct}
}

// tagsFromCategory converts a discovery category into tags.
func tagsFromCategory(category string) []string {
	if category == "" {
		return nil
	}
	return []string{category}
}
