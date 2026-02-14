package apispec

import (
	"time"

	"github.com/waftester/waftester/pkg/discovery"
)

// ToDiscoveryResult converts a Spec into a discovery.DiscoveryResult
// for compatibility with tools that consume DiscoveryResult (e.g., the
// learn MCP tool).
func ToDiscoveryResult(spec *Spec, target string) *discovery.DiscoveryResult {
	if spec == nil {
		return &discovery.DiscoveryResult{
			Target:       target,
			DiscoveredAt: time.Now(),
		}
	}

	result := &discovery.DiscoveryResult{
		Target:       target,
		DiscoveredAt: spec.ParsedAt,
		Endpoints:    make([]discovery.Endpoint, 0, len(spec.Endpoints)),
	}

	// Build attack surface from spec metadata.
	result.AttackSurface = buildAttackSurface(spec)

	// Build statistics.
	result.Statistics = buildStatistics(spec)

	// Convert endpoints.
	for _, ep := range spec.Endpoints {
		result.Endpoints = append(result.Endpoints, specEndpointToDiscovery(ep))
	}

	return result
}

// specEndpointToDiscovery converts an apispec.Endpoint to a discovery.Endpoint.
func specEndpointToDiscovery(ep Endpoint) discovery.Endpoint {
	dep := discovery.Endpoint{
		Method:   ep.Method,
		Path:     ep.Path,
		Category: ep.Group,
	}

	if len(ep.ContentTypes) > 0 {
		dep.ContentType = ep.ContentTypes[0]
	}

	for _, p := range ep.Parameters {
		dep.Parameters = append(dep.Parameters, discovery.Parameter{
			Name:     p.Name,
			Location: string(p.In),
			Type:     p.Schema.Type,
			Required: p.Required,
			Example:  exampleToString(p.Example),
		})
	}

	return dep
}

// buildAttackSurface derives an AttackSurface from spec metadata.
func buildAttackSurface(spec *Spec) discovery.AttackSurface {
	as := discovery.AttackSurface{}

	for _, ep := range spec.Endpoints {
		// Auth detection.
		if len(ep.Auth) > 0 {
			as.HasAuthEndpoints = true
		}

		// API detection.
		if len(ep.Parameters) > 0 || len(ep.RequestBodies) > 0 {
			as.HasAPIEndpoints = true
		}

		// Content type detection.
		for _, ct := range ep.ContentTypes {
			switch {
			case ct == "application/json" || ct == "text/json":
				as.AcceptsJSON = true
			case ct == "application/xml" || ct == "text/xml":
				as.AcceptsXML = true
			case ct == "application/x-www-form-urlencoded" || ct == "multipart/form-data":
				as.AcceptsFormData = true
			}
		}

		// File upload detection.
		for _, rb := range ep.RequestBodies {
			if rb.Schema.Format == "binary" || rb.Schema.Type == "file" {
				as.HasFileUpload = true
			}
		}
	}

	// Auth scheme detection.
	for _, scheme := range spec.AuthSchemes {
		if scheme.Type == AuthOAuth2 {
			as.HasOAuth = true
		}
	}

	// GraphQL/WebSocket from format.
	if spec.Format == FormatGraphQL {
		as.HasGraphQL = true
	}
	if spec.Format == FormatAsyncAPI {
		as.HasWebSockets = true
	}

	// Build relevant categories.
	categories := make(map[string]bool)
	if as.AcceptsJSON {
		categories["nosqli"] = true
	}
	if as.AcceptsXML {
		categories["xxe"] = true
	}
	if as.HasAuthEndpoints {
		categories["brokenauth"] = true
	}
	if as.HasFileUpload {
		categories["upload"] = true
	}
	if as.HasOAuth {
		categories["oauth"] = true
	}
	if as.HasGraphQL {
		categories["graphql"] = true
	}
	for cat := range categories {
		as.RelevantCategories = append(as.RelevantCategories, cat)
	}

	return as
}

// buildStatistics derives DiscoveryStatistics from spec data.
func buildStatistics(spec *Spec) discovery.DiscoveryStatistics {
	stats := discovery.DiscoveryStatistics{
		TotalEndpoints: len(spec.Endpoints),
		ByMethod:       make(map[string]int),
		ByCategory:     make(map[string]int),
	}

	for _, ep := range spec.Endpoints {
		stats.ByMethod[ep.Method]++
		if ep.Group != "" {
			stats.ByCategory[ep.Group]++
		}
		stats.TotalParameters += len(ep.Parameters)
	}

	return stats
}

// exampleToString converts an example value to string for discovery compatibility.
func exampleToString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
