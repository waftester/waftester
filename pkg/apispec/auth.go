package apispec

import (
	"encoding/base64"
	"fmt"
	"net/http"
)

// ResolveAuth merges spec-declared auth schemes with CLI-provided credentials.
// CLI credentials always take precedence over spec declarations.
// Returns a function that applies auth to each outgoing request.
func ResolveAuth(specAuth []AuthScheme, cli AuthConfig) RequestAuthFunc {
	// CLI credentials always win.
	if cli.HasAuth() {
		return cliAuth(cli)
	}

	// Fall back to spec-declared auth (log only, no auto-apply for security).
	// The spec tells us *what* auth is needed, but the user must provide credentials.
	return noAuth
}

// RequestAuthFunc applies authentication to an HTTP request.
type RequestAuthFunc func(req *http.Request)

// noAuth is a no-op auth function used when no credentials are configured.
func noAuth(_ *http.Request) {}

// cliAuth builds an auth function from CLI-provided credentials.
func cliAuth(cfg AuthConfig) RequestAuthFunc {
	return func(req *http.Request) {
		if cfg.BearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
		}
		if cfg.AuthHeader != "" {
			req.Header.Set("Authorization", cfg.AuthHeader)
		}
		if cfg.BasicUser != "" {
			req.SetBasicAuth(cfg.BasicUser, cfg.BasicPass)
		}
		if cfg.APIKey != "" {
			header := cfg.APIKeyHeader
			if header == "" {
				header = "X-API-Key"
			}
			req.Header.Set(header, cfg.APIKey)
		}
		for k, v := range cfg.CustomHeaders {
			req.Header.Set(k, v)
		}
	}
}

// DescribeSpecAuth returns a human-readable description of spec-declared auth
// schemes so users know what credentials to provide.
func DescribeSpecAuth(schemes []AuthScheme) []string {
	var descriptions []string
	for _, s := range schemes {
		switch s.Type {
		case AuthBearer:
			desc := fmt.Sprintf("Bearer token auth (use --bearer <token>)")
			if s.BearerFormat != "" {
				desc = fmt.Sprintf("Bearer token auth [%s] (use --bearer <token>)", s.BearerFormat)
			}
			descriptions = append(descriptions, desc)
		case AuthAPIKey:
			desc := fmt.Sprintf("API key in %s '%s' (use --api-key <key>)", s.In, s.FieldName)
			descriptions = append(descriptions, desc)
		case AuthBasic:
			descriptions = append(descriptions, "HTTP Basic auth (use --basic-user and --basic-pass)")
		case AuthOAuth2:
			desc := "OAuth 2.0"
			if len(s.Flows) > 0 {
				desc += " (" + s.Flows[0].Type + ")"
			}
			descriptions = append(descriptions, desc)
		case AuthCustom:
			descriptions = append(descriptions, fmt.Sprintf("Custom auth: %s", s.Name))
		}
	}
	return descriptions
}

// BuildBasicAuthHeader encodes username:password for HTTP Basic auth.
func BuildBasicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
