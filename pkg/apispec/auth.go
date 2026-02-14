package apispec

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ResolveAuth merges spec-declared auth schemes with CLI-provided credentials.
// CLI credentials always take precedence over spec declarations.
// Returns a function that applies auth to each outgoing request.
func ResolveAuth(specAuth []AuthScheme, cli AuthConfig) RequestAuthFunc {
	// CLI credentials always win.
	if cli.HasAuth() {
		// OAuth2 client_credentials flow: acquire token first.
		if cli.OAuth2ClientID != "" {
			return oauth2Auth(specAuth, cli)
		}
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

// oauth2Auth acquires a token via OAuth2 client_credentials flow and caches it.
// The token URL is taken from CLI config, falling back to the spec's
// securitySchemes if available.
func oauth2Auth(specAuth []AuthScheme, cli AuthConfig) RequestAuthFunc {
	tokenURL := cli.OAuth2TokenURL
	if tokenURL == "" {
		tokenURL = findTokenURL(specAuth)
	}
	if tokenURL == "" {
		log.Printf("[auth] OAuth2 client_credentials: no token URL found in CLI or spec")
		return noAuth
	}

	cache := &oauth2TokenCache{}

	return func(req *http.Request) {
		token, err := cache.getOrRefresh(tokenURL, cli.OAuth2ClientID, cli.OAuth2ClientSecret, cli.OAuth2Scopes)
		if err != nil {
			log.Printf("[auth] OAuth2 token error: %v", err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// findTokenURL extracts the first client_credentials token URL from spec auth schemes.
func findTokenURL(schemes []AuthScheme) string {
	for _, s := range schemes {
		if s.Type != AuthOAuth2 {
			continue
		}
		for _, f := range s.Flows {
			if f.Type == "clientCredentials" && f.TokenURL != "" {
				return f.TokenURL
			}
		}
		// Fall back to any flow that has a token URL.
		for _, f := range s.Flows {
			if f.TokenURL != "" {
				return f.TokenURL
			}
		}
	}
	return ""
}

// oauth2TokenCache caches an access token with expiry.
type oauth2TokenCache struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (c *oauth2TokenCache) getOrRefresh(tokenURL, clientID, clientSecret, scopes string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid (with 30s margin).
	if c.token != "" && time.Now().Add(30*time.Second).Before(c.expires) {
		return c.token, nil
	}

	// Request new token.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if scopes != "" {
		form.Set("scope", strings.ReplaceAll(scopes, ",", " "))
	}

	resp, err := http.PostForm(tokenURL, form) //nolint:gosec // User-provided tokenURL is intentional.
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}

	c.token = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		c.expires = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		c.expires = time.Now().Add(time.Hour) // Default 1h if not specified.
	}

	return c.token, nil
}