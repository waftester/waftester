package placeholders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/defaults"
)

func init() {
	Register(&URLParamPlaceholder{})
	Register(&URLPathPlaceholder{})
	Register(&URLFragmentPlaceholder{})
	Register(&HeaderPlaceholder{})
	Register(&UserAgentPlaceholder{})
	Register(&RefererPlaceholder{})
	Register(&CookiePlaceholder{})
	Register(&BodyJSONPlaceholder{})
	Register(&BodyFormPlaceholder{})
	Register(&BodyXMLPlaceholder{})
	Register(&BodyMultipartPlaceholder{})
	Register(&BodyRawPlaceholder{})
	Register(&HostHeaderPlaceholder{})
	Register(&XForwardedForPlaceholder{})
	Register(&ContentTypePlaceholder{})
	Register(&AcceptPlaceholder{})
	Register(&AuthorizationPlaceholder{})
}

// URLParamPlaceholder injects payload into URL query parameter
type URLParamPlaceholder struct{}

func (p *URLParamPlaceholder) Name() string        { return "url-param" }
func (p *URLParamPlaceholder) Description() string { return "URL query parameter" }
func (p *URLParamPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	cfg := MergeConfig(config)
	q := u.Query()
	q.Set(cfg.ParamName, payload)
	u.RawQuery = q.Encode()

	return http.NewRequest(http.MethodGet, u.String(), nil)
}

// URLPathPlaceholder injects payload into URL path
type URLPathPlaceholder struct{}

func (p *URLPathPlaceholder) Name() string        { return "url-path" }
func (p *URLPathPlaceholder) Description() string { return "URL path segment" }
func (p *URLPathPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.Path += payload

	return http.NewRequest(http.MethodGet, u.String(), nil)
}

// URLFragmentPlaceholder injects payload into URL fragment
type URLFragmentPlaceholder struct{}

func (p *URLFragmentPlaceholder) Name() string        { return "url-fragment" }
func (p *URLFragmentPlaceholder) Description() string { return "URL fragment (#)" }
func (p *URLFragmentPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}
	u.Fragment = payload
	return http.NewRequest(http.MethodGet, u.String(), nil)
}

// HeaderPlaceholder injects payload into custom header
type HeaderPlaceholder struct{}

func (p *HeaderPlaceholder) Name() string        { return "header" }
func (p *HeaderPlaceholder) Description() string { return "Custom HTTP header" }
func (p *HeaderPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	cfg := MergeConfig(config)
	req.Header.Set(cfg.HeaderName, payload)
	return req, nil
}

// UserAgentPlaceholder injects payload into User-Agent header
type UserAgentPlaceholder struct{}

func (p *UserAgentPlaceholder) Name() string        { return "user-agent" }
func (p *UserAgentPlaceholder) Description() string { return "User-Agent header" }
func (p *UserAgentPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", payload)
	return req, nil
}

// RefererPlaceholder injects payload into Referer header
type RefererPlaceholder struct{}

func (p *RefererPlaceholder) Name() string        { return "referer" }
func (p *RefererPlaceholder) Description() string { return "Referer header" }
func (p *RefererPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Referer", payload)
	return req, nil
}

// CookiePlaceholder injects payload into Cookie header
type CookiePlaceholder struct{}

func (p *CookiePlaceholder) Name() string        { return "cookie" }
func (p *CookiePlaceholder) Description() string { return "Cookie header" }
func (p *CookiePlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	cfg := MergeConfig(config)
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", cfg.CookieName, payload))
	return req, nil
}

// BodyJSONPlaceholder injects payload into JSON body
type BodyJSONPlaceholder struct{}

func (p *BodyJSONPlaceholder) Name() string        { return "body-json" }
func (p *BodyJSONPlaceholder) Description() string { return "JSON request body" }
func (p *BodyJSONPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	cfg := MergeConfig(config)

	body := map[string]string{cfg.FieldName: payload}
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", defaults.ContentTypeJSON)
	return req, nil
}

// BodyFormPlaceholder injects payload into form body
type BodyFormPlaceholder struct{}

func (p *BodyFormPlaceholder) Name() string        { return "body-form" }
func (p *BodyFormPlaceholder) Description() string { return "Form URL-encoded body" }
func (p *BodyFormPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	cfg := MergeConfig(config)

	form := url.Values{}
	form.Set(cfg.FieldName, payload)

	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", defaults.ContentTypeForm)
	return req, nil
}

// BodyXMLPlaceholder injects payload into XML body
type BodyXMLPlaceholder struct{}

func (p *BodyXMLPlaceholder) Name() string        { return "body-xml" }
func (p *BodyXMLPlaceholder) Description() string { return "XML request body" }
func (p *BodyXMLPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	cfg := MergeConfig(config)

	xmlBody := fmt.Sprintf("<?xml version=\"1.0\"?><root><%s>%s</%s></root>", cfg.FieldName, payload, cfg.FieldName)

	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(xmlBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", defaults.ContentTypeXML)
	return req, nil
}

// BodyMultipartPlaceholder injects payload into multipart form
type BodyMultipartPlaceholder struct{}

func (p *BodyMultipartPlaceholder) Name() string        { return "body-multipart" }
func (p *BodyMultipartPlaceholder) Description() string { return "Multipart form body" }
func (p *BodyMultipartPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	cfg := MergeConfig(config)

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField(cfg.FieldName, payload); err != nil {
		return nil, err
	}
	writer.Close()

	req, err := http.NewRequest(http.MethodPost, targetURL, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}

// BodyRawPlaceholder sends payload as raw body
type BodyRawPlaceholder struct{}

func (p *BodyRawPlaceholder) Name() string        { return "body-raw" }
func (p *BodyRawPlaceholder) Description() string { return "Raw request body" }
func (p *BodyRawPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	cfg := MergeConfig(config)
	contentType := "text/plain"
	if cfg.ContentType != "" {
		contentType = cfg.ContentType
	}

	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

// HostHeaderPlaceholder injects payload into Host header
type HostHeaderPlaceholder struct{}

func (p *HostHeaderPlaceholder) Name() string        { return "host-header" }
func (p *HostHeaderPlaceholder) Description() string { return "Host header injection" }
func (p *HostHeaderPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Host = payload
	return req, nil
}

// XForwardedForPlaceholder injects payload into X-Forwarded-For header
type XForwardedForPlaceholder struct{}

func (p *XForwardedForPlaceholder) Name() string        { return "x-forwarded-for" }
func (p *XForwardedForPlaceholder) Description() string { return "X-Forwarded-For header" }
func (p *XForwardedForPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Forwarded-For", payload)
	return req, nil
}

// ContentTypePlaceholder injects payload into Content-Type header
type ContentTypePlaceholder struct{}

func (p *ContentTypePlaceholder) Name() string        { return "content-type" }
func (p *ContentTypePlaceholder) Description() string { return "Content-Type header injection" }
func (p *ContentTypePlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader("test"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", payload)
	return req, nil
}

// AcceptPlaceholder injects payload into Accept header
type AcceptPlaceholder struct{}

func (p *AcceptPlaceholder) Name() string        { return "accept" }
func (p *AcceptPlaceholder) Description() string { return "Accept header injection" }
func (p *AcceptPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", payload)
	return req, nil
}

// AuthorizationPlaceholder injects payload into Authorization header
type AuthorizationPlaceholder struct{}

func (p *AuthorizationPlaceholder) Name() string        { return "authorization" }
func (p *AuthorizationPlaceholder) Description() string { return "Authorization header injection" }
func (p *AuthorizationPlaceholder) Apply(targetURL, payload string, config *PlaceholderConfig) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", payload)
	return req, nil
}
