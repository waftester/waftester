// Package httputil provides HTTP request helpers for WAF testing.
package httputil

import "net/http"

// SetPayloadCookie adds a cookie to the request without Go's net/http value
// sanitization. Go's http.Cookie strips bytes like `"`, `\`, `;`, `\r`, and
// `\x00` from cookie values, which silently neuters attack payloads and
// produces false negatives. Use this for attack payloads only. Use
// req.AddCookie() for legitimate session cookies that don't contain payloads.
func SetPayloadCookie(req *http.Request, name, value string) {
	if req == nil {
		return
	}
	pair := name + "=" + value
	if existing := req.Header.Get("Cookie"); existing != "" {
		req.Header.Set("Cookie", existing+"; "+pair)
	} else {
		req.Header.Set("Cookie", pair)
	}
}

// SetPayloadHeader sets a header value without Go's \r\n sanitization.
// Go's http.Header.Set() strips carriage return and newline characters,
// which defeats CRLF injection testing. Use this for attack payloads
// that may contain CRLF sequences.
func SetPayloadHeader(req *http.Request, key, value string) {
	if req == nil {
		return
	}
	req.Header[http.CanonicalHeaderKey(key)] = []string{value}
}
