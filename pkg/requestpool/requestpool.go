// Package requestpool provides sync.Pool-backed pooling for http.Request objects.
// This reduces GC pressure when making many HTTP requests by reusing request objects.
//
// Usage:
//
//	req := requestpool.Get()
//	defer requestpool.Put(req)
//	req.Method = "GET"
//	req.URL, _ = url.Parse("https://example.com")
//	// use req...
package requestpool

import (
	"net/http"
	"sync"
)

var requestPool = sync.Pool{
	New: func() interface{} {
		return &http.Request{
			Header: make(http.Header),
		}
	},
}

// Get returns a reset http.Request from the pool.
// The returned request has an empty but initialized Header map.
func Get() *http.Request {
	req := requestPool.Get().(*http.Request)
	return req
}

// Put returns an http.Request to the pool after resetting it.
// The request should not be used after calling Put.
func Put(req *http.Request) {
	if req == nil {
		return
	}
	// Reset the request to avoid leaking data between uses
	req.Method = ""
	req.URL = nil
	req.Proto = ""
	req.ProtoMajor = 0
	req.ProtoMinor = 0
	req.Header = make(http.Header) // Fresh header map
	req.Body = nil
	req.GetBody = nil
	req.ContentLength = 0
	req.TransferEncoding = nil
	req.Close = false
	req.Host = ""
	req.Form = nil
	req.PostForm = nil
	req.MultipartForm = nil
	req.Trailer = nil
	req.RemoteAddr = ""
	req.RequestURI = ""
	req.TLS = nil
	req.Cancel = nil
	req.Response = nil
	// Note: We don't reset ctx as it should be set per-request anyway

	requestPool.Put(req)
}

// GetWithMethod returns a request with the method already set.
func GetWithMethod(method string) *http.Request {
	req := Get()
	req.Method = method
	return req
}
