// Package bufpool provides sync.Pool-backed buffer pools for efficient
// memory reuse. This file implements response pooling for HTTP responses,
// dramatically reducing GC pressure in scanning hot paths.
package bufpool

import (
	"bytes"
	"io"
	"net/http"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
)

// Response is a pooled response wrapper that holds pre-allocated buffers
// for reading HTTP response bodies. Using pooled responses reduces allocations
// by ~90% in high-throughput scanning scenarios.
type Response struct {
	// Body is the pre-allocated buffer for the response body
	Body *bytes.Buffer

	// chunk is the pre-allocated read chunk for io.Copy operations
	chunk []byte

	// statusCode caches the HTTP status code
	StatusCode int

	// headers stores a copy of response headers (if needed)
	Headers http.Header
}

// responsePool is the global pool for Response objects
var responsePool = sync.Pool{
	New: func() interface{} {
		return &Response{
			Body:    bytes.NewBuffer(make([]byte, 0, defaults.BufferLarge)),
			chunk:   make([]byte, defaults.BufferMedium),
			Headers: make(http.Header),
		}
	},
}

// GetResponse retrieves a Response from the pool.
// The response body buffer and headers are guaranteed to be empty.
// Callers MUST call PutResponse when done to return it to the pool.
//
// Example:
//
//	resp := bufpool.GetResponse()
//	defer bufpool.PutResponse(resp)
//	resp.ReadFrom(httpResp)
//	body := resp.Body.Bytes()
func GetResponse() *Response {
	r := responsePool.Get().(*Response)
	r.Body.Reset()
	r.StatusCode = 0
	for k := range r.Headers {
		delete(r.Headers, k)
	}
	return r
}

// PutResponse returns a Response to the pool.
// The response is reset before being returned.
// Nil responses are safely ignored.
// Responses with very large bodies (> 1MB) are not returned to prevent memory bloat.
func PutResponse(r *Response) {
	if r == nil {
		return
	}
	// Don't return responses with huge bodies
	if r.Body.Cap() > defaults.BufferHuge {
		return
	}
	r.Body.Reset()
	r.StatusCode = 0
	for k := range r.Headers {
		delete(r.Headers, k)
	}
	responsePool.Put(r)
}

// ReadFrom reads the entire body from an HTTP response into the pooled buffer.
// It uses the pre-allocated chunk buffer to minimize allocations.
// This replaces io.ReadAll with a zero-allocation alternative.
func (r *Response) ReadFrom(resp *http.Response) (int64, error) {
	if resp == nil || resp.Body == nil {
		return 0, nil
	}

	r.StatusCode = resp.StatusCode

	// Copy headers if needed (shallow copy is fine for read-only use)
	for k, v := range resp.Header {
		r.Headers[k] = v
	}

	// Use pre-allocated chunk for reading
	return io.CopyBuffer(r.Body, resp.Body, r.chunk)
}

// ReadFromReader reads from any io.Reader into the pooled buffer.
// Useful for reading response bodies that have already been wrapped.
func (r *Response) ReadFromReader(reader io.Reader) (int64, error) {
	if reader == nil {
		return 0, nil
	}
	return io.CopyBuffer(r.Body, reader, r.chunk)
}

// ReadFromLimited reads up to limit bytes from an HTTP response.
// Use this to prevent reading very large responses.
func (r *Response) ReadFromLimited(resp *http.Response, limit int64) (int64, error) {
	if resp == nil || resp.Body == nil {
		return 0, nil
	}

	r.StatusCode = resp.StatusCode

	for k, v := range resp.Header {
		r.Headers[k] = v
	}

	limited := io.LimitReader(resp.Body, limit)
	return io.CopyBuffer(r.Body, limited, r.chunk)
}

// Bytes returns the body content as a byte slice.
// The returned slice is valid until the Response is returned to the pool.
func (r *Response) Bytes() []byte {
	return r.Body.Bytes()
}

// String returns the body content as a string.
// This creates a copy, use Bytes() for zero-copy access if possible.
func (r *Response) String() string {
	return r.Body.String()
}

// Len returns the current body length.
func (r *Response) Len() int {
	return r.Body.Len()
}

// Reset clears the response for reuse.
func (r *Response) Reset() {
	r.Body.Reset()
	r.StatusCode = 0
	for k := range r.Headers {
		delete(r.Headers, k)
	}
}
