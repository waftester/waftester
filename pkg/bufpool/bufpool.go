// Package bufpool provides sync.Pool-backed buffer pools for efficient
// memory reuse. Using pooled buffers significantly reduces GC pressure
// and allocations in hot paths.
package bufpool

import (
	"bytes"
	"strings"
	"sync"
)

// maxBufferSize is the maximum buffer size to keep in pool.
// Buffers larger than this are not returned to prevent memory bloat.
const maxBufferSize = 64 * 1024 // 64KB

// bufferPool is the global pool for bytes.Buffer
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// stringBuilderPool is the global pool for strings.Builder
var stringBuilderPool = sync.Pool{
	New: func() interface{} {
		return new(strings.Builder)
	},
}

// Get retrieves a bytes.Buffer from the pool.
// The buffer is guaranteed to be empty (Reset() is called).
// Callers should call Put() when done to return the buffer to the pool.
func Get() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// Put returns a bytes.Buffer to the pool.
// The buffer is reset before being returned.
// Nil buffers are safely ignored.
// Very large buffers (> 64KB) are not returned to prevent memory bloat.
func Put(buf *bytes.Buffer) {
	if buf == nil {
		return
	}
	// Don't return huge buffers to pool (prevents memory bloat)
	if buf.Cap() > maxBufferSize {
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
}

// GetSized retrieves a buffer with at least the given capacity.
// Use this when you know the approximate size needed to avoid reallocation.
func GetSized(size int) *bytes.Buffer {
	buf := Get()
	if buf.Cap() < size {
		buf.Grow(size)
	}
	return buf
}

// GetString retrieves a strings.Builder from the pool.
// The builder is guaranteed to be empty (Reset() is called).
// Callers should call PutString() when done to return the builder to the pool.
func GetString() *strings.Builder {
	sb := stringBuilderPool.Get().(*strings.Builder)
	sb.Reset()
	return sb
}

// PutString returns a strings.Builder to the pool.
// The builder is reset before being returned.
// Nil builders are safely ignored.
// Very large builders (> 64KB) are not returned to prevent memory bloat.
func PutString(sb *strings.Builder) {
	if sb == nil {
		return
	}
	// Don't return huge builders to pool (prevents memory bloat)
	if sb.Cap() > maxBufferSize {
		return
	}
	sb.Reset()
	stringBuilderPool.Put(sb)
}

// GetStringSized retrieves a strings.Builder with at least the given capacity.
// Use this when you know the approximate size needed to avoid reallocation.
func GetStringSized(size int) *strings.Builder {
	sb := GetString()
	if sb.Cap() < size {
		sb.Grow(size)
	}
	return sb
}
