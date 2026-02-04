// Package bufpool provides sync.Pool-backed buffer pools for efficient
// memory reuse. This file implements tiered byte slice pooling similar to
// high-performance frameworks like gnet and fasthttp.
package bufpool

import (
	"math/bits"
	"sync"

	"github.com/waftester/waftester/pkg/defaults"
)

// Pool sizes: powers of 2 from 64 bytes to 64KB (11 pools)
// Index 0 = 64 bytes (2^6)
// Index 10 = 64KB (2^16)
const (
	minBitSize = 6  // 2^6 = 64 bytes minimum
	maxBitSize = 16 // 2^16 = 64KB maximum
	poolSteps  = maxBitSize - minBitSize + 1
)

// slicePools contains tiered pools for byte slices of different sizes
var slicePools [poolSteps]sync.Pool

func init() {
	for i := 0; i < poolSteps; i++ {
		size := 1 << (minBitSize + i)
		slicePools[i].New = func(s int) func() interface{} {
			return func() interface{} {
				buf := make([]byte, s)
				return &buf
			}
		}(size)
	}
}

// poolIndex returns the pool index for a given size
func poolIndex(size int) int {
	if size <= 1<<minBitSize {
		return 0
	}
	// Round up to next power of 2
	idx := bits.Len(uint(size - 1))
	if idx < minBitSize {
		return 0
	}
	idx -= minBitSize
	if idx >= poolSteps {
		return -1 // Too large for pool
	}
	return idx
}

// GetSlice retrieves a byte slice of at least the given size from the pool.
// The slice length is set to size, capacity may be larger (power of 2).
// Callers MUST call PutSlice when done to return the slice to the pool.
//
// Example:
//
//	buf := bufpool.GetSlice(1024)
//	defer bufpool.PutSlice(buf)
//	n, err := reader.Read(buf)
func GetSlice(size int) []byte {
	if size <= 0 {
		return nil
	}

	idx := poolIndex(size)
	if idx < 0 {
		// Too large for pool, allocate directly
		return make([]byte, size)
	}

	ptr := slicePools[idx].Get().(*[]byte)
	buf := *ptr
	return buf[:size]
}

// PutSlice returns a byte slice to the pool.
// The slice must have been obtained via GetSlice.
// Nil slices are safely ignored.
// Slices larger than 64KB are not returned to prevent memory bloat.
func PutSlice(buf []byte) {
	if buf == nil {
		return
	}

	cap := cap(buf)
	if cap > defaults.BufferLarge || cap < (1<<minBitSize) {
		// Too large or too small for pool
		return
	}

	idx := poolIndex(cap)
	if idx < 0 {
		return
	}

	// Reset to full capacity before returning
	buf = buf[:cap]
	slicePools[idx].Put(&buf)
}

// GetSliceSmall returns a 4KB slice from the pool.
// Convenience function for typical small reads.
func GetSliceSmall() []byte {
	return GetSlice(defaults.BufferSmall)
}

// GetSliceMedium returns a 32KB slice from the pool.
// Convenience function for typical medium reads.
func GetSliceMedium() []byte {
	return GetSlice(defaults.BufferMedium)
}

// GetSliceLarge returns a 64KB slice from the pool.
// Convenience function for bulk reads.
func GetSliceLarge() []byte {
	return GetSlice(defaults.BufferLarge)
}
