package fp

import (
	"hash/fnv"
	"strings"
)

// Simhash computes a 64-bit simhash fingerprint for the given text.
// Simhash is a locality-sensitive hash — similar texts produce similar hashes.
// This is used for near-duplicate detection of WAF block pages and response bodies.
func Simhash(text string) uint64 {
	var v [64]int
	words := strings.Fields(strings.ToLower(text))
	for _, word := range words {
		h := fnv.New64a()
		h.Write([]byte(word))
		hash := h.Sum64()
		for i := 0; i < 64; i++ {
			if (hash>>i)&1 == 1 {
				v[i]++
			} else {
				v[i]--
			}
		}
	}
	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			fingerprint |= 1 << i
		}
	}
	return fingerprint
}

// HammingDistance returns the number of differing bits between two simhash values.
// A distance of 0 means identical content; higher distances indicate less similarity.
// Typical thresholds: <3 = near-duplicate, <5 = similar, >10 = different.
func HammingDistance(a, b uint64) int {
	xor := a ^ b
	count := 0
	for xor != 0 {
		count++
		xor &= xor - 1
	}
	return count
}
