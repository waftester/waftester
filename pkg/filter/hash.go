package filter

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

// HashAlgorithm represents a supported hash algorithm
type HashAlgorithm string

const (
	HashMD5     HashAlgorithm = "md5"
	HashSHA1    HashAlgorithm = "sha1"
	HashSHA256  HashAlgorithm = "sha256"
	HashSHA512  HashAlgorithm = "sha512"
	HashMMH3    HashAlgorithm = "mmh3"    // MurmurHash3 - used for Shodan favicon
	HashSimhash HashAlgorithm = "simhash" // For similarity detection
)

// ComputeHash computes the hash of data using the specified algorithm
func ComputeHash(data []byte, algo HashAlgorithm) string {
	switch algo {
	case HashMD5:
		return computeStandardHash(data, md5.New())
	case HashSHA1:
		return computeStandardHash(data, sha1.New())
	case HashSHA256:
		return computeStandardHash(data, sha256.New())
	case HashSHA512:
		return computeStandardHash(data, sha512.New())
	case HashMMH3:
		return fmt.Sprintf("%d", computeMMH3(data))
	case HashSimhash:
		return fmt.Sprintf("%d", ComputeSimhash(data))
	default:
		return ""
	}
}

func computeStandardHash(data []byte, h hash.Hash) string {
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeFaviconHash computes the MMH3 hash of a favicon for Shodan compatibility
// This matches Shodan's favicon hash format
func ComputeFaviconHash(faviconData []byte) int32 {
	// Base64 encode the favicon
	b64 := base64.StdEncoding.EncodeToString(faviconData)
	// Compute MMH3 hash
	return computeMMH3([]byte(b64))
}

// computeMMH3 computes MurmurHash3 (32-bit version)
// This is a simplified implementation for favicon hashing
func computeMMH3(data []byte) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)

	h1 := uint32(0) // seed
	length := len(data)
	nblocks := length / 4

	// Body
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])

		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	// Tail
	tail := data[nblocks*4:]
	k1 := uint32(0)
	switch length & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint32(length)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16

	return int32(h1)
}

// ComputeSimhash computes a simhash for similarity detection
// Uses a simple implementation based on character shingles
func ComputeSimhash(data []byte) uint64 {
	if len(data) == 0 {
		return 0
	}

	// Create shingles (3-character sequences)
	shingleSize := 3
	var v [64]int

	for i := 0; i <= len(data)-shingleSize; i++ {
		shingle := data[i : i+shingleSize]
		h := hashShingle(shingle)

		for j := 0; j < 64; j++ {
			if h&(1<<j) != 0 {
				v[j]++
			} else {
				v[j]--
			}
		}
	}

	// Convert to simhash
	var simhash uint64
	for i := 0; i < 64; i++ {
		if v[i] > 0 {
			simhash |= 1 << i
		}
	}

	return simhash
}

// hashShingle creates a 64-bit hash of a shingle
func hashShingle(shingle []byte) uint64 {
	h := sha256.Sum256(shingle)
	return binary.LittleEndian.Uint64(h[:8])
}

// SimhashDistance returns the Hamming distance between two simhashes
// Lower distance = more similar
func SimhashDistance(a, b uint64) int {
	xor := a ^ b
	distance := 0
	for xor != 0 {
		distance++
		xor &= xor - 1
	}
	return distance
}

// IsSimilar returns true if two simhashes are within the threshold
// Typical threshold is 3-5 for near-duplicates
func IsSimilar(a, b uint64, threshold int) bool {
	return SimhashDistance(a, b) <= threshold
}

// HashResponse computes multiple hashes for a response body
type ResponseHashes struct {
	MD5     string
	SHA1    string
	SHA256  string
	SHA512  string
	MMH3    int32
	Simhash uint64
}

// ComputeAllHashes computes all supported hashes for data
func ComputeAllHashes(data []byte) ResponseHashes {
	return ResponseHashes{
		MD5:     ComputeHash(data, HashMD5),
		SHA1:    ComputeHash(data, HashSHA1),
		SHA256:  ComputeHash(data, HashSHA256),
		SHA512:  ComputeHash(data, HashSHA512),
		MMH3:    computeMMH3(data),
		Simhash: ComputeSimhash(data),
	}
}
