// Regression tests for concurrency bugs in the encoder registry.
package encoding

import (
	"fmt"
	"sync"
	"testing"
)

// testEncoder is a minimal Encoder implementation for concurrency testing.
type testEncoder struct{ n string }

func (e testEncoder) Name() string                    { return e.n }
func (e testEncoder) Encode(p string) (string, error) { return p, nil }
func (e testEncoder) Decode(p string) (string, error) { return p, nil }

// Regression test for bug: concurrent Register and Get could race on the registry map.
func TestConcurrentRegisterAndGet(t *testing.T) {
	t.Parallel()

	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(10)

	// 5 goroutines registering unique encoders
	for g := 0; g < 5; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("reg-test-%d-%d", id, i)
				Register(testEncoder{n: name})
			}
		}(g)
	}

	// 5 goroutines reading encoders
	for g := 0; g < 5; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = Get(fmt.Sprintf("reg-test-%d-%d", id, i))
				_ = Get("nonexistent")
			}
		}(g)
	}

	wg.Wait()
}

// Regression test for bug: concurrent List and Register could panic with concurrent map iteration.
func TestConcurrentListAndRegister(t *testing.T) {
	t.Parallel()

	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(4)

	// 2 goroutines registering
	for g := 0; g < 2; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				Register(testEncoder{n: fmt.Sprintf("list-test-%d-%d", id, i)})
			}
		}(g)
	}

	// 2 goroutines listing
	for g := 0; g < 2; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				names := List()
				_ = names
			}
		}()
	}

	wg.Wait()
}

// Regression test for bug: concurrent EncodeWithAll could race on registry iteration.
func TestConcurrentEncodeWithAll(t *testing.T) {
	t.Parallel()

	// Register 5 encoders for the test
	for i := 0; i < 5; i++ {
		Register(testEncoder{n: fmt.Sprintf("encode-all-test-%d", i)})
	}

	const goroutines = 10
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				results := EncodeWithAll("<script>alert(1)</script>")
				if len(results) == 0 {
					t.Error("EncodeWithAll returned empty map")
				}
			}
		}()
	}

	wg.Wait()
}
