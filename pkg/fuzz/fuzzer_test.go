package fuzz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFuzzer(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		cfg := &Config{
			TargetURL: "http://example.com/FUZZ",
			Words:     []string{"admin", "test"},
		}
		f := NewFuzzer(cfg)
		require.NotNil(t, f)
		assert.Equal(t, 40, f.config.Concurrency)
		assert.Equal(t, 100, f.config.RateLimit)
		assert.Equal(t, 10*time.Second, f.config.Timeout)
		assert.Equal(t, "GET", f.config.Method)
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := &Config{
			TargetURL:   "http://example.com/FUZZ",
			Words:       []string{"admin"},
			Concurrency: 10,
			RateLimit:   50,
			Timeout:     5 * time.Second,
			Method:      "POST",
		}
		f := NewFuzzer(cfg)
		require.NotNil(t, f)
		assert.Equal(t, 10, f.config.Concurrency)
		assert.Equal(t, 50, f.config.RateLimit)
		assert.Equal(t, 5*time.Second, f.config.Timeout)
		assert.Equal(t, "POST", f.config.Method)
	})

	t.Run("with skip verify", func(t *testing.T) {
		cfg := &Config{
			TargetURL:  "https://example.com/FUZZ",
			Words:      []string{"test"},
			SkipVerify: true,
		}
		f := NewFuzzer(cfg)
		require.NotNil(t, f)
		assert.True(t, f.config.SkipVerify)
	})

	t.Run("with proxy", func(t *testing.T) {
		cfg := &Config{
			TargetURL: "http://example.com/FUZZ",
			Words:     []string{"test"},
			Proxy:     "http://127.0.0.1:8080",
		}
		f := NewFuzzer(cfg)
		require.NotNil(t, f)
	})
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		TargetURL:      "http://example.com/FUZZ",
		Words:          []string{"admin", "test", "login"},
		Concurrency:    20,
		RateLimit:      100,
		Timeout:        5 * time.Second,
		Method:         "POST",
		Headers:        map[string]string{"X-Custom": "value"},
		Data:           "user=FUZZ",
		Cookies:        "session=abc123",
		FollowRedir:    true,
		Extensions:     []string{".php", ".html"},
		FilterStatus:   []int{404, 403},
		MatchStatus:    []int{200, 301},
		Recursive:      true,
		RecursionDepth: 3,
	}

	assert.Equal(t, "http://example.com/FUZZ", cfg.TargetURL)
	assert.Len(t, cfg.Words, 3)
	assert.Equal(t, 20, cfg.Concurrency)
	assert.True(t, cfg.FollowRedir)
	assert.Contains(t, cfg.Extensions, ".php")
	assert.Contains(t, cfg.FilterStatus, 404)
}

func TestResultStruct(t *testing.T) {
	r := Result{
		Input:         "admin",
		URL:           "http://example.com/admin",
		StatusCode:    200,
		ContentLength: 1234,
		WordCount:     100,
		LineCount:     50,
		ResponseTime:  150 * time.Millisecond,
		Redirected:    true,
		RedirectURL:   "http://example.com/dashboard",
	}

	assert.Equal(t, "admin", r.Input)
	assert.Equal(t, 200, r.StatusCode)
	assert.Equal(t, 1234, r.ContentLength)
	assert.True(t, r.Redirected)
}

func TestStatsStruct(t *testing.T) {
	s := Stats{
		TotalRequests:   1000,
		Matches:         50,
		Filtered:        900,
		Errors:          10,
		StartTime:       time.Now(),
		Duration:        10 * time.Second,
		RequestsPerSec:  100.0,
		StatusBreakdown: map[int]int{200: 50, 404: 900, 500: 10},
	}

	assert.Equal(t, int64(1000), s.TotalRequests)
	assert.Equal(t, int64(50), s.Matches)
	assert.Equal(t, 100.0, s.RequestsPerSec)
}

func TestFuzzerRun(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Admin page"))
		case "/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Login page"))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		}
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"admin", "login", "unknown"},
		Concurrency: 2,
		RateLimit:   100,
		Timeout:     5 * time.Second,
		MatchStatus: []int{200},
	}

	f := NewFuzzer(cfg)
	ctx := context.Background()

	var results []*Result
	callback := func(r *Result) {
		results = append(results, r)
	}

	stats := f.Run(ctx, callback)

	require.NotNil(t, stats)
	assert.Equal(t, int64(3), stats.TotalRequests)
	assert.GreaterOrEqual(t, len(results), 2) // admin and login should match
}

func TestFuzzerRunWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"a", "b", "c", "d", "e"},
		Concurrency: 1,
		RateLimit:   10,
	}

	f := NewFuzzer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	stats := f.Run(ctx, nil)
	require.NotNil(t, stats)
	// Should have been cancelled before completing all requests
	assert.Less(t, stats.TotalRequests, int64(5))
}

func TestFuzzerExpandWords(t *testing.T) {
	cfg := &Config{
		TargetURL:  "http://example.com/FUZZ",
		Words:      []string{"admin", "test"},
		Extensions: []string{".php", ".html"},
	}

	f := NewFuzzer(cfg)
	expanded := f.expandWords()

	// Should have original words + words with extensions
	assert.Contains(t, expanded, "admin")
	assert.Contains(t, expanded, "test")
	assert.Contains(t, expanded, "admin.php")
	assert.Contains(t, expanded, "admin.html")
	assert.Contains(t, expanded, "test.php")
	assert.Contains(t, expanded, "test.html")
}

func TestFuzzerFilters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		case "/notfound":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not found"))
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
		}
	}))
	defer server.Close()

	t.Run("filter by status", func(t *testing.T) {
		cfg := &Config{
			TargetURL:    server.URL + "/FUZZ",
			Words:        []string{"ok", "notfound", "forbidden"},
			Concurrency:  1,
			FilterStatus: []int{404, 403},
		}

		f := NewFuzzer(cfg)
		var count int32
		f.Run(context.Background(), func(r *Result) {
			atomic.AddInt32(&count, 1)
		})

		assert.Equal(t, int32(1), count) // Only /ok should match
	})

	t.Run("match by status", func(t *testing.T) {
		cfg := &Config{
			TargetURL:   server.URL + "/FUZZ",
			Words:       []string{"ok", "notfound", "forbidden"},
			Concurrency: 1,
			MatchStatus: []int{200},
		}

		f := NewFuzzer(cfg)
		var count int32
		f.Run(context.Background(), func(r *Result) {
			atomic.AddInt32(&count, 1)
		})

		assert.Equal(t, int32(1), count) // Only /ok should match
	})
}

func TestFuzzerWithHeaders(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"test"},
		Concurrency: 1,
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"Authorization":   "Bearer token123",
		},
	}

	f := NewFuzzer(cfg)
	f.Run(context.Background(), nil)

	assert.Equal(t, "custom-value", receivedHeaders.Get("X-Custom-Header"))
	assert.Equal(t, "Bearer token123", receivedHeaders.Get("Authorization"))
}

func TestFuzzerWithPostData(t *testing.T) {
	var receivedBody string
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/api",
		Words:       []string{"admin"},
		Concurrency: 1,
		Method:      "POST",
		Data:        "username=FUZZ&password=test",
	}

	f := NewFuzzer(cfg)
	f.Run(context.Background(), nil)

	assert.Equal(t, "POST", receivedMethod)
	assert.Equal(t, "username=admin&password=test", receivedBody)
}

func TestFuzzerRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/destination", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Destination"))
	}))
	defer server.Close()

	t.Run("follow redirects", func(t *testing.T) {
		cfg := &Config{
			TargetURL:   server.URL + "/FUZZ",
			Words:       []string{"redirect"},
			Concurrency: 1,
			FollowRedir: true,
		}

		f := NewFuzzer(cfg)
		var result *Result
		f.Run(context.Background(), func(r *Result) {
			result = r
		})

		require.NotNil(t, result)
		assert.Equal(t, 200, result.StatusCode)
	})

	t.Run("no follow redirects", func(t *testing.T) {
		cfg := &Config{
			TargetURL:   server.URL + "/FUZZ",
			Words:       []string{"redirect"},
			Concurrency: 1,
			FollowRedir: false,
		}

		f := NewFuzzer(cfg)
		var result *Result
		f.Run(context.Background(), func(r *Result) {
			result = r
		})

		require.NotNil(t, result)
		assert.Equal(t, 302, result.StatusCode)
	})
}

func TestFuzzerShouldShow(t *testing.T) {
	cfg := &Config{
		TargetURL:   "http://example.com/FUZZ",
		Words:       []string{"test"},
		MatchStatus: []int{200},
		FilterSize:  []int{0},
	}

	f := NewFuzzer(cfg)

	t.Run("matches status", func(t *testing.T) {
		result := &Result{StatusCode: 200, ContentLength: 100}
		assert.True(t, f.shouldShow(result, "body content"))
	})

	t.Run("no match status", func(t *testing.T) {
		result := &Result{StatusCode: 404, ContentLength: 100}
		assert.False(t, f.shouldShow(result, "body content"))
	})

	t.Run("filtered size", func(t *testing.T) {
		result := &Result{StatusCode: 200, ContentLength: 0}
		assert.False(t, f.shouldShow(result, ""))
	})
}

func TestFuzzerMatchRegex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/secret":
			w.Write([]byte("API_KEY=abc123secret"))
		default:
			w.Write([]byte("Nothing here"))
		}
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"secret", "public"},
		Concurrency: 1,
		MatchRegex:  regexp.MustCompile(`API_KEY=\w+`),
	}

	f := NewFuzzer(cfg)
	var count int32
	f.Run(context.Background(), func(r *Result) {
		atomic.AddInt32(&count, 1)
	})

	assert.Equal(t, int32(1), count) // Only /secret should match
}

func TestCalibration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return consistent response for calibration
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Page not found - standard error"))
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"test"},
		Concurrency: 1,
	}

	f := NewFuzzer(cfg)
	cal := f.Calibrate(context.Background())

	require.NotNil(t, cal)
	assert.Equal(t, 404, cal.BaselineStatus)
	assert.Greater(t, cal.BaselineSize, 0)
}

func TestCalibrationShouldFilter(t *testing.T) {
	cal := &Calibration{
		BaselineStatus: 404,
		BaselineSize:   100,
		BaselineWords:  10,
		BaselineLines:  5,
		Threshold:      0.95,
	}

	t.Run("filter baseline response", func(t *testing.T) {
		result := &Result{
			StatusCode:    404,
			ContentLength: 100,
			WordCount:     10,
			LineCount:     5,
		}
		assert.True(t, cal.ShouldFilter(result))
	})

	t.Run("no filter different status", func(t *testing.T) {
		result := &Result{
			StatusCode:    200,
			ContentLength: 100,
		}
		assert.False(t, cal.ShouldFilter(result))
	})

	t.Run("no filter different size", func(t *testing.T) {
		result := &Result{
			StatusCode:    404,
			ContentLength: 500, // Different size
			WordCount:     10,
			LineCount:     5,
		}
		assert.False(t, cal.ShouldFilter(result))
	})
}

func TestRandomString(t *testing.T) {
	s1 := randomString(10)
	s2 := randomString(10)

	assert.Len(t, s1, 10)
	assert.Len(t, s2, 10)
	assert.NotEqual(t, s1, s2) // Should be random
}

func TestMedian(t *testing.T) {
	assert.Equal(t, 3, median([]int{1, 3, 5}))
	assert.Equal(t, 3, median([]int{1, 2, 3, 4, 5}))
	assert.Equal(t, 5, median([]int{5}))
	assert.Equal(t, 0, median([]int{}))
}

func TestAbs(t *testing.T) {
	assert.Equal(t, 5, abs(5))
	assert.Equal(t, 5, abs(-5))
	assert.Equal(t, 0, abs(0))
}

func TestFuzzerMultipleFUZZKeywords(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/api/FUZZ/action",
		Words:       []string{"users"},
		Concurrency: 1,
	}

	f := NewFuzzer(cfg)
	f.Run(context.Background(), nil)

	assert.Equal(t, "/api/users/action", receivedPath)
}

func TestFuzzerWithCookies(t *testing.T) {
	var receivedCookies string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookies = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"test"},
		Concurrency: 1,
		Cookies:     "session=abc123; auth=token",
	}

	f := NewFuzzer(cfg)
	f.Run(context.Background(), nil)

	assert.Equal(t, "session=abc123; auth=token", receivedCookies)
}

func TestFuzzerNilCallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{
		TargetURL:   server.URL + "/FUZZ",
		Words:       []string{"test"},
		Concurrency: 1,
	}

	f := NewFuzzer(cfg)
	stats := f.Run(context.Background(), nil)

	require.NotNil(t, stats)
	assert.Equal(t, int64(1), stats.TotalRequests)
}

func TestFuzzerEmptyWords(t *testing.T) {
	cfg := &Config{
		TargetURL:   "http://example.com/FUZZ",
		Words:       []string{},
		Concurrency: 1,
	}

	f := NewFuzzer(cfg)
	stats := f.Run(context.Background(), nil)

	require.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalRequests)
}
