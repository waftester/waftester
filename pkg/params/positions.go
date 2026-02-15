// Package params — multi-position parameter discovery (JSON body, headers, cookies).
// Extends the Arjun-style query/body discovery with additional positions.
package params

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/iohelper"
)

// containsPosition checks if a position is in the list.
func containsPosition(positions []string, target string) bool {
	for _, p := range positions {
		if p == target {
			return true
		}
	}
	return false
}

// jsonBodyDiscovery tests parameters in JSON body format.
// Sends POST with Content-Type: application/json and body {"param1":"canary",...}.
// Uses the same binary search strategy as wordlistDiscovery.
func (d *Discoverer) jsonBodyDiscovery(ctx context.Context, targetURL string, baseline *baselineResponse) []DiscoveredParam {
	var params []DiscoveredParam
	var mu sync.Mutex

	jsonBaseline, err := d.getJSONBaseline(ctx, targetURL)
	if err != nil {
		return params
	}

	words := d.getWordlist()
	chunkSize := 256

	var chunks [][]string
	for i := 0; i < len(words); i += chunkSize {
		end := i + chunkSize
		if end > len(words) {
			end = len(words)
		}
		chunks = append(chunks, words[i:end])
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, d.concurrency)

	for _, chunk := range chunks {
		wg.Add(1)
		go func(c []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			found := d.testJSONParamChunk(ctx, targetURL, c, jsonBaseline)
			if len(found) > 0 {
				mu.Lock()
				params = append(params, found...)
				mu.Unlock()
			}
		}(chunk)
	}
	wg.Wait()
	return params
}

func (d *Discoverer) getJSONBaseline(ctx context.Context, targetURL string) (*baselineResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", d.userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	body, _ := iohelper.ReadBodyDefault(resp.Body)

	return &baselineResponse{
		StatusCode:    resp.StatusCode,
		ContentLength: len(body),
		ContentHash:   fmt.Sprintf("%x", md5.Sum(body)),
		Headers:       resp.Header,
	}, nil
}

func (d *Discoverer) testJSONParamChunk(ctx context.Context, targetURL string, chunk []string, baseline *baselineResponse) []DiscoveredParam {
	if ctx.Err() != nil {
		return nil
	}
	var found []DiscoveredParam
	canary := generateCanary()

	jsonObj := make(map[string]string, len(chunk))
	for _, param := range chunk {
		jsonObj[param] = canary + param
	}
	body, err := json.Marshal(jsonObj)
	if err != nil {
		return found
	}

	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		return found
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", d.userAgent)

	resp, err := d.client.Do(req)
	if err != nil {
		return found
	}
	defer iohelper.DrainAndClose(resp.Body)
	respBody, _ := iohelper.ReadBodyDefault(resp.Body)
	newHash := fmt.Sprintf("%x", md5.Sum(respBody))

	differs := resp.StatusCode != baseline.StatusCode ||
		len(respBody) != baseline.ContentLength ||
		newHash != baseline.ContentHash

	if !differs {
		return found
	}

	// Binary search to isolate which params caused the change
	if len(chunk) > 1 {
		mid := len(chunk) / 2
		left := d.testJSONParamChunk(ctx, targetURL, chunk[:mid], baseline)
		right := d.testJSONParamChunk(ctx, targetURL, chunk[mid:], baseline)
		found = append(found, left...)
		found = append(found, right...)
	} else if len(chunk) == 1 {
		found = append(found, DiscoveredParam{
			Name:       chunk[0],
			Type:       "json",
			Confidence: 0.85,
			Source:     "wordlist-json",
			Methods:    []string{"POST"},
		})
	}
	return found
}

// headerDiscovery tests if adding custom headers causes response changes.
// Uses smaller chunks (10) since HTTP header count is limited.
func (d *Discoverer) headerDiscovery(ctx context.Context, targetURL string, baseline *baselineResponse) []DiscoveredParam {
	var params []DiscoveredParam
	headerWords := commonHeaders()
	chunkSize := 10

	for i := 0; i < len(headerWords); i += chunkSize {
		select {
		case <-ctx.Done():
			return params
		default:
		}

		end := i + chunkSize
		if end > len(headerWords) {
			end = len(headerWords)
		}
		chunk := headerWords[i:end]

		canary := generateCanary()
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		for _, h := range chunk {
			req.Header.Set(h, canary+h)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		newHash := fmt.Sprintf("%x", md5.Sum(body))

		differs := resp.StatusCode != baseline.StatusCode ||
			len(body) != baseline.ContentLength ||
			newHash != baseline.ContentHash

		if !differs {
			continue
		}

		// Binary search within this chunk
		found := d.binarySearchHeaders(ctx, targetURL, baseline, chunk, canary)
		params = append(params, found...)
	}
	return params
}

func (d *Discoverer) binarySearchHeaders(ctx context.Context, targetURL string, baseline *baselineResponse, headers []string, canary string) []DiscoveredParam {
	if ctx.Err() != nil {
		return nil
	}
	var found []DiscoveredParam

	if len(headers) == 1 {
		found = append(found, DiscoveredParam{
			Name:       headers[0],
			Type:       "header",
			Confidence: 0.80,
			Source:     "wordlist-header",
			Methods:    []string{"GET"},
		})
		return found
	}

	mid := len(headers) / 2
	for _, half := range [][]string{headers[:mid], headers[mid:]} {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		for _, h := range half {
			req.Header.Set(h, canary+h)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		newHash := fmt.Sprintf("%x", md5.Sum(body))

		differs := resp.StatusCode != baseline.StatusCode ||
			len(body) != baseline.ContentLength ||
			newHash != baseline.ContentHash

		if differs {
			sub := d.binarySearchHeaders(ctx, targetURL, baseline, half, canary)
			found = append(found, sub...)
		}
	}
	return found
}

// cookieDiscovery tests if adding cookies causes response changes.
func (d *Discoverer) cookieDiscovery(ctx context.Context, targetURL string, baseline *baselineResponse) []DiscoveredParam {
	var params []DiscoveredParam
	words := d.getWordlist()
	chunkSize := 50

	for i := 0; i < len(words); i += chunkSize {
		select {
		case <-ctx.Done():
			return params
		default:
		}

		end := i + chunkSize
		if end > len(words) {
			end = len(words)
		}
		chunk := words[i:end]

		canary := generateCanary()
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		for _, name := range chunk {
			req.AddCookie(&http.Cookie{Name: name, Value: canary + name})
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		newHash := fmt.Sprintf("%x", md5.Sum(body))

		differs := resp.StatusCode != baseline.StatusCode ||
			len(body) != baseline.ContentLength ||
			newHash != baseline.ContentHash

		if !differs {
			continue
		}

		found := d.binarySearchCookies(ctx, targetURL, baseline, chunk, canary)
		params = append(params, found...)
	}
	return params
}

func (d *Discoverer) binarySearchCookies(ctx context.Context, targetURL string, baseline *baselineResponse, cookies []string, canary string) []DiscoveredParam {
	if ctx.Err() != nil {
		return nil
	}
	var found []DiscoveredParam

	if len(cookies) == 1 {
		found = append(found, DiscoveredParam{
			Name:       cookies[0],
			Type:       "cookie",
			Confidence: 0.80,
			Source:     "wordlist-cookie",
			Methods:    []string{"GET"},
		})
		return found
	}

	mid := len(cookies) / 2
	for _, half := range [][]string{cookies[:mid], cookies[mid:]} {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.userAgent)
		for _, name := range half {
			req.AddCookie(&http.Cookie{Name: name, Value: canary + name})
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body)
		newHash := fmt.Sprintf("%x", md5.Sum(body))

		differs := resp.StatusCode != baseline.StatusCode ||
			len(body) != baseline.ContentLength ||
			newHash != baseline.ContentHash

		if differs {
			sub := d.binarySearchCookies(ctx, targetURL, baseline, half, canary)
			found = append(found, sub...)
		}
	}
	return found
}

// commonHeaders returns a curated list of headers for discovery.
func commonHeaders() []string {
	return []string{
		"X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
		"X-API-Key", "X-Auth-Token", "X-CSRF-Token", "X-Request-ID",
		"True-Client-IP", "CF-Connecting-IP", "Fastly-Client-IP",
		"X-Cluster-Client-IP", "X-Client-IP", "X-Originating-IP",
		"X-Remote-IP", "X-Remote-Addr", "X-Host",
		"X-Forwarded-Server", "X-HTTP-Method-Override",
		"X-Method-Override", "X-HTTP-Method", "X-Requested-With",
		"X-Debug", "X-Debug-Token", "X-Token",
		"X-ProxyUser-Ip", "X-Original-Host", "X-Forwarded-By",
		"X-Originating-URL", "X-Original-Method", "X-Http-Destinationurl",
		"X-Arbitrary", "X-Custom-Header", "Proxy-Host",
		"Forwarded", "Via", "X-Backend-Server",
		"X-Content-Type-Options", "X-Permitted-Cross-Domain-Policies",
		"Access-Control-Allow-Origin", "Origin",
		"X-Api-Version", "X-Version", "Accept-Version",
		"If-None-Match", "If-Modified-Since", "X-Request-Start",
		"X-Correlation-ID", "X-Trace-ID", "X-Span-ID",
		"X-Amzn-Trace-Id", "Traceparent", "Tracestate",
	}
}
