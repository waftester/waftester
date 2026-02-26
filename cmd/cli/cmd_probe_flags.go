// cmd_probe_flags.go - Flag definitions for the probe command
// Extracted from cmd_probe.go to reduce function complexity
package main

import (
	"flag"
	"time"

	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/ui"
)

// probeConfig bundles all flag values for the probe command.
type probeConfig struct {
	Out OutputFlags

	// Target and basic options
	TargetURLs  input.StringSliceFlag
	OutputFile  *string
	Timeout     *int
	Silent      *bool
	Oneliner    *bool
	Concurrency *int

	// Probe toggles
	TLSProbe     *bool
	HeaderProbe  *bool
	HTTPProbe    *bool
	WAFProbe     *bool
	FaviconProbe *bool
	JARMProbe    *bool
	TechProbe    *bool
	DNSProbe     *bool

	// Output format flags
	JSONOutput *bool
	JSONL      *bool
	StdinInput *bool
	CSVOutput  *bool

	// httpx-style output flags
	ShowContentLength *bool
	ShowContentType   *bool
	ShowWordCount     *bool
	ShowLineCount     *bool
	ShowServer        *bool
	ShowMethod        *bool
	ShowLocation      *bool
	FollowRedirects   *bool
	MaxRedirects      *int
	CustomHeaders     *string
	HTTPMethod        *string
	RequestBody       *string
	RandomAgent       *bool
	ProbeStatus       *bool

	// Missing httpx features
	SkipVerify       *bool
	Retries          *int
	Delay            *time.Duration
	RateLimit        *int
	RateLimitPerHost *bool
	ProxyURL         *string
	StoreResponse    *bool
	StoreResponseDir *string

	// Additional output flags
	HashType  *string
	Debug     *bool
	ShowTitle *bool
	ShowIP    *bool
	ShowASN   *bool
	ShowCDN   *bool
	ShowTech  *bool
	ListFile  *string
	OutputCSV *string

	// More httpx features - section 2
	BodyPreview     *int
	ShowWebSocket   *bool
	ShowCNAME       *bool
	ExtractRegex    *string
	ExtractPreset   *string
	ProbePorts      *string
	ProbePaths      *string
	ShowHTTP2       *bool
	ShowPipeline    *bool
	ShowStats       *bool
	NoColor         *bool
	Verbose         *bool
	Threads         *int
	IncludeChain    *bool
	HeaderHash      *bool
	ShowFaviconHash *bool
	ShowScheme      *bool
	MatchCode       *string
	FilterCode      *string
	MatchString     *string
	FilterString    *string

	// Additional httpx matchers
	MatchLength    *string
	MatchLineCount *string
	MatchWordCount *string
	MatchRegex     *string
	MatchFavicon   *string
	MatchCDN       *string
	MatchRespTime  *string

	// Additional httpx filters
	FilterLength    *string
	FilterLineCount *string
	FilterWordCount *string
	FilterRegex     *string
	FilterFavicon   *string
	FilterCDN       *string
	FilterRespTime  *string

	// Batch 1: Missing Probe flags
	ExtractFQDN   *bool
	ShowCPE       *bool
	ShowWordPress *bool

	// Batch 2: Missing Rate-Limit flags
	RateLimitMinute *int

	// Batch 3: Missing Misc flags
	ProbeAllIPs       *bool
	TLSProbeExtracted *bool
	CSPProbe          *bool
	TLSGrab           *bool
	VHostProbe        *bool
	ListDSLVars       *bool

	// Batch 4: Missing Output flags
	OutputAll         *bool
	OmitBody          *bool
	CSVEncoding       *string
	IncludeRespHeader *bool
	IncludeResponse   *bool
	IncludeRespBase64 *bool
	StoreChain        *bool
	ProtocolOutput    *string
	ListOutputFields  *bool
	ExcludeFields     *string

	// Batch 5: Missing Filter flags
	FilterErrorPage  *bool
	FilterDuplicates *bool
	StripTags        *string

	// Batch 6: Missing Config flags
	ConfigFile          *string
	Resolvers           *string
	AllowList           *string
	DenyList            *string
	SNIName             *string
	AutoReferer         *bool
	UnsafeMode          *bool
	ResumeScan          *bool
	FollowHostRedirects *bool
	RespectHSTS         *bool
	VHostInput          *bool
	StreamMode          *bool
	SkipDedupe          *bool
	LeaveDefaultPorts   *bool
	UseZTLS             *bool
	NoDecode            *bool
	TLSImpersonate      *bool
	NoStdin             *bool
	SecretFile          *string

	// Batch 7: Missing Debug flags
	HealthCheck   *bool
	DebugReq      *bool
	DebugResp     *bool
	ShowVersion   *bool
	StatsInterval *int
	TraceMode     *bool

	// Batch 8: Missing Optimization flags
	NoFallback       *bool
	NoFallbackScheme *bool
	MaxHostErrors    *int
	ExcludeHosts     *string
	RespSizeToSave   *int
	RespSizeToRead   *int

	// DSL Condition Matching
	MatchCondition  *string
	FilterCondition *string

	// Raw Request Support
	RawRequestFile *string
	InputMode      *string

	// Screenshot/Headless
	Screenshot        *bool
	ScreenshotTimeout *int

	// Simhash
	SimhashThreshold *int

	// Custom fingerprint file
	CustomFingerprintFile *string

	// HTML summary report
	HTMLOutput *string

	// Memory profiling
	MemProfile *string

	// Update command
	UpdateCheck        *bool
	DisableUpdateCheck *bool

	// Headless options
	SystemChrome           *bool
	HeadlessOptions        *string
	ExcludeScreenshotBytes *bool
	NoScreenshotFullPage   *bool
	ExcludeHeadlessBody    *bool
	ScreenshotIdle         *int
	JavascriptCode         *string

	// Output options (httpx compatibility)
	StoreVisionRecon    *bool
	FilterErrorPagePath *string

	// HTTP API
	HTTPAPIEndpoint *string

	// Cloud/Dashboard (httpx compatibility)
	PdAuth            *bool
	PdAuthConfig      *string
	PdDashboard       *bool
	PdTeamID          *string
	PdAssetID         *string
	PdAssetName       *string
	PdDashboardUpload *string
}

// registerProbeFlags creates the flag set and probeConfig for the probe command.
func registerProbeFlags() (*flag.FlagSet, *probeConfig) {
	probeFlags := flag.NewFlagSet("probe", flag.ExitOnError)
	cfg := &probeConfig{}

	// Target and basic options
	probeFlags.Var(&cfg.TargetURLs, "u", "Target URL(s) - comma-separated or repeated")
	probeFlags.Var(&cfg.TargetURLs, "target", "Target URL(s) - comma-separated or repeated")
	cfg.OutputFile = probeFlags.String("output", "", "Output file for results (JSON)")
	cfg.Timeout = probeFlags.Int("timeout", 10, "Request timeout in seconds")
	cfg.TLSProbe = probeFlags.Bool("tls", true, "Probe TLS configuration")
	cfg.HeaderProbe = probeFlags.Bool("headers", true, "Probe security headers")
	cfg.HTTPProbe = probeFlags.Bool("http", true, "Probe HTTP/2, pipeline, methods")
	cfg.WAFProbe = probeFlags.Bool("waf", true, "Detect WAF/CDN")
	cfg.FaviconProbe = probeFlags.Bool("favicon", true, "Probe favicon and calculate hash")
	cfg.JARMProbe = probeFlags.Bool("jarm", true, "Calculate JARM TLS fingerprint")
	cfg.TechProbe = probeFlags.Bool("tech", true, "Detect technologies (title, frameworks, CMS)")
	cfg.DNSProbe = probeFlags.Bool("dns", true, "DNS resolution (IP, CNAME, ASN)")
	cfg.JSONOutput = probeFlags.Bool("j", false, "Output in JSONL(ines) format")
	probeFlags.BoolVar(cfg.JSONOutput, "json", false, "Output in JSONL(ines) format")
	cfg.JSONL = probeFlags.Bool("jsonl", false, "Output in JSONL format (one JSON per line)")
	cfg.StdinInput = probeFlags.Bool("stdin", false, "Read targets from stdin")
	cfg.Silent = probeFlags.Bool("silent", false, "Only output results, no banner")
	cfg.Oneliner = probeFlags.Bool("1", false, "One-liner output (single line per result)")
	cfg.Concurrency = probeFlags.Int("c", 0, "Concurrency for multiple targets (overrides -t)")

	// httpx-style output flags
	cfg.ShowContentLength = probeFlags.Bool("cl", false, "Show content-length in output")
	cfg.ShowContentType = probeFlags.Bool("ct", false, "Show content-type in output")
	cfg.ShowWordCount = probeFlags.Bool("wc", false, "Show word count in output")
	cfg.ShowLineCount = probeFlags.Bool("lc", false, "Show line count in output")
	cfg.ShowServer = probeFlags.Bool("server", false, "Show server header in output")
	cfg.ShowMethod = probeFlags.Bool("method", false, "Show HTTP method in output")
	cfg.ShowLocation = probeFlags.Bool("location", false, "Show redirect location")
	cfg.FollowRedirects = probeFlags.Bool("fr", false, "Follow HTTP redirects")
	cfg.MaxRedirects = probeFlags.Int("max-redirects", 10, "Max redirects to follow")
	cfg.CustomHeaders = probeFlags.String("H", "", "Custom header (format: 'Name: Value')")
	cfg.HTTPMethod = probeFlags.String("x", "GET", "HTTP method to use")
	cfg.RequestBody = probeFlags.String("body", "", "Request body for POST/PUT")
	cfg.RandomAgent = probeFlags.Bool("random-agent", false, "Use random User-Agent")
	cfg.ProbeStatus = probeFlags.Bool("probe", false, "Show probe status (up/down)")

	// Missing httpx features - now added
	cfg.SkipVerify = probeFlags.Bool("k", false, "Skip TLS certificate verification")
	probeFlags.BoolVar(cfg.SkipVerify, "skip-verify", false, "Skip TLS certificate verification")
	cfg.Retries = probeFlags.Int("retries", 0, "Number of retries on failure")
	cfg.Delay = probeFlags.Duration("delay", 0, "Delay between requests (e.g., 100ms, 1s)")
	cfg.RateLimit = probeFlags.Int("rl", 0, "Rate limit (requests per second, 0=unlimited)")
	probeFlags.IntVar(cfg.RateLimit, "rate-limit", 0, "Rate limit (requests per second, 0=unlimited)")
	cfg.RateLimitPerHost = probeFlags.Bool("rlph", false, "Apply rate limit per host (not global)")
	probeFlags.BoolVar(cfg.RateLimitPerHost, "rate-limit-per-host", false, "Apply rate limit per host (not global)")
	cfg.ProxyURL = probeFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	cfg.StoreResponse = probeFlags.Bool("sr", false, "Store HTTP response to file")
	probeFlags.BoolVar(cfg.StoreResponse, "store-response", false, "Store HTTP response to file")
	cfg.StoreResponseDir = probeFlags.String("srd", "./responses", "Directory to store responses")
	probeFlags.StringVar(cfg.StoreResponseDir, "store-response-dir", "./responses", "Directory to store responses")
	cfg.CSVOutput = probeFlags.Bool("csv", false, "Output in CSV format")
	cfg.HashType = probeFlags.String("hash", "", "Calculate body hash (md5, sha256, mmh3)")
	cfg.Debug = probeFlags.Bool("debug", false, "Show request/response details")
	cfg.ShowTitle = probeFlags.Bool("title", false, "Show page title in output")
	cfg.ShowIP = probeFlags.Bool("ip", false, "Show resolved IP in output")
	cfg.ShowASN = probeFlags.Bool("asn", false, "Show ASN info in output")
	cfg.ShowCDN = probeFlags.Bool("cdn", false, "Show CDN/WAF detection in output")
	cfg.ShowTech = probeFlags.Bool("td", false, "Show technology detection in output")
	probeFlags.BoolVar(cfg.ShowTech, "tech-detect", false, "Show technology detection in output")
	cfg.ListFile = probeFlags.String("l", "", "File containing list of targets")
	probeFlags.StringVar(cfg.ListFile, "list", "", "File containing list of targets")
	cfg.OutputCSV = probeFlags.String("o", "", "Output file (auto-detect format by extension)")
	probeFlags.StringVar(cfg.OutputCSV, "output-file", "", "Output file (auto-detect format by extension)")

	// More httpx features - section 2
	cfg.BodyPreview = probeFlags.Int("bp", 0, "Show first N characters of response body")
	probeFlags.IntVar(cfg.BodyPreview, "body-preview", 0, "Show first N characters of response body")
	cfg.ShowWebSocket = probeFlags.Bool("ws", false, "Show WebSocket support")
	probeFlags.BoolVar(cfg.ShowWebSocket, "websocket", false, "Show WebSocket support")
	cfg.ShowCNAME = probeFlags.Bool("cname", false, "Show CNAME record in output")
	cfg.ExtractRegex = probeFlags.String("er", "", "Extract content matching regex")
	probeFlags.StringVar(cfg.ExtractRegex, "extract-regex", "", "Extract content matching regex")
	cfg.ExtractPreset = probeFlags.String("ep", "", "Extract preset patterns (url,ipv4,mail)")
	probeFlags.StringVar(cfg.ExtractPreset, "extract-preset", "", "Extract preset patterns (url,ipv4,mail)")
	cfg.ProbePorts = probeFlags.String("ports", "", "Ports to probe (e.g., 80,443,8080)")
	probeFlags.StringVar(cfg.ProbePorts, "p", "", "Ports to probe (e.g., 80,443,8080)")
	cfg.ProbePaths = probeFlags.String("path", "", "Paths to probe (comma-separated)")
	cfg.ShowHTTP2 = probeFlags.Bool("http2", false, "Show HTTP/2 support")
	cfg.ShowPipeline = probeFlags.Bool("pipeline", false, "Show HTTP pipelining support")
	cfg.ShowStats = probeFlags.Bool("stats", false, "Show scan statistics at end")
	cfg.NoColor = probeFlags.Bool("nc", false, "Disable colors in output")
	probeFlags.BoolVar(cfg.NoColor, "no-color", false, "Disable colors in output")
	cfg.Verbose = probeFlags.Bool("v", false, "Verbose output")
	probeFlags.BoolVar(cfg.Verbose, "verbose", false, "Verbose output")
	cfg.Threads = probeFlags.Int("t", 10, "Number of concurrent threads")
	probeFlags.IntVar(cfg.Threads, "threads", 10, "Number of concurrent threads")
	cfg.IncludeChain = probeFlags.Bool("include-chain", false, "Include redirect chain in output")
	cfg.HeaderHash = probeFlags.Bool("header-hash", false, "Show hash of response headers")
	cfg.ShowFaviconHash = probeFlags.Bool("favicon-hash", false, "Show favicon hash in one-liner output")
	cfg.ShowScheme = probeFlags.Bool("scheme", false, "Show URL scheme (http/https)")
	cfg.MatchCode = probeFlags.String("mc", "", "Match status codes (e.g., 200,302)")
	probeFlags.StringVar(cfg.MatchCode, "match-code", "", "Match status codes (e.g., 200,302)")
	cfg.FilterCode = probeFlags.String("fc", "", "Filter out status codes (e.g., 404,500)")
	probeFlags.StringVar(cfg.FilterCode, "filter-code", "", "Filter out status codes (e.g., 404,500)")
	cfg.MatchString = probeFlags.String("ms", "", "Match responses containing string")
	probeFlags.StringVar(cfg.MatchString, "match-string", "", "Match responses containing string")
	cfg.FilterString = probeFlags.String("fs", "", "Filter responses containing string")
	probeFlags.StringVar(cfg.FilterString, "filter-string", "", "Filter responses containing string")

	// Additional httpx matchers
	cfg.MatchLength = probeFlags.String("ml", "", "Match content length (e.g., 100,200-500)")
	probeFlags.StringVar(cfg.MatchLength, "match-length", "", "Match content length (e.g., 100,200-500)")
	cfg.MatchLineCount = probeFlags.String("mlc", "", "Match line count (e.g., 10,20-50)")
	probeFlags.StringVar(cfg.MatchLineCount, "match-line-count", "", "Match line count (e.g., 10,20-50)")
	cfg.MatchWordCount = probeFlags.String("mwc", "", "Match word count (e.g., 100,200-500)")
	probeFlags.StringVar(cfg.MatchWordCount, "match-word-count", "", "Match word count (e.g., 100,200-500)")
	cfg.MatchRegex = probeFlags.String("mr", "", "Match responses with regex")
	probeFlags.StringVar(cfg.MatchRegex, "match-regex", "", "Match responses with regex")
	cfg.MatchFavicon = probeFlags.String("mfc", "", "Match favicon hash (murmur3)")
	probeFlags.StringVar(cfg.MatchFavicon, "match-favicon", "", "Match favicon hash (murmur3)")
	cfg.MatchCDN = probeFlags.String("mcdn", "", "Match CDN provider (cloudflare,akamai,etc)")
	probeFlags.StringVar(cfg.MatchCDN, "match-cdn", "", "Match CDN provider (cloudflare,akamai,etc)")
	cfg.MatchRespTime = probeFlags.String("mrt", "", "Match response time (e.g., '<1s', '>500ms')")
	probeFlags.StringVar(cfg.MatchRespTime, "match-response-time", "", "Match response time (e.g., '<1s', '>500ms')")

	// Additional httpx filters
	cfg.FilterLength = probeFlags.String("fl", "", "Filter content length (e.g., 0,404)")
	probeFlags.StringVar(cfg.FilterLength, "filter-length", "", "Filter content length (e.g., 0,404)")
	cfg.FilterLineCount = probeFlags.String("flc", "", "Filter line count (e.g., 1,2)")
	probeFlags.StringVar(cfg.FilterLineCount, "filter-line-count", "", "Filter line count (e.g., 1,2)")
	cfg.FilterWordCount = probeFlags.String("fwc", "", "Filter word count (e.g., 0,10)")
	probeFlags.StringVar(cfg.FilterWordCount, "filter-word-count", "", "Filter word count (e.g., 0,10)")
	cfg.FilterRegex = probeFlags.String("fe", "", "Filter responses with regex")
	probeFlags.StringVar(cfg.FilterRegex, "filter-regex", "", "Filter responses with regex")
	cfg.FilterFavicon = probeFlags.String("ffc", "", "Filter favicon hash (murmur3)")
	probeFlags.StringVar(cfg.FilterFavicon, "filter-favicon", "", "Filter favicon hash (murmur3)")
	cfg.FilterCDN = probeFlags.String("fcdn", "", "Filter CDN provider (cloudflare,akamai,etc)")
	probeFlags.StringVar(cfg.FilterCDN, "filter-cdn", "", "Filter CDN provider (cloudflare,akamai,etc)")
	cfg.FilterRespTime = probeFlags.String("frt", "", "Filter response time (e.g., '>5s')")
	probeFlags.StringVar(cfg.FilterRespTime, "filter-response-time", "", "Filter response time (e.g., '>5s')")

	// Batch 1: Missing Probe flags
	cfg.ExtractFQDN = probeFlags.Bool("efqdn", false, "Extract domains/subdomains from response")
	probeFlags.BoolVar(cfg.ExtractFQDN, "extract-fqdn", false, "Extract domains/subdomains from response")
	cfg.ShowCPE = probeFlags.Bool("cpe", false, "Show CPE (Common Platform Enumeration)")
	cfg.ShowWordPress = probeFlags.Bool("wp", false, "Detect WordPress plugins and themes")
	probeFlags.BoolVar(cfg.ShowWordPress, "wordpress", false, "Detect WordPress plugins and themes")

	// Batch 2: Missing Rate-Limit flags
	cfg.RateLimitMinute = probeFlags.Int("rlm", 0, "Rate limit per minute (0=unlimited)")
	probeFlags.IntVar(cfg.RateLimitMinute, "rate-limit-minute", 0, "Rate limit per minute (0=unlimited)")

	// Batch 3: Missing Misc flags
	cfg.ProbeAllIPs = probeFlags.Bool("pa", false, "Probe all IPs associated with host")
	probeFlags.BoolVar(cfg.ProbeAllIPs, "probe-all-ips", false, "Probe all IPs associated with host")
	cfg.TLSProbeExtracted = probeFlags.Bool("tls-probe", false, "Send probes on extracted TLS domains")
	cfg.CSPProbe = probeFlags.Bool("csp-probe", false, "Send probes on extracted CSP domains")
	cfg.TLSGrab = probeFlags.Bool("tls-grab", false, "Perform TLS/SSL data grabbing")
	cfg.VHostProbe = probeFlags.Bool("vhost", false, "Probe and display VHOST support")
	cfg.ListDSLVars = probeFlags.Bool("ldv", false, "List DSL variable names")
	probeFlags.BoolVar(cfg.ListDSLVars, "list-dsl-variables", false, "List DSL variable names")

	// Batch 4: Missing Output flags
	cfg.OutputAll = probeFlags.Bool("oa", false, "Output in all formats (json, csv, txt)")
	probeFlags.BoolVar(cfg.OutputAll, "output-all", false, "Output in all formats (json, csv, txt)")
	cfg.OmitBody = probeFlags.Bool("ob", false, "Omit response body in output")
	probeFlags.BoolVar(cfg.OmitBody, "omit-body", false, "Omit response body in output")
	cfg.CSVEncoding = probeFlags.String("csvo", "utf-8", "CSV output encoding")
	probeFlags.StringVar(cfg.CSVEncoding, "csv-output-encoding", "utf-8", "CSV output encoding")
	cfg.IncludeRespHeader = probeFlags.Bool("irh", false, "Include response headers in JSON output")
	probeFlags.BoolVar(cfg.IncludeRespHeader, "include-response-header", false, "Include response headers in JSON output")
	cfg.IncludeResponse = probeFlags.Bool("irr", false, "Include full request/response in JSON output")
	probeFlags.BoolVar(cfg.IncludeResponse, "include-response", false, "Include full request/response in JSON output")
	cfg.IncludeRespBase64 = probeFlags.Bool("irrb", false, "Include base64 encoded response in JSON")
	probeFlags.BoolVar(cfg.IncludeRespBase64, "include-response-base64", false, "Include base64 encoded response in JSON")
	cfg.StoreChain = probeFlags.Bool("store-chain", false, "Store redirect chain in responses")
	cfg.ProtocolOutput = probeFlags.String("pr", "", "Protocol to use (http11, h2)")
	probeFlags.StringVar(cfg.ProtocolOutput, "protocol", "", "Protocol to use (http11, h2)")
	cfg.ListOutputFields = probeFlags.Bool("lof", false, "List available output field names")
	probeFlags.BoolVar(cfg.ListOutputFields, "list-output-fields", false, "List available output field names")
	cfg.ExcludeFields = probeFlags.String("eof", "", "Exclude output fields (comma-separated)")
	probeFlags.StringVar(cfg.ExcludeFields, "exclude-output-fields", "", "Exclude output fields (comma-separated)")

	// Batch 5: Missing Filter flags
	cfg.FilterErrorPage = probeFlags.Bool("fep", false, "Filter error pages")
	probeFlags.BoolVar(cfg.FilterErrorPage, "filter-error-page", false, "Filter error pages")
	cfg.FilterDuplicates = probeFlags.Bool("fd", false, "Filter near-duplicate responses")
	probeFlags.BoolVar(cfg.FilterDuplicates, "filter-duplicates", false, "Filter near-duplicate responses")
	cfg.StripTags = probeFlags.String("strip", "", "Strip tags from response (html, xml)")

	// Batch 6: Missing Config flags
	cfg.ConfigFile = probeFlags.String("config", "", "Path to config file")
	cfg.Resolvers = probeFlags.String("r", "", "Custom resolvers (file or comma-separated)")
	probeFlags.StringVar(cfg.Resolvers, "resolvers", "", "Custom resolvers (file or comma-separated)")
	cfg.AllowList = probeFlags.String("allow", "", "Allowed IP/CIDR list")
	cfg.DenyList = probeFlags.String("deny", "", "Denied IP/CIDR list")
	cfg.SNIName = probeFlags.String("sni", "", "Custom TLS SNI name")
	probeFlags.StringVar(cfg.SNIName, "sni-name", "", "Custom TLS SNI name")
	cfg.AutoReferer = probeFlags.Bool("auto-referer", false, "Set Referer header to current URL")
	cfg.UnsafeMode = probeFlags.Bool("unsafe", false, "Send raw requests without normalization")
	cfg.ResumeScan = probeFlags.Bool("resume", false, "Resume scan using resume.cfg")
	cfg.FollowHostRedirects = probeFlags.Bool("fhr", false, "Follow redirects on same host only")
	probeFlags.BoolVar(cfg.FollowHostRedirects, "follow-host-redirects", false, "Follow redirects on same host only")
	cfg.RespectHSTS = probeFlags.Bool("rhsts", false, "Respect HSTS for redirect requests")
	probeFlags.BoolVar(cfg.RespectHSTS, "respect-hsts", false, "Respect HSTS for redirect requests")
	cfg.VHostInput = probeFlags.Bool("vhost-input", false, "Get vhosts as input")
	cfg.StreamMode = probeFlags.Bool("s", false, "Stream mode - process without sorting")
	probeFlags.BoolVar(cfg.StreamMode, "stream", false, "Stream mode - process without sorting")
	cfg.SkipDedupe = probeFlags.Bool("sd", false, "Skip deduplication in stream mode")
	probeFlags.BoolVar(cfg.SkipDedupe, "skip-dedupe", false, "Skip deduplication in stream mode")
	cfg.LeaveDefaultPorts = probeFlags.Bool("ldp", false, "Leave default ports in host header")
	probeFlags.BoolVar(cfg.LeaveDefaultPorts, "leave-default-ports", false, "Leave default ports in host header")
	cfg.UseZTLS = probeFlags.Bool("ztls", false, "Use ztls library for TLS1.3")
	cfg.NoDecode = probeFlags.Bool("no-decode", false, "Avoid decoding response body")
	cfg.TLSImpersonate = probeFlags.Bool("tlsi", false, "Enable TLS client hello randomization")
	probeFlags.BoolVar(cfg.TLSImpersonate, "tls-impersonate", false, "Enable TLS client hello randomization")
	cfg.NoStdin = probeFlags.Bool("no-stdin", false, "Disable stdin processing")
	cfg.SecretFile = probeFlags.String("sf", "", "Path to secret file for authentication")
	probeFlags.StringVar(cfg.SecretFile, "secret-file", "", "Path to secret file for authentication")

	// Batch 7: Missing Debug flags
	cfg.HealthCheck = probeFlags.Bool("hc", false, "Run diagnostic check")
	probeFlags.BoolVar(cfg.HealthCheck, "health-check", false, "Run diagnostic check")
	cfg.DebugReq = probeFlags.Bool("debug-req", false, "Display request content")
	cfg.DebugResp = probeFlags.Bool("debug-resp", false, "Display response content")
	cfg.ShowVersion = probeFlags.Bool("version", false, "Display version")
	cfg.StatsInterval = probeFlags.Int("si", 5, "Stats update interval in seconds")
	probeFlags.IntVar(cfg.StatsInterval, "stats-interval", 5, "Stats update interval in seconds")
	cfg.TraceMode = probeFlags.Bool("tr", false, "Enable trace mode")
	probeFlags.BoolVar(cfg.TraceMode, "trace", false, "Enable trace mode")

	// Batch 8: Missing Optimization flags
	cfg.NoFallback = probeFlags.Bool("nf", false, "Display both HTTP and HTTPS results")
	probeFlags.BoolVar(cfg.NoFallback, "no-fallback", false, "Display both HTTP and HTTPS results")
	cfg.NoFallbackScheme = probeFlags.Bool("nfs", false, "Probe with scheme from input only")
	probeFlags.BoolVar(cfg.NoFallbackScheme, "no-fallback-scheme", false, "Probe with scheme from input only")
	cfg.MaxHostErrors = probeFlags.Int("maxhr", 30, "Max errors per host before skipping")
	probeFlags.IntVar(cfg.MaxHostErrors, "max-host-error", 30, "Max errors per host before skipping")
	cfg.ExcludeHosts = probeFlags.String("e", "", "Exclude hosts (cdn, private-ips, cidr, regex)")
	probeFlags.StringVar(cfg.ExcludeHosts, "exclude", "", "Exclude hosts (cdn, private-ips, cidr, regex)")
	cfg.RespSizeToSave = probeFlags.Int("rsts", 0, "Max response size to save (bytes)")
	probeFlags.IntVar(cfg.RespSizeToSave, "response-size-to-save", 0, "Max response size to save (bytes)")
	cfg.RespSizeToRead = probeFlags.Int("rstr", 0, "Max response size to read (bytes)")
	probeFlags.IntVar(cfg.RespSizeToRead, "response-size-to-read", 0, "Max response size to read (bytes)")

	// NEW: DSL Condition Matching (httpx power feature)
	cfg.MatchCondition = probeFlags.String("mdc", "", "Match with DSL expression (e.g., 'status_code == 200 && contains(body, \"admin\")')")
	probeFlags.StringVar(cfg.MatchCondition, "match-condition", "", "Match with DSL expression")
	cfg.FilterCondition = probeFlags.String("fdc", "", "Filter with DSL expression")
	probeFlags.StringVar(cfg.FilterCondition, "filter-condition", "", "Filter with DSL expression")

	// NEW: Raw Request Support (Burp import)
	cfg.RawRequestFile = probeFlags.String("rr", "", "File containing raw HTTP request")
	probeFlags.StringVar(cfg.RawRequestFile, "request", "", "File containing raw HTTP request")
	cfg.InputMode = probeFlags.String("im", "", "Input mode (burp for Burp XML)")
	probeFlags.StringVar(cfg.InputMode, "input-mode", "", "Input mode (burp for Burp XML)")

	// NEW: Screenshot/Headless (basic support)
	cfg.Screenshot = probeFlags.Bool("ss", false, "Enable saving screenshot (requires chromedp)")
	probeFlags.BoolVar(cfg.Screenshot, "screenshot", false, "Enable saving screenshot")
	cfg.ScreenshotTimeout = probeFlags.Int("st", 10, "Screenshot timeout in seconds")
	probeFlags.IntVar(cfg.ScreenshotTimeout, "screenshot-timeout", 10, "Screenshot timeout in seconds")

	// NEW: Simhash for near-duplicate detection
	cfg.SimhashThreshold = probeFlags.Int("simhash", 0, "Simhash similarity threshold (0-64, 0=disabled)")

	// NEW: Custom fingerprint file
	cfg.CustomFingerprintFile = probeFlags.String("cff", "", "Custom fingerprint file for tech detection")
	probeFlags.StringVar(cfg.CustomFingerprintFile, "custom-fingerprint-file", "", "Custom fingerprint file")

	// NEW: HTML summary report
	cfg.HTMLOutput = probeFlags.String("html", "", "Generate HTML summary report")

	// NEW: Memory profiling
	cfg.MemProfile = probeFlags.String("profile-mem", "", "Memory profile dump file")

	// NEW: Update command
	cfg.UpdateCheck = probeFlags.Bool("up", false, "Update to latest version")
	probeFlags.BoolVar(cfg.UpdateCheck, "update", false, "Update to latest version")
	cfg.DisableUpdateCheck = probeFlags.Bool("duc", false, "Disable automatic update check")
	probeFlags.BoolVar(cfg.DisableUpdateCheck, "disable-update-check", false, "Disable automatic update check")

	// HEADLESS OPTIONS (httpx compatibility)
	cfg.SystemChrome = probeFlags.Bool("system-chrome", false, "Use local installed chrome for screenshot")
	cfg.HeadlessOptions = probeFlags.String("ho", "", "Start headless chrome with additional options")
	probeFlags.StringVar(cfg.HeadlessOptions, "headless-options", "", "Start headless chrome with additional options")
	cfg.ExcludeScreenshotBytes = probeFlags.Bool("esb", false, "Exclude screenshot bytes from JSON output")
	probeFlags.BoolVar(cfg.ExcludeScreenshotBytes, "exclude-screenshot-bytes", false, "Exclude screenshot bytes from JSON output")
	cfg.NoScreenshotFullPage = probeFlags.Bool("no-screenshot-full-page", false, "Disable saving full page screenshot")
	cfg.ExcludeHeadlessBody = probeFlags.Bool("ehb", false, "Exclude headless header from JSON output")
	probeFlags.BoolVar(cfg.ExcludeHeadlessBody, "exclude-headless-body", false, "Exclude headless header from JSON output")
	cfg.ScreenshotIdle = probeFlags.Int("sid", 1, "Set idle time before taking screenshot in seconds")
	probeFlags.IntVar(cfg.ScreenshotIdle, "screenshot-idle", 1, "Set idle time before taking screenshot in seconds")
	cfg.JavascriptCode = probeFlags.String("jsc", "", "Execute JavaScript code after navigation")
	probeFlags.StringVar(cfg.JavascriptCode, "javascript-code", "", "Execute JavaScript code after navigation")

	// OUTPUT OPTIONS (httpx compatibility)
	cfg.StoreVisionRecon = probeFlags.Bool("svrc", false, "Include visual recon clusters (-ss and -sr only)")
	probeFlags.BoolVar(cfg.StoreVisionRecon, "store-vision-recon-cluster", false, "Include visual recon clusters")
	cfg.FilterErrorPagePath = probeFlags.String("fepp", "filtered_error_page.json", "Path to store filtered error pages")
	probeFlags.StringVar(cfg.FilterErrorPagePath, "filter-error-page-path", "filtered_error_page.json", "Path to store filtered error pages")

	// HTTP API (httpx compatibility)
	cfg.HTTPAPIEndpoint = probeFlags.String("hae", "", "Experimental HTTP API endpoint")
	probeFlags.StringVar(cfg.HTTPAPIEndpoint, "http-api-endpoint", "", "Experimental HTTP API endpoint")

	// CLOUD/DASHBOARD (httpx compatibility - stubs for API compatibility)
	cfg.PdAuth = probeFlags.Bool("auth", false, "Configure projectdiscovery cloud API key")
	cfg.PdAuthConfig = probeFlags.String("ac", "", "Configure pdcp API key credential file")
	probeFlags.StringVar(cfg.PdAuthConfig, "auth-config", "", "Configure pdcp API key credential file")
	cfg.PdDashboard = probeFlags.Bool("pd", false, "Upload/view output in projectdiscovery cloud UI")
	probeFlags.BoolVar(cfg.PdDashboard, "dashboard", false, "Upload/view output in pdcp UI")
	cfg.PdTeamID = probeFlags.String("tid", "", "Upload results to team ID")
	probeFlags.StringVar(cfg.PdTeamID, "team-id", "", "Upload results to team ID")
	cfg.PdAssetID = probeFlags.String("aid", "", "Upload to existing asset ID")
	probeFlags.StringVar(cfg.PdAssetID, "asset-id", "", "Upload to existing asset ID")
	cfg.PdAssetName = probeFlags.String("aname", "", "Asset group name to set")
	probeFlags.StringVar(cfg.PdAssetName, "asset-name", "", "Asset group name to set")
	cfg.PdDashboardUpload = probeFlags.String("pdu", "", "Upload httpx output file to pdcp UI")
	probeFlags.StringVar(cfg.PdDashboardUpload, "dashboard-upload", "", "Upload httpx output file to pdcp UI")

	// Output configuration (unified architecture)
	cfg.Out.RegisterProbeEnterpriseFlags(probeFlags)
	cfg.Out.Version = ui.Version

	return probeFlags, cfg
}
