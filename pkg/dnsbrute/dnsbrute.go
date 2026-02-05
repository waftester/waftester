// Package dnsbrute provides DNS bruteforce subdomain enumeration
package dnsbrute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waftester/waftester/pkg/defaults"
	"github.com/waftester/waftester/pkg/duration"
)

// Config configures DNS bruteforce
type Config struct {
	Wordlist       string        // Path to wordlist file
	Concurrency    int           // Number of concurrent workers
	Timeout        time.Duration // DNS query timeout
	Resolvers      []string      // Custom resolvers
	Retries        int           // Number of retries per query
	WildcardFilter bool          // Filter wildcard responses
	RecursionDepth int           // Depth for recursive brute
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Concurrency:    defaults.ConcurrencyDNS,
		Timeout:        duration.DNSTimeout,
		Resolvers:      DefaultResolvers(),
		Retries:        defaults.RetryLow,
		WildcardFilter: true,
		RecursionDepth: 0, // No recursion by default
	}
}

// DefaultResolvers returns default public DNS resolvers
func DefaultResolvers() []string {
	return []string{
		"8.8.8.8:53",        // Google
		"8.8.4.4:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"1.0.0.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
		"208.67.220.220:53", // OpenDNS
	}
}

// Result represents a DNS bruteforce result
type Result struct {
	Subdomain  string    `json:"subdomain"`
	Domain     string    `json:"domain"`
	FQDN       string    `json:"fqdn"`
	IPs        []string  `json:"ips,omitempty"`
	CNAMEs     []string  `json:"cnames,omitempty"`
	IsWildcard bool      `json:"is_wildcard"`
	Resolver   string    `json:"resolver"`
	Timestamp  time.Time `json:"timestamp"`
}

// Stats tracks bruteforce statistics
type Stats struct {
	Total     int64         `json:"total"`
	Tested    int64         `json:"tested"`
	Found     int64         `json:"found"`
	Errors    int64         `json:"errors"`
	Wildcards int64         `json:"wildcards"`
	Duration  time.Duration `json:"duration"`
	Rate      float64       `json:"rate_per_second"`
}

// Bruteforcer performs DNS bruteforce enumeration
type Bruteforcer struct {
	config    Config
	resolvers []*net.Resolver
	wildcards map[string][]string
	results   []Result
	stats     Stats
	mu        sync.RWMutex
	startTime time.Time
	cancel    context.CancelFunc
}

// NewBruteforcer creates a DNS bruteforcer
func NewBruteforcer(config Config) *Bruteforcer {
	if config.Concurrency <= 0 {
		config.Concurrency = defaults.ConcurrencyDNS
	}
	if config.Timeout <= 0 {
		config.Timeout = duration.DNSTimeout
	}
	if len(config.Resolvers) == 0 {
		config.Resolvers = DefaultResolvers()
	}
	if config.Retries <= 0 {
		config.Retries = defaults.RetryLow
	}

	resolvers := make([]*net.Resolver, len(config.Resolvers))
	for i, r := range config.Resolvers {
		resolver := r // Capture loop variable for closure
		resolvers[i] = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: config.Timeout}
				return d.DialContext(ctx, "udp", resolver)
			},
		}
	}

	return &Bruteforcer{
		config:    config,
		resolvers: resolvers,
		wildcards: make(map[string][]string),
		results:   make([]Result, 0),
	}
}

// Run performs DNS bruteforce on a domain
func (b *Bruteforcer) Run(ctx context.Context, domain string, words []string) ([]Result, error) {
	ctx, cancel := context.WithCancel(ctx)
	b.cancel = cancel
	defer cancel() // Ensure context is cancelled when function returns
	b.startTime = time.Now()
	atomic.StoreInt64(&b.stats.Total, int64(len(words)))

	// Detect wildcards first
	if b.config.WildcardFilter {
		if err := b.detectWildcard(ctx, domain); err != nil {
			// Non-fatal, continue without wildcard filtering
		}
	}

	// Worker pool
	wordChan := make(chan string, b.config.Concurrency)
	resultChan := make(chan Result, b.config.Concurrency)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < b.config.Concurrency; i++ {
		wg.Add(1)
		go func(resolverIdx int) {
			defer wg.Done()
			resolver := b.resolvers[resolverIdx%len(b.resolvers)]
			for word := range wordChan {
				select {
				case <-ctx.Done():
					return
				default:
					if result, err := b.bruteforce(ctx, domain, word, resolver); err == nil {
						resultChan <- result
					}
					atomic.AddInt64(&b.stats.Tested, 1)
				}
			}
		}(i)
	}

	// Feed words
	go func() {
		defer close(wordChan)
		for _, word := range words {
			select {
			case <-ctx.Done():
				return
			case wordChan <- word:
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if !result.IsWildcard {
			b.mu.Lock()
			b.results = append(b.results, result)
			b.mu.Unlock()
			atomic.AddInt64(&b.stats.Found, 1)
		} else {
			atomic.AddInt64(&b.stats.Wildcards, 1)
		}
	}

	b.stats.Duration = time.Since(b.startTime)
	if b.stats.Duration.Seconds() > 0 {
		b.stats.Rate = float64(b.stats.Tested) / b.stats.Duration.Seconds()
	}

	return b.results, nil
}

// RunWithWordlist reads words from file and runs bruteforce
func (b *Bruteforcer) RunWithWordlist(ctx context.Context, domain string) ([]Result, error) {
	if b.config.Wordlist == "" {
		return nil, fmt.Errorf("wordlist path required")
	}

	words, err := loadWordlist(b.config.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	return b.Run(ctx, domain, words)
}

// Stop cancels the bruteforce operation
func (b *Bruteforcer) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
}

// GetStats returns current statistics
func (b *Bruteforcer) GetStats() Stats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := b.stats
	stats.Duration = time.Since(b.startTime)
	if stats.Duration.Seconds() > 0 {
		stats.Rate = float64(stats.Tested) / stats.Duration.Seconds()
	}
	return stats
}

// GetResults returns found results
func (b *Bruteforcer) GetResults() []Result {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.results
}

// bruteforce tests a single subdomain
func (b *Bruteforcer) bruteforce(ctx context.Context, domain, word string, resolver *net.Resolver) (Result, error) {
	fqdn := fmt.Sprintf("%s.%s", word, domain)
	result := Result{
		Subdomain: word,
		Domain:    domain,
		FQDN:      fqdn,
		Timestamp: time.Now(),
	}

	var lastErr error
	for retry := 0; retry <= b.config.Retries; retry++ {
		ips, err := resolver.LookupHost(ctx, fqdn)
		if err == nil {
			result.IPs = ips
			result.IsWildcard = b.isWildcard(domain, ips)
			return result, nil
		}
		lastErr = err

		// Check for CNAME
		cname, err := resolver.LookupCNAME(ctx, fqdn)
		if err == nil && cname != "" && cname != fqdn+"." {
			result.CNAMEs = append(result.CNAMEs, strings.TrimSuffix(cname, "."))
			result.IsWildcard = b.isWildcardCNAME(domain, cname)
			return result, nil
		}
	}

	atomic.AddInt64(&b.stats.Errors, 1)
	return Result{}, lastErr
}

// detectWildcard detects wildcard DNS
func (b *Bruteforcer) detectWildcard(ctx context.Context, domain string) error {
	// Generate random subdomain for wildcard detection
	randomSub := fmt.Sprintf("wc%d%d%d", time.Now().UnixNano()%1000, time.Now().UnixNano()%100, time.Now().UnixNano()%10)
	fqdn := fmt.Sprintf("%s.%s", randomSub, domain)

	for _, resolver := range b.resolvers {
		ips, err := resolver.LookupHost(ctx, fqdn)
		if err == nil && len(ips) > 0 {
			b.mu.Lock()
			b.wildcards[domain] = ips
			b.mu.Unlock()
			break
		}
	}

	return nil
}

// isWildcard checks if IPs match wildcard
func (b *Bruteforcer) isWildcard(domain string, ips []string) bool {
	b.mu.RLock()
	wildcardIPs, ok := b.wildcards[domain]
	b.mu.RUnlock()

	if !ok {
		return false
	}

	for _, ip := range ips {
		for _, wcIP := range wildcardIPs {
			if ip == wcIP {
				return true
			}
		}
	}
	return false
}

// isWildcardCNAME checks if CNAME matches wildcard pattern
func (b *Bruteforcer) isWildcardCNAME(domain, cname string) bool {
	// Check for common wildcard CNAME patterns
	wildcardPatterns := []string{
		"*." + domain,
		"wildcard.",
		"catch-all.",
	}

	for _, pattern := range wildcardPatterns {
		if strings.Contains(cname, pattern) {
			return true
		}
	}
	return false
}

// loadWordlist reads words from file
func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

// CommonWordlist returns a common wordlist for testing
func CommonWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
		"ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
		"mx", "mx1", "mx2", "email", "remote", "blog", "shop",
		"api", "dev", "staging", "test", "qa", "uat", "prod",
		"admin", "administrator", "portal", "gateway", "vpn", "secure",
		"app", "apps", "mobile", "m", "wap", "cdn", "static",
		"assets", "img", "images", "media", "video", "download",
		"upload", "files", "backup", "db", "database", "sql", "mysql",
		"postgres", "mongo", "redis", "cache", "queue", "mq",
		"jenkins", "gitlab", "github", "ci", "cd", "build",
		"monitor", "grafana", "prometheus", "elastic", "kibana", "logs",
		"status", "health", "metrics", "auth", "sso", "oauth", "login",
		"register", "signup", "account", "user", "users", "customer",
		"support", "help", "docs", "documentation", "wiki", "forum",
		"community", "social", "connect", "share", "chat", "msg",
		"news", "press", "about", "info", "contact", "feedback",
		"search", "beta", "alpha", "demo", "sandbox", "playground",
		"internal", "intranet", "extranet", "partner", "vendor", "client",
	}
}

// RecursiveBrute performs recursive subdomain bruteforcing
type RecursiveBrute struct {
	config   Config
	maxDepth int
	results  map[string]Result
	mu       sync.RWMutex
}

// NewRecursiveBrute creates a recursive bruteforcer
func NewRecursiveBrute(config Config) *RecursiveBrute {
	depth := config.RecursionDepth
	if depth <= 0 {
		depth = 2
	}
	return &RecursiveBrute{
		config:   config,
		maxDepth: depth,
		results:  make(map[string]Result),
	}
}

// Run performs recursive bruteforce
func (r *RecursiveBrute) Run(ctx context.Context, domain string, words []string) ([]Result, error) {
	return r.recurse(ctx, domain, words, 0)
}

func (r *RecursiveBrute) recurse(ctx context.Context, domain string, words []string, depth int) ([]Result, error) {
	if depth >= r.maxDepth {
		return nil, nil
	}

	brute := NewBruteforcer(r.config)
	results, err := brute.Run(ctx, domain, words)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	for _, result := range results {
		r.results[result.FQDN] = result
	}
	r.mu.Unlock()

	// Recurse into found subdomains
	for _, result := range results {
		if !result.IsWildcard && len(result.IPs) > 0 {
			_, _ = r.recurse(ctx, result.FQDN, words, depth+1)
		}
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var allResults []Result
	for _, result := range r.results {
		allResults = append(allResults, result)
	}

	return allResults, nil
}

// PermutationGenerator generates subdomain permutations
type PermutationGenerator struct {
	prefixes []string
	suffixes []string
	numbers  []string
}

// NewPermutationGenerator creates a permutation generator
func NewPermutationGenerator() *PermutationGenerator {
	return &PermutationGenerator{
		prefixes: []string{"dev", "staging", "test", "uat", "qa", "prod", "new", "old", "beta", "alpha"},
		suffixes: []string{"api", "app", "web", "srv", "svc", "backend", "frontend", "admin"},
		numbers:  []string{"1", "2", "3", "01", "02", "001", "002"},
	}
}

// Generate creates permutations from base words
func (p *PermutationGenerator) Generate(baseWords []string) []string {
	seen := make(map[string]bool)
	var permutations []string

	addUnique := func(word string) {
		if !seen[word] {
			seen[word] = true
			permutations = append(permutations, word)
		}
	}

	for _, base := range baseWords {
		addUnique(base)

		// Add prefixes
		for _, prefix := range p.prefixes {
			addUnique(prefix + "-" + base)
			addUnique(prefix + base)
		}

		// Add suffixes
		for _, suffix := range p.suffixes {
			addUnique(base + "-" + suffix)
			addUnique(base + suffix)
		}

		// Add numbers
		for _, num := range p.numbers {
			addUnique(base + num)
			addUnique(base + "-" + num)
		}
	}

	sort.Strings(permutations)
	return permutations
}

// GenerateFromDiscovered generates permutations from discovered subdomains
func (p *PermutationGenerator) GenerateFromDiscovered(discovered []Result) []string {
	baseWords := make([]string, 0, len(discovered))
	for _, r := range discovered {
		baseWords = append(baseWords, r.Subdomain)
	}
	return p.Generate(baseWords)
}

// MergeResults combines and deduplicates results
func MergeResults(resultSets ...[]Result) []Result {
	seen := make(map[string]Result)
	for _, set := range resultSets {
		for _, r := range set {
			existing, ok := seen[r.FQDN]
			if !ok {
				seen[r.FQDN] = r
			} else {
				// Merge IPs and CNAMEs
				merged := existing
				for _, ip := range r.IPs {
					found := false
					for _, eip := range merged.IPs {
						if ip == eip {
							found = true
							break
						}
					}
					if !found {
						merged.IPs = append(merged.IPs, ip)
					}
				}
				seen[r.FQDN] = merged
			}
		}
	}

	var results []Result
	for _, r := range seen {
		results = append(results, r)
	}

	// Sort by FQDN
	sort.Slice(results, func(i, j int) bool {
		return results[i].FQDN < results[j].FQDN
	})

	return results
}
