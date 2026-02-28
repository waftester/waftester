// Package wordlist provides comprehensive wordlist management
// Including built-in wordlists, custom loading, and intelligent generation
package wordlist

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Wordlist represents a loaded wordlist
type Wordlist struct {
	Name        string       `json:"name"`
	Path        string       `json:"path"`
	Words       []string     `json:"words,omitempty"`
	Size        int          `json:"size"`
	Type        WordlistType `json:"type"`
	Category    string       `json:"category,omitempty"`
	Description string       `json:"description,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	Loaded      time.Time    `json:"loaded"`
}

// WordlistType defines the type of wordlist
type WordlistType string

const (
	TypeGeneral     WordlistType = "general"
	TypeDirectories WordlistType = "directories"
	TypeFiles       WordlistType = "files"
	TypeExtensions  WordlistType = "extensions"
	TypeParameters  WordlistType = "parameters"
	TypeSubdomains  WordlistType = "subdomains"
	TypeUsernames   WordlistType = "usernames"
	TypePasswords   WordlistType = "passwords"
	TypeAPI         WordlistType = "api"
	TypeBackup      WordlistType = "backup"
	TypeCMS         WordlistType = "cms"
	TypeDatabase    WordlistType = "database"
	TypeFuzzing     WordlistType = "fuzzing"
	TypePayloads    WordlistType = "payloads"
	TypeCustom      WordlistType = "custom"
)

// Manager handles wordlist loading, caching, and generation
type Manager struct {
	mu           sync.RWMutex
	cache        map[string]*Wordlist
	cacheDir     string
	maxCacheSize int64
	httpClient   *http.Client
	builtInLists map[string][]string
}

// Config for the wordlist manager
type Config struct {
	CacheDir        string
	MaxCacheSize    int64
	DownloadTimeout time.Duration
}

// NewManager creates a new wordlist manager
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = filepath.Join(os.TempDir(), "waf-tester-wordlists")
	}
	if cfg.MaxCacheSize == 0 {
		cfg.MaxCacheSize = 100 * 1024 * 1024 // 100MB
	}
	if cfg.DownloadTimeout == 0 {
		cfg.DownloadTimeout = httpclient.TimeoutLongOps
	}

	m := &Manager{
		cache:        make(map[string]*Wordlist),
		cacheDir:     cfg.CacheDir,
		maxCacheSize: cfg.MaxCacheSize,
		httpClient:   httpclient.New(httpclient.WithTimeout(cfg.DownloadTimeout)),
		builtInLists: initBuiltInLists(),
	}

	// Create cache directory
	if err := os.MkdirAll(cfg.CacheDir, 0755); err != nil {
		slog.Warn("wordlist: failed to create cache directory",
			slog.String("path", cfg.CacheDir),
			slog.String("error", err.Error()))
	}

	return m
}

// Load loads a wordlist from a file or URL
func (m *Manager) Load(source string) (*Wordlist, error) {
	m.mu.RLock()
	if wl, ok := m.cache[source]; ok {
		m.mu.RUnlock()
		return wl, nil
	}
	m.mu.RUnlock()

	// Check for built-in wordlists
	if strings.HasPrefix(source, "builtin:") {
		name := strings.TrimPrefix(source, "builtin:")
		return m.loadBuiltIn(name)
	}

	// Check if it's a URL
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return m.loadFromURL(source)
	}

	// Load from file
	return m.loadFromFile(source)
}

// LoadMultiple loads multiple wordlists and combines them
func (m *Manager) LoadMultiple(sources []string) (*Wordlist, error) {
	var allWords []string
	names := make([]string, 0, len(sources))

	for _, source := range sources {
		wl, err := m.Load(source)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", source, err)
		}
		allWords = append(allWords, wl.Words...)
		names = append(names, wl.Name)
	}

	// Deduplicate
	allWords = deduplicate(allWords)

	return &Wordlist{
		Name:   strings.Join(names, "+"),
		Words:  allWords,
		Size:   len(allWords),
		Type:   TypeGeneral,
		Loaded: time.Now(),
	}, nil
}

// loadBuiltIn loads a built-in wordlist
func (m *Manager) loadBuiltIn(name string) (*Wordlist, error) {
	words, ok := m.builtInLists[name]
	if !ok {
		// Check for category match
		for category, catWords := range m.builtInLists {
			if strings.EqualFold(category, name) {
				words = catWords
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("built-in wordlist '%s' not found", name)
	}

	wl := &Wordlist{
		Name:   "builtin:" + name,
		Words:  words,
		Size:   len(words),
		Type:   TypeGeneral,
		Loaded: time.Now(),
	}

	m.mu.Lock()
	m.cache["builtin:"+name] = wl
	m.mu.Unlock()

	return wl, nil
}

// loadFromFile loads a wordlist from a file
func (m *Manager) loadFromFile(path string) (*Wordlist, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Check for gzip
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	words, err := m.readLines(reader)
	if err != nil {
		return nil, err
	}

	wl := &Wordlist{
		Name:   filepath.Base(path),
		Path:   path,
		Words:  words,
		Size:   len(words),
		Type:   detectWordlistType(path, words),
		Loaded: time.Now(),
	}

	m.mu.Lock()
	m.cache[path] = wl
	m.mu.Unlock()

	return wl, nil
}

// loadFromURL downloads and loads a wordlist from a URL
func (m *Manager) loadFromURL(url string) (*Wordlist, error) {
	// Check if cached locally
	cachePath := filepath.Join(m.cacheDir, sanitizeFilename(url))
	if info, err := os.Stat(cachePath); err == nil {
		// Use cached version if less than 24 hours old
		if time.Since(info.ModTime()) < 24*time.Hour {
			return m.loadFromFile(cachePath)
		}
	}

	// Download
	resp, err := m.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	// Save to cache with size limit (100 MB)
	file, err := os.Create(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache file: %w", err)
	}
	defer file.Close()

	const maxWordlistSize = 100 << 20 // 100 MB
	if _, err := io.Copy(file, io.LimitReader(resp.Body, maxWordlistSize)); err != nil {
		file.Close()
		os.Remove(cachePath)
		return nil, fmt.Errorf("failed to write cache file: %w", err)
	}
	file.Close() // explicit close before re-read

	return m.loadFromFile(cachePath)
}

// readLines reads lines from a reader
func (m *Manager) readLines(r io.Reader) ([]string, error) {
	var words []string
	scanner := bufio.NewScanner(r)

	// Increase buffer size for long lines
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading wordlist: %w", err)
	}

	return words, nil
}

// Generate creates a custom wordlist based on parameters
func (m *Manager) Generate(opts GenerateOptions) (*Wordlist, error) {
	var words []string

	switch opts.Type {
	case GenerateNumeric:
		words = generateNumeric(opts.Min, opts.Max, opts.Padding)
	case GenerateAlpha:
		words = generateAlpha(opts.MinLength, opts.MaxLength, opts.Charset)
	case GeneratePattern:
		words = generateFromPattern(opts.Pattern, opts.Count)
	case GenerateMutations:
		words = generateMutations(opts.BaseWord, opts.MutationRules)
	case GenerateCombinations:
		words = generateCombinations(opts.Parts, opts.Separator)
	case GenerateDates:
		words = generateDates(opts.StartDate, opts.EndDate, opts.DateFormats)
	default:
		return nil, fmt.Errorf("unknown generation type: %s", opts.Type)
	}

	return &Wordlist{
		Name:   fmt.Sprintf("generated-%s", opts.Type),
		Words:  words,
		Size:   len(words),
		Type:   TypeCustom,
		Loaded: time.Now(),
	}, nil
}

// GenerateType defines wordlist generation type
type GenerateType string

const (
	GenerateNumeric      GenerateType = "numeric"
	GenerateAlpha        GenerateType = "alpha"
	GeneratePattern      GenerateType = "pattern"
	GenerateMutations    GenerateType = "mutations"
	GenerateCombinations GenerateType = "combinations"
	GenerateDates        GenerateType = "dates"
)

// GenerateOptions for wordlist generation
type GenerateOptions struct {
	Type          GenerateType
	Min           int
	Max           int
	Padding       int
	MinLength     int
	MaxLength     int
	Charset       string
	Pattern       string
	Count         int
	BaseWord      string
	MutationRules []MutationRule
	Parts         [][]string
	Separator     string
	StartDate     time.Time
	EndDate       time.Time
	DateFormats   []string
}

// MutationRule defines a mutation rule
type MutationRule struct {
	From string
	To   string
}

// generateNumeric creates numeric wordlist
func generateNumeric(min, max, padding int) []string {
	// Bounds validation to prevent OOM
	if max < min {
		return nil
	}
	if max-min > 10000000 {
		max = min + 10000000 // Cap at 10 million entries
	}

	words := make([]string, 0, max-min+1)
	format := fmt.Sprintf("%%0%dd", padding)

	for i := min; i <= max; i++ {
		if padding > 0 {
			words = append(words, fmt.Sprintf(format, i))
		} else {
			words = append(words, fmt.Sprintf("%d", i))
		}
	}

	return words
}

// generateAlpha creates alphabetic wordlist
func generateAlpha(minLen, maxLen int, charset string) []string {
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyz"
	}

	var words []string
	chars := []rune(charset)

	var generate func(prefix string, length int)
	generate = func(prefix string, length int) {
		if len(words) >= 1000000 {
			return
		}
		if length == 0 {
			if len(prefix) >= minLen {
				words = append(words, prefix)
			}
			return
		}
		for _, c := range chars {
			generate(prefix+string(c), length-1)
		}
	}

	for l := minLen; l <= maxLen; l++ {
		generate("", l)
		// Limit to prevent memory explosion
		if len(words) >= 1000000 {
			break
		}
	}

	return words
}

// generateFromPattern generates words from a pattern
func generateFromPattern(pattern string, count int) []string {
	// Pattern syntax:
	// ?l = lowercase letter
	// ?u = uppercase letter
	// ?d = digit
	// ?s = special char
	// ?a = any printable
	// literal chars are kept as-is

	words := make([]string, 0, count)

	for i := 0; i < count; i++ {
		word := expandPattern(pattern)
		words = append(words, word)
	}

	return deduplicate(words)
}

func expandPattern(pattern string) string {
	var result strings.Builder

	chars := []rune(pattern)
	for i := 0; i < len(chars); i++ {
		if chars[i] == '?' && i+1 < len(chars) {
			switch chars[i+1] {
			case 'l':
				result.WriteRune(rune('a' + randomInt(26)))
			case 'u':
				result.WriteRune(rune('A' + randomInt(26)))
			case 'd':
				result.WriteRune(rune('0' + randomInt(10)))
			case 's':
				specials := "!@#$%^&*()_+-=[]{}|;:,.<>?"
				result.WriteRune([]rune(specials)[randomInt(len(specials))])
			case 'a':
				result.WriteRune(rune(32 + randomInt(95)))
			case '?':
				result.WriteRune('?')
			default:
				result.WriteRune(chars[i])
				continue
			}
			i++
		} else {
			result.WriteRune(chars[i])
		}
	}

	return result.String()
}

// generateMutations creates mutations of a base word
func generateMutations(base string, rules []MutationRule) []string {
	if len(rules) == 0 {
		rules = defaultMutationRules()
	}

	words := []string{base}

	// Apply each rule
	for _, rule := range rules {
		newWords := make([]string, 0)
		for _, word := range words {
			newWords = append(newWords, word)
			if strings.Contains(strings.ToLower(word), strings.ToLower(rule.From)) {
				mutated := strings.ReplaceAll(word, rule.From, rule.To)
				mutated2 := strings.ReplaceAll(strings.ToLower(word), strings.ToLower(rule.From), rule.To)
				mutated3 := strings.ReplaceAll(strings.ToUpper(word), strings.ToUpper(rule.From), rule.To)
				newWords = append(newWords, mutated, mutated2, mutated3)
			}
		}
		words = deduplicate(newWords)
	}

	// Add common variations
	var variations []string
	for _, word := range words {
		variations = append(variations, word)
		variations = append(variations, strings.ToLower(word))
		variations = append(variations, strings.ToUpper(word))
		variations = append(variations, cases.Title(language.English).String(strings.ToLower(word)))

		// Add numbers
		for i := 0; i <= 9; i++ {
			variations = append(variations, fmt.Sprintf("%s%d", word, i))
		}
		for i := 0; i <= 99; i++ {
			variations = append(variations, fmt.Sprintf("%s%02d", word, i))
		}

		// Add years
		for year := 2020; year <= 2025; year++ {
			variations = append(variations, fmt.Sprintf("%s%d", word, year))
		}

		// Add common suffixes
		suffixes := []string{"!", "123", "1234", "@", "#", "$", "_"}
		for _, suffix := range suffixes {
			variations = append(variations, word+suffix)
		}
	}

	return deduplicate(variations)
}

func defaultMutationRules() []MutationRule {
	return []MutationRule{
		{From: "a", To: "@"},
		{From: "a", To: "4"},
		{From: "e", To: "3"},
		{From: "i", To: "1"},
		{From: "i", To: "!"},
		{From: "o", To: "0"},
		{From: "s", To: "$"},
		{From: "s", To: "5"},
		{From: "t", To: "7"},
		{From: "l", To: "1"},
		{From: "g", To: "9"},
	}
}

// generateCombinations creates combinations from multiple parts
func generateCombinations(parts [][]string, separator string) []string {
	if len(parts) == 0 {
		return nil
	}

	// Calculate total combinations with overflow protection
	total := 1
	for _, part := range parts {
		if len(part) == 0 {
			return nil
		}
		// Check for overflow before multiplying
		if total > 1000000/len(part) {
			total = 1000000
			break
		}
		total *= len(part)
	}

	// Limit to prevent memory explosion
	if total > 1000000 {
		total = 1000000
	}

	words := make([]string, 0, total)

	var combine func(prefix string, partIdx int)
	combine = func(prefix string, partIdx int) {
		if len(words) >= total {
			return
		}
		if partIdx >= len(parts) {
			words = append(words, prefix)
			return
		}
		for _, word := range parts[partIdx] {
			newPrefix := prefix
			if newPrefix != "" {
				newPrefix += separator
			}
			newPrefix += word
			combine(newPrefix, partIdx+1)
		}
	}

	combine("", 0)
	return words
}

// generateDates creates date-based wordlist
func generateDates(start, end time.Time, formats []string) []string {
	if formats == nil {
		formats = []string{
			"20060102",
			"2006-01-02",
			"01/02/2006",
			"02-01-2006",
			"Jan2006",
			"January2006",
		}
	}

	var words []string
	current := start

	for current.Before(end) || current.Equal(end) {
		for _, format := range formats {
			words = append(words, current.Format(format))
		}
		current = current.AddDate(0, 0, 1)

		// Limit to prevent explosion
		if len(words) > 100000 {
			break
		}
	}

	return words
}

// Transform applies transformations to a wordlist
func (m *Manager) Transform(wl *Wordlist, transforms []Transform) (*Wordlist, error) {
	words := make([]string, 0, len(wl.Words)*3)

	for _, word := range wl.Words {
		words = append(words, word)

		for _, t := range transforms {
			transformed := applyTransform(word, t)
			words = append(words, transformed...)
		}
	}

	deduped := deduplicate(words)
	return &Wordlist{
		Name:   wl.Name + "-transformed",
		Words:  deduped,
		Size:   len(deduped),
		Type:   wl.Type,
		Loaded: time.Now(),
	}, nil
}

// Transform defines a wordlist transformation
type Transform struct {
	Type    TransformType
	Prefix  string
	Suffix  string
	Pattern string
	Rules   []MutationRule
}

// TransformType defines transformation type
type TransformType string

const (
	TransformPrefix  TransformType = "prefix"
	TransformSuffix  TransformType = "suffix"
	TransformCase    TransformType = "case"
	TransformLeet    TransformType = "leet"
	TransformReverse TransformType = "reverse"
	TransformPrepend TransformType = "prepend"
	TransformAppend  TransformType = "append"
	TransformReplace TransformType = "replace"
)

func applyTransform(word string, t Transform) []string {
	var results []string

	switch t.Type {
	case TransformPrefix:
		results = append(results, t.Prefix+word)
	case TransformSuffix:
		results = append(results, word+t.Suffix)
	case TransformCase:
		results = append(results, strings.ToLower(word))
		results = append(results, strings.ToUpper(word))
		results = append(results, cases.Title(language.English).String(strings.ToLower(word)))
		results = append(results, toggleCase(word))
	case TransformLeet:
		results = append(results, leetSpeak(word))
	case TransformReverse:
		results = append(results, reverse(word))
	case TransformReplace:
		for _, rule := range t.Rules {
			results = append(results, strings.ReplaceAll(word, rule.From, rule.To))
		}
	}

	return results
}

func toggleCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i%2 == 0 {
			result.WriteRune(unicode.ToLower(r))
		} else {
			result.WriteRune(unicode.ToUpper(r))
		}
	}
	return result.String()
}

func leetSpeak(s string) string {
	replacer := strings.NewReplacer(
		"a", "4", "A", "4",
		"e", "3", "E", "3",
		"i", "1", "I", "1",
		"o", "0", "O", "0",
		"s", "5", "S", "5",
		"t", "7", "T", "7",
	)
	return replacer.Replace(s)
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// Filter filters a wordlist based on criteria
func (m *Manager) Filter(wl *Wordlist, opts FilterOptions) (*Wordlist, error) {
	// Precompile regex once instead of per-word
	var regexFilter *regexp.Regexp
	if opts.Regex != "" {
		var err error
		regexFilter, err = regexp.Compile(opts.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
	}

	var filtered []string
	for _, word := range wl.Words {
		if matchesFilter(word, opts, regexFilter) {
			filtered = append(filtered, word)
		}
	}

	return &Wordlist{
		Name:   wl.Name + "-filtered",
		Words:  filtered,
		Size:   len(filtered),
		Type:   wl.Type,
		Loaded: time.Now(),
	}, nil
}

// FilterOptions for wordlist filtering
type FilterOptions struct {
	MinLength   int
	MaxLength   int
	Contains    string
	NotContains string
	StartsWith  string
	EndsWith    string
	Regex       string
	NoNumbers   bool
	NoSpecials  bool
	OnlyAlpha   bool
}

func matchesFilter(word string, opts FilterOptions, regexFilter *regexp.Regexp) bool {
	wordLen := len([]rune(word))
	if opts.MinLength > 0 && wordLen < opts.MinLength {
		return false
	}
	if opts.MaxLength > 0 && wordLen > opts.MaxLength {
		return false
	}
	if opts.Contains != "" && !strings.Contains(word, opts.Contains) {
		return false
	}
	if opts.NotContains != "" && strings.Contains(word, opts.NotContains) {
		return false
	}
	if opts.StartsWith != "" && !strings.HasPrefix(word, opts.StartsWith) {
		return false
	}
	if opts.EndsWith != "" && !strings.HasSuffix(word, opts.EndsWith) {
		return false
	}
	if regexFilter != nil {
		if !regexFilter.MatchString(word) {
			return false
		}
	}
	if opts.NoNumbers {
		for _, r := range word {
			if unicode.IsDigit(r) {
				return false
			}
		}
	}
	if opts.NoSpecials {
		for _, r := range word {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return false
			}
		}
	}
	if opts.OnlyAlpha {
		for _, r := range word {
			if !unicode.IsLetter(r) {
				return false
			}
		}
	}
	return true
}

// ListBuiltIn returns available built-in wordlists
func (m *Manager) ListBuiltIn() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.builtInLists))
	for name := range m.builtInLists {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetStats returns statistics for a wordlist
func (m *Manager) GetStats(wl *Wordlist) WordlistStats {
	stats := WordlistStats{
		TotalWords:  len(wl.Words),
		UniqueWords: len(deduplicate(wl.Words)),
	}

	lengthSum := 0
	for _, word := range wl.Words {
		l := len(word)
		lengthSum += l
		if l < stats.MinLength || stats.MinLength == 0 {
			stats.MinLength = l
		}
		if l > stats.MaxLength {
			stats.MaxLength = l
		}
	}

	if len(wl.Words) > 0 {
		stats.AvgLength = float64(lengthSum) / float64(len(wl.Words))
	}

	return stats
}

// WordlistStats contains wordlist statistics
type WordlistStats struct {
	TotalWords  int     `json:"total_words"`
	UniqueWords int     `json:"unique_words"`
	MinLength   int     `json:"min_length"`
	MaxLength   int     `json:"max_length"`
	AvgLength   float64 `json:"avg_length"`
}

// Helper functions

func deduplicate(words []string) []string {
	seen := make(map[string]struct{}, len(words))
	result := make([]string, 0, len(words))

	for _, word := range words {
		if _, ok := seen[word]; !ok {
			seen[word] = struct{}{}
			result = append(result, word)
		}
	}

	return result
}

func detectWordlistType(path string, words []string) WordlistType {
	name := strings.ToLower(filepath.Base(path))

	if strings.Contains(name, "dir") || strings.Contains(name, "folder") {
		return TypeDirectories
	}
	if strings.Contains(name, "file") {
		return TypeFiles
	}
	if strings.Contains(name, "ext") {
		return TypeExtensions
	}
	if strings.Contains(name, "param") {
		return TypeParameters
	}
	if strings.Contains(name, "subdomain") || strings.Contains(name, "dns") {
		return TypeSubdomains
	}
	if strings.Contains(name, "user") {
		return TypeUsernames
	}
	if strings.Contains(name, "pass") {
		return TypePasswords
	}
	if strings.Contains(name, "api") {
		return TypeAPI
	}

	return TypeGeneral
}

func sanitizeFilename(url string) string {
	// Create a safe filename from URL
	safe := regexcache.MustGet(`[^a-zA-Z0-9.-]`).ReplaceAllString(url, "_")
	if len(safe) > 100 {
		safe = safe[:100]
	}
	return safe
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	return rand.IntN(max)
}

// initBuiltInLists initializes built-in wordlists
func initBuiltInLists() map[string][]string {
	return map[string][]string{
		"common-dirs": {
			"admin", "administrator", "api", "app", "assets", "auth", "backup",
			"bin", "blog", "cache", "cgi-bin", "config", "console", "content",
			"css", "dashboard", "data", "db", "debug", "dev", "docs", "download",
			"downloads", "files", "fonts", "help", "home", "images", "img", "inc",
			"include", "includes", "js", "lib", "libs", "log", "login", "logs",
			"mail", "media", "modules", "old", "panel", "php", "phpmyadmin",
			"plugins", "portal", "private", "public", "rest", "scripts", "secure",
			"server-status", "setup", "sql", "src", "static", "stats", "status",
			"storage", "store", "styles", "system", "temp", "templates", "test",
			"tests", "themes", "tmp", "tools", "upload", "uploads", "user", "users",
			"v1", "v2", "vendor", "web", "webmail", "wp-admin", "wp-content",
			"wp-includes", ".git", ".svn", ".env", ".htaccess", ".htpasswd",
		},
		"common-files": {
			".git/config", ".git/HEAD", ".gitignore", ".env", ".env.local",
			".env.production", ".env.development", ".htaccess", ".htpasswd",
			"robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
			".well-known/security.txt", "humans.txt", "package.json",
			"package-lock.json", "composer.json", "composer.lock", "Gemfile",
			"Gemfile.lock", "Makefile", "Dockerfile", "docker-compose.yml",
			"webpack.config.js", "gulpfile.js", "Gruntfile.js", ".babelrc",
			"tsconfig.json", "phpinfo.php", "info.php", "test.php", "config.php",
			"configuration.php", "settings.php", "wp-config.php", "local.xml",
			"database.yml", "config.yml", "config.json", "appsettings.json",
			"web.config", "server.xml", "readme.md", "README.md", "CHANGELOG.md",
			"LICENSE", "backup.sql", "dump.sql", "database.sql", ".DS_Store",
		},
		"common-params": {
			"id", "page", "search", "q", "query", "name", "user", "username",
			"email", "password", "pass", "pwd", "token", "key", "api_key",
			"apikey", "access_token", "auth", "action", "type", "category",
			"cat", "lang", "language", "locale", "redirect", "return", "url",
			"next", "goto", "dest", "destination", "file", "filename", "path",
			"dir", "folder", "include", "template", "tpl", "view", "sort",
			"order", "orderby", "filter", "limit", "offset", "start", "end",
			"from", "to", "date", "year", "month", "day", "format", "callback",
			"jsonp", "debug", "test", "mode", "admin", "config", "setting",
		},
		"extensions": {
			".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action", ".html",
			".htm", ".xhtml", ".shtml", ".xml", ".json", ".txt", ".md", ".pdf",
			".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".tar",
			".gz", ".rar", ".7z", ".bak", ".old", ".orig", ".save", ".swp",
			".tmp", ".log", ".sql", ".db", ".sqlite", ".mdb", ".cfg", ".conf",
			".config", ".ini", ".yml", ".yaml", ".env", ".git", ".svn",
		},
		"backup-files": {
			"backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
			"site.zip", "www.zip", "web.zip", "html.zip", "public_html.zip",
			"database.sql", "dump.sql", "db.sql", "mysql.sql", "data.sql",
			"old.zip", "archive.zip", "files.zip", "source.zip", "src.zip",
			".bak", ".backup", ".old", ".orig", ".save", "~", ".copy",
		},
		"api-endpoints": {
			"/api", "/api/v1", "/api/v2", "/api/v3", "/rest", "/rest/v1",
			"/graphql", "/graphiql", "/swagger", "/swagger-ui", "/api-docs",
			"/openapi", "/openapi.json", "/swagger.json", "/api/swagger",
			"/docs", "/documentation", "/health", "/healthz", "/ready",
			"/live", "/liveness", "/readiness", "/status", "/ping", "/version",
			"/metrics", "/actuator", "/actuator/health", "/actuator/info",
			"/debug", "/debug/pprof", "/.well-known", "/oauth", "/oauth2",
			"/auth", "/authenticate", "/login", "/logout", "/register",
			"/signup", "/forgot-password", "/reset-password", "/verify",
		},
		"fuzzing-special": {
			"", " ", "  ", "\t", "\n", "\r\n", "%00", "%0a", "%0d",
			"null", "nil", "undefined", "NaN", "Infinity", "-Infinity",
			"true", "false", "True", "False", "TRUE", "FALSE",
			"0", "-1", "1", "2147483647", "-2147483648", "9999999999",
			"0.0", "0.1", "-0.1", "1e308", "-1e308",
			"[]", "{}", "''", "\"\"", "()", "//", "/**/",
			"../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f",
			"<script>", "</script>", "<img>", "javascript:",
			"' OR 1=1--", "\" OR 1=1--", "1; DROP TABLE",
			"{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
		},
	}
}
