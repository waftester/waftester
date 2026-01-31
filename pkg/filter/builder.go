package filter

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Builder provides a fluent API for constructing filter configurations
// Inspired by ffuf's command-line filter options
type Builder struct {
	config *Config
	errors []error
}

// NewBuilder creates a new filter configuration builder
func NewBuilder() *Builder {
	return &Builder{
		config: &Config{
			MatchHeaders:  make(map[string]string),
			FilterHeaders: make(map[string]string),
		},
	}
}

// MatchStatus adds status codes to match (show only these)
// Accepts: "200", "200,301,302", "2xx", "200-299"
func (b *Builder) MatchStatus(s string) *Builder {
	codes, err := ParseStatusCodes(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("match-status: %w", err))
		return b
	}
	b.config.MatchStatus = append(b.config.MatchStatus, codes...)
	return b
}

// FilterStatus adds status codes to filter (exclude these)
func (b *Builder) FilterStatus(s string) *Builder {
	codes, err := ParseStatusCodes(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("filter-status: %w", err))
		return b
	}
	b.config.FilterStatus = append(b.config.FilterStatus, codes...)
	return b
}

// MatchSize adds content length ranges to match
// Accepts: "100", "100-200", "100,200,300-400"
func (b *Builder) MatchSize(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("match-size: %w", err))
		return b
	}
	b.config.MatchSize = append(b.config.MatchSize, ranges...)
	return b
}

// FilterSize adds content length ranges to filter
func (b *Builder) FilterSize(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("filter-size: %w", err))
		return b
	}
	b.config.FilterSize = append(b.config.FilterSize, ranges...)
	return b
}

// MatchWords adds word count ranges to match
func (b *Builder) MatchWords(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("match-words: %w", err))
		return b
	}
	b.config.MatchWords = append(b.config.MatchWords, ranges...)
	return b
}

// FilterWords adds word count ranges to filter
func (b *Builder) FilterWords(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("filter-words: %w", err))
		return b
	}
	b.config.FilterWords = append(b.config.FilterWords, ranges...)
	return b
}

// MatchLines adds line count ranges to match
func (b *Builder) MatchLines(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("match-lines: %w", err))
		return b
	}
	b.config.MatchLines = append(b.config.MatchLines, ranges...)
	return b
}

// FilterLines adds line count ranges to filter
func (b *Builder) FilterLines(s string) *Builder {
	ranges, err := ParseRanges(s)
	if err != nil {
		b.errors = append(b.errors, fmt.Errorf("filter-lines: %w", err))
		return b
	}
	b.config.FilterLines = append(b.config.FilterLines, ranges...)
	return b
}

// MatchRegex adds regex patterns to match against response body
func (b *Builder) MatchRegex(patterns ...string) *Builder {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			b.errors = append(b.errors, fmt.Errorf("match-regex %q: %w", p, err))
			continue
		}
		b.config.MatchRegex = append(b.config.MatchRegex, re)
	}
	return b
}

// FilterRegex adds regex patterns to filter
func (b *Builder) FilterRegex(patterns ...string) *Builder {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			b.errors = append(b.errors, fmt.Errorf("filter-regex %q: %w", p, err))
			continue
		}
		b.config.FilterRegex = append(b.config.FilterRegex, re)
	}
	return b
}

// MatchString adds strings to match in response body
func (b *Builder) MatchString(strs ...string) *Builder {
	b.config.MatchString = append(b.config.MatchString, strs...)
	return b
}

// FilterString adds strings to filter from response body
func (b *Builder) FilterString(strs ...string) *Builder {
	b.config.FilterString = append(b.config.FilterString, strs...)
	return b
}

// MatchTime sets response time threshold to match (slower responses)
func (b *Builder) MatchTime(d time.Duration) *Builder {
	b.config.MatchTime = d
	return b
}

// FilterTime sets response time threshold to filter (exclude slower responses)
func (b *Builder) FilterTime(d time.Duration) *Builder {
	b.config.FilterTime = d
	return b
}

// MatchCDN adds CDN provider names to match
func (b *Builder) MatchCDN(providers ...string) *Builder {
	b.config.MatchCDN = append(b.config.MatchCDN, providers...)
	return b
}

// FilterCDN adds CDN provider names to filter
func (b *Builder) FilterCDN(providers ...string) *Builder {
	b.config.FilterCDN = append(b.config.FilterCDN, providers...)
	return b
}

// MatchFavicon adds favicon hashes to match
func (b *Builder) MatchFavicon(hashes ...string) *Builder {
	b.config.MatchFavicon = append(b.config.MatchFavicon, hashes...)
	return b
}

// MatchHeader adds a header key-value pair to match
func (b *Builder) MatchHeader(key, value string) *Builder {
	b.config.MatchHeaders[key] = value
	return b
}

// FilterHeader adds a header key-value pair to filter
func (b *Builder) FilterHeader(key, value string) *Builder {
	b.config.FilterHeaders[key] = value
	return b
}

// FilterDuplicates enables simhash-based duplicate filtering
func (b *Builder) FilterDuplicates() *Builder {
	b.config.FilterDuplicates = true
	return b
}

// FilterErrorPages enables error page detection and filtering
func (b *Builder) FilterErrorPages() *Builder {
	b.config.FilterErrorPage = true
	return b
}

// MatchModeAnd sets match mode to AND (all criteria must match)
func (b *Builder) MatchModeAnd() *Builder {
	b.config.MatchMode = ModeAnd
	return b
}

// MatchModeOr sets match mode to OR (any criterion can match)
func (b *Builder) MatchModeOr() *Builder {
	b.config.MatchMode = ModeOr
	return b
}

// FilterModeAnd sets filter mode to AND (all criteria must match to filter)
func (b *Builder) FilterModeAnd() *Builder {
	b.config.FilterMode = ModeAnd
	return b
}

// FilterModeOr sets filter mode to OR (any criterion can filter)
func (b *Builder) FilterModeOr() *Builder {
	b.config.FilterMode = ModeOr
	return b
}

// Build returns the filter configuration and any errors
func (b *Builder) Build() (*Config, error) {
	if len(b.errors) > 0 {
		var errStrs []string
		for _, e := range b.errors {
			errStrs = append(errStrs, e.Error())
		}
		return b.config, fmt.Errorf("filter configuration errors: %s", strings.Join(errStrs, "; "))
	}
	return b.config, nil
}

// BuildFilter returns a ready-to-use filter
func (b *Builder) BuildFilter() (*Filter, error) {
	cfg, err := b.Build()
	return NewFilter(cfg), err
}

// FromCalibration creates filter configuration from auto-calibration results
func FromCalibration(baselineStatus, baselineSize, baselineWords, baselineLines int) *Builder {
	b := NewBuilder()

	// Filter out the baseline responses (common 404/error pages)
	if baselineStatus > 0 {
		b.FilterStatus(fmt.Sprintf("%d", baselineStatus))
	}
	if baselineSize > 0 {
		// Filter exact size and nearby (±10 bytes for minor variations)
		min := baselineSize - 10
		if min < 0 {
			min = 0
		}
		max := baselineSize + 10
		b.FilterSize(fmt.Sprintf("%d-%d", min, max))
	}
	if baselineWords > 0 {
		// Filter similar word counts
		min := baselineWords - 2
		if min < 0 {
			min = 0
		}
		max := baselineWords + 2
		b.FilterWords(fmt.Sprintf("%d-%d", min, max))
	}
	if baselineLines > 0 {
		// Filter similar line counts
		min := baselineLines - 2
		if min < 0 {
			min = 0
		}
		max := baselineLines + 2
		b.FilterLines(fmt.Sprintf("%d-%d", min, max))
	}

	return b
}
