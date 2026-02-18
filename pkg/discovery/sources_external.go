// Package discovery - External URL sources (Wayback, CommonCrawl, OTX, VirusTotal, forms)
package discovery

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/regexcache"
)

// ==================== WAYBACK MACHINE ====================

// WaybackURL represents a URL from the Wayback Machine
type WaybackURL struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
}

// FetchWaybackURLs retrieves historical URLs from the Wayback Machine
func (es *ExternalSources) FetchWaybackURLs(ctx context.Context, domain string, includeSubs bool) ([]WaybackURL, error) {
	subsWildcard := ""
	if includeSubs {
		subsWildcard = "*."
	}

	waybackURL := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey&limit=5000",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", waybackURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback machine request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback machine returned status %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return nil, err
	}

	var wrapper [][]string
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	result := make([]WaybackURL, 0, len(wrapper))
	skip := true
	for _, urls := range wrapper {
		// First row is headers
		if skip {
			skip = false
			continue
		}
		if len(urls) >= 3 {
			result = append(result, WaybackURL{
				Timestamp: urls[1],
				URL:       urls[2],
			})
		}
	}

	return result, nil
}

// ==================== COMMONCRAWL ====================

// FetchCommonCrawlURLs retrieves URLs from CommonCrawl
func (es *ExternalSources) FetchCommonCrawlURLs(ctx context.Context, domain string, includeSubs bool) ([]string, error) {
	subsWildcard := ""
	if includeSubs {
		subsWildcard = "*."
	}

	// Using a recent CommonCrawl index
	ccURL := fmt.Sprintf(
		"http://index.commoncrawl.org/CC-MAIN-2024-10-index?url=%s%s/*&output=json&limit=1000",
		subsWildcard, domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", ccURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("commoncrawl request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("commoncrawl returned status %d", resp.StatusCode)
	}

	var urls []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var entry struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			if entry.URL != "" && !seen[entry.URL] {
				seen[entry.URL] = true
				urls = append(urls, entry.URL)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return urls, fmt.Errorf("commoncrawl scan error: %w", err)
	}

	return urls, nil
}

// ==================== FORM EXTRACTION ====================

// FormField represents a form input field
type FormField struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // text, password, email, file, hidden, etc.
	ID          string `json:"id,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Value       string `json:"value,omitempty"`
}

// Form represents an HTML form
type Form struct {
	Action   string      `json:"action"`
	Method   string      `json:"method"`
	ID       string      `json:"id,omitempty"`
	Fields   []FormField `json:"fields"`
	HasFile  bool        `json:"has_file_upload"`
	IsLogin  bool        `json:"is_login_form"`
	IsSearch bool        `json:"is_search_form"`
}

// ExtractForms extracts forms from HTML content
func ExtractForms(htmlContent, baseURL string) []Form {
	var forms []Form

	// Simple regex-based form extraction
	formRe := regexcache.MustGet(`(?is)<form[^>]*>(.*?)</form>`)
	actionRe := regexcache.MustGet(`(?i)action=["']([^"']+)["']`)
	methodRe := regexcache.MustGet(`(?i)method=["']([^"']+)["']`)
	formIDRe := regexcache.MustGet(`(?i)id=["']([^"']+)["']`)

	inputRe := regexcache.MustGet(`(?i)<input[^>]*>`)
	inputNameRe := regexcache.MustGet(`(?i)name=["']([^"']+)["']`)
	inputTypeRe := regexcache.MustGet(`(?i)type=["']([^"']+)["']`)
	inputIDRe := regexcache.MustGet(`(?i)id=["']([^"']+)["']`)
	inputValueRe := regexcache.MustGet(`(?i)value=["']([^"']+)["']`)
	inputPlaceholderRe := regexcache.MustGet(`(?i)placeholder=["']([^"']+)["']`)
	inputRequiredRe := regexcache.MustGet(`(?i)\brequired\b`)

	textareaRe := regexcache.MustGet(`(?i)<textarea[^>]*`)
	selectRe := regexcache.MustGet(`(?i)<select[^>]*`)

	formMatches := formRe.FindAllStringSubmatch(htmlContent, -1)
	for _, formMatch := range formMatches {
		if len(formMatch) < 2 {
			continue
		}

		formTag := formMatch[0]
		formBody := formMatch[1]

		form := Form{
			Method: "GET", // Default
			Fields: make([]FormField, 0),
		}

		// Extract action
		if match := actionRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.Action = resolveURL(match[1], baseURL)
		}

		// Extract method
		if match := methodRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.Method = strings.ToUpper(match[1])
		}

		// Extract form ID
		if match := formIDRe.FindStringSubmatch(formTag); len(match) > 1 {
			form.ID = match[1]
		}

		// Extract input fields
		inputs := inputRe.FindAllString(formBody, -1)
		for _, input := range inputs {
			field := FormField{Type: "text"} // Default

			if match := inputNameRe.FindStringSubmatch(input); len(match) > 1 {
				field.Name = match[1]
			}
			if match := inputTypeRe.FindStringSubmatch(input); len(match) > 1 {
				field.Type = strings.ToLower(match[1])
			}
			if match := inputIDRe.FindStringSubmatch(input); len(match) > 1 {
				field.ID = match[1]
			}
			if match := inputValueRe.FindStringSubmatch(input); len(match) > 1 {
				field.Value = match[1]
			}
			if match := inputPlaceholderRe.FindStringSubmatch(input); len(match) > 1 {
				field.Placeholder = match[1]
			}
			if inputRequiredRe.MatchString(input) {
				field.Required = true
			}

			if field.Name != "" {
				form.Fields = append(form.Fields, field)

				// Check for file upload
				if field.Type == "file" {
					form.HasFile = true
				}
			}
		}

		// Check for textareas
		textareas := textareaRe.FindAllString(formBody, -1)
		for _, textarea := range textareas {
			field := FormField{Type: "textarea"}
			if match := inputNameRe.FindStringSubmatch(textarea); len(match) > 1 {
				field.Name = match[1]
			}
			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		// Check for selects
		selects := selectRe.FindAllString(formBody, -1)
		for _, sel := range selects {
			field := FormField{Type: "select"}
			if match := inputNameRe.FindStringSubmatch(sel); len(match) > 1 {
				field.Name = match[1]
			}
			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		// Determine form type
		form.IsLogin = isLoginForm(form)
		form.IsSearch = isSearchForm(form)

		if len(form.Fields) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

func isLoginForm(form Form) bool {
	hasPassword := false
	hasUsername := false

	for _, field := range form.Fields {
		if field.Type == "password" {
			hasPassword = true
		}
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "user") || strings.Contains(name, "email") || strings.Contains(name, "login") {
			hasUsername = true
		}
	}

	return hasPassword && hasUsername
}

func isSearchForm(form Form) bool {
	for _, field := range form.Fields {
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "search") || strings.Contains(name, "query") || strings.Contains(name, "q") {
			return true
		}
	}
	return false
}

func resolveURL(link, baseURL string) string {
	if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
		return link
	}
	if strings.HasPrefix(link, "//") {
		return "https:" + link
	}
	if strings.HasPrefix(link, "/") {
		base, err := url.Parse(baseURL)
		if err != nil || base.Host == "" {
			return baseURL + link // fallback
		}
		return base.Scheme + "://" + base.Host + link
	}
	return baseURL + "/" + link
}

// ==================== OTX ALIENVAULT ====================
// From gospider - excellent source for historical URLs

// OTXURLResult represents a URL from AlienVault OTX
type OTXURLResult struct {
	URL      string `json:"url"`
	Domain   string `json:"domain"`
	Hostname string `json:"hostname"`
	HTTPCode int    `json:"httpcode"`
}

// FetchOTXURLs retrieves URLs from AlienVault OTX
func (es *ExternalSources) FetchOTXURLs(ctx context.Context, domain string) ([]OTXURLResult, error) {
	var allURLs []OTXURLResult
	page := 0
	maxPages := 10 // Limit to prevent infinite loops

	for page < maxPages {
		otxURL := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/hostname/%s/url_list?limit=50&page=%d",
			domain, page,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", otxURL, nil)
		if err != nil {
			return allURLs, err
		}
		req.Header.Set("User-Agent", es.userAgent)

		resp, err := es.httpClient.Do(req)
		if err != nil {
			return allURLs, fmt.Errorf("OTX request failed: %w", err)
		}

		body, err := iohelper.ReadBody(resp.Body, 5*1024*1024)
		iohelper.DrainAndClose(resp.Body)
		if err != nil {
			return allURLs, err
		}

		if resp.StatusCode != 200 {
			return allURLs, fmt.Errorf("OTX returned status %d", resp.StatusCode)
		}

		var wrapper struct {
			HasNext bool `json:"has_next"`
			URLList []struct {
				URL      string `json:"url"`
				Domain   string `json:"domain"`
				Hostname string `json:"hostname"`
				HTTPCode int    `json:"httpcode"`
			} `json:"url_list"`
		}

		if err := json.Unmarshal(body, &wrapper); err != nil {
			return allURLs, err
		}

		for _, u := range wrapper.URLList {
			allURLs = append(allURLs, OTXURLResult{
				URL:      u.URL,
				Domain:   u.Domain,
				Hostname: u.Hostname,
				HTTPCode: u.HTTPCode,
			})
		}

		if !wrapper.HasNext {
			break
		}
		page++
	}

	return allURLs, nil
}

// ==================== VIRUSTOTAL ====================
// From gospider - URLs detected by VirusTotal (requires API key)

// FetchVirusTotalURLs retrieves URLs from VirusTotal
// Requires VT_API_KEY environment variable
func (es *ExternalSources) FetchVirusTotalURLs(ctx context.Context, domain string, apiKey string) ([]string, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key not provided")
	}

	vtURL := fmt.Sprintf(
		"https://www.virustotal.com/vtapi/v2/domain/report?domain=%s",
		domain,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", vtURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", es.userAgent)
	req.Header.Set("x-apikey", apiKey)

	resp, err := es.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("VirusTotal request failed: %w", err)
	}
	defer iohelper.DrainAndClose(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VirusTotal returned status %d", resp.StatusCode)
	}

	body, err := iohelper.ReadBody(resp.Body, iohelper.LargeMaxBodySize)
	if err != nil {
		return nil, err
	}

	var wrapper struct {
		DetectedURLs []struct {
			URL string `json:"url"`
		} `json:"detected_urls"`
	}

	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	var urls []string
	for _, u := range wrapper.DetectedURLs {
		urls = append(urls, u.URL)
	}

	return urls, nil
}
