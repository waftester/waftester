package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// ClickableElement represents an interactive DOM element found on a page.
type ClickableElement struct {
	Selector string `json:"selector"`
	Tag      string `json:"tag"`
	Text     string `json:"text"`
	Type     string `json:"type"` // link, button, onclick, role-button, framework-binding, cursor-pointer
	Href     string `json:"href,omitempty"`
	OnClick  string `json:"onclick,omitempty"`
}

// EventCrawlResult holds what was discovered by interacting with one element.
type EventCrawlResult struct {
	Element        ClickableElement `json:"element"`
	DiscoveredURLs []string         `json:"discovered_urls"`
	XHRRequests    []string         `json:"xhr_requests"`
	NavigatedTo    string           `json:"navigated_to,omitempty"`
	DOMChanged     bool             `json:"dom_changed"`
}

// EventCrawlConfig configures DOM event crawling behavior.
type EventCrawlConfig struct {
	MaxClicks      int           `json:"max_clicks"`
	ClickTimeout   time.Duration `json:"click_timeout"`
	WaitAfterClick time.Duration `json:"wait_after_click"`
	SkipExternal   bool          `json:"skip_external"`
}

// DefaultEventCrawlConfig returns default event crawling settings.
func DefaultEventCrawlConfig() *EventCrawlConfig {
	return &EventCrawlConfig{
		MaxClicks:      50,
		ClickTimeout:   5 * time.Second,
		WaitAfterClick: 2 * time.Second,
		SkipExternal:   true,
	}
}

// discoverClickablesJS is injected into the page to find all interactive elements.
// Categories: links, buttons, onclick handlers, ARIA roles, framework bindings, cursor-pointer.
const discoverClickablesJS = `
(function() {
    const elements = [];
    const seen = new Set();

    function addElement(el, type) {
        const selector = cssSelector(el);
        if (seen.has(selector)) return;
        seen.add(selector);

        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return;

        elements.push({
            selector: selector,
            tag: el.tagName.toLowerCase(),
            text: (el.textContent || '').trim().substring(0, 100),
            type: type,
            href: el.getAttribute('href') || '',
            onclick: el.getAttribute('onclick') || ''
        });
    }

    function cssSelector(el) {
        if (el.id) return '#' + el.id;
        let path = [];
        while (el && el.nodeType === 1) {
            let selector = el.tagName.toLowerCase();
            if (el.id) { path.unshift('#' + el.id); break; }
            let sibling = el;
            let nth = 1;
            while (sibling = sibling.previousElementSibling) {
                if (sibling.tagName === el.tagName) nth++;
            }
            if (nth > 1) selector += ':nth-of-type(' + nth + ')';
            path.unshift(selector);
            el = el.parentElement;
        }
        return path.join(' > ');
    }

    // 1. Links
    document.querySelectorAll('a[href]').forEach(function(el) {
        var href = el.getAttribute('href');
        if (href && href !== '#' && !href.startsWith('javascript:')) {
            addElement(el, 'link');
        }
    });

    // 2. Buttons
    document.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach(function(el) {
        addElement(el, 'button');
    });

    // 3. onclick handlers
    document.querySelectorAll('[onclick]').forEach(function(el) {
        addElement(el, 'onclick');
    });

    // 4. ARIA roles
    document.querySelectorAll('[role="button"], [role="link"], [role="tab"], [role="menuitem"]').forEach(function(el) {
        addElement(el, 'role-button');
    });

    // 5. Framework bindings (Angular, Vue, Stimulus, etc.)
    document.querySelectorAll('[ng-click], [v-on\\:click], [\\@click], [(click)], [data-action]').forEach(function(el) {
        addElement(el, 'framework-binding');
    });

    // 6. Cursor pointer catch-all for custom components
    document.querySelectorAll('div, span, li, td, label').forEach(function(el) {
        var style = window.getComputedStyle(el);
        if (style.cursor === 'pointer') {
            addElement(el, 'cursor-pointer');
        }
    });

    return JSON.stringify(elements);
})()
`

// getDOMHashJS returns a hash of the DOM structure for change detection.
const getDOMHashJS = `document.documentElement.outerHTML.length.toString()`

// DiscoverClickables executes JavaScript on the current page to find all interactive elements.
// Requires an active chromedp context with a page already loaded.
func DiscoverClickables(ctx context.Context) ([]ClickableElement, error) {
	var resultJSON string
	if err := chromedp.Run(ctx, chromedp.Evaluate(discoverClickablesJS, &resultJSON)); err != nil {
		return nil, fmt.Errorf("discover clickables: %w", err)
	}

	var elements []ClickableElement
	if err := json.Unmarshal([]byte(resultJSON), &elements); err != nil {
		return nil, fmt.Errorf("parse clickables: %w", err)
	}
	return elements, nil
}

// ClickAndCapture clicks an element and captures any new URLs or XHR requests triggered.
// It records the pre-click state, clicks, waits for activity, then restores the page.
func ClickAndCapture(ctx context.Context, element ClickableElement, originalURL string, waitDuration time.Duration) (*EventCrawlResult, error) {
	result := &EventCrawlResult{
		Element: element,
	}

	// Get DOM hash before click
	var domHashBefore string
	if err := chromedp.Run(ctx, chromedp.Evaluate(getDOMHashJS, &domHashBefore)); err != nil {
		return nil, fmt.Errorf("pre-click DOM hash: %w", err)
	}

	// Collect network requests during click.
	// Use a child context so the listener is removed when this function returns,
	// preventing listener accumulation across multiple ClickAndCapture calls.
	listenerCtx, listenerCancel := context.WithCancel(ctx)
	defer listenerCancel()

	var mu sync.Mutex
	var xhrURLs []string

	chromedp.ListenTarget(listenerCtx, func(ev interface{}) {
		if req, ok := ev.(*network.EventRequestWillBeSent); ok {
			mu.Lock()
			xhrURLs = append(xhrURLs, req.Request.URL)
			mu.Unlock()
		}
	})

	// Click the element
	if err := chromedp.Run(ctx, chromedp.Click(element.Selector, chromedp.NodeVisible)); err != nil {
		// Element may have disappeared; not fatal
		result.DiscoveredURLs = nil
		return result, nil
	}

	// Wait for network activity to settle
	select {
	case <-time.After(waitDuration):
	case <-ctx.Done():
		return result, ctx.Err()
	}

	// Check if page navigated
	var currentURL string
	if err := chromedp.Run(ctx, chromedp.Location(&currentURL)); err == nil {
		if currentURL != originalURL {
			result.NavigatedTo = currentURL
			result.DiscoveredURLs = append(result.DiscoveredURLs, currentURL)
		}
	}

	// Check DOM changes
	var domHashAfter string
	if err := chromedp.Run(ctx, chromedp.Evaluate(getDOMHashJS, &domHashAfter)); err == nil {
		result.DOMChanged = domHashBefore != domHashAfter
	}

	// Collect XHR requests
	mu.Lock()
	result.XHRRequests = xhrURLs
	mu.Unlock()

	// Deduplicate XHR into discovered URLs
	seen := make(map[string]bool)
	for _, u := range result.DiscoveredURLs {
		seen[u] = true
	}
	for _, u := range result.XHRRequests {
		if !seen[u] {
			seen[u] = true
			result.DiscoveredURLs = append(result.DiscoveredURLs, u)
		}
	}

	// If page navigated, go back
	if result.NavigatedTo != "" {
		_ = chromedp.Run(ctx, chromedp.Navigate(originalURL))
		select {
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}

	return result, nil
}

// EventCrawl navigates to a URL, discovers interactive elements, clicks each one,
// and returns all discovered URLs and API endpoints.
func EventCrawl(ctx context.Context, targetURL string, config *EventCrawlConfig) ([]EventCrawlResult, error) {
	if config == nil {
		config = DefaultEventCrawlConfig()
	}

	// Navigate to target
	if err := chromedp.Run(ctx, chromedp.Navigate(targetURL)); err != nil {
		return nil, fmt.Errorf("navigate to %s: %w", targetURL, err)
	}

	// Wait for page load
	if err := chromedp.Run(ctx, chromedp.WaitReady("body")); err != nil {
		return nil, fmt.Errorf("wait for body: %w", err)
	}

	// Discover clickable elements
	elements, err := DiscoverClickables(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover clickables: %w", err)
	}

	// Parse target for external URL filtering
	targetParsed, _ := url.Parse(targetURL)

	// Click each element up to maxClicks
	var results []EventCrawlResult
	clicked := 0
	for _, el := range elements {
		if clicked >= config.MaxClicks {
			break
		}

		// Skip external links if configured
		if config.SkipExternal && el.Href != "" {
			if parsed, err := url.Parse(el.Href); err == nil && parsed.Host != "" && parsed.Host != targetParsed.Host {
				continue
			}
		}

		result, err := ClickAndCapture(ctx, el, targetURL, config.WaitAfterClick)
		if err != nil {
			continue
		}
		results = append(results, *result)
		clicked++
	}

	return results, nil
}

// CollectDiscoveredURLs extracts all unique URLs from event crawl results,
// filtering to same-origin only when sameOrigin is true.
func CollectDiscoveredURLs(results []EventCrawlResult, baseURL string, sameOrigin bool) []string {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var urls []string
	for _, r := range results {
		for _, u := range r.DiscoveredURLs {
			if seen[u] {
				continue
			}
			if sameOrigin {
				parsed, err := url.Parse(u)
				if err != nil || parsed.Host != baseParsed.Host {
					continue
				}
			}
			// Skip data: and blob: URLs
			if strings.HasPrefix(u, "data:") || strings.HasPrefix(u, "blob:") {
				continue
			}
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}

// ParseClickablesJSON parses the raw JSON output from discoverClickablesJS.
// Exported for testing without a browser.
func ParseClickablesJSON(jsonData string) ([]ClickableElement, error) {
	var elements []ClickableElement
	if err := json.Unmarshal([]byte(jsonData), &elements); err != nil {
		return nil, fmt.Errorf("parse clickables JSON: %w", err)
	}
	return elements, nil
}
