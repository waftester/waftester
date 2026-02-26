package crawler

import "context"

// WebCrawler is the consumer-side interface for web crawling.
// Consumers that need crawling capabilities should depend on this interface
// rather than the concrete Crawler type, enabling testing with mock crawlers.
type WebCrawler interface {
	Crawl(ctx context.Context, startURL string) (<-chan *CrawlResult, error)
}

// Ensure the concrete Crawler satisfies the interface at compile time.
var _ WebCrawler = (*Crawler)(nil)
