// cmd_probe_types.go - Data types for probe command
package main

import (
	"time"

	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/waf"
)

// ProbeResults holds the results of probing a single target.
type ProbeResults struct {
	Target          string                  `json:"target"`
	Scheme          string                  `json:"scheme,omitempty"`
	Method          string                  `json:"method,omitempty"`
	DNS             *probes.DNSResult       `json:"dns,omitempty"`
	TLS             *probes.TLSInfo         `json:"tls,omitempty"`
	JARM            *probes.JARMResult      `json:"jarm,omitempty"`
	Headers         *probes.SecurityHeaders `json:"headers,omitempty"`
	Tech            *probes.TechResult      `json:"tech,omitempty"`
	HTTP            *probes.HTTPProbeResult `json:"http,omitempty"`
	Favicon         *probes.FaviconResult   `json:"favicon,omitempty"`
	WAF             *waf.DetectionResult    `json:"waf,omitempty"`
	ResponseTime    string                  `json:"response_time,omitempty"`
	StatusCode      int                     `json:"status_code,omitempty"`
	ContentLength   int64                   `json:"content_length,omitempty"`
	ContentType     string                  `json:"content_type,omitempty"`
	Server          string                  `json:"server,omitempty"`
	Location        string                  `json:"location,omitempty"`
	WordCount       int                     `json:"word_count,omitempty"`
	LineCount       int                     `json:"line_count,omitempty"`
	FinalURL        string                  `json:"final_url,omitempty"`
	BodyHash        string                  `json:"body_hash,omitempty"`
	HeaderHash      string                  `json:"header_hash,omitempty"`
	BodyPreview     string                  `json:"body_preview,omitempty"`
	WebSocket       bool                    `json:"websocket,omitempty"`
	HTTP2           bool                    `json:"http2,omitempty"`
	Pipeline        bool                    `json:"pipeline,omitempty"`
	WordPress       bool                    `json:"wordpress,omitempty"`
	WPPlugins       []string                `json:"wp_plugins,omitempty"`
	WPThemes        []string                `json:"wp_themes,omitempty"`
	CPEs            []string                `json:"cpes,omitempty"`
	RedirectChain   []string                `json:"redirect_chain,omitempty"`
	Extracted       []string                `json:"extracted,omitempty"`
	ResponseHeaders map[string][]string     `json:"response_headers,omitempty"`
	ResponseBody    string                  `json:"response_body,omitempty"`
	ScreenshotFile  string                  `json:"screenshot_file,omitempty"`
	ScreenshotBytes string                  `json:"screenshot_bytes,omitempty"` // base64 encoded PNG
	Alive           bool                    `json:"alive"`
	ProbeAt         time.Time               `json:"probed_at"`
	rawBody         string                  // internal, not exported to JSON
}

// ScreenshotCluster holds vision clustering data for a probed target.
type ScreenshotCluster struct {
	Target  string `json:"target"`
	File    string `json:"file"`
	Cluster int    `json:"cluster"`
	Simhash uint64 `json:"simhash"`
}
