package main

import (
	"time"

	"github.com/waftester/waftester/pkg/api"
	"github.com/waftester/waftester/pkg/apifuzz"
	"github.com/waftester/waftester/pkg/bizlogic"
	"github.com/waftester/waftester/pkg/cache"
	"github.com/waftester/waftester/pkg/clickjack"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/csrf"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/graphql"
	"github.com/waftester/waftester/pkg/hostheader"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/idor"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/jwt"
	"github.com/waftester/waftester/pkg/ldap"
	"github.com/waftester/waftester/pkg/lfi"
	"github.com/waftester/waftester/pkg/massassignment"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/oauth"
	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/prototype"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/rce"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/rfi"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssi"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/subtakeover"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/waf"
	"github.com/waftester/waftester/pkg/websocket"
	"github.com/waftester/waftester/pkg/xmlinjection"
	"github.com/waftester/waftester/pkg/xpath"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// ScanResult holds comprehensive vulnerability scan results.
type ScanResult struct {
	Target       string                      `json:"target"`
	StartTime    time.Time                   `json:"start_time"`
	Duration     time.Duration               `json:"duration"`
	TotalVulns   int                         `json:"total_vulnerabilities"`
	BySeverity   map[string]int              `json:"by_severity"`
	ByCategory   map[string]int              `json:"by_category"`
	ReportTitle  string                      `json:"report_title,omitempty"`
	ReportAuthor string                      `json:"report_author,omitempty"`
	SQLi         *sqli.ScanResult            `json:"sqli,omitempty"`
	XSS          *xss.ScanResult             `json:"xss,omitempty"`
	Traversal    *traversal.ScanResult       `json:"traversal,omitempty"`
	CMDI         *cmdi.Result                `json:"cmdi,omitempty"`
	NoSQLi       *nosqli.ScanResult          `json:"nosqli,omitempty"`
	HPP          *hpp.ScanResult             `json:"hpp,omitempty"`
	CRLF         *crlf.ScanResult            `json:"crlf,omitempty"`
	Prototype    *prototype.ScanResult       `json:"prototype,omitempty"`
	CORS         *cors.Result                `json:"cors,omitempty"`
	Redirect     *redirect.Result            `json:"redirect,omitempty"`
	HostHeader   *hostheader.ScanResult      `json:"hostheader,omitempty"`
	WebSocket    *websocket.ScanResult       `json:"websocket,omitempty"`
	Cache        *cache.ScanResult           `json:"cache,omitempty"`
	Upload       []upload.Vulnerability      `json:"upload,omitempty"`
	Deserialize  []deserialize.Vulnerability `json:"deserialize,omitempty"`
	OAuth        []oauth.Vulnerability       `json:"oauth,omitempty"`
	SSRF         *ssrf.Result                `json:"ssrf,omitempty"`
	SSTI         []*ssti.Vulnerability       `json:"ssti,omitempty"`
	XXE          []*xxe.Vulnerability        `json:"xxe,omitempty"`
	Smuggling    *smuggling.Result           `json:"smuggling,omitempty"`
	GraphQL      *graphql.ScanResult         `json:"graphql,omitempty"`
	JWT          []*jwt.Vulnerability        `json:"jwt,omitempty"`
	Subtakeover  []subtakeover.ScanResult    `json:"subtakeover,omitempty"`
	BizLogic     []bizlogic.Vulnerability    `json:"bizlogic,omitempty"`
	Race         *race.Result                `json:"race,omitempty"`
	APIFuzz      []apifuzz.Vulnerability     `json:"apifuzz,omitempty"`
	LDAP         []ldap.Result               `json:"ldap,omitempty"`
	SSI          []ssi.Result                `json:"ssi,omitempty"`
	XPath        []xpath.Result              `json:"xpath,omitempty"`
	XMLInjection []xmlinjection.Result       `json:"xmlinjection,omitempty"`
	RFI          []rfi.Result                `json:"rfi,omitempty"`
	LFI          []lfi.Result                `json:"lfi,omitempty"`
	RCE          []rce.Result                `json:"rce,omitempty"`
	CSRF         *csrf.Result                `json:"csrf,omitempty"`
	Clickjack    *clickjack.Result           `json:"clickjack,omitempty"`
	IDOR         []idor.Result               `json:"idor,omitempty"`
	MassAssign   []massassignment.Result     `json:"massassignment,omitempty"`
	WAFDetect    *waf.DetectionResult        `json:"waf_detect,omitempty"`
	WAFFprint    *waf.Fingerprint            `json:"waf_fingerprint,omitempty"`
	WAFEvasion   []waf.TransformedPayload    `json:"waf_evasion,omitempty"`
	TLSInfo      *probes.TLSInfo             `json:"tls_info,omitempty"`
	HTTPInfo     *probes.HTTPProbeResult     `json:"http_info,omitempty"`
	SecHeaders   *probes.SecurityHeaders     `json:"security_headers,omitempty"`
	JSAnalysis   *js.ExtractedData           `json:"js_analysis,omitempty"`
	APIRoutes    []api.ScanResult            `json:"api_routes,omitempty"`
	// Advanced reconnaissance scanners
	OSINT     *discovery.AllSourcesResult `json:"osint,omitempty"`
	VHosts    []probes.VHostProbeResult   `json:"vhosts,omitempty"`
	TechStack []string                    `json:"tech_stack,omitempty"`
	DNSInfo   *DNSReconResult             `json:"dns_info,omitempty"`
}

// DNSReconResult holds DNS reconnaissance findings.
type DNSReconResult struct {
	CNAMEs     []string `json:"cnames,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
	MXRecords  []string `json:"mx_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
	NSRecords  []string `json:"ns_records,omitempty"`
}
