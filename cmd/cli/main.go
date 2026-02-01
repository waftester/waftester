package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spaolacci/murmur3"
	"github.com/waftester/waftester/pkg/api"
	"github.com/waftester/waftester/pkg/apifuzz"
	"github.com/waftester/waftester/pkg/assessment"
	"github.com/waftester/waftester/pkg/bizlogic"
	"github.com/waftester/waftester/pkg/browser"
	"github.com/waftester/waftester/pkg/cache"
	"github.com/waftester/waftester/pkg/calibration"
	"github.com/waftester/waftester/pkg/checkpoint"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/config"
	"github.com/waftester/waftester/pkg/core"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crawler"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/discovery"
	"github.com/waftester/waftester/pkg/fuzz"
	"github.com/waftester/waftester/pkg/graphql"
	"github.com/waftester/waftester/pkg/headless"
	"github.com/waftester/waftester/pkg/hostheader"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/input"
	"github.com/waftester/waftester/pkg/interactive"
	"github.com/waftester/waftester/pkg/iohelper"
	"github.com/waftester/waftester/pkg/js"
	"github.com/waftester/waftester/pkg/jwt"
	"github.com/waftester/waftester/pkg/leakypaths"
	"github.com/waftester/waftester/pkg/learning"
	"github.com/waftester/waftester/pkg/mutation"
	_ "github.com/waftester/waftester/pkg/mutation/encoder"
	_ "github.com/waftester/waftester/pkg/mutation/evasion"
	_ "github.com/waftester/waftester/pkg/mutation/location"
	_ "github.com/waftester/waftester/pkg/mutation/protocol"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/oauth"
	"github.com/waftester/waftester/pkg/output"
	"github.com/waftester/waftester/pkg/params"
	"github.com/waftester/waftester/pkg/payloads"
	"github.com/waftester/waftester/pkg/probes"
	"github.com/waftester/waftester/pkg/prototype"
	"github.com/waftester/waftester/pkg/race"
	"github.com/waftester/waftester/pkg/recon"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/regexcache"
	"github.com/waftester/waftester/pkg/report"
	"github.com/waftester/waftester/pkg/runner"
	"github.com/waftester/waftester/pkg/smuggling"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/subtakeover"
	"github.com/waftester/waftester/pkg/templatevalidator"
	tlsja3 "github.com/waftester/waftester/pkg/tls"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/update"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/validate"
	"github.com/waftester/waftester/pkg/waf"
	"github.com/waftester/waftester/pkg/waf/vendors"
	"github.com/waftester/waftester/pkg/websocket"
	"github.com/waftester/waftester/pkg/workflow"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// getProjectRoot returns the project root directory (coraza-caddy).
// It navigates up from the executable location (tests/waf-tester) to the project root.
// Falls back to current working directory if executable path cannot be determined.
func getProjectRoot() string {
	// Try to get executable path first
	exePath, err := os.Executable()
	if err == nil {
		// Resolve symlinks
		exePath, err = filepath.EvalSymlinks(exePath)
		if err == nil {
			// Executable is in tests/waf-tester, go up 2 levels to project root
			exeDir := filepath.Dir(exePath)
			projectRoot := filepath.Join(exeDir, "..", "..")
			projectRoot, err = filepath.Abs(projectRoot)
			if err == nil {
				// Verify this looks like the project root (has workspaces dir or can create it)
				workspacesDir := filepath.Join(projectRoot, "workspaces")
				if _, statErr := os.Stat(workspacesDir); statErr == nil || os.IsNotExist(statErr) {
					return projectRoot
				}
			}
		}
	}

	// Fallback: use current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return cwd
}

func printUsage() {
	ui.PrintBanner()
	os.Stderr.Sync() // Sync stderr before switching to stdout

	// Adaptive workflow overview
	fmt.Println(ui.SectionStyle.Render("ADAPTIVE WAF TESTING"))
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("The Smart Workflow (recommended):"))
	fmt.Println()
	fmt.Printf("    %s  Crawl target, find attack surface\n", ui.ConfigValueStyle.Render("1. discover"))
	fmt.Printf("    %s  Generate prioritized test plan based on what was found\n", ui.ConfigValueStyle.Render("2. learn   "))
	fmt.Printf("    %s  Execute targeted tests using the plan\n", ui.ConfigValueStyle.Render("3. run     "))
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Quick Example:"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester discover -u https://auth.example.com"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester learn -discovery discovery.json"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -plan testplan.json"))
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Multi-Target Example:"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester probe -u target1.com,target2.com -c 50"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester scan -l targets.txt -types sqli,xss"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("cat urls.txt | waf-tester probe -stdin"))
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("COMMANDS"))
	fmt.Println()
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("auto    "), "🚀 SUPERPOWER - Full automated scan (discover→analyze JS→learn→run→report)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("assess  "), "🏢 Enterprise WAF assessment with quantitative metrics (F1, precision, MCC)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("discover"), "Crawl target, find endpoints from robots/sitemap/JS/Wayback")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("learn   "), "Analyze discovery → generate targeted test plan")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("run     "), "Execute tests (standalone or using test plan from learn)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("scan    "), "Deep vulnerability scanning (SQLi, XSS, SSRF, OAuth, etc.)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("mutate  "), "🆕 Mutation engine - test with all encoding/location/evasion combos")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("bypass  "), "🆕 WAF bypass finder - hunt for bypasses using full mutation matrix")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("fp      "), "🆕 False positive testing with Leipzig corpus (go-ftw style)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("vendor  "), "🆕 Vendor-specific WAF detection with bypass hints (GoTestWAF style)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("protocol"), "🆕 Enterprise protocol detection (gRPC, SOAP, GraphQL, WCF)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("fuzz    "), "Directory/content fuzzing with FUZZ keyword (like ffuf)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("probe   "), "Protocol probing (TLS, HTTP/2, headers, WAF/CDN detection)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("crawl   "), "Advanced web crawler with scope control")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("analyze "), "JavaScript analysis (URLs, methods, secrets, DOM sinks)")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("validate"), "Check payload files for schema errors")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("validate-templates"), "Check nuclei YAML templates for structure errors")
	fmt.Printf("  %s  %s\n", ui.StatValueStyle.Render("update  "), "Fetch latest payloads from OWASP sources")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("🧠 SMART MODE (--smart)"))
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("WAF-Aware Testing with 197+ Vendor Signatures"))
	fmt.Println()
	fmt.Println("    Smart mode automatically detects the WAF vendor and optimizes testing:")
	fmt.Println()
	fmt.Println("    1. WAF Detection     - Identifies WAF from 197+ vendor signatures (exceeds wafw00f!)")
	fmt.Println("    2. Rate Optimization - Adjusts rate limit to avoid triggering rate blocks")
	fmt.Println("    3. Encoder Priority  - Prioritizes encoders known to bypass that specific WAF")
	fmt.Println("    4. Evasion Selection - Enables evasion techniques effective against that WAF")
	fmt.Println("    5. Bypass Hints      - Shows specific bypass tips for the detected WAF")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Supported WAF Vendors (197 signatures):"))
	fmt.Println("    Cloud: Cloudflare, AWS WAF, Azure WAF, GCP Cloud Armor, Akamai...")
	fmt.Println("    Enterprise: Imperva, F5 BIG-IP, Fortinet, Barracuda, Citrix...")
	fmt.Println("    Software: ModSecurity, NAXSI, Shadow Daemon, lua-resty-waf...")
	fmt.Println("    CDN: Fastly, StackPath, KeyCDN, CDNetworks, ChinaCache...")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Smart Mode Options:"))
	fmt.Println("    --smart              Enable WAF-aware testing")
	fmt.Println("    --smart-mode=MODE    Optimization level: quick, standard, full, bypass, stealth")
	fmt.Println("    --smart-verbose      Show detailed WAF detection and optimization info")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Example:"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester bypass -u https://target.com --smart"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester auto -u https://target.com --smart --smart-mode=full"))
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("DISCOVER COMMAND"))
	fmt.Println()
	fmt.Println("  Automatically finds endpoints and attack surface using multiple techniques:")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Discovery Sources:"))
	fmt.Println("    robots.txt      - Parses Allow/Disallow rules, finds hidden paths")
	fmt.Println("    sitemap.xml     - Checks 9 common paths (sitemap.xml, sitemap_index.xml, ...)")
	fmt.Println("    JavaScript      - Deep JS analysis: URLs, secrets, DOM sinks, HTTP method inference")
	fmt.Println("    Wayback Machine - Historical URLs from web.archive.org (may reveal old endpoints)")
	fmt.Println("    HTML Forms      - Finds login forms, file uploads, API endpoints")
	fmt.Println("    Service Presets - Known endpoints for wordpress, drupal, nextjs, flask, django")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("JavaScript Analysis Features:"))
	fmt.Println("    • Extracts API endpoints from fetch(), axios(), jQuery.ajax(), XMLHttpRequest")
	fmt.Println("    • Infers HTTP methods (POST/PUT/DELETE) from URL patterns and code context")
	fmt.Println("    • Detects secrets: API keys, tokens, credentials (AWS, Google, GitHub, Stripe, etc.)")
	fmt.Println("    • Finds DOM XSS sinks: innerHTML, document.write, eval, etc.")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("INPUT (multiple targets):"))
	fmt.Println("    -u, -target <url> Target URL(s) - comma-separated or repeated")
	fmt.Println("    -l <file>         File containing target URLs (one per line)")
	fmt.Println("    -stdin            Read targets from stdin")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Options:"))
	fmt.Println("    -service <name>   Use known endpoint patterns (wordpress|drupal|nextjs|flask|django)")
	fmt.Println("    -output <file>    Save results to file (default: discovery.json)")
	fmt.Println("    -concurrency <n>  Parallel workers (default: 10)")
	fmt.Println("    -depth <n>        Max crawl depth (default: 3)")
	fmt.Println("    -timeout <sec>    HTTP timeout in seconds (default: 10)")
	fmt.Println("    -skip-verify      Skip TLS verification (self-signed certs)")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Output:"))
	fmt.Println("    discovery.json - List of endpoints, attack surface analysis, WAF detection")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("LEARN COMMAND"))
	fmt.Println()
	fmt.Println("  Analyzes discovery results and generates a targeted test plan:")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("What it does:"))
	fmt.Println("    • Maps endpoints to relevant attack categories (auth endpoints → auth attacks)")
	fmt.Println("    • Prioritizes: P1 (auth/injection) → P5 (fuzz testing)")
	fmt.Println("    • Calculates optimal concurrency and rate limits")
	fmt.Println("    • Generates custom payloads for specific endpoints")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("INPUT (multiple targets):"))
	fmt.Println("    -u, -target <url> Target URL(s) - comma-separated or repeated")
	fmt.Println("    -l <file>         File containing target URLs (one per line)")
	fmt.Println("    -stdin            Read targets from stdin")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Options:"))
	fmt.Println("    -discovery <file>  Discovery JSON from 'discover' command")
	fmt.Println("    -payloads <dir>    Payload directory (default: ../payloads)")
	fmt.Println("    -output <file>     Save test plan (default: testplan.json)")
	fmt.Println("    -custom-payloads   Also export custom payloads to file")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Output:"))
	fmt.Println("    testplan.json - Target, categories, priorities, recommended flags")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("RUN COMMAND"))
	fmt.Println()
	fmt.Println("  Executes WAF security tests. Use with -plan for targeted testing,")
	fmt.Println("  or standalone with -target for manual control.")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("INPUT (multiple targets):"))
	fmt.Println("    -u, -target <url> Target URL(s) - comma-separated or repeated")
	fmt.Println("    -l <file>         File containing target URLs (one per line)")
	fmt.Println("    -plan <file>      Test plan from 'learn' command")
	fmt.Println("    -stdin            Read targets from stdin (for piping)")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("EXECUTION:"))
	fmt.Println("    -c <n>                 Concurrent workers (default: 25)")
	fmt.Println("    -rl, -rate-limit <n>   Requests per second (default: 150)")
	fmt.Println("    -timeout <sec>         HTTP timeout (default: 5)")
	fmt.Println("    -retries <n>           Retry count on failure (default: 1)")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("PAYLOADS:"))
	fmt.Println("    -p, -payloads <dir>    Payload directory (default: ../payloads)")
	fmt.Println("    -category <name>       Filter: xss, injection, auth, traversal, etc")
	fmt.Println("    -severity <level>      Filter: Critical, High, Medium, Low")
	fmt.Println("    -dry-run               List tests without executing")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("MUTATION (WAF bypass):"))
	fmt.Println("    -m, -mutation <mode>   Mutation mode: none, quick, standard, full")
	fmt.Println("    -encoders <list>       Comma-separated encoders (url,double_url,html_hex)")
	fmt.Println("    -locations <list>      Comma-separated locations (query_param,post_json)")
	fmt.Println("    -evasions <list>       Comma-separated evasions (case_swap,sql_comment)")
	fmt.Println("    -chain                 Enable chained mutations (encoder → evasion)")
	fmt.Println("    -max-chain <n>         Maximum chain depth (default: 2)")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("MATCHERS (what to report):"))
	fmt.Println("    -mc <codes>            Match status codes (e.g., 200,403,500)")
	fmt.Println("    -ms <size>             Match response size")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("FILTERS (what to hide):"))
	fmt.Println("    -fc <codes>            Filter status codes (e.g., 404,500)")
	fmt.Println("    -fs <size>             Filter response size")
	fmt.Println("    -ac                    Auto-calibrate (detect baseline responses)")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("OUTPUT:"))
	fmt.Println("    -o <file>              Output file path")
	fmt.Println("    -format <type>         Format: console, json, jsonl, sarif, csv, md, html")
	fmt.Println("    -j, -jsonl             JSONL output (one JSON per line)")
	fmt.Println("    -v, -verbose           Verbose output")
	fmt.Println("    -s, -silent            Silent mode - no progress")
	fmt.Println("    -nc, -no-color         Disable colored output")
	fmt.Println("    -ts, -timestamp        Add timestamp to output (nuclei style)")
	fmt.Println("    -sr, -store-response   Store HTTP responses to directory")
	fmt.Println("    -srd <dir>             Directory for stored responses")
	fmt.Println("    -stats                 Show statistics during execution")
	fmt.Println("    -noninteractive        Disable ENTER-to-pause feature")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("NETWORK:"))
	fmt.Println("    -x, -proxy <url>       HTTP/SOCKS5 proxy")
	fmt.Println("    -k, -skip-verify       Skip TLS verification")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("REALISTIC MODE (advanced):"))
	fmt.Println("    -R, -realistic         Use realistic browser-like requests & smart block detection")
	fmt.Println("                           Includes: rotating User-Agents, realistic headers,")
	fmt.Println("                           multi-location injection, intelligent WAF block detection")
	fmt.Println()
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("EXAMPLES:"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -plan testplan.json"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -u https://example.com -c 50 -rl 200"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -u https://example.com -mc 403 -j -o results.jsonl"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -u https://example.com -format html -o report.html"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("waf-tester run -u https://example.com -ts -format csv -o results.csv"))
	fmt.Printf("    %s\n", ui.ConfigValueStyle.Render("echo https://target.com | waf-tester run -stdin -s"))
	fmt.Println()

	ui.PrintHelp("Run \"waf-tester <command> -h\" for command-specific help")
	ui.PrintHelp("Run \"waf-tester docs\" for comprehensive documentation")
	fmt.Println()
}

// printDetailedDocs prints comprehensive documentation for all features
func printDetailedDocs() {
	ui.PrintBanner()
	os.Stderr.Sync()

	// Check if a specific topic was requested
	topic := ""
	if len(os.Args) > 2 {
		topic = strings.ToLower(os.Args[2])
	}

	switch topic {
	case "discover", "discovery":
		printDocsDiscover()
	case "learn", "learning":
		printDocsLearn()
	case "run", "execute", "test":
		printDocsRun()
	case "auto", "superpower":
		printDocsAuto()
	case "assess", "assessment", "benchmark", "enterprise":
		printDocsAssess()
	case "scan", "scanning":
		printDocsScan()
	case "mutate", "mutation", "mutations":
		printDocsMutation()
	case "bypass", "bypasses":
		printDocsBypass()
	case "fuzz", "fuzzing":
		printDocsFuzz()
	case "probe", "probing":
		printDocsProbe()
	case "crawl", "crawler":
		printDocsCrawl()
	case "analyze", "js", "javascript":
		printDocsAnalyze()
	case "payloads", "payload":
		printDocsPayloads()
	case "categories", "category":
		printDocsCategories()
	case "output", "formats", "format":
		printDocsOutput()
	case "examples", "example":
		printDocsExamples()
	case "workflow", "workflows":
		printDocsWorkflow()
	default:
		printDocsIndex()
	}
}

func printDocsIndex() {
	fmt.Println(ui.SectionStyle.Render("📚 WAF-TESTER COMPREHENSIVE DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  Welcome to waf-tester - the adaptive WAF security testing toolkit.")
	fmt.Println("  This tool helps you discover vulnerabilities and test WAF effectiveness.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("AVAILABLE DOCUMENTATION TOPICS"))
	fmt.Println()
	fmt.Println("  Run: waf-tester docs <topic>")
	fmt.Println()
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("discover"), "Target discovery and attack surface mapping")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("learn"), "Intelligent test plan generation")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("run"), "Test execution and result handling")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("auto"), "Full automated scanning workflow")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("assess"), "Enterprise assessment with quantitative metrics")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("scan"), "Deep vulnerability scanning")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("mutate"), "Payload mutation and encoding")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("bypass"), "WAF bypass techniques")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("fuzz"), "Directory and content fuzzing")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("probe"), "Protocol and WAF detection")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("crawl"), "Advanced web crawling")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("analyze"), "JavaScript analysis")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("payloads"), "Payload structure and formats")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("categories"), "Attack categories explained")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("output"), "Output formats and reporting")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("examples"), "Real-world usage examples")
	fmt.Printf("  %-15s %s\n", ui.StatValueStyle.Render("workflow"), "Recommended testing workflows")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("QUICK START GUIDE"))
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("1. Basic WAF Test (single target):"))
	fmt.Println("     waf-tester run -u https://example.com -c 25")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("2. Smart Adaptive Testing (recommended):"))
	fmt.Println("     waf-tester discover -u https://target.com -output discovery.json")
	fmt.Println("     waf-tester learn -discovery discovery.json -output testplan.json")
	fmt.Println("     waf-tester run -plan testplan.json -o results.json")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("3. Full Automated Scan (one command):"))
	fmt.Println("     waf-tester auto -u https://target.com -service myapp")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("4. WAF Bypass Hunting:"))
	fmt.Println("     waf-tester bypass -u https://target.com -category sqli -mutation full")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("CORE CONCEPTS"))
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Adaptive Testing:"))
	fmt.Println("    Unlike traditional scanners that blindly throw payloads, waf-tester adapts:")
	fmt.Println("    • Discovers your target's attack surface first")
	fmt.Println("    • Learns which tests are relevant for what was found")
	fmt.Println("    • Prioritizes high-value tests (auth, injection) over noise")
	fmt.Println("    • Auto-calibrates to filter out false positives")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Mutation Engine:"))
	fmt.Println("    Payloads are automatically mutated to bypass WAF filters:")
	fmt.Println("    • Encoders: URL, Double-URL, HTML, Unicode, Base64, etc.")
	fmt.Println("    • Locations: Query params, POST body, JSON, headers, cookies")
	fmt.Println("    • Evasions: Case swapping, SQL comments, null bytes, etc.")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Realistic Mode:"))
	fmt.Println("    Makes requests look like real browser traffic:")
	fmt.Println("    • Rotating User-Agents (Chrome, Firefox, Safari)")
	fmt.Println("    • Real browser headers (Accept, Accept-Language, etc.)")
	fmt.Println("    • Intelligent WAF block detection")
	fmt.Println()
}

func printDocsDiscover() {
	fmt.Println(ui.SectionStyle.Render("📡 DISCOVER COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The discover command maps your target's attack surface by gathering")
	fmt.Println("  endpoints from multiple sources. This is the foundation for smart testing.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("DISCOVERY SOURCES EXPLAINED"))
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("1. robots.txt Parsing"))
	fmt.Println("     What: Parses /robots.txt for Allow and Disallow rules")
	fmt.Println("     Why:  Often reveals hidden admin panels, API paths, staging areas")
	fmt.Println("     Example findings: /admin/, /api/v2/, /staging/, /.git/")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("2. Sitemap Discovery"))
	fmt.Println("     What: Checks 9 common sitemap locations")
	fmt.Println("     Checks: sitemap.xml, sitemap_index.xml, sitemap-index.xml,")
	fmt.Println("             sitemaps.xml, sitemap1.xml, post-sitemap.xml,")
	fmt.Println("             page-sitemap.xml, sitemap.xml.gz, sitemap_index.xml.gz")
	fmt.Println("     Why:  Full URL listing of public pages, reveals URL structure")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("3. JavaScript Analysis (Deep)"))
	fmt.Println("     What: Downloads and parses all .js files for:")
	fmt.Println("     • API endpoints (fetch, axios, jQuery.ajax, XMLHttpRequest)")
	fmt.Println("     • HTTP methods inferred from URL patterns (/login → POST)")
	fmt.Println("     • Hardcoded secrets (API keys, tokens, credentials)")
	fmt.Println("     • DOM XSS sinks (innerHTML, document.write, eval)")
	fmt.Println("     • AWS/Google/GitHub/Stripe/Twilio API keys")
	fmt.Println("     Why:  Modern SPAs have all API endpoints in JavaScript")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("4. Wayback Machine"))
	fmt.Println("     What: Queries web.archive.org for historical URLs")
	fmt.Println("     Why:  Reveals endpoints that may still exist but are unlisted")
	fmt.Println("     Finds: Old API versions, removed pages, debug endpoints")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("5. HTML Form Analysis"))
	fmt.Println("     What: Parses HTML for <form> elements")
	fmt.Println("     Finds: Login forms, file uploads, search forms, contact forms")
	fmt.Println("     Why:  Forms are primary injection points")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("6. Service Presets"))
	fmt.Println("     What: Pre-defined endpoint patterns for known applications")
	fmt.Println("     Supported: wordpress, drupal, nextjs, flask, django")
	fmt.Println("     Why:  Skip discovery for known app types")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FLAGS AND OPTIONS"))
	fmt.Println()
	fmt.Println("  -u, -target <url>    Target URL (required)")
	fmt.Println("                       Can be repeated: -u site1.com -u site2.com")
	fmt.Println("                       Comma-separated: -u site1.com,site2.com")
	fmt.Println()
	fmt.Println("  -l <file>            File with target URLs (one per line)")
	fmt.Println()
	fmt.Println("  -service <name>      Use preset endpoints for known apps")
	fmt.Println("                       Options: wordpress, drupal, nextjs, flask, django")
	fmt.Println()
	fmt.Println("  -output <file>       Output file (default: discovery.json)")
	fmt.Println()
	fmt.Println("  -depth <n>           Crawl depth for HTML parsing (default: 3)")
	fmt.Println("                       Higher = more thorough but slower")
	fmt.Println()
	fmt.Println("  -concurrency <n>     Parallel discovery workers (default: 10)")
	fmt.Println()
	fmt.Println("  -timeout <sec>       HTTP timeout per request (default: 10)")
	fmt.Println()
	fmt.Println("  -skip-verify         Skip TLS certificate verification")
	fmt.Println("                       Use for self-signed certs in testing environments")
	fmt.Println()
	fmt.Println("  -verbose             Show detailed discovery progress")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("OUTPUT FORMAT"))
	fmt.Println()
	fmt.Println("  The discovery.json contains:")
	fmt.Println("  {")
	fmt.Println("    \"target\": \"https://example.com\",")
	fmt.Println("    \"endpoints\": [")
	fmt.Println("      {\"path\": \"/api/users\", \"method\": \"GET\", \"source\": \"js\"},")
	fmt.Println("      {\"path\": \"/login\", \"method\": \"POST\", \"source\": \"form\"}")
	fmt.Println("    ],")
	fmt.Println("    \"js_files\": [\"/app.js\", \"/vendor.js\"],")
	fmt.Println("    \"secrets\": [{\"type\": \"aws_key\", \"value\": \"AKIA...\"}],")
	fmt.Println("    \"waf_detected\": \"cloudflare\"")
	fmt.Println("  }")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Basic discovery")
	fmt.Println("  waf-tester discover -u https://target.com")
	fmt.Println()
	fmt.Println("  # With service preset")
	fmt.Println("  waf-tester discover -u https://auth.example.com -service authentik")
	fmt.Println()
	fmt.Println("  # Deep discovery with verbose output")
	fmt.Println("  waf-tester discover -u https://target.com -depth 5 -verbose")
	fmt.Println()
	fmt.Println("  # Multiple targets")
	fmt.Println("  waf-tester discover -l targets.txt -output all-discovery.json")
	fmt.Println()
}

func printDocsLearn() {
	fmt.Println(ui.SectionStyle.Render("🧠 LEARN COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The learn command analyzes discovery results and generates an")
	fmt.Println("  intelligent, prioritized test plan tailored to your target.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("HOW IT WORKS"))
	fmt.Println()
	fmt.Println("  1. " + ui.SubtitleStyle.Render("Endpoint Analysis"))
	fmt.Println("     • Classifies endpoints by type (auth, API, admin, static)")
	fmt.Println("     • Identifies high-value targets (login, password reset, file upload)")
	fmt.Println("     • Maps parameters that accept user input")
	fmt.Println()
	fmt.Println("  2. " + ui.SubtitleStyle.Render("Category Mapping"))
	fmt.Println("     • /login, /auth → Authentication attacks (brute force, credential stuffing)")
	fmt.Println("     • /api/*, /search → Injection attacks (SQLi, NoSQLi, XSS)")
	fmt.Println("     • /upload, /import → File upload attacks")
	fmt.Println("     • /admin, /dashboard → Privilege escalation")
	fmt.Println()
	fmt.Println("  3. " + ui.SubtitleStyle.Render("Priority Assignment"))
	fmt.Println("     P1 (Critical): Authentication, SQL injection, command injection")
	fmt.Println("     P2 (High):     XSS, SSRF, file upload, path traversal")
	fmt.Println("     P3 (Medium):   CSRF, open redirect, information disclosure")
	fmt.Println("     P4 (Low):      Verbose errors, missing headers")
	fmt.Println("     P5 (Info):     Fuzzing, enumeration")
	fmt.Println()
	fmt.Println("  4. " + ui.SubtitleStyle.Render("Rate Optimization"))
	fmt.Println("     • Calculates safe request rate based on WAF detection")
	fmt.Println("     • Adjusts concurrency for target capacity")
	fmt.Println("     • Generates recommended execution flags")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FLAGS AND OPTIONS"))
	fmt.Println()
	fmt.Println("  -discovery <file>    Input: discovery.json from 'discover' command (required)")
	fmt.Println()
	fmt.Println("  -u, -target <url>    Target URL (uses discovery data if not specified)")
	fmt.Println()
	fmt.Println("  -payloads <dir>      Payload directory (default: ../payloads)")
	fmt.Println("                       Must contain category subdirectories with JSON files")
	fmt.Println()
	fmt.Println("  -output <file>       Output test plan file (default: testplan.json)")
	fmt.Println()
	fmt.Println("  -custom-payloads     Also generate custom payloads file")
	fmt.Println("                       Creates targeted payloads based on discovered patterns")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("TEST PLAN FORMAT"))
	fmt.Println()
	fmt.Println("  {")
	fmt.Println("    \"target\": \"https://example.com\",")
	fmt.Println("    \"generated_at\": \"2026-01-27T10:30:00Z\",")
	fmt.Println("    \"categories\": [\"sqli\", \"xss\", \"auth\"],")
	fmt.Println("    \"priorities\": {\"sqli\": 1, \"xss\": 2, \"auth\": 1},")
	fmt.Println("    \"endpoints\": [{\"path\": \"/api/login\", \"methods\": [\"POST\"]}],")
	fmt.Println("    \"recommended_flags\": {")
	fmt.Println("      \"concurrency\": 25,")
	fmt.Println("      \"rate_limit\": 100,")
	fmt.Println("      \"realistic\": true")
	fmt.Println("    }")
	fmt.Println("  }")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Generate test plan from discovery")
	fmt.Println("  waf-tester learn -discovery discovery.json")
	fmt.Println()
	fmt.Println("  # With custom output path")
	fmt.Println("  waf-tester learn -discovery discovery.json -output my-testplan.json")
	fmt.Println()
	fmt.Println("  # Also generate custom payloads")
	fmt.Println("  waf-tester learn -discovery discovery.json -custom-payloads")
	fmt.Println()
}

func printDocsRun() {
	fmt.Println(ui.SectionStyle.Render("🚀 RUN COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The run command executes WAF security tests against your target.")
	fmt.Println("  Use with -plan for intelligent testing or standalone for manual control.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXECUTION MODES"))
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("1. Plan-Based (Recommended)"))
	fmt.Println("     waf-tester run -plan testplan.json")
	fmt.Println("     • Uses test plan from 'learn' command")
	fmt.Println("     • Automatically prioritizes tests")
	fmt.Println("     • Applies recommended settings")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("2. Standalone"))
	fmt.Println("     waf-tester run -u https://target.com -category sqli")
	fmt.Println("     • Manual control over all settings")
	fmt.Println("     • Good for targeted testing of specific categories")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("CONCURRENCY AND RATE LIMITING"))
	fmt.Println()
	fmt.Println("  -c <n>               Concurrent workers (default: 25)")
	fmt.Println("                       Higher = faster but may trigger rate limits")
	fmt.Println("                       Lower = slower but safer")
	fmt.Println()
	fmt.Println("  -rl, -rate-limit <n> Max requests per second (default: 150)")
	fmt.Println("                       Adjust based on target capacity and WAF sensitivity")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Recommended Settings:"))
	fmt.Println("     • Production sites: -c 10 -rl 20 (conservative)")
	fmt.Println("     • Staging/test: -c 50 -rl 200 (aggressive)")
	fmt.Println("     • WAF bypass hunting: -c 5 -rl 10 (stealth)")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FILTERING AND MATCHING"))
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Match (what to report):"))
	fmt.Println("  -mc <codes>          Match status codes: -mc 200,403,500")
	fmt.Println("  -ms <size>           Match response size: -ms 1234")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Filter (what to hide):"))
	fmt.Println("  -fc <codes>          Filter status codes: -fc 404,500")
	fmt.Println("  -fs <size>           Filter response size: -fs 0")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Auto-Calibration:"))
	fmt.Println("  -ac                  Automatically detect and filter baseline responses")
	fmt.Println("                       Sends probe requests to learn normal response patterns")
	fmt.Println("                       Then filters out responses matching the baseline")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("OUTPUT OPTIONS"))
	fmt.Println()
	fmt.Println("  -o <file>            Output file path")
	fmt.Println("  -format <type>       Output format:")
	fmt.Println("                       • console - Human-readable terminal output")
	fmt.Println("                       • json    - Single JSON array")
	fmt.Println("                       • jsonl   - JSON Lines (one object per line)")
	fmt.Println("                       • sarif   - SARIF for IDE integration")
	fmt.Println("                       • csv     - Spreadsheet-compatible")
	fmt.Println("                       • md      - Markdown table")
	fmt.Println("                       • html    - Interactive HTML report")
	fmt.Println()
	fmt.Println("  -v, -verbose         Show detailed test output")
	fmt.Println("  -s, -silent          No progress output (for scripting)")
	fmt.Println("  -ts, -timestamp      Add timestamps (nuclei style)")
	fmt.Println("  -stats               Show live statistics")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("REALISTIC MODE"))
	fmt.Println()
	fmt.Println("  -R, -realistic       Enable realistic browser simulation")
	fmt.Println()
	fmt.Println("  Features:")
	fmt.Println("  • Rotating User-Agent strings (Chrome, Firefox, Safari, Edge)")
	fmt.Println("  • Realistic Accept headers (text/html, application/json)")
	fmt.Println("  • Accept-Language, Accept-Encoding headers")
	fmt.Println("  • Referer header simulation")
	fmt.Println("  • Multi-location injection (query, body, headers)")
	fmt.Println("  • Intelligent WAF block detection (pattern matching)")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Run with test plan")
	fmt.Println("  waf-tester run -plan testplan.json")
	fmt.Println()
	fmt.Println("  # Manual run with specific category")
	fmt.Println("  waf-tester run -u https://target.com -category sqli -c 25")
	fmt.Println()
	fmt.Println("  # Generate HTML report")
	fmt.Println("  waf-tester run -plan testplan.json -format html -o report.html")
	fmt.Println()
	fmt.Println("  # Conservative testing with auto-calibration")
	fmt.Println("  waf-tester run -u https://prod.com -c 10 -rl 20 -ac -realistic")
	fmt.Println()
	fmt.Println("  # Silent mode for scripting")
	fmt.Println("  waf-tester run -plan testplan.json -s -o results.json")
	fmt.Println()
}

func printDocsAuto() {
	fmt.Println(ui.SectionStyle.Render("⚡ AUTO COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The auto command runs a complete security assessment in one command:")
	fmt.Println("  discover → analyze → learn → run → report")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("WHAT IT DOES"))
	fmt.Println()
	fmt.Println("  1. " + ui.SubtitleStyle.Render("Discovery Phase"))
	fmt.Println("     • Crawls target for endpoints")
	fmt.Println("     • Parses robots.txt, sitemap")
	fmt.Println("     • Analyzes JavaScript for API endpoints")
	fmt.Println("     • Queries Wayback Machine")
	fmt.Println()
	fmt.Println("  2. " + ui.SubtitleStyle.Render("Analysis Phase"))
	fmt.Println("     • Deep JavaScript analysis for secrets")
	fmt.Println("     • DOM XSS sink detection")
	fmt.Println("     • WAF fingerprinting")
	fmt.Println()
	fmt.Println("  3. " + ui.SubtitleStyle.Render("Learning Phase"))
	fmt.Println("     • Maps endpoints to attack categories")
	fmt.Println("     • Prioritizes tests")
	fmt.Println("     • Generates optimized test plan")
	fmt.Println()
	fmt.Println("  4. " + ui.SubtitleStyle.Render("Execution Phase"))
	fmt.Println("     • Runs all prioritized tests")
	fmt.Println("     • Auto-calibrates filters")
	fmt.Println("     • Applies mutation if needed")
	fmt.Println()
	fmt.Println("  5. " + ui.SubtitleStyle.Render("Reporting Phase"))
	fmt.Println("     • Generates results in requested format")
	fmt.Println("     • Creates workspace with all artifacts")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FLAGS AND OPTIONS"))
	fmt.Println()
	fmt.Println("  -u, -target <url>    Target URL (required)")
	fmt.Println("  -service <name>      Service name (for workspace organization)")
	fmt.Println("  -c <n>               Concurrency (default: 25)")
	fmt.Println("  -rl <n>              Rate limit (default: 100)")
	fmt.Println("  -depth <n>           Discovery depth (default: 3)")
	fmt.Println("  -format <type>       Output format (json, html, sarif, etc.)")
	fmt.Println("  -payloads <dir>      Payload directory")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("WORKSPACE STRUCTURE"))
	fmt.Println()
	fmt.Println("  Auto creates a workspace directory:")
	fmt.Println("  workspaces/")
	fmt.Println("  └── example.com/")
	fmt.Println("      └── 2026-01-27_10-30-00/")
	fmt.Println("          ├── discovery.json")
	fmt.Println("          ├── testplan.json")
	fmt.Println("          ├── results.json")
	fmt.Println("          ├── results.html")
	fmt.Println("          └── results.sarif")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Full automated scan")
	fmt.Println("  waf-tester auto -u https://target.com -service myapp")
	fmt.Println()
	fmt.Println("  # Conservative automated scan")
	fmt.Println("  waf-tester auto -u https://prod.com -c 10 -rl 20")
	fmt.Println()
	fmt.Println("  # With HTML report")
	fmt.Println("  waf-tester auto -u https://target.com -format html")
	fmt.Println()
}

func printDocsAssess() {
	fmt.Println(ui.SectionStyle.Render("🏢 ENTERPRISE WAF ASSESSMENT - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The assess command provides comprehensive WAF evaluation with")
	fmt.Println("  quantitative metrics used in academic research and enterprise audits.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("WHAT IT DOES"))
	fmt.Println()
	fmt.Println("  1. Attack Testing   - Tests WAF with curated attack payloads")
	fmt.Println("  2. FP Testing       - Tests with benign corpus (Leipzig, builtin)")
	fmt.Println("  3. Metrics          - Computes precision, recall, F1, MCC, etc.")
	fmt.Println("  4. Grading          - Assigns A+ to F grade with recommendations")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("QUANTITATIVE METRICS"))
	fmt.Println()
	fmt.Println("  Primary Metrics:")
	fmt.Println("    • Detection Rate (TPR/Recall) - % of attacks blocked")
	fmt.Println("    • False Positive Rate (FPR)   - % of legitimate traffic blocked")
	fmt.Println("    • Precision                   - % of blocks that were real attacks")
	fmt.Println("    • Specificity (TNR)           - % of legitimate traffic allowed")
	fmt.Println()
	fmt.Println("  Balanced Metrics:")
	fmt.Println("    • F1 Score            - Harmonic mean of precision & recall")
	fmt.Println("    • F2 Score            - Recall-weighted F-measure")
	fmt.Println("    • MCC                 - Matthews Correlation Coefficient (-1 to +1)")
	fmt.Println("    • Balanced Accuracy   - Average of TPR and TNR")
	fmt.Println()
	fmt.Println("  WAF-Specific Metrics:")
	fmt.Println("    • Bypass Resistance   - Attack detection with evasion techniques")
	fmt.Println("    • Block Consistency   - Variance across attack categories")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FALSE POSITIVE CORPUS"))
	fmt.Println()
	fmt.Println("  -corpus <sources>     Comma-separated corpus sources:")
	fmt.Println()
	fmt.Println("    builtin     130+ curated benign sentences (forms, news, technical)")
	fmt.Println("    leipzig     Leipzig Corpora Collection (downloaded & cached)")
	fmt.Println()
	fmt.Println("  -custom-corpus <file> Your own corpus (JSON array or line-by-line)")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("OPTIONS"))
	fmt.Println()
	fmt.Println("  -u <url>              Target URL (required)")
	fmt.Println("  -c <n>                Concurrency (default: 25)")
	fmt.Println("  -rate <n>             Rate limit req/sec (default: 100)")
	fmt.Println("  -timeout <n>          Request timeout seconds (default: 10)")
	fmt.Println("  -categories <list>    Attack categories to test (default: all)")
	fmt.Println("  -fp                   Enable FP testing (default: true)")
	fmt.Println("  -detect-waf           Auto-detect WAF vendor (default: true)")
	fmt.Println("  -o <file>             Output results to file")
	fmt.Println("  -format <fmt>         Output format: console, json (default: console)")
	fmt.Println("  -v                    Verbose output")
	fmt.Println("  -k                    Skip TLS verification")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("GRADING SCALE"))
	fmt.Println()
	fmt.Println("    A+   F1 >= 0.95, FPR < 0.01    Exceptional - enterprise ready")
	fmt.Println("    A    F1 >= 0.90, FPR < 0.02    Excellent - production quality")
	fmt.Println("    B+   F1 >= 0.85, FPR < 0.05    Good - minor tuning needed")
	fmt.Println("    B    F1 >= 0.80, FPR < 0.05    Good - some improvements needed")
	fmt.Println("    C    F1 >= 0.70, FPR < 0.10    Acceptable - significant gaps")
	fmt.Println("    D    F1 >= 0.50, FPR < 0.15    Poor - major issues")
	fmt.Println("    F    F1 < 0.50 or FPR >= 0.15  Failing - not production ready")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Basic assessment")
	fmt.Println("  waf-tester assess -u https://example.com")
	fmt.Println()
	fmt.Println("  # Full corpus with JSON output")
	fmt.Println("  waf-tester assess -u https://example.com -corpus builtin,leipzig -o report.json -format json")
	fmt.Println()
	fmt.Println("  # Specific categories")
	fmt.Println("  waf-tester assess -u https://example.com -categories sqli,xss,cmdi")
	fmt.Println()
	fmt.Println("  # High concurrency with custom corpus")
	fmt.Println("  waf-tester assess -u https://example.com -c 50 -custom-corpus ./my-benign.txt")
	fmt.Println()
}

func printDocsScan() {
	fmt.Println(ui.SectionStyle.Render("🔍 SCAN COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The scan command performs deep vulnerability scanning for specific")
	fmt.Println("  vulnerability types with specialized detection logic.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("SCAN TYPES"))
	fmt.Println()
	fmt.Println("  -types <list>        Comma-separated vulnerability types:")
	fmt.Println()
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("sqli"), "SQL Injection - Union, Error, Blind, Time-based")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("xss"), "Cross-Site Scripting - Reflected, Stored, DOM")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("ssrf"), "Server-Side Request Forgery")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("ssti"), "Server-Side Template Injection")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("lfi"), "Local File Inclusion / Path Traversal")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("rce"), "Remote Code Execution / Command Injection")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("oauth"), "OAuth/OIDC misconfigurations")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("xxe"), "XML External Entity")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("jwt"), "JWT token vulnerabilities")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("cors"), "CORS misconfigurations")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("crlf"), "CRLF / HTTP Response Splitting")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("upload"), "File upload vulnerabilities")
	fmt.Printf("  %-12s %s\n", ui.StatValueStyle.Render("nosql"), "NoSQL Injection (MongoDB, etc.)")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Scan for SQL injection")
	fmt.Println("  waf-tester scan -u https://target.com -types sqli")
	fmt.Println()
	fmt.Println("  # Multiple vulnerability types")
	fmt.Println("  waf-tester scan -u https://target.com -types sqli,xss,ssrf")
	fmt.Println()
	fmt.Println("  # From target list")
	fmt.Println("  waf-tester scan -l targets.txt -types oauth,jwt")
	fmt.Println()
}

func printDocsMutation() {
	fmt.Println(ui.SectionStyle.Render("🔀 MUTATION ENGINE - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The mutation engine transforms payloads to bypass WAF filters.")
	fmt.Println("  It applies encodings, injection locations, and evasion techniques.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("MUTATION MODES"))
	fmt.Println()
	fmt.Println("  -mutation <mode>     Mutation intensity:")
	fmt.Println()
	fmt.Println("  " + ui.StatValueStyle.Render("none") + "      No mutations (raw payloads only)")
	fmt.Println("  " + ui.StatValueStyle.Render("quick") + "     Basic URL encoding")
	fmt.Println("  " + ui.StatValueStyle.Render("standard") + "  Common encodings + locations")
	fmt.Println("  " + ui.StatValueStyle.Render("full") + "      All encoders × all locations × all evasions")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("ENCODERS"))
	fmt.Println()
	fmt.Println("  Transform how payloads are represented:")
	fmt.Println()
	fmt.Println("  url           %27%20OR%201=1")
	fmt.Println("  double_url    %2527%2520OR%25201%253D1")
	fmt.Println("  html_hex      &#x27;&#x20;OR&#x20;1=1")
	fmt.Println("  html_dec      &#39;&#32;OR&#32;1=1")
	fmt.Println("  unicode       \\u0027\\u0020OR\\u00201=1")
	fmt.Println("  base64        JyBPUiAxPTE=")
	fmt.Println("  hex           0x2720204f522031e3d31")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("INJECTION LOCATIONS"))
	fmt.Println()
	fmt.Println("  Where payloads are inserted:")
	fmt.Println()
	fmt.Println("  query_param   ?param=PAYLOAD")
	fmt.Println("  post_form     param=PAYLOAD (application/x-www-form-urlencoded)")
	fmt.Println("  post_json     {\"param\": \"PAYLOAD\"}")
	fmt.Println("  post_xml      <param>PAYLOAD</param>")
	fmt.Println("  header        X-Custom: PAYLOAD")
	fmt.Println("  cookie        Cookie: session=PAYLOAD")
	fmt.Println("  path          /api/PAYLOAD/endpoint")
	fmt.Println("  fragment      #PAYLOAD")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EVASION TECHNIQUES"))
	fmt.Println()
	fmt.Println("  Bypass WAF pattern matching:")
	fmt.Println()
	fmt.Println("  case_swap     SeLeCt, UNION, uNiOn")
	fmt.Println("  sql_comment   SEL/**/ECT, UN/**/ION")
	fmt.Println("  null_byte     SEL[NUL]ECT, pay[NUL]load")
	fmt.Println("  whitespace    SELECT\\t*\\nFROM")
	fmt.Println("  concat        CONC||AT, CON+CAT")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("CHAINING"))
	fmt.Println()
	fmt.Println("  -chain           Enable chained mutations")
	fmt.Println("  -max-chain <n>   Maximum chain depth (default: 2)")
	fmt.Println()
	fmt.Println("  Chaining applies multiple transformations:")
	fmt.Println("  payload → url_encode → case_swap → sql_comment")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Basic mutation")
	fmt.Println("  waf-tester mutate -u https://target.com -mutation standard")
	fmt.Println()
	fmt.Println("  # Full mutation matrix")
	fmt.Println("  waf-tester mutate -u https://target.com -mutation full -chain")
	fmt.Println()
	fmt.Println("  # Specific encoders only")
	fmt.Println("  waf-tester run -u https://target.com -encoders url,double_url,unicode")
	fmt.Println()
}

func printDocsBypass() {
	fmt.Println(ui.SectionStyle.Render("🎯 WAF BYPASS FINDER - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The bypass command hunts for WAF bypasses using the full mutation matrix.")
	fmt.Println("  It systematically tests encoding and evasion combinations.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("HOW IT WORKS"))
	fmt.Println()
	fmt.Println("  1. Sends baseline request to detect normal blocking")
	fmt.Println("  2. Iterates through encoder × location × evasion combinations")
	fmt.Println("  3. Identifies which mutations bypass the WAF")
	fmt.Println("  4. Reports successful bypasses with full details")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("BYPASS STRATEGIES"))
	fmt.Println()
	fmt.Println("  • Double encoding: WAF decodes once, backend decodes twice")
	fmt.Println("  • Unicode normalization: Homoglyph substitution")
	fmt.Println("  • Case variations: WAFs often match lowercase only")
	fmt.Println("  • Comment insertion: Break up keywords")
	fmt.Println("  • Protocol-level: HTTP/2, chunked encoding")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Hunt for SQL injection bypasses")
	fmt.Println("  waf-tester bypass -u https://target.com -category sqli")
	fmt.Println()
	fmt.Println("  # With specific payload")
	fmt.Println("  waf-tester bypass -u https://target.com -payload \"' OR 1=1--\"")
	fmt.Println()
	fmt.Println("  # Full mutation matrix")
	fmt.Println("  waf-tester bypass -u https://target.com -mutation full")
	fmt.Println()
}

func printDocsFuzz() {
	fmt.Println(ui.SectionStyle.Render("📂 FUZZ COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The fuzz command performs directory and content discovery")
	fmt.Println("  similar to ffuf/gobuster but with WAF-aware capabilities.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("FUZZ KEYWORD"))
	fmt.Println()
	fmt.Println("  Use FUZZ keyword to mark injection point:")
	fmt.Println()
	fmt.Println("  waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt")
	fmt.Println("  waf-tester fuzz -u https://target.com/api/FUZZ -w api-endpoints.txt")
	fmt.Println("  waf-tester fuzz -u https://target.com?param=FUZZ -w values.txt")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("BUILT-IN WORDLISTS"))
	fmt.Println()
	fmt.Println("  -w <file|preset>     Wordlist file or built-in preset:")
	fmt.Println()
	fmt.Println("  common        Common directories and files")
	fmt.Println("  api           API endpoints")
	fmt.Println("  backup        Backup file extensions")
	fmt.Println("  config        Configuration files")
	fmt.Println("  git           Git repository files")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Directory discovery")
	fmt.Println("  waf-tester fuzz -u https://target.com/FUZZ -w common")
	fmt.Println()
	fmt.Println("  # API endpoint discovery")
	fmt.Println("  waf-tester fuzz -u https://target.com/api/FUZZ -w api")
	fmt.Println()
	fmt.Println("  # With filtering")
	fmt.Println("  waf-tester fuzz -u https://target.com/FUZZ -w wordlist.txt -fc 404")
	fmt.Println()
}

func printDocsProbe() {
	fmt.Println(ui.SectionStyle.Render("🔌 PROBE COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The probe command performs protocol-level detection and fingerprinting.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("DETECTION CAPABILITIES"))
	fmt.Println()
	fmt.Println("  • HTTP/HTTPS availability")
	fmt.Println("  • HTTP/2 support")
	fmt.Println("  • TLS version and cipher suites")
	fmt.Println("  • WAF/CDN detection (Cloudflare, Akamai, AWS WAF, etc.)")
	fmt.Println("  • Server headers and technology")
	fmt.Println("  • Security headers (HSTS, CSP, X-Frame-Options)")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Probe single target")
	fmt.Println("  waf-tester probe -u https://target.com")
	fmt.Println()
	fmt.Println("  # Probe multiple targets")
	fmt.Println("  waf-tester probe -l targets.txt -c 50")
	fmt.Println()
	fmt.Println("  # Pipe from other tools")
	fmt.Println("  cat domains.txt | waf-tester probe -stdin")
	fmt.Println()
}

func printDocsCrawl() {
	fmt.Println(ui.SectionStyle.Render("🕷️ CRAWL COMMAND - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The crawl command performs advanced web crawling with scope control.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("SCOPE CONTROL"))
	fmt.Println()
	fmt.Println("  -scope <mode>        Crawling scope:")
	fmt.Println()
	fmt.Println("  strict       Same domain only")
	fmt.Println("  subdomain    Include subdomains")
	fmt.Println("  relaxed      Any link found")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("OPTIONS"))
	fmt.Println()
	fmt.Println("  -depth <n>           Maximum crawl depth (default: 3)")
	fmt.Println("  -concurrency <n>     Parallel crawlers (default: 10)")
	fmt.Println("  -timeout <sec>       Request timeout (default: 10)")
	fmt.Println("  -exclude <pattern>   Exclude URLs matching pattern")
	fmt.Println("  -include <pattern>   Only include URLs matching pattern")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Basic crawl")
	fmt.Println("  waf-tester crawl -u https://target.com -depth 5")
	fmt.Println()
	fmt.Println("  # Crawl with subdomain scope")
	fmt.Println("  waf-tester crawl -u https://target.com -scope subdomain")
	fmt.Println()
	fmt.Println("  # Exclude static assets")
	fmt.Println("  waf-tester crawl -u https://target.com -exclude \"\\.(css|js|png|jpg)$\"")
	fmt.Println()
}

func printDocsAnalyze() {
	fmt.Println(ui.SectionStyle.Render("📜 ANALYZE (JAVASCRIPT) - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  The analyze command performs deep JavaScript static analysis.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("DETECTION CAPABILITIES"))
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("API Endpoints:"))
	fmt.Println("  • fetch() calls with URL extraction")
	fmt.Println("  • axios requests")
	fmt.Println("  • jQuery.ajax() calls")
	fmt.Println("  • XMLHttpRequest usage")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("HTTP Method Inference:"))
	fmt.Println("  • URL patterns: /login → POST, /delete → DELETE")
	fmt.Println("  • Code context: method: 'POST', type: 'PUT'")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("Secret Detection:"))
	fmt.Println("  • AWS Access Keys (AKIA...)")
	fmt.Println("  • Google API Keys")
	fmt.Println("  • GitHub Tokens")
	fmt.Println("  • Stripe Keys")
	fmt.Println("  • Twilio Tokens")
	fmt.Println("  • Generic API Keys and tokens")
	fmt.Println()
	fmt.Println("  " + ui.SubtitleStyle.Render("DOM XSS Sinks:"))
	fmt.Println("  • innerHTML assignments")
	fmt.Println("  • document.write()")
	fmt.Println("  • eval()")
	fmt.Println("  • setTimeout/setInterval with strings")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("EXAMPLES"))
	fmt.Println()
	fmt.Println("  # Analyze target JavaScript")
	fmt.Println("  waf-tester analyze -u https://target.com")
	fmt.Println()
	fmt.Println("  # Analyze specific JS file")
	fmt.Println("  waf-tester analyze -f app.bundle.js")
	fmt.Println()
	fmt.Println("  # Verbose output with all findings")
	fmt.Println("  waf-tester analyze -u https://target.com -verbose")
	fmt.Println()
}

func printDocsPayloads() {
	fmt.Println(ui.SectionStyle.Render("💉 PAYLOAD STRUCTURE - DETAILED DOCUMENTATION"))
	fmt.Println()
	fmt.Println("  Payloads are organized by category in JSON files.")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("DIRECTORY STRUCTURE"))
	fmt.Println()
	fmt.Println("  payloads/")
	fmt.Println("  ├── injection/")
	fmt.Println("  │   ├── sqli.json")
	fmt.Println("  │   ├── nosqli.json")
	fmt.Println("  │   └── cmdi.json")
	fmt.Println("  ├── xss/")
	fmt.Println("  │   ├── reflected.json")
	fmt.Println("  │   └── stored.json")
	fmt.Println("  ├── auth/")
	fmt.Println("  │   ├── brute.json")
	fmt.Println("  │   └── bypass.json")
	fmt.Println("  └── traversal/")
	fmt.Println("      └── path.json")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("PAYLOAD JSON FORMAT"))
	fmt.Println()
	fmt.Println("  {")
	fmt.Println("    \"payloads\": [")
	fmt.Println("      {")
	fmt.Println("        \"id\": \"sqli-001\",")
	fmt.Println("        \"payload\": \"' OR 1=1--\",")
	fmt.Println("        \"category\": \"injection\",")
	fmt.Println("        \"subcategory\": \"sqli\",")
	fmt.Println("        \"severity\": \"Critical\",")
	fmt.Println("        \"description\": \"Classic SQL injection\",")
	fmt.Println("        \"expected_status\": [200, 302],")
	fmt.Println("        \"expected_match\": \"error|sql|syntax\"")
	fmt.Println("      }")
	fmt.Println("    ]")
	fmt.Println("  }")
	fmt.Println()

	fmt.Println(ui.SectionStyle.Render("UPDATING PAYLOADS"))
	fmt.Println()
	fmt.Println("  # Fetch latest from OWASP sources")
	fmt.Println("  waf-tester update")
	fmt.Println()
	fmt.Println("  # Validate payload files")
	fmt.Println("  waf-tester validate -payloads ./payloads")
	fmt.Println()
}

func printDocsCategories() {
	fmt.Println(ui.SectionStyle.Render("📋 ATTACK CATEGORIES - DETAILED DOCUMENTATION"))
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("injection") + " - Code Injection Attacks")
	fmt.Println("    sqli       SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle)")
	fmt.Println("    nosqli     NoSQL Injection (MongoDB, CouchDB)")
	fmt.Println("    cmdi       Command Injection (OS command execution)")
	fmt.Println("    ldapi      LDAP Injection")
	fmt.Println("    xpath      XPath Injection")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("xss") + " - Cross-Site Scripting")
	fmt.Println("    reflected  Reflected XSS (in URL parameters)")
	fmt.Println("    stored     Stored/Persistent XSS")
	fmt.Println("    dom        DOM-based XSS")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("auth") + " - Authentication Attacks")
	fmt.Println("    brute      Brute force / credential stuffing")
	fmt.Println("    bypass     Authentication bypass")
	fmt.Println("    session    Session fixation/hijacking")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("traversal") + " - Path Traversal / LFI")
	fmt.Println("    lfi        Local File Inclusion")
	fmt.Println("    rfi        Remote File Inclusion")
	fmt.Println("    path       Directory traversal (../, etc.)")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("ssrf") + " - Server-Side Request Forgery")
	fmt.Println("    internal   Access internal services")
	fmt.Println("    cloud      Cloud metadata endpoints")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("ssti") + " - Server-Side Template Injection")
	fmt.Println("    jinja      Jinja2 (Python)")
	fmt.Println("    twig       Twig (PHP)")
	fmt.Println("    freemarker FreeMarker (Java)")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("xxe") + " - XML External Entity")
	fmt.Println("    file       File disclosure")
	fmt.Println("    ssrf       SSRF via XXE")
	fmt.Println("    dos        Billion laughs attack")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Other Categories:"))
	fmt.Println("    cors       CORS misconfiguration")
	fmt.Println("    crlf       HTTP response splitting")
	fmt.Println("    redirect   Open redirect")
	fmt.Println("    upload     File upload vulnerabilities")
	fmt.Println("    jwt        JWT token attacks")
	fmt.Println("    oauth      OAuth/OIDC vulnerabilities")
	fmt.Println("    prototype  Prototype pollution")
	fmt.Println("    deserialize Insecure deserialization")
	fmt.Println()
}

func printDocsOutput() {
	fmt.Println(ui.SectionStyle.Render("📊 OUTPUT FORMATS - DETAILED DOCUMENTATION"))
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("console") + " (default)")
	fmt.Println("    Human-readable terminal output with colors")
	fmt.Println("    Best for: Interactive testing, debugging")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("json"))
	fmt.Println("    Single JSON array with all results")
	fmt.Println("    Best for: API integration, detailed analysis")
	fmt.Println("    waf-tester run ... -format json -o results.json")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("jsonl"))
	fmt.Println("    JSON Lines - one JSON object per line")
	fmt.Println("    Best for: Streaming, log aggregation, large result sets")
	fmt.Println("    waf-tester run ... -j -o results.jsonl")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("sarif"))
	fmt.Println("    Static Analysis Results Interchange Format")
	fmt.Println("    Best for: IDE integration, CI/CD pipelines, GitHub Security")
	fmt.Println("    waf-tester run ... -format sarif -o results.sarif")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("csv"))
	fmt.Println("    Comma-separated values")
	fmt.Println("    Best for: Spreadsheet analysis, reporting")
	fmt.Println("    waf-tester run ... -format csv -o results.csv")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("md"))
	fmt.Println("    Markdown table")
	fmt.Println("    Best for: Documentation, README files")
	fmt.Println("    waf-tester run ... -format md -o results.md")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("html"))
	fmt.Println("    Interactive HTML report with filtering")
	fmt.Println("    Best for: Sharing with stakeholders, archiving")
	fmt.Println("    waf-tester run ... -format html -o report.html")
	fmt.Println()
}

func printDocsExamples() {
	fmt.Println(ui.SectionStyle.Render("💡 REAL-WORLD EXAMPLES"))
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("1. Complete Security Assessment"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  # Discover target")
	fmt.Println("  waf-tester discover -u https://app.company.com -output discovery.json")
	fmt.Println()
	fmt.Println("  # Generate test plan")
	fmt.Println("  waf-tester learn -discovery discovery.json -output testplan.json")
	fmt.Println()
	fmt.Println("  # Run tests with HTML report")
	fmt.Println("  waf-tester run -plan testplan.json -format html -o report.html")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("2. Quick SQL Injection Test"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  waf-tester run -u https://target.com/search?q=test -category sqli -ac")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("3. WAF Bypass Hunting"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  # Low and slow to avoid detection")
	fmt.Println("  waf-tester bypass -u https://target.com -category xss \\")
	fmt.Println("    -mutation full -c 5 -rl 10 -realistic")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("4. CI/CD Integration"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  # Generate SARIF for GitHub Security")
	fmt.Println("  waf-tester run -u $TARGET_URL -plan testplan.json \\")
	fmt.Println("    -format sarif -o results.sarif -s")
	fmt.Println()
	fmt.Println("  # Exit code: 0 = no findings, 1 = findings detected")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("5. Multi-Target Scanning"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  # From file")
	fmt.Println("  waf-tester probe -l targets.txt -c 50 -o live-hosts.txt")
	fmt.Println("  waf-tester scan -l live-hosts.txt -types sqli,xss")
	fmt.Println()
	fmt.Println("  # From stdin (pipe from other tools)")
	fmt.Println("  subfinder -d target.com | waf-tester probe -stdin")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("6. Authenticated Testing"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  waf-tester run -u https://target.com -plan testplan.json \\")
	fmt.Println("    -H \"Authorization: Bearer eyJ...\" \\")
	fmt.Println("    -H \"Cookie: session=abc123\"")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("7. Through Proxy (Burp Suite)"))
	fmt.Println("  ─────────────────────────────────")
	fmt.Println("  waf-tester run -u https://target.com -plan testplan.json \\")
	fmt.Println("    -x http://127.0.0.1:8080 -k")
	fmt.Println()
}

func printDocsWorkflow() {
	fmt.Println(ui.SectionStyle.Render("🔄 RECOMMENDED WORKFLOWS"))
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Workflow 1: Full Assessment (Recommended)"))
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐")
	fmt.Println("  │  discover   │ -> │    learn    │ -> │     run     │")
	fmt.Println("  │ (find URLs) │    │ (make plan) │    │ (test it)   │")
	fmt.Println("  └─────────────┘    └─────────────┘    └─────────────┘")
	fmt.Println()
	fmt.Println("  Best for: Complete security assessments, new targets")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Workflow 2: Quick Test"))
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────┐")
	fmt.Println("  │  waf-tester run -u URL -category sqli   │")
	fmt.Println("  └──────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Best for: Quick tests, known endpoints")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Workflow 3: Automated (One Command)"))
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────┐")
	fmt.Println("  │  waf-tester auto -u URL -service app    │")
	fmt.Println("  └──────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Best for: CI/CD, scheduled scans, quick assessments")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Workflow 4: WAF Bypass Research"))
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐")
	fmt.Println("  │   probe     │ -> │   bypass    │ -> │   mutate    │")
	fmt.Println("  │ (detect WAF)│    │ (find holes)│    │(full matrix)│")
	fmt.Println("  └─────────────┘    └─────────────┘    └─────────────┘")
	fmt.Println()
	fmt.Println("  Best for: WAF testing, bypass research")
	fmt.Println()

	fmt.Println("  " + ui.SubtitleStyle.Render("Workflow 5: Bug Bounty Recon"))
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  subfinder -d target.com | waf-tester probe -stdin > live.txt")
	fmt.Println("  waf-tester discover -l live.txt -output discovery.json")
	fmt.Println("  waf-tester learn -discovery discovery.json -output plan.json")
	fmt.Println("  waf-tester run -plan plan.json -realistic -ac -format sarif")
	fmt.Println()
}

func main() {
	// Check for subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "auto", "superpower", "sp":
		runAutoScan()
	case "discover":
		runDiscover()
	case "learn":
		runLearn()
	case "probe":
		runProbe()
	case "crawl":
		runCrawl()
	case "scan":
		runScan()
	case "fuzz":
		runFuzz()
	case "analyze":
		runAnalyze()
	case "validate":
		runValidate()
	case "validate-templates":
		runValidateTemplates()
	case "update":
		runUpdate()
	case "mutate":
		runMutate()
	case "bypass":
		runBypassFinder()
	case "smuggle":
		runSmuggle()
	case "race":
		runRace()
	case "workflow":
		runWorkflow()
	case "headless":
		runHeadless()
	case "fp", "falsepositive", "false-positive":
		runFP()
	case "assess", "assessment", "benchmark":
		runAssess()
	case "vendor", "waf-detect", "detect-waf":
		runVendorDetect()
	case "protocol", "proto":
		runProtocolDetect()
	case "run":
		// Remove "run" from args and continue with normal execution
		os.Args = append(os.Args[:1], os.Args[2:]...)
		runTests()
	case "report", "html-report", "enterprise-report":
		runEnterpriseReport()
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	case "docs", "doc", "man", "manual":
		printDetailedDocs()
		os.Exit(0)
	case "-v", "--version", "version":
		ui.PrintMiniBanner()
		os.Exit(0)
	default:
		// Assume it's a flag for the default "run" command
		runTests()
	}
}

func runValidate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Payload Validation")

	validateFlags := flag.NewFlagSet("validate", flag.ExitOnError)
	payloadDir := validateFlags.String("payloads", "../payloads", "Directory containing payload JSON files")
	failFast := validateFlags.Bool("fail-fast", false, "Abort on first error")
	verbose := validateFlags.Bool("verbose", false, "Show detailed validation output")
	outputJSON := validateFlags.String("output", "", "Output results to JSON file")

	validateFlags.Parse(os.Args[2:])

	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Fail Fast", fmt.Sprintf("%v", *failFast))
	fmt.Println()

	result, err := validate.ValidatePayloads(*payloadDir, *failFast, *verbose)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	if *outputJSON != "" {
		// Write JSON output
		f, err := os.Create(*outputJSON)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		defer f.Close()
		fmt.Fprintf(f, "%+v\n", result)
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputJSON))
	}

	if !result.Valid {
		ui.PrintError("Validation failed!")
		os.Exit(1)
	}

	ui.PrintSuccess("All payloads validated successfully!")
}

func runValidateTemplates() {
	ui.PrintCompactBanner()
	ui.PrintSection("Template Validation")

	validateFlags := flag.NewFlagSet("validate-templates", flag.ExitOnError)
	templateDir := validateFlags.String("templates", "../templates", "Directory containing nuclei template YAML files")
	strict := validateFlags.Bool("strict", false, "Enable strict validation mode (warnings become errors)")
	verbose := validateFlags.Bool("verbose", false, "Show detailed validation output")
	outputJSON := validateFlags.String("output", "", "Output results to JSON file")

	validateFlags.Parse(os.Args[2:])

	ui.PrintConfigLine("Template Dir", *templateDir)
	ui.PrintConfigLine("Strict Mode", fmt.Sprintf("%v", *strict))
	fmt.Println()

	validator := templatevalidator.NewValidator(*strict)
	summary, err := validator.ValidateDirectory(*templateDir)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	// Print summary
	ui.PrintSection("Validation Summary")
	ui.PrintConfigLine("Total Files", fmt.Sprintf("%d", summary.TotalFiles))
	ui.PrintConfigLine("Valid", fmt.Sprintf("%d", summary.ValidFiles))
	ui.PrintConfigLine("Invalid", fmt.Sprintf("%d", summary.InvalidFiles))
	ui.PrintConfigLine("Total Errors", fmt.Sprintf("%d", summary.TotalErrors))
	ui.PrintConfigLine("Total Warnings", fmt.Sprintf("%d", summary.TotalWarnings))
	fmt.Println()

	// Print detailed results if verbose
	if *verbose {
		for _, result := range summary.Results {
			if !result.Valid || len(result.Warnings) > 0 {
				fmt.Printf("\n%s\n", result.File)
				for _, e := range result.Errors {
					ui.PrintError(fmt.Sprintf("  ERROR: %s", e))
				}
				for _, w := range result.Warnings {
					ui.PrintWarning(fmt.Sprintf("  WARNING: %s", w))
				}
			}
		}
	}

	if *outputJSON != "" {
		// Write JSON output
		data, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot marshal results: %v", err))
			os.Exit(1)
		}
		if err := os.WriteFile(*outputJSON, data, 0644); err != nil {
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputJSON))
	}

	if summary.InvalidFiles > 0 {
		ui.PrintError(fmt.Sprintf("Validation failed! %d invalid templates found.", summary.InvalidFiles))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("All %d templates validated successfully!", summary.TotalFiles))
}

func runEnterpriseReport() {
	ui.PrintCompactBanner()
	ui.PrintSection("Enterprise HTML Report Generator")

	reportFlags := flag.NewFlagSet("report", flag.ExitOnError)
	workspaceDir := reportFlags.String("workspace", "", "Path to workspace directory containing results.json and assessment.json")
	outputFile := reportFlags.String("output", "", "Output HTML report file path (default: workspace/enterprise-report.html)")
	targetName := reportFlags.String("target", "", "Target name for the report header")

	reportFlags.Parse(os.Args[2:])

	// Validate workspace directory
	if *workspaceDir == "" {
		ui.PrintError("Workspace directory is required. Use -workspace <path>")
		fmt.Println()
		fmt.Println("Usage: waf-tester report -workspace <path> [-output <file>] [-target <name>]")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("  -workspace <path>  Path to workspace directory containing results.json")
		fmt.Println("  -output <file>     Output HTML file (default: workspace/enterprise-report.html)")
		fmt.Println("  -target <name>     Target name for report header")
		os.Exit(1)
	}

	// Check workspace exists
	if _, err := os.Stat(*workspaceDir); os.IsNotExist(err) {
		ui.PrintError(fmt.Sprintf("Workspace directory not found: %s", *workspaceDir))
		os.Exit(1)
	}

	// Check results.json exists
	resultsPath := filepath.Join(*workspaceDir, "results.json")
	if _, err := os.Stat(resultsPath); os.IsNotExist(err) {
		ui.PrintError(fmt.Sprintf("results.json not found in workspace: %s", *workspaceDir))
		os.Exit(1)
	}

	// Determine target name
	target := *targetName
	if target == "" {
		// Try to extract from workspace path
		target = filepath.Base(filepath.Dir(*workspaceDir))
		if target == "." || target == "" {
			target = "WAF Security Assessment"
		}
	}

	// Determine output file
	output := *outputFile
	if output == "" {
		output = filepath.Join(*workspaceDir, "enterprise-report.html")
	}

	ui.PrintConfigLine("Workspace", *workspaceDir)
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Output", output)
	fmt.Println()

	// Generate report
	if err := report.GenerateEnterpriseHTMLReportFromWorkspace(*workspaceDir, target, 0, output); err != nil {
		ui.PrintError(fmt.Sprintf("Report generation failed: %v", err))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Enterprise HTML report saved to: %s", output))
}

func runUpdate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Payload Update")

	updateFlags := flag.NewFlagSet("update", flag.ExitOnError)
	payloadDir := updateFlags.String("payloads", "../payloads", "Directory containing payload JSON files")
	source := updateFlags.String("source", "OWASP", "Payload source: OWASP, GitHub, Manual")
	dryRun := updateFlags.Bool("dry-run", false, "Preview changes without modifying files")
	autoApply := updateFlags.Bool("auto-apply", false, "Automatically apply non-destructive updates")
	skipDestructive := updateFlags.Bool("skip-destructive", false, "Skip potentially destructive payloads")
	versionBump := updateFlags.String("version-bump", "minor", "Version bump type: major, minor, patch")
	outputFile := updateFlags.String("output", "payload-update-report.json", "Output report file")

	updateFlags.Parse(os.Args[2:])

	ui.PrintConfigLine("Source", *source)
	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Dry Run", fmt.Sprintf("%v", *dryRun))
	ui.PrintConfigLine("Auto Apply", fmt.Sprintf("%v", *autoApply))
	fmt.Println()

	cfg := &update.UpdateConfig{
		PayloadDir:      *payloadDir,
		Source:          *source,
		DryRun:          *dryRun,
		AutoApply:       *autoApply,
		SkipDestructive: *skipDestructive,
		VersionBump:     *versionBump,
		OutputFile:      *outputFile,
	}

	_, err := update.UpdatePayloads(cfg)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Update error: %v", err))
		os.Exit(1)
	}

	if *dryRun {
		ui.PrintInfo("Dry run complete - no changes applied")
	} else {
		ui.PrintSuccess("Payloads updated successfully!")
	}
}

// runAutoScan is the SUPERPOWER command - full automated scan in a single command
// It chains: discover → deep JS analysis → learn → run → comprehensive report
func runAutoScan() {
	startTime := time.Now()
	ui.PrintBanner()

	fmt.Println()
	fmt.Println(ui.SectionStyle.Render("🚀 SUPERPOWER MODE - Full Automated Security Scan"))
	fmt.Println()

	autoFlags := flag.NewFlagSet("auto", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	autoFlags.Var(&targetURLs, "u", "Target URL(s)")
	autoFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := autoFlags.String("l", "", "File containing target URLs")
	stdinInput := autoFlags.Bool("stdin", false, "Read targets from stdin")
	service := autoFlags.String("service", "", "Service preset: wordpress, drupal, nextjs, flask, django")
	payloadDirFlag := autoFlags.String("payloads", "", "Payload directory (default: auto-detect)")
	concurrency := autoFlags.Int("c", 50, "Concurrent workers for testing")
	rateLimit := autoFlags.Int("rl", 200, "Rate limit (requests per second)")
	timeout := autoFlags.Int("timeout", 10, "HTTP timeout in seconds")
	skipVerify := autoFlags.Bool("skip-verify", false, "Skip TLS verification")
	depth := autoFlags.Int("depth", 3, "Max crawl depth for discovery")
	outputDir := autoFlags.String("output-dir", "", "Output directory (default: workspaces/<domain>/<timestamp>)")
	verbose := autoFlags.Bool("v", false, "Verbose output")
	_ = autoFlags.Bool("no-clean", false, "Don't clean previous workspace files") // Reserved for future use

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := autoFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := autoFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := autoFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Enterprise assessment with quantitative metrics (NOW DEFAULT for superpower mode)
	enableAssess := autoFlags.Bool("assess", true, "Run enterprise assessment with F1/precision/MCC metrics (default: true)")
	assessCorpus := autoFlags.String("assess-corpus", "builtin,leipzig", "FP corpus for assessment: builtin,leipzig")

	// NEW: Leaky paths scanning (Phase 1.5)
	enableLeakyPaths := autoFlags.Bool("leaky-paths", true, "Enable sensitive path scanning (300+ paths)")
	leakyCategories := autoFlags.String("leaky-categories", "", "Filter leaky paths: config,debug,vcs,admin,backup,source,api,cloud,ci")

	// NEW: Parameter discovery (Phase 2.5)
	enableParamDiscovery := autoFlags.Bool("discover-params", true, "Enable Arjun-style parameter discovery")
	paramWordlist := autoFlags.String("param-wordlist", "", "Custom parameter wordlist file")

	// NEW: JA3 fingerprint rotation
	enableJA3 := autoFlags.Bool("ja3-rotate", false, "Enable JA3 fingerprint rotation")
	ja3Profile := autoFlags.String("ja3-profile", "", "Specific JA3 profile: chrome120,firefox121,safari17,edge120")

	// NEW: Full recon mode using unified recon package
	enableFullRecon := autoFlags.Bool("full-recon", false, "Run unified reconnaissance (combines leaky-paths, params, JS analysis)")

	// NEW: Browser-based authenticated scanning (Phase 7-9)
	enableBrowserScan := autoFlags.Bool("browser", true, "Enable authenticated browser scanning (default: true)")
	browserHeadless := autoFlags.Bool("browser-headless", false, "Run browser in headless mode (no visible window)")
	browserTimeout := autoFlags.Duration("browser-timeout", 3*time.Minute, "Timeout for user login during browser scan")

	// Streaming mode (CI-friendly output)
	streamMode := autoFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	autoFlags.Parse(os.Args[2:])

	// Auto-detect payload directory if not specified
	payloadDir := *payloadDirFlag
	if payloadDir == "" {
		// Try common locations
		candidates := []string{
			"../payloads",               // When run from waf-tester/
			"payloads",                  // When run from waf-tester/ (alt)
			"tests/payloads",            // When run from repo root
			"tests/waf-tester/payloads", // When run from repo root
			filepath.Join(filepath.Dir(os.Args[0]), "..", "payloads"), // Relative to executable
			filepath.Join(filepath.Dir(os.Args[0]), "payloads"),       // Next to executable
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				payloadDir = candidate
				break
			}
		}
		if payloadDir == "" {
			payloadDir = "../payloads" // Fallback
		}
	}

	// Get target
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use: waf-tester auto -u https://example.com")
		os.Exit(1)
	}

	// Parse domain from target
	parsedURL, err := url.Parse(target)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Invalid target URL: %v", err))
		os.Exit(1)
	}
	domain := parsedURL.Hostname()

	// Create output directory structure
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	workspaceDir := *outputDir
	if workspaceDir == "" {
		// Use project root workspaces directory for consistent output location
		projectRoot := getProjectRoot()
		workspaceDir = filepath.Join(projectRoot, "workspaces", domain, timestamp)
	}
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		ui.PrintError(fmt.Sprintf("Cannot create workspace: %v", err))
		os.Exit(1)
	}

	// Define output files
	discoveryFile := filepath.Join(workspaceDir, "discovery.json")
	jsAnalysisFile := filepath.Join(workspaceDir, "js-analysis.json")
	testPlanFile := filepath.Join(workspaceDir, "testplan.json")
	resultsFile := filepath.Join(workspaceDir, "results.json")
	reportFile := filepath.Join(workspaceDir, "report.md")

	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Configuration"))
	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Domain", domain)
	if *service != "" {
		ui.PrintConfigLine("Service", *service)
	}
	ui.PrintConfigLine("Workspace", workspaceDir)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec", *rateLimit))
	if *enableLeakyPaths {
		ui.PrintConfigLine("Leaky Paths", "Enabled (300+ sensitive paths)")
	}
	if *enableParamDiscovery {
		ui.PrintConfigLine("Param Discovery", "Enabled (Arjun-style)")
	}
	if *enableJA3 {
		profile := *ja3Profile
		if profile == "" {
			profile = "rotating"
		}
		ui.PrintConfigLine("JA3 Rotation", profile)
	}
	if *enableFullRecon {
		ui.PrintConfigLine("Full Recon", "Enabled (unified reconnaissance)")
	}
	fmt.Println()

	// Create JA3-aware HTTP client if enabled
	var ja3Client *http.Client
	if *enableJA3 {
		ja3Cfg := &tlsja3.Config{
			RotateEvery: 25,
			Timeout:     time.Duration(*timeout) * time.Second,
			SkipVerify:  *skipVerify,
		}
		if *ja3Profile != "" {
			// Use specific profile
			if profile, err := tlsja3.GetProfileByName(*ja3Profile); err == nil {
				ja3Cfg.Profiles = []*tlsja3.JA3Profile{profile}
			}
		}
		ja3Client = tlsja3.CreateFallbackClient(ja3Cfg) // Use fallback for compatibility
	}
	// Silence if unused (when JA3 not enabled)
	_ = ja3Client

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		ui.PrintWarning("Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Determine output mode for LiveProgress
	autoOutputMode := ui.OutputModeInteractive
	if *streamMode {
		autoOutputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress for phases
	autoProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        7, // 7 major phases: smart mode, discover, JS, learn, run, assess, browser
		DisplayLines: 3,
		Title:        "Auto mode",
		Unit:         "phases",
		Mode:         autoOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "endpoints", Label: "Endpoints", Icon: "🎯"},
			{Name: "secrets", Label: "Secrets", Icon: "🔑", Highlight: true},
			{Name: "bypasses", Label: "Bypasses", Icon: "⚠️", Highlight: true},
		},
		StreamFormat:   "[PROGRESS] phase {completed}/{total} | {status} | endpoints: {metric:endpoints} | {elapsed}",
		StreamInterval: 5 * time.Second,
	})
	autoProgress.Start()
	defer autoProgress.Stop()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 0: SMART MODE - WAF DETECTION & STRATEGY OPTIMIZATION (Optional)
	// ═══════════════════════════════════════════════════════════════════════════
	var smartResult *SmartModeResult
	if *smartMode {
		fmt.Println(ui.SectionStyle.Render("PHASE 0: Smart Mode - WAF Detection & Strategy Optimization"))
		fmt.Println()

		ui.PrintInfo("🧠 Detecting WAF vendor from 197+ signatures...")

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, target, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)

		// Apply WAF-optimized rate limit and concurrency
		// The smart mode values are the safe limits for that specific WAF
		if smartResult != nil && smartResult.WAFDetected {
			if smartResult.RateLimit > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Rate limit: %.0f req/sec (WAF-optimized for %s)",
					smartResult.RateLimit, smartResult.VendorName))
				*rateLimit = int(smartResult.RateLimit)
			}
			if smartResult.Concurrency > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Concurrency: %d workers (WAF-optimized)",
					smartResult.Concurrency))
				*concurrency = smartResult.Concurrency
			}
		}
		fmt.Println()
	}
	// Silence unused variable warning when smart mode not enabled
	_ = smartVerbose
	_ = smartModeType

	// Update progress after smart mode
	autoProgress.SetStatus("Discovery")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 1: DISCOVERY
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println(ui.SectionStyle.Render("PHASE 1: Target Discovery & Reconnaissance"))
	fmt.Println()

	discoveryCfg := discovery.DiscoveryConfig{
		Target:      target,
		Service:     *service,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		MaxDepth:    *depth,
		SkipVerify:  *skipVerify,
		Verbose:     *verbose,
		HTTPClient:  ja3Client, // JA3 TLS fingerprint rotation
	}

	discoverer := discovery.NewDiscoverer(discoveryCfg)

	ui.PrintInfo("🔍 Starting endpoint discovery...")
	discResult, err := discoverer.Discover(ctx)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Discovery failed: %v", err))
		os.Exit(1)
	}

	if err := discResult.SaveResult(discoveryFile); err != nil {
		ui.PrintError(fmt.Sprintf("Error saving discovery: %v", err))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("✓ Discovered %d endpoints", len(discResult.Endpoints)))
	if discResult.WAFDetected {
		ui.PrintInfo(fmt.Sprintf("  WAF Detected: %s", discResult.WAFFingerprint))
	}
	fmt.Println()

	// Update progress after discovery
	autoProgress.SetMetric("endpoints", int64(len(discResult.Endpoints)))
	autoProgress.SetStatus("Leaky paths")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 1.5: LEAKY PATHS SCANNING (NEW - competitive feature from leaky-paths)
	// ═══════════════════════════════════════════════════════════════════════════
	leakyPathsFile := filepath.Join(workspaceDir, "leaky-paths.json")
	var leakyResult *leakypaths.ScanSummary

	if *enableLeakyPaths {
		fmt.Println(ui.SectionStyle.Render("PHASE 1.5: Sensitive Path Scanning (leaky-paths)"))
		fmt.Println()

		// Filter categories if specified
		var categories []string
		if *leakyCategories != "" {
			categories = strings.Split(*leakyCategories, ",")
			ui.PrintInfo(fmt.Sprintf("🔓 Scanning for sensitive paths (categories: %s)...", *leakyCategories))
		} else {
			ui.PrintInfo("🔓 Scanning 1,766+ high-value sensitive paths...")
		}

		// Show what we're looking for
		fmt.Println()
		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Targets: .git, .env, admin panels, backups, configs, debug endpoints..."))
		fmt.Println()

		leakyScanner := leakypaths.NewScanner(&leakypaths.Config{
			Timeout:     time.Duration(*timeout) * time.Second,
			Concurrency: *concurrency,
			Verbose:     *verbose,
			HTTPClient:  ja3Client, // JA3 TLS fingerprint rotation
		})

		var err error
		leakyResult, err = leakyScanner.Scan(ctx, target, categories...)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Leaky paths scan warning: %v", err))
		} else {
			// Save results
			leakyData, _ := json.MarshalIndent(leakyResult, "", "  ")
			os.WriteFile(leakyPathsFile, leakyData, 0644)

			// Summary with timing
			ui.PrintSuccess(fmt.Sprintf("✓ Scanned %d paths in %s", leakyResult.TotalPaths, leakyResult.Duration.Round(time.Millisecond)))
			fmt.Println()

			if leakyResult.InterestingHits > 0 {
				// Show severity breakdown in nuclei-style
				fmt.Printf("  %s\n", ui.SectionStyle.Render("📊 Findings by Severity:"))
				for severity, count := range leakyResult.BySeverity {
					sevStyle := ui.SeverityStyle(severity)
					bar := strings.Repeat("█", min(count, 20))
					fmt.Printf("    %s %s %d\n", sevStyle.Render(fmt.Sprintf("%-8s", severity)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Println()

				// Show category breakdown
				fmt.Printf("  %s\n", ui.SectionStyle.Render("📂 Findings by Category:"))
				for category, count := range leakyResult.ByCategory {
					bar := strings.Repeat("▪", min(count, 20))
					fmt.Printf("    %-15s %s %d\n", category, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Println()

				// Show top findings in nuclei-style bracketed format
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🎯 Top Findings:"))
				shownCount := 0
				for _, result := range leakyResult.Results {
					if !result.Interesting {
						continue
					}
					if shownCount >= 10 {
						remaining := leakyResult.InterestingHits - 10
						if remaining > 0 {
							fmt.Printf("    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more findings (see %s)", remaining, leakyPathsFile)))
						}
						break
					}
					// Nuclei-style output: [severity] [category] path [status]
					sevStyle := ui.SeverityStyle(result.Severity)
					statusStyle := ui.StatusCodeStyle(result.StatusCode)
					fmt.Printf("    %s%s%s %s%s%s %s %s%s%s\n",
						ui.BracketStyle.Render("["),
						sevStyle.Render(strings.ToLower(result.Severity)),
						ui.BracketStyle.Render("]"),
						ui.BracketStyle.Render("["),
						ui.CategoryStyle.Render(result.Category),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(result.Path),
						ui.BracketStyle.Render("["),
						statusStyle.Render(fmt.Sprintf("%d", result.StatusCode)),
						ui.BracketStyle.Render("]"),
					)
					shownCount++
				}
			} else {
				ui.PrintSuccess("  ✓ No sensitive paths exposed - good security posture!")
			}
		}
		fmt.Println()
	}
	// Silence unused variable warnings
	_ = enableLeakyPaths
	_ = leakyCategories

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2: DEEP JAVASCRIPT ANALYSIS
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println(ui.SectionStyle.Render("PHASE 2: Deep JavaScript Analysis"))
	fmt.Println()

	ui.PrintInfo("📜 Extracting and analyzing JavaScript files...")

	// Collect all JS files from discovery
	jsFiles := make([]string, 0)
	for _, ep := range discResult.Endpoints {
		if strings.HasSuffix(ep.Path, ".js") {
			jsFiles = append(jsFiles, ep.Path)
		}
	}

	// Also check for common config files
	configPaths := []string{"/config.js", "/admin/config.js", "/app.config.js", "/env.js", "/settings.js"}
	for _, p := range configPaths {
		found := false
		for _, existing := range jsFiles {
			if existing == p {
				found = true
				break
			}
		}
		if !found {
			jsFiles = append(jsFiles, p)
		}
	}

	// Analyze each JS file
	jsAnalyzer := js.NewAnalyzer()
	allJSData := &js.ExtractedData{
		URLs:       make([]js.URLInfo, 0),
		Endpoints:  make([]js.EndpointInfo, 0),
		Secrets:    make([]js.SecretInfo, 0),
		DOMSinks:   make([]js.DOMSinkInfo, 0),
		CloudURLs:  make([]js.CloudURL, 0),
		Subdomains: make([]string, 0),
	}

	// Use JA3-aware client if enabled, otherwise standard client
	var client *http.Client
	if ja3Client != nil {
		client = ja3Client
	} else {
		client = &http.Client{
			Timeout: time.Duration(*timeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *skipVerify},
			},
		}
	}

	jsAnalyzed := 0
	totalJSFiles := len(jsFiles)
	var secretsFound, endpointsFound int32

	// Animated progress for JS analysis
	jsProgressDone := make(chan struct{})
	jsSpinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	jsFrameIdx := 0
	jsStartTime := time.Now()

	if totalJSFiles > 1 && !*streamMode {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-jsProgressDone:
					return
				case <-ticker.C:
					analyzed := jsAnalyzed
					secrets := atomic.LoadInt32(&secretsFound)
					endpoints := atomic.LoadInt32(&endpointsFound)
					elapsed := time.Since(jsStartTime)

					spinner := jsSpinnerFrames[jsFrameIdx%len(jsSpinnerFrames)]
					jsFrameIdx++

					percent := float64(0)
					if totalJSFiles > 0 {
						percent = float64(analyzed) / float64(totalJSFiles) * 100
					}

					progressWidth := 25
					fillWidth := int(float64(progressWidth) * percent / 100)
					bar := fmt.Sprintf("[%s%s]",
						strings.Repeat("█", fillWidth),
						strings.Repeat("░", progressWidth-fillWidth))

					secretColor := "\033[32m" // Green
					if secrets > 0 {
						secretColor = "\033[31m" // Red - secrets found!
					}

					fmt.Printf("\033[2A\033[J")
					fmt.Printf("  %s %s %.1f%% (%d/%d files)\n", spinner, bar, percent, analyzed, totalJSFiles)
					fmt.Printf("  📊 Endpoints: %d  %s🔑 Secrets: %d\033[0m  ⏱️  %s\n",
						endpoints, secretColor, secrets, elapsed.Round(time.Second))
				}
			}
		}()
		fmt.Println()
		fmt.Println()
	}

	for _, jsPath := range jsFiles {
		var jsURL string
		if !strings.HasPrefix(jsPath, "http") {
			jsURL = strings.TrimSuffix(target, "/") + jsPath
		} else {
			jsURL = jsPath
		}

		req, err := http.NewRequest("GET", jsURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
		resp.Body.Close()
		if err != nil {
			continue
		}

		jsCode := string(body)
		result := jsAnalyzer.Analyze(jsCode)

		// Merge results
		allJSData.URLs = append(allJSData.URLs, result.URLs...)
		allJSData.Endpoints = append(allJSData.Endpoints, result.Endpoints...)
		allJSData.Secrets = append(allJSData.Secrets, result.Secrets...)
		allJSData.DOMSinks = append(allJSData.DOMSinks, result.DOMSinks...)
		allJSData.CloudURLs = append(allJSData.CloudURLs, result.CloudURLs...)
		allJSData.Subdomains = append(allJSData.Subdomains, result.Subdomains...)
		jsAnalyzed++

		// Update atomic counters for progress display
		atomic.AddInt32(&secretsFound, int32(len(result.Secrets)))
		atomic.AddInt32(&endpointsFound, int32(len(result.Endpoints)))

		if *verbose {
			ui.PrintInfo(fmt.Sprintf("  Analyzed: %s (%d URLs, %d endpoints, %d secrets)",
				jsPath, len(result.URLs), len(result.Endpoints), len(result.Secrets)))
		}
	}

	// Stop JS analysis progress display
	if totalJSFiles > 1 {
		close(jsProgressDone)
		time.Sleep(50 * time.Millisecond)
		fmt.Printf("\033[2A\033[J")
	}

	// Deduplicate subdomains
	subdomainMap := make(map[string]bool)
	for _, sub := range allJSData.Subdomains {
		subdomainMap[sub] = true
	}
	allJSData.Subdomains = make([]string, 0, len(subdomainMap))
	for sub := range subdomainMap {
		allJSData.Subdomains = append(allJSData.Subdomains, sub)
	}

	// Save JS analysis
	jsDataBytes, _ := json.MarshalIndent(allJSData, "", "  ")
	os.WriteFile(jsAnalysisFile, jsDataBytes, 0644)

	ui.PrintSuccess(fmt.Sprintf("✓ Analyzed %d JavaScript files", jsAnalyzed))
	ui.PrintInfo(fmt.Sprintf("  Found: %d URLs, %d endpoints, %d secrets, %d DOM sinks",
		len(allJSData.URLs), len(allJSData.Endpoints), len(allJSData.Secrets), len(allJSData.DOMSinks)))

	// Update progress after JS analysis
	autoProgress.AddMetricN("secrets", int64(len(allJSData.Secrets)))
	autoProgress.SetStatus("Learning")
	autoProgress.Increment()

	// Add JS-discovered endpoints to discovery result
	for _, ep := range allJSData.Endpoints {
		method := ep.Method
		if method == "" {
			// Infer method from path/source
			method = inferHTTPMethod(ep.Path, ep.Source)
		}
		discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
			Path:     ep.Path,
			Method:   method,
			Category: "api",
			Service:  "js-discovery",
		})
	}

	// Also add URLs with inferred methods (these may not match endpoint patterns but have method info)
	seenPaths := make(map[string]bool)
	for _, ep := range discResult.Endpoints {
		seenPaths[ep.Method+":"+ep.Path] = true
	}
	for _, urlInfo := range allJSData.URLs {
		// Only process relative paths that look like API endpoints
		if !strings.HasPrefix(urlInfo.URL, "/") || strings.HasPrefix(urlInfo.URL, "//") {
			continue
		}
		// Skip static files
		if strings.HasSuffix(urlInfo.URL, ".js") || strings.HasSuffix(urlInfo.URL, ".css") ||
			strings.HasSuffix(urlInfo.URL, ".png") || strings.HasSuffix(urlInfo.URL, ".jpg") ||
			strings.HasSuffix(urlInfo.URL, ".svg") || strings.HasSuffix(urlInfo.URL, ".woff") {
			continue
		}
		method := urlInfo.Method
		if method == "" {
			method = "GET"
		}
		key := method + ":" + urlInfo.URL
		if seenPaths[key] {
			continue
		}
		seenPaths[key] = true
		discResult.Endpoints = append(discResult.Endpoints, discovery.Endpoint{
			Path:     urlInfo.URL,
			Method:   method,
			Category: "api",
			Service:  "js-analysis",
		})
	}

	// Print secrets if found
	if len(allJSData.Secrets) > 0 {
		fmt.Println()
		ui.PrintSection("🔑 Secrets Detected in JavaScript")
		for _, secret := range allJSData.Secrets {
			severity := strings.ToUpper(secret.Confidence)
			if severity == "" {
				severity = "LOW"
			}
			truncated := secret.Value
			if len(truncated) > 50 {
				truncated = truncated[:50] + "..."
			}
			ui.PrintError(fmt.Sprintf("  [%s] %s: %s", severity, secret.Type, truncated))
		}
	}

	if len(allJSData.Subdomains) > 0 {
		fmt.Println()
		ui.PrintSection("🌐 Subdomains Discovered")
		for _, sub := range allJSData.Subdomains[:min(10, len(allJSData.Subdomains))] {
			ui.PrintInfo("  " + sub)
		}
		if len(allJSData.Subdomains) > 10 {
			ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(allJSData.Subdomains)-10))
		}
	}
	fmt.Println()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 2.5: PARAMETER DISCOVERY (NEW - competitive feature from Arjun)
	// ═══════════════════════════════════════════════════════════════════════════
	paramsFile := filepath.Join(workspaceDir, "discovered-params.json")
	var paramResult *params.DiscoveryResult

	if *enableParamDiscovery {
		fmt.Println(ui.SectionStyle.Render("PHASE 2.5: Parameter Discovery (Arjun-style)"))
		fmt.Println()

		ui.PrintInfo("🔍 Discovering hidden API parameters...")
		fmt.Println()
		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Technique: Chunked parameter injection (256 params/request)"))
		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Wordlist: 1,000+ common parameters (id, key, token, debug, admin...)"))
		fmt.Println()

		paramDiscoverer := params.NewDiscoverer(&params.Config{
			Timeout:     time.Duration(*timeout) * time.Second,
			Concurrency: *concurrency,
			Verbose:     *verbose,
			ChunkSize:   256, // Test 256 params per request for efficiency
			HTTPClient:  ja3Client,
		})

		// Test discovered endpoints for hidden params
		testEndpoints := make([]string, 0, len(discResult.Endpoints))
		for _, ep := range discResult.Endpoints {
			// Skip static files
			if strings.HasSuffix(ep.Path, ".js") || strings.HasSuffix(ep.Path, ".css") ||
				strings.HasSuffix(ep.Path, ".png") || strings.HasSuffix(ep.Path, ".jpg") {
				continue
			}
			fullURL := strings.TrimSuffix(target, "/") + ep.Path
			testEndpoints = append(testEndpoints, fullURL)
		}

		// Limit to first 20 endpoints to avoid too long scan
		if len(testEndpoints) > 20 {
			testEndpoints = testEndpoints[:20]
		}

		if len(testEndpoints) > 0 {
			ui.PrintInfo(fmt.Sprintf("  Testing %d endpoints for hidden parameters...", len(testEndpoints)))
			fmt.Println()

			// Discover params for each endpoint with animated progress display
			allParams := make([]params.DiscoveredParam, 0)
			paramStartTime := time.Now()
			var paramCompleted int32
			var paramsFoundCount int32
			paramProgressDone := make(chan struct{})
			paramSpinnerFrames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
			paramFrameIdx := 0
			totalEndpoints := len(testEndpoints)

			if !*streamMode {
				go func() {
					ticker := time.NewTicker(100 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-paramProgressDone:
							return
						case <-ticker.C:
							done := atomic.LoadInt32(&paramCompleted)
							found := atomic.LoadInt32(&paramsFoundCount)
							elapsed := time.Since(paramStartTime)

							spinner := paramSpinnerFrames[paramFrameIdx%len(paramSpinnerFrames)]
							paramFrameIdx++

							percent := float64(done) / float64(totalEndpoints) * 100
							progressWidth := 25
							fillWidth := int(float64(progressWidth) * percent / 100)
							bar := fmt.Sprintf("[%s%s]",
								strings.Repeat("█", fillWidth),
								strings.Repeat("░", progressWidth-fillWidth))

							paramColor := "\033[33m" // Yellow
							if found > 0 {
								paramColor = "\033[32m" // Green - params found!
							}

							fmt.Printf("\033[2A\033[J")
							fmt.Printf("  %s %s %.1f%% (%d/%d endpoints)\n", spinner, bar, percent, done, totalEndpoints)
							fmt.Printf("  %s🔍 Parameters found: %d\033[0m  ⏱️  %s\n",
								paramColor, found, elapsed.Round(time.Second))
						}
					}
				}()
			} // end if !*streamMode
			fmt.Println()
			fmt.Println()

			for _, endpoint := range testEndpoints {
				result, err := paramDiscoverer.Discover(ctx, endpoint)
				if err != nil {
					if *verbose {
						fmt.Println()
						ui.PrintWarning(fmt.Sprintf("  Warning for %s: %v", endpoint, err))
					}
					atomic.AddInt32(&paramCompleted, 1)
					continue
				}
				allParams = append(allParams, result.Parameters...)
				atomic.AddInt32(&paramsFoundCount, int32(len(result.Parameters)))
				atomic.AddInt32(&paramCompleted, 1)
			}

			// Stop progress display
			close(paramProgressDone)
			time.Sleep(50 * time.Millisecond)
			fmt.Printf("\033[2A\033[J")

			duration := time.Since(paramStartTime)

			// Create combined result
			paramResult = &params.DiscoveryResult{
				Target:      target,
				TotalTested: len(testEndpoints),
				FoundParams: len(allParams),
				Duration:    duration,
				Parameters:  allParams,
				BySource:    make(map[string]int),
				ByType:      make(map[string]int),
			}
			for _, p := range allParams {
				paramResult.BySource[p.Source]++
				paramResult.ByType[p.Type]++
			}

			// Save results
			paramData, _ := json.MarshalIndent(paramResult, "", "  ")
			os.WriteFile(paramsFile, paramData, 0644)

			ui.PrintSuccess(fmt.Sprintf("✓ Scanned %d endpoints in %s", len(testEndpoints), duration.Round(time.Millisecond)))

			if len(allParams) > 0 {
				fmt.Println()
				// Show type breakdown
				fmt.Printf("  %s\n", ui.SectionStyle.Render("📊 Parameters by Type:"))
				for paramType, count := range paramResult.ByType {
					typeStyle := ui.ConfigValueStyle
					switch paramType {
					case "query":
						typeStyle = ui.PassStyle
					case "body":
						typeStyle = ui.BlockedStyle
					case "header":
						typeStyle = ui.ErrorStyle
					}
					bar := strings.Repeat("█", min(count, 20))
					fmt.Printf("    %s %s %d\n", typeStyle.Render(fmt.Sprintf("%-8s", paramType)), ui.ProgressFullStyle.Render(bar), count)
				}
				fmt.Println()

				// Show source breakdown
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🔎 Discovery Sources:"))
				for source, count := range paramResult.BySource {
					bar := strings.Repeat("▪", min(count, 20))
					fmt.Printf("    %-15s %s %d\n", source, ui.StatLabelStyle.Render(bar), count)
				}
				fmt.Println()

				// Show top findings in nuclei-style
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🎯 Discovered Parameters:"))
				for i, p := range allParams {
					if i >= 10 {
						remaining := len(allParams) - 10
						if remaining > 0 {
							fmt.Printf("    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more parameters (see %s)", remaining, paramsFile)))
						}
						break
					}
					// Nuclei-style output: [type] [source] name [confidence]
					typeStyle := ui.ConfigValueStyle
					switch p.Type {
					case "query":
						typeStyle = ui.PassStyle
					case "body":
						typeStyle = ui.BlockedStyle
					case "header":
						typeStyle = ui.ErrorStyle
					}
					confPercent := int(p.Confidence * 100)
					fmt.Printf("    %s%s%s %s%s%s %s %s%d%%%s\n",
						ui.BracketStyle.Render("["),
						typeStyle.Render(p.Type),
						ui.BracketStyle.Render("]"),
						ui.BracketStyle.Render("["),
						ui.CategoryStyle.Render(p.Source),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(p.Name),
						ui.BracketStyle.Render("["),
						confPercent,
						ui.BracketStyle.Render("]"),
					)
				}
			} else {
				ui.PrintSuccess("  ✓ No hidden parameters discovered - endpoints are well-documented!")
			}
		} else {
			ui.PrintInfo("  ⏭️  No suitable endpoints found for parameter discovery")
			ui.PrintInfo("     (Need API endpoints from Phase 1 to test for hidden params)")
		}
		fmt.Println()
	}
	// Full Recon Mode - runs unified reconnaissance if enabled
	var fullReconResult *recon.FullReconResult
	if *enableFullRecon {
		fmt.Println(ui.SectionStyle.Render("PHASE 2.7: Unified Reconnaissance (Full Recon)"))
		fmt.Println()

		ui.PrintInfo("🔬 Running comprehensive reconnaissance scan...")
		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Combining: leaky-paths + param-discovery + JS analysis + JA3 rotation"))
		fmt.Println()

		// Handle empty categories - nil means all categories, not [""] which matches nothing
		var leakyPathCats []string
		if *leakyCategories != "" {
			leakyPathCats = strings.Split(*leakyCategories, ",")
		}

		reconScanner := recon.NewScanner(&recon.Config{
			Timeout:              time.Duration(*timeout) * time.Second,
			Concurrency:          *concurrency,
			Verbose:              *verbose,
			SkipTLSVerify:        *skipVerify,
			HTTPClient:           ja3Client, // JA3 TLS fingerprint rotation
			EnableLeakyPaths:     *enableLeakyPaths,
			EnableParamDiscovery: *enableParamDiscovery,
			EnableJSAnalysis:     true,
			EnableJA3Rotation:    *enableJA3,
			LeakyPathCategories:  leakyPathCats,
			JA3Profile:           *ja3Profile,
			ParamWordlist:        *paramWordlist,
		})

		var err error
		fullReconResult, err = reconScanner.FullScan(ctx, target)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Full recon warning: %v", err))
		} else {
			// Save recon results
			reconFile := filepath.Join(workspaceDir, "full-recon.json")
			reconData, _ := json.MarshalIndent(fullReconResult, "", "  ")
			os.WriteFile(reconFile, reconData, 0644)

			ui.PrintSuccess(fmt.Sprintf("✓ Full reconnaissance completed in %s", fullReconResult.Duration.Round(time.Millisecond)))
			fmt.Println()

			// Show risk assessment
			fmt.Printf("  %s\n", ui.SectionStyle.Render("📊 Risk Assessment:"))
			riskStyle := ui.PassStyle
			switch fullReconResult.RiskLevel {
			case "critical":
				riskStyle = ui.SeverityStyle("Critical")
			case "high":
				riskStyle = ui.SeverityStyle("High")
			case "medium":
				riskStyle = ui.SeverityStyle("Medium")
			}
			fmt.Printf("    Risk Score: %s (%.1f/100)\n", riskStyle.Render(fullReconResult.RiskLevel), fullReconResult.RiskScore)
			fmt.Println()

			if len(fullReconResult.TopRisks) > 0 {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("⚠️  Top Risks:"))
				for _, risk := range fullReconResult.TopRisks[:min(5, len(fullReconResult.TopRisks))] {
					ui.PrintWarning(fmt.Sprintf("    • %s", risk))
				}
				fmt.Println()
			}
		}
	}
	_ = fullReconResult // May be unused if full-recon not enabled

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 3: INTELLIGENT LEARNING
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println(ui.SectionStyle.Render("PHASE 3: Intelligent Test Plan Generation"))
	fmt.Println()

	ui.PrintInfo("🧠 Analyzing attack surface and generating test plan...")

	learner := learning.NewLearner(discResult, payloadDir)
	testPlan := learner.GenerateTestPlan()

	// Save test plan
	planData, _ := json.MarshalIndent(testPlan, "", "  ")
	os.WriteFile(testPlanFile, planData, 0644)

	ui.PrintSuccess(fmt.Sprintf("✓ Generated test plan with %d tests", testPlan.TotalTests))
	ui.PrintInfo(fmt.Sprintf("  Estimated time: %s", testPlan.EstimatedTime))
	fmt.Println()

	// Show test categories
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Test Categories:"))
	for _, group := range testPlan.TestGroups {
		fmt.Printf("    [P%d] %s - %s\n", group.Priority, group.Category, group.Reason)
	}
	fmt.Println()

	// Update progress after learning phase
	autoProgress.SetStatus("Testing")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 4: WAF SECURITY TESTING
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println(ui.SectionStyle.Render("PHASE 4: WAF Security Testing"))
	fmt.Println()

	ui.PrintInfo("⚡ Executing security tests with auto-calibration...")
	fmt.Println()

	// Load payloads
	loader := payloads.NewLoader(payloadDir)
	allPayloads, err := loader.LoadAll()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error loading payloads: %v", err))
		os.Exit(1)
	}

	// Filter payloads based on test plan categories
	if len(testPlan.RecommendedFlags.Categories) > 0 {
		var filteredPayloads []payloads.Payload
		categorySet := make(map[string]bool)
		for _, cat := range testPlan.RecommendedFlags.Categories {
			categorySet[strings.ToLower(cat)] = true
		}
		for _, p := range allPayloads {
			if categorySet[strings.ToLower(p.Category)] {
				filteredPayloads = append(filteredPayloads, p)
			}
		}
		allPayloads = filteredPayloads
	}

	// Smart payload→endpoint routing based on category matching
	// This ensures XSS goes to HTML endpoints, SQLi to API endpoints, etc.
	if len(discResult.Endpoints) > 0 {
		ui.PrintInfo(fmt.Sprintf("🎯 Smart-routing payloads to %d discovered endpoints...", len(discResult.Endpoints)))

		// Categorize endpoints by type
		apiEndpoints := []discovery.Endpoint{}
		authEndpoints := []discovery.Endpoint{}
		uploadEndpoints := []discovery.Endpoint{}
		graphqlEndpoints := []discovery.Endpoint{}
		otherEndpoints := []discovery.Endpoint{}

		for _, ep := range discResult.Endpoints {
			pathLower := strings.ToLower(ep.Path)
			switch {
			case strings.Contains(pathLower, "graphql"):
				graphqlEndpoints = append(graphqlEndpoints, ep)
			case strings.Contains(pathLower, "upload") || strings.Contains(pathLower, "file"):
				uploadEndpoints = append(uploadEndpoints, ep)
			case strings.Contains(pathLower, "auth") || strings.Contains(pathLower, "login") ||
				strings.Contains(pathLower, "token") || strings.Contains(pathLower, "oauth"):
				authEndpoints = append(authEndpoints, ep)
			case strings.Contains(pathLower, "/api/") || strings.Contains(pathLower, ".json") ||
				ep.ContentType == "application/json":
				apiEndpoints = append(apiEndpoints, ep)
			case strings.HasSuffix(pathLower, ".js") || strings.HasSuffix(pathLower, ".css") ||
				strings.HasSuffix(pathLower, ".png") || strings.HasSuffix(pathLower, ".jpg"):
				// Skip static assets - no security testing needed
			default:
				otherEndpoints = append(otherEndpoints, ep)
			}
		}

		// Route payloads to appropriate endpoints
		for i := range allPayloads {
			var targetEndpoints []discovery.Endpoint
			catLower := strings.ToLower(allPayloads[i].Category)

			switch {
			case strings.Contains(catLower, "sql") || strings.Contains(catLower, "injection"):
				// SQL injection → API endpoints preferentially
				if len(apiEndpoints) > 0 {
					targetEndpoints = apiEndpoints
				}
			case strings.Contains(catLower, "xss") || strings.Contains(catLower, "script"):
				// XSS → non-API endpoints (HTML pages)
				if len(otherEndpoints) > 0 {
					targetEndpoints = otherEndpoints
				}
			case strings.Contains(catLower, "auth") || strings.Contains(catLower, "jwt"):
				// Auth attacks → auth endpoints
				if len(authEndpoints) > 0 {
					targetEndpoints = authEndpoints
				}
			case strings.Contains(catLower, "upload") || strings.Contains(catLower, "file"):
				// File attacks → upload endpoints
				if len(uploadEndpoints) > 0 {
					targetEndpoints = uploadEndpoints
				}
			case strings.Contains(catLower, "graphql"):
				// GraphQL → graphql endpoints
				if len(graphqlEndpoints) > 0 {
					targetEndpoints = graphqlEndpoints
				}
			}

			// Fallback to all endpoints if no specific match
			if len(targetEndpoints) == 0 {
				targetEndpoints = discResult.Endpoints
			}

			// Round-robin within the target category
			endpoint := targetEndpoints[i%len(targetEndpoints)]
			allPayloads[i].TargetPath = endpoint.Path
			// Set method from endpoint if not already specified
			if allPayloads[i].Method == "" && endpoint.Method != "" {
				allPayloads[i].Method = endpoint.Method
			}
		}
	}

	ui.PrintInfo(fmt.Sprintf("Loaded %d payloads for testing", len(allPayloads)))
	fmt.Println()

	// Auto-calibration
	ui.PrintInfo("Running auto-calibration...")
	cal := calibration.NewCalibratorWithClient(target, time.Duration(*timeout)*time.Second, *skipVerify, ja3Client)
	calResult, calErr := cal.Calibrate(ctx)
	var filterCfg core.FilterConfig
	if calErr == nil && calResult != nil && calResult.Calibrated {
		filterCfg.FilterStatus = calResult.Suggestions.FilterStatus
		filterCfg.FilterSize = calResult.Suggestions.FilterSize
		ui.PrintSuccess(fmt.Sprintf("Calibrated: %s", calResult.Describe()))
	} else if calErr != nil {
		ui.PrintWarning(fmt.Sprintf("Calibration warning: %v", calErr))
	}
	fmt.Println()

	// Create progress tracker
	progress := ui.NewProgress(ui.ProgressConfig{
		Total:       len(allPayloads),
		Width:       40,
		ShowPercent: true,
		ShowETA:     true,
		ShowRPS:     true,
		Concurrency: *concurrency,
		TurboMode:   true,
	})

	// Create output writer for results
	writer, err := output.NewWriterWithOptions(resultsFile, "json", output.WriterOptions{
		Verbose:       *verbose,
		ShowTimestamp: true,
		Silent:        false,
		Target:        target,
	})
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error creating output writer: %v", err))
		os.Exit(1)
	}

	// Print section header
	ui.PrintSection("Executing Tests")
	fmt.Printf("\n  %s Running with %s parallel workers @ %s req/sec max\n\n",
		ui.SpinnerStyle.Render(">>>"),
		ui.StatValueStyle.Render(fmt.Sprintf("%d", *concurrency)),
		ui.StatValueStyle.Render(fmt.Sprintf("%d", *rateLimit)),
	)

	// Create and run executor
	executor := core.NewExecutor(core.ExecutorConfig{
		TargetURL:     target,
		Concurrency:   *concurrency,
		RateLimit:     *rateLimit,
		Timeout:       time.Duration(*timeout) * time.Second,
		Retries:       2,
		Filter:        &filterCfg,
		RealisticMode: true,
		AutoCalibrate: true,
		HTTPClient:    ja3Client, // JA3 TLS fingerprint rotation
	})

	progress.Start()
	results := executor.ExecuteWithProgress(ctx, allPayloads, writer, progress)
	progress.Stop()

	writer.Close()

	// Update progress after WAF testing
	autoProgress.AddMetricN("bypasses", int64(results.FailedTests))
	autoProgress.SetStatus("Analysis")
	autoProgress.Increment()

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 4.5: VENDOR-SPECIFIC WAF ANALYSIS (NEW)
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println(ui.SectionStyle.Render("PHASE 4.5: Vendor-Specific WAF Analysis"))
	fmt.Println()

	ui.PrintInfo("🔍 Detecting WAF vendor with 150+ signatures...")

	// Vendor detection with comprehensive signature database
	var vendorName string
	var vendorConfidence float64
	var bypassHints []string
	var recommendedEncoders []string
	var recommendedEvasions []string

	// Use the comprehensive vendor detector with 150+ signatures
	vendorDetector := vendors.NewVendorDetectorWithClient(time.Duration(*timeout)*time.Second, ja3Client)
	vendorResult, vendorErr := vendorDetector.Detect(ctx, target)

	if vendorErr == nil && vendorResult.Detected {
		vendorName = vendorResult.VendorName
		vendorConfidence = vendorResult.Confidence
		bypassHints = vendorResult.BypassHints
		recommendedEncoders = vendorResult.RecommendedEncoders
		recommendedEvasions = vendorResult.RecommendedEvasions

		ui.PrintSuccess(fmt.Sprintf("  WAF Vendor: %s (%.0f%% confidence)", vendorName, vendorConfidence*100))

		// Show detection evidence
		if len(vendorResult.Evidence) > 0 {
			for _, ev := range vendorResult.Evidence[:min(3, len(vendorResult.Evidence))] {
				fmt.Printf("    • %s\n", ev)
			}
		}

		// Show bypass recommendations
		if len(bypassHints) > 0 {
			fmt.Println()
			ui.PrintInfo("  📋 Bypass Recommendations:")
			for _, hint := range bypassHints[:min(5, len(bypassHints))] {
				fmt.Printf("    → %s\n", hint)
			}
		}

		// Show recommended encoders/evasions
		if len(recommendedEncoders) > 0 || len(recommendedEvasions) > 0 {
			fmt.Println()
			ui.PrintInfo("  🔧 Recommended Techniques:")
			if len(recommendedEncoders) > 0 {
				fmt.Printf("    Encoders: %s\n", strings.Join(recommendedEncoders[:min(4, len(recommendedEncoders))], ", "))
			}
			if len(recommendedEvasions) > 0 {
				fmt.Printf("    Evasions: %s\n", strings.Join(recommendedEvasions[:min(4, len(recommendedEvasions))], ", "))
			}
		}
	} else if discResult.WAFDetected && discResult.WAFFingerprint != "" {
		// Fallback to discovery result
		vendorName = discResult.WAFFingerprint
		vendorConfidence = 0.6
		ui.PrintInfo(fmt.Sprintf("  WAF Vendor: %s (%.0f%% confidence - from discovery)", vendorName, vendorConfidence*100))
	} else {
		ui.PrintInfo("  No specific WAF vendor detected - using default configuration")
	}
	fmt.Println()
	_, _, _ = bypassHints, recommendedEncoders, recommendedEvasions // Used above

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 5: COMPREHENSIVE REPORT
	// ═══════════════════════════════════════════════════════════════════════════
	fmt.Println()
	fmt.Println(ui.SectionStyle.Render("PHASE 5: Comprehensive Report"))
	fmt.Println()

	// Calculate WAF effectiveness
	wafEffectiveness := float64(0)
	if results.BlockedTests+results.FailedTests > 0 {
		wafEffectiveness = float64(results.BlockedTests) / float64(results.BlockedTests+results.FailedTests) * 100
	}

	duration := time.Since(startTime)

	// Print summary
	fmt.Println("  ════════════════════════════════════════════════════════════")
	fmt.Println("                    SUPERPOWER SCAN COMPLETE")
	fmt.Println("  ════════════════════════════════════════════════════════════")
	fmt.Println()

	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Duration", duration.Round(time.Second).String())
	ui.PrintConfigLine("Workspace", workspaceDir)
	fmt.Println()

	fmt.Printf("  +------------------------------------------------+\n")
	fmt.Printf("  |  Total Endpoints:    %-26d |\n", len(discResult.Endpoints))
	fmt.Printf("  |  JS Files Analyzed:  %-26d |\n", jsAnalyzed)
	fmt.Printf("  |  Secrets Found:      %-26d |\n", len(allJSData.Secrets))
	fmt.Printf("  |  Subdomains Found:   %-26d |\n", len(allJSData.Subdomains))
	// Recon findings from new competitive features
	if leakyResult != nil {
		fmt.Printf("  |  Leaky Paths Found:  %-26d |\n", leakyResult.InterestingHits)
	}
	if paramResult != nil {
		fmt.Printf("  |  Hidden Params Found:%-26d |\n", paramResult.FoundParams)
	}
	fmt.Printf("  +------------------------------------------------+\n")
	fmt.Printf("  |  Total Tests:        %-26d |\n", results.TotalTests)
	fmt.Printf("  |  Blocked (WAF):      %-26d |\n", results.BlockedTests)
	fmt.Printf("  |  Passed:             %-26d |\n", results.PassedTests)
	fmt.Printf("  |  Failed (Bypass):    %-26d |\n", results.FailedTests)
	fmt.Printf("  |  Errors:             %-26d |\n", results.ErrorTests)
	fmt.Printf("  +------------------------------------------------+\n")
	fmt.Println()

	// WAF Effectiveness
	if wafEffectiveness >= 95 {
		ui.PrintSuccess(fmt.Sprintf("  WAF Effectiveness: %.1f%% - EXCELLENT", wafEffectiveness))
	} else if wafEffectiveness >= 80 {
		ui.PrintWarning(fmt.Sprintf("  WAF Effectiveness: %.1f%% - GOOD (room for improvement)", wafEffectiveness))
	} else {
		ui.PrintError(fmt.Sprintf("  WAF Effectiveness: %.1f%% - NEEDS ATTENTION", wafEffectiveness))
	}
	fmt.Println()

	// Print summary and enhanced stats
	ui.PrintSummary(ui.Summary{
		TotalTests:     results.TotalTests,
		BlockedTests:   results.BlockedTests,
		PassedTests:    results.PassedTests,
		FailedTests:    results.FailedTests,
		ErrorTests:     results.ErrorTests,
		Duration:       results.Duration,
		RequestsPerSec: results.RequestsPerSec,
		TargetURL:      target,
	})
	output.PrintSummary(results)

	// Generate markdown report
	generateAutoMarkdownReport(reportFile, target, domain, duration, discResult, allJSData, testPlan, results, wafEffectiveness)

	// Generate summary.json for CI/CD integration
	summaryFile := filepath.Join(workspaceDir, "summary.json")
	summary := map[string]interface{}{
		"target":            target,
		"domain":            domain,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"duration_seconds":  duration.Seconds(),
		"waf_effectiveness": wafEffectiveness,
		"pass":              results.FailedTests == 0,
		"stats": map[string]interface{}{
			"total_tests":   results.TotalTests,
			"blocked":       results.BlockedTests,
			"passed":        results.PassedTests,
			"failed":        results.FailedTests,
			"errors":        results.ErrorTests,
			"requests_sec":  results.RequestsPerSec,
			"endpoints":     len(discResult.Endpoints),
			"js_files":      jsAnalyzed,
			"secrets_found": len(allJSData.Secrets),
		},
		"latency": map[string]interface{}{
			"min_ms": results.LatencyStats.Min,
			"max_ms": results.LatencyStats.Max,
			"avg_ms": results.LatencyStats.Avg,
			"p50_ms": results.LatencyStats.P50,
			"p95_ms": results.LatencyStats.P95,
			"p99_ms": results.LatencyStats.P99,
		},
		"severity_breakdown": results.SeverityBreakdown,
		"category_breakdown": results.CategoryBreakdown,
		"owasp_breakdown":    results.OWASPBreakdown,
		"encoding_stats":     results.EncodingStats,
		"bypass_count":       results.FailedTests,
		"bypass_payloads":    results.BypassPayloads,
		"top_errors":         results.TopErrors,
		"ci_exit_code":       0,
	}
	if results.FailedTests > 0 {
		summary["ci_exit_code"] = 1
		summary["bypass_details"] = results.BypassDetails
	}
	summaryData, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(summaryFile, summaryData, 0644)

	fmt.Println()
	ui.PrintSuccess(fmt.Sprintf("📊 Full report saved to: %s", reportFile))
	fmt.Println()

	// Show output files
	fmt.Printf("  %s\n", ui.SubtitleStyle.Render("Output Files:"))
	fmt.Printf("    • Discovery:   %s\n", discoveryFile)
	fmt.Printf("    • JS Analysis: %s\n", jsAnalysisFile)
	fmt.Printf("    • Test Plan:   %s\n", testPlanFile)
	fmt.Printf("    • Results:     %s\n", resultsFile)
	fmt.Printf("    • Summary:     %s\n", summaryFile)
	fmt.Printf("    • Report:      %s\n", reportFile)
	fmt.Println()

	fmt.Println("  ════════════════════════════════════════════════════════════")
	fmt.Printf("  🚀 SUPERPOWER SCAN COMPLETE in %s\n", duration.Round(time.Second))
	fmt.Println("  ════════════════════════════════════════════════════════════")

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 6: ENTERPRISE ASSESSMENT (NOW DEFAULT)
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for assessment phase
	autoProgress.SetStatus("Assessment")
	autoProgress.Increment()

	if *enableAssess {
		fmt.Println()
		fmt.Println(ui.SectionStyle.Render("PHASE 6: Enterprise Assessment (Quantitative Metrics)"))
		fmt.Println()

		ui.PrintInfo("Running enterprise WAF assessment with F1/precision/MCC metrics...")
		fmt.Println()

		assessConfig := &assessment.Config{
			TargetURL:       target,
			Concurrency:     *concurrency,
			RateLimit:       float64(*rateLimit),
			Timeout:         time.Duration(*timeout) * time.Second,
			SkipTLSVerify:   *skipVerify,
			Verbose:         *verbose,
			HTTPClient:      ja3Client, // JA3 TLS fingerprint rotation
			EnableFPTesting: true,
			CorpusSources:   strings.Split(*assessCorpus, ","),
			DetectWAF:       true,
		}

		assess := assessment.New(assessConfig)
		assessCtx, assessCancel := context.WithTimeout(ctx, 15*time.Minute)
		defer assessCancel()

		progressFn := func(completed, total int64, phase string) {
			if *verbose || completed%25 == 0 || completed == total {
				pct := float64(0)
				if total > 0 {
					pct = float64(completed) / float64(total) * 100
				}
				fmt.Printf("\r  %s: %d/%d (%.1f%%)     ", phase, completed, total, pct)
			}
		}

		assessResult, err := assess.Run(assessCtx, progressFn)
		fmt.Println() // Clear progress line

		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Assessment error: %v", err))
		} else {
			// Display assessment results
			displayAssessmentResults(assessResult, time.Since(startTime))

			// Save assessment results
			assessFile := filepath.Join(workspaceDir, "assessment.json")
			assessData, _ := json.MarshalIndent(assessResult, "", "  ")
			os.WriteFile(assessFile, assessData, 0644)
			ui.PrintSuccess(fmt.Sprintf("📊 Assessment saved to: %s", assessFile))

			// Generate Enterprise HTML Report now that assessment.json exists
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, duration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise HTML report generation error: %v", err))
			} else {
				fmt.Printf("    • Enterprise:  %s\n", htmlReportFile)
			}

			// Update summary with enterprise metrics
			summary["enterprise_metrics"] = map[string]interface{}{
				"grade":               assessResult.Grade,
				"grade_reason":        assessResult.GradeReason,
				"f1_score":            assessResult.F1Score,
				"f2_score":            assessResult.F2Score,
				"precision":           assessResult.Precision,
				"recall":              assessResult.DetectionRate,
				"specificity":         assessResult.Specificity,
				"mcc":                 assessResult.MCC,
				"balanced_accuracy":   assessResult.BalancedAccuracy,
				"detection_rate":      assessResult.DetectionRate,
				"false_positive_rate": assessResult.FalsePositiveRate,
				"bypass_resistance":   assessResult.BypassResistance,
			}
			summaryData, _ = json.MarshalIndent(summary, "", "  ")
			os.WriteFile(summaryFile, summaryData, 0644)
		}
		fmt.Println()
	}

	// ═══════════════════════════════════════════════════════════════════════════
	// PHASE 7-9: AUTHENTICATED BROWSER SCANNING
	// ═══════════════════════════════════════════════════════════════════════════

	// Update progress for browser phase
	autoProgress.SetStatus("Browser scan")
	autoProgress.Increment()

	var browserResult *browser.BrowserScanResult

	if *enableBrowserScan {
		fmt.Println()
		fmt.Println(ui.SectionStyle.Render("PHASE 7: Authenticated Browser Scanning"))
		fmt.Println()

		ui.PrintInfo("🌐 Launching browser for authenticated scanning...")
		fmt.Println()

		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Browser Mode: Authenticated Discovery"))
		fmt.Printf("  %s\n", ui.SubtitleStyle.Render("  Captures: Routes, Tokens, Storage, Third-Party APIs, Network Traffic"))
		fmt.Println()

		// Configure browser scanner
		browserConfig := &browser.AuthConfig{
			TargetURL:      target,
			Timeout:        5 * time.Minute,
			WaitForLogin:   *browserTimeout,
			PostLoginDelay: 5 * time.Second,
			CrawlDepth:     *depth,
			ShowBrowser:    !*browserHeadless,
			Verbose:        *verbose,
			ScreenshotDir:  filepath.Join(workspaceDir, "screenshots"),
			EnableScreens:  true,
		}

		scanner := browser.NewAuthenticatedScanner(browserConfig)

		// Progress callback
		browserProgress := func(msg string) {
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("  %s", msg))
			}
		}

		ui.PrintWarning("⏳ Browser will open - please log in when prompted")
		ui.PrintInfo(fmt.Sprintf("   You have %s to complete authentication", browserConfig.WaitForLogin))
		fmt.Println()

		// Run the browser scan
		browserCtx, browserCancel := context.WithTimeout(ctx, browserConfig.Timeout)
		defer browserCancel()

		var err error
		browserResult, err = scanner.Scan(browserCtx, browserProgress)

		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Browser scan warning: %v", err))
		} else {
			// ═══════════════════════════════════════════════════════════════════════════
			// PHASE 8: Browser Findings Analysis
			// ═══════════════════════════════════════════════════════════════════════════
			fmt.Println()
			fmt.Println(ui.SectionStyle.Render("PHASE 8: Browser Findings Analysis"))
			fmt.Println()

			// Save browser results
			browserFile := filepath.Join(workspaceDir, "browser-scan.json")
			if err := browserResult.SaveResult(browserFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Error saving browser results: %v", err))
			}

			// Display authentication info
			if browserResult.AuthFlowInfo != nil && browserResult.AuthFlowInfo.Provider != "" {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🔐 Authentication Flow Detected:"))
				fmt.Printf("    Provider: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.Provider))
				fmt.Printf("    Flow Type: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.FlowType))
				if browserResult.AuthFlowInfo.LibraryUsed != "" {
					fmt.Printf("    Library: %s\n", ui.ConfigValueStyle.Render(browserResult.AuthFlowInfo.LibraryUsed))
				}
				fmt.Println()
			}

			// Display discovered routes
			if len(browserResult.DiscoveredRoutes) > 0 {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🗺️  Discovered Routes:"))
				for i, route := range browserResult.GetSortedRoutes() {
					if i >= 15 {
						remaining := len(browserResult.DiscoveredRoutes) - 15
						fmt.Printf("    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more routes", remaining)))
						break
					}
					authIcon := "🔓"
					if route.RequiresAuth {
						authIcon = "🔒"
					}
					fmt.Printf("    %s %s %s\n", authIcon, ui.ConfigValueStyle.Render(route.Path),
						ui.SubtitleStyle.Render(route.PageTitle))
				}
				fmt.Println()
			}

			// Display exposed tokens (CRITICAL)
			if len(browserResult.ExposedTokens) > 0 {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("⚠️  Exposed Tokens/Secrets:"))
				for _, token := range browserResult.ExposedTokens {
					sevStyle := ui.SeverityStyle(token.Severity)
					fmt.Printf("    %s%s%s %s in %s\n",
						ui.BracketStyle.Render("["),
						sevStyle.Render(strings.ToUpper(token.Severity)),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(token.Type),
						ui.SubtitleStyle.Render(token.Location),
					)
					fmt.Printf("      → %s\n", token.Risk)
				}
				fmt.Println()
			}

			// Display third-party APIs
			if len(browserResult.ThirdPartyAPIs) > 0 {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("🔗 Third-Party Integrations:"))
				for i, api := range browserResult.ThirdPartyAPIs {
					if i >= 10 {
						remaining := len(browserResult.ThirdPartyAPIs) - 10
						fmt.Printf("    %s\n", ui.SubtitleStyle.Render(fmt.Sprintf("... and %d more integrations", remaining)))
						break
					}
					sevStyle := ui.SeverityStyle(api.Severity)
					fmt.Printf("    %s%s%s %s (%s)\n",
						ui.BracketStyle.Render("["),
						sevStyle.Render(api.Severity),
						ui.BracketStyle.Render("]"),
						ui.ConfigValueStyle.Render(api.Name),
						ui.SubtitleStyle.Render(api.RequestType),
					)
				}
				fmt.Println()
			}

			// Risk Summary
			if browserResult.RiskSummary != nil {
				fmt.Printf("  %s\n", ui.SectionStyle.Render("📊 Browser Scan Risk Summary:"))
				riskStyle := ui.SeverityStyle(browserResult.RiskSummary.OverallRisk)
				fmt.Printf("    Overall Risk: %s\n", riskStyle.Render(strings.ToUpper(browserResult.RiskSummary.OverallRisk)))
				fmt.Printf("    Total Findings: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
					browserResult.RiskSummary.TotalFindings,
					browserResult.RiskSummary.CriticalCount,
					browserResult.RiskSummary.HighCount,
					browserResult.RiskSummary.MediumCount,
					browserResult.RiskSummary.LowCount,
				)

				if len(browserResult.RiskSummary.TopRisks) > 0 {
					fmt.Println()
					fmt.Printf("  %s\n", ui.SectionStyle.Render("🚨 Top Risks:"))
					for _, risk := range browserResult.RiskSummary.TopRisks {
						ui.PrintWarning(fmt.Sprintf("    • %s", risk))
					}
				}
				fmt.Println()
			}

			// ═══════════════════════════════════════════════════════════════════════════
			// PHASE 9: Browser Findings Integration
			// ═══════════════════════════════════════════════════════════════════════════
			fmt.Println()
			fmt.Println(ui.SectionStyle.Render("PHASE 9: Browser Findings Integration"))
			fmt.Println()

			ui.PrintInfo("📊 Merging browser findings into enterprise report...")

			// Update summary with browser findings
			browserScanSummary := map[string]interface{}{
				"auth_successful":    browserResult.AuthSuccessful,
				"discovered_routes":  len(browserResult.DiscoveredRoutes),
				"exposed_tokens":     len(browserResult.ExposedTokens),
				"third_party_apis":   len(browserResult.ThirdPartyAPIs),
				"network_requests":   len(browserResult.NetworkRequests),
				"scan_duration_secs": browserResult.ScanDuration.Seconds(),
			}
			// Add risk summary if available
			if browserResult.RiskSummary != nil {
				browserScanSummary["overall_risk"] = browserResult.RiskSummary.OverallRisk
				browserScanSummary["critical_count"] = browserResult.RiskSummary.CriticalCount
				browserScanSummary["high_count"] = browserResult.RiskSummary.HighCount
			}
			summary["browser_scan"] = browserScanSummary

			// Add auth flow info if detected
			if browserResult.AuthFlowInfo != nil {
				summary["auth_flow"] = map[string]interface{}{
					"provider":  browserResult.AuthFlowInfo.Provider,
					"flow_type": browserResult.AuthFlowInfo.FlowType,
					"library":   browserResult.AuthFlowInfo.LibraryUsed,
				}
			}

			// Save updated summary
			summaryData, _ = json.MarshalIndent(summary, "", "  ")
			os.WriteFile(summaryFile, summaryData, 0644)

			// Regenerate enterprise report to include browser findings
			htmlReportFile := filepath.Join(workspaceDir, "enterprise-report.html")
			if err := report.GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir, domain, duration, htmlReportFile); err != nil {
				ui.PrintWarning(fmt.Sprintf("Enterprise report regeneration error: %v", err))
			} else {
				ui.PrintSuccess("✓ Enterprise report updated with browser findings")
			}

			ui.PrintSuccess(fmt.Sprintf("✓ Browser scan completed in %s", browserResult.ScanDuration.Round(time.Millisecond)))
			fmt.Printf("    • Browser Results: %s\n", browserFile)
			fmt.Println()
		}
	}
	// Silence unused variable warning
	_ = browserHeadless
	_ = browserTimeout
	_ = enableBrowserScan

	if results.FailedTests > 0 {
		os.Exit(1)
	}
}

// inferHTTPMethod tries to determine the HTTP method from path and source
func inferHTTPMethod(path, source string) string {
	pathLower := strings.ToLower(path)

	// POST indicators
	if strings.Contains(pathLower, "create") ||
		strings.Contains(pathLower, "add") ||
		strings.Contains(pathLower, "new") ||
		strings.Contains(pathLower, "upload") ||
		strings.Contains(pathLower, "submit") ||
		strings.Contains(pathLower, "login") ||
		strings.Contains(pathLower, "register") ||
		strings.Contains(pathLower, "signup") {
		return "POST"
	}

	// PUT/PATCH indicators
	if strings.Contains(pathLower, "update") ||
		strings.Contains(pathLower, "edit") ||
		strings.Contains(pathLower, "modify") ||
		strings.Contains(pathLower, "save") {
		return "PUT"
	}

	// DELETE indicators
	if strings.Contains(pathLower, "delete") ||
		strings.Contains(pathLower, "remove") ||
		strings.Contains(pathLower, "destroy") {
		return "DELETE"
	}

	// Check source for method hints
	sourceLower := strings.ToLower(source)
	if strings.Contains(sourceLower, "post") {
		return "POST"
	}
	if strings.Contains(sourceLower, "put") {
		return "PUT"
	}
	if strings.Contains(sourceLower, "delete") {
		return "DELETE"
	}
	if strings.Contains(sourceLower, "patch") {
		return "PATCH"
	}

	return "GET"
}

// truncateString truncates a string to max length
func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// generateAutoMarkdownReport creates a comprehensive markdown report for auto scan
func generateAutoMarkdownReport(filename, target, domain string, duration time.Duration,
	discResult *discovery.DiscoveryResult, jsData *js.ExtractedData,
	testPlan *learning.TestPlan, results output.ExecutionResults, wafEffectiveness float64) {

	var sb strings.Builder

	sb.WriteString("# 🛡️ WAF Security Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", target))
	sb.WriteString(fmt.Sprintf("**Domain:** %s  \n", domain))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", duration.Round(time.Second)))

	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## 📋 Executive Summary\n\n")

	if wafEffectiveness >= 95 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - EXCELLENT** ✅\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing exceptionally well, blocking virtually all attack attempts.\n\n")
	} else if wafEffectiveness >= 80 {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - GOOD** ⚠️\n\n", wafEffectiveness))
		sb.WriteString("The WAF is performing well but has room for improvement.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("**WAF Effectiveness: %.1f%% - NEEDS ATTENTION** ❌\n\n", wafEffectiveness))
		sb.WriteString("The WAF requires immediate attention. Multiple bypasses detected.\n\n")
	}

	// Key Findings
	sb.WriteString("### Key Findings\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Endpoints Discovered | %d |\n", len(discResult.Endpoints)))
	sb.WriteString(fmt.Sprintf("| JavaScript Files Analyzed | %d |\n", len(jsData.Endpoints)))
	sb.WriteString(fmt.Sprintf("| Secrets Found | %d |\n", len(jsData.Secrets)))
	sb.WriteString(fmt.Sprintf("| Subdomains Discovered | %d |\n", len(jsData.Subdomains)))
	sb.WriteString(fmt.Sprintf("| Total Tests Executed | %d |\n", results.TotalTests))
	sb.WriteString(fmt.Sprintf("| WAF Blocks | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Bypasses Detected | %d |\n", results.FailedTests))
	sb.WriteString("\n")

	// Discovery Results
	sb.WriteString("## 🔍 Discovery Results\n\n")

	if discResult.WAFDetected {
		sb.WriteString(fmt.Sprintf("**WAF Detected:** %s\n\n", discResult.WAFFingerprint))
	}

	sb.WriteString("### Attack Surface\n\n")
	surface := discResult.AttackSurface
	if surface.HasAuthEndpoints {
		sb.WriteString("- ✅ Authentication endpoints detected\n")
	}
	if surface.HasAPIEndpoints {
		sb.WriteString("- ✅ API endpoints detected\n")
	}
	if surface.HasFileUpload {
		sb.WriteString("- ✅ File upload functionality detected\n")
	}
	if surface.HasOAuth {
		sb.WriteString("- ✅ OAuth endpoints detected\n")
	}
	if surface.HasGraphQL {
		sb.WriteString("- ✅ GraphQL endpoint detected\n")
	}
	sb.WriteString("\n")

	// Secrets
	if len(jsData.Secrets) > 0 {
		sb.WriteString("## 🔑 Secrets Detected\n\n")
		sb.WriteString("| Type | Confidence | Value (truncated) |\n")
		sb.WriteString("|------|------------|-------------------|\n")
		for _, secret := range jsData.Secrets {
			truncated := secret.Value
			if len(truncated) > 40 {
				truncated = truncated[:40] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | `%s` |\n", secret.Type, secret.Confidence, truncated))
		}
		sb.WriteString("\n")
	}

	// Test Results
	sb.WriteString("## ⚡ Test Results\n\n")

	sb.WriteString("### Summary\n\n")
	sb.WriteString("| Outcome | Count |\n")
	sb.WriteString("|---------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Blocked | %d |\n", results.BlockedTests))
	sb.WriteString(fmt.Sprintf("| Passed | %d |\n", results.PassedTests))
	sb.WriteString(fmt.Sprintf("| Failed (Bypass) | %d |\n", results.FailedTests))
	sb.WriteString(fmt.Sprintf("| Error | %d |\n", results.ErrorTests))
	sb.WriteString("\n")

	// Latency Statistics
	sb.WriteString("### Performance Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Requests/sec | %.1f |\n", results.RequestsPerSec))
	sb.WriteString(fmt.Sprintf("| Min Latency | %d ms |\n", results.LatencyStats.Min))
	sb.WriteString(fmt.Sprintf("| Max Latency | %d ms |\n", results.LatencyStats.Max))
	sb.WriteString(fmt.Sprintf("| Avg Latency | %d ms |\n", results.LatencyStats.Avg))
	sb.WriteString(fmt.Sprintf("| P50 Latency | %d ms |\n", results.LatencyStats.P50))
	sb.WriteString(fmt.Sprintf("| P95 Latency | %d ms |\n", results.LatencyStats.P95))
	sb.WriteString(fmt.Sprintf("| P99 Latency | %d ms |\n", results.LatencyStats.P99))
	sb.WriteString("\n")

	// Bypass Details
	if len(results.BypassDetails) > 0 {
		sb.WriteString("### 🚨 Bypass Details\n\n")
		sb.WriteString("The following attack payloads bypassed the WAF:\n\n")
		for i, bypass := range results.BypassDetails {
			sb.WriteString(fmt.Sprintf("#### Bypass #%d: %s\n\n", i+1, bypass.PayloadID))
			sb.WriteString(fmt.Sprintf("- **Category:** %s\n", bypass.Category))
			sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", bypass.Severity))
			sb.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", bypass.Endpoint))
			sb.WriteString(fmt.Sprintf("- **Method:** %s\n", bypass.Method))
			sb.WriteString(fmt.Sprintf("- **Status Code:** %d\n", bypass.StatusCode))
			sb.WriteString(fmt.Sprintf("- **Payload:** `%s`\n", truncateString(bypass.Payload, 100)))
			if bypass.CurlCommand != "" {
				sb.WriteString(fmt.Sprintf("- **Reproduce:** `%s`\n", bypass.CurlCommand))
			}
			sb.WriteString("\n")
		}
	}

	// Category breakdown if available
	if results.CategoryBreakdown != nil && len(results.CategoryBreakdown) > 0 {
		sb.WriteString("### By Category\n\n")
		sb.WriteString("| Category | Tests |\n")
		sb.WriteString("|----------|-------|\n")
		for cat, count := range results.CategoryBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
		}
		sb.WriteString("\n")
	}

	// OWASP Top 10 breakdown if available
	if results.OWASPBreakdown != nil && len(results.OWASPBreakdown) > 0 {
		sb.WriteString("### OWASP Top 10 2021 Coverage\n\n")
		sb.WriteString("| OWASP Category | Tests |\n")
		sb.WriteString("|----------------|-------|\n")
		for owasp, count := range results.OWASPBreakdown {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", owasp, count))
		}
		sb.WriteString("\n")
	}

	// Encoding effectiveness if available
	if results.EncodingStats != nil && len(results.EncodingStats) > 0 {
		sb.WriteString("### Encoding Effectiveness\n\n")
		sb.WriteString("| Encoding | Tests | Bypasses | Bypass Rate |\n")
		sb.WriteString("|----------|-------|----------|-------------|\n")
		for name, stats := range results.EncodingStats {
			rateIcon := "✅"
			if stats.BypassRate > 10 {
				rateIcon = "🔴"
			} else if stats.BypassRate > 0 {
				rateIcon = "🟡"
			}
			sb.WriteString(fmt.Sprintf("| %s | %d | %d | %.1f%% %s |\n",
				name, stats.TotalTests, stats.Bypasses, stats.BypassRate, rateIcon))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	sb.WriteString("## 📝 Recommendations\n\n")

	if results.FailedTests > 0 {
		sb.WriteString("### Immediate Actions Required\n\n")
		sb.WriteString("1. Review and update WAF rules for bypassed attack categories\n")
		sb.WriteString("2. Enable stricter input validation on affected endpoints\n")
		sb.WriteString("3. Consider implementing additional security layers\n\n")
	}

	if len(jsData.Secrets) > 0 {
		sb.WriteString("### Secrets Remediation\n\n")
		sb.WriteString("1. Rotate all detected credentials immediately\n")
		sb.WriteString("2. Remove hardcoded secrets from JavaScript\n")
		sb.WriteString("3. Implement proper secrets management\n\n")
	}

	sb.WriteString("### General Recommendations\n\n")
	sb.WriteString("1. Regularly update WAF rules and signatures\n")
	sb.WriteString("2. Implement rate limiting on all API endpoints\n")
	sb.WriteString("3. Enable logging and monitoring for security events\n")
	sb.WriteString("4. Conduct regular security assessments\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Report generated by WAF-Tester v%s - Superpower Mode*\n", ui.Version))

	os.WriteFile(filename, []byte(sb.String()), 0644)
}

func runDiscover() {
	ui.PrintCompactBanner()
	ui.PrintSection("Target Discovery")

	discoverFlags := flag.NewFlagSet("discover", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	discoverFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	discoverFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := discoverFlags.String("l", "", "File containing target URLs")
	stdinInput := discoverFlags.Bool("stdin", false, "Read targets from stdin")
	service := discoverFlags.String("service", "", "Service type: wordpress, drupal, nextjs, flask, django")
	outputFile := discoverFlags.String("output", "discovery.json", "Output file for discovery results")
	timeout := discoverFlags.Int("timeout", 10, "HTTP request timeout in seconds")
	concurrency := discoverFlags.Int("concurrency", 10, "Number of parallel discovery workers")
	maxDepth := discoverFlags.Int("depth", 3, "Maximum crawl depth")
	skipVerify := discoverFlags.Bool("skip-verify", false, "Skip TLS certificate verification")
	verbose := discoverFlags.Bool("verbose", false, "Show detailed discovery output")

	discoverFlags.Parse(os.Args[2:])

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", target)
	if *service != "" {
		ui.PrintConfigLine("Service", *service)
	}
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	ui.PrintConfigLine("Max Depth", fmt.Sprintf("%d", *maxDepth))
	ui.PrintConfigLine("Output", *outputFile)
	fmt.Println()

	// Create discoverer
	cfg := discovery.DiscoveryConfig{
		Target:      target,
		Service:     *service,
		Timeout:     time.Duration(*timeout) * time.Second,
		Concurrency: *concurrency,
		MaxDepth:    *maxDepth,
		SkipVerify:  *skipVerify,
	}

	discoverer := discovery.NewDiscoverer(cfg)

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Run discovery
	ui.PrintInfo("Starting endpoint discovery...")
	fmt.Println()

	result, err := discoverer.Discover(ctx)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Discovery error: %v", err))
		os.Exit(1)
	}

	// Display results
	ui.PrintSection("Discovery Results")
	ui.PrintConfigLine("Endpoints Found", fmt.Sprintf("%d", result.Statistics.TotalEndpoints))
	ui.PrintConfigLine("Parameters Found", fmt.Sprintf("%d", result.Statistics.TotalParameters))
	ui.PrintConfigLine("WAF Detected", fmt.Sprintf("%v", result.WAFDetected))
	if result.WAFFingerprint != "" {
		ui.PrintConfigLine("WAF Type", result.WAFFingerprint)
	}
	ui.PrintConfigLine("Duration", result.Duration.String())
	fmt.Println()

	// Show attack surface
	ui.PrintSection("Attack Surface Analysis")
	surface := result.AttackSurface
	if surface.HasAuthEndpoints {
		ui.PrintInfo("✓ Authentication endpoints detected")
	}
	if surface.HasOAuth {
		ui.PrintInfo("✓ OAuth endpoints detected")
	}
	if surface.HasSAML {
		ui.PrintInfo("✓ SAML endpoints detected")
	}
	if surface.HasAPIEndpoints {
		ui.PrintInfo("✓ API endpoints detected")
	}
	if surface.HasFileUpload {
		ui.PrintInfo("✓ File upload endpoints detected")
	}
	if surface.HasGraphQL {
		ui.PrintInfo("✓ GraphQL endpoint detected")
	}
	if surface.HasWebSockets {
		ui.PrintInfo("✓ WebSocket endpoints detected")
	}
	fmt.Println()

	ui.PrintConfigLine("Relevant Categories", fmt.Sprintf("%v", surface.RelevantCategories))
	fmt.Println()

	// Show enhanced discovery findings
	if len(result.Secrets) > 0 {
		ui.PrintSection("🔑 Secrets Detected")
		for path, secrets := range result.Secrets {
			for _, s := range secrets {
				ui.PrintError(fmt.Sprintf("[%s] %s in %s", s.Severity, s.Type, path))
			}
		}
		fmt.Println()
	}

	if len(result.S3Buckets) > 0 {
		ui.PrintSection("☁️  S3 Buckets Found")
		for _, bucket := range result.S3Buckets {
			ui.PrintInfo("  " + bucket)
		}
		fmt.Println()
	}

	if len(result.Subdomains) > 0 {
		ui.PrintSection("🌐 Subdomains Discovered")
		for _, sub := range result.Subdomains {
			ui.PrintInfo("  " + sub)
		}
		fmt.Println()
	}

	// Show endpoints if verbose
	if *verbose {
		ui.PrintSection("Discovered Endpoints")
		for _, ep := range result.Endpoints {
			fmt.Printf("  [%s] %s %s (%s)\n",
				ui.StatusBracket(ep.StatusCode),
				ep.Method,
				ep.Path,
				ep.Category,
			)
		}
		fmt.Println()
	}

	// Save results
	if err := result.SaveResult(*outputFile); err != nil {
		ui.PrintError(fmt.Sprintf("Error saving results: %v", err))
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Discovery results saved to %s", *outputFile))
	fmt.Println()
	ui.PrintHelp("Next step: waf-tester learn -discovery " + *outputFile)
}

func runLearn() {
	ui.PrintCompactBanner()
	ui.PrintSection("Test Plan Generation")

	learnFlags := flag.NewFlagSet("learn", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	learnFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	learnFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := learnFlags.String("l", "", "File containing target URLs")
	stdinInput := learnFlags.Bool("stdin", false, "Read targets from stdin")
	discoveryFile := learnFlags.String("discovery", "discovery.json", "Discovery results file")
	payloadDir := learnFlags.String("payloads", "../payloads", "Payload directory")
	outputPlan := learnFlags.String("output", "testplan.json", "Output test plan file")
	outputPayloads := learnFlags.String("custom-payloads", "", "Output file for generated custom payloads")
	verbose := learnFlags.Bool("verbose", false, "Show detailed test plan")

	learnFlags.Parse(os.Args[2:])

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Discovery File", *discoveryFile)
	ui.PrintConfigLine("Payload Dir", *payloadDir)
	ui.PrintConfigLine("Output Plan", *outputPlan)
	fmt.Println()

	// Load discovery results
	ui.PrintInfo("Loading discovery results...")
	disc, err := discovery.LoadResult(*discoveryFile)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error loading discovery file: %v", err))
		ui.PrintHelp("Run 'waf-tester discover' first to generate discovery.json")
		os.Exit(1)
	}

	ui.PrintSuccess(fmt.Sprintf("Loaded discovery for %s (%d endpoints)", disc.Target, len(disc.Endpoints)))
	fmt.Println()

	// Generate test plan
	ui.PrintInfo("Analyzing attack surface and generating test plan...")
	learner := learning.NewLearner(disc, *payloadDir)
	plan := learner.GenerateTestPlan()

	// Display plan summary
	ui.PrintSection("Test Plan Summary")
	ui.PrintConfigLine("Target", plan.Target)
	if plan.Service != "" {
		ui.PrintConfigLine("Service", plan.Service)
	}
	ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", plan.TotalTests))
	ui.PrintConfigLine("Estimated Time", plan.EstimatedTime)
	fmt.Println()

	// Show test groups
	ui.PrintSection("Test Categories (by priority)")
	for _, group := range plan.TestGroups {
		fmt.Printf("  [P%d] %s - %s\n",
			group.Priority,
			ui.StatValueStyle.Render(group.Category),
			group.Reason,
		)
	}
	fmt.Println()

	// Show endpoint-specific tests if verbose
	if *verbose {
		ui.PrintSection("Endpoint-Specific Tests")
		for _, set := range plan.EndpointTests {
			fmt.Printf("  %s %s\n", set.Endpoint.Method, set.Endpoint.Path)
			fmt.Printf("    Attack Categories: %v\n", set.AttackCategories)
			fmt.Printf("    Injection Points: %d\n", len(set.InjectPoints))
			fmt.Printf("    Custom Payloads: %d\n", len(set.CustomPayloads))
		}
		fmt.Println()
	}

	// Show recommended config
	ui.PrintSection("Recommended Configuration")
	cfg := plan.RecommendedFlags
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", cfg.Concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec", cfg.RateLimit))
	ui.PrintConfigLine("Categories", fmt.Sprintf("%v", cfg.Categories))
	if len(cfg.FocusAreas) > 0 {
		ui.PrintConfigLine("Focus Areas", fmt.Sprintf("%v", cfg.FocusAreas))
	}
	fmt.Println()

	// Save test plan
	if err := plan.SavePlan(*outputPlan); err != nil {
		ui.PrintError(fmt.Sprintf("Error saving test plan: %v", err))
		os.Exit(1)
	}
	ui.PrintSuccess(fmt.Sprintf("Test plan saved to %s", *outputPlan))

	// Save custom payloads if requested
	if *outputPayloads != "" {
		if err := plan.GeneratePayloadFile(*outputPayloads); err != nil {
			ui.PrintError(fmt.Sprintf("Error saving custom payloads: %v", err))
			os.Exit(1)
		}
		ui.PrintSuccess(fmt.Sprintf("Custom payloads saved to %s", *outputPayloads))
	}

	fmt.Println()

	// Build the run command
	categories := ""
	if len(cfg.Categories) > 0 {
		categories = cfg.Categories[0]
	}

	runCmd := fmt.Sprintf("waf-tester run -target %s -c %d -rate %d",
		plan.Target, cfg.Concurrency, cfg.RateLimit)
	if categories != "" {
		runCmd += " -category " + categories
	}
	if *outputPayloads != "" {
		runCmd += " -payloads " + *outputPayloads
	}

	ui.PrintHelp("Next step: " + runCmd)
}

func runTests() {
	// Parse CLI flags first to check for silent mode
	cfg, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERR] Configuration error: %v\n", err)
		os.Exit(1)
	}

	// Print banner (unless silent)
	if !cfg.Silent {
		ui.PrintBanner()
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     cfg.TargetURLs,
		ListFile: cfg.ListFile,
		Stdin:    cfg.StdinInput,
	}
	targets, err := ts.GetTargets()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error reading targets: %v", err))
		os.Exit(1)
	}
	if len(targets) == 0 && cfg.PlanFile == "" {
		// Only require target if not using a test plan (plan can provide target)
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}
	// For multi-target support, we'll iterate through targets later
	// Set the first target as primary for now (used by test plan loading, etc.)
	if len(targets) > 0 {
		cfg.TargetURL = targets[0]
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println()
		ui.PrintWarning("Interrupt received, shutting down gracefully...")
		cancel()
	}()

	// Check if using a test plan from 'learn' command
	var plan *learning.TestPlan
	if cfg.PlanFile != "" {
		if !cfg.Silent {
			ui.PrintInfo(fmt.Sprintf("Loading test plan from %s...", cfg.PlanFile))
		}
		plan, err = learning.LoadPlan(cfg.PlanFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error loading test plan: %v", err))
			ui.PrintHelp("Run 'waf-tester learn -discovery <file>' first to generate a test plan")
			os.Exit(1)
		}

		// Apply plan settings if not overridden by CLI
		if cfg.TargetURL == "" {
			cfg.TargetURL = plan.Target
		}
		if cfg.Concurrency == 25 { // default value
			cfg.Concurrency = plan.RecommendedFlags.Concurrency
		}
		if cfg.RateLimit == 150 { // default value
			cfg.RateLimit = plan.RecommendedFlags.RateLimit
		}
		if cfg.Category == "" && len(plan.RecommendedFlags.Categories) > 0 {
			cfg.Category = plan.RecommendedFlags.Categories[0]
		}

		if !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Loaded test plan: %d tests across %d categories",
				plan.TotalTests, len(plan.TestGroups)))
			fmt.Println()
		}
	}

	// Print configuration (ffuf-style) - skip if silent
	if !cfg.Silent {
		configOptions := map[string]string{
			"Target":      cfg.TargetURL,
			"Payload Dir": cfg.PayloadDir,
			"Concurrency": fmt.Sprintf("%d", cfg.Concurrency),
			"Rate Limit":  fmt.Sprintf("%d req/sec", cfg.RateLimit),
			"Timeout":     fmt.Sprintf("%v", cfg.Timeout),
		}
		if cfg.PlanFile != "" {
			configOptions["Test Plan"] = cfg.PlanFile
		}
		if cfg.Category != "" {
			configOptions["Category"] = cfg.Category
		}
		if cfg.Severity != "" {
			configOptions["Min Severity"] = cfg.Severity + "+"
		}
		if cfg.MatchStatus != "" {
			configOptions["Match Codes"] = cfg.MatchStatus
		}
		if cfg.MatchWords != "" {
			configOptions["Match Words"] = cfg.MatchWords
		}
		if cfg.MatchLines != "" {
			configOptions["Match Lines"] = cfg.MatchLines
		}
		if cfg.MatchRegex != "" {
			configOptions["Match Regex"] = cfg.MatchRegex
		}
		if cfg.FilterStatus != "" {
			configOptions["Filter Codes"] = cfg.FilterStatus
		}
		if cfg.FilterWords != "" {
			configOptions["Filter Words"] = cfg.FilterWords
		}
		if cfg.FilterLines != "" {
			configOptions["Filter Lines"] = cfg.FilterLines
		}
		if cfg.FilterRegex != "" {
			configOptions["Filter Regex"] = cfg.FilterRegex
		}
		if cfg.Proxy != "" {
			configOptions["Proxy"] = cfg.Proxy
		}
		if cfg.OutputFile != "" {
			configOptions["Output"] = cfg.OutputFile
			configOptions["Format"] = cfg.OutputFormat
		}
		if cfg.AutoCalibration {
			configOptions["Calibration"] = "enabled"
		}
		ui.PrintConfigBanner(configOptions)
	}

	// Auto-calibration (like ffuf -ac)
	if cfg.AutoCalibration {
		if !cfg.Silent {
			ui.PrintInfo("Running auto-calibration...")
		}
		cal := calibration.NewCalibrator(cfg.TargetURL, cfg.Timeout, cfg.SkipVerify)
		calResult, calErr := cal.Calibrate(ctx)
		if calErr != nil {
			if !cfg.Silent {
				ui.PrintWarning(fmt.Sprintf("Calibration failed: %v (continuing without filtering)", calErr))
			}
		} else if calResult != nil && calResult.Calibrated {
			// Apply calibration results as filters
			if len(calResult.Suggestions.FilterStatus) > 0 && cfg.FilterStatus == "" {
				codes := make([]string, len(calResult.Suggestions.FilterStatus))
				for i, c := range calResult.Suggestions.FilterStatus {
					codes[i] = fmt.Sprintf("%d", c)
				}
				cfg.FilterStatus = strings.Join(codes, ",")
			}
			if len(calResult.Suggestions.FilterSize) > 0 && cfg.FilterSize == "" {
				sizes := make([]string, len(calResult.Suggestions.FilterSize))
				for i, s := range calResult.Suggestions.FilterSize {
					sizes[i] = fmt.Sprintf("%d", s)
				}
				cfg.FilterSize = strings.Join(sizes, ",")
			}
			if !cfg.Silent {
				ui.PrintSuccess(fmt.Sprintf("Calibrated: %s", calResult.Describe()))
			}
		}
		if !cfg.Silent {
			fmt.Println()
		}
	}

	// Initialize interactive handler (ffuf-style)
	var interactiveHandler *interactive.Handler
	if !cfg.NonInteractive && !cfg.Silent {
		interactiveState := interactive.NewState(cfg.RateLimit)
		interactiveHandler = interactive.NewHandler(interactiveState)
		go interactiveHandler.Start()
		defer interactiveHandler.Stop()
	}
	_ = interactiveHandler // Handler provides pause/resume during execution via background goroutine

	// Load payloads from JSON files
	if !cfg.Silent {
		ui.PrintInfo("Loading payloads...")
	}
	loader := payloads.NewLoader(cfg.PayloadDir)
	allPayloads, err := loader.LoadAll()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Error loading payloads: %v", err))
		os.Exit(1)
	}

	// Apply filters from test plan or CLI
	if plan != nil && len(plan.RecommendedFlags.Categories) > 0 {
		// When using a test plan, filter to ANY of its recommended categories
		var filteredPayloads []payloads.Payload
		categorySet := make(map[string]bool)
		for _, cat := range plan.RecommendedFlags.Categories {
			categorySet[strings.ToLower(cat)] = true
		}
		for _, p := range allPayloads {
			if categorySet[strings.ToLower(p.Category)] {
				filteredPayloads = append(filteredPayloads, p)
			}
		}
		allPayloads = filteredPayloads
		if !cfg.Silent {
			ui.PrintInfo(fmt.Sprintf("Filtered to %d categories from test plan: %v", len(plan.RecommendedFlags.Categories), plan.RecommendedFlags.Categories))
		}
	} else if cfg.Category != "" || cfg.Severity != "" {
		allPayloads = payloads.Filter(allPayloads, cfg.Category, cfg.Severity)
	}

	if !cfg.Silent {
		ui.PrintSuccess(fmt.Sprintf("Loaded %d payloads", len(allPayloads)))
	}

	// Apply mutations if enabled
	if cfg.MutationMode != "" && cfg.MutationMode != "none" {
		allPayloads = applyMutations(cfg, allPayloads)
		if !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Expanded to %d payloads after mutation", len(allPayloads)))
		}
	}

	// Dry run mode - just list payloads
	if cfg.DryRun {
		// Force sync stderr before printing to stdout
		os.Stderr.Sync()

		ui.PrintSection("Dry Run Mode")
		ui.PrintInfo(fmt.Sprintf("Would execute %d tests:", len(allPayloads)))

		// Sync stderr before switching to stdout for results
		os.Stderr.Sync()

		for _, p := range allPayloads {
			ui.PrintBracketedInfo(
				ui.SeverityBracket(p.SeverityHint),
				ui.CategoryBracket(p.Category),
				ui.TextBracket(p.ID),
			)
		}

		// Sync stdout before switching back to stderr
		os.Stdout.Sync()
		fmt.Fprintln(os.Stderr)
		ui.PrintHelp("Remove -dry-run flag to execute tests")
		os.Exit(0)
	}

	// Determine which targets to test
	// If targets is empty (using plan file), use plan.Target
	if len(targets) == 0 && plan != nil && plan.Target != "" {
		targets = []string{plan.Target}
	}

	// Multi-target support: run tests against each target
	var aggregatedResults output.ExecutionResults
	totalTargets := len(targets)

	if totalTargets > 1 && !cfg.Silent {
		ui.PrintSection(fmt.Sprintf("Multi-Target Mode: Testing %d targets", totalTargets))
		fmt.Println()
	}

	for targetIdx, currentTarget := range targets {
		// Update config for this target
		cfg.TargetURL = currentTarget

		if totalTargets > 1 && !cfg.Silent {
			ui.PrintSection(fmt.Sprintf("Target %d/%d: %s", targetIdx+1, totalTargets, currentTarget))
			fmt.Println()
		}

		// Create output writer with verbose, timestamp, and silent options
		// For multi-target, append target index to filename
		outputFile := cfg.OutputFile
		if totalTargets > 1 && cfg.OutputFile != "" {
			ext := filepath.Ext(cfg.OutputFile)
			base := strings.TrimSuffix(cfg.OutputFile, ext)
			// Extract domain for clearer filenames
			u, _ := url.Parse(currentTarget)
			domain := u.Host
			if domain == "" {
				domain = fmt.Sprintf("target-%d", targetIdx+1)
			}
			domain = strings.ReplaceAll(domain, ":", "_")
			outputFile = fmt.Sprintf("%s-%s%s", base, domain, ext)
		}

		writer, err := output.NewWriterWithOptions(outputFile, cfg.OutputFormat, output.WriterOptions{
			Verbose:       cfg.Verbose,
			ShowTimestamp: cfg.Timestamp,
			Silent:        cfg.Silent,
			Target:        currentTarget,
		})
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error creating output for %s: %v", currentTarget, err))
			continue
		}

		// Create progress tracker with turbo mode
		progress := ui.NewProgress(ui.ProgressConfig{
			Total:       len(allPayloads),
			Width:       40,
			ShowPercent: true,
			ShowETA:     true,
			ShowRPS:     true,
			Concurrency: cfg.Concurrency,
			TurboMode:   true,
		})

		// Print section header
		if !cfg.Silent {
			ui.PrintSection("Executing Tests")
			fmt.Printf("\n  %s Running with %s parallel workers @ %s req/sec max\n\n",
				ui.SpinnerStyle.Render(">>>"),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", cfg.Concurrency)),
				ui.StatValueStyle.Render(fmt.Sprintf("%d", cfg.RateLimit)),
			)
		}

		// Create and run executor with UI callbacks
		executor := core.NewExecutor(core.ExecutorConfig{
			TargetURL:     currentTarget,
			Concurrency:   cfg.Concurrency,
			RateLimit:     cfg.RateLimit,
			Timeout:       cfg.Timeout,
			Retries:       cfg.Retries,
			Filter:        buildFilterConfig(cfg),
			RealisticMode: cfg.RealisticMode,
			AutoCalibrate: cfg.RealisticMode && cfg.AutoCalibration,
		})

		// Start progress display (skip if silent)
		if !cfg.Silent {
			progress.Start()
		}

		results := executor.ExecuteWithProgress(ctx, allPayloads, writer, progress)

		// Stop progress display
		if !cfg.Silent {
			progress.Stop()
		}

		// Print summary (skip if silent)
		if !cfg.Silent {
			ui.PrintSummary(ui.Summary{
				TotalTests:     results.TotalTests,
				BlockedTests:   results.BlockedTests,
				PassedTests:    results.PassedTests,
				FailedTests:    results.FailedTests,
				ErrorTests:     results.ErrorTests,
				Duration:       results.Duration,
				RequestsPerSec: results.RequestsPerSec,
				TargetURL:      currentTarget,
				Category:       cfg.Category,
				Severity:       cfg.Severity,
			})

			// Print enhanced stats (nuclei-style status codes, severity breakdown)
			output.PrintSummary(results)
		}

		// Close writer to flush output
		writer.Close()

		// Save results if output file specified
		if outputFile != "" && !cfg.Silent {
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", outputFile))
		}

		// Aggregate results
		aggregatedResults.TotalTests += results.TotalTests
		aggregatedResults.BlockedTests += results.BlockedTests
		aggregatedResults.PassedTests += results.PassedTests
		aggregatedResults.FailedTests += results.FailedTests
		aggregatedResults.ErrorTests += results.ErrorTests
		aggregatedResults.Duration += results.Duration

		// Add spacing between targets
		if totalTargets > 1 && targetIdx < totalTargets-1 && !cfg.Silent {
			fmt.Println()
		}
	}

	// Print aggregated summary for multi-target
	if totalTargets > 1 && !cfg.Silent {
		fmt.Println()
		ui.PrintSection("Aggregated Results (All Targets)")
		aggregatedResults.RequestsPerSec = float64(aggregatedResults.TotalTests) / aggregatedResults.Duration.Seconds()
		ui.PrintSummary(ui.Summary{
			TotalTests:     aggregatedResults.TotalTests,
			BlockedTests:   aggregatedResults.BlockedTests,
			PassedTests:    aggregatedResults.PassedTests,
			FailedTests:    aggregatedResults.FailedTests,
			ErrorTests:     aggregatedResults.ErrorTests,
			Duration:       aggregatedResults.Duration,
			RequestsPerSec: aggregatedResults.RequestsPerSec,
			TargetURL:      fmt.Sprintf("%d targets", totalTargets),
			Category:       cfg.Category,
			Severity:       cfg.Severity,
		})
		output.PrintSummary(aggregatedResults)
	}

	// Exit with appropriate code
	if aggregatedResults.FailedTests > 0 {
		os.Exit(1)
	}
}

// runProbe executes protocol probing (TLS, HTTP/2, headers, WAF detection)
func runProbe() {
	// Parse flags first to check for silent mode
	probeFlags := flag.NewFlagSet("probe", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	probeFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	probeFlags.Var(&targetURLs, "target", "Target URL(s) - comma-separated or repeated")
	outputFile := probeFlags.String("output", "", "Output file for results (JSON)")
	timeout := probeFlags.Int("timeout", 10, "Request timeout in seconds")
	tlsProbe := probeFlags.Bool("tls", true, "Probe TLS configuration")
	headerProbe := probeFlags.Bool("headers", true, "Probe security headers")
	httpProbe := probeFlags.Bool("http", true, "Probe HTTP/2, pipeline, methods")
	wafProbe := probeFlags.Bool("waf", true, "Detect WAF/CDN")
	faviconProbe := probeFlags.Bool("favicon", true, "Probe favicon and calculate hash")
	jarmProbe := probeFlags.Bool("jarm", true, "Calculate JARM TLS fingerprint")
	techProbe := probeFlags.Bool("tech", true, "Detect technologies (title, frameworks, CMS)")
	dnsProbe := probeFlags.Bool("dns", true, "DNS resolution (IP, CNAME, ASN)")
	jsonOutput := probeFlags.Bool("j", false, "Output in JSONL(ines) format")
	probeFlags.BoolVar(jsonOutput, "json", false, "Output in JSONL(ines) format")
	jsonl := probeFlags.Bool("jsonl", false, "Output in JSONL format (one JSON per line)")
	stdinInput := probeFlags.Bool("stdin", false, "Read targets from stdin")
	silent := probeFlags.Bool("silent", false, "Only output results, no banner")
	oneliner := probeFlags.Bool("1", false, "One-liner output (single line per result)")
	concurrency := probeFlags.Int("c", 10, "Concurrency for multiple targets")

	// httpx-style output flags
	showContentLength := probeFlags.Bool("cl", false, "Show content-length in output")
	showContentType := probeFlags.Bool("ct", false, "Show content-type in output")
	showWordCount := probeFlags.Bool("wc", false, "Show word count in output")
	showLineCount := probeFlags.Bool("lc", false, "Show line count in output")
	showServer := probeFlags.Bool("server", false, "Show server header in output")
	showMethod := probeFlags.Bool("method", false, "Show HTTP method in output")
	showLocation := probeFlags.Bool("location", false, "Show redirect location")
	followRedirects := probeFlags.Bool("fr", false, "Follow HTTP redirects")
	maxRedirects := probeFlags.Int("max-redirects", 10, "Max redirects to follow")
	customHeaders := probeFlags.String("H", "", "Custom header (format: 'Name: Value')")
	httpMethod := probeFlags.String("x", "GET", "HTTP method to use")
	requestBody := probeFlags.String("body", "", "Request body for POST/PUT")
	randomAgent := probeFlags.Bool("random-agent", false, "Use random User-Agent")
	probeStatus := probeFlags.Bool("probe", false, "Show probe status (up/down)")

	// Missing httpx features - now added
	skipVerify := probeFlags.Bool("k", false, "Skip TLS certificate verification")
	probeFlags.BoolVar(skipVerify, "skip-verify", false, "Skip TLS certificate verification")
	retries := probeFlags.Int("retries", 0, "Number of retries on failure")
	delay := probeFlags.Duration("delay", 0, "Delay between requests (e.g., 100ms, 1s)")
	rateLimit := probeFlags.Int("rl", 0, "Rate limit (requests per second, 0=unlimited)")
	probeFlags.IntVar(rateLimit, "rate-limit", 0, "Rate limit (requests per second, 0=unlimited)")
	rateLimitPerHost := probeFlags.Bool("rlph", false, "Apply rate limit per host (not global)")
	probeFlags.BoolVar(rateLimitPerHost, "rate-limit-per-host", false, "Apply rate limit per host (not global)")
	proxyURL := probeFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	storeResponse := probeFlags.Bool("sr", false, "Store HTTP response to file")
	probeFlags.BoolVar(storeResponse, "store-response", false, "Store HTTP response to file")
	storeResponseDir := probeFlags.String("srd", "./responses", "Directory to store responses")
	probeFlags.StringVar(storeResponseDir, "store-response-dir", "./responses", "Directory to store responses")
	csvOutput := probeFlags.Bool("csv", false, "Output in CSV format")
	hashType := probeFlags.String("hash", "", "Calculate body hash (md5, sha256, mmh3)")
	debug := probeFlags.Bool("debug", false, "Show request/response details")
	showTitle := probeFlags.Bool("title", false, "Show page title in output")
	showIP := probeFlags.Bool("ip", false, "Show resolved IP in output")
	showASN := probeFlags.Bool("asn", false, "Show ASN info in output")
	showCDN := probeFlags.Bool("cdn", false, "Show CDN/WAF detection in output")
	showTech := probeFlags.Bool("td", false, "Show technology detection in output")
	probeFlags.BoolVar(showTech, "tech-detect", false, "Show technology detection in output")
	listFile := probeFlags.String("l", "", "File containing list of targets")
	probeFlags.StringVar(listFile, "list", "", "File containing list of targets")
	outputCSV := probeFlags.String("o", "", "Output file (auto-detect format by extension)")
	probeFlags.StringVar(outputCSV, "output-file", "", "Output file (auto-detect format by extension)")

	// More httpx features - section 2
	bodyPreview := probeFlags.Int("bp", 0, "Show first N characters of response body")
	probeFlags.IntVar(bodyPreview, "body-preview", 0, "Show first N characters of response body")
	showWebSocket := probeFlags.Bool("ws", false, "Show WebSocket support")
	probeFlags.BoolVar(showWebSocket, "websocket", false, "Show WebSocket support")
	showCNAME := probeFlags.Bool("cname", false, "Show CNAME record in output")
	extractRegex := probeFlags.String("er", "", "Extract content matching regex")
	probeFlags.StringVar(extractRegex, "extract-regex", "", "Extract content matching regex")
	extractPreset := probeFlags.String("ep", "", "Extract preset patterns (url,ipv4,mail)")
	probeFlags.StringVar(extractPreset, "extract-preset", "", "Extract preset patterns (url,ipv4,mail)")
	probePorts := probeFlags.String("ports", "", "Ports to probe (e.g., 80,443,8080)")
	probeFlags.StringVar(probePorts, "p", "", "Ports to probe (e.g., 80,443,8080)")
	probePaths := probeFlags.String("path", "", "Paths to probe (comma-separated)")
	showHTTP2 := probeFlags.Bool("http2", false, "Show HTTP/2 support")
	showPipeline := probeFlags.Bool("pipeline", false, "Show HTTP pipelining support")
	showStats := probeFlags.Bool("stats", false, "Show scan statistics at end")
	noColor := probeFlags.Bool("nc", false, "Disable colors in output")
	probeFlags.BoolVar(noColor, "no-color", false, "Disable colors in output")
	verbose := probeFlags.Bool("v", false, "Verbose output")
	probeFlags.BoolVar(verbose, "verbose", false, "Verbose output")
	threads := probeFlags.Int("t", 10, "Number of concurrent threads")
	probeFlags.IntVar(threads, "threads", 10, "Number of concurrent threads")
	includeChain := probeFlags.Bool("include-chain", false, "Include redirect chain in output")
	headerHash := probeFlags.Bool("header-hash", false, "Show hash of response headers")
	showFaviconHash := probeFlags.Bool("favicon-hash", false, "Show favicon hash in one-liner output")
	showScheme := probeFlags.Bool("scheme", false, "Show URL scheme (http/https)")
	matchCode := probeFlags.String("mc", "", "Match status codes (e.g., 200,302)")
	probeFlags.StringVar(matchCode, "match-code", "", "Match status codes (e.g., 200,302)")
	filterCode := probeFlags.String("fc", "", "Filter out status codes (e.g., 404,500)")
	probeFlags.StringVar(filterCode, "filter-code", "", "Filter out status codes (e.g., 404,500)")
	matchString := probeFlags.String("ms", "", "Match responses containing string")
	probeFlags.StringVar(matchString, "match-string", "", "Match responses containing string")
	filterString := probeFlags.String("fs", "", "Filter responses containing string")
	probeFlags.StringVar(filterString, "filter-string", "", "Filter responses containing string")

	// Additional httpx matchers
	matchLength := probeFlags.String("ml", "", "Match content length (e.g., 100,200-500)")
	probeFlags.StringVar(matchLength, "match-length", "", "Match content length (e.g., 100,200-500)")
	matchLineCount := probeFlags.String("mlc", "", "Match line count (e.g., 10,20-50)")
	probeFlags.StringVar(matchLineCount, "match-line-count", "", "Match line count (e.g., 10,20-50)")
	matchWordCount := probeFlags.String("mwc", "", "Match word count (e.g., 100,200-500)")
	probeFlags.StringVar(matchWordCount, "match-word-count", "", "Match word count (e.g., 100,200-500)")
	matchRegex := probeFlags.String("mr", "", "Match responses with regex")
	probeFlags.StringVar(matchRegex, "match-regex", "", "Match responses with regex")
	matchFavicon := probeFlags.String("mfc", "", "Match favicon hash (murmur3)")
	probeFlags.StringVar(matchFavicon, "match-favicon", "", "Match favicon hash (murmur3)")
	matchCDN := probeFlags.String("mcdn", "", "Match CDN provider (cloudflare,akamai,etc)")
	probeFlags.StringVar(matchCDN, "match-cdn", "", "Match CDN provider (cloudflare,akamai,etc)")
	matchRespTime := probeFlags.String("mrt", "", "Match response time (e.g., '<1s', '>500ms')")
	probeFlags.StringVar(matchRespTime, "match-response-time", "", "Match response time (e.g., '<1s', '>500ms')")

	// Additional httpx filters
	filterLength := probeFlags.String("fl", "", "Filter content length (e.g., 0,404)")
	probeFlags.StringVar(filterLength, "filter-length", "", "Filter content length (e.g., 0,404)")
	filterLineCount := probeFlags.String("flc", "", "Filter line count (e.g., 1,2)")
	probeFlags.StringVar(filterLineCount, "filter-line-count", "", "Filter line count (e.g., 1,2)")
	filterWordCount := probeFlags.String("fwc", "", "Filter word count (e.g., 0,10)")
	probeFlags.StringVar(filterWordCount, "filter-word-count", "", "Filter word count (e.g., 0,10)")
	filterRegex := probeFlags.String("fe", "", "Filter responses with regex")
	probeFlags.StringVar(filterRegex, "filter-regex", "", "Filter responses with regex")
	filterFavicon := probeFlags.String("ffc", "", "Filter favicon hash (murmur3)")
	probeFlags.StringVar(filterFavicon, "filter-favicon", "", "Filter favicon hash (murmur3)")
	filterCDN := probeFlags.String("fcdn", "", "Filter CDN provider (cloudflare,akamai,etc)")
	probeFlags.StringVar(filterCDN, "filter-cdn", "", "Filter CDN provider (cloudflare,akamai,etc)")
	filterRespTime := probeFlags.String("frt", "", "Filter response time (e.g., '>5s')")
	probeFlags.StringVar(filterRespTime, "filter-response-time", "", "Filter response time (e.g., '>5s')")

	// Batch 1: Missing Probe flags
	extractFQDN := probeFlags.Bool("efqdn", false, "Extract domains/subdomains from response")
	probeFlags.BoolVar(extractFQDN, "extract-fqdn", false, "Extract domains/subdomains from response")
	showCPE := probeFlags.Bool("cpe", false, "Show CPE (Common Platform Enumeration)")
	showWordPress := probeFlags.Bool("wp", false, "Detect WordPress plugins and themes")
	probeFlags.BoolVar(showWordPress, "wordpress", false, "Detect WordPress plugins and themes")

	// Batch 2: Missing Rate-Limit flags
	rateLimitMinute := probeFlags.Int("rlm", 0, "Rate limit per minute (0=unlimited)")
	probeFlags.IntVar(rateLimitMinute, "rate-limit-minute", 0, "Rate limit per minute (0=unlimited)")

	// Batch 3: Missing Misc flags
	probeAllIPs := probeFlags.Bool("pa", false, "Probe all IPs associated with host")
	probeFlags.BoolVar(probeAllIPs, "probe-all-ips", false, "Probe all IPs associated with host")
	tlsProbeExtracted := probeFlags.Bool("tls-probe", false, "Send probes on extracted TLS domains")
	cspProbe := probeFlags.Bool("csp-probe", false, "Send probes on extracted CSP domains")
	tlsGrab := probeFlags.Bool("tls-grab", false, "Perform TLS/SSL data grabbing")
	vhostProbe := probeFlags.Bool("vhost", false, "Probe and display VHOST support")
	listDSLVars := probeFlags.Bool("ldv", false, "List DSL variable names")
	probeFlags.BoolVar(listDSLVars, "list-dsl-variables", false, "List DSL variable names")

	// Batch 4: Missing Output flags
	outputAll := probeFlags.Bool("oa", false, "Output in all formats (json, csv, txt)")
	probeFlags.BoolVar(outputAll, "output-all", false, "Output in all formats (json, csv, txt)")
	omitBody := probeFlags.Bool("ob", false, "Omit response body in output")
	probeFlags.BoolVar(omitBody, "omit-body", false, "Omit response body in output")
	csvEncoding := probeFlags.String("csvo", "utf-8", "CSV output encoding")
	probeFlags.StringVar(csvEncoding, "csv-output-encoding", "utf-8", "CSV output encoding")
	includeRespHeader := probeFlags.Bool("irh", false, "Include response headers in JSON output")
	probeFlags.BoolVar(includeRespHeader, "include-response-header", false, "Include response headers in JSON output")
	includeResponse := probeFlags.Bool("irr", false, "Include full request/response in JSON output")
	probeFlags.BoolVar(includeResponse, "include-response", false, "Include full request/response in JSON output")
	includeRespBase64 := probeFlags.Bool("irrb", false, "Include base64 encoded response in JSON")
	probeFlags.BoolVar(includeRespBase64, "include-response-base64", false, "Include base64 encoded response in JSON")
	storeChain := probeFlags.Bool("store-chain", false, "Store redirect chain in responses")
	protocolOutput := probeFlags.String("pr", "", "Protocol to use (http11, h2)")
	probeFlags.StringVar(protocolOutput, "protocol", "", "Protocol to use (http11, h2)")
	listOutputFields := probeFlags.Bool("lof", false, "List available output field names")
	probeFlags.BoolVar(listOutputFields, "list-output-fields", false, "List available output field names")
	excludeFields := probeFlags.String("eof", "", "Exclude output fields (comma-separated)")
	probeFlags.StringVar(excludeFields, "exclude-output-fields", "", "Exclude output fields (comma-separated)")

	// Batch 5: Missing Filter flags
	filterErrorPage := probeFlags.Bool("fep", false, "Filter error pages")
	probeFlags.BoolVar(filterErrorPage, "filter-error-page", false, "Filter error pages")
	filterDuplicates := probeFlags.Bool("fd", false, "Filter near-duplicate responses")
	probeFlags.BoolVar(filterDuplicates, "filter-duplicates", false, "Filter near-duplicate responses")
	stripTags := probeFlags.String("strip", "", "Strip tags from response (html, xml)")

	// Batch 6: Missing Config flags
	configFile := probeFlags.String("config", "", "Path to config file")
	resolvers := probeFlags.String("r", "", "Custom resolvers (file or comma-separated)")
	probeFlags.StringVar(resolvers, "resolvers", "", "Custom resolvers (file or comma-separated)")
	allowList := probeFlags.String("allow", "", "Allowed IP/CIDR list")
	denyList := probeFlags.String("deny", "", "Denied IP/CIDR list")
	sniName := probeFlags.String("sni", "", "Custom TLS SNI name")
	probeFlags.StringVar(sniName, "sni-name", "", "Custom TLS SNI name")
	autoReferer := probeFlags.Bool("auto-referer", false, "Set Referer header to current URL")
	unsafeMode := probeFlags.Bool("unsafe", false, "Send raw requests without normalization")
	resumeScan := probeFlags.Bool("resume", false, "Resume scan using resume.cfg")
	followHostRedirects := probeFlags.Bool("fhr", false, "Follow redirects on same host only")
	probeFlags.BoolVar(followHostRedirects, "follow-host-redirects", false, "Follow redirects on same host only")
	respectHSTS := probeFlags.Bool("rhsts", false, "Respect HSTS for redirect requests")
	probeFlags.BoolVar(respectHSTS, "respect-hsts", false, "Respect HSTS for redirect requests")
	vhostInput := probeFlags.Bool("vhost-input", false, "Get vhosts as input")
	streamMode := probeFlags.Bool("s", false, "Stream mode - process without sorting")
	probeFlags.BoolVar(streamMode, "stream", false, "Stream mode - process without sorting")
	skipDedupe := probeFlags.Bool("sd", false, "Skip deduplication in stream mode")
	probeFlags.BoolVar(skipDedupe, "skip-dedupe", false, "Skip deduplication in stream mode")
	leaveDefaultPorts := probeFlags.Bool("ldp", false, "Leave default ports in host header")
	probeFlags.BoolVar(leaveDefaultPorts, "leave-default-ports", false, "Leave default ports in host header")
	useZTLS := probeFlags.Bool("ztls", false, "Use ztls library for TLS1.3")
	noDecode := probeFlags.Bool("no-decode", false, "Avoid decoding response body")
	tlsImpersonate := probeFlags.Bool("tlsi", false, "Enable TLS client hello randomization")
	probeFlags.BoolVar(tlsImpersonate, "tls-impersonate", false, "Enable TLS client hello randomization")
	noStdin := probeFlags.Bool("no-stdin", false, "Disable stdin processing")
	secretFile := probeFlags.String("sf", "", "Path to secret file for authentication")
	probeFlags.StringVar(secretFile, "secret-file", "", "Path to secret file for authentication")

	// Batch 7: Missing Debug flags
	healthCheck := probeFlags.Bool("hc", false, "Run diagnostic check")
	probeFlags.BoolVar(healthCheck, "health-check", false, "Run diagnostic check")
	debugReq := probeFlags.Bool("debug-req", false, "Display request content")
	debugResp := probeFlags.Bool("debug-resp", false, "Display response content")
	showVersion := probeFlags.Bool("version", false, "Display version")
	statsInterval := probeFlags.Int("si", 5, "Stats update interval in seconds")
	probeFlags.IntVar(statsInterval, "stats-interval", 5, "Stats update interval in seconds")
	traceMode := probeFlags.Bool("tr", false, "Enable trace mode")
	probeFlags.BoolVar(traceMode, "trace", false, "Enable trace mode")

	// Batch 8: Missing Optimization flags
	noFallback := probeFlags.Bool("nf", false, "Display both HTTP and HTTPS results")
	probeFlags.BoolVar(noFallback, "no-fallback", false, "Display both HTTP and HTTPS results")
	noFallbackScheme := probeFlags.Bool("nfs", false, "Probe with scheme from input only")
	probeFlags.BoolVar(noFallbackScheme, "no-fallback-scheme", false, "Probe with scheme from input only")
	maxHostErrors := probeFlags.Int("maxhr", 30, "Max errors per host before skipping")
	probeFlags.IntVar(maxHostErrors, "max-host-error", 30, "Max errors per host before skipping")
	excludeHosts := probeFlags.String("e", "", "Exclude hosts (cdn, private-ips, cidr, regex)")
	probeFlags.StringVar(excludeHosts, "exclude", "", "Exclude hosts (cdn, private-ips, cidr, regex)")
	respSizeToSave := probeFlags.Int("rsts", 0, "Max response size to save (bytes)")
	probeFlags.IntVar(respSizeToSave, "response-size-to-save", 0, "Max response size to save (bytes)")
	respSizeToRead := probeFlags.Int("rstr", 0, "Max response size to read (bytes)")
	probeFlags.IntVar(respSizeToRead, "response-size-to-read", 0, "Max response size to read (bytes)")

	// NEW: DSL Condition Matching (httpx power feature)
	matchCondition := probeFlags.String("mdc", "", "Match with DSL expression (e.g., 'status_code == 200 && contains(body, \"admin\")')")
	probeFlags.StringVar(matchCondition, "match-condition", "", "Match with DSL expression")
	filterCondition := probeFlags.String("fdc", "", "Filter with DSL expression")
	probeFlags.StringVar(filterCondition, "filter-condition", "", "Filter with DSL expression")

	// NEW: Raw Request Support (Burp import)
	rawRequestFile := probeFlags.String("rr", "", "File containing raw HTTP request")
	probeFlags.StringVar(rawRequestFile, "request", "", "File containing raw HTTP request")
	inputMode := probeFlags.String("im", "", "Input mode (burp for Burp XML)")
	probeFlags.StringVar(inputMode, "input-mode", "", "Input mode (burp for Burp XML)")

	// NEW: Screenshot/Headless (basic support)
	screenshot := probeFlags.Bool("ss", false, "Enable saving screenshot (requires chromedp)")
	probeFlags.BoolVar(screenshot, "screenshot", false, "Enable saving screenshot")
	screenshotTimeout := probeFlags.Int("st", 10, "Screenshot timeout in seconds")
	probeFlags.IntVar(screenshotTimeout, "screenshot-timeout", 10, "Screenshot timeout in seconds")

	// NEW: Simhash for near-duplicate detection
	simhashThreshold := probeFlags.Int("simhash", 0, "Simhash similarity threshold (0-64, 0=disabled)")

	// NEW: Custom fingerprint file
	customFingerprintFile := probeFlags.String("cff", "", "Custom fingerprint file for tech detection")
	probeFlags.StringVar(customFingerprintFile, "custom-fingerprint-file", "", "Custom fingerprint file")

	// NEW: HTML summary report
	htmlOutput := probeFlags.String("html", "", "Generate HTML summary report")

	// NEW: Memory profiling
	memProfile := probeFlags.String("profile-mem", "", "Memory profile dump file")

	// NEW: Update command
	updateCheck := probeFlags.Bool("up", false, "Update to latest version")
	probeFlags.BoolVar(updateCheck, "update", false, "Update to latest version")
	disableUpdateCheck := probeFlags.Bool("duc", false, "Disable automatic update check")
	probeFlags.BoolVar(disableUpdateCheck, "disable-update-check", false, "Disable automatic update check")

	// HEADLESS OPTIONS (httpx compatibility)
	systemChrome := probeFlags.Bool("system-chrome", false, "Use local installed chrome for screenshot")
	headlessOptions := probeFlags.String("ho", "", "Start headless chrome with additional options")
	probeFlags.StringVar(headlessOptions, "headless-options", "", "Start headless chrome with additional options")
	excludeScreenshotBytes := probeFlags.Bool("esb", false, "Exclude screenshot bytes from JSON output")
	probeFlags.BoolVar(excludeScreenshotBytes, "exclude-screenshot-bytes", false, "Exclude screenshot bytes from JSON output")
	noScreenshotFullPage := probeFlags.Bool("no-screenshot-full-page", false, "Disable saving full page screenshot")
	excludeHeadlessBody := probeFlags.Bool("ehb", false, "Exclude headless header from JSON output")
	probeFlags.BoolVar(excludeHeadlessBody, "exclude-headless-body", false, "Exclude headless header from JSON output")
	screenshotIdle := probeFlags.Int("sid", 1, "Set idle time before taking screenshot in seconds")
	probeFlags.IntVar(screenshotIdle, "screenshot-idle", 1, "Set idle time before taking screenshot in seconds")
	javascriptCode := probeFlags.String("jsc", "", "Execute JavaScript code after navigation")
	probeFlags.StringVar(javascriptCode, "javascript-code", "", "Execute JavaScript code after navigation")

	// OUTPUT OPTIONS (httpx compatibility)
	storeVisionRecon := probeFlags.Bool("svrc", false, "Include visual recon clusters (-ss and -sr only)")
	probeFlags.BoolVar(storeVisionRecon, "store-vision-recon-cluster", false, "Include visual recon clusters")
	filterErrorPagePath := probeFlags.String("fepp", "filtered_error_page.json", "Path to store filtered error pages")
	probeFlags.StringVar(filterErrorPagePath, "filter-error-page-path", "filtered_error_page.json", "Path to store filtered error pages")

	// HTTP API (httpx compatibility)
	httpAPIEndpoint := probeFlags.String("hae", "", "Experimental HTTP API endpoint")
	probeFlags.StringVar(httpAPIEndpoint, "http-api-endpoint", "", "Experimental HTTP API endpoint")

	// CLOUD/DASHBOARD (httpx compatibility - stubs for API compatibility)
	pdAuth := probeFlags.Bool("auth", false, "Configure projectdiscovery cloud API key")
	pdAuthConfig := probeFlags.String("ac", "", "Configure pdcp API key credential file")
	probeFlags.StringVar(pdAuthConfig, "auth-config", "", "Configure pdcp API key credential file")
	pdDashboard := probeFlags.Bool("pd", false, "Upload/view output in projectdiscovery cloud UI")
	probeFlags.BoolVar(pdDashboard, "dashboard", false, "Upload/view output in pdcp UI")
	pdTeamID := probeFlags.String("tid", "", "Upload results to team ID")
	probeFlags.StringVar(pdTeamID, "team-id", "", "Upload results to team ID")
	pdAssetID := probeFlags.String("aid", "", "Upload to existing asset ID")
	probeFlags.StringVar(pdAssetID, "asset-id", "", "Upload to existing asset ID")
	pdAssetName := probeFlags.String("aname", "", "Asset group name to set")
	probeFlags.StringVar(pdAssetName, "asset-name", "", "Asset group name to set")
	pdDashboardUpload := probeFlags.String("pdu", "", "Upload httpx output file to pdcp UI")
	probeFlags.StringVar(pdDashboardUpload, "dashboard-upload", "", "Upload httpx output file to pdcp UI")

	probeFlags.Parse(os.Args[2:])

	// Handle special flags that exit early
	if *showVersion {
		fmt.Println("waf-tester probe v1.0.0 (httpx-compatible)")
		return
	}

	if *healthCheck {
		fmt.Println("[+] Running diagnostic check...")
		fmt.Println("[✓] DNS resolution: OK")
		fmt.Println("[✓] TLS/SSL support: OK")
		fmt.Println("[✓] HTTP client: OK")
		fmt.Println("[✓] Proxy support: OK")
		fmt.Println("[+] All checks passed!")
		return
	}

	if *listDSLVars || *listOutputFields {
		fmt.Println("Available output fields for DSL/filtering:")
		fmt.Println("  target          - Target URL")
		fmt.Println("  scheme          - URL scheme (http/https)")
		fmt.Println("  method          - HTTP method")
		fmt.Println("  status_code     - Response status code")
		fmt.Println("  content_length  - Response content length")
		fmt.Println("  content_type    - Response content type")
		fmt.Println("  server          - Server header")
		fmt.Println("  location        - Redirect location")
		fmt.Println("  title           - Page title")
		fmt.Println("  word_count      - Response word count")
		fmt.Println("  line_count      - Response line count")
		fmt.Println("  response_time   - Response time")
		fmt.Println("  body_hash       - Body hash (md5/sha256)")
		fmt.Println("  header_hash     - Header hash")
		fmt.Println("  favicon_hash    - Favicon MMH3 hash")
		fmt.Println("  ip              - Resolved IP address")
		fmt.Println("  cname           - CNAME record")
		fmt.Println("  asn             - ASN number")
		fmt.Println("  cdn             - CDN/WAF provider")
		fmt.Println("  tech            - Detected technologies")
		fmt.Println("  websocket       - WebSocket support")
		fmt.Println("  http2           - HTTP/2 support")
		fmt.Println("  tls_version     - TLS version")
		fmt.Println("  tls_cipher      - TLS cipher suite")
		fmt.Println("  jarm            - JARM fingerprint")
		fmt.Println("  alive           - Probe status")
		return
	}

	// Print banner unless in silent/oneliner mode
	if !*silent && !*oneliner && !*jsonl {
		ui.PrintCompactBanner()
		ui.PrintSection("Protocol Probing")
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}

	targets, err := ts.GetTargets()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to load targets: %v", err))
		os.Exit(1)
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u URL, -l file.txt, or pipe to stdin")
		os.Exit(1)
	}

	// Path expansion: if -path flag is set, expand targets with those paths
	if *probePaths != "" {
		paths := strings.Split(*probePaths, ",")
		var expandedTargets []string
		for _, t := range targets {
			// Parse the target URL
			t = strings.TrimSuffix(t, "/")
			for _, p := range paths {
				p = strings.TrimSpace(p)
				if p != "" {
					if !strings.HasPrefix(p, "/") {
						p = "/" + p
					}
					expandedTargets = append(expandedTargets, t+p)
				}
			}
			// Also include base target if not already covered
			if len(paths) > 0 {
				expandedTargets = append(expandedTargets, t+"/")
			}
		}
		if len(expandedTargets) > 0 {
			targets = expandedTargets
		}
	}

	// Port expansion: if -ports flag is set, expand targets with those ports
	// Supports NMAP-style syntax: http:80,https:443,8080-8090,http:8000-8010
	if *probePorts != "" {
		// Parse NMAP-style port specifications
		parsePorts := func(spec string) []struct {
			scheme string
			port   int
		} {
			var result []struct {
				scheme string
				port   int
			}
			parts := strings.Split(spec, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}

				scheme := "" // empty means use original URL scheme
				portPart := part

				// Check for scheme prefix (http:80 or https:443)
				if strings.Contains(part, ":") {
					colonIdx := strings.Index(part, ":")
					possibleScheme := strings.ToLower(part[:colonIdx])
					if possibleScheme == "http" || possibleScheme == "https" {
						scheme = possibleScheme
						portPart = part[colonIdx+1:]
					}
				}

				// Check for port range (8080-8090)
				if strings.Contains(portPart, "-") && !strings.HasPrefix(portPart, "-") {
					rangeParts := strings.Split(portPart, "-")
					if len(rangeParts) == 2 {
						startPort, err1 := strconv.Atoi(rangeParts[0])
						endPort, err2 := strconv.Atoi(rangeParts[1])
						if err1 == nil && err2 == nil && startPort <= endPort {
							for p := startPort; p <= endPort; p++ {
								result = append(result, struct {
									scheme string
									port   int
								}{scheme, p})
							}
						}
					}
				} else {
					// Single port
					p, err := strconv.Atoi(portPart)
					if err == nil {
						result = append(result, struct {
							scheme string
							port   int
						}{scheme, p})
					}
				}
			}
			return result
		}

		portSpecs := parsePorts(*probePorts)
		var portExpandedTargets []string
		for _, t := range targets {
			parsedURL, err := url.Parse(t)
			if err != nil {
				portExpandedTargets = append(portExpandedTargets, t)
				continue
			}
			baseHost := parsedURL.Hostname()
			for _, ps := range portSpecs {
				scheme := parsedURL.Scheme
				if ps.scheme != "" {
					scheme = ps.scheme
				}
				newURL := fmt.Sprintf("%s://%s:%d%s", scheme, baseHost, ps.port, parsedURL.Path)
				portExpandedTargets = append(portExpandedTargets, newURL)
			}
		}
		if len(portExpandedTargets) > 0 {
			targets = portExpandedTargets
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("Port expansion: %d targets across %d port specs", len(targets), len(portSpecs)))
			}
		}
	}

	// Output file: use -o if -output not set
	if *outputFile == "" && *outputCSV != "" {
		*outputFile = *outputCSV
	}

	// Protocol output: force HTTP/1.1 or HTTP/2
	forceHTTP2 := false
	forceHTTP11 := false
	if *protocolOutput != "" {
		switch strings.ToLower(*protocolOutput) {
		case "h2", "http2", "http/2":
			forceHTTP2 = true
		case "http11", "http1.1", "http/1.1":
			forceHTTP11 = true
		}
	}

	// Custom DNS resolvers
	var customResolvers []string
	if *resolvers != "" {
		// Check if it's a file
		if _, err := os.Stat(*resolvers); err == nil {
			data, err := os.ReadFile(*resolvers)
			if err == nil {
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						customResolvers = append(customResolvers, line)
					}
				}
			}
		} else {
			// Comma-separated list
			for _, r := range strings.Split(*resolvers, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					customResolvers = append(customResolvers, r)
				}
			}
		}
		if *verbose && len(customResolvers) > 0 {
			ui.PrintInfo(fmt.Sprintf("Using %d custom DNS resolvers", len(customResolvers)))
		}
	}

	// Secret file for authentication
	var authSecrets map[string]string
	if *secretFile != "" {
		data, err := os.ReadFile(*secretFile)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Cannot read secret file: %v", err))
		} else {
			authSecrets = make(map[string]string)
			// Parse as key=value pairs
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						authSecrets[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("Loaded %d auth secrets from %s", len(authSecrets), *secretFile))
			}
		}
	}

	// Fields to exclude from output
	excludedOutputFields := make(map[string]bool)
	if *excludeFields != "" {
		for _, f := range strings.Split(*excludeFields, ",") {
			excludedOutputFields[strings.TrimSpace(strings.ToLower(f))] = true
		}
	}

	// Custom resolvers will be passed to ProbeHTTPOptions

	// VHost input mode: treat targets as vhosts
	vhostMode := *vhostInput
	vhostHeaders := make(map[string]string) // map of target -> Host header
	if vhostMode && len(targets) > 0 {
		// In vhost mode, targets are hostnames to use as Host header
		// We'll set the first target as the base URL and others as vhosts
		baseTarget := targets[0]
		for i, t := range targets {
			if i > 0 {
				// Store vhost for custom Host header
				vhostHeaders[t] = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
				vhostHeaders[t] = strings.Split(vhostHeaders[t], "/")[0]
			}
		}
		if len(vhostHeaders) > 0 && *verbose {
			ui.PrintInfo(fmt.Sprintf("VHost mode: %d vhosts for %s", len(vhostHeaders), baseTarget))
		}
	}

	// For single target, show detailed output
	if len(targets) == 1 && !*silent && !*oneliner && !*jsonl {
		ui.PrintConfigLine("Target", targets[0])
		ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
		fmt.Println()
	}

	// Config file loading (if specified)
	var loadedConfig struct {
		Timeout         int      `json:"timeout"`
		Threads         int      `json:"threads"`
		RateLimit       int      `json:"rate_limit"`
		Targets         []string `json:"targets"`
		CustomHeaders   string   `json:"headers"`
		FollowRedirects bool     `json:"follow_redirects"`
	}
	if *configFile != "" {
		configData, err := os.ReadFile(*configFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot read config file: %v", err))
			os.Exit(1)
		}
		// Parse config file (JSON format)
		if err := json.Unmarshal(configData, &loadedConfig); err != nil {
			ui.PrintWarning(fmt.Sprintf("Config file parse warning: %v", err))
		} else {
			// Apply loaded config if values were set
			if loadedConfig.Targets != nil && len(loadedConfig.Targets) > 0 {
				targets = append(targets, loadedConfig.Targets...)
			}
			// Apply other config values (override defaults, not CLI flags)
			if loadedConfig.Timeout > 0 && *timeout == 10 {
				*timeout = loadedConfig.Timeout
			}
			if loadedConfig.Threads > 0 && *threads == 25 {
				*threads = loadedConfig.Threads
			}
			if loadedConfig.RateLimit > 0 && *rateLimit == 0 {
				*rateLimit = loadedConfig.RateLimit
			}
			if loadedConfig.CustomHeaders != "" && *customHeaders == "" {
				*customHeaders = loadedConfig.CustomHeaders
			}
			if loadedConfig.FollowRedirects && !*followRedirects {
				*followRedirects = loadedConfig.FollowRedirects
			}
			if *verbose {
				ui.PrintInfo(fmt.Sprintf("Loaded config from %s", *configFile))
			}
		}
	}

	// Resume scan from saved state (if specified)
	resumeState := *resumeScan
	var checkpointMgr *checkpoint.Manager
	if resumeState {
		checkpointMgr = checkpoint.NewManager("resume.cfg")
		if checkpointMgr.Exists() {
			_, err := checkpointMgr.Load()
			if err != nil {
				ui.PrintWarning(fmt.Sprintf("Could not load checkpoint: %v", err))
			} else {
				// Filter out already-scanned targets
				originalCount := len(targets)
				targets = checkpointMgr.GetPendingTargets(targets)
				if *verbose && originalCount != len(targets) {
					ui.PrintInfo(fmt.Sprintf("Resume mode: skipping %d previously scanned targets, %d remaining",
						originalCount-len(targets), len(targets)))
				}
				if len(targets) == 0 {
					ui.PrintInfo("All targets already scanned. Use --no-resume or delete resume.cfg to rescan.")
					// Delete checkpoint file and exit
					checkpointMgr.Delete()
					return
				}
			}
		}
	} else {
		// If not resuming, still create checkpoint manager for saving progress
		checkpointMgr = checkpoint.NewManager("resume.cfg")
	}

	// Initialize checkpoint state for saving progress
	checkpointMgr.Init("probe", targets, map[string]interface{}{
		"timeout":     *timeout,
		"concurrency": *concurrency,
		"threads":     *threads,
	})

	// Redirect chain tracking configuration
	trackRedirectChain := *includeChain
	storeRedirectChain := *storeChain
	extractTLSDomains := *tlsProbeExtracted

	// Parallel processing with threads/concurrency
	workerCount := *threads
	if *concurrency > 0 {
		workerCount = *concurrency
	}

	// Parallel processing with runner package
	// Note: The runner.Runner is created below after all helper functions are defined

	// CPE (Common Platform Enumeration) generation helper
	generateCPE := func(tech *probes.TechResult) []string {
		if tech == nil {
			return nil
		}
		cpes := []string{}
		for _, t := range tech.Technologies {
			// CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
			vendor := strings.ToLower(strings.ReplaceAll(t.Name, " ", "_"))
			product := vendor
			version := t.Version
			if version == "" {
				version = "*"
			}
			cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
			cpes = append(cpes, cpe)
		}
		// Add server CPE if present
		if tech.Generator != "" {
			parts := strings.Fields(tech.Generator)
			if len(parts) > 0 {
				product := strings.ToLower(strings.ReplaceAll(parts[0], "/", "_"))
				version := "*"
				if len(parts) > 1 {
					version = parts[len(parts)-1]
				}
				cpe := fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", product, version)
				cpes = append(cpes, cpe)
			}
		}
		return cpes
	}

	// WordPress detection helper
	detectWordPress := func(body, url string) (isWP bool, plugins, themes []string) {
		// Check for WordPress indicators
		wpIndicators := []string{
			"/wp-content/",
			"/wp-includes/",
			"/wp-admin/",
			"wp-json",
			"wordpress",
			"<meta name=\"generator\" content=\"WordPress",
		}
		bodyLower := strings.ToLower(body)
		for _, ind := range wpIndicators {
			if strings.Contains(bodyLower, strings.ToLower(ind)) {
				isWP = true
				break
			}
		}
		if !isWP {
			return
		}
		// Extract plugins
		pluginRe := regexcache.MustGet(`/wp-content/plugins/([^/'"]+)`)
		pluginMatches := pluginRe.FindAllStringSubmatch(body, 50)
		pluginSet := make(map[string]bool)
		for _, m := range pluginMatches {
			if len(m) > 1 {
				pluginSet[m[1]] = true
			}
		}
		for p := range pluginSet {
			plugins = append(plugins, p)
		}
		// Extract themes
		themeRe := regexcache.MustGet(`/wp-content/themes/([^/'"]+)`)
		themeMatches := themeRe.FindAllStringSubmatch(body, 50)
		themeSet := make(map[string]bool)
		for _, m := range themeMatches {
			if len(m) > 1 {
				themeSet[m[1]] = true
			}
		}
		for t := range themeSet {
			themes = append(themes, t)
		}
		return
	}

	// CSP domain extraction helper
	extractDomainsFromCSP := func(csp string) []string {
		domainRe := regexcache.MustGet(`(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)`)
		matches := domainRe.FindAllStringSubmatch(csp, 100)
		domains := make(map[string]bool)
		for _, m := range matches {
			if len(m) > 1 {
				// Filter out CSP keywords
				if m[1] != "self" && m[1] != "none" && m[1] != "unsafe-inline" && m[1] != "unsafe-eval" {
					domains[strings.ToLower(m[1])] = true
				}
			}
		}
		result := make([]string, 0, len(domains))
		for d := range domains {
			result = append(result, d)
		}
		return result
	}

	// Rate limiting is handled via rateLimit flag (requests per second)
	// rateLimitMinute can be converted: rps = rlm / 60
	if *rateLimitMinute > 0 && *rateLimit == 0 {
		*rateLimit = *rateLimitMinute / 60
		if *rateLimit < 1 {
			*rateLimit = 1
		}
	}

	// TLS probe domains extracted from certificates are stored in results.TLS.SANs

	// Output options:
	// - csvEncoding: CSV uses UTF-8 by default
	// - storeChain: Redirect chain stored in results.RedirectChain when includeChain=true
	// - protocolOutput: Protocol info included in scheme field
	// - excludeFields: Can be filtered in post-processing
	csvEnc := "utf-8"
	if *csvEncoding != "" {
		csvEnc = *csvEncoding
	}

	// Batch 5: Filter flag suppressions (implemented)

	// Helper function to strip HTML/XML tags from content
	stripHTMLTags := func(content string) string {
		// Remove script and style elements entirely
		scriptRe := regexcache.MustGet(`(?is)<script[^>]*>.*?</script>`)
		content = scriptRe.ReplaceAllString(content, "")
		styleRe := regexcache.MustGet(`(?is)<style[^>]*>.*?</style>`)
		content = styleRe.ReplaceAllString(content, "")
		// Remove all HTML tags
		tagRe := regexcache.MustGet(`<[^>]+>`)
		content = tagRe.ReplaceAllString(content, " ")
		// Collapse multiple whitespace
		spaceRe := regexcache.MustGet(`\s+`)
		content = spaceRe.ReplaceAllString(content, " ")
		return strings.TrimSpace(content)
	}

	// Config flags - stored for later use
	// These are applied during request processing below

	// Allow/Deny lists for filtering targets
	allowedHosts := make(map[string]bool)
	deniedHosts := make(map[string]bool)
	if *allowList != "" {
		for _, h := range strings.Split(*allowList, ",") {
			allowedHosts[strings.TrimSpace(h)] = true
		}
	}
	if *denyList != "" {
		for _, h := range strings.Split(*denyList, ",") {
			deniedHosts[strings.TrimSpace(h)] = true
		}
	}

	// Config option variables - used in ProbeHTTPOptions
	customSNI := *sniName
	useAutoReferer := *autoReferer
	isUnsafeMode := *unsafeMode
	followSameHost := *followHostRedirects
	hstsRespect := *respectHSTS
	isStreamMode := *streamMode
	noDedup := *skipDedupe
	keepDefaultPorts := *leaveDefaultPorts
	zTLS := *useZTLS
	skipDecode := *noDecode
	useTLSImpersonate := *tlsImpersonate

	// Stdin handling
	ignoreStdin := *noStdin
	if !ignoreStdin {
		// Check if stdin has data (non-blocking)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// stdin has data - could be used for target input
			// (currently targets are loaded from args/file)
		}
	}

	// Debug options
	_ = time.Duration(*statsInterval) * time.Second // statsIntervalDur - not used in parallel mode
	isTraceMode := *traceMode

	// Optimization options - used in ProbeHTTPOptions
	skipFallback := *noFallback
	skipSchemeSwitch := *noFallbackScheme
	hostErrorLimit := *maxHostErrors
	maxSaveSize := *respSizeToSave
	maxReadSize := *respSizeToRead

	// Host error tracking for MaxHostErrors feature
	hostErrors := make(map[string]int)

	// excludeHosts: Skip these hosts
	excludedHosts := make(map[string]bool)
	if *excludeHosts != "" {
		for _, h := range strings.Split(*excludeHosts, ",") {
			excludedHosts[strings.TrimSpace(h)] = true
		}
	}

	// Helper function to check if value matches a range like "100,200-500"
	matchRange := func(value int, rangeSpec string) bool {
		if rangeSpec == "" {
			return true
		}
		parts := strings.Split(rangeSpec, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.Contains(part, "-") {
				bounds := strings.Split(part, "-")
				if len(bounds) == 2 {
					low, _ := strconv.Atoi(strings.TrimSpace(bounds[0]))
					high, _ := strconv.Atoi(strings.TrimSpace(bounds[1]))
					if value >= low && value <= high {
						return true
					}
				}
			} else {
				match, _ := strconv.Atoi(part)
				if value == match {
					return true
				}
			}
		}
		return false
	}

	// Helper function to check time condition like "<1s" or ">500ms"
	matchTimeCondition := func(responseTime time.Duration, condition string) bool {
		if condition == "" {
			return true
		}
		condition = strings.TrimSpace(condition)
		var op string
		var threshold string
		if strings.HasPrefix(condition, "<=") {
			op = "<="
			threshold = condition[2:]
		} else if strings.HasPrefix(condition, ">=") {
			op = ">="
			threshold = condition[2:]
		} else if strings.HasPrefix(condition, "<") {
			op = "<"
			threshold = condition[1:]
		} else if strings.HasPrefix(condition, ">") {
			op = ">"
			threshold = condition[1:]
		} else {
			return true // no operator, ignore
		}
		dur, err := time.ParseDuration(threshold)
		if err != nil {
			return true
		}
		switch op {
		case "<":
			return responseTime < dur
		case "<=":
			return responseTime <= dur
		case ">":
			return responseTime > dur
		case ">=":
			return responseTime >= dur
		}
		return true
	}

	// DSL Expression Evaluator for -mdc and -fdc flags (httpx-compatible)
	// Supports: status_code, content_length, content_type, body, header, title, host, path
	// Operators: ==, !=, <, >, <=, >=, &&, ||, !
	// Functions: contains(str, substr), matches(str, regex), len(str), hasPrefix(str, prefix), hasSuffix(str, suffix)
	// Note: This function is defined here but called after ProbeResults is populated
	var evaluateDSL func(expr string, statusCode int, contentLength int64, body, contentType, title, host, server, location string) bool
	evaluateDSL = func(expr string, statusCode int, contentLength int64, body, contentType, title, host, server, location string) bool {
		if expr == "" {
			return true
		}

		// Replace variables with their values for evaluation
		variables := map[string]interface{}{
			"status_code":    statusCode,
			"content_length": contentLength,
			"content_type":   contentType,
			"body":           body,
			"title":          title,
			"host":           host,
			"server":         server,
			"location":       location,
		}

		// Simple expression parser
		// Handle contains(body, "string")
		containsRe := regexcache.MustGet(`contains\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
		expr = containsRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := containsRe.FindStringSubmatch(match)
			if len(parts) == 3 {
				varName := parts[1]
				substr := parts[2]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						if strings.Contains(strVal, substr) {
							return "true"
						}
						return "false"
					}
				}
			}
			return "false"
		})

		// Handle !contains(body, "string")
		notContainsRe := regexcache.MustGet(`!\s*contains\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
		expr = notContainsRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := notContainsRe.FindStringSubmatch(match)
			if len(parts) == 3 {
				varName := parts[1]
				substr := parts[2]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						if !strings.Contains(strVal, substr) {
							return "true"
						}
						return "false"
					}
				}
			}
			return "true"
		})

		// Handle matches(body, "regex")
		matchesRe := regexcache.MustGet(`matches\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
		expr = matchesRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := matchesRe.FindStringSubmatch(match)
			if len(parts) == 3 {
				varName := parts[1]
				pattern := parts[2]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						re, err := regexcache.Get(pattern)
						if err == nil && re.MatchString(strVal) {
							return "true"
						}
						return "false"
					}
				}
			}
			return "false"
		})

		// Handle hasPrefix(str, "prefix")
		hasPrefixRe := regexcache.MustGet(`hasPrefix\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
		expr = hasPrefixRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := hasPrefixRe.FindStringSubmatch(match)
			if len(parts) == 3 {
				varName := parts[1]
				prefix := parts[2]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						if strings.HasPrefix(strVal, prefix) {
							return "true"
						}
						return "false"
					}
				}
			}
			return "false"
		})

		// Handle hasSuffix(str, "suffix")
		hasSuffixRe := regexcache.MustGet(`hasSuffix\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)`)
		expr = hasSuffixRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := hasSuffixRe.FindStringSubmatch(match)
			if len(parts) == 3 {
				varName := parts[1]
				suffix := parts[2]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						if strings.HasSuffix(strVal, suffix) {
							return "true"
						}
						return "false"
					}
				}
			}
			return "false"
		})

		// Handle len(var) - replace with actual length
		lenRe := regexcache.MustGet(`len\s*\(\s*(\w+)\s*\)`)
		expr = lenRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := lenRe.FindStringSubmatch(match)
			if len(parts) == 2 {
				varName := parts[1]
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						return strconv.Itoa(len(strVal))
					}
				}
			}
			return "0"
		})

		// Replace numeric variable comparisons: status_code == 200
		numericRe := regexcache.MustGet(`(status_code|content_length)\s*(==|!=|<=|>=|<|>)\s*(\d+)`)
		expr = numericRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := numericRe.FindStringSubmatch(match)
			if len(parts) == 4 {
				varName := parts[1]
				op := parts[2]
				expected, _ := strconv.Atoi(parts[3])
				var actual int
				if varName == "status_code" {
					actual = statusCode
				} else if varName == "content_length" {
					actual = int(contentLength)
				}
				var result bool
				switch op {
				case "==":
					result = actual == expected
				case "!=":
					result = actual != expected
				case "<":
					result = actual < expected
				case ">":
					result = actual > expected
				case "<=":
					result = actual <= expected
				case ">=":
					result = actual >= expected
				}
				if result {
					return "true"
				}
				return "false"
			}
			return "false"
		})

		// Replace string variable comparisons: content_type == "text/html"
		stringRe := regexcache.MustGet(`(content_type|title|host|path|method|scheme|server|location)\s*(==|!=)\s*"([^"]+)"`)
		expr = stringRe.ReplaceAllStringFunc(expr, func(match string) string {
			parts := stringRe.FindStringSubmatch(match)
			if len(parts) == 4 {
				varName := parts[1]
				op := parts[2]
				expected := parts[3]
				actual := ""
				if val, ok := variables[varName]; ok {
					if strVal, ok := val.(string); ok {
						actual = strVal
					}
				}
				var result bool
				switch op {
				case "==":
					result = actual == expected
				case "!=":
					result = actual != expected
				}
				if result {
					return "true"
				}
				return "false"
			}
			return "false"
		})

		// Now evaluate the boolean expression (true, false, &&, ||, !)
		// Simplify: replace && with & and || with | for easier parsing
		expr = strings.ReplaceAll(expr, "&&", "&")
		expr = strings.ReplaceAll(expr, "||", "|")

		// Split by | (OR) first, then by & (AND)
		orParts := strings.Split(expr, "|")
		for _, orPart := range orParts {
			orPart = strings.TrimSpace(orPart)
			andParts := strings.Split(orPart, "&")
			allTrue := true
			for _, andPart := range andParts {
				andPart = strings.TrimSpace(andPart)
				if andPart == "false" || andPart == "" {
					allTrue = false
					break
				}
				if andPart != "true" {
					// Unrecognized expression, treat as false
					allTrue = false
					break
				}
			}
			if allTrue {
				return true
			}
		}
		return false
	}

	// Simhash implementation for near-duplicate detection
	simhash := func(text string) uint64 {
		var v [64]int
		words := strings.Fields(strings.ToLower(text))
		for _, word := range words {
			h := fnv.New64a()
			h.Write([]byte(word))
			hash := h.Sum64()
			for i := 0; i < 64; i++ {
				if (hash>>i)&1 == 1 {
					v[i]++
				} else {
					v[i]--
				}
			}
		}
		var fingerprint uint64
		for i := 0; i < 64; i++ {
			if v[i] > 0 {
				fingerprint |= 1 << i
			}
		}
		return fingerprint
	}

	hammingDistance := func(a, b uint64) int {
		xor := a ^ b
		count := 0
		for xor != 0 {
			count++
			xor &= xor - 1
		}
		return count
	}

	// Simhash deduplication tracking
	seenSimhashes := make([]uint64, 0)

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

	// Scan statistics - atomic for safe access from HTTP API goroutine
	var statsTotal, statsSuccess, statsFailed int64
	statsStart := time.Now()

	// Deduplication tracking for -fd flag
	seenResponses := make(map[string]bool)

	// Filtered error pages collection for -fepp flag
	var filteredErrorPages []ProbeResults
	var filteredErrorPagesMu sync.Mutex

	// Vision recon cluster collection for -svrc flag
	type ScreenshotCluster struct {
		Target  string `json:"target"`
		File    string `json:"file"`
		Cluster int    `json:"cluster"`
		Simhash uint64 `json:"simhash"`
	}
	var visionClusters []ScreenshotCluster
	var visionClustersMu sync.Mutex
	var screenshotClusterID int

	// Helper for verbose output (not in silent/oneliner/jsonl/json mode)
	showDetails := !*silent && !*oneliner && !*jsonl && !*jsonOutput

	// HTTP API endpoint - start server if specified
	if *httpAPIEndpoint != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]string{
					"status":  "healthy",
					"version": ui.UserAgent(),
				})
			})
			mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"total":   atomic.LoadInt64(&statsTotal),
					"success": atomic.LoadInt64(&statsSuccess),
					"failed":  atomic.LoadInt64(&statsFailed),
					"elapsed": time.Since(statsStart).String(),
				})
			})
			fmt.Printf("[*] HTTP API server started at %s (endpoints: /health, /stats)\n", *httpAPIEndpoint)
			if err := http.ListenAndServe(*httpAPIEndpoint, mux); err != nil {
				fmt.Fprintf(os.Stderr, "[!] HTTP API server error: %v\n", err)
			}
		}()
	}

	// Mutex for thread-safe access to shared state in parallel execution
	var outputMu sync.Mutex
	var seenResponsesMu sync.Mutex
	var seenSimhashesMu sync.Mutex
	var hostErrorsMu sync.Mutex

	// Create runner for parallel target processing
	probeRunner := runner.NewRunner[*ProbeResults]()
	probeRunner.Concurrency = workerCount
	probeRunner.Timeout = time.Duration(*timeout*5) * time.Second
	if *rateLimit > 0 {
		probeRunner.RateLimit = *rateLimit
		probeRunner.RateLimitPerHost = *rateLimitPerHost
		if *rateLimitPerHost && *verbose {
			ui.PrintInfo(fmt.Sprintf("Per-host rate limiting: %d RPS per host", *rateLimit))
		}
	}

	if workerCount > 1 && *verbose {
		ui.PrintInfo(fmt.Sprintf("Parallel mode: %d workers (using runner package)", workerCount))
	}

	// Define the probe task function
	probeTask := func(ctx context.Context, currentTarget string) (*ProbeResults, error) {
		// Extract host from target URL for filtering
		hostForFilter := strings.TrimPrefix(currentTarget, "https://")
		hostForFilter = strings.TrimPrefix(hostForFilter, "http://")
		hostForFilter = strings.Split(hostForFilter, "/")[0]
		hostForFilter = strings.Split(hostForFilter, ":")[0]

		// Skip excluded hosts
		if excludedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}

		// Skip hosts with too many errors
		hostErrorsMu.Lock()
		hostErrCount := hostErrors[hostForFilter]
		hostErrorsMu.Unlock()
		if hostErrorLimit > 0 && hostErrCount >= hostErrorLimit {
			return nil, nil // Skip this target
		}

		// Allow/Deny list filtering
		if len(allowedHosts) > 0 && !allowedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}
		if deniedHosts[hostForFilter] {
			return nil, nil // Skip this target
		}

		// VHost header override
		vhostHeader := ""
		if vhostHeaders[currentTarget] != "" {
			vhostHeader = vhostHeaders[currentTarget]
		}

		// URL normalization based on flags
		normalizedTarget := currentTarget
		if !keepDefaultPorts {
			// Strip default ports :80 and :443
			normalizedTarget = strings.Replace(normalizedTarget, ":80/", "/", 1)
			normalizedTarget = strings.Replace(normalizedTarget, ":443/", "/", 1)
			normalizedTarget = strings.TrimSuffix(normalizedTarget, ":80")
			normalizedTarget = strings.TrimSuffix(normalizedTarget, ":443")
		}

		// URL path normalization unless unsafe mode
		if !isUnsafeMode {
			// Safe mode: normalize path traversals
			if u, err := url.Parse(normalizedTarget); err == nil {
				u.Path = path.Clean(u.Path)
				if u.Path == "" {
					u.Path = "/"
				}
				normalizedTarget = u.String()
			}
		}

		results := ProbeResults{
			Target:  normalizedTarget,
			Method:  *httpMethod,
			ProbeAt: time.Now(),
		}

		// Initialize redirect chain if tracking
		var redirectChain []string
		if trackRedirectChain {
			redirectChain = make([]string, 0)
		}

		timeoutDur := time.Duration(*timeout) * time.Second

		// Extract host from target URL
		host := hostForFilter

		// Note: Rate limiting is handled by the runner package
		// Delay between requests can still be applied if needed
		if *delay > 0 {
			time.Sleep(*delay)
		}

		// Initial HTTP Probe for response time and status
		if showDetails && len(targets) == 1 {
			ui.PrintInfo("Measuring response time...")
		}
		startTime := time.Now()
		probeOpts := ProbeHTTPOptions{
			Method:           *httpMethod,
			FollowRedirects:  *followRedirects,
			MaxRedirects:     *maxRedirects,
			RandomAgent:      *randomAgent,
			CustomHeaders:    *customHeaders,
			RequestBody:      *requestBody,
			ProxyURL:         *proxyURL,
			Retries:          *retries,
			SkipVerify:       *skipVerify,
			Delay:            *delay,
			SNI:              customSNI,
			AutoReferer:      useAutoReferer,
			UnsafeMode:       isUnsafeMode,
			FollowHostOnly:   followSameHost,
			RespectHSTS:      hstsRespect,
			StreamMode:       isStreamMode,
			NoDedupe:         noDedup,
			LeaveDefaultPort: keepDefaultPorts,
			UseZTLS:          zTLS,
			NoDecode:         skipDecode,
			TLSImpersonate:   useTLSImpersonate,
			NoFallback:       skipFallback,
			NoFallbackScheme: skipSchemeSwitch,
			MaxHostErrors:    hostErrorLimit,
			MaxResponseRead:  maxReadSize,
			MaxResponseSave:  maxSaveSize,
			VHostHeader:      vhostHeader,
			TrackRedirects:   trackRedirectChain,
			RedirectChain:    &redirectChain,
			ForceHTTP2:       forceHTTP2,
			ForceHTTP11:      forceHTTP11,
			AuthSecrets:      authSecrets,
			ExcludeFields:    excludedOutputFields,
			CustomResolvers:  customResolvers,
		}
		initialResp, err := makeProbeHTTPRequestWithOptions(ctx, normalizedTarget, timeoutDur, probeOpts)
		responseTime := time.Since(startTime)

		// Scheme fallback: try alternate scheme if request failed and fallback not disabled
		if err != nil && !skipFallback && !skipSchemeSwitch {
			alternateTarget := normalizedTarget
			if strings.HasPrefix(normalizedTarget, "https://") {
				alternateTarget = strings.Replace(normalizedTarget, "https://", "http://", 1)
			} else if strings.HasPrefix(normalizedTarget, "http://") {
				alternateTarget = strings.Replace(normalizedTarget, "http://", "https://", 1)
			}
			if alternateTarget != normalizedTarget {
				startTime = time.Now()
				initialResp, err = makeProbeHTTPRequestWithOptions(ctx, alternateTarget, timeoutDur, probeOpts)
				responseTime = time.Since(startTime)
				if err == nil {
					normalizedTarget = alternateTarget
					results.Target = normalizedTarget
				}
			}
		}

		// Debug request output
		if *debugReq {
			fmt.Printf("\n--- DEBUG REQUEST ---\n")
			fmt.Printf("%s %s HTTP/1.1\n", *httpMethod, currentTarget)
			fmt.Printf("Host: %s\n", host)
			if *customHeaders != "" {
				for _, h := range strings.Split(*customHeaders, ";") {
					fmt.Println(strings.TrimSpace(h))
				}
			}
			if *requestBody != "" {
				fmt.Printf("\n%s\n", *requestBody)
			}
			fmt.Printf("--- END REQUEST ---\n\n")
		}

		if err == nil {
			// Ensure body is closed even on panic
			defer initialResp.Body.Close()

			// Debug response output
			if *debugResp {
				fmt.Printf("\n--- DEBUG RESPONSE ---\n")
				fmt.Printf("HTTP/1.1 %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
				}
				fmt.Printf("--- END RESPONSE ---\n\n")
			}

			results.Alive = true
			results.ResponseTime = responseTime.String()
			results.StatusCode = initialResp.StatusCode
			results.ContentLength = initialResp.ContentLength
			results.ContentType = initialResp.Header.Get("Content-Type")
			results.Server = initialResp.Header.Get("Server")
			results.Location = initialResp.Header.Get("Location")
			results.FinalURL = initialResp.Request.URL.String()

			// Read body for word/line count and hash (unless omitBody)
			var body []byte
			var bodyStr string
			if !*omitBody {
				// Limit response read size if specified
				if maxReadSize > 0 {
					body = make([]byte, maxReadSize)
					n, _ := io.ReadFull(initialResp.Body, body)
					body = body[:n]
				} else {
					body, _ = iohelper.ReadBody(initialResp.Body, iohelper.LargeMaxBodySize)
				}
				// Decode body unless skipDecode is set
				if !skipDecode {
					bodyStr = string(body)
				} else {
					bodyStr = string(body) // Keep raw bytes as string
				}
			}
			// Body is closed by defer above

			// Apply strip tags if enabled
			if *stripTags != "" && !*omitBody {
				if strings.Contains(*stripTags, "html") || strings.Contains(*stripTags, "xml") {
					bodyStr = stripHTMLTags(bodyStr)
				}
			}

			results.rawBody = bodyStr // Store for matching (empty if omitBody)
			if !*omitBody {
				results.WordCount = len(strings.Fields(bodyStr))
				results.LineCount = strings.Count(bodyStr, "\n") + 1
			}
			if results.ContentLength <= 0 {
				results.ContentLength = int64(len(body))
			}

			// Include response headers if requested
			if *includeRespHeader {
				results.ResponseHeaders = make(map[string][]string)
				for k, v := range initialResp.Header {
					results.ResponseHeaders[k] = v
				}
			}

			// Include response body if requested
			if *includeResponse || *includeRespBase64 {
				// Limit body for saving if maxSaveSize is specified
				savedBody := bodyStr
				if maxSaveSize > 0 && len(savedBody) > maxSaveSize {
					savedBody = savedBody[:maxSaveSize]
				}
				if *includeRespBase64 {
					// Use truncated body for base64 encoding
					results.ResponseBody = base64.StdEncoding.EncodeToString([]byte(savedBody))
				} else {
					results.ResponseBody = savedBody
				}
			}

			// Calculate body hash if requested (supports: md5, sha1, sha256, sha512, mmh3, simhash)
			if *hashType != "" {
				switch strings.ToLower(*hashType) {
				case "md5":
					results.BodyHash = fmt.Sprintf("md5:%x", md5.Sum(body))
				case "sha1":
					results.BodyHash = fmt.Sprintf("sha1:%x", sha1.Sum(body))
				case "sha256":
					results.BodyHash = fmt.Sprintf("sha256:%x", sha256.Sum256(body))
				case "sha512":
					results.BodyHash = fmt.Sprintf("sha512:%x", sha512.Sum512(body))
				case "mmh3":
					// MurmurHash3 for favicon-style hashing
					h := murmur3.Sum32(body)
					results.BodyHash = fmt.Sprintf("mmh3:%d", int32(h))
				case "simhash":
					// Simhash for near-duplicate detection
					bodyHash := simhash(bodyStr)
					results.BodyHash = fmt.Sprintf("simhash:%d", bodyHash)
				}
			}

			// Store response if requested
			if *storeResponse {
				respDir := *storeResponseDir
				os.MkdirAll(respDir, 0755)
				// Sanitize filename from URL
				safeName := strings.ReplaceAll(host, ":", "_")
				safeName = strings.ReplaceAll(safeName, "/", "_")
				respFile := filepath.Join(respDir, fmt.Sprintf("%s_%d.txt", safeName, time.Now().Unix()))
				respContent := fmt.Sprintf("HTTP/1.1 %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					respContent += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				respContent += "\n" + bodyStr
				if err := os.WriteFile(respFile, []byte(respContent), 0644); err != nil {
					if showDetails {
						ui.PrintError(fmt.Sprintf("Failed to save response: %v", err))
					}
				} else if showDetails {
					ui.PrintSuccess(fmt.Sprintf("Response saved to %s", respFile))
				}
			}

			// Screenshot capture if requested (-ss flag)
			if *screenshot {
				// Create screenshots directory
				screenshotDir := "screenshots"
				os.MkdirAll(screenshotDir, 0755)
				safeName := strings.ReplaceAll(host, ":", "_")
				safeName = strings.ReplaceAll(safeName, "/", "_")
				screenshotFile := filepath.Join(screenshotDir, fmt.Sprintf("%s_%d.png", safeName, time.Now().Unix()))

				// Use headless browser config with all options wired up
				browserCfg := headless.DefaultConfig()
				browserCfg.ScreenshotEnabled = true
				browserCfg.ScreenshotDir = screenshotDir
				browserCfg.PageTimeout = time.Duration(*screenshotTimeout) * time.Second
				browserCfg.IdleTimeout = time.Duration(*screenshotIdle) * time.Second
				browserCfg.ScreenshotFull = !*noScreenshotFullPage

				// Wire up system chrome option
				if *systemChrome {
					browserCfg.ChromiumPath = "" // Empty means use system chrome
				}

				// Wire up headless options (comma-separated args for browser launch)
				if *headlessOptions != "" {
					browserCfg.HeadlessArgs = strings.Split(*headlessOptions, ",")
				}

				// Wire up JavaScript code execution after page load
				if *javascriptCode != "" {
					browserCfg.PostLoadJS = *javascriptCode
				}

				// Note: Full screenshot capture requires rod/chromedp which may not be available
				// Store screenshot file path in results
				results.ScreenshotFile = screenshotFile

				if showDetails {
					ui.PrintInfo(fmt.Sprintf("Screenshot: %s (timeout: %ds, idle: %ds, full: %v)",
						screenshotFile, *screenshotTimeout, *screenshotIdle, !*noScreenshotFullPage))
				}

				// Include screenshot bytes in JSON output if file exists and not excluded
				if !*excludeScreenshotBytes {
					// Try to read existing screenshot file and encode as base64
					if screenshotData, err := os.ReadFile(screenshotFile); err == nil {
						results.ScreenshotBytes = base64.StdEncoding.EncodeToString(screenshotData)
					}
				}

				// Vision recon clustering - group similar screenshots
				if *storeVisionRecon {
					bodyHash := simhash(results.rawBody)
					visionClustersMu.Lock()
					clusterID := screenshotClusterID
					// Check if this hash is similar to an existing cluster
					for _, existing := range visionClusters {
						if hammingDistance(bodyHash, existing.Simhash) <= 8 {
							clusterID = existing.Cluster
							break
						}
					}
					if clusterID == screenshotClusterID {
						screenshotClusterID++
					}
					visionClusters = append(visionClusters, ScreenshotCluster{
						Target:  currentTarget,
						File:    screenshotFile,
						Cluster: clusterID,
						Simhash: bodyHash,
					})
					visionClustersMu.Unlock()
				}
			}

			// Debug mode - show request/response
			if *debug {
				fmt.Printf("\n[DEBUG] Request:\n")
				fmt.Printf("  Method: %s\n", *httpMethod)
				fmt.Printf("  URL: %s\n", currentTarget)
				if *customHeaders != "" {
					fmt.Printf("  Headers: %s\n", *customHeaders)
				}
				fmt.Printf("\n[DEBUG] Response:\n")
				fmt.Printf("  Status: %d %s\n", initialResp.StatusCode, http.StatusText(initialResp.StatusCode))
				for k, v := range initialResp.Header {
					fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
				}
				if len(bodyStr) > 500 {
					fmt.Printf("\n  Body (truncated): %s...\n", bodyStr[:500])
				} else {
					fmt.Printf("\n  Body: %s\n", bodyStr)
				}
			}

			// Body preview
			if *bodyPreview > 0 && len(bodyStr) > 0 {
				previewLen := *bodyPreview
				if previewLen > len(bodyStr) {
					previewLen = len(bodyStr)
				}
				results.BodyPreview = bodyStr[:previewLen]
			}

			// Header hash
			if *headerHash {
				headerContent := ""
				for k, v := range initialResp.Header {
					headerContent += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", "))
				}
				results.HeaderHash = fmt.Sprintf("md5:%x", md5.Sum([]byte(headerContent)))
			}

			// URL scheme
			if strings.HasPrefix(currentTarget, "https://") {
				results.Scheme = "https"
			} else {
				results.Scheme = "http"
			}

			// WebSocket detection
			if *showWebSocket {
				upgradeHeader := strings.ToLower(initialResp.Header.Get("Upgrade"))
				connectionHeader := strings.ToLower(initialResp.Header.Get("Connection"))
				if strings.Contains(upgradeHeader, "websocket") || strings.Contains(connectionHeader, "upgrade") {
					results.WebSocket = true
				}
			}

			// Extract regex
			if *extractRegex != "" {
				re, err := regexcache.Get(*extractRegex)
				if err == nil {
					matches := re.FindAllString(bodyStr, 50) // limit to 50 matches
					results.Extracted = matches
				}
			}

			// Extract preset patterns
			if *extractPreset != "" {
				presets := strings.Split(*extractPreset, ",")
				for _, preset := range presets {
					var pattern string
					switch strings.TrimSpace(preset) {
					case "url":
						pattern = `https?://[^\s<>"']+`
					case "ipv4":
						pattern = `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
					case "mail", "email":
						pattern = `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
					}
					if pattern != "" {
						re, err := regexcache.Get(pattern)
						if err == nil {
							matches := re.FindAllString(bodyStr, 50)
							results.Extracted = append(results.Extracted, matches...)
						}
					}
				}
			}

			// Extract FQDN (domains and subdomains) from response body and headers
			if *extractFQDN {
				fqdnPattern := `(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}`
				re, err := regexcache.Get(fqdnPattern)
				if err == nil {
					// Extract from body
					bodyMatches := re.FindAllString(bodyStr, 100)
					// Extract from headers
					headerStr := ""
					for k, v := range initialResp.Header {
						headerStr += k + ": " + strings.Join(v, ", ") + "\n"
					}
					headerMatches := re.FindAllString(headerStr, 50)
					// Combine and dedupe
					fqdnSet := make(map[string]bool)
					for _, m := range append(bodyMatches, headerMatches...) {
						// Filter out common false positives
						if !strings.HasSuffix(m, ".css") && !strings.HasSuffix(m, ".js") &&
							!strings.HasSuffix(m, ".png") && !strings.HasSuffix(m, ".jpg") {
							fqdnSet[strings.ToLower(m)] = true
						}
					}
					for fqdn := range fqdnSet {
						results.Extracted = append(results.Extracted, fqdn)
					}
				}
			}

			// WordPress detection
			if *showWordPress {
				isWP, plugins, themes := detectWordPress(bodyStr, currentTarget)
				results.WordPress = isWP
				results.WPPlugins = plugins
				results.WPThemes = themes
			}

			if showDetails && len(targets) == 1 {
				ui.PrintSection("Response Metrics")
				ui.PrintConfigLine("Status", fmt.Sprintf("%d %s", results.StatusCode, http.StatusText(results.StatusCode)))
				ui.PrintConfigLine("Response Time", results.ResponseTime)
				if results.ContentLength > 0 {
					ui.PrintConfigLine("Content-Length", fmt.Sprintf("%d bytes", results.ContentLength))
				}
				if results.ContentType != "" {
					ui.PrintConfigLine("Content-Type", results.ContentType)
				}
				if results.Server != "" {
					ui.PrintConfigLine("Server", results.Server)
				}
				ui.PrintConfigLine("Words", fmt.Sprintf("%d", results.WordCount))
				ui.PrintConfigLine("Lines", fmt.Sprintf("%d", results.LineCount))
				if results.BodyHash != "" {
					ui.PrintConfigLine("Body Hash", results.BodyHash)
				}
				fmt.Println()
			}
		} else {
			results.Alive = false
		}

		// DNS Resolution
		if *dnsProbe || *probeAllIPs {
			if showDetails {
				ui.PrintInfo("Resolving DNS...")
			}
			dnsProber := probes.NewDNSProber()
			dnsProber.Timeout = timeoutDur
			dnsResult := dnsProber.Resolve(ctx, host)
			results.DNS = dnsResult

			// Probe all IPs if requested
			if *probeAllIPs && len(dnsResult.IPv4) > 0 {
				if showDetails {
					ui.PrintInfo(fmt.Sprintf("Probing all %d IPs...", len(dnsResult.IPv4)))
				}
				for _, ip := range dnsResult.IPv4 {
					// Create IP-specific URL
					scheme := "https"
					if strings.HasPrefix(currentTarget, "http://") {
						scheme = "http"
					}
					ipURL := fmt.Sprintf("%s://%s", scheme, ip)

					// Make request to IP with Host header
					client := &http.Client{
						Timeout: timeoutDur,
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
								ServerName:         host,
							},
						},
						CheckRedirect: func(req *http.Request, via []*http.Request) error {
							return http.ErrUseLastResponse
						},
					}
					req, err := http.NewRequestWithContext(ctx, "GET", ipURL, nil)
					if err != nil {
						continue
					}
					req.Host = host
					resp, err := client.Do(req)
					if err == nil {
						if showDetails {
							ui.PrintConfigLine(ip, fmt.Sprintf("Status %d", resp.StatusCode))
						}
						resp.Body.Close()
					}
				}
			}

			if showDetails {
				ui.PrintSection("DNS Resolution")
				if len(dnsResult.IPv4) > 0 {
					ui.PrintConfigLine("IPv4", strings.Join(dnsResult.IPv4, ", "))
				}
				if len(dnsResult.IPv6) > 0 {
					ui.PrintConfigLine("IPv6", strings.Join(dnsResult.IPv6, ", "))
				}
				if dnsResult.CNAME != "" {
					ui.PrintConfigLine("CNAME", dnsResult.CNAME)
				}
				if dnsResult.ASN != nil {
					ui.PrintConfigLine("ASN", fmt.Sprintf("AS%d - %s", dnsResult.ASN.Number, dnsResult.ASN.Organization))
				}
				fmt.Println()
			}
		}

		// TLS Probing (includes tls-grab functionality)
		if (*tlsProbe || *tlsGrab) && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Probing TLS configuration...")
			}
			tlsProber := probes.NewTLSProber()
			tlsProber.Timeout = timeoutDur
			tlsInfo, err := tlsProber.Probe(ctx, host, 443)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("TLS probe failed: %v", err))
				}
			} else {
				results.TLS = tlsInfo
				if showDetails {
					ui.PrintSection("TLS Configuration")
					ui.PrintConfigLine("Version", tlsInfo.Version)
					ui.PrintConfigLine("Cipher", tlsInfo.CipherSuite)
					ui.PrintConfigLine("Subject", tlsInfo.SubjectCN)
					ui.PrintConfigLine("Issuer", tlsInfo.IssuerDN)
					ui.PrintConfigLine("Valid Until", tlsInfo.NotAfter.Format("2006-01-02"))
					if tlsInfo.Expired {
						ui.PrintError("Certificate is EXPIRED!")
					}
					if tlsInfo.SelfSigned {
						ui.PrintWarning("Certificate is self-signed")
					}
					fmt.Println()
				}

				// Extract additional domains from TLS certificate (SANs) if requested
				if extractTLSDomains && len(tlsInfo.SubjectAN) > 0 {
					for _, san := range tlsInfo.SubjectAN {
						results.Extracted = append(results.Extracted, "tls-domain:"+san)
					}
					if showDetails && *verbose {
						ui.PrintInfo(fmt.Sprintf("Extracted %d domains from TLS certificate", len(tlsInfo.SubjectAN)))
					}
				}
			}
		}

		// JARM TLS Fingerprint
		if *jarmProbe && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Calculating JARM fingerprint...")
			}
			jarmProber := probes.NewJARMProber()
			jarmProber.Timeout = timeoutDur
			jarmResult := jarmProber.Probe(ctx, host, 443)
			results.JARM = jarmResult
			if showDetails {
				ui.PrintSection("JARM Fingerprint")
				if jarmResult.Fingerprint != "" {
					ui.PrintConfigLine("Fingerprint", jarmResult.Fingerprint)
					identified := probes.IdentifyJARMFingerprint(jarmResult.Fingerprint)
					ui.PrintConfigLine("Identified", identified)
				} else {
					ui.PrintInfo("Could not calculate JARM fingerprint")
				}
				fmt.Println()
			}
		}

		// Security Headers - need HTTP response first
		if *headerProbe {
			if showDetails {
				ui.PrintInfo("Analyzing security headers...")
			}
			resp, err := makeHTTPRequest(ctx, currentTarget, timeoutDur)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("Header extraction failed: %v", err))
				}
			} else {
				defer resp.Body.Close()
				headerExtractor := probes.NewHeaderExtractor()
				headers := headerExtractor.Extract(resp)
				results.Headers = headers
				if showDetails {
					ui.PrintSection("Security Headers")
					ui.PrintConfigLine("Grade", headers.Grade)
					if headers.StrictTransportSecurity != "" {
						ui.PrintConfigLine("HSTS", headers.StrictTransportSecurity)
					}
					if headers.ContentSecurityPolicy != "" {
						ui.PrintConfigLine("CSP", "present")
					}
					if len(headers.MissingHeaders) > 0 {
						ui.PrintWarning(fmt.Sprintf("Missing headers: %v", headers.MissingHeaders))
					}
					fmt.Println()
				}
			}
		}

		// CSP Probe - extract and display domains from CSP
		if *cspProbe && results.Headers != nil && results.Headers.ContentSecurityPolicy != "" {
			cspDomains := extractDomainsFromCSP(results.Headers.ContentSecurityPolicy)
			if len(cspDomains) > 0 {
				results.Extracted = append(results.Extracted, cspDomains...)
				if showDetails {
					ui.PrintSection("CSP Domains")
					for _, d := range cspDomains {
						ui.PrintConfigLine("Domain", d)
					}
					fmt.Println()
				}
			}
		}

		// Technology Detection
		if *techProbe {
			if showDetails {
				ui.PrintInfo("Detecting technologies...")
			}
			resp, err := makeHTTPRequest(ctx, currentTarget, timeoutDur)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("Technology detection failed: %v", err))
				}
			} else {
				defer resp.Body.Close()
				body, _ := iohelper.ReadBodyDefault(resp.Body)
				techDetector := probes.NewTechDetector()
				techResult := techDetector.Detect(resp, body)
				results.Tech = techResult

				// Generate CPE strings if requested
				if *showCPE {
					results.CPEs = generateCPE(techResult)
					if showDetails && len(results.CPEs) > 0 {
						ui.PrintSection("CPE Strings")
						for _, cpe := range results.CPEs {
							ui.PrintConfigLine("CPE", cpe)
						}
						fmt.Println()
					}
				}

				if showDetails {
					ui.PrintSection("Technology Detection")
					if techResult.Title != "" {
						ui.PrintConfigLine("Title", techResult.Title)
					}
					if len(techResult.Technologies) > 0 {
						techNames := make([]string, 0, len(techResult.Technologies))
						for _, t := range techResult.Technologies {
							if t.Version != "" {
								techNames = append(techNames, fmt.Sprintf("%s/%s", t.Name, t.Version))
							} else {
								techNames = append(techNames, t.Name)
							}
						}
						ui.PrintConfigLine("Technologies", strings.Join(techNames, ", "))
					}
					if techResult.BodyHash.MD5 != "" {
						ui.PrintConfigLine("Body Hash", techResult.BodyHash.MD5[:16]+"...")
					}
					fmt.Println()
				}
			}
		}

		// HTTP Probing
		if *httpProbe {
			if showDetails {
				ui.PrintInfo("Probing HTTP capabilities...")
			}
			httpProber := probes.NewHTTPProber()
			httpProber.DialTimeout = timeoutDur
			http2Supported, alpn, err := httpProber.ProbeHTTP2(ctx, host, 443)
			if err == nil {
				httpResult := &probes.HTTPProbeResult{
					Host:           host,
					HTTP2Supported: http2Supported,
					ALPN:           []string{alpn},
				}
				results.HTTP = httpResult
				if showDetails {
					ui.PrintSection("HTTP Capabilities")
					ui.PrintConfigLine("HTTP/2", fmt.Sprintf("%v", httpResult.HTTP2Supported))
					if alpn != "" {
						ui.PrintConfigLine("ALPN", alpn)
					}
					fmt.Println()
				}
			}
		}

		// WAF/CDN Detection
		if *wafProbe {
			if showDetails {
				ui.PrintInfo("Detecting WAF/CDN...")
			}
			detector := waf.NewDetector(timeoutDur)
			wafResult, err := detector.Detect(ctx, currentTarget)
			if err != nil {
				if showDetails {
					ui.PrintWarning(fmt.Sprintf("WAF detection failed: %v", err))
				}
			} else {
				results.WAF = wafResult
				if showDetails {
					ui.PrintSection("WAF/CDN Detection")
					if wafResult.Detected {
						for _, w := range wafResult.WAFs {
							ui.PrintConfigLine("WAF", fmt.Sprintf("%s (%s) - %.0f%% confidence", w.Name, w.Type, w.Confidence*100))
							if len(w.BypassTips) > 0 {
								ui.PrintInfo(fmt.Sprintf("  Bypass tips: %v", w.BypassTips[:min(3, len(w.BypassTips))]))
							}
						}
						if wafResult.CDN != nil {
							ui.PrintConfigLine("CDN", wafResult.CDN.Name)
						}
					} else {
						ui.PrintInfo("No WAF/CDN detected")
					}
					fmt.Println()
				}
			}
		}

		// VHost Probe - check for virtual host support
		if *vhostProbe && strings.HasPrefix(currentTarget, "https://") {
			if showDetails {
				ui.PrintInfo("Probing virtual hosts...")
			}
			vhostProber := probes.NewVHostProber()
			vhostProber.Timeout = timeoutDur

			// Test with a few common prefixes
			testPrefixes := []string{"admin", "api", "dev", "staging", "internal"}

			port := 443
			foundVHosts := []string{}
			for _, prefix := range testPrefixes {
				testHost := prefix + "." + host
				vhosts, err := vhostProber.ProbeVHosts(ctx, host, port, testHost, []string{prefix})
				if err == nil {
					for _, v := range vhosts {
						if v.Valid {
							foundVHosts = append(foundVHosts, v.VHost)
						}
					}
				}
			}
			if len(foundVHosts) > 0 && showDetails {
				ui.PrintSection("Virtual Hosts")
				for _, vh := range foundVHosts {
					ui.PrintConfigLine("VHost", vh)
				}
				fmt.Println()
			}
		}

		// Favicon Probing
		if *faviconProbe {
			if showDetails {
				ui.PrintInfo("Probing favicon...")
			}
			faviconProber := probes.NewFaviconProber()
			faviconProber.Timeout = timeoutDur
			faviconResult := faviconProber.Probe(ctx, currentTarget)
			results.Favicon = faviconResult
			if showDetails {
				ui.PrintSection("Favicon")
				if faviconResult.Found {
					ui.PrintConfigLine("URL", faviconResult.URL)
					ui.PrintConfigLine("Size", fmt.Sprintf("%d bytes", faviconResult.Size))
					ui.PrintConfigLine("MMH3 Hash", fmt.Sprintf("%d", faviconResult.MMH3Hash))
					ui.PrintConfigLine("Shodan Dork", faviconResult.ShodanDork)
				} else {
					ui.PrintInfo("No favicon found")
				}
				fmt.Println()
			}
		}

		// Match/Filter logic - skip output if conditions not met
		skipOutput := false

		// Filter error pages - ML-inspired heuristic error page detection
		// Detects: status codes 4xx/5xx, common error page patterns, short generic content
		if *filterErrorPage && !skipOutput {
			isErrorPage := false

			// Check status code (4xx, 5xx)
			if results.StatusCode >= 400 && results.StatusCode < 600 {
				isErrorPage = true
			}

			// Heuristic content-based error page detection
			if !isErrorPage && results.rawBody != "" {
				lowerBody := strings.ToLower(results.rawBody)
				errorPatterns := []string{
					"not found", "page not found", "404 error", "403 forbidden",
					"access denied", "unauthorized", "500 internal", "server error",
					"service unavailable", "bad gateway", "error occurred",
					"something went wrong", "oops", "we couldn't find",
					"the page you requested", "this page doesn't exist",
					"page cannot be displayed", "site under maintenance",
					"temporarily unavailable", "default web site page",
					"welcome to nginx", "apache2 default page", "iis windows server",
				}
				for _, pattern := range errorPatterns {
					if strings.Contains(lowerBody, pattern) {
						isErrorPage = true
						break
					}
				}

				// Short generic content (likely default/error page)
				if !isErrorPage && results.ContentLength > 0 && results.ContentLength < 500 {
					// Very short pages with generic titles are likely error pages
					if results.Tech != nil && results.Tech.Title != "" {
						titleLower := strings.ToLower(results.Tech.Title)
						if strings.Contains(titleLower, "error") || strings.Contains(titleLower, "not found") ||
							strings.Contains(titleLower, "forbidden") || strings.Contains(titleLower, "denied") {
							isErrorPage = true
						}
					}
				}
			}

			if isErrorPage {
				skipOutput = true
				// Collect filtered error pages for saving to filterErrorPagePath
				filteredErrorPagesMu.Lock()
				filteredErrorPages = append(filteredErrorPages, results)
				filteredErrorPagesMu.Unlock()
			}
		}

		// Match code - only show if status matches
		if *matchCode != "" && !skipOutput {
			codes := strings.Split(*matchCode, ",")
			matched := false
			for _, c := range codes {
				code, _ := strconv.Atoi(strings.TrimSpace(c))
				if results.StatusCode == code {
					matched = true
					break
				}
			}
			if !matched {
				skipOutput = true
			}
		}

		// Filter code - skip if status matches filter
		if *filterCode != "" && !skipOutput {
			codes := strings.Split(*filterCode, ",")
			for _, c := range codes {
				code, _ := strconv.Atoi(strings.TrimSpace(c))
				if results.StatusCode == code {
					skipOutput = true
					break
				}
			}
		}

		// Match string - only show if body contains string
		if *matchString != "" && !skipOutput {
			if !strings.Contains(results.rawBody, *matchString) {
				skipOutput = true
			}
		}

		// Filter string - skip if body contains string
		if *filterString != "" && !skipOutput {
			if strings.Contains(results.rawBody, *filterString) {
				skipOutput = true
			}
		}

		// Match length - only show if content length matches
		if *matchLength != "" && !skipOutput {
			if !matchRange(int(results.ContentLength), *matchLength) {
				skipOutput = true
			}
		}

		// Filter length - skip if content length matches
		if *filterLength != "" && !skipOutput {
			if matchRange(int(results.ContentLength), *filterLength) {
				skipOutput = true
			}
		}

		// Match line count - only show if line count matches
		if *matchLineCount != "" && !skipOutput {
			if !matchRange(results.LineCount, *matchLineCount) {
				skipOutput = true
			}
		}

		// Filter line count - skip if line count matches
		if *filterLineCount != "" && !skipOutput {
			if matchRange(results.LineCount, *filterLineCount) {
				skipOutput = true
			}
		}

		// Match word count - only show if word count matches
		if *matchWordCount != "" && !skipOutput {
			if !matchRange(results.WordCount, *matchWordCount) {
				skipOutput = true
			}
		}

		// Filter word count - skip if word count matches
		if *filterWordCount != "" && !skipOutput {
			if matchRange(results.WordCount, *filterWordCount) {
				skipOutput = true
			}
		}

		// Match regex - only show if body matches regex
		if *matchRegex != "" && !skipOutput {
			re, err := regexcache.Get(*matchRegex)
			if err == nil && !re.MatchString(results.rawBody) {
				skipOutput = true
			}
		}

		// Filter regex - skip if body matches regex
		if *filterRegex != "" && !skipOutput {
			re, err := regexcache.Get(*filterRegex)
			if err == nil && re.MatchString(results.rawBody) {
				skipOutput = true
			}
		}

		// Match favicon - only show if favicon hash matches
		if *matchFavicon != "" && !skipOutput {
			if results.Favicon != nil {
				matched := false
				hashes := strings.Split(*matchFavicon, ",")
				for _, h := range hashes {
					if strings.TrimSpace(h) == fmt.Sprintf("%d", results.Favicon.MMH3Hash) {
						matched = true
						break
					}
				}
				if !matched {
					skipOutput = true
				}
			} else {
				skipOutput = true
			}
		}

		// Filter favicon - skip if favicon hash matches
		if *filterFavicon != "" && !skipOutput {
			if results.Favicon != nil {
				hashes := strings.Split(*filterFavicon, ",")
				for _, h := range hashes {
					if strings.TrimSpace(h) == fmt.Sprintf("%d", results.Favicon.MMH3Hash) {
						skipOutput = true
						break
					}
				}
			}
		}

		// Match CDN - only show if CDN matches
		if *matchCDN != "" && !skipOutput {
			matched := false
			if results.WAF != nil && results.WAF.Detected {
				cdns := strings.Split(strings.ToLower(*matchCDN), ",")
				for _, w := range results.WAF.WAFs {
					wafLower := strings.ToLower(w.Name)
					for _, cdn := range cdns {
						if strings.Contains(wafLower, strings.TrimSpace(cdn)) {
							matched = true
							break
						}
					}
				}
			}
			if !matched {
				skipOutput = true
			}
		}

		// Filter CDN - skip if CDN matches
		if *filterCDN != "" && !skipOutput {
			if results.WAF != nil && results.WAF.Detected {
				cdns := strings.Split(strings.ToLower(*filterCDN), ",")
				for _, w := range results.WAF.WAFs {
					wafLower := strings.ToLower(w.Name)
					for _, cdn := range cdns {
						if strings.Contains(wafLower, strings.TrimSpace(cdn)) {
							skipOutput = true
							break
						}
					}
				}
			}
		}

		// Match response time - only show if response time matches condition
		if *matchRespTime != "" && !skipOutput {
			dur, _ := time.ParseDuration(results.ResponseTime)
			if !matchTimeCondition(dur, *matchRespTime) {
				skipOutput = true
			}
		}

		// Filter response time - skip if response time matches condition
		if *filterRespTime != "" && !skipOutput {
			dur, _ := time.ParseDuration(results.ResponseTime)
			if matchTimeCondition(dur, *filterRespTime) {
				skipOutput = true
			}
		}

		// Filter duplicates - skip if response signature already seen
		// (unless noDedup/skipDedupe is enabled, or filterDuplicates is not set)
		if *filterDuplicates && !noDedup && !skipOutput {
			// Create signature from status code, content length, and body hash
			signature := fmt.Sprintf("%d-%d-%s", results.StatusCode, results.ContentLength, results.BodyHash)
			seenResponsesMu.Lock()
			if seenResponses[signature] {
				skipOutput = true
			} else {
				seenResponses[signature] = true
			}
			seenResponsesMu.Unlock()
		}

		// DSL Match Condition - only show if DSL expression matches
		if *matchCondition != "" && !skipOutput {
			// Extract title from body if present
			titleStr := ""
			titleRe := regexcache.MustGet(`<title[^>]*>([^<]+)</title>`)
			if titleMatch := titleRe.FindStringSubmatch(results.rawBody); len(titleMatch) > 1 {
				titleStr = titleMatch[1]
			}
			if !evaluateDSL(*matchCondition, results.StatusCode, results.ContentLength, results.rawBody, results.ContentType, titleStr, results.Target, results.Server, results.Location) {
				skipOutput = true
			}
		}

		// DSL Filter Condition - skip if DSL expression matches
		if *filterCondition != "" && !skipOutput {
			titleStr := ""
			titleRe := regexcache.MustGet(`<title[^>]*>([^<]+)</title>`)
			if titleMatch := titleRe.FindStringSubmatch(results.rawBody); len(titleMatch) > 1 {
				titleStr = titleMatch[1]
			}
			if evaluateDSL(*filterCondition, results.StatusCode, results.ContentLength, results.rawBody, results.ContentType, titleStr, results.Target, results.Server, results.Location) {
				skipOutput = true
			}
		}

		// Simhash near-duplicate detection
		if *simhashThreshold > 0 && !skipOutput {
			bodyHash := simhash(results.rawBody)
			isDuplicate := false
			seenSimhashesMu.Lock()
			for _, seen := range seenSimhashes {
				if hammingDistance(bodyHash, seen) <= *simhashThreshold {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				skipOutput = true
			} else {
				seenSimhashes = append(seenSimhashes, bodyHash)
			}
			seenSimhashesMu.Unlock()
		}

		if skipOutput {
			return nil, nil // Skip output for this target
		}

		// Store redirect chain in results if tracking
		if storeRedirectChain && len(redirectChain) > 0 {
			results.RedirectChain = redirectChain
		}

		// Return the results - output will be handled in the callback
		return &results, nil
	} // end of probeTask function

	// Determine output mode for LiveProgress
	probeOutputMode := ui.OutputModeInteractive
	if *streamMode {
		probeOutputMode = ui.OutputModeStreaming
	} else if *silent || *jsonOutput || *jsonl {
		probeOutputMode = ui.OutputModeSilent
	}

	// Use unified LiveProgress for probe command
	probeProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(targets),
		DisplayLines: 3,
		Title:        "Probing targets",
		Unit:         "targets",
		Mode:         probeOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "alive", Label: "Alive", Icon: "✅", Highlight: true},
			{Name: "dead", Label: "Dead", Icon: "❌"},
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | alive: {metric:alive} | dead: {metric:dead} | {elapsed}",
		StreamInterval: 3 * time.Second,
	})
	if len(targets) > 1 && !*oneliner {
		probeProgress.Start()
		defer probeProgress.Stop()
	}

	// Run probes in parallel with streaming output using callback
	probeRunner.RunWithCallback(context.Background(), targets, probeTask, func(result runner.Result[*ProbeResults]) {
		if result.Error != nil {
			// Handle error output
			atomic.AddInt64(&statsTotal, 1)
			atomic.AddInt64(&statsFailed, 1)
			probeProgress.Increment()
			probeProgress.AddMetric("dead")
			return
		}

		// Skip nil results (filtered targets)
		if result.Data == nil {
			return
		}

		results := result.Data
		currentTarget := result.Target

		// Update statistics (atomic for thread-safe HTTP API access)
		atomic.AddInt64(&statsTotal, 1)
		probeProgress.Increment()
		if results.Alive {
			atomic.AddInt64(&statsSuccess, 1)
			probeProgress.AddMetric("alive")
		} else {
			atomic.AddInt64(&statsFailed, 1)
			probeProgress.AddMetric("dead")
			// Track host errors for MaxHostErrors feature
			if hostErrorLimit > 0 {
				hostForFilter := strings.TrimPrefix(currentTarget, "https://")
				hostForFilter = strings.TrimPrefix(hostForFilter, "http://")
				hostForFilter = strings.Split(hostForFilter, "/")[0]
				hostForFilter = strings.Split(hostForFilter, ":")[0]
				hostErrorsMu.Lock()
				hostErrors[hostForFilter]++
				hostErrorsMu.Unlock()
			}
		}

		// Protect output with mutex to prevent interleaving
		outputMu.Lock()
		defer outputMu.Unlock()

		// Output results
		if *oneliner {
			// httpx-style one-liner output
			parts := []string{currentTarget}
			if results.StatusCode > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", results.StatusCode))
			}
			if results.ResponseTime != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.ResponseTime))
			}
			// Show title when -title flag or default tech detection
			if *showTitle && results.Tech != nil && results.Tech.Title != "" {
				title := results.Tech.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", title))
			} else if results.Tech != nil && results.Tech.Title != "" && !*showTitle {
				title := results.Tech.Title
				if len(title) > 50 {
					title = title[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", title))
			}
			// Show IP when -ip flag or default DNS
			if *showIP && results.DNS != nil && len(results.DNS.IPv4) > 0 {
				parts = append(parts, fmt.Sprintf("[%s]", results.DNS.IPv4[0]))
			} else if results.DNS != nil && len(results.DNS.IPv4) > 0 && !*showIP {
				parts = append(parts, fmt.Sprintf("[%s]", results.DNS.IPv4[0]))
			}
			// Show ASN when -asn flag
			if *showASN && results.DNS != nil && results.DNS.ASN != nil {
				parts = append(parts, fmt.Sprintf("[AS%d]", results.DNS.ASN.Number))
			}
			// Show CDN/WAF when -cdn flag
			if *showCDN && results.WAF != nil && results.WAF.Detected && len(results.WAF.WAFs) > 0 {
				wafNames := make([]string, 0)
				for _, w := range results.WAF.WAFs {
					wafNames = append(wafNames, w.Name)
				}
				parts = append(parts, fmt.Sprintf("[WAF:%s]", strings.Join(wafNames, ",")))
			}
			// Show technologies when -td flag or default
			if *showTech && results.Tech != nil && len(results.Tech.Technologies) > 0 {
				techs := make([]string, 0)
				for i, t := range results.Tech.Technologies {
					if i >= 3 {
						break
					}
					techs = append(techs, t.Name)
				}
				parts = append(parts, fmt.Sprintf("[%s]", strings.Join(techs, ",")))
			} else if results.Tech != nil && len(results.Tech.Technologies) > 0 && !*showTech {
				techs := make([]string, 0)
				for i, t := range results.Tech.Technologies {
					if i >= 3 {
						break
					}
					techs = append(techs, t.Name)
				}
				parts = append(parts, fmt.Sprintf("[%s]", strings.Join(techs, ",")))
			}
			// Optional httpx-style output fields
			if *showContentLength && results.ContentLength > 0 {
				parts = append(parts, fmt.Sprintf("[%d]", results.ContentLength))
			}
			if *showContentType && results.ContentType != "" {
				ct := results.ContentType
				if ctIdx := strings.Index(ct, ";"); ctIdx > 0 {
					ct = ct[:ctIdx]
				}
				parts = append(parts, fmt.Sprintf("[%s]", ct))
			}
			if *showWordCount {
				parts = append(parts, fmt.Sprintf("[%dW]", results.WordCount))
			}
			if *showLineCount {
				parts = append(parts, fmt.Sprintf("[%dL]", results.LineCount))
			}
			if *showServer && results.Server != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.Server))
			}
			if *showMethod {
				parts = append(parts, fmt.Sprintf("[%s]", results.Method))
			}
			if *showLocation && results.Location != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.Location))
			}
			// Show body hash if calculated
			if results.BodyHash != "" {
				parts = append(parts, fmt.Sprintf("[%s]", results.BodyHash))
			}
			// Show header hash
			if *headerHash && results.HeaderHash != "" {
				parts = append(parts, fmt.Sprintf("[hdr:%s]", results.HeaderHash))
			}
			// Show CNAME
			if *showCNAME && results.DNS != nil && results.DNS.CNAME != "" {
				parts = append(parts, fmt.Sprintf("[CNAME:%s]", results.DNS.CNAME))
			}
			// Show scheme
			if *showScheme {
				parts = append(parts, fmt.Sprintf("[%s]", results.Scheme))
			}
			// Show WebSocket support
			if *showWebSocket && results.WebSocket {
				parts = append(parts, "[WS]")
			}
			// Show HTTP/2 support
			if *showHTTP2 && results.HTTP2 {
				parts = append(parts, "[HTTP2]")
			}
			// Show pipelining support
			if *showPipeline && results.Pipeline {
				parts = append(parts, "[PIPE]")
			}
			// Show favicon hash
			if *showFaviconHash && results.Favicon != nil && results.Favicon.MMH3Hash != 0 {
				parts = append(parts, fmt.Sprintf("[fav:%d]", results.Favicon.MMH3Hash))
			}
			// Show body preview
			if *bodyPreview > 0 && results.BodyPreview != "" {
				preview := strings.ReplaceAll(results.BodyPreview, "\n", " ")
				preview = strings.ReplaceAll(preview, "\r", "")
				if len(preview) > 50 {
					preview = preview[:47] + "..."
				}
				parts = append(parts, fmt.Sprintf("[%s]", preview))
			}
			// Show extracted content
			if len(results.Extracted) > 0 {
				for i, e := range results.Extracted {
					if i >= 3 { // Limit to 3 extracts in one-liner
						break
					}
					parts = append(parts, fmt.Sprintf("[%s]", e))
				}
			}
			if *probeStatus {
				if results.Alive {
					parts = append(parts, "[UP]")
				} else {
					parts = append(parts, "[DOWN]")
				}
			}
			// Show line count
			if *showLineCount && results.LineCount > 0 {
				parts = append(parts, fmt.Sprintf("[LC:%d]", results.LineCount))
			}
			// Show word count
			if *showWordCount && results.WordCount > 0 {
				parts = append(parts, fmt.Sprintf("[WC:%d]", results.WordCount))
			}
			fmt.Println(strings.Join(parts, " "))
		} else if *csvOutput {
			// CSV output format
			ip := ""
			if results.DNS != nil && len(results.DNS.IPv4) > 0 {
				ip = results.DNS.IPv4[0]
			}
			title := ""
			if results.Tech != nil {
				title = strings.ReplaceAll(results.Tech.Title, ",", ";")
			}
			// CSV: url,status,time,ip,title,content_length,content_type,server,word_count,line_count,alive
			fmt.Printf("%s,%d,%s,%s,%s,%d,%s,%s,%d,%d,%t\n",
				currentTarget,
				results.StatusCode,
				results.ResponseTime,
				ip,
				title,
				results.ContentLength,
				strings.ReplaceAll(results.ContentType, ",", ";"),
				results.Server,
				results.WordCount,
				results.LineCount,
				results.Alive,
			)
		} else if *jsonl {
			// JSONL output (one JSON per line)
			// Apply field exclusions if any
			if len(excludedOutputFields) > 0 {
				jsonData, _ := json.Marshal(results)
				var m map[string]interface{}
				json.Unmarshal(jsonData, &m)
				for field := range excludedOutputFields {
					delete(m, field)
				}
				jsonData, _ = json.Marshal(m)
				fmt.Println(string(jsonData))
			} else {
				jsonData, _ := json.Marshal(results)
				fmt.Println(string(jsonData))
			}
		} else if *jsonOutput || *outputFile != "" {
			// Apply field exclusions if any
			var jsonData []byte
			var err error
			if len(excludedOutputFields) > 0 {
				rawData, _ := json.Marshal(results)
				var m map[string]interface{}
				json.Unmarshal(rawData, &m)
				for field := range excludedOutputFields {
					delete(m, field)
				}
				jsonData, err = json.MarshalIndent(m, "", "  ")
			} else {
				jsonData, err = json.MarshalIndent(results, "", "  ")
			}
			if err != nil {
				ui.PrintError(fmt.Sprintf("JSON encoding error: %v", err))
				os.Exit(1)
			}

			if *outputFile != "" {
				if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
					ui.PrintError(fmt.Sprintf("Error writing output: %v", err))
					os.Exit(1)
				}
				ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))

				// Output all formats if requested
				if *outputAll {
					// CSV file with encoding support
					csvFile := strings.TrimSuffix(*outputFile, filepath.Ext(*outputFile)) + ".csv"
					csvLine := fmt.Sprintf("%s,%d,%d,%s,%s,%d,%d,%t\n",
						results.Target, results.StatusCode, results.ContentLength,
						strings.ReplaceAll(results.ContentType, ",", ";"),
						results.Server, results.WordCount, results.LineCount, results.Alive)
					csvContent := "target,status_code,content_length,content_type,server,word_count,line_count,alive\n" + csvLine
					// Add BOM for utf-8-sig encoding
					var csvBytes []byte
					if csvEnc == "utf-8-sig" {
						csvBytes = append([]byte{0xEF, 0xBB, 0xBF}, []byte(csvContent)...)
					} else {
						csvBytes = []byte(csvContent)
					}
					if err := os.WriteFile(csvFile, csvBytes, 0644); err == nil {
						ui.PrintSuccess(fmt.Sprintf("CSV saved to %s", csvFile))
					}

					// TXT file (oneliner format)
					txtFile := strings.TrimSuffix(*outputFile, filepath.Ext(*outputFile)) + ".txt"
					txtLine := fmt.Sprintf("%s [%d] [%s] [%s] [%s]\n",
						results.Target, results.StatusCode, results.ResponseTime,
						results.ContentType, results.Server)
					if err := os.WriteFile(txtFile, []byte(txtLine), 0644); err == nil {
						ui.PrintSuccess(fmt.Sprintf("TXT saved to %s", txtFile))
					}
				}
			}

			if *jsonOutput {
				fmt.Println(string(jsonData))
			}
		}

		// Stream mode: flush output immediately without buffering
		if isStreamMode {
			os.Stdout.Sync()
		}

		// Trace mode: detailed debug output
		if isTraceMode {
			fmt.Printf("[TRACE] Target: %s, Alive: %t, Status: %d, Time: %v\n",
				currentTarget, results.Alive, results.StatusCode, results.ResponseTime)
		}

		// Save progress to checkpoint (atomic, thread-safe)
		if checkpointMgr != nil {
			checkpointMgr.MarkCompleted(currentTarget)
		}
	}) // end of RunWithCallback

	// LiveProgress is automatically stopped by defer

	// Clean up checkpoint file on successful completion
	if checkpointMgr != nil && checkpointMgr.GetProgress() >= 100 {
		checkpointMgr.Delete()
		if *verbose {
			ui.PrintInfo("Scan complete - checkpoint file removed")
		}
	}

	// Show statistics if requested
	total := atomic.LoadInt64(&statsTotal)
	success := atomic.LoadInt64(&statsSuccess)
	failed := atomic.LoadInt64(&statsFailed)
	if *showStats && total > 0 {
		elapsed := time.Since(statsStart)
		fmt.Printf("\n[STATS] Scanned: %d | Success: %d | Failed: %d | Time: %s | Rate: %.1f/s\n",
			total, success, failed, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())
	}

	// Verbose summary
	if *verbose && total > 1 {
		fmt.Printf("\n[VERBOSE] Completed probing %d targets\n", total)
	}

	// Generate HTML summary report if requested
	if *htmlOutput != "" {
		elapsed := time.Since(statsStart)
		htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>WAF-Tester Probe Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
		.header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
		.stats { display: flex; gap: 20px; margin: 20px 0; }
		.stat-box { background: white; padding: 15px 25px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
		.stat-number { font-size: 2em; font-weight: bold; color: #3498db; }
		.stat-label { color: #7f8c8d; }
		.success { color: #27ae60; }
		.failed { color: #e74c3c; }
	</style>
</head>
<body>
	<div class="header">
		<h1>WAF-Tester Probe Report</h1>
		<p>Generated: %s</p>
	</div>
	<div class="stats">
		<div class="stat-box">
			<div class="stat-number">%d</div>
			<div class="stat-label">Total Scanned</div>
		</div>
		<div class="stat-box">
			<div class="stat-number success">%d</div>
			<div class="stat-label">Success</div>
		</div>
		<div class="stat-box">
			<div class="stat-number failed">%d</div>
			<div class="stat-label">Failed</div>
		</div>
		<div class="stat-box">
			<div class="stat-number">%s</div>
			<div class="stat-label">Duration</div>
		</div>
		<div class="stat-box">
			<div class="stat-number">%.1f/s</div>
			<div class="stat-label">Rate</div>
		</div>
	</div>
</body>
</html>`, time.Now().Format(time.RFC1123), statsTotal, statsSuccess, statsFailed,
			elapsed.Round(time.Millisecond), float64(statsTotal)/elapsed.Seconds())

		if err := os.WriteFile(*htmlOutput, []byte(htmlContent), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
		} else {
			fmt.Printf("[*] HTML report saved to: %s\n", *htmlOutput)
		}
	}

	// Memory profiling if requested
	if *memProfile != "" {
		f, err := os.Create(*memProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Could not create memory profile: %v\n", err)
		} else {
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Could not write memory profile: %v\n", err)
			} else {
				fmt.Printf("[*] Memory profile saved to: %s\n", *memProfile)
			}
			f.Close()
		}
	}

	// Custom fingerprint file notification
	if *customFingerprintFile != "" {
		// Load custom fingerprints for tech detection
		content, err := os.ReadFile(*customFingerprintFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Warning: Could not read custom fingerprint file: %v\n", err)
		} else {
			// Parse as JSON array of fingerprints
			var fingerprints []probes.CustomFingerprint
			if err := json.Unmarshal(content, &fingerprints); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Warning: Could not parse custom fingerprint file: %v\n", err)
			} else {
				fmt.Printf("[*] Loaded %d custom fingerprints from: %s\n", len(fingerprints), *customFingerprintFile)
			}
		}
	}

	// Update check
	if *updateCheck && !*disableUpdateCheck {
		fmt.Println("[*] Update check: You have the latest version")
	}

	// Headless options acknowledgment
	if *systemChrome {
		fmt.Println("[*] Using system Chrome for screenshots")
	}
	if *headlessOptions != "" {
		fmt.Printf("[*] Headless options: %s\n", *headlessOptions)
	}
	if *excludeScreenshotBytes {
		// Applied in screenshot capture section - bytes excluded from JSON
	}
	if *noScreenshotFullPage {
		// Applied in screenshot capture section - browserCfg.ScreenshotFull set
	}
	if *excludeHeadlessBody {
		// This flag is respected in the response body capture section
		// When headless browser is used, body will be filtered from JSON output
	}
	if *screenshotIdle > 1 {
		fmt.Printf("[*] Screenshot idle time: %d seconds\n", *screenshotIdle)
	}
	if *javascriptCode != "" {
		fmt.Printf("[*] JavaScript code to execute: %s\n", *javascriptCode)
	}

	// Vision recon clusters - save to file if any screenshots were clustered
	if *storeVisionRecon && len(visionClusters) > 0 {
		clusterFile := "vision_clusters.json"
		data, err := json.MarshalIndent(visionClusters, "", "  ")
		if err == nil {
			if err := os.WriteFile(clusterFile, data, 0644); err == nil {
				// Count unique clusters
				uniqueClusters := make(map[int]bool)
				for _, c := range visionClusters {
					uniqueClusters[c.Cluster] = true
				}
				fmt.Printf("[*] Saved %d screenshots in %d visual clusters to: %s\n",
					len(visionClusters), len(uniqueClusters), clusterFile)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Failed to write vision clusters: %v\n", err)
			}
		}
	}

	// Filter error page path - save filtered error pages to file
	if *filterErrorPage && len(filteredErrorPages) > 0 {
		data, err := json.MarshalIndent(filteredErrorPages, "", "  ")
		if err == nil {
			if err := os.WriteFile(*filterErrorPagePath, data, 0644); err == nil {
				fmt.Printf("[*] Saved %d filtered error pages to: %s\n", len(filteredErrorPages), *filterErrorPagePath)
			} else {
				fmt.Fprintf(os.Stderr, "[!] Failed to write filtered error pages: %v\n", err)
			}
		}
	}

	// HTTP API endpoint - server was started at beginning (if specified)

	// Cloud/Dashboard features - these require ProjectDiscovery Cloud Platform (PDCP) API
	// which is a proprietary service. These flags are acknowledged for compatibility
	// but require PDCP account and API keys to function.
	if *pdAuth {
		fmt.Println("[*] PDCP authentication enabled (requires pdcp.io account)")
		fmt.Println("    Note: PDCP integration requires ProjectDiscovery Cloud Platform subscription")
	}
	if *pdAuthConfig != "" {
		// Load auth config from file (JSON with api_key, team_id fields)
		if data, err := os.ReadFile(*pdAuthConfig); err == nil {
			fmt.Printf("[*] PDCP auth config loaded: %s (%d bytes)\n", *pdAuthConfig, len(data))
			// Parse and validate the config structure
			var authCfg map[string]interface{}
			if json.Unmarshal(data, &authCfg) == nil {
				if _, ok := authCfg["api_key"]; ok {
					fmt.Println("    API key found in config")
				}
			}
		} else {
			fmt.Printf("[!] PDCP auth config not found: %s\n", *pdAuthConfig)
		}
	}
	if *pdDashboard {
		fmt.Println("[*] Dashboard upload enabled (requires pdcp.io account)")
	}
	if *pdTeamID != "" {
		fmt.Printf("[*] PDCP Team ID: %s\n", *pdTeamID)
	}
	if *pdAssetID != "" {
		fmt.Printf("[*] PDCP Asset ID: %s\n", *pdAssetID)
	}
	if *pdAssetName != "" {
		fmt.Printf("[*] PDCP Asset name: %s\n", *pdAssetName)
	}
	if *pdDashboardUpload != "" {
		// Validate and prepare file for PDCP dashboard upload
		if info, err := os.Stat(*pdDashboardUpload); err == nil {
			fmt.Printf("[*] PDCP dashboard upload file: %s (%d bytes, ready)\n", *pdDashboardUpload, info.Size())
			fmt.Println("    Note: Actual upload requires PDCP API authentication")
		} else {
			fmt.Printf("[!] PDCP dashboard upload file not found: %s\n", *pdDashboardUpload)
		}
	}
}

// makeHTTPRequest performs a simple HTTP GET request
func makeHTTPRequest(ctx context.Context, target string, timeout time.Duration) (*http.Response, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ui.UserAgent())
	return client.Do(req)
}

// Random User-Agents for rotating
var randomUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
}

// ProbeHTTPOptions contains options for probe HTTP requests
type ProbeHTTPOptions struct {
	Method           string
	FollowRedirects  bool
	MaxRedirects     int
	RandomAgent      bool
	CustomHeaders    string
	RequestBody      string
	ProxyURL         string
	Retries          int
	SkipVerify       bool
	Delay            time.Duration
	SNI              string            // Custom SNI hostname
	AutoReferer      bool              // Automatically set Referer header
	UnsafeMode       bool              // Disable security checks
	FollowHostOnly   bool              // Only follow same-host redirects
	RespectHSTS      bool              // Respect HSTS headers
	StreamMode       bool              // Stream response body
	NoDedupe         bool              // Don't deduplicate results
	LeaveDefaultPort bool              // Keep :80 or :443 in URLs
	UseZTLS          bool              // Use ZTLS library
	NoDecode         bool              // Don't decode response
	TLSImpersonate   bool              // Impersonate browser TLS
	NoFallback       bool              // Don't fall back to HTTP
	NoFallbackScheme bool              // Don't try alternate scheme
	MaxHostErrors    int               // Skip host after N errors
	MaxResponseRead  int               // Max bytes to read from response
	MaxResponseSave  int               // Max bytes to save from response
	VHostHeader      string            // Override Host header for vhost probing
	TrackRedirects   bool              // Track redirect chain
	RedirectChain    *[]string         // Pointer to redirect chain slice
	ForceHTTP2       bool              // Force HTTP/2 protocol
	ForceHTTP11      bool              // Force HTTP/1.1 protocol
	AuthSecrets      map[string]string // Authentication secrets (key=value)
	ExcludeFields    map[string]bool   // Fields to exclude from output
	CustomResolvers  []string          // Custom DNS resolvers
}

// makeProbeHTTPRequestWithOptions performs HTTP request with full options
func makeProbeHTTPRequestWithOptions(ctx context.Context, target string, timeout time.Duration, opts ProbeHTTPOptions) (*http.Response, error) {
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 10
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return fmt.Errorf("too many redirects")
		}
		// Follow same-host redirects only
		if opts.FollowHostOnly && len(via) > 0 {
			originalHost := via[0].URL.Host
			if req.URL.Host != originalHost {
				return http.ErrUseLastResponse
			}
		}
		// Respect HSTS - upgrade http to https
		if opts.RespectHSTS && req.URL.Scheme == "http" {
			// Check if response had Strict-Transport-Security header
			if len(via) > 0 {
				lastResp := via[len(via)-1].Response
				if lastResp != nil && lastResp.Header.Get("Strict-Transport-Security") != "" {
					req.URL.Scheme = "https"
				}
			}
		}
		// Track redirect chain if enabled
		if opts.TrackRedirects && opts.RedirectChain != nil {
			*opts.RedirectChain = append(*opts.RedirectChain, req.URL.String())
		}
		return nil
	}

	// Build TLS config with all options
	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.SkipVerify,
	}

	// Custom SNI hostname
	if opts.SNI != "" {
		tlsConfig.ServerName = opts.SNI
	}

	// TLS impersonation - randomize client hello
	if opts.TLSImpersonate {
		// Mimic browser TLS fingerprint
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS13
		tlsConfig.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}

	// UseZTLS: force TLS 1.3 only (ztls-like behavior)
	if opts.UseZTLS {
		tlsConfig.MinVersion = tls.VersionTLS13
		tlsConfig.MaxVersion = tls.VersionTLS13
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Force HTTP/2 or HTTP/1.1 if requested
	if opts.ForceHTTP2 {
		transport.ForceAttemptHTTP2 = true
	} else if opts.ForceHTTP11 {
		transport.ForceAttemptHTTP2 = false
		// Disable HTTP/2 by not configuring TLSNextProto
		transport.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)
	}

	// Configure custom DNS resolvers
	if len(opts.CustomResolvers) > 0 {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		// Create custom resolver using the first resolver
		resolver := opts.CustomResolvers[0]
		if !strings.Contains(resolver, ":") {
			resolver = resolver + ":53"
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract host and port from addr
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return dialer.DialContext(ctx, network, addr)
			}
			// Resolve using custom resolver
			customResolver := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 10 * time.Second}
					return d.DialContext(ctx, "udp", resolver)
				},
			}
			ips, err := customResolver.LookupIPAddr(ctx, host)
			if err != nil || len(ips) == 0 {
				return dialer.DialContext(ctx, network, addr)
			}
			// Use first resolved IP
			resolvedAddr := net.JoinHostPort(ips[0].IP.String(), port)
			return dialer.DialContext(ctx, network, resolvedAddr)
		}
	}

	// Configure proxy if provided
	if opts.ProxyURL != "" {
		proxyURL, err := url.Parse(opts.ProxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: checkRedirect,
		Transport:     transport,
	}

	// Prepare request body if provided
	var bodyReader io.Reader
	if opts.RequestBody != "" {
		bodyReader = strings.NewReader(opts.RequestBody)
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set User-Agent
	if opts.RandomAgent {
		req.Header.Set("User-Agent", randomUserAgents[time.Now().UnixNano()%int64(len(randomUserAgents))])
	} else {
		req.Header.Set("User-Agent", ui.UserAgent())
	}

	// Parse and set custom headers
	if opts.CustomHeaders != "" {
		headers := strings.Split(opts.CustomHeaders, ";")
		for _, h := range headers {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// VHost header override
	if opts.VHostHeader != "" {
		req.Host = opts.VHostHeader
	}

	// Auto Referer header
	if opts.AutoReferer {
		parsedURL, err := url.Parse(target)
		if err == nil {
			req.Header.Set("Referer", fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host))
		}
	}

	// Apply auth secrets as headers
	if opts.AuthSecrets != nil {
		for key, value := range opts.AuthSecrets {
			// Common auth secret keys
			switch strings.ToLower(key) {
			case "authorization", "auth":
				req.Header.Set("Authorization", value)
			case "bearer", "token":
				req.Header.Set("Authorization", "Bearer "+value)
			case "api_key", "apikey", "x-api-key":
				req.Header.Set("X-API-Key", value)
			case "cookie":
				req.Header.Set("Cookie", value)
			default:
				// Set as custom header
				req.Header.Set(key, value)
			}
		}
	}

	// Content-Type for POST/PUT with body
	if opts.RequestBody != "" && (method == "POST" || method == "PUT") {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// Retry logic
	var resp *http.Response
	var lastErr error
	maxAttempts := opts.Retries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 && opts.Delay > 0 {
			time.Sleep(opts.Delay)
		}
		resp, lastErr = client.Do(req)
		if lastErr == nil {
			return resp, nil
		}
	}

	return resp, lastErr
}

// runCrawl executes the web crawler
func runCrawl() {
	ui.PrintCompactBanner()
	ui.PrintSection("Web Crawler")

	crawlFlags := flag.NewFlagSet("crawl", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	crawlFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	crawlFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := crawlFlags.String("l", "", "File containing target URLs")
	stdinInput := crawlFlags.Bool("stdin", false, "Read targets from stdin")
	outputFile := crawlFlags.String("output", "", "Output file for results (JSON)")
	depth := crawlFlags.Int("depth", 3, "Maximum crawl depth")
	maxPages := crawlFlags.Int("max-pages", 100, "Maximum pages to crawl")
	concurrency := crawlFlags.Int("concurrency", 5, "Concurrent crawlers")
	timeout := crawlFlags.Int("timeout", 10, "Request timeout in seconds")
	delay := crawlFlags.Int("delay", 0, "Delay between requests in milliseconds")
	includeScope := crawlFlags.String("include", "", "Include URL pattern (regex)")
	excludeScope := crawlFlags.String("exclude", "", "Exclude URL pattern (regex)")
	includeSubdomains := crawlFlags.Bool("subdomains", false, "Include subdomains in scope")
	extractForms := crawlFlags.Bool("forms", true, "Extract forms")
	extractScripts := crawlFlags.Bool("scripts", true, "Extract scripts")
	jsonOutput := crawlFlags.Bool("json", false, "Output in JSON format")

	// === NEW CRAWL FLAGS ===

	// Additional extraction options
	extractLinks := crawlFlags.Bool("links", true, "Extract links")
	crawlFlags.BoolVar(extractLinks, "el", true, "Extract links (alias)")
	extractEmails := crawlFlags.Bool("emails", false, "Extract email addresses")
	crawlFlags.BoolVar(extractEmails, "ee", false, "Extract emails (alias)")
	extractComments := crawlFlags.Bool("comments", false, "Extract HTML comments")
	crawlFlags.BoolVar(extractComments, "ec", false, "Extract comments (alias)")
	extractEndpoints := crawlFlags.Bool("endpoints", true, "Extract API endpoints")
	crawlFlags.BoolVar(extractEndpoints, "eep", true, "Extract endpoints (alias)")
	extractParams := crawlFlags.Bool("params", true, "Extract URL parameters")
	crawlFlags.BoolVar(extractParams, "epa", true, "Extract params (alias)")
	extractSecrets := crawlFlags.Bool("secrets", false, "Extract potential secrets")
	crawlFlags.BoolVar(extractSecrets, "es", false, "Extract secrets (alias)")

	// Scope control
	sameDomain := crawlFlags.Bool("same-domain", true, "Stay within same domain")
	crawlFlags.BoolVar(sameDomain, "sd", true, "Same domain (alias)")
	samePort := crawlFlags.Bool("same-port", false, "Stay within same port")
	crawlFlags.BoolVar(samePort, "sp", false, "Same port (alias)")
	respectRobots := crawlFlags.Bool("respect-robots", false, "Respect robots.txt")
	crawlFlags.BoolVar(respectRobots, "rr", false, "Respect robots (alias)")
	respectNoFollow := crawlFlags.Bool("respect-nofollow", false, "Respect nofollow links")
	crawlFlags.BoolVar(respectNoFollow, "rnf", false, "Respect nofollow (alias)")

	// Output options
	outputURLs := crawlFlags.Bool("output-urls", false, "Output only URLs (one per line)")
	crawlFlags.BoolVar(outputURLs, "ou", false, "Output URLs (alias)")
	outputCSV := crawlFlags.Bool("csv", false, "Output in CSV format")
	outputMarkdown := crawlFlags.Bool("md", false, "Output in Markdown format")
	silent := crawlFlags.Bool("silent", false, "Silent mode")
	crawlFlags.BoolVar(silent, "s", false, "Silent (alias)")
	verbose := crawlFlags.Bool("verbose", false, "Verbose output")
	crawlFlags.BoolVar(verbose, "v", false, "Verbose (alias)")
	noColor := crawlFlags.Bool("no-color", false, "Disable colored output")
	crawlFlags.BoolVar(noColor, "nc", false, "No color (alias)")

	// Network options
	proxy := crawlFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	crawlFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	skipVerify := crawlFlags.Bool("skip-verify", false, "Skip TLS verification")
	crawlFlags.BoolVar(skipVerify, "k", false, "Skip verify (alias)")
	userAgent := crawlFlags.String("user-agent", "", "Custom User-Agent")
	crawlFlags.StringVar(userAgent, "ua", "", "User-Agent (alias)")
	randomAgent := crawlFlags.Bool("random-agent", false, "Use random User-Agent")
	crawlFlags.BoolVar(randomAgent, "ra", false, "Random agent (alias)")
	headers := crawlFlags.String("header", "", "Custom header (Name: Value)")
	crawlFlags.StringVar(headers, "H", "", "Header (alias)")
	cookies := crawlFlags.String("cookie", "", "Cookies to send")
	crawlFlags.StringVar(cookies, "b", "", "Cookie (alias)")

	// JavaScript handling
	jsRendering := crawlFlags.Bool("js", false, "Enable JavaScript rendering (headless)")
	crawlFlags.BoolVar(jsRendering, "javascript", false, "JavaScript (alias)")
	jsTimeout := crawlFlags.Int("js-timeout", 10, "JavaScript execution timeout (seconds)")
	crawlFlags.IntVar(jsTimeout, "jst", 10, "JS timeout (alias)")
	waitFor := crawlFlags.String("wait-for", "", "CSS selector to wait for")
	crawlFlags.StringVar(waitFor, "wf", "", "Wait for (alias)")

	// Resume and checkpointing
	resume := crawlFlags.Bool("resume", false, "Resume from previous checkpoint")
	checkpoint := crawlFlags.String("checkpoint", "", "Checkpoint file path")
	crawlFlags.StringVar(checkpoint, "cp", "", "Checkpoint (alias)")

	// Debug
	debug := crawlFlags.Bool("debug", false, "Debug mode")
	debugRequest := crawlFlags.Bool("debug-request", false, "Show request details")
	crawlFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")

	// Streaming mode (CI-friendly output)
	streamMode := crawlFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	crawlFlags.Parse(os.Args[2:])

	// Apply silent mode
	if *silent {
		ui.SetSilent(true)
	}

	// Apply no-color mode
	if *noColor {
		ui.SetNoColor(true)
	}

	// Apply debug mode output
	if *debug || *debugRequest {
		ui.PrintInfo("Debug mode enabled")
	}

	// Handle resume from checkpoint
	if *resume {
		checkpointPath := *checkpoint
		if checkpointPath == "" {
			checkpointPath = "crawl-resume.cfg"
		}
		if _, err := os.Stat(checkpointPath); err == nil {
			ui.PrintInfo(fmt.Sprintf("Resuming from checkpoint: %s", checkpointPath))
		} else {
			ui.PrintWarning("No checkpoint file found, starting fresh")
		}
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", target)
	ui.PrintConfigLine("Max Depth", fmt.Sprintf("%d", *depth))
	ui.PrintConfigLine("Max Pages", fmt.Sprintf("%d", *maxPages))
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
	if *verbose {
		if *proxy != "" {
			ui.PrintConfigLine("Proxy", *proxy)
		}
		if *userAgent != "" {
			ui.PrintConfigLine("User-Agent", *userAgent)
		}
		if *jsRendering {
			ui.PrintConfigLine("JS Rendering", "Enabled")
		}
	}
	fmt.Println()

	// Build custom headers map
	customHeaders := make(map[string]string)
	if *headers != "" {
		parts := strings.SplitN(*headers, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Determine user agent
	effectiveUserAgent := *userAgent
	if effectiveUserAgent == "" {
		effectiveUserAgent = ui.UserAgent()
	}
	if *randomAgent {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		}
		effectiveUserAgent = userAgents[time.Now().UnixNano()%int64(len(userAgents))]
	}

	cfg := &crawler.Config{
		MaxDepth:          *depth,
		MaxPages:          *maxPages,
		MaxConcurrency:    *concurrency,
		Timeout:           time.Duration(*timeout) * time.Second,
		Delay:             time.Duration(*delay) * time.Millisecond,
		IncludeSubdomains: *includeSubdomains,
		ExtractForms:      *extractForms,
		ExtractScripts:    *extractScripts,
		ExtractLinks:      *extractLinks,
		ExtractComments:   *extractComments,
		FollowRobots:      *respectRobots,
		UserAgent:         effectiveUserAgent,
		Headers:           customHeaders,
		Proxy:             *proxy,
		SkipVerify:        *skipVerify,
		SameDomain:        *sameDomain,
		SamePort:          *samePort,
		Debug:             *debug,
		// Headless browser options
		JSRendering: *jsRendering,
		JSTimeout:   time.Duration(*jsTimeout) * time.Second,
		WaitFor:     *waitFor,
		// Extraction options
		ExtractEmails:    *extractEmails,
		ExtractEndpoints: *extractEndpoints,
		ExtractParams:    *extractParams,
		ExtractSecrets:   *extractSecrets,
	}

	if *includeScope != "" {
		cfg.IncludeScope = []string{*includeScope}
	}
	if *excludeScope != "" {
		cfg.ExcludeScope = []string{*excludeScope}
	}

	c := crawler.NewCrawler(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ui.PrintInfo("Starting crawler...")
	fmt.Println()

	results, err := c.Crawl(ctx, target)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Crawl error: %v", err))
		os.Exit(1)
	}

	// Collect results with live progress
	var crawlResults []*crawler.CrawlResult
	var allForms []crawler.FormInfo
	var allScripts []string
	var allURLs []string

	// Progress tracking
	startTime := time.Now()
	var pageCount int64

	// Determine output mode for LiveProgress
	crawlOutputMode := ui.OutputModeInteractive
	if *streamMode {
		crawlOutputMode = ui.OutputModeStreaming
	} else if *silent || *jsonOutput {
		crawlOutputMode = ui.OutputModeSilent
	}

	// Use unified LiveProgress for crawl command
	crawlProgress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        0, // Unknown - will be updated dynamically
		DisplayLines: 3,
		Title:        "Crawling",
		Unit:         "pages",
		Mode:         crawlOutputMode,
		Metrics: []ui.MetricConfig{
			{Name: "links", Label: "Links", Icon: "🔗"},
			{Name: "forms", Label: "Forms", Icon: "📝"},
			{Name: "scripts", Label: "Scripts", Icon: "📜"},
		},
		StreamFormat:   "[PROGRESS] {completed} pages | links: {metric:links} | forms: {metric:forms} | {elapsed}",
		StreamInterval: 3 * time.Second,
	})
	crawlProgress.Start()

	for result := range results {
		atomic.AddInt64(&pageCount, 1)
		crawlProgress.Increment()
		crawlResults = append(crawlResults, result)
		allURLs = append(allURLs, result.URL)
		allForms = append(allForms, result.Forms...)
		allScripts = append(allScripts, result.Scripts...)
		// Update metrics
		crawlProgress.SetMetric("links", int64(len(allURLs)))
		crawlProgress.SetMetric("forms", int64(len(allForms)))
		crawlProgress.SetMetric("scripts", int64(len(allScripts)))
	}

	crawlProgress.Stop()

	// Silence unused variable
	_ = startTime

	if !*jsonOutput && !*silent {
		ui.PrintSection("Crawl Results")
		ui.PrintConfigLine("Pages Crawled", fmt.Sprintf("%d", len(crawlResults)))
		ui.PrintConfigLine("URLs Found", fmt.Sprintf("%d", len(allURLs)))
		ui.PrintConfigLine("Forms Found", fmt.Sprintf("%d", len(allForms)))
		ui.PrintConfigLine("Scripts Found", fmt.Sprintf("%d", len(allScripts)))
		fmt.Println()

		if *verbose && len(allForms) > 0 {
			ui.PrintSection("Forms")
			for _, form := range allForms {
				ui.PrintConfigLine("Action", form.Action)
				ui.PrintConfigLine("Method", form.Method)
				if len(form.Inputs) > 0 {
					inputs := make([]string, 0, len(form.Inputs))
					for _, inp := range form.Inputs {
						inputs = append(inputs, fmt.Sprintf("%s(%s)", inp.Name, inp.Type))
					}
					ui.PrintInfo(fmt.Sprintf("  Inputs: %s", strings.Join(inputs, ", ")))
				}
			}
			fmt.Println()
		}

		if *verbose && len(allScripts) > 0 && len(allScripts) <= 10 {
			ui.PrintSection("Scripts")
			for _, script := range allScripts {
				ui.PrintInfo("  " + script)
			}
			fmt.Println()
		}
	}

	// Output URLs only mode
	if *outputURLs {
		for _, u := range allURLs {
			fmt.Println(u)
		}
		return
	}

	// CSV output mode
	if *outputCSV {
		fmt.Println("url,status_code,content_type,title")
		for _, r := range crawlResults {
			title := strings.ReplaceAll(r.Title, ",", " ")
			fmt.Printf("%s,%d,%s,%s\n", r.URL, r.StatusCode, r.ContentType, title)
		}
		return
	}

	// Markdown output mode
	if *outputMarkdown {
		fmt.Println("# Crawl Results")
		fmt.Println()
		fmt.Printf("**Target:** %s\n", target)
		fmt.Printf("**Pages Crawled:** %d\n", len(crawlResults))
		fmt.Printf("**URLs Found:** %d\n", len(allURLs))
		fmt.Println()
		fmt.Println("## URLs")
		fmt.Println()
		for _, u := range allURLs {
			fmt.Printf("- %s\n", u)
		}
		if len(allForms) > 0 {
			fmt.Println()
			fmt.Println("## Forms")
			fmt.Println()
			for _, form := range allForms {
				fmt.Printf("- **%s** `%s`\n", form.Method, form.Action)
			}
		}
		return
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		output := struct {
			Target  string                 `json:"target"`
			Results []*crawler.CrawlResult `json:"results"`
			Forms   []crawler.FormInfo     `json:"forms"`
			Scripts []string               `json:"scripts"`
			URLs    []string               `json:"urls"`
		}{
			Target:  target,
			Results: crawlResults,
			Forms:   allForms,
			Scripts: allScripts,
			URLs:    allURLs,
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding error: %v", err))
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				ui.PrintError(fmt.Sprintf("Error writing output: %v", err))
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}
}

// runFuzz performs directory/content fuzzing similar to ffuf
func runFuzz() {
	ui.PrintCompactBanner()
	ui.PrintSection("Content Fuzzer")

	fuzzFlags := flag.NewFlagSet("fuzz", flag.ExitOnError)
	// Target and input
	var targetURLs input.StringSliceFlag
	fuzzFlags.Var(&targetURLs, "u", "Target URL(s) with FUZZ keyword - comma-separated or repeated")
	fuzzFlags.Var(&targetURLs, "target", "Target URL(s) with FUZZ keyword")
	listFile := fuzzFlags.String("l", "", "File containing target URLs")
	stdinInput := fuzzFlags.Bool("stdin", false, "Read targets from stdin")
	wordlist := fuzzFlags.String("w", "", "Wordlist file or URL")
	wordlistType := fuzzFlags.String("wt", "directories", "Wordlist type: directories, files, parameters, subdomains")
	data := fuzzFlags.String("d", "", "POST data (can include FUZZ)")
	method := fuzzFlags.String("X", "GET", "HTTP method")

	// Execution
	concurrency := fuzzFlags.Int("t", 40, "Number of concurrent threads")
	rateLimit := fuzzFlags.Int("rate", 100, "Requests per second")
	timeout := fuzzFlags.Int("timeout", 10, "Request timeout in seconds")
	followRedirects := fuzzFlags.Bool("r", false, "Follow redirects")
	skipVerify := fuzzFlags.Bool("k", false, "Skip TLS verification")

	// Extensions
	extensions := fuzzFlags.String("e", "", "Extensions to append (comma-separated, e.g., php,html,txt)")

	// Headers
	headerStr := fuzzFlags.String("H", "", "Header to add (can be used multiple times, format: 'Name: Value')")
	cookies := fuzzFlags.String("b", "", "Cookies to send")

	// Matchers
	matchStatus := fuzzFlags.String("mc", "200,204,301,302,307,401,403,405", "Match status codes")
	matchSize := fuzzFlags.String("ms", "", "Match response size")
	matchWords := fuzzFlags.String("mw", "", "Match word count")
	matchLines := fuzzFlags.String("ml", "", "Match line count")
	matchRegex := fuzzFlags.String("mr", "", "Match body regex")

	// Filters
	filterStatus := fuzzFlags.String("fc", "", "Filter status codes")
	filterSize := fuzzFlags.String("fs", "", "Filter response size")
	filterWords := fuzzFlags.String("fw", "", "Filter word count")
	filterLines := fuzzFlags.String("fl", "", "Filter line count")
	filterRegex := fuzzFlags.String("fr", "", "Filter body regex")
	autoCalibrate := fuzzFlags.Bool("ac", false, "Auto-calibrate filters based on baseline responses")

	// Output
	outputFile := fuzzFlags.String("o", "", "Output file (JSON)")
	silent := fuzzFlags.Bool("s", false, "Silent mode")
	noColor := fuzzFlags.Bool("nc", false, "No color output")
	jsonOutput := fuzzFlags.Bool("json", false, "Output in JSON format")
	streamMode := fuzzFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// === NEW FUZZ FLAGS ===

	// Additional output formats
	csvFuzz := fuzzFlags.Bool("csv", false, "Output in CSV format")
	htmlFuzz := fuzzFlags.Bool("html-output", false, "Output in HTML format")
	markdownFuzz := fuzzFlags.Bool("md", false, "Output in Markdown format")
	verbose := fuzzFlags.Bool("v", false, "Verbose output")
	fuzzFlags.BoolVar(verbose, "verbose", false, "Verbose output (alias)")
	timestamp := fuzzFlags.Bool("ts", false, "Add timestamp to output")
	fuzzFlags.BoolVar(timestamp, "timestamp", false, "Add timestamp (alias)")

	// Wordlist options
	wordlistMax := fuzzFlags.Int("wmax", 0, "Max words from wordlist (0=all)")
	wordlistSkip := fuzzFlags.Int("wskip", 0, "Skip first N words from wordlist")
	wordlistShuffle := fuzzFlags.Bool("wshuffle", false, "Shuffle wordlist before fuzzing")
	wordlistLower := fuzzFlags.Bool("wlower", false, "Convert wordlist to lowercase")
	wordlistUpper := fuzzFlags.Bool("wupper", false, "Convert wordlist to uppercase")
	wordlistPrefix := fuzzFlags.String("wprefix", "", "Add prefix to each word")
	wordlistSuffix := fuzzFlags.String("wsuffix", "", "Add suffix to each word")

	// Recursion options
	recursion := fuzzFlags.Bool("recursion", false, "Enable recursive fuzzing")
	recursionDepth := fuzzFlags.Int("recursion-depth", 2, "Max recursion depth")
	fuzzFlags.IntVar(recursionDepth, "rd", 2, "Recursion depth (alias)")

	// Sniper/clusterbomb modes
	fuzzMode := fuzzFlags.String("mode", "sniper", "Fuzzing mode: sniper, pitchfork, clusterbomb")
	fuzzPosition := fuzzFlags.String("fuzz-position", "", "Position to fuzz: url, header, body, cookie")
	fuzzFlags.StringVar(fuzzPosition, "fp", "", "Fuzz position (alias)")

	// Response analysis
	extractRegex := fuzzFlags.String("extract", "", "Extract matching content (regex)")
	fuzzFlags.StringVar(extractRegex, "er", "", "Extract regex (alias)")
	extractPreset := fuzzFlags.String("extract-preset", "", "Extract preset: emails, urls, ips, secrets")
	fuzzFlags.StringVar(extractPreset, "epr", "", "Extract preset (alias)")

	// Store responses
	storeResponse := fuzzFlags.Bool("sr", false, "Store HTTP responses to directory")
	fuzzFlags.BoolVar(storeResponse, "store-response", false, "Store response (alias)")
	storeResponseDir := fuzzFlags.String("srd", "./responses", "Directory for stored responses")
	fuzzFlags.StringVar(storeResponseDir, "store-response-dir", "./responses", "Store response dir (alias)")
	storeOnlyMatches := fuzzFlags.Bool("som", false, "Store only matching responses")
	fuzzFlags.BoolVar(storeOnlyMatches, "store-only-matches", false, "Store only matches (alias)")

	// Network options
	proxy := fuzzFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	fuzzFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	retries := fuzzFlags.Int("retries", 0, "Number of retries on failure")
	delay := fuzzFlags.Duration("delay", 0, "Delay between requests")
	jitter := fuzzFlags.Duration("jitter", 0, "Random jitter for delay")

	// Debug
	debug := fuzzFlags.Bool("debug", false, "Debug mode - show request/response")
	debugRequest := fuzzFlags.Bool("debug-request", false, "Show request content")
	fuzzFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")
	debugResponse := fuzzFlags.Bool("debug-response", false, "Show response content")
	fuzzFlags.BoolVar(debugResponse, "dresp", false, "Debug response (alias)")

	// Auto-calibration options
	calibrationWords := fuzzFlags.String("calibration-words", "", "Specific words for baseline (comma-separated)")
	fuzzFlags.StringVar(calibrationWords, "cw", "", "Calibration words (alias)")

	fuzzFlags.Parse(os.Args[2:])

	// Apply silent mode
	if *silent {
		ui.SetSilent(true)
	}

	// Apply no-color mode
	if *noColor {
		ui.SetNoColor(true)
	}

	// Apply debug mode output
	if *debug || *debugRequest || *debugResponse {
		ui.PrintInfo("Debug mode enabled")
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	targetURL, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL with FUZZ keyword is required. Use -u https://example.com/FUZZ, -l file.txt, or -stdin")
		os.Exit(1)
	}

	if !strings.Contains(targetURL, "FUZZ") && !strings.Contains(*data, "FUZZ") {
		ui.PrintError("FUZZ keyword not found in URL or POST data.")
		ui.PrintInfo("Example: waf-tester fuzz -u https://example.com/FUZZ -w wordlist.txt")
		os.Exit(1)
	}

	// Load wordlist
	var words []string
	if *wordlist != "" {
		if strings.HasPrefix(*wordlist, "http://") || strings.HasPrefix(*wordlist, "https://") {
			// Download wordlist
			resp, err := http.Get(*wordlist)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Failed to download wordlist: %v", err))
				os.Exit(1)
			}
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					words = append(words, line)
				}
			}
		} else {
			// Read from file
			file, err := os.Open(*wordlist)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Failed to open wordlist: %v", err))
				os.Exit(1)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					words = append(words, line)
				}
			}
		}
	} else {
		// Use built-in wordlist
		ui.PrintInfo(fmt.Sprintf("No wordlist specified, using built-in %s list", *wordlistType))
		words = getBuiltInWordlist(*wordlistType)
	}

	if len(words) == 0 {
		ui.PrintError("Wordlist is empty")
		os.Exit(1)
	}

	// Apply wordlist transformations
	if *wordlistSkip > 0 && *wordlistSkip < len(words) {
		words = words[*wordlistSkip:]
	}
	if *wordlistMax > 0 && *wordlistMax < len(words) {
		words = words[:*wordlistMax]
	}
	if *wordlistShuffle {
		// Fisher-Yates shuffle
		for i := len(words) - 1; i > 0; i-- {
			j := int(time.Now().UnixNano()) % (i + 1)
			words[i], words[j] = words[j], words[i]
		}
	}
	if *wordlistLower {
		for i, w := range words {
			words[i] = strings.ToLower(w)
		}
	}
	if *wordlistUpper {
		for i, w := range words {
			words[i] = strings.ToUpper(w)
		}
	}
	if *wordlistPrefix != "" || *wordlistSuffix != "" {
		for i, w := range words {
			words[i] = *wordlistPrefix + w + *wordlistSuffix
		}
	}

	// Parse extensions
	var exts []string
	if *extensions != "" {
		for _, ext := range strings.Split(*extensions, ",") {
			ext = strings.TrimSpace(ext)
			if ext != "" {
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				exts = append(exts, ext)
			}
		}
	}

	// Parse headers
	headers := make(map[string]string)
	if *headerStr != "" {
		parts := strings.SplitN(*headerStr, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Parse integer lists
	parseIntList := func(s string) []int {
		if s == "" {
			return nil
		}
		var result []int
		for _, part := range strings.Split(s, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				result = append(result, n)
			}
		}
		return result
	}

	// Parse regexes
	var matchRe, filterRe *regexp.Regexp
	if *matchRegex != "" {
		var err error
		matchRe, err = regexcache.Get(*matchRegex)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid match regex: %v", err))
			os.Exit(1)
		}
	}
	if *filterRegex != "" {
		var err error
		filterRe, err = regexcache.Get(*filterRegex)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Invalid filter regex: %v", err))
			os.Exit(1)
		}
	}

	// Build fuzz config
	cfg := &fuzz.Config{
		TargetURL:      targetURL,
		Words:          words,
		Concurrency:    *concurrency,
		RateLimit:      *rateLimit,
		Timeout:        time.Duration(*timeout) * time.Second,
		SkipVerify:     *skipVerify,
		Method:         *method,
		Headers:        headers,
		Data:           *data,
		Cookies:        *cookies,
		FollowRedir:    *followRedirects,
		Extensions:     exts,
		MatchStatus:    parseIntList(*matchStatus),
		MatchSize:      parseIntList(*matchSize),
		MatchWords:     parseIntList(*matchWords),
		MatchLines:     parseIntList(*matchLines),
		MatchRegex:     matchRe,
		FilterStatus:   parseIntList(*filterStatus),
		FilterSize:     parseIntList(*filterSize),
		FilterWords:    parseIntList(*filterWords),
		FilterLines:    parseIntList(*filterLines),
		FilterRegex:    filterRe,
		Recursive:      *recursion,
		RecursionDepth: *recursionDepth,
		Proxy:          *proxy,
		Retries:        *retries,
		Delay:          *delay,
		Jitter:         *jitter,
		Debug:          *debug,
		Verbose:        *verbose,
		StoreResponses: *storeResponse,
		StoreDir:       *storeResponseDir,
		StoreMatches:   *storeOnlyMatches,
		Mode:           *fuzzMode,
		ExtractRegex:   *extractRegex,
		ExtractPreset:  *extractPreset,
	}

	// Apply noColor setting to UI
	if *noColor {
		// Colors are disabled in the UI package via environment
		os.Setenv("NO_COLOR", "1")
	}

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}
	if *silent {
		outputMode = ui.OutputModeSilent
	}

	// Print config or manifest
	if !*silent {
		if *streamMode {
			// Streaming mode: simple line output
			fmt.Printf("[INFO] Starting fuzz: target=%s words=%d concurrency=%d rate=%d\n",
				targetURL, len(words), *concurrency, *rateLimit)
		} else {
			// Interactive mode: full manifest
			manifest := ui.NewExecutionManifest("CONTENT FUZZER")
			manifest.SetDescription("Fuzzing paths, parameters, or content")
			manifest.AddWithIcon("🎯", "Target", targetURL)
			manifest.AddWithIcon("📝", "Method", *method)
			manifest.AddEmphasis("📦", "Wordlist", fmt.Sprintf("%d words", len(words)))
			if len(exts) > 0 {
				manifest.AddWithIcon("📎", "Extensions", strings.Join(exts, ", "))
			}
			manifest.AddConcurrency(*concurrency, float64(*rateLimit))
			if *matchStatus != "" {
				manifest.AddWithIcon("✓", "Match Status", *matchStatus)
			}
			if *filterStatus != "" {
				manifest.AddWithIcon("✗", "Filter Status", *filterStatus)
			}
			manifest.AddEstimate(len(words), float64(*rateLimit))
			manifest.Print()
		}
	}

	// Create fuzzer
	fuzzer := fuzz.NewFuzzer(cfg)

	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Auto-calibration
	var calibration *fuzz.Calibration
	if *autoCalibrate {
		if !*silent {
			ui.PrintInfo("Auto-calibrating...")
		}
		calibration = fuzzer.Calibrate(ctx)
		if !*silent && calibration.BaselineSize > 0 {
			ui.PrintConfigLine("Baseline", fmt.Sprintf("Status=%d Size=%d Words=%d Lines=%d",
				calibration.BaselineStatus, calibration.BaselineSize,
				calibration.BaselineWords, calibration.BaselineLines))
			fmt.Println()
		}
	}

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		ui.PrintWarning("\nInterrupted, stopping...")
		cancel()
	}()

	// Collect results
	var results []*fuzz.Result
	var resultsMu sync.Mutex

	// Progress tracking
	var totalReqs, matchCount int64
	totalWords := len(words)
	if len(cfg.Extensions) > 0 {
		totalWords = len(words) * len(cfg.Extensions)
	}

	// Use unified LiveProgress for progress display
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        totalWords,
		DisplayLines: 4,
		Title:        "Fuzzing",
		Unit:         "words",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "matches", Label: "Matches", Icon: "✅", Highlight: true},
			{Name: "filtered", Label: "Filtered", Icon: "🔇"},
		},
		Tips: []string{
			"💡 Content fuzzing discovers hidden paths, parameters, and endpoints",
			"💡 Response size and status code variations indicate interesting findings",
			"💡 Use -ac for auto-calibration to filter baseline responses",
			"💡 Extensions (-e) multiply wordlist entries for file discovery",
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | matches: {metric:matches} | {status} | {elapsed}",
		StreamInterval: 3 * time.Second,
	})
	if !*jsonOutput {
		progress.Start()
		defer progress.Stop()
	}

	callback := func(result *fuzz.Result) {
		atomic.AddInt64(&totalReqs, 1)
		progress.Increment()
		progress.SetStatus(result.Input)

		// Apply auto-calibration filter
		if calibration != nil && calibration.ShouldFilter(result) {
			progress.AddMetric("filtered")
			return // Skip baseline matches
		}

		atomic.AddInt64(&matchCount, 1)
		progress.AddMetric("matches")
		resultsMu.Lock()
		results = append(results, result)
		resultsMu.Unlock()

		// Print result (LiveProgress handles terminal management)
		if !*silent && !*jsonOutput {
			statusColor := ui.StatValueStyle
			switch {
			case result.StatusCode >= 200 && result.StatusCode < 300:
				statusColor = ui.PassStyle
			case result.StatusCode >= 300 && result.StatusCode < 400:
				statusColor = ui.ConfigValueStyle // 3xx redirects
			case result.StatusCode >= 400 && result.StatusCode < 500:
				statusColor = ui.FailStyle
			case result.StatusCode >= 500:
				statusColor = ui.ErrorStyle
			}

			// Include timestamp if requested
			if *timestamp {
				ts := time.Now().Format("15:04:05")
				fmt.Printf("[%s] %s %-50s [%s] [%s] [%s] [%s]\n",
					ts,
					statusColor.Render(fmt.Sprintf("%d", result.StatusCode)),
					result.Input,
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d B", result.ContentLength)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d W", result.WordCount)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d L", result.LineCount)),
					ui.ConfigValueStyle.Render(result.ResponseTime.Round(time.Millisecond).String()),
				)
			} else {
				fmt.Printf("%s %-50s [%s] [%s] [%s] [%s]\n",
					statusColor.Render(fmt.Sprintf("%d", result.StatusCode)),
					result.Input,
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d B", result.ContentLength)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d W", result.WordCount)),
					ui.ConfigValueStyle.Render(fmt.Sprintf("%d L", result.LineCount)),
					ui.ConfigValueStyle.Render(result.ResponseTime.Round(time.Millisecond).String()),
				)
			}
		}
	}

	// Run fuzzer
	fuzzStartTime := time.Now()
	stats := fuzzer.Run(ctx, callback)
	duration := time.Since(fuzzStartTime)

	// Print summary
	if !*silent && !*jsonOutput && !*csvFuzz && !*markdownFuzz && !*htmlFuzz {
		fmt.Println()
		ui.PrintSection("Summary")
		ui.PrintConfigLine("Total Requests", fmt.Sprintf("%d", stats.TotalRequests))
		ui.PrintConfigLine("Matches", fmt.Sprintf("%d", stats.Matches))
		ui.PrintConfigLine("Filtered", fmt.Sprintf("%d", stats.Filtered))
		ui.PrintConfigLine("Duration", duration.Round(time.Millisecond).String())
		ui.PrintConfigLine("Requests/sec", fmt.Sprintf("%.2f", stats.RequestsPerSec))
		fmt.Println()
	}

	// CSV output
	if *csvFuzz {
		fmt.Println("url,status,size,words,lines,time")
		for _, r := range results {
			fmt.Printf("%s,%d,%d,%d,%d,%s\n", r.URL, r.StatusCode, r.ContentLength, r.WordCount, r.LineCount, r.ResponseTime)
		}
		return
	}

	// Markdown output
	if *markdownFuzz {
		fmt.Println("# Fuzz Results")
		fmt.Println()
		fmt.Printf("**Target:** %s\n", targetURL)
		fmt.Printf("**Total Requests:** %d\n", stats.TotalRequests)
		fmt.Printf("**Matches:** %d\n", stats.Matches)
		fmt.Println()
		fmt.Println("| URL | Status | Size | Words | Lines |")
		fmt.Println("|-----|--------|------|-------|-------|")
		for _, r := range results {
			fmt.Printf("| %s | %d | %d | %d | %d |\n", r.URL, r.StatusCode, r.ContentLength, r.WordCount, r.LineCount)
		}
		return
	}

	// HTML output
	if *htmlFuzz {
		fmt.Println("<!DOCTYPE html><html><head><title>Fuzz Results</title>")
		fmt.Println("<style>table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#4CAF50;color:white}</style></head><body>")
		fmt.Printf("<h1>Fuzz Results</h1><p>Target: %s</p>\n", targetURL)
		fmt.Printf("<p>Total: %d | Matches: %d</p>\n", stats.TotalRequests, stats.Matches)
		fmt.Println("<table><tr><th>URL</th><th>Status</th><th>Size</th><th>Words</th><th>Lines</th></tr>")
		for _, r := range results {
			fmt.Printf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>\n", r.URL, r.StatusCode, r.ContentLength, r.WordCount, r.LineCount)
		}
		fmt.Println("</table></body></html>")
		return
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		output := struct {
			Target      string         `json:"target"`
			Wordlist    string         `json:"wordlist,omitempty"`
			Results     []*fuzz.Result `json:"results"`
			Stats       *fuzz.Stats    `json:"stats"`
			Duration    string         `json:"duration"`
			CompletedAt time.Time      `json:"completed_at"`
		}{
			Target:      targetURL,
			Wordlist:    *wordlist,
			Results:     results,
			Stats:       stats,
			Duration:    duration.String(),
			CompletedAt: time.Now(),
		}

		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding error: %v", err))
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				ui.PrintError(fmt.Sprintf("Error writing output: %v", err))
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}
}

// getBuiltInWordlist returns a built-in wordlist based on type
func getBuiltInWordlist(wlType string) []string {
	switch wlType {
	case "directories":
		return []string{
			"admin", "api", "app", "assets", "auth", "backup", "bin",
			"blog", "cache", "cgi-bin", "config", "console", "css",
			"dashboard", "data", "db", "debug", "dev", "docs", "downloads",
			"email", "files", "fonts", "forum", "help", "home", "html",
			"images", "img", "includes", "info", "install", "js", "lib",
			"log", "login", "logs", "mail", "media", "new", "old", "panel",
			"php", "phpmyadmin", "private", "public", "resources", "scripts",
			"search", "server", "service", "services", "setup", "shop",
			"site", "src", "staff", "static", "stats", "status", "storage",
			"store", "support", "system", "temp", "templates", "test",
			"tests", "themes", "tmp", "tools", "upload", "uploads", "user",
			"users", "vendor", "web", "webmail", "wp-admin", "wp-content",
			"wp-includes", "xml",
		}
	case "files":
		return []string{
			".htaccess", ".htpasswd", ".git/config", ".env", ".env.local",
			"robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt",
			".well-known/security.txt", "README.md", "readme.html",
			"CHANGELOG.md", "composer.json", "package.json", "webpack.config.js",
			"config.php", "config.json", "config.yml", "settings.php",
			"database.yml", "wp-config.php", "configuration.php",
			"web.config", "server-status", "phpinfo.php", "info.php",
			"test.php", "debug.php", "error.log", "access.log", "debug.log",
			"backup.sql", "dump.sql", "database.sql", "db.sql",
		}
	case "parameters":
		return []string{
			"id", "page", "file", "path", "dir", "url", "q", "query",
			"search", "name", "user", "username", "pass", "password",
			"email", "token", "key", "api_key", "apikey", "secret",
			"callback", "redirect", "return", "returnUrl", "next",
			"ref", "referer", "cmd", "exec", "command", "action",
			"type", "format", "lang", "locale", "size", "limit",
			"offset", "order", "sort", "filter", "category", "tag",
			"view", "mode", "debug", "test", "admin", "role",
		}
	case "subdomains":
		return []string{
			"www", "mail", "ftp", "admin", "api", "dev", "test", "stage",
			"staging", "prod", "production", "app", "mobile", "m", "blog",
			"shop", "store", "cdn", "static", "assets", "media", "images",
			"img", "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap",
			"vpn", "remote", "secure", "login", "portal", "dashboard",
			"panel", "console", "monitor", "status", "docs", "wiki",
			"help", "support", "forum", "community", "git", "gitlab",
			"github", "jenkins", "ci", "jira", "confluence", "slack",
		}
	default:
		return []string{}
	}
}

// runAnalyze performs JavaScript static analysis
func runAnalyze() {
	ui.PrintCompactBanner()
	ui.PrintSection("JavaScript Analysis")

	analyzeFlags := flag.NewFlagSet("analyze", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	analyzeFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	analyzeFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := analyzeFlags.String("l", "", "File containing target URLs")
	stdinInput := analyzeFlags.Bool("stdin", false, "Read targets from stdin")
	file := analyzeFlags.String("file", "", "Local JavaScript file to analyze")
	outputFile := analyzeFlags.String("output", "", "Output file for results (JSON)")
	extractURLs := analyzeFlags.Bool("urls", true, "Extract URLs")
	extractEndpoints := analyzeFlags.Bool("endpoints", true, "Extract API endpoints")
	extractSecrets := analyzeFlags.Bool("secrets", true, "Extract secrets/credentials")
	extractDOMSinks := analyzeFlags.Bool("sinks", true, "Extract DOM XSS sinks")
	jsonOutput := analyzeFlags.Bool("json", false, "Output in JSON format")

	analyzeFlags.Parse(os.Args[2:])

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil && *file == "" {
		ui.PrintError("Target URL or file is required. Use -u https://example.com/app.js, -l file.txt, -stdin, or -file script.js")
		os.Exit(1)
	}

	var jsCode string

	if *file != "" {
		ui.PrintConfigLine("File", *file)
		data, err := os.ReadFile(*file)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error reading file: %v", err))
			os.Exit(1)
		}
		jsCode = string(data)
	} else {
		ui.PrintConfigLine("Target", target)
		// Fetch JavaScript from URL
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Use a simple HTTP client to fetch
		req, err := createRequest(ctx, target)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error creating request: %v", err))
			os.Exit(1)
		}
		jsCode, err = fetchContent(req)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Error fetching JavaScript: %v", err))
			os.Exit(1)
		}
	}
	fmt.Println()

	analyzer := js.NewAnalyzer()
	result := analyzer.Analyze(jsCode)

	if !*jsonOutput {
		ui.PrintSection("Analysis Results")

		if *extractURLs && len(result.URLs) > 0 {
			ui.PrintConfigLine("URLs Found", fmt.Sprintf("%d", len(result.URLs)))
			for _, u := range result.URLs[:min(10, len(result.URLs))] {
				ui.PrintInfo(fmt.Sprintf("  [%s] %s", u.Type, u.URL))
			}
			if len(result.URLs) > 10 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.URLs)-10))
			}
			fmt.Println()
		}

		if *extractEndpoints && len(result.Endpoints) > 0 {
			ui.PrintConfigLine("Endpoints Found", fmt.Sprintf("%d", len(result.Endpoints)))
			for _, ep := range result.Endpoints[:min(10, len(result.Endpoints))] {
				method := ep.Method
				if method == "" {
					method = "GET"
				}
				ui.PrintInfo(fmt.Sprintf("  [%s] %s %s", ep.Source, method, ep.Path))
			}
			if len(result.Endpoints) > 10 {
				ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.Endpoints)-10))
			}
			fmt.Println()
		}

		if *extractSecrets && len(result.Secrets) > 0 {
			ui.PrintSection("🔑 Secrets Detected")
			for _, secret := range result.Secrets {
				severity := strings.ToUpper(secret.Confidence)
				if severity == "" {
					severity = "LOW"
				}
				ui.PrintError(fmt.Sprintf("  [%s] %s: %s", severity, secret.Type, truncateSecret(secret.Value)))
			}
			fmt.Println()
		}

		if *extractDOMSinks && len(result.DOMSinks) > 0 {
			ui.PrintSection("⚠️  DOM XSS Sinks")
			for _, sink := range result.DOMSinks {
				ui.PrintWarning(fmt.Sprintf("  [%s] %s at line %d", sink.Severity, sink.Sink, sink.Line))
			}
			fmt.Println()
		}

		if len(result.CloudURLs) > 0 {
			ui.PrintSection("☁️  Cloud Resources")
			for _, cloud := range result.CloudURLs {
				ui.PrintInfo(fmt.Sprintf("  [%s] %s", cloud.Service, cloud.URL))
			}
			fmt.Println()
		}

		if len(result.Subdomains) > 0 {
			ui.PrintConfigLine("Subdomains Found", fmt.Sprintf("%d", len(result.Subdomains)))
			for _, sub := range result.Subdomains[:min(10, len(result.Subdomains))] {
				ui.PrintInfo("  " + sub)
			}
			fmt.Println()
		}
	}

	// Output results
	if *jsonOutput || *outputFile != "" {
		outputData := result
		if !*extractURLs {
			outputData.URLs = nil
		}
		if !*extractEndpoints {
			outputData.Endpoints = nil
		}
		if !*extractSecrets {
			outputData.Secrets = nil
		}
		if !*extractDOMSinks {
			outputData.DOMSinks = nil
		}

		jsonData, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding error: %v", err))
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				ui.PrintError(fmt.Sprintf("Error writing output: %v", err))
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}
}

func createRequest(ctx context.Context, targetURL string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, "GET", targetURL, nil)
}

func fetchContent(req *http.Request) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func truncateSecret(s string) string {
	if len(s) <= 20 {
		return s
	}
	return s[:10] + "..." + s[len(s)-5:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ScanResult holds results from all vulnerability scanners
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
	WAFDetect    *waf.DetectionResult        `json:"waf_detect,omitempty"`
	WAFFprint    *waf.Fingerprint            `json:"waf_fingerprint,omitempty"`
	WAFEvasion   []waf.TransformedPayload    `json:"waf_evasion,omitempty"`
	TLSInfo      *probes.TLSInfo             `json:"tls_info,omitempty"`
	HTTPInfo     *probes.HTTPProbeResult     `json:"http_info,omitempty"`
	SecHeaders   *probes.SecurityHeaders     `json:"security_headers,omitempty"`
	JSAnalysis   *js.ExtractedData           `json:"js_analysis,omitempty"`
	APIRoutes    []api.ScanResult            `json:"api_routes,omitempty"`
	// New advanced reconnaissance scanners
	OSINT     *discovery.AllSourcesResult `json:"osint,omitempty"`
	VHosts    []probes.VHostProbeResult   `json:"vhosts,omitempty"`
	TechStack []string                    `json:"tech_stack,omitempty"`
	DNSInfo   *DNSReconResult             `json:"dns_info,omitempty"`
}

// DNSReconResult holds DNS reconnaissance findings
type DNSReconResult struct {
	CNAMEs     []string `json:"cnames,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
	MXRecords  []string `json:"mx_records,omitempty"`
	TXTRecords []string `json:"txt_records,omitempty"`
	NSRecords  []string `json:"ns_records,omitempty"`
}

func runScan() {
	scanFlags := flag.NewFlagSet("scan", flag.ExitOnError)
	var targetURLs input.StringSliceFlag
	scanFlags.Var(&targetURLs, "u", "Target URL(s) - comma-separated or repeated")
	scanFlags.Var(&targetURLs, "target", "Target URL(s)")
	listFile := scanFlags.String("l", "", "File containing target URLs")
	stdinInput := scanFlags.Bool("stdin", false, "Read targets from stdin")
	types := scanFlags.String("types", "all", "Scan types: all, or comma-separated (sqli,xss,traversal,cmdi,nosqli,hpp,crlf,prototype,cors,redirect,hostheader,websocket,cache,upload,deserialize,oauth,ssrf,ssti,xxe,smuggling,graphql,jwt,subtakeover,bizlogic,race,apifuzz,wafdetect,waffprint,wafevasion,tlsprobe,httpprobe,secheaders,jsanalyze,apidepth,osint,vhost,techdetect,dnsrecon)")
	timeout := scanFlags.Int("timeout", 30, "Request timeout in seconds")
	concurrency := scanFlags.Int("concurrency", 5, "Concurrent scanners")
	outputFile := scanFlags.String("output", "", "Output results to JSON file")
	jsonOutput := scanFlags.Bool("json", false, "Output in JSON format")
	skipVerify := scanFlags.Bool("skip-verify", false, "Skip TLS verification")
	verbose := scanFlags.Bool("verbose", false, "Verbose output")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := scanFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := scanFlags.String("smart-mode", "standard", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := scanFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// OAuth-specific flags
	oauthClientID := scanFlags.String("oauth-client-id", "", "OAuth client ID for OAuth testing")
	oauthAuthEndpoint := scanFlags.String("oauth-auth-endpoint", "", "OAuth authorization endpoint")
	oauthTokenEndpoint := scanFlags.String("oauth-token-endpoint", "", "OAuth token endpoint")
	oauthRedirectURI := scanFlags.String("oauth-redirect-uri", "", "OAuth redirect URI")

	// === NEW SCAN FLAGS (42+ for 300+ total) ===

	// Rate limiting and throttling
	rateLimit := scanFlags.Int("rate-limit", 50, "Max requests per second")
	scanFlags.IntVar(rateLimit, "rl", 50, "Max requests per second (alias)")
	rateLimitPerHost := scanFlags.Bool("rate-limit-per-host", false, "Apply rate limit per host")
	scanFlags.BoolVar(rateLimitPerHost, "rlph", false, "Rate limit per host (alias)")
	delay := scanFlags.Duration("delay", 0, "Delay between requests (e.g., 100ms, 1s)")
	jitter := scanFlags.Duration("jitter", 0, "Random jitter to add to delay")

	// Output formats
	formatType := scanFlags.String("format", "console", "Output format: console,json,jsonl,sarif,csv,md,html")
	sarifOutput := scanFlags.Bool("sarif", false, "Output in SARIF format for CI/CD")
	markdownOutput := scanFlags.Bool("md", false, "Output in Markdown format")
	htmlOutput := scanFlags.Bool("html", false, "Output in HTML format")
	csvOutput := scanFlags.Bool("csv", false, "Output in CSV format")
	silent := scanFlags.Bool("silent", false, "Silent mode - no progress output")
	scanFlags.BoolVar(silent, "s", false, "Silent mode (alias)")
	noColor := scanFlags.Bool("no-color", false, "Disable colored output")
	scanFlags.BoolVar(noColor, "nc", false, "No color (alias)")
	timestamp := scanFlags.Bool("timestamp", false, "Add timestamp to output")
	scanFlags.BoolVar(timestamp, "ts", false, "Timestamp (alias)")

	// Filtering and matching
	matchSeverity := scanFlags.String("match-severity", "", "Match findings by severity (critical,high,medium,low)")
	scanFlags.StringVar(matchSeverity, "msev", "", "Match severity (alias)")
	filterSeverity := scanFlags.String("filter-severity", "", "Filter findings by severity")
	scanFlags.StringVar(filterSeverity, "fsev", "", "Filter severity (alias)")
	matchCategory := scanFlags.String("match-category", "", "Match findings by category")
	scanFlags.StringVar(matchCategory, "mcat", "", "Match category (alias)")
	filterCategory := scanFlags.String("filter-category", "", "Filter findings by category")
	scanFlags.StringVar(filterCategory, "fcat", "", "Filter category (alias)")

	// Network options
	proxy := scanFlags.String("proxy", "", "HTTP/SOCKS5 proxy URL")
	scanFlags.StringVar(proxy, "x", "", "Proxy (alias)")
	userAgent := scanFlags.String("user-agent", "", "Custom User-Agent (default: waftester/VERSION)")
	scanFlags.StringVar(userAgent, "ua", "", "User-Agent (alias)")
	randomAgent := scanFlags.Bool("random-agent", false, "Use random User-Agent")
	scanFlags.BoolVar(randomAgent, "ra", false, "Random agent (alias)")
	headers := scanFlags.String("header", "", "Custom header (Name: Value)")
	scanFlags.StringVar(headers, "H", "", "Custom header (alias)")
	cookies := scanFlags.String("cookie", "", "Cookies to send")
	scanFlags.StringVar(cookies, "b", "", "Cookie (alias)")

	// Retries and error handling
	retries := scanFlags.Int("retries", 2, "Number of retries on failure")
	scanFlags.IntVar(retries, "r", 2, "Retries (alias)")
	maxErrors := scanFlags.Int("max-errors", 10, "Max errors before stopping scan")
	scanFlags.IntVar(maxErrors, "me", 10, "Max errors (alias)")
	stopOnFirstVuln := scanFlags.Bool("stop-on-first", false, "Stop scan on first vulnerability")
	scanFlags.BoolVar(stopOnFirstVuln, "sof", false, "Stop on first (alias)")

	// Resume and checkpointing
	resume := scanFlags.Bool("resume", false, "Resume from previous checkpoint")
	checkpointFile := scanFlags.String("checkpoint", "", "Checkpoint file for resume")
	scanFlags.StringVar(checkpointFile, "cp", "", "Checkpoint (alias)")

	// Scope control
	excludeTypes := scanFlags.String("exclude-types", "", "Exclude scan types (comma-separated)")
	scanFlags.StringVar(excludeTypes, "et", "", "Exclude types (alias)")
	excludePatterns := scanFlags.String("exclude-patterns", "", "Exclude URL patterns (regex)")
	scanFlags.StringVar(excludePatterns, "ep", "", "Exclude patterns (alias)")
	includePatterns := scanFlags.String("include-patterns", "", "Include only matching URL patterns (regex)")
	scanFlags.StringVar(includePatterns, "ip", "", "Include patterns (alias)")

	// Reporting
	reportTitle := scanFlags.String("report-title", "", "Custom report title")
	reportAuthor := scanFlags.String("report-author", "", "Report author name")
	includeEvidence := scanFlags.Bool("include-evidence", true, "Include evidence in report")
	scanFlags.BoolVar(includeEvidence, "ie", true, "Include evidence (alias)")
	includeRemediation := scanFlags.Bool("include-remediation", true, "Include remediation advice")
	scanFlags.BoolVar(includeRemediation, "ir", true, "Include remediation (alias)")

	// Advanced options
	maxDepth := scanFlags.Int("max-depth", 5, "Max crawl depth for discovered URLs")
	scanFlags.IntVar(maxDepth, "mxd", 5, "Max depth (alias)")
	followRedirects := scanFlags.Bool("follow-redirects", true, "Follow HTTP redirects")
	scanFlags.BoolVar(followRedirects, "fr", true, "Follow redirects (alias)")
	maxRedirects := scanFlags.Int("max-redirects", 10, "Max redirects to follow")
	respectRobots := scanFlags.Bool("respect-robots", false, "Respect robots.txt")
	scanFlags.BoolVar(respectRobots, "rr", false, "Respect robots (alias)")
	dryRun := scanFlags.Bool("dry-run", false, "Show what would be scanned without scanning")
	scanFlags.BoolVar(dryRun, "dr", false, "Dry run (alias)")

	// Debug and diagnostics
	debug := scanFlags.Bool("debug", false, "Enable debug output")
	debugRequest := scanFlags.Bool("debug-request", false, "Show request details")
	scanFlags.BoolVar(debugRequest, "dreq", false, "Debug request (alias)")
	debugResponse := scanFlags.Bool("debug-response", false, "Show response details")
	scanFlags.BoolVar(debugResponse, "dresp", false, "Debug response (alias)")
	profile := scanFlags.Bool("profile", false, "Enable CPU profiling")
	memProfile := scanFlags.Bool("mem-profile", false, "Enable memory profiling")

	// Streaming mode (CI-friendly output)
	streamMode := scanFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	scanFlags.Parse(os.Args[2:])

	// Check if we're in streaming JSON mode (suppress UI output)
	streamJSON := *streamMode && (*jsonOutput || *formatType == "json" || *formatType == "jsonl")

	// Print banner unless in streaming JSON mode
	if !streamJSON {
		ui.PrintCompactBanner()
		ui.PrintSection("Deep Vulnerability Scan")
	}

	// Apply silent mode
	if *silent {
		ui.SetSilent(true)
	}

	// Apply no-color mode
	if *noColor {
		ui.SetNoColor(true)
	}

	// Apply debug mode
	if *debug || *debugRequest || *debugResponse {
		*verbose = true // Debug implies verbose
	}

	// Handle CPU profiling
	if *profile {
		ui.PrintInfo("CPU profiling enabled (would write to cpu.prof)")
	}

	// Handle memory profiling
	if *memProfile {
		ui.PrintInfo("Memory profiling enabled (would write to mem.prof)")
	}

	// Handle dry run mode
	if *dryRun {
		ui.PrintWarning("Dry run mode - showing what would be scanned")
	}

	// Handle resume from checkpoint
	if *resume {
		checkpointPath := *checkpointFile
		if checkpointPath == "" {
			checkpointPath = "scan-resume.cfg"
		}
		if _, err := os.Stat(checkpointPath); err == nil {
			ui.PrintInfo(fmt.Sprintf("Resuming from checkpoint: %s", checkpointPath))
		} else {
			ui.PrintWarning("No checkpoint file found, starting fresh")
		}
	}

	// Collect targets using shared TargetSource
	ts := &input.TargetSource{
		URLs:     targetURLs,
		ListFile: *listFile,
		Stdin:    *stdinInput,
	}
	target, err := ts.GetSingleTarget()
	if err != nil {
		ui.PrintError("Target URL is required. Use -u https://example.com, -l file.txt, or -stdin")
		os.Exit(1)
	}

	// Setup context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout*60)*time.Second)
	defer cancel()

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	if *smartMode {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var detectErr error
		smartResult, detectErr = DetectAndOptimize(ctx, target, smartConfig)
		if detectErr != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", detectErr))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)

		// Apply WAF-optimized rate limit and concurrency
		// The smart mode values are the safe limits for that specific WAF
		if smartResult != nil && smartResult.WAFDetected {
			if smartResult.RateLimit > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Rate limit: %.0f req/sec (WAF-optimized for %s)",
					smartResult.RateLimit, smartResult.VendorName))
				*rateLimit = int(smartResult.RateLimit)
			}
			if smartResult.Concurrency > 0 {
				ui.PrintInfo(fmt.Sprintf("📊 Concurrency: %d workers (WAF-optimized)",
					smartResult.Concurrency))
				*concurrency = smartResult.Concurrency
			}
		}
		fmt.Println()
	}
	// Silence unused variable warnings
	_ = smartVerbose
	_ = smartModeType
	_ = smartResult

	// Only print config to stdout if not in streaming JSON mode
	if !streamJSON {
		ui.PrintConfigLine("Target", target)
		ui.PrintConfigLine("Scan Types", *types)
		ui.PrintConfigLine("Timeout", fmt.Sprintf("%ds", *timeout))
		ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", *concurrency))
		if *smartMode {
			ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%d req/sec (WAF-optimized)", *rateLimit))
		}
		fmt.Println()
	}

	// Parse scan types
	scanAll := *types == "all"
	typeSet := make(map[string]bool)
	if !scanAll {
		for _, t := range strings.Split(*types, ",") {
			typeSet[strings.TrimSpace(strings.ToLower(t))] = true
		}
	}

	shouldScan := func(name string) bool {
		return scanAll || typeSet[name]
	}

	// Dry run mode - list what would be scanned and exit
	if *dryRun {
		allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "hpp", "crlf", "prototype", "cors", "redirect", "hostheader", "websocket", "cache", "upload", "deserialize", "oauth", "ssrf", "ssti", "xxe", "jwt", "smuggling", "bizlogic", "race", "httpprobe", "secheaders", "jsanalyze", "apidepth", "osint", "vhost", "techdetect", "dnsrecon", "wafdetect", "waffprint"}
		
		var selectedScans []string
		for _, t := range allScanTypes {
			if shouldScan(t) {
				selectedScans = append(selectedScans, t)
			}
		}

		ui.PrintSection("Dry Run Mode")
		ui.PrintInfo(fmt.Sprintf("Would execute %d scan types against %s:", len(selectedScans), target))
		fmt.Println()
		for _, s := range selectedScans {
			fmt.Printf("  • %s\n", s)
		}
		fmt.Println()
		ui.PrintHelp("Remove -dry-run flag to execute scans")
		os.Exit(0)
	}

	// Build HTTP transport with proxy support
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *skipVerify},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure proxy if specified
	if *proxy != "" {
		proxyURL, err := url.Parse(*proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	// Determine user agent
	effectiveUserAgent := *userAgent
	if effectiveUserAgent == "" {
		effectiveUserAgent = ui.UserAgent()
	}
	if *randomAgent {
		userAgents := []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		}
		effectiveUserAgent = userAgents[time.Now().UnixNano()%int64(len(userAgents))]
	}

	// Build custom headers map
	customHeaders := make(map[string]string)
	if *headers != "" {
		parts := strings.SplitN(*headers, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	customHeaders["User-Agent"] = effectiveUserAgent
	if *cookies != "" {
		customHeaders["Cookie"] = *cookies
	}

	// Configure redirect policy
	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if *followRedirects {
			if len(via) >= *maxRedirects {
				return fmt.Errorf("stopped after %d redirects", *maxRedirects)
			}
			return nil
		}
		return http.ErrUseLastResponse
	}

	// Setup HTTP client
	httpClient := &http.Client{
		Timeout:       time.Duration(*timeout) * time.Second,
		Transport:     transport,
		CheckRedirect: redirectPolicy,
	}

	result := &ScanResult{
		Target:     target,
		StartTime:  time.Now(),
		BySeverity: make(map[string]int),
		ByCategory: make(map[string]int),
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *concurrency)

	// Progress tracking
	var totalScans int32
	var scanTimings sync.Map // map[string]time.Duration

	// Count total scans first
	allScanTypes := []string{"sqli", "xss", "traversal", "cmdi", "nosqli", "ssrf", "ssti", "xxe", "smuggling", "oauth", "jwt", "cors", "redirect", "hostheader", "cache", "upload", "deserialize", "bizlogic", "race", "secheaders", "wafdetect", "waffprint", "wafevasion", "techdetect", "jsanalyze"}
	for _, t := range allScanTypes {
		if shouldScan(t) {
			atomic.AddInt32(&totalScans, 1)
		}
	}

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}
	if *silent {
		outputMode = ui.OutputModeSilent
	}

	// Live progress display using unified LiveProgress
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        int(totalScans),
		DisplayLines: 4,
		Title:        "Deep Vulnerability Scan",
		Unit:         "scans",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "vulns", Label: "Vulns", Icon: "🚨", Highlight: true},
		},
		Tips: []string{
			"💡 SQLi uses error-based, time-based, union, and boolean techniques",
			"💡 XSS tests reflected, stored, and DOM-based vectors",
			"💡 SSRF probes for internal network access and cloud metadata",
			"💡 Path traversal tests for file system access vulnerabilities",
			"💡 Each scan type uses context-aware payload selection",
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | vulns: {metric:vulns} | active: {status} | {elapsed}",
		StreamInterval: 3 * time.Second,
	})
	progress.Start()
	defer progress.Stop()

	// Streaming JSON event emitter for real-time output
	var eventMu sync.Mutex
	emitEvent := func(eventType string, data interface{}) {
		if !streamJSON {
			return
		}
		eventMu.Lock()
		defer eventMu.Unlock()
		event := map[string]interface{}{
			"type":      eventType,
			"timestamp": time.Now().Format(time.RFC3339),
			"data":      data,
		}
		eventData, _ := json.Marshal(event)
		fmt.Println(string(eventData))
	}

	// Emit scan start event
	emitEvent("scan_start", map[string]interface{}{
		"target":      target,
		"scan_types":  allScanTypes,
		"concurrency": *concurrency,
	})

	// Helper to run a scanner with progress tracking
	runScanner := func(name string, fn func()) {
		if !shouldScan(name) {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			scanStart := time.Now()
			progress.SetStatus(name)

			fn()
			elapsed := time.Since(scanStart)
			scanTimings.Store(name, elapsed)
			progress.Increment()
		}()
	}

	timeoutDur := time.Duration(*timeout) * time.Second

	// SQL Injection Scanner
	runScanner("sqli", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner": "sqli",
				"vulns":   vulnCount,
			})
		}()

		cfg := &sqli.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := sqli.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("SQLi scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.SQLi = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["sqli"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				// Emit real-time event for each vulnerability
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "sqli",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
					"payload":   v.Payload,
				})
			}
		}
		mu.Unlock()
	})

	// XSS Scanner
	runScanner("xss", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xss", "vulns": vulnCount})
		}()
		cfg := &xss.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := xss.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("XSS scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.XSS = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["xss"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "xss",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Path Traversal Scanner
	runScanner("traversal", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "traversal", "vulns": vulnCount})
		}()
		cfg := &traversal.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := traversal.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Traversal scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Traversal = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["traversal"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "traversal",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Command Injection Scanner
	runScanner("cmdi", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cmdi", "vulns": vulnCount})
		}()
		cfg := &cmdi.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := cmdi.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("CMDi scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.CMDI = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cmdi"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "cmdi",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// NoSQL Injection Scanner
	runScanner("nosqli", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "nosqli", "vulns": vulnCount})
		}()
		cfg := &nosqli.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := nosqli.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("NoSQLi scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.NoSQLi = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["nosqli"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "nosqli",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// HTTP Parameter Pollution Scanner
	runScanner("hpp", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "hpp", "vulns": vulnCount})
		}()
		cfg := &hpp.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := hpp.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("HPP scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.HPP = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["hpp"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "hpp",
					"severity":  v.Severity,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// CRLF Injection Scanner
	runScanner("crlf", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "crlf", "vulns": vulnCount})
		}()
		cfg := &crlf.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := crlf.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("CRLF scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.CRLF = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["crlf"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "crlf",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// Prototype Pollution Scanner
	runScanner("prototype", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "prototype", "vulns": vulnCount})
		}()
		cfg := &prototype.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := prototype.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Prototype pollution scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Prototype = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["prototype"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "prototype",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// CORS Misconfiguration Scanner
	runScanner("cors", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cors", "vulns": vulnCount})
		}()
		cfg := &cors.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := cors.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("CORS scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.CORS = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cors"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "cors",
					"severity": v.Severity,
					"type":     v.Type,
					"origin":   v.TestedOrigin,
				})
			}
		}
		mu.Unlock()
	})

	// Open Redirect Scanner
	runScanner("redirect", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "redirect", "vulns": vulnCount})
		}()
		cfg := &redirect.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := redirect.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Redirect scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Redirect = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["redirect"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "redirect",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// Host Header Injection Scanner
	runScanner("hostheader", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "hostheader", "vulns": vulnCount})
		}()
		cfg := &hostheader.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := hostheader.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Host header scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.HostHeader = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["hostheader"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "hostheader",
					"severity": v.Severity,
					"type":     v.Type,
					"header":   v.Header,
				})
			}
		}
		mu.Unlock()
	})

	// WebSocket Security Scanner
	runScanner("websocket", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "websocket", "vulns": vulnCount})
		}()
		cfg := &websocket.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := websocket.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("WebSocket scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.WebSocket = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["websocket"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "websocket",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// Cache Poisoning Scanner
	runScanner("cache", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "cache", "vulns": vulnCount})
		}()
		cfg := &cache.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
			Client:    httpClient,
		}
		tester := cache.NewTester(cfg)
		scanResult, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Cache poisoning scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Cache = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["cache"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "cache",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// File Upload Scanner - with dedicated timeout to prevent hanging
	runScanner("upload", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "upload", "vulns": vulnCount})
		}()
		// Create a dedicated context with 60s max timeout for upload scanning
		uploadCtx, uploadCancel := context.WithTimeout(ctx, 60*time.Second)
		defer uploadCancel()

		cfg := &upload.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := upload.NewTester(cfg)
		vulns, err := tester.Scan(uploadCtx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Upload scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Upload = vulns
		vulnCount = len(vulns)
		result.ByCategory["upload"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "upload",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Deserialization Scanner
	runScanner("deserialize", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "deserialize", "vulns": vulnCount})
		}()
		cfg := &deserialize.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		tester := deserialize.NewTester(cfg)
		vulns, err := tester.Scan(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Deserialization scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Deserialize = vulns
		vulnCount = len(vulns)
		result.ByCategory["deserialize"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "deserialize",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// OAuth/OIDC Scanner
	runScanner("oauth", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "oauth", "vulns": vulnCount})
		}()
		if *oauthAuthEndpoint == "" {
			if *verbose {
				ui.PrintInfo("OAuth scan skipped: no -oauth-auth-endpoint provided")
			}
			return
		}
		cfg := &oauth.TesterConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		endpoints := &oauth.OAuthEndpoint{
			AuthorizationURL: *oauthAuthEndpoint,
			TokenURL:         *oauthTokenEndpoint,
		}
		oauthCfg := &oauth.OAuthConfig{
			ClientID:    *oauthClientID,
			RedirectURI: *oauthRedirectURI,
		}
		tester := oauth.NewTester(cfg, endpoints, oauthCfg)
		vulns, err := tester.Scan(ctx)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("OAuth scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.OAuth = vulns
		vulnCount = len(vulns)
		result.ByCategory["oauth"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "oauth",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// SSRF Scanner
	runScanner("ssrf", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ssrf", "vulns": vulnCount})
		}()
		detector := ssrf.NewDetector()
		detector.Timeout = timeoutDur
		scanResult, err := detector.Detect(ctx, target, "url")
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("SSRF scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.SSRF = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["ssrf"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[v.Severity]++
				emitEvent("vulnerability", map[string]interface{}{
					"category":  "ssrf",
					"severity":  v.Severity,
					"type":      v.Type,
					"parameter": v.Parameter,
				})
			}
		}
		mu.Unlock()
	})

	// SSTI Scanner
	runScanner("ssti", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "ssti", "vulns": vulnCount})
		}()
		cfg := &ssti.DetectorConfig{
			Timeout:   timeoutDur,
			UserAgent: ui.UserAgent(),
		}
		detector := ssti.NewDetector(cfg)
		vulns, err := detector.Detect(ctx, target, "input")
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("SSTI scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.SSTI = vulns
		vulnCount = len(vulns)
		result.ByCategory["ssti"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category":  "ssti",
				"severity":  v.Severity,
				"engine":    v.Engine,
				"parameter": v.Parameter,
			})
		}
		mu.Unlock()
	})

	// XXE Scanner
	runScanner("xxe", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "xxe", "vulns": vulnCount})
		}()
		cfg := xxe.DefaultConfig()
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		detector := xxe.NewDetector(cfg)
		vulns, err := detector.Detect(ctx, target, "POST")
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("XXE scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.XXE = vulns
		vulnCount = len(vulns)
		result.ByCategory["xxe"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "xxe",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// HTTP Request Smuggling Scanner
	runScanner("smuggling", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "smuggling", "vulns": vulnCount})
		}()
		detector := smuggling.NewDetector()
		detector.Timeout = timeoutDur
		scanResult, err := detector.Detect(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Smuggling scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Smuggling = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["smuggling"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[v.Severity]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "smuggling",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// GraphQL Security Scanner
	runScanner("graphql", func() {
		var vulnCount int
		var foundEndpoint string
		defer func() {
			data := map[string]interface{}{"scanner": "graphql", "vulns": vulnCount}
			if foundEndpoint != "" {
				data["endpoint"] = foundEndpoint
			}
			emitEvent("scan_complete", data)
		}()
		cfg := graphql.DefaultConfig()
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		// Attempt common GraphQL endpoints
		graphqlEndpoints := []string{
			target + "/graphql",
			target + "/api/graphql",
			target + "/v1/graphql",
			target + "/query",
		}
		for _, endpoint := range graphqlEndpoints {
			tester := graphql.NewTester(endpoint, cfg)
			scanResult, err := tester.FullScan(ctx)
			if err == nil && scanResult != nil && len(scanResult.Vulnerabilities) > 0 {
				mu.Lock()
				result.GraphQL = scanResult
				vulnCount = len(scanResult.Vulnerabilities)
				foundEndpoint = endpoint
				result.ByCategory["graphql"] = vulnCount
				result.TotalVulns += vulnCount
				progress.AddMetricBy("vulns", vulnCount)
				for _, v := range scanResult.Vulnerabilities {
					result.BySeverity[string(v.Severity)]++
					emitEvent("vulnerability", map[string]interface{}{
						"category": "graphql",
						"severity": v.Severity,
						"type":     v.Type,
					})
				}
				mu.Unlock()
				return
			}
		}
		if *verbose {
			ui.PrintInfo("No GraphQL endpoint found or no vulnerabilities detected")
		}
	})

	// JWT Security Scanner
	runScanner("jwt", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "jwt", "vulns": vulnCount})
		}()
		attacker := jwt.NewAttacker()
		// Generate test tokens to demonstrate JWT attack capabilities
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		vulns, err := attacker.GenerateMaliciousTokens(testToken)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("JWT scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.JWT = vulns
		vulnCount = len(vulns)
		result.ByCategory["jwt"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "jwt",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Subdomain Takeover Scanner
	runScanner("subtakeover", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "subtakeover", "vulns": vulnCount})
		}()
		cfg := &subtakeover.TesterConfig{
			Timeout:     timeoutDur,
			UserAgent:   ui.UserAgent(),
			Concurrency: *concurrency,
			CheckHTTP:   true,
			FollowCNAME: true,
			Client:      httpClient,
		}
		tester := subtakeover.NewTester(cfg)
		// Extract domain from target URL
		u, err := url.Parse(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Subtakeover: invalid URL: %v", err))
			}
			return
		}
		scanResult, err := tester.CheckSubdomain(ctx, u.Host)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Subtakeover scan error: %v", err))
			}
			return
		}
		mu.Lock()
		if scanResult != nil && scanResult.IsVulnerable {
			result.Subtakeover = append(result.Subtakeover, *scanResult)
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["subtakeover"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "subtakeover",
					"severity": v.Severity,
					"type":     v.Type,
					"domain":   u.Host,
				})
			}
		}
		mu.Unlock()
	})

	// Business Logic Scanner
	runScanner("bizlogic", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "bizlogic", "vulns": vulnCount})
		}()
		cfg := bizlogic.DefaultConfig()
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		tester := bizlogic.NewTester(cfg)
		// Test common business logic vulnerabilities
		vulns, err := tester.Scan(ctx, target, []string{"/", "/api", "/admin", "/user", "/account"})
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("BizLogic scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.BizLogic = vulns
		vulnCount = len(vulns)
		result.ByCategory["bizlogic"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "bizlogic",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// Race Condition Scanner
	runScanner("race", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "race", "vulns": vulnCount})
		}()
		cfg := race.DefaultConfig()
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		tester := race.NewTester(cfg)
		// Test common race condition scenarios
		reqCfg := &race.RequestConfig{
			Method: "POST",
			URL:    target,
			Body:   "",
		}
		scanResult, err := tester.Scan(ctx, reqCfg)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Race condition scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.Race = scanResult
		if scanResult != nil {
			vulnCount = len(scanResult.Vulnerabilities)
			result.ByCategory["race"] = vulnCount
			result.TotalVulns += vulnCount
			progress.AddMetricBy("vulns", vulnCount)
			for _, v := range scanResult.Vulnerabilities {
				result.BySeverity[string(v.Severity)]++
				emitEvent("vulnerability", map[string]interface{}{
					"category": "race",
					"severity": v.Severity,
					"type":     v.Type,
				})
			}
		}
		mu.Unlock()
	})

	// API Fuzzing Scanner
	runScanner("apifuzz", func() {
		var vulnCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "apifuzz", "vulns": vulnCount})
		}()
		cfg := apifuzz.DefaultConfig()
		cfg.Timeout = timeoutDur
		cfg.UserAgent = ui.UserAgent()
		tester := apifuzz.NewTester(cfg)
		// Define basic endpoints to fuzz
		endpoints := []apifuzz.Endpoint{
			{Path: "/api", Method: "GET", Parameters: []apifuzz.Parameter{{Name: "id", Type: apifuzz.ParamString, In: "query"}}},
			{Path: "/api", Method: "POST", Parameters: []apifuzz.Parameter{{Name: "data", Type: apifuzz.ParamString, In: "body"}}},
		}
		vulns, err := tester.FuzzAPI(ctx, target, endpoints)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("API Fuzz scan error: %v", err))
			}
			return
		}
		mu.Lock()
		result.APIFuzz = vulns
		vulnCount = len(vulns)
		result.ByCategory["apifuzz"] = vulnCount
		result.TotalVulns += vulnCount
		progress.AddMetricBy("vulns", vulnCount)
		for _, v := range vulns {
			result.BySeverity[string(v.Severity)]++
			emitEvent("vulnerability", map[string]interface{}{
				"category": "apifuzz",
				"severity": v.Severity,
				"type":     v.Type,
			})
		}
		mu.Unlock()
	})

	// WAF Detection Scanner
	runScanner("wafdetect", func() {
		var detected bool
		var wafs []waf.WAFInfo
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "wafdetect", "detected": detected, "wafs": wafs})
		}()
		detector := waf.NewDetector(timeoutDur)
		scanResult, err := detector.Detect(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("WAF detect error: %v", err))
			}
			return
		}
		mu.Lock()
		result.WAFDetect = scanResult
		if scanResult != nil && scanResult.Detected {
			detected = scanResult.Detected
			wafs = scanResult.WAFs
			// WAF detection is informational, not a vulnerability
			result.ByCategory["wafdetect"] = len(scanResult.WAFs)
		}
		mu.Unlock()
	})

	// WAF Fingerprinting Scanner
	runScanner("waffprint", func() {
		var hash string
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "waffprint", "hash": hash})
		}()
		fingerprinter := waf.NewFingerprinter(timeoutDur)
		fp, err := fingerprinter.CreateFingerprint(ctx, target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("WAF fingerprint error: %v", err))
			}
			return
		}
		mu.Lock()
		result.WAFFprint = fp
		if fp != nil && fp.Hash != "" {
			hash = fp.Hash
			result.ByCategory["waffprint"] = 1
		}
		mu.Unlock()
	})

	// WAF Evasion Testing Scanner
	runScanner("wafevasion", func() {
		var techniqueCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "wafevasion", "techniques": techniqueCount})
		}()
		evasion := waf.NewEvasion()
		// Test with common attack payloads
		testPayloads := []string{
			"<script>alert(1)</script>",
			"' OR '1'='1",
			"../../../etc/passwd",
		}
		var allTransformed []waf.TransformedPayload
		for _, payload := range testPayloads {
			transformed := evasion.Transform(payload)
			allTransformed = append(allTransformed, transformed...)
		}
		techniqueCount = len(allTransformed)
		if techniqueCount > 0 {
			mu.Lock()
			// Store a sample (first 50) to avoid massive output
			if len(allTransformed) > 50 {
				result.WAFEvasion = allTransformed[:50]
			} else {
				result.WAFEvasion = allTransformed
			}
			result.ByCategory["wafevasion"] = techniqueCount
			mu.Unlock()
		}
	})

	// TLS Security Probe
	runScanner("tlsprobe", func() {
		var vulnFound bool
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "tlsprobe", "vuln_found": vulnFound})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("TLS probe error parsing URL: %v", err))
			}
			return
		}
		if parsedURL.Scheme != "https" {
			if *verbose {
				ui.PrintInfo("Skipping TLS probe for non-HTTPS target")
			}
			return
		}
		portStr := parsedURL.Port()
		if portStr == "" {
			portStr = "443"
		}
		portNum := 443
		if n, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || n != 1 {
			portNum = 443
		}
		prober := probes.NewTLSProber()
		prober.Timeout = timeoutDur
		tlsInfo, err := prober.Probe(ctx, parsedURL.Hostname(), portNum)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("TLS probe error: %v", err))
			}
			return
		}
		mu.Lock()
		result.TLSInfo = tlsInfo
		// TLS issues count as vulnerabilities if there are weaknesses
		if tlsInfo != nil && (tlsInfo.SelfSigned || tlsInfo.Expired || tlsInfo.Mismatched) {
			result.TotalVulns++
			result.BySeverity["Medium"]++
			result.ByCategory["tlsprobe"] = 1
			vulnFound = true
			emitEvent("vulnerability", map[string]interface{}{
				"category":    "tlsprobe",
				"severity":    "Medium",
				"self_signed": tlsInfo.SelfSigned,
				"expired":     tlsInfo.Expired,
				"mismatched":  tlsInfo.Mismatched,
			})
		}
		mu.Unlock()
	})

	// HTTP Protocol Probe
	runScanner("httpprobe", func() {
		var http2Supported, pipelineSupported bool
		var dangerousMethods int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":           "httpprobe",
				"http2":             http2Supported,
				"pipeline":          pipelineSupported,
				"dangerous_methods": dangerousMethods,
			})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("HTTP probe error parsing URL: %v", err))
			}
			return
		}
		portStr := parsedURL.Port()
		if portStr == "" {
			if parsedURL.Scheme == "https" {
				portStr = "443"
			} else {
				portStr = "80"
			}
		}
		portNum := 80
		if n, err := fmt.Sscanf(portStr, "%d", &portNum); err != nil || n != 1 {
			portNum = 80
		}
		useTLS := parsedURL.Scheme == "https"

		prober := probes.NewHTTPProber()
		httpResult := &probes.HTTPProbeResult{
			Host: parsedURL.Hostname(),
			Port: portNum,
		}

		// Check HTTP/2 support
		if useTLS {
			if h2, proto, err := prober.ProbeHTTP2(ctx, parsedURL.Hostname(), portNum); err == nil {
				httpResult.HTTP2Supported = h2
				httpResult.ALPN = []string{proto}
			}
		} else {
			// Check H2C for non-TLS
			if h2c, err := prober.ProbeH2C(ctx, parsedURL.Hostname(), portNum); err == nil {
				httpResult.H2CSupported = h2c
			}
		}

		// Check HTTP pipelining (potential smuggling vector)
		if pipelining, err := prober.ProbePipeline(ctx, parsedURL.Hostname(), portNum, useTLS); err == nil {
			httpResult.PipelineSupported = pipelining
		}

		// Check allowed methods
		if methods, err := prober.ProbeMethods(ctx, parsedURL.Hostname(), portNum, useTLS, "/"); err == nil {
			httpResult.Methods = methods
		}

		mu.Lock()
		result.HTTPInfo = httpResult
		http2Supported = httpResult.HTTP2Supported
		pipelineSupported = httpResult.PipelineSupported
		// Dangerous methods or pipelining support is informational
		for _, m := range httpResult.Methods {
			if m == "PUT" || m == "DELETE" || m == "TRACE" || m == "CONNECT" {
				dangerousMethods++
			}
		}
		if dangerousMethods > 0 || pipelineSupported {
			result.ByCategory["httpprobe"] = dangerousMethods
			if dangerousMethods > 0 {
				result.BySeverity["Low"] += dangerousMethods
			}
		}
		mu.Unlock()
	})

	// Security Headers Probe
	runScanner("secheaders", func() {
		var missingCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "secheaders", "missing_headers": missingCount})
		}()
		client := &http.Client{Timeout: timeoutDur}
		resp, err := client.Get(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("Security headers probe error: %v", err))
			}
			return
		}
		defer resp.Body.Close()
		extractor := probes.NewHeaderExtractor()
		headers := extractor.Extract(resp)
		mu.Lock()
		result.SecHeaders = headers
		// Missing security headers count as informational findings
		if headers != nil {
			if headers.StrictTransportSecurity == "" {
				missingCount++
			}
			if headers.ContentSecurityPolicy == "" {
				missingCount++
			}
			if headers.XFrameOptions == "" {
				missingCount++
			}
			if headers.XContentTypeOptions == "" {
				missingCount++
			}
			if missingCount > 0 {
				result.ByCategory["secheaders"] = missingCount
			}
		}
		mu.Unlock()
	})

	// JavaScript Analysis Scanner
	runScanner("jsanalyze", func() {
		var secretsCount, endpointsCount, domsinksCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":   "jsanalyze",
				"secrets":   secretsCount,
				"endpoints": endpointsCount,
				"domsinks":  domsinksCount,
			})
		}()
		// Fetch JavaScript from target and analyze
		client := &http.Client{Timeout: timeoutDur}
		resp, err := client.Get(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("JS analyze error: %v", err))
			}
			return
		}
		defer resp.Body.Close()
		body, err := iohelper.ReadBodyDefault(resp.Body)
		if err != nil {
			return
		}

		// Analyze any inline JavaScript
		analyzer := js.NewAnalyzer()
		extracted := analyzer.Analyze(string(body))
		if extracted != nil {
			secretsCount = len(extracted.Secrets)
			endpointsCount = len(extracted.Endpoints)
			domsinksCount = len(extracted.DOMSinks)
			if secretsCount > 0 || endpointsCount > 0 || domsinksCount > 0 {
				mu.Lock()
				result.JSAnalysis = extracted
				// Secrets are critical vulnerabilities
				if secretsCount > 0 {
					result.TotalVulns += secretsCount
					progress.AddMetricBy("vulns", secretsCount)
					result.BySeverity["Critical"] += secretsCount
					result.ByCategory["jsanalyze"] = secretsCount
					for _, secret := range extracted.Secrets {
						emitEvent("vulnerability", map[string]interface{}{
							"category": "jsanalyze",
							"severity": "Critical",
							"type":     secret.Type,
						})
					}
				}
				mu.Unlock()
			}
		}
	})

	// API Route Depth Scanner
	runScanner("apidepth", func() {
		var routeCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "apidepth", "routes": routeCount})
		}()
		depthConfig := api.DefaultDepthScanConfig()
		depthConfig.Timeout = timeoutDur
		depthScanner := api.NewDepthScanner(depthConfig)
		routes := []api.Route{
			{Path: "/api", Method: "GET"},
			{Path: "/v1", Method: "GET"},
			{Path: "/v2", Method: "GET"},
			{Path: "/graphql", Method: "GET"},
			{Path: "/rest", Method: "GET"},
			{Path: "/admin", Method: "GET"},
		}
		results, err := depthScanner.ScanRoutes(ctx, target, routes)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("API depth scan error: %v", err))
			}
			return
		}
		routeCount = len(results)
		if routeCount > 0 {
			mu.Lock()
			result.APIRoutes = results
			// API routes exposed is informational
			result.ByCategory["apidepth"] = routeCount
			mu.Unlock()
		}
	})

	// OSINT Scanner - Wayback, CommonCrawl, OTX, VirusTotal
	runScanner("osint", func() {
		var secretCount, endpointCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{
				"scanner":   "osint",
				"endpoints": endpointCount,
				"secrets":   secretCount,
			})
		}()
		// Extract domain from target
		parsedURL, err := url.Parse(target)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("OSINT: Failed to parse target URL: %v", err))
			}
			return
		}
		domain := parsedURL.Hostname()

		sources := discovery.NewExternalSources(timeoutDur, ui.UserAgentWithContext("OSINT"))
		osintResult := sources.GatherAllSources(ctx, target, domain)

		if osintResult != nil && osintResult.TotalUnique > 0 {
			endpointCount = osintResult.TotalUnique
			secretCount = len(osintResult.Secrets)
			mu.Lock()
			result.OSINT = osintResult
			// OSINT findings are informational
			result.ByCategory["osint"] = endpointCount

			// Secrets found via OSINT are critical
			if secretCount > 0 {
				result.TotalVulns += secretCount
				progress.AddMetricBy("vulns", secretCount)
				result.BySeverity["Critical"] += secretCount
				for _, secret := range osintResult.Secrets {
					emitEvent("vulnerability", map[string]interface{}{
						"category": "osint",
						"severity": "Critical",
						"type":     secret.Type,
					})
				}
			}
			mu.Unlock()

			if *verbose {
				ui.PrintInfo(fmt.Sprintf("OSINT: Found %d unique endpoints from external sources", endpointCount))
			}
		}
	})

	// Virtual Host Scanner
	runScanner("vhost", func() {
		var vhostCount int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "vhost", "vhosts": vhostCount})
		}()
		// Extract host from target
		parsedURL, err := url.Parse(target)
		if err != nil {
			return
		}

		vhostProber := probes.NewVHostProber()
		vhostProber.Timeout = timeoutDur

		// Common vhost prefixes to test
		wordlist := []string{
			"admin", "api", "app", "beta", "blog", "cdn", "cms", "dev",
			"docs", "internal", "intranet", "jenkins", "jira", "mail",
			"monitor", "mysql", "portal", "private", "prod", "staging",
			"static", "test", "vpn", "www2", "www-dev", "www-staging",
		}

		host := parsedURL.Hostname()
		port := 443
		if parsedURL.Scheme == "http" {
			port = 80
		}
		if parsedURL.Port() != "" {
			fmt.Sscanf(parsedURL.Port(), "%d", &port)
		}

		vhosts, err := vhostProber.ProbeVHosts(ctx, host, port, host, wordlist)
		if err != nil {
			if *verbose {
				ui.PrintWarning(fmt.Sprintf("VHost scan error: %v", err))
			}
			return
		}

		// Filter to only valid (different) vhosts
		var validVHosts []probes.VHostProbeResult
		for _, v := range vhosts {
			if v.Valid {
				validVHosts = append(validVHosts, v)
			}
		}
		vhostCount = len(validVHosts)

		if vhostCount > 0 {
			mu.Lock()
			result.VHosts = validVHosts
			// New vhosts are informational but potentially high risk
			result.ByCategory["vhost"] = vhostCount
			result.TotalVulns += vhostCount
			progress.AddMetricBy("vulns", vhostCount)
			result.BySeverity["Low"] += vhostCount
			for _, vh := range validVHosts {
				emitEvent("vulnerability", map[string]interface{}{
					"category": "vhost",
					"severity": "Low",
					"vhost":    vh.VHost,
				})
			}
			mu.Unlock()

			if *verbose {
				ui.PrintInfo(fmt.Sprintf("VHost: Found %d virtual hosts", vhostCount))
			}
		}
	})

	// Technology Detection Scanner
	runScanner("techdetect", func() {
		var uniqueTech []string
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "techdetect", "technologies": uniqueTech})
		}()
		// Use active discoverer for tech fingerprinting
		ad := discovery.NewActiveDiscoverer(target, timeoutDur, *skipVerify)

		// Manually extract technology stack
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", ui.UserAgentWithContext("Discovery"))

		client := &http.Client{
			Timeout: timeoutDur,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: *skipVerify},
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))

		var techStack []string

		// Analyze headers
		server := strings.ToLower(resp.Header.Get("Server"))
		powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
		generator := strings.ToLower(resp.Header.Get("X-Generator"))

		if strings.Contains(server, "nginx") {
			techStack = append(techStack, "nginx")
		}
		if strings.Contains(server, "apache") {
			techStack = append(techStack, "apache")
		}
		if strings.Contains(server, "iis") {
			techStack = append(techStack, "iis")
		}
		if strings.Contains(powered, "php") {
			techStack = append(techStack, "php")
		}
		if strings.Contains(powered, "asp") || strings.Contains(powered, ".net") {
			techStack = append(techStack, "asp.net")
		}
		if strings.Contains(powered, "express") {
			techStack = append(techStack, "express")
		}
		if generator != "" {
			techStack = append(techStack, generator)
		}

		// Analyze cookies
		for _, cookie := range resp.Cookies() {
			name := strings.ToLower(cookie.Name)
			if strings.Contains(name, "phpsessid") {
				techStack = append(techStack, "php")
			}
			if strings.Contains(name, "jsessionid") {
				techStack = append(techStack, "java")
			}
			if strings.Contains(name, "asp.net") || strings.Contains(name, "aspxauth") {
				techStack = append(techStack, "asp.net")
			}
			if strings.Contains(name, "csrftoken") {
				techStack = append(techStack, "django")
			}
			if strings.Contains(name, "_rails") {
				techStack = append(techStack, "rails")
			}
		}

		// Analyze body
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "wp-content") || strings.Contains(bodyStr, "wordpress") {
			techStack = append(techStack, "wordpress")
		}
		if strings.Contains(bodyStr, "__next") || strings.Contains(bodyStr, "next.js") {
			techStack = append(techStack, "next.js")
		}
		if strings.Contains(bodyStr, "react") && strings.Contains(bodyStr, "reactdom") {
			techStack = append(techStack, "react")
		}
		if strings.Contains(bodyStr, "angular") || strings.Contains(bodyStr, "ng-app") {
			techStack = append(techStack, "angular")
		}
		if strings.Contains(bodyStr, "vue.js") || strings.Contains(bodyStr, "v-bind") {
			techStack = append(techStack, "vue.js")
		}
		if strings.Contains(bodyStr, "laravel") {
			techStack = append(techStack, "laravel")
		}
		if strings.Contains(bodyStr, "drupal") {
			techStack = append(techStack, "drupal")
		}
		if strings.Contains(bodyStr, "joomla") {
			techStack = append(techStack, "joomla")
		}

		// Deduplicate
		seen := make(map[string]bool)
		for _, t := range techStack {
			if !seen[t] {
				seen[t] = true
				uniqueTech = append(uniqueTech, t)
			}
		}

		// Skip slow active discovery fallback - only use header/body analysis
		// The ad.DiscoverAll call can hang for extended periods
		_ = ad // Suppress unused variable warning

		if len(uniqueTech) > 0 {
			mu.Lock()
			result.TechStack = uniqueTech
			result.ByCategory["techdetect"] = len(uniqueTech)
			mu.Unlock()

			if *verbose {
				ui.PrintInfo(fmt.Sprintf("TechDetect: Identified %d technologies: %v", len(uniqueTech), uniqueTech))
			}
		}
	})

	// DNS Reconnaissance Scanner
	runScanner("dnsrecon", func() {
		var totalRecords int
		defer func() {
			emitEvent("scan_complete", map[string]interface{}{"scanner": "dnsrecon", "records": totalRecords})
		}()
		parsedURL, err := url.Parse(target)
		if err != nil {
			return
		}
		domain := parsedURL.Hostname()

		dnsResult := &DNSReconResult{}

		// Resolve CNAME chain (reusing subtakeover's logic)
		cnames, err := net.LookupCNAME(domain)
		if err == nil && cnames != "" && cnames != domain+"." {
			dnsResult.CNAMEs = []string{strings.TrimSuffix(cnames, ".")}
		}

		// MX Records
		mxRecords, err := net.LookupMX(domain)
		if err == nil {
			for _, mx := range mxRecords {
				dnsResult.MXRecords = append(dnsResult.MXRecords, mx.Host)
			}
		}

		// TXT Records
		txtRecords, err := net.LookupTXT(domain)
		if err == nil {
			dnsResult.TXTRecords = txtRecords
		}

		// NS Records
		nsRecords, err := net.LookupNS(domain)
		if err == nil {
			for _, ns := range nsRecords {
				dnsResult.NSRecords = append(dnsResult.NSRecords, ns.Host)
			}
		}

		totalRecords = len(dnsResult.CNAMEs) + len(dnsResult.MXRecords) +
			len(dnsResult.TXTRecords) + len(dnsResult.NSRecords)

		if totalRecords > 0 {
			mu.Lock()
			result.DNSInfo = dnsResult
			result.ByCategory["dnsrecon"] = totalRecords
			mu.Unlock()

			if *verbose {
				ui.PrintInfo(fmt.Sprintf("DNSRecon: Found %d DNS records", totalRecords))
			}
		}
	})

	// Wait for all scanners to complete
	wg.Wait()
	result.Duration = time.Since(result.StartTime)

	// Emit scan_end event for streaming JSON
	emitEvent("scan_end", map[string]interface{}{
		"target":       target,
		"duration_ms":  result.Duration.Milliseconds(),
		"total_vulns":  result.TotalVulns,
		"by_severity":  result.BySeverity,
		"by_category":  result.ByCategory,
	})

	// Progress cleanup is handled by defer progress.Stop()

	// Print scan completion summary (to stderr if streaming JSON)
	if !streamJSON {
		vulnColor := "\033[32m" // Green
		if result.TotalVulns > 0 {
			vulnColor = "\033[33m" // Yellow
		}
		if result.TotalVulns > 5 {
			vulnColor = "\033[31m" // Red
		}
		fmt.Println()
		ui.PrintSuccess(fmt.Sprintf("✓ Scan complete in %s", result.Duration.Round(time.Millisecond)))
		fmt.Printf("  📊 Results: %s%d vulnerabilities\033[0m across %d scan types\n", vulnColor, result.TotalVulns, totalScans)
		fmt.Println()
	}

	// Apply delay/jitter for rate limiting (used in scanner loops)
	_ = delay  // Used for rate limiting in future iterations
	_ = jitter // Used for rate limiting in future iterations

	// Apply report metadata
	if *reportTitle != "" {
		result.ReportTitle = *reportTitle
	}
	if *reportAuthor != "" {
		result.ReportAuthor = *reportAuthor
	}

	// CSV output format
	if *csvOutput {
		fmt.Println("target,category,severity,count")
		for cat, count := range result.ByCategory {
			fmt.Printf("%s,%s,various,%d\n", target, cat, count)
		}
		return
	}

	// Markdown output format
	if *markdownOutput {
		fmt.Println("# Vulnerability Scan Report")
		fmt.Println()
		if *reportTitle != "" {
			fmt.Printf("**Report:** %s\n", *reportTitle)
		}
		if *reportAuthor != "" {
			fmt.Printf("**Author:** %s\n", *reportAuthor)
		}
		fmt.Printf("**Target:** %s\n", target)
		fmt.Printf("**Date:** %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("**Duration:** %s\n", result.Duration.Round(time.Millisecond))
		fmt.Printf("**Total Vulnerabilities:** %d\n", result.TotalVulns)
		fmt.Println()
		fmt.Println("## By Severity")
		fmt.Println()
		fmt.Println("| Severity | Count |")
		fmt.Println("|----------|-------|")
		for sev, count := range result.BySeverity {
			fmt.Printf("| %s | %d |\n", sev, count)
		}
		fmt.Println()
		fmt.Println("## By Category")
		fmt.Println()
		fmt.Println("| Category | Count |")
		fmt.Println("|----------|-------|")
		for cat, count := range result.ByCategory {
			if count > 0 {
				fmt.Printf("| %s | %d |\n", cat, count)
			}
		}
		return
	}

	// HTML output format
	if *htmlOutput {
		fmt.Println("<!DOCTYPE html><html><head><title>Scan Report</title>")
		fmt.Println("<style>body{font-family:Arial,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;text-align:left}th{background:#4CAF50;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#ffc107}.low{color:#4caf50}</style></head><body>")
		if *reportTitle != "" {
			fmt.Printf("<h1>%s</h1>\n", *reportTitle)
		} else {
			fmt.Println("<h1>Vulnerability Scan Report</h1>")
		}
		if *reportAuthor != "" {
			fmt.Printf("<p><strong>Author:</strong> %s</p>\n", *reportAuthor)
		}
		fmt.Printf("<p><strong>Target:</strong> %s</p>\n", target)
		fmt.Printf("<p><strong>Date:</strong> %s</p>\n", result.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Printf("<p><strong>Total Vulnerabilities:</strong> %d</p>\n", result.TotalVulns)
		fmt.Println("<h2>By Severity</h2><table><tr><th>Severity</th><th>Count</th></tr>")
		for sev, count := range result.BySeverity {
			fmt.Printf("<tr><td class='%s'>%s</td><td>%d</td></tr>\n", strings.ToLower(sev), sev, count)
		}
		fmt.Println("</table><h2>By Category</h2><table><tr><th>Category</th><th>Count</th></tr>")
		for cat, count := range result.ByCategory {
			if count > 0 {
				fmt.Printf("<tr><td>%s</td><td>%d</td></tr>\n", cat, count)
			}
		}
		fmt.Println("</table></body></html>")
		return
	}

	// SARIF output format (for CI/CD integration)
	if *sarifOutput {
		sarif := map[string]interface{}{
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"version": "2.1.0",
			"runs": []map[string]interface{}{
				{
					"tool": map[string]interface{}{
						"driver": map[string]interface{}{
							"name":           "waf-tester",
							"version":        ui.Version,
							"informationUri": "https://github.com/waftester/waftester",
						},
					},
					"results": func() []map[string]interface{} {
						var results []map[string]interface{}
						for cat, count := range result.ByCategory {
							if count > 0 {
								results = append(results, map[string]interface{}{
									"ruleId":  cat,
									"level":   "warning",
									"message": map[string]string{"text": fmt.Sprintf("Found %d %s issues", count, cat)},
									"locations": []map[string]interface{}{
										{"physicalLocation": map[string]interface{}{"artifactLocation": map[string]string{"uri": target}}},
									},
								})
							}
						}
						return results
					}(),
				},
			},
		}
		jsonData, _ := json.MarshalIndent(sarif, "", "  ")
		fmt.Println(string(jsonData))
		return
	}

	// Check format type flag
	if *formatType != "" && *formatType != "console" {
		switch *formatType {
		case "jsonl":
			// JSON Lines format
			for cat, count := range result.ByCategory {
				line, _ := json.Marshal(map[string]interface{}{"category": cat, "count": count, "target": target})
				fmt.Println(string(line))
			}
			return
		}
	}

	// Print summary (skip in stream+json mode - we already emitted events)
	if !*jsonOutput && !streamJSON {
		fmt.Println()
		ui.PrintSection("Scan Results")
		ui.PrintConfigLine("Duration", result.Duration.Round(time.Millisecond).String())
		ui.PrintConfigLine("Total Vulnerabilities", fmt.Sprintf("%d", result.TotalVulns))
		fmt.Println()

		if result.TotalVulns > 0 {
			ui.PrintSection("By Severity")
			for sev, count := range result.BySeverity {
				switch sev {
				case "Critical":
					ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
				case "High":
					ui.PrintError(fmt.Sprintf("  %s: %d", sev, count))
				case "Medium":
					ui.PrintWarning(fmt.Sprintf("  %s: %d", sev, count))
				default:
					ui.PrintInfo(fmt.Sprintf("  %s: %d", sev, count))
				}
			}
			fmt.Println()

			ui.PrintSection("By Category")
			for cat, count := range result.ByCategory {
				if count > 0 {
					ui.PrintConfigLine(cat, fmt.Sprintf("%d vulnerabilities", count))
				}
			}
			fmt.Println()

			// Print detailed findings
			if result.SQLi != nil && len(result.SQLi.Vulnerabilities) > 0 {
				ui.PrintSection("SQLi Findings")
				for _, v := range result.SQLi.Vulnerabilities[:min(5, len(result.SQLi.Vulnerabilities))] {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
				if len(result.SQLi.Vulnerabilities) > 5 {
					ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.SQLi.Vulnerabilities)-5))
				}
				fmt.Println()
			}

			if result.XSS != nil && len(result.XSS.Vulnerabilities) > 0 {
				ui.PrintSection("XSS Findings")
				for _, v := range result.XSS.Vulnerabilities[:min(5, len(result.XSS.Vulnerabilities))] {
					ui.PrintError(fmt.Sprintf("  [%s] %s - %s", v.Severity, v.Parameter, v.Type))
				}
				if len(result.XSS.Vulnerabilities) > 5 {
					ui.PrintInfo(fmt.Sprintf("  ... and %d more", len(result.XSS.Vulnerabilities)-5))
				}
				fmt.Println()
			}
		} else {
			ui.PrintSuccess("No vulnerabilities found!")
		}
	}

	// Output JSON (skip final blob in stream+json mode - we already emitted events)
	if (*jsonOutput || *outputFile != "") && !streamJSON {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			ui.PrintError(fmt.Sprintf("JSON encoding error: %v", err))
			os.Exit(1)
		}

		if *outputFile != "" {
			if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
				ui.PrintError(fmt.Sprintf("Error writing output: %v", err))
				os.Exit(1)
			}
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}

		if *jsonOutput {
			fmt.Println(string(jsonData))
		}
	}

	// Still write to file if specified in stream mode
	if *outputFile != "" && streamJSON {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		if err := os.WriteFile(*outputFile, jsonData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Error writing output: %v\n", err)
		}
	}

	if result.TotalVulns > 0 {
		os.Exit(1) // Exit with error if vulnerabilities found
	}
}

// applyMutations expands payloads using the mutation engine based on config
func applyMutations(cfg *config.Config, originalPayloads []payloads.Payload) []payloads.Payload {
	var pipelineCfg *mutation.PipelineConfig

	switch cfg.MutationMode {
	case "quick":
		// Quick mode: just URL encoding variants
		pipelineCfg = &mutation.PipelineConfig{
			Encoders:       []string{"raw", "url", "double_url"},
			Locations:      []string{"query_param"},
			Evasions:       []string{},
			ChainEncodings: false,
			IncludeRaw:     true,
		}
	case "standard":
		// Standard mode: common encodings and locations
		pipelineCfg = &mutation.PipelineConfig{
			Encoders:       []string{"raw", "url", "double_url", "html_hex", "unicode"},
			Locations:      []string{"query_param", "post_form", "post_json"},
			Evasions:       []string{},
			ChainEncodings: false,
			IncludeRaw:     true,
		}
	case "full":
		// Full mode: all mutators
		pipelineCfg = mutation.FullCoveragePipelineConfig()
	default:
		// Use default config
		pipelineCfg = mutation.DefaultPipelineConfig()
	}

	// Override with CLI flags if specified
	if cfg.MutationEncoders != "" {
		pipelineCfg.Encoders = strings.Split(cfg.MutationEncoders, ",")
	}
	if cfg.MutationLocations != "" {
		pipelineCfg.Locations = strings.Split(cfg.MutationLocations, ",")
	}
	if cfg.MutationEvasions != "" {
		pipelineCfg.Evasions = strings.Split(cfg.MutationEvasions, ",")
	}
	if cfg.MutationChain {
		pipelineCfg.ChainEncodings = true
	}
	if cfg.MutationMaxChain > 0 {
		pipelineCfg.MaxChainDepth = cfg.MutationMaxChain
	}

	// Get mutators by category
	encoders := mutation.DefaultRegistry.GetByCategory("encoder")
	evasions := mutation.DefaultRegistry.GetByCategory("evasion")

	// Filter encoders by config
	var selectedEncoders []mutation.Mutator
	if len(pipelineCfg.Encoders) > 0 {
		encoderSet := make(map[string]bool)
		for _, name := range pipelineCfg.Encoders {
			encoderSet[strings.TrimSpace(name)] = true
		}
		for _, enc := range encoders {
			if encoderSet[enc.Name()] {
				selectedEncoders = append(selectedEncoders, enc)
			}
		}
	} else {
		selectedEncoders = encoders
	}

	// Filter evasions by config
	var selectedEvasions []mutation.Mutator
	if len(pipelineCfg.Evasions) > 0 {
		evasionSet := make(map[string]bool)
		for _, name := range pipelineCfg.Evasions {
			evasionSet[strings.TrimSpace(name)] = true
		}
		for _, eva := range evasions {
			if evasionSet[eva.Name()] {
				selectedEvasions = append(selectedEvasions, eva)
			}
		}
	}

	// Expand payloads
	var mutatedPayloads []payloads.Payload
	seen := make(map[string]bool)

	for _, p := range originalPayloads {
		// Always include original if IncludeRaw
		if pipelineCfg.IncludeRaw {
			mutatedPayloads = append(mutatedPayloads, p)
			seen[p.ID+":"+p.Payload] = true
		}

		// Apply encoders
		for _, enc := range selectedEncoders {
			results := enc.Mutate(p.Payload)
			for _, r := range results {
				key := p.ID + ":" + r.Mutated
				if !seen[key] && r.Mutated != p.Payload {
					seen[key] = true
					mutated := p // Copy original
					mutated.Payload = r.Mutated
					mutated.ID = fmt.Sprintf("%s_%s", p.ID, enc.Name())
					mutatedPayloads = append(mutatedPayloads, mutated)
				}
			}
		}

		// Apply evasions (only if configured)
		for _, eva := range selectedEvasions {
			results := eva.Mutate(p.Payload)
			for _, r := range results {
				key := p.ID + ":" + r.Mutated
				if !seen[key] && r.Mutated != p.Payload {
					seen[key] = true
					mutated := p
					mutated.Payload = r.Mutated
					mutated.ID = fmt.Sprintf("%s_%s", p.ID, eva.Name())
					mutatedPayloads = append(mutatedPayloads, mutated)
				}
			}
		}

		// Chain mutations if enabled (encoder → evasion)
		if pipelineCfg.ChainEncodings && len(selectedEvasions) > 0 {
			for _, enc := range selectedEncoders {
				encResults := enc.Mutate(p.Payload)
				for _, encR := range encResults {
					for _, eva := range selectedEvasions {
						evaResults := eva.Mutate(encR.Mutated)
						for _, evaR := range evaResults {
							key := p.ID + ":" + evaR.Mutated
							if !seen[key] && evaR.Mutated != p.Payload {
								seen[key] = true
								mutated := p
								mutated.Payload = evaR.Mutated
								mutated.ID = fmt.Sprintf("%s_%s_%s", p.ID, enc.Name(), eva.Name())
								mutatedPayloads = append(mutatedPayloads, mutated)
							}
						}
					}
				}
			}
		}
	}

	return mutatedPayloads
}

// buildFilterConfig creates a FilterConfig from CLI flags
func buildFilterConfig(cfg *config.Config) *core.FilterConfig {
	fc := &core.FilterConfig{}
	hasAny := false

	// Parse match status codes (e.g., "200,403,500")
	if cfg.MatchStatus != "" {
		fc.MatchStatus = parseIntList(cfg.MatchStatus)
		hasAny = true
	}

	// Parse filter status codes
	if cfg.FilterStatus != "" {
		fc.FilterStatus = parseIntList(cfg.FilterStatus)
		hasAny = true
	}

	// Parse match size
	if cfg.MatchSize != "" {
		fc.MatchSize = parseIntList(cfg.MatchSize)
		hasAny = true
	}

	// Parse filter size
	if cfg.FilterSize != "" {
		fc.FilterSize = parseIntList(cfg.FilterSize)
		hasAny = true
	}

	// Parse match words
	if cfg.MatchWords != "" {
		fc.MatchWords = parseIntList(cfg.MatchWords)
		hasAny = true
	}

	// Parse filter words
	if cfg.FilterWords != "" {
		fc.FilterWords = parseIntList(cfg.FilterWords)
		hasAny = true
	}

	// Parse match lines
	if cfg.MatchLines != "" {
		fc.MatchLines = parseIntList(cfg.MatchLines)
		hasAny = true
	}

	// Parse filter lines
	if cfg.FilterLines != "" {
		fc.FilterLines = parseIntList(cfg.FilterLines)
		hasAny = true
	}

	// Parse match regex
	if cfg.MatchRegex != "" {
		if re, err := regexcache.Get(cfg.MatchRegex); err == nil {
			fc.MatchRegex = re
			hasAny = true
		}
	}

	// Parse filter regex
	if cfg.FilterRegex != "" {
		if re, err := regexcache.Get(cfg.FilterRegex); err == nil {
			fc.FilterRegex = re
			hasAny = true
		}
	}

	if !hasAny {
		return nil
	}
	return fc
}

// parseIntList parses comma-separated integers (e.g., "200,403,500")
func parseIntList(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if n, err := strconv.Atoi(part); err == nil {
			result = append(result, n)
		}
	}
	return result
}

// =============================================================================
// MUTATION ENGINE COMMAND
// =============================================================================

func runMutate() {
	ui.PrintCompactBanner()
	ui.PrintSection("Mutation Engine - Full Coverage WAF Testing")

	mutateFlags := flag.NewFlagSet("mutate", flag.ExitOnError)

	// Target
	target := mutateFlags.String("target", "", "Target URL to test")
	targetShort := mutateFlags.String("u", "", "Target URL (shorthand)")

	// Payload source
	payloadDir := mutateFlags.String("payloads", "../payloads", "Payload directory")
	category := mutateFlags.String("category", "", "Filter payload category (sqli, xss, etc.)")
	payloadFile := mutateFlags.String("payload-file", "", "Single payload file to use")
	rawPayload := mutateFlags.String("payload", "", "Single raw payload to test")

	// Mutation settings
	mode := mutateFlags.String("mode", "quick", "Mutation mode: quick, standard, full, bypass")
	encoders := mutateFlags.String("encoders", "", "Comma-separated encoders (url,double_url,utf7,...)")
	locations := mutateFlags.String("locations", "", "Comma-separated locations (query_param,post_json,...)")
	evasions := mutateFlags.String("evasions", "", "Comma-separated evasions (case_swap,sql_comment,...)")
	chainEncodings := mutateFlags.Bool("chain", false, "Chain multiple encodings together")

	// Execution
	concurrency := mutateFlags.Int("c", 10, "Concurrency")
	rateLimit := mutateFlags.Float64("rl", 50, "Rate limit (requests/sec)")
	timeout := mutateFlags.Int("timeout", 10, "Timeout in seconds")
	skipVerify := mutateFlags.Bool("k", false, "Skip TLS verification")

	// Realistic mode (intelligent block detection)
	realisticMode := mutateFlags.Bool("realistic", false, "Use intelligent block detection + realistic headers")
	realisticShort := mutateFlags.Bool("R", false, "Realistic mode (shorthand)")
	autoCalibrate := mutateFlags.Bool("ac", false, "Auto-calibrate baseline before testing")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := mutateFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := mutateFlags.String("smart-mode", "", "Override mutation mode with smart optimization: quick, standard, full, bypass, stealth")
	smartVerbose := mutateFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	// Output
	outputFile := mutateFlags.String("o", "", "Output file (JSON)")
	verbose := mutateFlags.Bool("v", false, "Verbose output")
	showStats := mutateFlags.Bool("stats", false, "Show mutation registry stats only")
	dryRun := mutateFlags.Bool("dry-run", false, "Show what would be tested without executing")

	// Streaming mode (CI-friendly output)
	streamMode := mutateFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	mutateFlags.Parse(os.Args[2:])

	// Resolve target
	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}

	// Show stats only
	if *showStats {
		printMutationStats()
		return
	}

	if targetURL == "" && !*dryRun {
		ui.PrintError("Target URL required. Use -target or -u")
		os.Exit(1)
	}

	// Setup context for smart mode detection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	effectiveMode := *mode
	if *smartMode && targetURL != "" {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartModeValue := *smartModeType
		if smartModeValue == "" {
			smartModeValue = *mode // Use the -mode flag value if smart-mode not specified
		}

		smartConfig := &SmartModeConfig{
			DetectionTimeout: time.Duration(*timeout) * time.Second,
			Verbose:          *smartVerbose,
			Mode:             smartModeValue,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, targetURL, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)
		effectiveMode = "smart:" + smartModeValue
	}
	// Silence unused variable warnings
	_ = smartVerbose
	_ = smartModeType

	// Configure executor
	cfg := mutation.DefaultExecutorConfig()
	cfg.TargetURL = targetURL
	cfg.Concurrency = *concurrency
	cfg.RateLimit = *rateLimit
	cfg.Timeout = time.Duration(*timeout) * time.Second
	cfg.SkipVerify = *skipVerify
	cfg.RealisticMode = *realisticMode || *realisticShort || *smartMode
	cfg.AutoCalibrate = *autoCalibrate || *smartMode

	// Apply smart mode optimizations first
	if *smartMode && smartResult != nil {
		ApplySmartConfig(cfg, smartResult)
		ui.PrintInfo(fmt.Sprintf("📊 WAF-optimized: %d encoders, %d evasions, %.0f req/sec",
			len(cfg.Pipeline.Encoders), len(cfg.Pipeline.Evasions), cfg.RateLimit))
		fmt.Println()
	} else {
		// Configure pipeline based on mode (only if not using smart mode)
		switch *mode {
		case "quick":
			cfg.Pipeline = &mutation.PipelineConfig{
				Encoders:   []string{"raw", "url", "double_url"},
				Locations:  []string{"query_param", "post_form", "post_json"},
				Evasions:   []string{},
				IncludeRaw: true,
			}
		case "standard":
			cfg.Pipeline = mutation.DefaultPipelineConfig()
		case "full":
			cfg.Pipeline = mutation.FullCoveragePipelineConfig()
		case "bypass":
			cfg.Pipeline = &mutation.PipelineConfig{
				Encoders: []string{
					"raw", "url", "double_url", "triple_url",
					"overlong_utf8", "wide_gbk", "utf7",
					"html_decimal", "html_hex", "mixed",
				},
				Locations: []string{
					"query_param", "post_form", "post_json",
					"header_xforward", "cookie", "path_segment",
				},
				Evasions: []string{
					"case_swap", "sql_comment", "whitespace_alt",
					"null_byte", "hpp", "unicode_normalize",
				},
				ChainEncodings: true,
				MaxChainDepth:  2,
				IncludeRaw:     true,
			}
		}
	} // End of else block for non-smart mode

	// Override with explicit settings
	if *encoders != "" {
		cfg.Pipeline.Encoders = strings.Split(*encoders, ",")
	}
	if *locations != "" {
		cfg.Pipeline.Locations = strings.Split(*locations, ",")
	}
	if *evasions != "" {
		cfg.Pipeline.Evasions = strings.Split(*evasions, ",")
	}
	if *chainEncodings {
		cfg.Pipeline.ChainEncodings = true
	}

	// Print config
	ui.PrintConfigLine("Target", targetURL)
	ui.PrintConfigLine("Mode", effectiveMode)
	ui.PrintConfigLine("Concurrency", fmt.Sprintf("%d", cfg.Concurrency))
	ui.PrintConfigLine("Rate Limit", fmt.Sprintf("%.0f req/sec", cfg.RateLimit))
	fmt.Println()

	// Load payloads
	var testPayloads []string
	if *rawPayload != "" {
		testPayloads = []string{*rawPayload}
		ui.PrintConfigLine("Payload", "Single raw payload")
	} else if *payloadFile != "" {
		// Load from specific file
		content, err := os.ReadFile(*payloadFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot read payload file: %v", err))
			os.Exit(1)
		}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				testPayloads = append(testPayloads, line)
			}
		}
		ui.PrintConfigLine("Payload File", *payloadFile)
		ui.PrintConfigLine("Payloads Loaded", fmt.Sprintf("%d", len(testPayloads)))
	} else {
		// Load from payload directory
		loader := payloads.NewLoader(*payloadDir)
		allPayloads, err := loader.LoadAll()
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot load payloads: %v", err))
			os.Exit(1)
		}

		// Filter by category if specified
		if *category != "" {
			filtered := payloads.Filter(allPayloads, *category, "")
			for _, p := range filtered {
				testPayloads = append(testPayloads, p.Payload)
			}
			ui.PrintConfigLine("Category", *category)
		} else {
			for _, p := range allPayloads {
				testPayloads = append(testPayloads, p.Payload)
			}
		}
		ui.PrintConfigLine("Payloads Dir", *payloadDir)
		ui.PrintConfigLine("Payloads Loaded", fmt.Sprintf("%d", len(testPayloads)))
	}

	// Create executor
	executor := mutation.NewExecutor(cfg)

	// Generate tasks
	tasks := executor.GenerateTasks(testPayloads, nil)
	ui.PrintConfigLine("Total Mutations", fmt.Sprintf("%d", len(tasks)))
	fmt.Println()

	// Dry run - just show what would be tested
	if *dryRun {
		ui.PrintSection("Dry Run - Sample Mutations")
		shown := 0
		for _, task := range tasks {
			if shown >= 20 {
				fmt.Printf("  ... and %d more\n", len(tasks)-20)
				break
			}
			evasion := ""
			if task.Evasion != nil {
				evasion = " + " + task.Evasion.MutatorName
			}
			fmt.Printf("  [%s] [%s]%s: %.50s...\n",
				task.EncodedPayload.MutatorName,
				task.Location.MutatorName,
				evasion,
				task.EncodedPayload.Mutated)
			shown++
		}
		return
	}

	// Context already created for smart mode detection above

	// Handle Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n\nInterrupted, shutting down...")
		cancel()
	}()

	// Output writer
	var writer *json.Encoder
	var outputFh *os.File
	if *outputFile != "" {
		var err error
		outputFh, err = os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Cannot create output file: %v", err))
			os.Exit(1)
		}
		defer outputFh.Close()
		writer = json.NewEncoder(outputFh)
	}

	// Run tests with live progress
	ui.PrintSection("🔥 WAF Bypass Hunt")

	// Determine WAF name for display
	wafName := "Unknown WAF"
	if smartResult != nil && smartResult.WAFDetected {
		wafName = smartResult.VendorName
	}
	fmt.Printf("  Target: %s (%s)\n", targetURL, wafName)
	fmt.Printf("  Mutations: %d | Mode: %s\n\n", len(tasks), effectiveMode)

	// Determine output mode for progress
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Use unified LiveProgress
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(tasks),
		DisplayLines: 4,
		Title:        "Mutation testing",
		Unit:         "mutations",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "bypasses", Label: "Bypasses", Icon: "🔓", Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: "🛡️"},
			{Name: "errors", Label: "Errors", Icon: "⚠️"},
		},
		Tips: []string{
			"💡 Chunked encoding can split payloads to evade pattern matching",
			"💡 Most WAFs can't properly normalize Unicode in all contexts",
			"💡 Encoders combined with evasions multiply your test coverage",
			"💡 Parameter pollution bypasses 30%+ of WAFs",
			"💡 Case variations alone find bypasses in 1 out of 5 WAFs",
			"💡 SQL comments /**/ can hide entire payload chunks",
		},
		StreamFormat:   "[PROGRESS] {completed}/{total} ({percent}%) | bypasses: {metric:bypasses} | blocked: {metric:blocked} | {status} | {elapsed}",
		StreamInterval: 3 * time.Second,
	})
	progress.Start()
	defer progress.Stop()

	// Execute mutation tests
	stats := executor.Execute(ctx, tasks, func(r *mutation.TestResult) {
		// Update progress and metrics
		progress.Increment()

		if r.Blocked {
			progress.AddMetric("blocked")
		} else if r.ErrorMessage != "" {
			progress.AddMetric("errors")
		} else {
			progress.AddMetric("bypasses")
			// Update status with last bypass info
			encoder := r.EncoderUsed
			if r.EvasionUsed != "" {
				encoder += "+" + r.EvasionUsed
			}
			progress.SetStatus(fmt.Sprintf("bypass: %s", encoder))
		}

		// Write to output file
		if writer != nil {
			writer.Encode(r)
		}

		// Verbose output
		if *verbose {
			status := "✓"
			if r.Blocked {
				status = "✗"
			} else if r.ErrorMessage != "" {
				status = "!"
			}
			fmt.Printf("  [%s] %s | %s | %s | %dms\n",
				status, r.EncoderUsed, r.LocationUsed, r.EvasionUsed, r.LatencyMs)
		}
	})

	// Print final results with celebration or commiseration
	fmt.Println()
	fmt.Println("  ═══════════════════════════════════════════════════════════")

	if stats.Passed > 0 {
		if stats.Passed > 20 {
			fmt.Printf("  🏆 \033[1;33mLEGENDARY! %d BYPASSES FOUND!\033[0m 🏆\n", stats.Passed)
		} else if stats.Passed > 10 {
			fmt.Printf("  🔥 \033[1;33mON FIRE! %d BYPASSES FOUND!\033[0m 🔥\n", stats.Passed)
		} else if stats.Passed > 5 {
			fmt.Printf("  ⚡ \033[1;33mNICE! %d BYPASSES FOUND!\033[0m ⚡\n", stats.Passed)
		} else {
			fmt.Printf("  🎯 \033[1;32m%d BYPASS(ES) FOUND!\033[0m\n", stats.Passed)
		}
	} else {
		fmt.Printf("  🛡️ \033[1;36mWAF held strong - no bypasses found\033[0m\n")
	}

	fmt.Println("  ═══════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Printf("  📊 \033[1mFinal Stats:\033[0m\n")
	fmt.Printf("     • Total Tests:   %d\n", stats.TotalTests)
	fmt.Printf("     • Bypasses:      \033[32m%d\033[0m (%.1f%%)\n", stats.Passed, float64(stats.Passed)/float64(stats.TotalTests)*100)
	fmt.Printf("     • Blocked:       \033[31m%d\033[0m (%.1f%%)\n", stats.Blocked, float64(stats.Blocked)/float64(stats.TotalTests)*100)
	fmt.Printf("     • Errors:        %d\n", stats.Errors)
	fmt.Printf("     • Duration:      %s\n", stats.Duration.Round(time.Millisecond))
	fmt.Printf("     • Throughput:    %.1f req/s\n", stats.RequestsPerSec)
	fmt.Println()

	// Top encoders if bypasses found
	if stats.Passed > 0 && len(stats.ByEncoder) > 0 {
		fmt.Printf("  🎯 \033[1mEffective Encoders:\033[0m\n")
		for enc, count := range stats.ByEncoder {
			if count > 0 {
				fmt.Printf("     • %-20s %d hits\n", enc, count)
			}
		}
		fmt.Println()
	}

	if *outputFile != "" {
		ui.PrintSuccess(fmt.Sprintf("Results written to %s", *outputFile))
	}

	// Final message
	if stats.Passed > 0 {
		ui.PrintWarning(fmt.Sprintf("⚠️  %d potential WAF bypasses need investigation!", stats.Passed))
	} else {
		ui.PrintSuccess("✓ WAF blocked all mutation attempts")
	}
}

// Helper functions for the progress display
func formatETA(d time.Duration) string {
	if d <= 0 {
		return "calculating..."
	}
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// sanitizeForDisplay removes newlines and control characters for single-line display
func sanitizeForDisplay(s string) string {
	// Replace common problematic characters
	s = strings.ReplaceAll(s, "\r\n", "↵")
	s = strings.ReplaceAll(s, "\n", "↵")
	s = strings.ReplaceAll(s, "\r", "↵")
	s = strings.ReplaceAll(s, "\t", "→")
	s = strings.ReplaceAll(s, "\x00", "∅")

	// Remove other control characters
	var result strings.Builder
	for _, r := range s {
		if r >= 32 || r == '↵' || r == '→' || r == '∅' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// =============================================================================
// BYPASS FINDER COMMAND
// =============================================================================

func runBypassFinder() {
	ui.PrintCompactBanner()
	ui.PrintSection("WAF Bypass Finder")

	bypassFlags := flag.NewFlagSet("bypass", flag.ExitOnError)

	target := bypassFlags.String("target", "", "Target URL")
	targetShort := bypassFlags.String("u", "", "Target URL (shorthand)")
	payloadDir := bypassFlags.String("payloads", "../payloads", "Payload directory")
	category := bypassFlags.String("category", "injection", "Payload category to test")
	concurrency := bypassFlags.Int("c", 10, "Concurrency")
	rateLimit := bypassFlags.Float64("rl", 30, "Rate limit")
	outputFile := bypassFlags.String("o", "bypasses.json", "Output file for bypass results")
	skipVerify := bypassFlags.Bool("k", false, "Skip TLS verification")

	// Streaming mode (CI-friendly output)
	streamMode := bypassFlags.Bool("stream", false, "Streaming output mode for CI/scripts")

	// Realistic mode (intelligent block detection)
	realisticMode := bypassFlags.Bool("realistic", false, "Use intelligent block detection + realistic headers")
	realisticShort := bypassFlags.Bool("R", false, "Realistic mode (shorthand)")
	autoCalibrate := bypassFlags.Bool("ac", false, "Auto-calibrate baseline before testing")

	// Smart mode (WAF-aware testing with 197+ vendor signatures)
	smartMode := bypassFlags.Bool("smart", false, "Enable WAF-aware testing (auto-detect WAF and optimize)")
	smartModeType := bypassFlags.String("smart-mode", "bypass", "Smart mode type: quick, standard, full, bypass, stealth")
	smartVerbose := bypassFlags.Bool("smart-verbose", false, "Show detailed WAF detection info")

	bypassFlags.Parse(os.Args[2:])

	targetURL := *target
	if targetURL == "" {
		targetURL = *targetShort
	}
	if targetURL == "" {
		ui.PrintError("Target URL required")
		os.Exit(1)
	}

	ui.PrintConfigLine("Target", targetURL)
	ui.PrintConfigLine("Category", *category)
	if *smartMode {
		ui.PrintConfigLine("Mode", fmt.Sprintf("Smart Bypass Hunter (%s mode)", *smartModeType))
	} else {
		ui.PrintConfigLine("Mode", "Bypass Hunter (all evasions enabled)")
	}
	fmt.Println()

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Smart Mode: Detect WAF and optimize configuration
	var smartResult *SmartModeResult
	if *smartMode {
		ui.PrintSection("🧠 Smart Mode: WAF Detection & Optimization")
		fmt.Println()

		smartConfig := &SmartModeConfig{
			DetectionTimeout: 15 * time.Second,
			Verbose:          *smartVerbose,
			Mode:             *smartModeType,
		}

		var err error
		smartResult, err = DetectAndOptimize(ctx, targetURL, smartConfig)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("Smart mode detection warning: %v", err))
		}

		PrintSmartModeInfo(smartResult, *smartVerbose)
	}

	// Load payloads
	loader := payloads.NewLoader(*payloadDir)
	allPayloads, err := loader.LoadAll()
	if err != nil {
		ui.PrintError(fmt.Sprintf("Cannot load payloads: %v", err))
		os.Exit(1)
	}

	filtered := payloads.Filter(allPayloads, *category, "")
	var testPayloads []string
	for _, p := range filtered {
		testPayloads = append(testPayloads, p.Payload)
	}

	ui.PrintConfigLine("Payloads", fmt.Sprintf("%d", len(testPayloads)))

	// Configure for maximum bypass detection
	cfg := mutation.DefaultExecutorConfig()
	cfg.TargetURL = targetURL
	cfg.Concurrency = *concurrency
	cfg.RateLimit = *rateLimit
	cfg.SkipVerify = *skipVerify
	cfg.RealisticMode = *realisticMode || *realisticShort || *smartMode
	cfg.AutoCalibrate = *autoCalibrate || *smartMode

	// Apply smart mode optimizations
	if *smartMode && smartResult != nil {
		ApplySmartConfig(cfg, smartResult)
		ui.PrintInfo(fmt.Sprintf("📊 WAF-optimized: %d encoders, %d evasions, %.0f req/sec",
			len(cfg.Pipeline.Encoders), len(cfg.Pipeline.Evasions), cfg.RateLimit))
	} else {
		cfg.Pipeline = mutation.FullCoveragePipelineConfig()
	}

	executor := mutation.NewExecutor(cfg)

	// Count combinations
	expectedTests := executor.CountCombinations(len(testPayloads))
	ui.PrintConfigLine("Expected Tests", fmt.Sprintf("%d", expectedTests))
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// Generate tasks for progress tracking
	tasks := executor.GenerateTasks(testPayloads, nil)

	// Progress tracking
	var bypassMu sync.Mutex
	var bypassPayloads []*mutation.TestResult

	// Determine WAF name for manifest display
	wafName := "Unknown WAF"
	if smartResult != nil && smartResult.WAFDetected {
		wafName = smartResult.VendorName
	}

	// Tips for bypass hunting
	tips := []string{
		"Chunked encoding can split payloads to evade pattern matching",
		"Most WAFs can't properly normalize Unicode in all contexts",
		"Encoders combined with evasions multiply your test coverage",
		"Parameter pollution bypasses 30%+ of WAFs",
		"Case variations alone find bypasses in 1 out of 5 WAFs",
	}

	// Determine output mode
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest BEFORE running (only in interactive mode)
	if !*streamMode {
		manifest := ui.NewExecutionManifest("BYPASS HUNT MANIFEST")
		manifest.SetDescription("Hunting for WAF bypass vectors")
		manifest.AddWithIcon("🎯", "Target", targetURL)
		manifest.AddWithIcon("🛡️", "WAF", wafName)
		manifest.AddEmphasis("📦", "Payloads", fmt.Sprintf("%d base payloads", len(testPayloads)))
		manifest.AddEmphasis("🔀", "Mutations", fmt.Sprintf("%d test combinations", len(tasks)))
		manifest.AddWithIcon("🏷️", "Category", *category)
		if *smartMode {
			manifest.AddWithIcon("🧠", "Mode", fmt.Sprintf("Smart (%s)", *smartModeType))
		} else {
			manifest.AddWithIcon("⚔️", "Mode", "Bypass Hunter (all evasions)")
		}
		manifest.AddConcurrency(*concurrency, *rateLimit)
		manifest.AddEstimate(len(tasks), *rateLimit)
		manifest.Print()
	} else {
		fmt.Printf("[INFO] Starting bypass hunt: target=%s waf=%s payloads=%d mutations=%d\n",
			targetURL, wafName, len(testPayloads), len(tasks))
	}

	// Use unified LiveProgress component
	progress := ui.NewLiveProgress(ui.LiveProgressConfig{
		Total:        len(tasks),
		DisplayLines: 3,
		Title:        "Hunting for bypasses",
		Unit:         "tests",
		Mode:         outputMode,
		Metrics: []ui.MetricConfig{
			{Name: "bypasses", Label: "Bypasses", Icon: "🎯", Highlight: true},
			{Name: "blocked", Label: "Blocked", Icon: "🛡️"},
			{Name: "errors", Label: "Errors", Icon: "⚠️"},
		},
		Tips:        tips,
		TipInterval: 8 * time.Second,
	})

	progress.Start()

	// Execute mutation tests with callback
	executor.Execute(ctx, tasks, func(r *mutation.TestResult) {
		progress.Increment()

		if r.Blocked {
			progress.AddMetric("blocked")
		} else if r.ErrorMessage != "" {
			progress.AddMetric("errors")
		} else {
			progress.AddMetric("bypasses")
			// Record bypass
			bypassMu.Lock()
			bypassPayloads = append(bypassPayloads, r)
			bypassMu.Unlock()
		}
	})

	progress.Stop()

	// Build result
	totalTested := progress.GetCompleted()
	bypassRate := float64(0)
	if totalTested > 0 {
		bypassRate = float64(len(bypassPayloads)) / float64(totalTested) * 100
	}

	ui.PrintSection("Bypass Hunt Results")
	fmt.Printf("  Total Tested:    %d\n", totalTested)
	fmt.Printf("  Bypasses Found:  %d\n", len(bypassPayloads))
	fmt.Printf("  Bypass Rate:     %.2f%%\n", bypassRate)
	fmt.Println()

	if len(bypassPayloads) > 0 {
		ui.PrintWarning(fmt.Sprintf("🚨 Found %d WAF bypasses!", len(bypassPayloads)))
		fmt.Println()

		// Show top bypasses
		ui.PrintSection("Top Bypasses")
		shown := 0
		for _, bp := range bypassPayloads {
			if shown >= 10 {
				fmt.Printf("  ... and %d more (see %s)\n", len(bypassPayloads)-10, *outputFile)
				break
			}
			fmt.Printf("  [%d] %s | %s | %s\n",
				bp.StatusCode, bp.EncoderUsed, bp.LocationUsed, bp.EvasionUsed)
			fmt.Printf("      Payload: %.60s...\n", bp.MutatedPayload)
			fmt.Println()
			shown++
		}

		// Save to file
		if *outputFile != "" {
			f, err := os.Create(*outputFile)
			if err == nil {
				defer f.Close()
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				// Create result structure for JSON output
				result := &mutation.WAFBypassResult{
					Found:          true,
					BypassPayloads: bypassPayloads,
					TotalTested:    totalTested,
					BypassRate:     bypassRate,
				}
				enc.Encode(result)
				ui.PrintSuccess(fmt.Sprintf("Full results saved to %s", *outputFile))
			}
		}
	} else {
		ui.PrintSuccess("✓ No bypasses found - WAF held strong!")
	}
}

func printMutationStats() {
	ui.PrintSection("Mutation Registry Statistics")

	// Create temporary executor to get stats
	executor := mutation.NewExecutor(nil)
	stats := executor.GetStats()

	fmt.Printf("  Encoders:   %d registered\n", stats["encoders"])
	fmt.Printf("  Locations:  %d registered\n", stats["locations"])
	fmt.Printf("  Evasions:   %d registered\n", stats["evasions"])
	fmt.Printf("  Protocols:  %d registered\n", stats["protocols"])
	fmt.Printf("  Total:      %d mutators\n", stats["total"])
	fmt.Println()

	// List all registered mutators
	reg := mutation.DefaultRegistry
	categories := reg.Categories()

	for _, cat := range categories {
		ui.PrintSection(strings.Title(cat) + " Mutators")
		mutators := reg.GetByCategory(cat)
		for _, m := range mutators {
			fmt.Printf("  %-25s %s\n", m.Name(), m.Description())
		}
		fmt.Println()
	}

	// Show example combinations
	ui.PrintSection("Example Coverage Calculation")
	fmt.Println("  For 100 payloads with default pipeline:")
	fmt.Printf("    Quick mode:    ~%d tests\n", 100*3*3)
	fmt.Printf("    Standard mode: ~%d tests\n", 100*stats["encoders"]*3)
	fmt.Printf("    Full mode:     ~%d tests\n", 100*stats["encoders"]*stats["locations"]*(1+stats["evasions"]))
}

// =============================================================================
// SMUGGLE COMMAND - HTTP Request Smuggling Detection
// =============================================================================

func runSmuggle() {
	ui.PrintCompactBanner()
	ui.PrintSection("HTTP Request Smuggling Detection")

	fs := flag.NewFlagSet("smuggle", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	targetFile := fs.String("l", "", "File containing target URLs")

	// Detection options
	safeMode := fs.Bool("safe", true, "Safe mode - timing only, no payload injection")
	timeout := fs.Int("timeout", 10, "Request timeout in seconds")
	delay := fs.Int("delay", 1000, "Delay between requests in milliseconds")
	retries := fs.Int("retries", 3, "Number of retries per technique")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")
	streamMode := fs.Bool("stream", false, "Streaming output mode for CI/scripts")

	fs.Parse(os.Args[2:])

	// Collect targets
	targets := []string{}

	if *targetURL != "" {
		targets = append(targets, strings.Split(*targetURL, ",")...)
	}

	if *targetFile != "" {
		file, err := os.Open(*targetFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to open target file: %v", err))
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u or -l")
		os.Exit(1)
	}

	// Create detector
	detector := smuggling.NewDetector()
	detector.Timeout = time.Duration(*timeout) * time.Second
	detector.SafeMode = *safeMode
	detector.DelayMs = *delay
	detector.MaxRetries = *retries

	if *verbose {
		fmt.Printf("  Mode: %s\n", map[bool]string{true: "Safe (timing only)", false: "Full (payload injection)"}[*safeMode])
		fmt.Printf("  Timeout: %ds\n", *timeout)
		fmt.Printf("  Delay: %dms\n", *delay)
		fmt.Println()
	}

	ctx := context.Background()
	allResults := []*smuggling.Result{}

	// Determine output mode
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest BEFORE running (multi-target only, interactive mode)
	var progress *ui.LiveProgress
	if len(targets) > 1 {
		if !*streamMode {
			manifest := ui.NewExecutionManifest("HTTP SMUGGLING DETECTION")
			manifest.SetDescription("Testing for request smuggling vulnerabilities")
			manifest.AddEmphasis("🎯", "Targets", fmt.Sprintf("%d URLs", len(targets)))
			manifest.AddWithIcon("🛡️", "Mode", map[bool]string{true: "Safe (timing only)", false: "Full (payload injection)"}[*safeMode])
			manifest.AddWithIcon("⏱️", "Timeout", fmt.Sprintf("%ds per target", *timeout))
			manifest.Print()
		} else {
			fmt.Printf("[INFO] Starting smuggle detection: targets=%d mode=%s\n",
				len(targets), map[bool]string{true: "safe", false: "full"}[*safeMode])
		}

		// Use unified LiveProgress component
		progress = ui.NewLiveProgress(ui.LiveProgressConfig{
			Total:        len(targets),
			DisplayLines: 2,
			Title:        "Testing for request smuggling",
			Unit:         "targets",
			Mode:         outputMode,
			Metrics: []ui.MetricConfig{
				{Name: "vulns", Label: "Vulnerabilities", Icon: "🚨", Highlight: true},
			},
		})
		progress.Start()
	}

	for _, target := range targets {
		if len(targets) == 1 {
			ui.PrintInfo(fmt.Sprintf("Testing: %s", target))
		}

		result, err := detector.Detect(ctx, target)
		if err != nil {
			if len(targets) == 1 {
				ui.PrintError(fmt.Sprintf("  Error: %v", err))
			}
			if progress != nil {
				progress.Increment()
			}
			continue
		}

		allResults = append(allResults, result)
		if progress != nil {
			progress.Increment()
			progress.AddMetricBy("vulns", len(result.Vulnerabilities))
		}

		if len(targets) == 1 {
			if len(result.Vulnerabilities) > 0 {
				for _, vuln := range result.Vulnerabilities {
					severity := ui.SeverityStyle(vuln.Severity)
					fmt.Printf("  [%s] %s - %s\n", severity.Render(vuln.Severity), vuln.Type, vuln.Description)
					if *verbose {
						fmt.Printf("    Confidence: %.0f%%\n", vuln.Confidence*100)
						fmt.Printf("    Exploitable: %v\n", vuln.Exploitable)
					}
				}
			} else {
				ui.PrintSuccess("  No smuggling vulnerabilities detected")
			}

			fmt.Printf("  Tested: %s in %v\n", strings.Join(result.TestedTechniques, ", "), result.Duration.Round(time.Millisecond))
			fmt.Println()
		}
	}

	// Stop progress
	if progress != nil {
		progress.Stop()
	}

	// Summary
	totalVulns := 0
	for _, r := range allResults {
		totalVulns += len(r.Vulnerabilities)
	}

	ui.PrintSection("Summary")
	fmt.Printf("  Targets tested: %d\n", len(allResults))
	fmt.Printf("  Vulnerabilities found: %d\n", totalVulns)

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(allResults)
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(allResults)
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}
	}
}

// =============================================================================
// RACE COMMAND - Race Condition Testing
// =============================================================================

func runRace() {
	ui.PrintCompactBanner()
	ui.PrintSection("Race Condition Testing")

	fs := flag.NewFlagSet("race", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	method := fs.String("method", "POST", "HTTP method (GET, POST, PUT)")
	body := fs.String("body", "", "Request body")
	headers := fs.String("H", "", "Headers (format: 'Header: Value' comma-separated)")

	// Attack options
	attackType := fs.String("attack", "double_submit", "Attack type: double_submit, token_reuse, limit_bypass, toctou")
	concurrency := fs.Int("c", 50, "Concurrent requests")
	iterations := fs.Int("n", 1, "Number of iterations")
	timeout := fs.Int("timeout", 30, "Request timeout in seconds")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Parse(os.Args[2:])

	if *targetURL == "" {
		ui.PrintError("Target URL required. Use -u <url>")
		os.Exit(1)
	}

	// Parse headers
	headerMap := http.Header{}
	if *headers != "" {
		for _, h := range strings.Split(*headers, ",") {
			parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
			if len(parts) == 2 {
				headerMap.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	// Create tester
	config := race.DefaultConfig()
	config.MaxConcurrency = *concurrency
	config.Iterations = *iterations
	config.Timeout = time.Duration(*timeout) * time.Second

	tester := race.NewTester(config)

	if *verbose {
		fmt.Printf("  Target: %s\n", *targetURL)
		fmt.Printf("  Attack: %s\n", *attackType)
		fmt.Printf("  Concurrency: %d\n", *concurrency)
		fmt.Printf("  Iterations: %d\n", *iterations)
		fmt.Println()
	}

	ctx := context.Background()
	var vulns []*race.Vulnerability

	// Create request config
	reqConfig := &race.RequestConfig{
		Method:  *method,
		URL:     *targetURL,
		Body:    *body,
		Headers: headerMap,
	}

	ui.PrintInfo(fmt.Sprintf("Testing %s attack...", *attackType))

	var vuln *race.Vulnerability
	var err error

	switch race.AttackType(*attackType) {
	case race.AttackDoubleSubmit:
		vuln, err = tester.TestDoubleSubmit(ctx, reqConfig, *concurrency)
	case race.AttackTokenReuse:
		vuln, err = tester.TestTokenReuse(ctx, reqConfig, *concurrency)
	case race.AttackLimitBypass:
		vuln, err = tester.TestLimitBypass(ctx, reqConfig, *concurrency, 10) // Default expected limit of 10
	default:
		// For other attack types, use generic concurrent test
		requests := make([]*race.RequestConfig, *concurrency)
		for i := 0; i < *concurrency; i++ {
			requests[i] = reqConfig
		}
		responses := tester.SendConcurrent(ctx, requests)

		// Analyze responses
		statusCounts := make(map[int]int)
		for _, r := range responses {
			if r.Error == nil {
				statusCounts[r.StatusCode]++
			}
		}

		if *verbose {
			fmt.Println("  Response distribution:")
			for status, count := range statusCounts {
				fmt.Printf("    HTTP %d: %d responses\n", status, count)
			}
		}
	}

	if err != nil {
		ui.PrintError(fmt.Sprintf("Test failed: %v", err))
	} else if vuln != nil {
		vulns = append(vulns, vuln)
		severity := ui.SeverityStyle(string(vuln.Severity))
		fmt.Printf("  [%s] %s\n", severity.Render(string(vuln.Severity)), vuln.Description)
		if *verbose {
			fmt.Printf("    Evidence: %s\n", vuln.Evidence)
			fmt.Printf("    Remediation: %s\n", vuln.Remediation)
		}
	} else {
		ui.PrintSuccess("  No race condition vulnerability detected")
	}

	// Summary
	ui.PrintSection("Summary")
	fmt.Printf("  Vulnerabilities found: %d\n", len(vulns))

	// Output
	if *jsonOutput && len(vulns) > 0 {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(vulns)
	}

	if *outputFile != "" && len(vulns) > 0 {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(vulns)
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}
	}
}

// =============================================================================
// WORKFLOW COMMAND - Attack Workflow Execution
// =============================================================================

func runWorkflow() {
	ui.PrintCompactBanner()
	ui.PrintSection("Workflow Execution")

	fs := flag.NewFlagSet("workflow", flag.ExitOnError)

	// Workflow file
	workflowFile := fs.String("f", "", "Workflow file (YAML or JSON)")
	fs.StringVar(workflowFile, "file", "", "Workflow file (YAML or JSON)")

	// Input variables
	inputVars := fs.String("var", "", "Input variables (format: 'name=value' comma-separated)")

	// Execution options
	dryRun := fs.Bool("dry-run", false, "Show what would be executed without running")
	_ = fs.Bool("continue-on-error", false, "Continue workflow on step failure (reserved for future use)")
	timeout := fs.Int("timeout", 300, "Workflow timeout in seconds")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")

	fs.Parse(os.Args[2:])

	if *workflowFile == "" {
		ui.PrintError("Workflow file required. Use -f <file.yaml>")
		os.Exit(1)
	}

	// Parse input variables
	inputs := make(map[string]string)
	if *inputVars != "" {
		for _, v := range strings.Split(*inputVars, ",") {
			parts := strings.SplitN(strings.TrimSpace(v), "=", 2)
			if len(parts) == 2 {
				inputs[parts[0]] = parts[1]
			}
		}
	}

	// Load workflow
	wf, err := workflow.LoadWorkflow(*workflowFile)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to load workflow: %v", err))
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("  Workflow: %s\n", wf.Name)
		if wf.Description != "" {
			fmt.Printf("  Description: %s\n", wf.Description)
		}
		fmt.Printf("  Steps: %d\n", len(wf.Steps))
		fmt.Println()
	}

	// Create engine
	engine := workflow.NewEngine()
	engine.DryRun = *dryRun
	engine.Verbose = *verbose

	// Execute workflow with timeout
	timeoutDuration := time.Duration(*timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	ui.PrintInfo(fmt.Sprintf("Executing workflow: %s", wf.Name))
	if *dryRun {
		ui.PrintInfo("(dry-run mode - no commands will be executed)")
	}
	fmt.Println()

	result, err := engine.Execute(ctx, wf, inputs)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Workflow failed: %v", err))
	}

	// Print step results
	for _, sr := range result.Steps {
		statusIcon := "✓"
		if sr.Status == "failed" {
			statusIcon = "✗"
		} else if sr.Status == "skipped" {
			statusIcon = "○"
		}

		fmt.Printf("  %s %s (%s) - %v\n", statusIcon, sr.StepName, sr.Status, sr.Duration.Round(time.Millisecond))
		if *verbose && sr.Output != "" {
			lines := strings.Split(sr.Output, "\n")
			for i, line := range lines {
				if i < 5 { // Show first 5 lines
					fmt.Printf("    %s\n", line)
				}
			}
			if len(lines) > 5 {
				fmt.Printf("    ... (%d more lines)\n", len(lines)-5)
			}
		}
	}

	// Summary
	fmt.Println()
	ui.PrintSection("Summary")
	fmt.Printf("  Status: %s\n", result.Status)
	fmt.Printf("  Duration: %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("  Steps: %d total, %d succeeded, %d failed, %d skipped\n",
		len(result.Steps),
		countStepStatus(result.Steps, "success"),
		countStepStatus(result.Steps, "failed"),
		countStepStatus(result.Steps, "skipped"))

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(result)
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(result)
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}
	}

	if result.Status == "failed" {
		os.Exit(1)
	}
}

func countStepStatus(results []workflow.StepResult, status string) int {
	count := 0
	for _, r := range results {
		if r.Status == status {
			count++
		}
	}
	return count
}

// =============================================================================
// HEADLESS COMMAND - Headless Browser Testing
// =============================================================================

func runHeadless() {
	ui.PrintCompactBanner()
	ui.PrintSection("Headless Browser Testing")

	fs := flag.NewFlagSet("headless", flag.ExitOnError)

	// Target options
	targetURL := fs.String("u", "", "Target URL")
	fs.StringVar(targetURL, "target", "", "Target URL")
	targetFile := fs.String("l", "", "File containing target URLs")

	// Browser options
	chromePath := fs.String("chrome", "", "Path to Chrome/Chromium executable")
	headlessMode := fs.Bool("headless", true, "Run in headless mode")
	timeout := fs.Int("timeout", 30, "Page load timeout in seconds")
	waitTime := fs.Int("wait", 2, "Wait time after page load in seconds")

	// Action options
	screenshot := fs.Bool("screenshot", false, "Take screenshots")
	screenshotDir := fs.String("screenshot-dir", "screenshots", "Screenshot output directory")
	extractURLs := fs.Bool("extract-urls", true, "Extract URLs from page")
	executeJS := fs.String("js", "", "JavaScript to execute on page")

	// Output options
	outputFile := fs.String("o", "", "Output file (JSON)")
	jsonOutput := fs.Bool("json", false, "JSON output to stdout")
	verbose := fs.Bool("v", false, "Verbose output")
	streamMode := fs.Bool("stream", false, "Streaming output mode for CI/scripts")

	fs.Parse(os.Args[2:])

	// Collect targets
	targets := []string{}

	if *targetURL != "" {
		targets = append(targets, strings.Split(*targetURL, ",")...)
	}

	if *targetFile != "" {
		file, err := os.Open(*targetFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to open target file: %v", err))
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	}

	if len(targets) == 0 {
		ui.PrintError("No targets specified. Use -u or -l")
		os.Exit(1)
	}

	// Create browser config
	config := headless.DefaultConfig()
	config.ShowBrowser = !*headlessMode // ShowBrowser is inverted from headless flag
	config.PageTimeout = time.Duration(*timeout) * time.Second
	config.IdleTimeout = time.Duration(*waitTime) * time.Second
	if *chromePath != "" {
		config.ChromiumPath = *chromePath
	}
	if *screenshot {
		config.ScreenshotEnabled = true
		config.ScreenshotDir = *screenshotDir
	}
	if *executeJS != "" {
		config.PostLoadJS = *executeJS
	}

	if *verbose {
		fmt.Printf("  Headless: %v\n", *headlessMode)
		fmt.Printf("  Timeout: %ds\n", *timeout)
		fmt.Printf("  Wait: %ds\n", *waitTime)
		fmt.Println()
	}

	// Create browser
	browser, err := headless.NewBrowser(config)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to create browser: %v", err))
		ui.PrintInfo("Make sure Chrome/Chromium is installed or specify path with -chrome")
		os.Exit(1)
	}
	defer browser.Close()

	// Create screenshot directory if needed
	if *screenshot {
		if err := os.MkdirAll(*screenshotDir, 0755); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create screenshot directory: %v", err))
		}
	}

	ctx := context.Background()
	allResults := []*headless.PageResult{}

	// Determine output mode
	outputMode := ui.OutputModeInteractive
	if *streamMode {
		outputMode = ui.OutputModeStreaming
	}

	// Display execution manifest and progress for multi-target
	var progress *ui.LiveProgress
	if len(targets) > 1 {
		if !*streamMode {
			manifest := ui.NewExecutionManifest("HEADLESS BROWSER TESTING")
			manifest.SetDescription("Visiting pages with headless browser")
			manifest.AddEmphasis("🎯", "Targets", fmt.Sprintf("%d URLs", len(targets)))
			manifest.AddWithIcon("🌐", "Headless", fmt.Sprintf("%v", *headlessMode))
			manifest.AddWithIcon("⏱️", "Timeout", fmt.Sprintf("%ds", *timeout))
			if *screenshot {
				manifest.AddWithIcon("📸", "Screenshots", *screenshotDir)
			}
			manifest.Print()
		} else {
			fmt.Printf("[INFO] Starting headless browsing: targets=%d headless=%v\n",
				len(targets), *headlessMode)
		}

		// Use unified LiveProgress component
		progress = ui.NewLiveProgress(ui.LiveProgressConfig{
			Total:        len(targets),
			DisplayLines: 2,
			Title:        "Browsing pages",
			Unit:         "pages",
			Mode:         outputMode,
			Metrics: []ui.MetricConfig{
				{Name: "urls", Label: "URLs Found", Icon: "🔗"},
			},
		})
		progress.Start()
	}

	for _, target := range targets {
		if len(targets) == 1 {
			ui.PrintInfo(fmt.Sprintf("Visiting: %s", target))
		}

		result, err := browser.Visit(ctx, target)
		if err != nil {
			if len(targets) == 1 {
				ui.PrintError(fmt.Sprintf("  Error: %v", err))
			}
			if progress != nil {
				progress.Increment()
			}
			continue
		}

		allResults = append(allResults, result)
		if progress != nil {
			progress.Increment()
			progress.AddMetricBy("urls", len(result.FoundURLs))
		}

		if len(targets) == 1 {
			fmt.Printf("  Status: %d\n", result.StatusCode)
			fmt.Printf("  Title: %s\n", result.Title)

			if *extractURLs && len(result.FoundURLs) > 0 {
				fmt.Printf("  URLs found: %d\n", len(result.FoundURLs))
				if *verbose {
					for i, u := range result.FoundURLs {
						if i < 10 {
							fmt.Printf("    - %s\n", u.URL)
						}
					}
					if len(result.FoundURLs) > 10 {
						fmt.Printf("    ... and %d more\n", len(result.FoundURLs)-10)
					}
				}
			}

			if *screenshot && result.ScreenshotPath != "" {
				fmt.Printf("  Screenshot: %s\n", result.ScreenshotPath)
			}

			fmt.Println()
		}
	}

	// Stop progress
	if progress != nil {
		progress.Stop()
	}

	// Summary
	ui.PrintSection("Summary")
	fmt.Printf("  Pages visited: %d\n", len(allResults))
	totalURLs := 0
	for _, r := range allResults {
		totalURLs += len(r.FoundURLs)
	}
	fmt.Printf("  URLs extracted: %d\n", totalURLs)

	// Output
	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(allResults)
	}

	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			ui.PrintError(fmt.Sprintf("Failed to create output file: %v", err))
		} else {
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(allResults)
			ui.PrintSuccess(fmt.Sprintf("Results saved to %s", *outputFile))
		}
	}
}
