package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/apispec"
	"github.com/waftester/waftester/pkg/attackconfig"
	"github.com/waftester/waftester/pkg/clickjack"
	"github.com/waftester/waftester/pkg/cmdi"
	"github.com/waftester/waftester/pkg/cors"
	"github.com/waftester/waftester/pkg/crlf"
	"github.com/waftester/waftester/pkg/csrf"
	"github.com/waftester/waftester/pkg/deserialize"
	"github.com/waftester/waftester/pkg/hpp"
	"github.com/waftester/waftester/pkg/httpclient"
	"github.com/waftester/waftester/pkg/idor"
	"github.com/waftester/waftester/pkg/ldap"
	"github.com/waftester/waftester/pkg/lfi"
	"github.com/waftester/waftester/pkg/massassignment"
	"github.com/waftester/waftester/pkg/nosqli"
	"github.com/waftester/waftester/pkg/output/events"
	"github.com/waftester/waftester/pkg/rce"
	"github.com/waftester/waftester/pkg/redirect"
	"github.com/waftester/waftester/pkg/rfi"
	"github.com/waftester/waftester/pkg/sqli"
	"github.com/waftester/waftester/pkg/ssi"
	"github.com/waftester/waftester/pkg/ssrf"
	"github.com/waftester/waftester/pkg/ssti"
	"github.com/waftester/waftester/pkg/traversal"
	"github.com/waftester/waftester/pkg/ui"
	"github.com/waftester/waftester/pkg/upload"
	"github.com/waftester/waftester/pkg/xmlinjection"
	"github.com/waftester/waftester/pkg/xpath"
	"github.com/waftester/waftester/pkg/xss"
	"github.com/waftester/waftester/pkg/xxe"
)

// runSpecScan handles the --spec scan path: loads the spec, builds a plan,
// iterates endpoints, and runs the requested scan types against each.
func runSpecScan(
	ctx context.Context,
	cfg *apispec.SpecConfig,
	cf *CommonFlags,
	outFlags *OutputFlags,
	shouldScan func(string) bool,
	targetOverride string,
	concurrency int,
	rateLimit int,
	proxy string,
	streamJSON bool,
	dispCtx *DispatcherContext,
) {
	// Load and parse the spec.
	source := cfg.Source()
	if !streamJSON {
		ui.PrintSection("API Spec Scan")
		ui.PrintConfigLine("Spec", source)
	}

	spec, err := apispec.ParseContext(ctx, source)
	if err != nil {
		ui.PrintError(fmt.Sprintf("Failed to parse spec: %v", err))
		os.Exit(1)
	}

	// Load environment file if specified.
	var envVars map[string]string
	if cfg.EnvFile != "" {
		var envErr error
		envVars, envErr = apispec.LoadPostmanEnvironment(cfg.EnvFile)
		if envErr != nil {
			ui.PrintWarning(fmt.Sprintf("Failed to load environment file: %v", envErr))
		}
	}

	// Always resolve variables — spec defaults can embed internal URLs that
	// bypass SSRF checks if left as {{var}} templates.
	apispec.ResolveVariables(spec, cfg.Variables, envVars)

	// SSRF blocklist: reject specs targeting internal networks unless allowed.
	// Must run AFTER variable resolution — variables can inject internal URLs.
	if !cfg.AllowInternal {
		if ssrfErr := apispec.CheckServerURLs(spec); ssrfErr != nil {
			ui.PrintError(ssrfErr.Error())
			os.Exit(1)
		}
	}

	// Resolve base URL: CLI -u overrides spec BaseURL.
	baseURL := spec.BaseURL()
	if targetOverride != "" {
		baseURL = targetOverride
	}
	if baseURL == "" {
		ui.PrintError("No base URL found in spec and no -u flag provided")
		os.Exit(1)
	}

	// Substitute variables in the base URL.
	baseURL = apispec.SubstituteVariables(baseURL, spec.Variables)

	if !streamJSON {
		ui.PrintConfigLine("Base URL", baseURL)
		ui.PrintConfigLine("Format", string(spec.Format))
		ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d total", len(spec.Endpoints)))
	}

	// Filter endpoints based on --group, --skip-group, --path.
	endpoints := cfg.FilterEndpoints(spec.Endpoints)
	if len(endpoints) == 0 {
		ui.PrintWarning("No endpoints match the current filters")
		os.Exit(0)
	}

	if !streamJSON && len(endpoints) != len(spec.Endpoints) {
		ui.PrintConfigLine("Filtered", fmt.Sprintf("%d endpoints", len(endpoints)))
	}

	// Show spec auth schemes.
	if !streamJSON && len(spec.AuthSchemes) > 0 {
		descs := apispec.DescribeSpecAuth(spec.AuthSchemes)
		for _, d := range descs {
			ui.PrintInfo(fmt.Sprintf("Auth required: %s", d))
		}
		if !cfg.Auth.HasAuth() {
			ui.PrintWarning("No auth credentials provided. Use --bearer, --api-key, or --auth-header")
		}
	}

	// Build scan plan.
	plan := apispec.BuildSimplePlan(spec, cfg)
	if plan == nil || len(plan.Entries) == 0 {
		ui.PrintWarning("No scan plan entries generated")
		os.Exit(0)
	}

	if !streamJSON {
		ui.PrintConfigLine("Plan", fmt.Sprintf("%d entries, ~%d tests", len(plan.Entries), plan.TotalTests))
		ui.PrintConfigLine("Est. Duration", plan.EstimatedDuration.Truncate(time.Second).String())
		fmt.Fprintln(os.Stderr)
	}

	// Spec dry-run: show plan and exit.
	if cfg.DryRun {
		runSpecDryRun(plan, endpoints, streamJSON)
		return
	}

	// Resolve auth. Wire warning callback to stderr (safe in CLI context).
	cfg.Auth.WarnFunc = func(msg string) {
		fmt.Fprintln(os.Stderr, msg)
	}
	authFn := apispec.ResolveAuth(spec.AuthSchemes, cfg.Auth)

	// Build scan ID for event dispatch.
	scanID := ""
	if dispCtx != nil {
		scanID = dispCtx.ScanID
	}

	// Emit spec scan started event.
	if dispCtx != nil {
		_ = dispCtx.EmitEvent(ctx, events.NewSpecScanStartedEvent(
			scanID, source, string(spec.Format),
			len(endpoints), plan.TotalTests, nil, string(cfg.Intensity),
		))
	}

	// Execute the plan.
	executor := &apispec.SimpleExecutor{
		BaseURL:     baseURL,
		Concurrency: concurrency,
		AuthFn:      authFn,
		ScanFn: func(ctx context.Context, name string, targetURL string, ep apispec.Endpoint) ([]apispec.SpecFinding, error) {
			if !shouldScan(name) {
				return nil, nil
			}

			// Run the scanner for this category against the endpoint URL.
			findings, scanErr := runScannerForSpec(ctx, name, targetURL, ep, cf, proxy)
			return findings, scanErr
		},
		OnEndpointStart: func(ep apispec.Endpoint, scanType string) {
			if !streamJSON {
				ui.PrintInfo(fmt.Sprintf("Scanning %s %s [%s]", ep.Method, ep.Path, scanType))
			}
			if dispCtx != nil {
				_ = dispCtx.EmitEvent(ctx, events.NewEndpointScanStartedEvent(
					scanID, ep.Method, ep.Path, ep.CorrelationTag, scanType,
				))
			}
		},
		OnEndpointComplete: func(ep apispec.Endpoint, scanType string, findingCount int, err error) {
			if err != nil && cf.Verbose {
				ui.PrintWarning(fmt.Sprintf("%s %s [%s]: %v", ep.Method, ep.Path, scanType, err))
			}
			if dispCtx != nil {
				errMsg := ""
				if err != nil {
					errMsg = err.Error()
				}
				_ = dispCtx.EmitEvent(ctx, events.NewEndpointScanCompletedEvent(
					scanID, ep.Method, ep.Path, ep.CorrelationTag, scanType, findingCount, 0, errMsg,
				))
			}
		},
		OnFinding: func(f apispec.SpecFinding) {
			if streamJSON {
				data, _ := json.Marshal(map[string]interface{}{
					"type":      "spec_finding",
					"timestamp": time.Now().Format(time.RFC3339),
					"data":      f,
				})
				fmt.Println(string(data)) // debug:keep
			} else {
				ui.PrintWarning(fmt.Sprintf("[%s] %s %s — %s: %s (param: %s)",
					strings.ToUpper(f.Severity), f.Method, f.Path, f.Category, f.Title, f.Parameter))
			}
			if dispCtx != nil {
				_ = dispCtx.EmitEvent(ctx, events.NewEndpointFindingEvent(
					scanID, f.Method, f.Path, f.CorrelationTag,
					f.Category, f.Parameter, f.Severity, f.Title, f.Evidence,
				))
			}
		},
	}

	session, execErr := executor.Execute(ctx, plan)
	if execErr != nil {
		ui.PrintError(fmt.Sprintf("Spec scan execution error: %v", execErr))
	}

	// Use the executor's result directly — it already has all findings,
	// endpoints, tests, and timing finalized.
	result := session.Result
	if result == nil {
		result = &apispec.SpecScanResult{
			SpecSource: source,
			StartedAt:  time.Now(),
		}
		result.Finalize()
	}

	// Print summary.
	if !streamJSON {
		fmt.Fprintln(os.Stderr)
		ui.PrintSection("Spec Scan Results")
		ui.PrintConfigLine("Spec", source)
		ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d", session.TotalEndpoints))
		ui.PrintConfigLine("Tests", fmt.Sprintf("%d", session.TotalTests))
		ui.PrintConfigLine("Findings", fmt.Sprintf("%d", result.TotalFindings()))
		ui.PrintConfigLine("Duration", result.Duration.Truncate(time.Millisecond).String())

		bySev := result.BySeverity()
		if len(bySev) > 0 {
			var sevParts []string
			for sev, count := range bySev {
				sevParts = append(sevParts, fmt.Sprintf("%s: %d", sev, count))
			}
			ui.PrintConfigLine("By Severity", strings.Join(sevParts, ", "))
		}

		byCat := result.ByCategory()
		if len(byCat) > 0 {
			var catParts []string
			for cat, count := range byCat {
				catParts = append(catParts, fmt.Sprintf("%s: %d", cat, count))
			}
			ui.PrintConfigLine("By Category", strings.Join(catParts, ", "))
		}
	}

	// Dispatch completion event.
	if dispCtx != nil {
		_ = dispCtx.EmitEvent(ctx, events.NewSpecScanCompletedEvent(
			scanID, source, session.TotalEndpoints, session.TotalTests,
			result.TotalFindings(), result.Duration, result.BySeverity(), result.ByCategory(),
		))
		_ = dispCtx.EmitSummary(ctx, session.TotalEndpoints, result.TotalFindings(), 0, result.Duration)
	}

	// Write output if configured.
	if outFlags.OutputFile != "" {
		writeSpecOutput(result, outFlags)
	}
}

// runSpecDryRun outputs the spec scan plan and exits.
func runSpecDryRun(plan *apispec.ScanPlan, endpoints []apispec.Endpoint, streamJSON bool) {
	if streamJSON {
		data, _ := json.Marshal(plan)
		fmt.Println(string(data)) // debug:keep
		os.Exit(0)
	}

	ui.PrintSection("Spec Scan Plan (Dry Run)")
	ui.PrintConfigLine("Total Entries", fmt.Sprintf("%d", len(plan.Entries)))
	ui.PrintConfigLine("Total Tests", fmt.Sprintf("%d", plan.TotalTests))
	ui.PrintConfigLine("Est. Duration", plan.EstimatedDuration.Truncate(time.Second).String())
	fmt.Fprintln(os.Stderr)

	// Group entries by endpoint for readable output.
	type epKey struct{ method, path string }
	seen := make(map[epKey][]string)
	var order []epKey

	for _, entry := range plan.Entries {
		k := epKey{entry.Endpoint.Method, entry.Endpoint.Path}
		if _, ok := seen[k]; !ok {
			order = append(order, k)
		}
		seen[k] = append(seen[k], entry.Attack.Category)
	}

	for _, k := range order {
		scanTypes := seen[k]
		fmt.Fprintf(os.Stderr, "  %s %s\n", k.method, k.path)
		fmt.Fprintf(os.Stderr, "    Scans: %s\n", strings.Join(unique(scanTypes), ", "))
	}

	fmt.Fprintln(os.Stderr)
	ui.PrintConfigLine("Endpoints", fmt.Sprintf("%d", len(endpoints)))
	ui.PrintHelp("Remove --spec-dry-run to execute")
	os.Exit(0)
}

// unique deduplicates a string slice preserving order.
func unique(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// runScannerForSpec runs a single scanner type against a spec endpoint URL.
// This bridges the gap between spec-driven scanning and the existing
// scanner Scan(ctx, targetURL) contract.
func runScannerForSpec(
	ctx context.Context,
	scanType string,
	targetURL string,
	ep apispec.Endpoint,
	cf *CommonFlags,
	proxy string,
) ([]apispec.SpecFinding, error) {
	tag := ep.CorrelationTag
	if tag == "" {
		tag = apispec.CorrelationTag(ep.Method, ep.Path)
	}

	timeout := time.Duration(cf.Timeout) * time.Second
	if timeout == 0 {
		timeout = httpclient.TimeoutScanning
	}

	httpClient := httpclient.New(httpclient.Config{
		Timeout:            timeout,
		InsecureSkipVerify: cf.SkipVerify,
		Proxy:              proxy,
		CookieJar:          true,
	})

	base := attackconfig.Base{
		Timeout: timeout,
		Client:  httpClient,
	}

	switch scanType {
	case "sqli":
		return runSQLi(ctx, targetURL, ep, tag, base)
	case "xss":
		return runXSS(ctx, targetURL, ep, tag, base)
	case "cmdi":
		return runCMDi(ctx, targetURL, ep, tag, base)
	case "traversal", "path-traversal":
		return runTraversal(ctx, targetURL, ep, tag, base)
	case "nosqli":
		return runNoSQLi(ctx, targetURL, ep, tag, base)
	case "ssrf":
		return runSSRF(ctx, targetURL, ep, tag)
	case "ssti":
		return runSSTI(ctx, targetURL, ep, tag, base)
	case "xxe":
		return runXXE(ctx, targetURL, ep, tag, base)
	case "lfi":
		return runLFI(ctx, targetURL, ep, tag, base)
	case "cors":
		return runCORS(ctx, targetURL, ep, tag, base)
	case "redirect", "open-redirect":
		return runRedirect(ctx, targetURL, ep, tag, base)
	case "upload":
		return runUpload(ctx, targetURL, ep, tag, base)
	case "crlf":
		return runCRLF(ctx, targetURL, ep, tag, base)
	case "hpp":
		return runHPP(ctx, targetURL, ep, tag, base)
	case "deserialize", "deserialization":
		return runDeserialize(ctx, targetURL, ep, tag, base)
	case "ldap":
		return runSpecLDAP(ctx, targetURL, ep, tag, base)
	case "ssi":
		return runSpecSSI(ctx, targetURL, ep, tag, base)
	case "xpath":
		return runSpecXPath(ctx, targetURL, ep, tag, base)
	case "xmlinjection":
		return runSpecXMLInjection(ctx, targetURL, ep, tag, base)
	case "rfi":
		return runSpecRFI(ctx, targetURL, ep, tag, base)
	case "rce":
		return runSpecRCE(ctx, targetURL, ep, tag, base)
	case "csrf":
		return runSpecCSRF(ctx, targetURL, ep, tag, base)
	case "clickjack":
		return runSpecClickjack(ctx, targetURL, ep, tag, base)
	case "idor":
		return runSpecIDOR(ctx, targetURL, ep, tag, base)
	case "massassignment":
		return runSpecMassAssignment(ctx, targetURL, ep, tag, base)
	default:
		return nil, fmt.Errorf("unsupported scan type: %s", scanType)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Scanner adapters — each converts scanner-specific results to []SpecFinding.
// ──────────────────────────────────────────────────────────────────────────────

func runSQLi(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := sqli.NewTester(&sqli.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("sqli: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "sqli",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-89",
		})
	}
	return findings, nil
}

func runXSS(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := xss.NewTester(&xss.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("xss: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "xss",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-79",
		})
	}
	return findings, nil
}

func runCMDi(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := cmdi.NewTester(&cmdi.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("cmdi: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		if v == nil {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "cmdi",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-78",
		})
	}
	return findings, nil
}

func runTraversal(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := traversal.NewTester(&traversal.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("traversal: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "traversal",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-22",
		})
	}
	return findings, nil
}

func runNoSQLi(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := nosqli.NewTester(&nosqli.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("nosqli: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "nosqli",
			Parameter:      v.Parameter,
			Payload:        v.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-943",
		})
	}
	return findings, nil
}

func runSSRF(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string) ([]apispec.SpecFinding, error) {
	// SSRF detector needs a parameter name. Use the first query/body param.
	param := firstInjectableParam(ep)
	if param == "" {
		return nil, nil
	}
	result, err := ssrf.NewDetector().Detect(ctx, targetURL, param)
	if err != nil {
		return nil, fmt.Errorf("ssrf: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "ssrf",
			Parameter:      v.Parameter,
			Payload:        v.Payload,
			Title:          v.Type,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-918",
		})
	}
	return findings, nil
}

func runSSTI(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := injectableParamNames(ep)
	if len(params) == 0 {
		return nil, nil
	}
	result, err := ssti.NewDetector(&ssti.DetectorConfig{Base: base}).ScanURL(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("ssti: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		if v == nil {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "ssti",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-1336",
		})
	}
	return findings, nil
}

func runXXE(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	vulns, err := xxe.NewDetector(&xxe.DetectorConfig{Base: base}).Detect(ctx, targetURL, ep.Method)
	if err != nil {
		return nil, fmt.Errorf("xxe: %w", err)
	}
	findings := make([]apispec.SpecFinding, 0, len(vulns))
	for _, v := range vulns {
		if v == nil {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "xxe",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-611",
		})
	}
	return findings, nil
}

func runLFI(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationPath {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := lfi.NewScanner(lfi.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("lfi: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "lfi",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("Local File Inclusion via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-98",
		})
	}
	return findings, nil
}

func runCORS(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := cors.NewTester(&cors.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("cors: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		if v == nil {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "cors",
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-942",
		})
	}
	return findings, nil
}

func runRedirect(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := redirect.NewTester(&redirect.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("redirect: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		if v == nil {
			continue
		}
		payload := ""
		if v.Payload != nil {
			payload = v.Payload.Value
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "redirect",
			Parameter:      v.Parameter,
			Payload:        payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-601",
		})
	}
	return findings, nil
}

func runUpload(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	vulns, err := upload.NewTester(&upload.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	findings := make([]apispec.SpecFinding, 0, len(vulns))
	for _, v := range vulns {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "upload",
			Parameter:      v.Parameter,
			Payload:        v.Vulnerability.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-434",
		})
	}
	return findings, nil
}

func runCRLF(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := crlf.NewTester(&crlf.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("crlf: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "crlf",
			Parameter:      v.Parameter,
			Payload:        v.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-93",
		})
	}
	return findings, nil
}

func runHPP(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := hpp.NewTester(&hpp.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("hpp: %w", err)
	}
	if result == nil {
		return nil, nil
	}
	findings := make([]apispec.SpecFinding, 0, len(result.Vulnerabilities))
	for _, v := range result.Vulnerabilities {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "hpp",
			Parameter:      v.Parameter,
			Payload:        v.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-235",
		})
	}
	return findings, nil
}

func runDeserialize(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	vulns, err := deserialize.NewTester(&deserialize.TesterConfig{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("deserialize: %w", err)
	}
	findings := make([]apispec.SpecFinding, 0, len(vulns))
	for _, v := range vulns {
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "deserialize",
			Parameter:      v.Parameter,
			Payload:        v.Payload,
			Title:          v.Description,
			Severity:       string(v.Severity),
			Evidence:       v.Evidence,
			Remediation:    v.Remediation,
			CWE:            "CWE-502",
		})
	}
	return findings, nil
}

// firstInjectableParam returns the first query or body parameter name, or "".
func firstInjectableParam(ep apispec.Endpoint) string {
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			return p.Name
		}
	}
	return ""
}

// injectableParamNames returns names of all query/body parameters.
func injectableParamNames(ep apispec.Endpoint) []string {
	var names []string
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			names = append(names, p.Name)
		}
	}
	return names
}

// writeSpecOutput writes spec scan results to the configured output file.
func writeSpecOutput(result *apispec.SpecScanResult, outFlags *OutputFlags) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to marshal spec results: %v", err))
		return
	}

	if writeErr := os.WriteFile(outFlags.OutputFile, data, 0o644); writeErr != nil {
		ui.PrintWarning(fmt.Sprintf("Failed to write output file: %v", writeErr))
		return
	}

	ui.PrintInfo(fmt.Sprintf("Results written to %s", outFlags.OutputFile))
}

func runSpecLDAP(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := ldap.NewScanner(ldap.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "ldap",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("LDAP Injection via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-90",
		})
	}
	return findings, nil
}

func runSpecSSI(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := ssi.NewScanner(ssi.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("ssi: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "ssi",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("SSI Injection via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-97",
		})
	}
	return findings, nil
}

func runSpecXPath(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := xpath.NewScanner(xpath.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("xpath: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "xpath",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("XPath Injection via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-643",
		})
	}
	return findings, nil
}

func runSpecXMLInjection(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	results, err := xmlinjection.NewScanner(xmlinjection.Config{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("xmlinjection: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "xmlinjection",
			Payload:        r.Payload,
			Title:          fmt.Sprintf("XML Injection (%s)", r.PayloadType),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-91",
		})
	}
	return findings, nil
}

func runSpecRFI(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationPath {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := rfi.NewScanner(rfi.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("rfi: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "rfi",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("Remote File Inclusion via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-98",
		})
	}
	return findings, nil
}

func runSpecRCE(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	params := make(map[string]string)
	for _, p := range ep.Parameters {
		if p.In == apispec.LocationQuery || p.In == apispec.LocationBody {
			params[p.Name] = "test"
		}
	}
	if len(params) == 0 {
		return nil, nil
	}
	results, err := rce.NewScanner(rce.Config{Base: base}).Scan(ctx, targetURL, params)
	if err != nil {
		return nil, fmt.Errorf("rce: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "rce",
			Parameter:      r.Parameter,
			Payload:        r.Payload,
			Title:          fmt.Sprintf("Remote Code Execution via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-94",
		})
	}
	return findings, nil
}

func runSpecCSRF(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	method := ep.Method
	if method == "" {
		method = "POST"
	}
	result, err := csrf.NewScanner(csrf.Config{Base: base}).Scan(ctx, targetURL, method)
	if err != nil {
		return nil, fmt.Errorf("csrf: %w", err)
	}
	if !result.Vulnerable {
		return nil, nil
	}
	return []apispec.SpecFinding{{
		Method:         ep.Method,
		Path:           ep.Path,
		CorrelationTag: tag,
		Category:       "csrf",
		Title:          "Missing CSRF Protection",
		Severity:       result.Severity,
		Evidence:       result.Evidence,
		CWE:            "CWE-352",
	}}, nil
}

func runSpecClickjack(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	result, err := clickjack.NewScanner(clickjack.Config{Base: base}).Scan(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("clickjack: %w", err)
	}
	if !result.Vulnerable {
		return nil, nil
	}
	return []apispec.SpecFinding{{
		Method:         ep.Method,
		Path:           ep.Path,
		CorrelationTag: tag,
		Category:       "clickjack",
		Title:          "Clickjacking: Missing Frame Protection",
		Severity:       result.Severity,
		Evidence:       result.Evidence,
		CWE:            "CWE-1021",
	}}, nil
}

func runSpecIDOR(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	cfg := idor.Config{
		Base:    base,
		BaseURL: targetURL,
	}
	scanner := idor.NewScanner(cfg)
	results, err := scanner.ScanEndpoint(ctx, ep.Path, ep.Method)
	if err != nil {
		return nil, fmt.Errorf("idor: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Accessible {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "idor",
			Title:          fmt.Sprintf("IDOR: %s accessible with ID %s", r.URL, r.TestedID),
			Severity:       r.Severity,
			Evidence:       r.Vulnerability,
			CWE:            "CWE-639",
		})
	}
	return findings, nil
}

func runSpecMassAssignment(ctx context.Context, targetURL string, ep apispec.Endpoint, tag string, base attackconfig.Base) ([]apispec.SpecFinding, error) {
	originalData := map[string]interface{}{"name": "test", "email": "test@example.com"}
	results, err := massassignment.NewScanner(massassignment.Config{Base: base}).Scan(ctx, targetURL, originalData)
	if err != nil {
		return nil, fmt.Errorf("massassignment: %w", err)
	}
	var findings []apispec.SpecFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		findings = append(findings, apispec.SpecFinding{
			Method:         ep.Method,
			Path:           ep.Path,
			CorrelationTag: tag,
			Category:       "massassignment",
			Parameter:      r.Parameter,
			Title:          fmt.Sprintf("Mass Assignment via %s", r.Parameter),
			Severity:       r.Severity,
			Evidence:       r.Evidence,
			CWE:            "CWE-915",
		})
	}
	return findings, nil
}
