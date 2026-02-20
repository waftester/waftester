package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/waftester/waftester/pkg/ui"
)

// BuildFromMetrics creates an EnterpriseReport from metrics.EnterpriseMetrics
// This is the main conversion function used by the auto command
func BuildFromMetrics(m interface{}, targetName string, scanDuration time.Duration) (*EnterpriseReport, error) {
	// Use reflection-free approach: marshal to JSON and unmarshal into our expected structure
	// This avoids import cycles while maintaining type safety
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Parse into a map for flexible access
	var metricsMap map[string]interface{}
	if err := json.Unmarshal(data, &metricsMap); err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	report := &EnterpriseReport{
		GeneratedAt:   time.Now(),
		ToolVersion:   ui.Version,
		ToolName:      "WAF-Tester",
		ReportVersion: "1.0",
		TargetName:    targetName,
		TestingDate:   time.Now().Format("2006-01-02 15:04:05"),
		ScanDuration:  scanDuration.Round(time.Second).String(),
	}

	// Extract target URL
	if url, ok := metricsMap["target_url"].(string); ok {
		report.TargetURL = url
	}

	// Extract WAF vendor
	if vendor, ok := metricsMap["waf_vendor"].(string); ok {
		report.WAFVendor = vendor
	}

	// Extract grade
	if grade, ok := metricsMap["grade"].(string); ok && len(grade) > 0 {
		// Compute grade from detection rate for styling
		detRate := 0.0
		if dr, ok := metricsMap["detection_rate"].(float64); ok {
			detRate = dr * 100
		}
		report.OverallGrade = Grade{
			Mark:           grade,
			Percentage:     detRate,
			CSSClassSuffix: strings.ToLower(string(grade[0])),
			Description:    "",
		}
		if gradeReason, ok := metricsMap["grade_reason"].(string); ok {
			report.OverallGrade.Description = gradeReason
		}
	}

	// Extract primary metrics
	if dr, ok := metricsMap["detection_rate"].(float64); ok {
		report.DetectionRate = dr
	}
	if fpr, ok := metricsMap["false_positive_rate"].(float64); ok {
		report.FalsePositiveRate = fpr
	}
	if br, ok := metricsMap["bypass_resistance"].(float64); ok {
		report.BypassResistance = br
	}

	// Extract enterprise metrics
	report.EnterpriseMetrics = &EnterpriseMetricsData{}
	if f1, ok := metricsMap["f1_score"].(float64); ok {
		report.EnterpriseMetrics.F1Score = f1
	}
	if f2, ok := metricsMap["f2_score"].(float64); ok {
		report.EnterpriseMetrics.F2Score = f2
	}
	if prec, ok := metricsMap["precision"].(float64); ok {
		report.EnterpriseMetrics.Precision = prec
	}
	if rec, ok := metricsMap["recall"].(float64); ok {
		report.EnterpriseMetrics.Recall = rec
	} else if dr, ok := metricsMap["detection_rate"].(float64); ok {
		report.EnterpriseMetrics.Recall = dr
	}
	if spec, ok := metricsMap["specificity"].(float64); ok {
		report.EnterpriseMetrics.Specificity = spec
	}
	if ba, ok := metricsMap["balanced_accuracy"].(float64); ok {
		report.EnterpriseMetrics.BalancedAccuracy = ba
	}
	if mcc, ok := metricsMap["mcc"].(float64); ok {
		report.EnterpriseMetrics.MCC = mcc
	}
	if bc, ok := metricsMap["block_consistency"].(float64); ok {
		report.EnterpriseMetrics.BlockConsistency = bc
	}
	if mp, ok := metricsMap["mutation_potency"].(float64); ok {
		report.EnterpriseMetrics.MutationPotency = mp
	}

	// Extract confusion matrix
	if cm, ok := metricsMap["confusion_matrix"].(map[string]interface{}); ok {
		if tp, ok := cm["true_positives"].(float64); ok {
			report.ConfusionMatrix.TruePositives = int(tp)
		}
		if tn, ok := cm["true_negatives"].(float64); ok {
			report.ConfusionMatrix.TrueNegatives = int(tn)
		}
		if fp, ok := cm["false_positives"].(float64); ok {
			report.ConfusionMatrix.FalsePositives = int(fp)
		}
		if fn, ok := cm["false_negatives"].(float64); ok {
			report.ConfusionMatrix.FalseNegatives = int(fn)
		}
	}

	// Extract latency
	if lat, ok := metricsMap["avg_latency_ms"].(float64); ok {
		report.AvgLatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p50_latency_ms"].(float64); ok {
		report.P50LatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p95_latency_ms"].(float64); ok {
		report.P95LatencyMs = int(lat)
	}
	if lat, ok := metricsMap["p99_latency_ms"].(float64); ok {
		report.P99LatencyMs = int(lat)
	}

	// Extract total requests
	if tr, ok := metricsMap["total_requests"].(float64); ok {
		report.TotalRequests = int(tr)
	}

	// Calculate blocked/passed from confusion matrix
	report.BlockedRequests = report.ConfusionMatrix.TruePositives + report.ConfusionMatrix.FalsePositives
	report.PassedRequests = report.ConfusionMatrix.TrueNegatives + report.ConfusionMatrix.FalseNegatives

	// Extract category metrics
	if catMetrics, ok := metricsMap["category_metrics"].(map[string]interface{}); ok {
		report.CategoryResults = make([]CategoryResult, 0, len(catMetrics))
		for cat, metrics := range catMetrics {
			catMap, ok := metrics.(map[string]interface{})
			if !ok {
				continue
			}

			cr := CategoryResult{
				Category:    cat,
				DisplayName: GetCategoryDisplayName(cat),
			}

			if dr, ok := catMap["detection_rate"].(float64); ok {
				cr.DetectionRate = dr
				cr.Grade = ComputeGrade(dr * 100)
			}
			if t, ok := catMap["total_tests"].(float64); ok {
				cr.TotalTests = int(t)
			}
			if b, ok := catMap["blocked"].(float64); ok {
				cr.Blocked = int(b)
			}
			if bp, ok := catMap["bypassed"].(float64); ok {
				cr.Bypassed = int(bp)
			}
			// If grade is directly provided in the metrics
			if g, ok := catMap["grade"].(string); ok && len(g) > 0 {
				cr.Grade = Grade{
					Mark:           g,
					Percentage:     cr.DetectionRate * 100,
					CSSClassSuffix: strings.ToLower(string(g[0])),
				}
			}

			report.CategoryResults = append(report.CategoryResults, cr)
		}

		// Sort categories alphabetically
		sort.Slice(report.CategoryResults, func(i, j int) bool {
			return report.CategoryResults[i].Category < report.CategoryResults[j].Category
		})

		// Build radar chart from categories
		report.RadarChartData = BuildRadarChartData(report.CategoryResults)
	}

	// Extract recommendations
	if recs, ok := metricsMap["recommendations"].([]interface{}); ok {
		report.Recommendations = make([]string, 0, len(recs))
		for _, r := range recs {
			if s, ok := r.(string); ok {
				report.Recommendations = append(report.Recommendations, s)
			}
		}
	}

	// Add comparison table
	report.ComparisonTable = DefaultComparisonTable()

	return report, nil
}

// GenerateEnterpriseHTMLReport is a convenience function that creates the report and writes to file
func GenerateEnterpriseHTMLReport(metrics interface{}, targetName string, scanDuration time.Duration, outputPath string) error {
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// GenerateEnterpriseHTMLReportWithDetails creates an HTML report with bypass and FP details
func GenerateEnterpriseHTMLReportWithDetails(metrics interface{}, targetName string, scanDuration time.Duration, bypasses interface{}, falsePositives interface{}, outputPath string) error {
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	// Add bypass details
	if bypasses != nil {
		bypassData, err := json.Marshal(bypasses)
		if err == nil {
			var bypassList []map[string]interface{}
			if json.Unmarshal(bypassData, &bypassList) == nil {
				for _, b := range bypassList {
					finding := BypassFinding{
						Severity: "high", // default
					}
					if cat, ok := b["category"].(string); ok {
						finding.Category = cat
					}
					if payload, ok := b["payload"].(string); ok {
						finding.Payload = payload
					}
					if endpoint, ok := b["endpoint"].(string); ok {
						finding.Endpoint = endpoint
					}
					if method, ok := b["method"].(string); ok {
						finding.Method = method
					}
					if status, ok := b["status_code"].(float64); ok {
						finding.StatusCode = int(status)
					}
					if sev, ok := b["severity"].(string); ok {
						finding.Severity = strings.ToLower(sev)
					}
					if size, ok := b["response_size"].(float64); ok {
						finding.ResponseSize = int(size)
					}
					// Enrich with enterprise vulnerability details
					EnrichBypassFinding(&finding)
					report.Bypasses = append(report.Bypasses, finding)
				}
			}
		}
	}

	// Add false positive details
	if falsePositives != nil {
		fpData, err := json.Marshal(falsePositives)
		if err == nil {
			var fpList []map[string]interface{}
			if json.Unmarshal(fpData, &fpList) == nil {
				for _, fp := range fpList {
					finding := FalsePositiveFinding{}
					if payload, ok := fp["payload"].(string); ok {
						finding.Payload = payload
					}
					if status, ok := fp["status_code"].(float64); ok {
						finding.StatusCode = int(status)
					}
					if reason, ok := fp["reason"].(string); ok {
						finding.Reason = reason
					} else {
						finding.Reason = "Legitimate request blocked by WAF"
					}
					report.FalsePositives = append(report.FalsePositives, finding)
				}
			}
		}
	}

	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// AddBypassesFromResults adds bypass details from output.ExecutionResults structure
func (r *EnterpriseReport) AddBypassesFromResults(results interface{}) error {
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}

	var resultsMap map[string]interface{}
	if err := json.Unmarshal(data, &resultsMap); err != nil {
		return err
	}

	// Extract bypass_details from the results
	if bypassDetails, ok := resultsMap["bypass_details"].([]interface{}); ok {
		for _, b := range bypassDetails {
			bMap, ok := b.(map[string]interface{})
			if !ok {
				continue
			}

			finding := BypassFinding{
				Severity: "high",
			}
			if cat, ok := bMap["category"].(string); ok {
				finding.Category = cat
			}
			if payload, ok := bMap["payload"].(string); ok {
				finding.Payload = payload
			}
			if endpoint, ok := bMap["endpoint"].(string); ok {
				finding.Endpoint = endpoint
			}
			if method, ok := bMap["method"].(string); ok {
				finding.Method = method
			}
			if status, ok := bMap["status_code"].(float64); ok {
				finding.StatusCode = int(status)
			}
			if sev, ok := bMap["severity"].(string); ok {
				finding.Severity = strings.ToLower(sev)
			}

			// Enrich with enterprise vulnerability details
			EnrichBypassFinding(&finding)

			r.Bypasses = append(r.Bypasses, finding)
		}
	}

	return nil
}

// AddBypassesFromResultsFile reads bypasses from a results.json file (array of test results)
func (r *EnterpriseReport) AddBypassesFromResultsFile(resultsFilePath string) error {
	data, err := os.ReadFile(resultsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results file: %w", err)
	}

	// Only "Pass" outcomes represent successful WAF bypasses.
	for _, result := range results {
		outcome, _ := result["outcome"].(string)
		if outcome != "Pass" {
			continue
		}

		finding := BypassFinding{
			Severity: "high",
		}

		// Basic fields
		if id, ok := result["id"].(string); ok {
			finding.ID = id
		}
		if cat, ok := result["category"].(string); ok {
			finding.Category = cat
		}
		if payload, ok := result["payload"].(string); ok {
			finding.Payload = payload
		}
		if url, ok := result["request_url"].(string); ok {
			finding.Endpoint = url
		} else if path, ok := result["target_path"].(string); ok {
			finding.Endpoint = path
		}
		if method, ok := result["method"].(string); ok {
			finding.Method = method
		}
		if status, ok := result["status_code"].(float64); ok {
			finding.StatusCode = int(status)
		}
		if sev, ok := result["severity"].(string); ok {
			finding.Severity = strings.ToLower(sev)
		}
		if size, ok := result["content_length"].(float64); ok {
			finding.ResponseSize = int(size)
		}
		if notes, ok := result["notes"].(string); ok {
			finding.TechnicalNotes = notes
		}

		// Extended fields
		if latency, ok := result["latency_ms"].(float64); ok {
			finding.LatencyMs = int(latency)
		}
		if timestamp, ok := result["timestamp"].(string); ok {
			finding.Timestamp = timestamp
		}
		if errorMsg, ok := result["error_message"].(string); ok {
			finding.TechnicalNotes = errorMsg
		}
		if blockConf, ok := result["block_confidence"].(float64); ok {
			// Convert confidence to percentage string
			if blockConf > 0 {
				finding.Confidence = fmt.Sprintf("%.0f%%", blockConf*100)
			}
		}

		// Extract response headers if present
		if headers, ok := result["response_headers"].(map[string]interface{}); ok {
			var headerLines []string
			for k, v := range headers {
				if vs, ok := v.(string); ok {
					headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, vs))
				}
			}
			if len(headerLines) > 0 {
				finding.Evidence = strings.Join(headerLines, "\n")
			}
		}

		// Extract risk score if present
		if riskData, ok := result["risk_score"].(map[string]interface{}); ok {
			if rs, ok := riskData["RiskScore"].(float64); ok {
				finding.RiskScore = rs
			}
			if escalation, ok := riskData["EscalationReason"].(string); ok {
				if finding.TechnicalNotes != "" {
					finding.TechnicalNotes += " | " + escalation
				} else {
					finding.TechnicalNotes = escalation
				}
			}
		}

		// Enrich with enterprise vulnerability details
		EnrichBypassFinding(&finding)

		r.Bypasses = append(r.Bypasses, finding)
	}

	return nil
}

// LoadAllResultsFromFile reads ALL results from a results.json file into AllResults
func (r *EnterpriseReport) LoadAllResultsFromFile(resultsFilePath string) error {
	data, err := os.ReadFile(resultsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results file: %w", err)
	}

	// Process all results
	for _, result := range results {
		tr := TestResult{}

		if id, ok := result["id"].(string); ok {
			tr.ID = id
		}
		if cat, ok := result["category"].(string); ok {
			tr.Category = cat
		}
		if sev, ok := result["severity"].(string); ok {
			tr.Severity = sev
		}
		if outcome, ok := result["outcome"].(string); ok {
			tr.Outcome = outcome
		}
		if status, ok := result["status_code"].(float64); ok {
			tr.StatusCode = int(status)
		}
		if latency, ok := result["latency_ms"].(float64); ok {
			tr.LatencyMs = int(latency)
		}
		if payload, ok := result["payload"].(string); ok {
			tr.Payload = payload
		}
		if method, ok := result["method"].(string); ok {
			tr.Method = method
		}
		if path, ok := result["target_path"].(string); ok {
			tr.TargetPath = path
		}
		if url, ok := result["request_url"].(string); ok {
			tr.RequestURL = url
		}
		if size, ok := result["content_length"].(float64); ok {
			tr.ContentLength = int(size)
		}
		if err, ok := result["error_message"].(string); ok {
			tr.ErrorMessage = err
		}
		if ts, ok := result["timestamp"].(string); ok {
			tr.Timestamp = ts
		}
		if conf, ok := result["block_confidence"].(float64); ok {
			tr.BlockConfidence = conf
		}
		if riskData, ok := result["risk_score"].(map[string]interface{}); ok {
			if rs, ok := riskData["RiskScore"].(float64); ok {
				tr.RiskScore = rs
			}
		}
		if headers, ok := result["response_headers"].(map[string]interface{}); ok {
			tr.ResponseHeaders = make(map[string]string)
			for k, v := range headers {
				if vs, ok := v.(string); ok {
					tr.ResponseHeaders[k] = vs
				}
			}
		}

		r.AllResults = append(r.AllResults, tr)
	}

	// Update summary counts
	r.TotalRequests = len(r.AllResults)
	r.BlockedRequests = 0
	r.PassedRequests = 0
	r.ErrorRequests = 0
	for _, tr := range r.AllResults {
		switch tr.Outcome {
		case "Blocked":
			r.BlockedRequests++
		case "Pass":
			r.PassedRequests++
		case "Error":
			r.ErrorRequests++
		}
	}

	return nil
}

// GenerateEnterpriseHTMLReportFromWorkspace creates an HTML report from a workspace directory
// It reads assessment.json for metrics and results.json for detailed findings
func GenerateEnterpriseHTMLReportFromWorkspace(workspaceDir string, targetName string, scanDuration time.Duration, outputPath string) error {
	// Read assessment.json
	assessmentPath := filepath.Join(workspaceDir, "assessment.json")
	assessmentData, err := os.ReadFile(assessmentPath)
	if err != nil {
		return fmt.Errorf("failed to read assessment.json: %w", err)
	}

	var metrics map[string]interface{}
	if err := json.Unmarshal(assessmentData, &metrics); err != nil {
		return fmt.Errorf("failed to parse assessment.json: %w", err)
	}

	// Build report from metrics
	report, err := BuildFromMetrics(metrics, targetName, scanDuration)
	if err != nil {
		return fmt.Errorf("failed to build report: %w", err)
	}

	// Load ALL results from results.json
	resultsPath := filepath.Join(workspaceDir, "results.json")
	if err := report.LoadAllResultsFromFile(resultsPath); err != nil {
		// Not critical - just log and continue
		fmt.Printf("Note: Could not load all results from results.json: %v\n", err)
	}

	// Extract bypasses from results.json (outcomes = "Pass" or "Fail")
	if err := report.AddBypassesFromResultsFile(resultsPath); err != nil {
		// Not critical - just log and continue
		fmt.Printf("Note: Could not read bypass details from results.json: %v\n", err)
	}

	// Load browser scan findings if available
	browserPath := filepath.Join(workspaceDir, "browser-scan.json")
	if browserData, err := os.ReadFile(browserPath); err == nil {
		var browserScan map[string]interface{}
		if err := json.Unmarshal(browserData, &browserScan); err == nil {
			report.BrowserFindings = parseBrowserFindings(browserScan)
		}
	}

	// Generate HTML
	generator, err := NewEnterpriseHTMLGenerator()
	if err != nil {
		return fmt.Errorf("failed to create generator: %w", err)
	}

	return generator.GenerateToFile(report, outputPath)
}

// parseBrowserFindings converts browser-scan.json data into report format
func parseBrowserFindings(data map[string]interface{}) *BrowserScanFindings {
	findings := &BrowserScanFindings{}

	// Auth status
	if v, ok := data["auth_successful"].(bool); ok {
		findings.AuthSuccessful = v
	}

	// Scan duration
	if v, ok := data["scan_duration"].(string); ok {
		findings.ScanDuration = v
	} else if v, ok := data["scan_duration"].(float64); ok {
		findings.ScanDuration = fmt.Sprintf("%.2fs", v/1000000000) // nanoseconds to seconds
	}

	// Auth flow info
	if authFlow, ok := data["auth_flow_info"].(map[string]interface{}); ok {
		if v, ok := authFlow["provider"].(string); ok {
			findings.AuthProvider = v
		}
		if v, ok := authFlow["flow_type"].(string); ok {
			findings.AuthFlowType = v
		}
	}

	// Discovered routes
	if routes, ok := data["discovered_routes"].([]interface{}); ok {
		for _, r := range routes {
			if route, ok := r.(map[string]interface{}); ok {
				br := BrowserRoute{}
				if v, ok := route["path"].(string); ok {
					br.Path = v
				}
				if v, ok := route["requires_auth"].(bool); ok {
					br.RequiresAuth = v
				}
				if v, ok := route["page_title"].(string); ok {
					br.PageTitle = v
				}
				if v, ok := route["category"].(string); ok {
					br.Category = v
				}
				findings.DiscoveredRoutes = append(findings.DiscoveredRoutes, br)
			}
		}
	}

	// Exposed tokens
	if tokens, ok := data["exposed_tokens"].([]interface{}); ok {
		for _, t := range tokens {
			if token, ok := t.(map[string]interface{}); ok {
				bt := BrowserExposedToken{}
				if v, ok := token["type"].(string); ok {
					bt.Type = v
				}
				if v, ok := token["location"].(string); ok {
					bt.Location = v
				}
				if v, ok := token["severity"].(string); ok {
					bt.Severity = v
				}
				if v, ok := token["risk"].(string); ok {
					bt.Risk = v
				}
				if v, ok := token["value"].(string); ok {
					bt.Value = v
				}
				findings.ExposedTokens = append(findings.ExposedTokens, bt)
			}
		}
	}

	// Third-party APIs
	if apis, ok := data["third_party_apis"].([]interface{}); ok {
		for _, a := range apis {
			if api, ok := a.(map[string]interface{}); ok {
				btp := BrowserThirdParty{}
				if v, ok := api["name"].(string); ok {
					btp.Name = v
				}
				if v, ok := api["request_type"].(string); ok {
					btp.RequestType = v
				}
				if v, ok := api["severity"].(string); ok {
					btp.Severity = v
				}
				findings.ThirdPartyAPIs = append(findings.ThirdPartyAPIs, btp)
			}
		}
	}

	// Risk summary
	if riskSummary, ok := data["risk_summary"].(map[string]interface{}); ok {
		findings.RiskSummary = &BrowserRiskSummary{}
		if v, ok := riskSummary["overall_risk"].(string); ok {
			findings.RiskSummary.OverallRisk = v
		}
		if v, ok := riskSummary["critical_count"].(float64); ok {
			findings.RiskSummary.CriticalCount = int(v)
		}
		if v, ok := riskSummary["high_count"].(float64); ok {
			findings.RiskSummary.HighCount = int(v)
		}
		if v, ok := riskSummary["medium_count"].(float64); ok {
			findings.RiskSummary.MediumCount = int(v)
		}
		if v, ok := riskSummary["low_count"].(float64); ok {
			findings.RiskSummary.LowCount = int(v)
		}
		if v, ok := riskSummary["total_findings"].(float64); ok {
			findings.RiskSummary.TotalFindings = int(v)
		}
		if topRisks, ok := riskSummary["top_risks"].([]interface{}); ok {
			for _, r := range topRisks {
				if risk, ok := r.(string); ok {
					findings.RiskSummary.TopRisks = append(findings.RiskSummary.TopRisks, risk)
				}
			}
		}
	}

	return findings
}
