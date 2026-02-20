package report

import (
	"fmt"
	"strings"
	"time"
)

// GenerateCurlCommand creates a curl reproduction command for a bypass finding
func GenerateCurlCommand(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	// Escape payload for shell
	escapedPayload := strings.ReplaceAll(finding.Payload, "'", "'\\''")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\n", "\\n")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\r", "\\r")

	method := finding.Method
	if method == "" {
		method = "GET"
	}

	// Escape single quotes in the endpoint URL for safe shell embedding
	escapedEndpoint := strings.ReplaceAll(finding.Endpoint, "'", "'\\''")

	var cmd strings.Builder
	cmd.WriteString("curl -X ")
	cmd.WriteString(method)
	cmd.WriteString(" '")
	cmd.WriteString(escapedEndpoint)
	cmd.WriteString("'")

	// Add payload as appropriate for method
	if method == "POST" || method == "PUT" || method == "PATCH" {
		cmd.WriteString(" \\\n  -d '")
		cmd.WriteString(escapedPayload)
		cmd.WriteString("'")
	} else if len(escapedPayload) < 200 && !strings.Contains(escapedPayload, "\n") {
		// For GET requests with short payloads, show as comment
		cmd.WriteString(" \\\n  # Payload: ")
		cmd.WriteString(escapedPayload)
	}

	cmd.WriteString(" \\\n  -H 'User-Agent: SecurityTester/1.0'")
	cmd.WriteString(" \\\n  -i -k")

	return cmd.String()
}

// EnrichBypassFinding adds enterprise details to a bypass finding
func EnrichBypassFinding(finding *BypassFinding) {
	if finding == nil {
		return
	}

	vulnInfo := GetVulnerabilityInfo(finding.Category)

	// Basic fields
	if finding.Description == "" {
		finding.Description = vulnInfo.Description
	}
	if finding.Impact == "" {
		finding.Impact = vulnInfo.Impact
	}
	if finding.CWE == "" {
		finding.CWE = vulnInfo.CWE
		finding.CWEURL = vulnInfo.CWEURL
	}
	if finding.OWASPCategory == "" {
		finding.OWASPCategory = vulnInfo.OWASPCategory
		finding.OWASPURL = vulnInfo.OWASPURL
	}
	if finding.Remediation == "" {
		finding.Remediation = vulnInfo.Remediation
	}
	if finding.RiskScore == 0 {
		finding.RiskScore = vulnInfo.RiskScore
	}
	if len(finding.References) == 0 {
		finding.References = vulnInfo.References
	}

	// NEW: Nuclei-style CVSS fields
	if finding.CVSSVector == "" && vulnInfo.CVSSVector != "" {
		finding.CVSSVector = vulnInfo.CVSSVector
	}
	if finding.CVSSScore == 0 && vulnInfo.CVSSScore > 0 {
		finding.CVSSScore = vulnInfo.CVSSScore
	}
	if finding.Timestamp == "" {
		finding.Timestamp = time.Now().Format("2006-01-02T15:04:05-07:00")
	}

	// NEW: Nuclei-style EPSS fields
	if finding.EPSSScore == 0 && vulnInfo.EPSSScore > 0 {
		finding.EPSSScore = vulnInfo.EPSSScore
	}
	if finding.EPSSPercentile == 0 && vulnInfo.EPSSPercentile > 0 {
		finding.EPSSPercentile = vulnInfo.EPSSPercentile
	}
	if finding.CPE == "" && vulnInfo.CPE != "" {
		finding.CPE = vulnInfo.CPE
	}

	// NEW: ZAP-style Solution and OtherInfo fields
	if finding.Solution == "" && vulnInfo.Solution != "" {
		finding.Solution = vulnInfo.Solution
	}
	if finding.OtherInfo == "" && vulnInfo.OtherInfo != "" {
		finding.OtherInfo = vulnInfo.OtherInfo
	}
	// Set Confidence default BEFORE computing RiskConfidence,
	// otherwise RiskConfidence would show "critical ()" instead of "critical (High)".
	if finding.Confidence == "" {
		// Default confidence based on bypass success
		finding.Confidence = "High"
	}
	if finding.RiskConfidence == "" {
		// Generate ZAP-style "High (Medium)" format
		finding.RiskConfidence = fmt.Sprintf("%s (%s)", finding.Severity, finding.Confidence)
	}

	// NEW: ZAP-style WASC fields
	if finding.WASCID == "" && vulnInfo.WASCID != "" {
		finding.WASCID = vulnInfo.WASCID
		finding.WASCURL = vulnInfo.WASCURL
	}
	if finding.InputVector == "" {
		// Detect input vector from payload/endpoint
		finding.InputVector = detectInputVector(finding)
	}
	if finding.Attack == "" {
		finding.Attack = finding.Payload
	}
	if finding.BypassTechnique == "" && len(vulnInfo.BypassTechniques) > 0 {
		finding.BypassTechnique = detectBypassTechnique(finding.Payload, vulnInfo.BypassTechniques)
	}

	// NEW: Compliance mapping
	if finding.PCIDSS == "" && vulnInfo.PCIDSS != "" {
		finding.PCIDSS = vulnInfo.PCIDSS
	}

	// NEW: ModSecurity rules
	if finding.ExpectedRule == "" && vulnInfo.ModSecRuleID != "" {
		finding.ExpectedRule = vulnInfo.ModSecRuleID
	}
	if finding.SuggestedRule == "" && vulnInfo.SuggestedRule != "" {
		finding.SuggestedRule = vulnInfo.SuggestedRule
	}

	// NEW: Detection metadata from vulnerability database
	if finding.InstanceCount == 0 {
		finding.InstanceCount = 1 // Default to 1 instance
	}

	// Generate reproduction commands
	if finding.CurlCommand == "" {
		finding.CurlCommand = GenerateCurlCommand(finding)
	}
	if finding.PowerShellCmd == "" {
		finding.PowerShellCmd = GeneratePowerShellCommand(finding)
	}
	if finding.PythonCode == "" {
		finding.PythonCode = GeneratePythonCode(finding)
	}
}

// detectInputVector determines where the attack was injected
func detectInputVector(finding *BypassFinding) string {
	payload := strings.ToLower(finding.Payload)
	endpoint := strings.ToLower(finding.Endpoint)

	if strings.Contains(payload, "cookie:") || strings.Contains(payload, "set-cookie") {
		return "Cookie"
	}
	if strings.Contains(payload, "referer:") || strings.Contains(payload, "x-forwarded") {
		return "Header"
	}
	if finding.Method == "POST" || finding.Method == "PUT" || finding.Method == "PATCH" {
		return "Request Body"
	}
	if strings.Contains(endpoint, "?") || strings.Contains(endpoint, "&") {
		return "Query Parameter"
	}
	return "URL Path"
}

// detectBypassTechnique identifies the evasion technique used
func detectBypassTechnique(payload string, techniques []string) string {
	payloadLower := strings.ToLower(payload)

	if strings.Contains(payload, "%00") || strings.Contains(payloadLower, "\\x00") {
		return "Null Byte Injection"
	}
	if strings.Contains(payload, "%25") || strings.Contains(payload, "%252") {
		return "Double URL Encoding"
	}
	if strings.Contains(payload, "\\u") || strings.Contains(payload, "%u") {
		return "Unicode Encoding"
	}
	// "/*" is a reliable C-style/SQL comment marker.
	// "-- " (trailing space) is SQL line comment per spec.
	// "#" only counts when preceded by SQL keywords to avoid false positives
	// on URL fragments and CSS selectors.
	isCommentHash := strings.Contains(payload, "#") &&
		(strings.Contains(payloadLower, "or#") || strings.Contains(payloadLower, "and#") || strings.Contains(payloadLower, "union#"))
	if strings.Contains(payload, "/*") || strings.Contains(payload, "-- ") || isCommentHash {
		return "Comment Insertion"
	}
	// Detect intentional alternating case (e.g., "SeLeCt", "uNiOn") by counting
	// case transitions between adjacent alpha characters. Normal mixed case like
	// "JavaScript" has few transitions; deliberate randomization has many.
	caseChanges := 0
	for i := 1; i < len(payload); i++ {
		curr, prev := payload[i], payload[i-1]
		if (curr >= 'a' && curr <= 'z' && prev >= 'A' && prev <= 'Z') ||
			(curr >= 'A' && curr <= 'Z' && prev >= 'a' && prev <= 'z') {
			caseChanges++
		}
	}
	if caseChanges >= 3 {
		return "Case Variation"
	}
	if strings.Contains(payload, "\t") || strings.Contains(payload, "  ") {
		return "Whitespace Manipulation"
	}
	if len(techniques) > 0 {
		return techniques[0] // Return first technique as fallback
	}
	return "Unknown Technique"
}

// GeneratePowerShellCommand creates a PowerShell reproduction command
func GeneratePowerShellCommand(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	escapedPayload := strings.ReplaceAll(finding.Payload, "'", "''")
	escapedPayload = strings.ReplaceAll(escapedPayload, "`", "``")

	method := finding.Method
	if method == "" {
		method = "GET"
	}

	var cmd strings.Builder
	cmd.WriteString("Invoke-WebRequest -Uri '")
	// Escape single quotes for PowerShell (double them)
	escapedEndpoint := strings.ReplaceAll(finding.Endpoint, "'", "''")
	cmd.WriteString(escapedEndpoint)
	cmd.WriteString("' -Method ")
	cmd.WriteString(method)

	if method == "POST" || method == "PUT" || method == "PATCH" {
		cmd.WriteString(" -Body '")
		cmd.WriteString(escapedPayload)
		cmd.WriteString("'")
	}

	cmd.WriteString(" -Headers @{'User-Agent'='SecurityTester/1.0'}")
	cmd.WriteString(" -SkipCertificateCheck")

	return cmd.String()
}

// GeneratePythonCode creates Python reproduction code
func GeneratePythonCode(finding *BypassFinding) string {
	if finding.Endpoint == "" {
		return ""
	}

	escapedPayload := strings.ReplaceAll(finding.Payload, "\"", "\\\"")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\n", "\\n")
	escapedPayload = strings.ReplaceAll(escapedPayload, "\r", "\\r")

	method := strings.ToLower(finding.Method)
	if method == "" {
		method = "get"
	}

	// Escape backslashes and double quotes in the endpoint URL for safe Python string embedding
	escapedEndpoint := strings.ReplaceAll(finding.Endpoint, "\\", "\\\\")
	escapedEndpoint = strings.ReplaceAll(escapedEndpoint, "\"", "\\\"")

	var code strings.Builder
	code.WriteString("import requests\n\n")
	code.WriteString("url = \"")
	code.WriteString(escapedEndpoint)
	code.WriteString("\"\n")
	code.WriteString("payload = \"")
	code.WriteString(escapedPayload)
	code.WriteString("\"\n")
	code.WriteString("headers = {'User-Agent': 'SecurityTester/1.0'}\n\n")

	if method == "post" || method == "put" || method == "patch" {
		code.WriteString("response = requests.")
		code.WriteString(method)
		code.WriteString("(url, data=payload, headers=headers, verify=False)\n")
	} else {
		code.WriteString("# Payload: ")
		code.WriteString(escapedPayload)
		code.WriteString("\nresponse = requests.")
		code.WriteString(method)
		code.WriteString("(url, headers=headers, verify=False)\n")
	}

	code.WriteString("print(f'Status: {response.status_code}')\n")
	code.WriteString("print(response.text[:500])")

	return code.String()
}
