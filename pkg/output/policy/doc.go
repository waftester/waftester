// Package policy provides a policy engine for evaluating scan results against
// user-defined rules to determine CI/CD pass/fail outcomes.
//
// The policy engine parses YAML policy files that define conditions under which
// a scan should be considered a failure. This enables security teams to set
// custom quality gates based on:
//   - Bypass thresholds (total, by severity)
//   - Category-specific bypass detection
//   - WAF effectiveness percentages
//   - Error rate thresholds
//
// # Policy File Format
//
// Policy files are YAML documents with the following structure:
//
//	version: "1.0"
//	name: "production-gate"
//
//	fail_on:
//	  bypasses:
//	    total: 5           # Fail if more than 5 total bypasses
//	    critical: 1        # Fail if any critical bypasses
//	    high: 3            # Fail if more than 3 high severity
//	  categories:
//	    - sqli             # Fail on any SQL injection bypass
//	    - rce              # Fail on any RCE bypass
//	  effectiveness_below: 95.0  # Fail if WAF effectiveness below 95%
//	  error_rate_above: 10.0     # Fail if error rate above 10%
//
//	ignore:
//	  test_ids:
//	    - "test-123"       # Ignore specific test IDs
//	  categories:
//	    - "informational"  # Ignore informational category
//
// # Usage
//
//	policy, err := policy.LoadPolicy("policy.yaml")
//	if err != nil {
//	    return err
//	}
//
//	summary := policy.SummaryData{
//	    TotalBypasses:  10,
//	    BypassesBySeverity: map[string]int{"critical": 2, "high": 5},
//	    // ... other fields
//	}
//
//	result := policy.Evaluate(summary)
//	if !result.Pass {
//	    fmt.Printf("Policy failed: %v\n", result.Failures)
//	    os.Exit(result.ExitCode)
//	}
//
// # Thread Safety
//
// Policy evaluation is thread-safe. A single Policy instance can be used
// concurrently from multiple goroutines.
package policy
