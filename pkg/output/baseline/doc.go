// Package baseline provides a baseline comparison engine for tracking WAF bypass
// regressions across scan runs.
//
// The baseline engine supports CI/CD workflows where you want to:
//   - Fail only on NEW bypasses (not existing known issues)
//   - Track when bypasses get fixed
//   - Update baseline on main branch merges
//
// # Baseline File Format
//
// Baseline files are JSON documents that record known bypasses from a reference scan:
//
//	{
//	  "version": "1.0",
//	  "created_at": "2026-01-15T10:30:00Z",
//	  "updated_at": "2026-01-20T14:45:00Z",
//	  "scan_id": "scan-abc123",
//	  "target": "https://example.com",
//	  "bypasses": [
//	    {
//	      "id": "sqli-001",
//	      "category": "sqli",
//	      "severity": "critical",
//	      "payload_hash": "sha256:abc123...",
//	      "target_path": "/api/users",
//	      "first_seen": "2026-01-15T10:30:00Z"
//	    }
//	  ],
//	  "summary": {
//	    "total_bypasses": 15,
//	    "effectiveness": 85.0
//	  }
//	}
//
// # Bypass Identity
//
// Bypasses are identified by their payload hash (SHA256), not just the test ID.
// This ensures that:
//   - Same payload is tracked consistently across runs
//   - Different payloads for the same test are tracked separately
//   - Renamed tests don't break baseline tracking
//
// # Usage
//
// Loading an existing baseline:
//
//	baseline, err := baseline.LoadBaseline("baseline.json")
//	if errors.Is(err, baseline.ErrBaselineNotFound) {
//	    // First run - no baseline exists yet
//	    baseline = baseline.New()
//	}
//
// Creating a baseline from scan results:
//
//	results := []*events.ResultEvent{...}
//	baseline := baseline.CreateFromResults(results, "scan-123", "https://example.com")
//	if err := baseline.SaveBaseline("baseline.json"); err != nil {
//	    return err
//	}
//
// Comparing current scan against baseline:
//
//	currentBypasses := baseline.ExtractBypasses(results)
//	comparison := baseline.Compare(currentBypasses)
//
//	if comparison.HasNewBypasses {
//	    fmt.Printf("Found %d new bypasses!\n", len(comparison.NewBypasses))
//	    os.Exit(1)
//	}
//
//	if len(comparison.FixedBypasses) > 0 {
//	    fmt.Printf("Good news: %d bypasses were fixed!\n", len(comparison.FixedBypasses))
//	}
//
// # Thread Safety
//
// All Baseline methods are safe for concurrent use. The baseline maintains
// internal synchronization for all read and write operations.
package baseline
