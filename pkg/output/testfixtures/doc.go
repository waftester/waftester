// Package testfixtures provides shared test data for output writer testing.
//
// This package contains golden files, sample test results, and fixture generators
// that ensure consistent testing across all output writers. All test data is
// centralized here to maintain single source of truth.
//
// Usage:
//
//	fixtures := testfixtures.LoadGoldenFiles(t)
//	results := testfixtures.MakeSampleResults(10)
//
// Golden Files:
//
//	golden/        - Expected output files for comparison
//	  json/        - JSON format golden files
//	  sarif/       - SARIF format golden files
//	  html/        - HTML format golden files
//	  markdown/    - Markdown format golden files
//	  csv/         - CSV format golden files
//
// Fixture Generators:
//
//	MakeSampleResults     - Generate n sample test results
//	MakeRealisticScan     - Generate realistic scan scenario
//	MakeBypassScenario    - Generate bypass test scenario
//	MakeAssessmentData    - Generate assessment metrics
package testfixtures
