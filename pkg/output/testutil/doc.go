// Package testutil provides reusable test helpers for output writer testing.
//
// This package contains assertion functions, comparison utilities, and
// test scaffolding that ensure consistent testing patterns across all
// output writers.
//
// Usage:
//
//	testutil.AssertJSONEqual(t, expected, actual)
//	testutil.AssertFileContains(t, path, []string{"header", "data"})
//	testutil.WithTempFile(t, func(path string) { ... })
//
// Patterns:
//
//	Golden file comparison - CompareWithGolden()
//	Format validation     - ValidateJSON(), ValidateSARIF(), ValidateHTML()
//	Temp file handling    - WithTempFile(), WithTempDir()
//	Writer scaffolding    - NewWriterTest(), RunWriterTest()
package testutil
