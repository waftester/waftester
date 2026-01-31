package fp

import (
	"testing"
)

func TestNewLocalWAF(t *testing.T) {
	waf := NewLocalWAF(2)
	if waf == nil {
		t.Fatal("NewLocalWAF returned nil")
	}
	if waf.paranoiaLevel != 2 {
		t.Errorf("Expected paranoia level 2, got %d", waf.paranoiaLevel)
	}
}

func TestNewLocalWAFParanoiaClamp(t *testing.T) {
	// Test lower bound
	waf := NewLocalWAF(0)
	if waf.paranoiaLevel != 1 {
		t.Errorf("Paranoia level should clamp to 1, got %d", waf.paranoiaLevel)
	}

	// Test upper bound
	waf = NewLocalWAF(10)
	if waf.paranoiaLevel != 4 {
		t.Errorf("Paranoia level should clamp to 4, got %d", waf.paranoiaLevel)
	}
}

func TestLocalWAFTest(t *testing.T) {
	waf := NewLocalWAF(2)

	// Test benign payload (should not block)
	result := waf.Test("Hello, world!")
	if result.Blocked {
		t.Error("Benign payload should not be blocked")
	}

	// Test SQL injection payload (should block)
	result = waf.Test("' OR 1=1--")
	if !result.Blocked {
		t.Error("SQL injection payload should be blocked")
	}
	if len(result.MatchedRules) == 0 {
		t.Error("Should have matched at least one rule")
	}
}

func TestLocalWAFTestXSS(t *testing.T) {
	waf := NewLocalWAF(2)

	// Test XSS payload
	result := waf.Test("<script>alert(1)</script>")
	if !result.Blocked {
		t.Error("XSS payload should be blocked")
	}
}

func TestLocalWAFTestLFI(t *testing.T) {
	waf := NewLocalWAF(2)

	// Test LFI payload
	result := waf.Test("../../../etc/passwd")
	if !result.Blocked {
		t.Error("LFI payload should be blocked")
	}
}

func TestLocalWAFSetParanoiaLevel(t *testing.T) {
	waf := NewLocalWAF(1)

	waf.SetParanoiaLevel(3)
	if waf.paranoiaLevel != 3 {
		t.Errorf("Expected paranoia level 3, got %d", waf.paranoiaLevel)
	}

	// Invalid levels should be ignored
	waf.SetParanoiaLevel(0)
	if waf.paranoiaLevel != 3 {
		t.Error("Invalid paranoia level should be ignored")
	}
	waf.SetParanoiaLevel(5)
	if waf.paranoiaLevel != 3 {
		t.Error("Invalid paranoia level should be ignored")
	}
}

func TestLocalWAFGetRuleCount(t *testing.T) {
	waf := NewLocalWAF(1)
	countPL1 := waf.GetRuleCount()

	waf.SetParanoiaLevel(4)
	countPL4 := waf.GetRuleCount()

	if countPL4 < countPL1 {
		t.Error("Higher paranoia level should have >= rules than lower")
	}
	if countPL1 == 0 {
		t.Error("Should have at least some rules at PL1")
	}
}

func TestLocalWAFTestCorpus(t *testing.T) {
	waf := NewLocalWAF(2)

	stats := waf.TestCorpus(false)
	if stats == nil {
		t.Fatal("TestCorpus returned nil")
	}

	// Should have stats for paranoia level 2
	if _, ok := stats[2]; !ok {
		t.Error("Should have stats for paranoia level 2")
	}

	pl2Stats := stats[2]
	if pl2Stats.TotalTests == 0 {
		t.Error("Should have tested some payloads")
	}
}

func TestRunLocalFPTest(t *testing.T) {
	corpus := NewCorpus()
	corpus.Load([]string{"leipzig"})

	results := RunLocalFPTest(corpus, []int{1, 2, 3, 4})

	if len(results) != 4 {
		t.Errorf("Expected results for 4 paranoia levels, got %d", len(results))
	}

	for pl := 1; pl <= 4; pl++ {
		if _, ok := results[pl]; !ok {
			t.Errorf("Missing results for paranoia level %d", pl)
		}
	}
}

func TestFormatLocalFPReport(t *testing.T) {
	corpus := NewCorpus()
	corpus.Load([]string{"leipzig"})

	stats := RunLocalFPTest(corpus, []int{2})
	report := FormatLocalFPReport(stats)

	if report == "" {
		t.Error("Report should not be empty")
	}
	if len(report) < 100 {
		t.Error("Report seems too short")
	}
}

func TestNewLocalFPStats(t *testing.T) {
	stats := NewLocalFPStats()
	if stats == nil {
		t.Fatal("NewLocalFPStats returned nil")
	}
	if stats.ByRule == nil {
		t.Error("ByRule map should not be nil")
	}
	if stats.ByParanoiaLevel == nil {
		t.Error("ByParanoiaLevel map should not be nil")
	}
	if stats.ByCategory == nil {
		t.Error("ByCategory map should not be nil")
	}
}

func TestLocalTestResultStruct(t *testing.T) {
	result := &LocalTestResult{
		Blocked:       true,
		MatchedRules:  []int{942100, 942110},
		RuleMessages:  []string{"SQL Injection", "SQL Injection"},
		ParanoiaLevel: 2,
	}

	if !result.Blocked {
		t.Error("Expected blocked to be true")
	}
	if len(result.MatchedRules) != 2 {
		t.Errorf("Expected 2 matched rules, got %d", len(result.MatchedRules))
	}
}
