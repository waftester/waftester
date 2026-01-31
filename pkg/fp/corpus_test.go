package fp

import (
	"testing"
)

func TestNewCorpus(t *testing.T) {
	corpus := NewCorpus()
	if corpus == nil {
		t.Fatal("NewCorpus returned nil")
	}
	if corpus.sources == nil {
		t.Error("Corpus sources map should not be nil")
	}
}

func TestCorpusLoad(t *testing.T) {
	corpus := NewCorpus()

	err := corpus.Load([]string{"leipzig", "edgecases", "forms"})
	if err != nil {
		t.Errorf("Unexpected error loading corpus: %v", err)
	}

	// Verify sources were loaded
	if len(corpus.Get("leipzig")) == 0 {
		t.Error("Leipzig corpus should have payloads")
	}
	if len(corpus.Get("edgecases")) == 0 {
		t.Error("EdgeCases corpus should have payloads")
	}
	if len(corpus.Get("forms")) == 0 {
		t.Error("Forms corpus should have payloads")
	}
}

func TestCorpusAll(t *testing.T) {
	corpus := NewCorpus()
	corpus.Load([]string{"leipzig", "forms"})

	all := corpus.All()
	if len(all) == 0 {
		t.Error("All() should return payloads after loading")
	}

	leipzigCount := len(corpus.Get("leipzig"))
	formsCount := len(corpus.Get("forms"))
	expectedTotal := leipzigCount + formsCount

	if len(all) != expectedTotal {
		t.Errorf("Expected %d total payloads, got %d", expectedTotal, len(all))
	}
}

func TestCorpusCount(t *testing.T) {
	corpus := NewCorpus()

	// Empty corpus
	if corpus.Count() != 0 {
		t.Error("Empty corpus should have count 0")
	}

	corpus.Load([]string{"leipzig"})
	if corpus.Count() == 0 {
		t.Error("Loaded corpus should have count > 0")
	}
}

func TestCorpusAddDynamicCorpus(t *testing.T) {
	corpus := NewCorpus()

	dynamicPayloads := []string{
		"custom payload 1",
		"custom payload 2",
		"custom payload 3",
	}

	corpus.AddDynamicCorpus(dynamicPayloads)

	dynamic := corpus.Get("dynamic")
	if len(dynamic) != 3 {
		t.Errorf("Expected 3 dynamic payloads, got %d", len(dynamic))
	}
}

func TestGetLeipzigCorpus(t *testing.T) {
	payloads := getLeipzigCorpus()
	if len(payloads) == 0 {
		t.Error("Leipzig corpus should not be empty")
	}

	// Check some expected content
	hasBusinessContent := false
	for _, p := range payloads {
		if len(p) > 10 { // Should have reasonable length sentences
			hasBusinessContent = true
			break
		}
	}
	if !hasBusinessContent {
		t.Error("Leipzig corpus should contain meaningful sentences")
	}
}

func TestGetEdgeCases(t *testing.T) {
	payloads := getEdgeCases()
	if len(payloads) == 0 {
		t.Error("Edge cases corpus should not be empty")
	}
}

func TestGetFormData(t *testing.T) {
	payloads := getFormData()
	if len(payloads) == 0 {
		t.Error("Form data corpus should not be empty")
	}
}

func TestGetAPIPayloads(t *testing.T) {
	payloads := getAPIPayloads()
	if len(payloads) == 0 {
		t.Error("API payloads corpus should not be empty")
	}
}

func TestGetTechnicalContent(t *testing.T) {
	payloads := getTechnicalContent()
	if len(payloads) == 0 {
		t.Error("Technical content corpus should not be empty")
	}
}

func TestGetInternationalNames(t *testing.T) {
	payloads := getInternationalNames()
	if len(payloads) == 0 {
		t.Error("International names corpus should not be empty")
	}
}

func TestCorpusGetNonExistent(t *testing.T) {
	corpus := NewCorpus()
	result := corpus.Get("nonexistent")
	if result != nil {
		t.Error("Getting non-existent source should return nil")
	}
}
