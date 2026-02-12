package fp

import "testing"

func TestSimhash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		text     string
		wantZero bool // expect zero fingerprint (empty input)
	}{
		{
			name:     "empty input no panic",
			text:     "",
			wantZero: true,
		},
		{
			name:     "non-empty produces non-zero",
			text:     "This is a WAF block page with some content",
			wantZero: false,
		},
		{
			name:     "single word",
			text:     "blocked",
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Simhash(tt.text)
			if tt.wantZero && got != 0 {
				t.Errorf("Simhash(%q) = %d, want 0", tt.text, got)
			}
			if !tt.wantZero && got == 0 {
				t.Errorf("Simhash(%q) = 0, want non-zero", tt.text)
			}
		})
	}
}

func TestSimhash_IdenticalPages(t *testing.T) {
	t.Parallel()
	page := "403 Forbidden. Your request has been blocked by the WAF."
	h1 := Simhash(page)
	h2 := Simhash(page)
	if h1 != h2 {
		t.Errorf("identical pages should produce same hash: %d != %d", h1, h2)
	}
	if HammingDistance(h1, h2) != 0 {
		t.Errorf("identical pages should have distance 0, got %d", HammingDistance(h1, h2))
	}
}

func TestSimhash_SimilarPages(t *testing.T) {
	t.Parallel()
	// Dynamic block page with small variation
	page1 := "403 Forbidden. Your request has been blocked by the WAF. Request ID: abc123"
	page2 := "403 Forbidden. Your request has been blocked by the WAF. Request ID: xyz789"
	dist := HammingDistance(Simhash(page1), Simhash(page2))
	if dist > 10 {
		t.Errorf("similar pages should have distance <= 10, got %d", dist)
	}
}

func TestSimhash_DifferentPages(t *testing.T) {
	t.Parallel()
	blockPage := "403 Forbidden. Your request has been blocked by the WAF."
	passPage := "<html><body><h1>Welcome to the admin panel</h1><p>User dashboard with sensitive data</p></body></html>"
	dist := HammingDistance(Simhash(blockPage), Simhash(passPage))
	if dist <= 5 {
		t.Errorf("different pages should have distance > 5, got %d", dist)
	}
}

func TestHammingDistance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b uint64
		want int
	}{
		{"identical", 0xFF, 0xFF, 0},
		{"all different", 0, 0xFFFFFFFFFFFFFFFF, 64},
		{"one bit", 0, 1, 1},
		{"two bits", 0, 3, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := HammingDistance(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("HammingDistance(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
