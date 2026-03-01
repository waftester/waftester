package presets

import (
	"testing"
)

func TestNames_Sorted(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Skip("no presets registered")
	}
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("Names() not sorted: %q before %q at index %d", names[i-1], names[i], i)
		}
	}
}
