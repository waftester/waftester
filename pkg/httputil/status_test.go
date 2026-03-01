package httputil

import "testing"

func TestIsSuccess(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{199, false},
		{200, true},
		{201, true},
		{204, true},
		{250, true},
		{299, true},
		{300, false},
		{301, false},
		{400, false},
		{403, false},
		{404, false},
		{500, false},
		{0, false},
		{-1, false},
	}
	for _, tt := range tests {
		if got := IsSuccess(tt.code); got != tt.want {
			t.Errorf("IsSuccess(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}

func TestIsSuccessOrRedirect(t *testing.T) {
	tests := []struct {
		code int
		want bool
	}{
		{199, false},
		{200, true},
		{201, true},
		{204, true},
		{250, true},
		{299, true},
		{300, true},
		{301, true},
		{302, true},
		{307, true},
		{399, true},
		{400, false},
		{403, false},
		{404, false},
		{500, false},
		{0, false},
		{-1, false},
	}
	for _, tt := range tests {
		if got := IsSuccessOrRedirect(tt.code); got != tt.want {
			t.Errorf("IsSuccessOrRedirect(%d) = %v, want %v", tt.code, got, tt.want)
		}
	}
}
