package duration

import (
	"math"
	"testing"
	"time"
)

func TestFormatPrecision(t *testing.T) {
	tests := []struct {
		name     string
		dur      time.Duration
		expected string
	}{
		{"negative_clamped", -5 * time.Second, "0µs"},
		{"zero", 0, "0µs"},
		{"microseconds", 500 * time.Microsecond, "500µs"},
		{"milliseconds", 250 * time.Millisecond, "250ms"},
		{"seconds", 2500 * time.Millisecond, "2.50s"},
		{"large_seconds", 150 * time.Millisecond, "150ms"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatPrecision(tt.dur)
			if result != tt.expected {
				t.Errorf("FormatPrecision(%v) = %q, want %q", tt.dur, result, tt.expected)
			}
		})
	}
}

func TestFormatClock(t *testing.T) {
	tests := []struct {
		name     string
		dur      time.Duration
		expected string
	}{
		{"zero", 0, "00:00"},
		{"negative_clamped", -5 * time.Second, "00:00"},
		{"thirty_seconds", 30 * time.Second, "00:30"},
		{"ninety_seconds", 90 * time.Second, "01:30"},
		{"one_hour", 60 * time.Minute, "01:00:00"},
		{"one_hour_one_min", 61 * time.Minute, "01:01:00"},
		{"ninety_minutes", 90 * time.Minute, "01:30:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatClock(tt.dur)
			if result != tt.expected {
				t.Errorf("FormatClock(%v) = %q, want %q", tt.dur, result, tt.expected)
			}
		})
	}
}

func TestFormatCompact(t *testing.T) {
	tests := []struct {
		name     string
		dur      time.Duration
		expected string
	}{
		{"negative_clamped", -90 * time.Second, "0.0s"},
		{"sub_minute", 30500 * time.Millisecond, "30.5s"},
		{"exact_minute", 60 * time.Second, "1m0s"},
		{"mixed", 150 * time.Second, "2m30s"},
		{"zero", 0, "0.0s"},
		{"sub_second", 500 * time.Millisecond, "0.5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatCompact(tt.dur)
			if result != tt.expected {
				t.Errorf("FormatCompact(%v) = %q, want %q", tt.dur, result, tt.expected)
			}
		})
	}
}

func TestFormatSeconds(t *testing.T) {
	tests := []struct {
		name     string
		seconds  float64
		expected string
	}{
		{"negative_clamped", -5.0, "0.0s"},
		{"nan_clamped", math.NaN(), "0.0s"},
		{"inf_clamped", math.Inf(1), "0.0s"},
		{"zero", 0, "0.0s"},
		{"short", 5.3, "5.3s"},
		{"just_under_minute", 59.9, "59.9s"},
		{"one_minute", 60, "1m 0s"},
		{"two_minutes_five", 125, "2m 5s"},
		{"one_hour", 3600, "1h 0m 0s"},
		{"mixed", 3723, "1h 2m 3s"},
		{"large", 7325, "2h 2m 5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSeconds(tt.seconds)
			if result != tt.expected {
				t.Errorf("FormatSeconds(%v) = %q, want %q", tt.seconds, result, tt.expected)
			}
		})
	}
}
