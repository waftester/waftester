package duration

import (
	"fmt"
	"time"
)

// FormatPrecision formats a duration with precision appropriate to its magnitude:
// microseconds for < 1ms, milliseconds for < 1s, seconds with 2 decimal places otherwise.
// This is the canonical formatter for response-time display (e.g. "500µs", "150ms", "2.50s").
func FormatPrecision(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// FormatClock formats a duration as a clock-style string: MM:SS or HH:MM:SS.
// This is the canonical formatter for progress-bar elapsed/ETA display.
// Negative durations are clamped to zero.
func FormatClock(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%02d:%02d", m, s)
}

// FormatCompact formats a duration compactly: "1.5s" for < 1min, "2m30s" otherwise.
// This is the canonical formatter for inline elapsed-time display.
// Negative durations are clamped to zero.
func FormatCompact(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%ds", mins, secs)
}

// FormatSeconds formats a float64 number of seconds into a human-readable duration string:
// "5.3s" for < 60s, "2m 5s" for < 1h, "1h 2m 3s" otherwise.
// This is the canonical formatter for report/PDF duration display where the input is seconds.
func FormatSeconds(secs float64) string {
	if secs < 60 {
		return fmt.Sprintf("%.1fs", secs)
	}
	m := int(secs) / 60
	s := int(secs) % 60
	if m < 60 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := m / 60
	m = m % 60
	return fmt.Sprintf("%dh %dm %ds", h, m, s)
}
