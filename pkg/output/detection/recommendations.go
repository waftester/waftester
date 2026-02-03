package detection

// Recommendations returns actionable advice based on detection stats.
// Returns an empty slice if no recommendations are applicable.
func (s Stats) Recommendations() []string {
	var recs []string

	if s.DropsDetected > 0 {
		if s.DropsDetected >= 10 {
			recs = append(recs, "High drop rate detected. Consider reducing concurrency with -c 10")
		} else {
			recs = append(recs, "Connection drops detected. Try reducing rate with -rate 50")
		}
	}

	if s.BansDetected > 0 {
		if s.BansDetected >= 5 {
			recs = append(recs, "Multiple silent bans detected. Target is actively blocking. Use -rate 25 and -delay 500ms")
		} else {
			recs = append(recs, "Silent ban detected. Target may be rate-limiting. Try -rate 50")
		}
	}

	if s.HostsSkipped > 0 {
		if s.HostsSkipped >= 3 {
			recs = append(recs, "Multiple hosts skipped. Check network connectivity or use --no-detect to bypass detection")
		} else {
			recs = append(recs, "Host skipped due to detection. Verify target is accessible")
		}
	}

	return recs
}
