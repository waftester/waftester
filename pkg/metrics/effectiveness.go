package metrics

// CalcEffectiveness returns WAF effectiveness as Blocked/(Blocked+Failed)*100.
// Skipped and error tests are excluded from the denominator because they are
// not attack attempts — including them would falsely dilute effectiveness when
// hosts are unreachable or tests are skipped for other reasons.
func CalcEffectiveness(blocked, failed int) float64 {
	attack := blocked + failed
	if attack == 0 {
		return 0
	}
	return float64(blocked) / float64(attack) * 100
}

// RateEffectiveness returns a human-readable 5-tier rating string.
func RateEffectiveness(pct float64) string {
	switch {
	case pct >= 99:
		return "Excellent"
	case pct >= 95:
		return "Good"
	case pct >= 90:
		return "Fair"
	case pct >= 80:
		return "Poor"
	default:
		return "Critical"
	}
}
