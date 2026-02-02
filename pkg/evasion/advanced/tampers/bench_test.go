package tampers

import (
	"testing"
)

// Benchmark payload transformation performance

var benchPayload = "SELECT * FROM users WHERE id=1 AND name='admin' OR role='root' UNION SELECT * FROM passwords"

func BenchmarkSpace2Comment(b *testing.B) {
	tamper := Get("space2comment")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkRandomCase(b *testing.B) {
	tamper := Get("randomcase")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkHalfVersionedMoreKeywords(b *testing.B) {
	tamper := Get("halfversionedmorekeywords")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkMSSQLBlind(b *testing.B) {
	tamper := Get("mssqlblind")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkRandomComments(b *testing.B) {
	tamper := Get("randomcomments")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

// Encoding tampers - now optimized with lookup tables
func BenchmarkCharEncode(b *testing.B) {
	tamper := Get("charencode")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkCharDoubleEncode(b *testing.B) {
	tamper := Get("chardoubleencode")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkDecEntities(b *testing.B) {
	tamper := Get("decentities")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkHexEntities(b *testing.B) {
	tamper := Get("hexentities")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkOverlongUTF8(b *testing.B) {
	tamper := Get("overlongutf8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(benchPayload)
	}
}

func BenchmarkHTMLEncode(b *testing.B) {
	tamper := Get("htmlencode")
	payload := "<script>alert('XSS')</script>&test=\"value\""
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tamper.Transform(payload)
	}
}

func BenchmarkChain3Tampers(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Chain(benchPayload, "space2comment", "randomcase", "base64encode")
	}
}

func BenchmarkChain5Tampers(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Chain(benchPayload, "space2comment", "randomcase", "base64encode", "uppercase", "charencode")
	}
}

func BenchmarkChainByPriority5Tampers(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ChainByPriority(benchPayload, "space2comment", "randomcase", "base64encode", "uppercase", "charencode")
	}
}

func BenchmarkGet(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Get("space2comment")
	}
}

func BenchmarkGetMultiple(b *testing.B) {
	names := []string{"space2comment", "randomcase", "base64encode", "uppercase", "charencode"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetMultiple(names...)
	}
}

// Compare 5x Get vs 1x GetMultiple
func BenchmarkGet5Times(b *testing.B) {
	names := []string{"space2comment", "randomcase", "base64encode", "uppercase", "charencode"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, n := range names {
			_ = Get(n)
		}
	}
}
