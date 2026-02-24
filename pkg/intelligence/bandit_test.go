package intelligence

import (
	"math"
	"math/rand"
	"sync"
	"testing"
)

func TestBetaArm_UniformPrior(t *testing.T) {
	arm := &BetaArm{Alpha: 1.0, Beta: 1.0}
	if got := arm.Mean(); got != 0.5 {
		t.Errorf("uniform prior Mean() = %v, want 0.5", got)
	}
}

func TestBetaArm_UpdateShiftsMean(t *testing.T) {
	arm := &BetaArm{Alpha: 1.0, Beta: 1.0}
	arm.Update(true)
	arm.Update(true)
	arm.Update(false)
	// Alpha=3, Beta=2 → Mean = 3/5 = 0.6
	if got := arm.Mean(); math.Abs(got-0.6) > 1e-10 {
		t.Errorf("after 2 success + 1 fail, Mean() = %v, want 0.6", got)
	}
	if arm.Pulls != 3 {
		t.Errorf("Pulls = %d, want 3", arm.Pulls)
	}
}

func TestBetaArm_Variance(t *testing.T) {
	arm := &BetaArm{Alpha: 3.0, Beta: 7.0}
	expected := (3.0 * 7.0) / (10.0 * 10.0 * 11.0)
	if got := arm.Variance(); math.Abs(got-expected) > 1e-10 {
		t.Errorf("Variance() = %v, want %v", got, expected)
	}
}

func TestBetaSample_AlwaysInBounds(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	cases := []struct {
		alpha, beta float64
	}{
		{1.0, 1.0},
		{0.5, 0.5},
		{10.0, 2.0},
		{0.1, 0.1},
		{100.0, 100.0},
	}
	for _, tc := range cases {
		for i := 0; i < 10000; i++ {
			s := betaSample(rng, tc.alpha, tc.beta)
			if s < 0 || s > 1 {
				t.Fatalf("betaSample(%v, %v) = %v, out of [0,1]", tc.alpha, tc.beta, s)
			}
		}
	}
}

func TestBetaSample_NormalApproxPath(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// alpha+beta > 100 triggers the normal approximation path
	sum := 0.0
	n := 10000
	for i := 0; i < n; i++ {
		s := betaSample(rng, 80.0, 30.0)
		if s < 0 || s > 1 {
			t.Fatalf("normal approx sample out of bounds: %v", s)
		}
		sum += s
	}
	mean := sum / float64(n)
	expected := 80.0 / 110.0
	if math.Abs(mean-expected) > 0.02 {
		t.Errorf("normal approx mean = %v, want ~%v (±0.02)", mean, expected)
	}
}

func TestBetaSample_EdgeCases(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// Zero/negative alpha should be clamped to 1.0
	s := betaSample(rng, 0, 1.0)
	if s < 0 || s > 1 {
		t.Errorf("negative alpha sample out of bounds: %v", s)
	}
	s = betaSample(rng, 1.0, -1.0)
	if s < 0 || s > 1 {
		t.Errorf("negative beta sample out of bounds: %v", s)
	}
}

func TestBanditSelector_ConvergesToBestArm(t *testing.T) {
	b := NewBanditSelector(42)

	// Arm "good" has 80% success, "bad" has 20%
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 500; i++ {
		b.Record("good", rng.Float64() < 0.8)
		b.Record("bad", rng.Float64() < 0.2)
	}

	// After 500 observations each, "good" should be selected most of the time
	goodCount := 0
	for i := 0; i < 1000; i++ {
		if b.Select() == "good" {
			goodCount++
		}
	}
	if goodCount < 900 {
		t.Errorf("selected 'good' %d/1000 times, want >900", goodCount)
	}
}

func TestBanditSelector_RankAll_Ordering(t *testing.T) {
	b := NewBanditSelector(42)
	// Set up arms with clearly different rates
	for i := 0; i < 100; i++ {
		b.Record("high", true)
		b.Record("low", false)
	}

	ranked := b.RankAll()
	if len(ranked) != 2 {
		t.Fatalf("RankAll() returned %d arms, want 2", len(ranked))
	}
	if ranked[0].Key != "high" {
		t.Errorf("top arm = %q, want 'high'", ranked[0].Key)
	}
}

func TestBanditSelector_GetOrCreate_Idempotent(t *testing.T) {
	b := NewBanditSelector(42)
	arm1 := b.GetOrCreate("test")
	arm2 := b.GetOrCreate("test")
	if arm1 != arm2 {
		t.Error("GetOrCreate returned different pointers for same key")
	}
	if b.ArmCount() != 1 {
		t.Errorf("ArmCount = %d, want 1", b.ArmCount())
	}
}

func TestBanditSelector_Decay_KeepsMinimum(t *testing.T) {
	b := NewBanditSelector(42)
	b.Record("test", true)
	b.Record("test", true)
	// Alpha=3, Beta=1

	b.Decay(0.1) // Aggressive decay
	arm := b.GetOrCreate("test")
	if arm.Alpha < 1.0 {
		t.Errorf("Alpha = %v after decay, want >= 1.0", arm.Alpha)
	}
	if arm.Beta < 1.0 {
		t.Errorf("Beta = %v after decay, want >= 1.0", arm.Beta)
	}
}

func TestBanditSelector_ExportImport(t *testing.T) {
	b := NewBanditSelector(42)
	for i := 0; i < 50; i++ {
		b.Record("cat-a", true)
		b.Record("cat-b", false)
	}

	state := b.Export()
	b2 := NewBanditSelector(42)
	b2.Import(state)

	if b2.ArmCount() != 2 {
		t.Fatalf("imported ArmCount = %d, want 2", b2.ArmCount())
	}
	arm := b2.GetOrCreate("cat-a")
	if arm.Alpha != 51.0 || arm.Beta != 1.0 || arm.Pulls != 50 {
		t.Errorf("imported cat-a = {Alpha:%v, Beta:%v, Pulls:%v}, want {51, 1, 50}", arm.Alpha, arm.Beta, arm.Pulls)
	}
}

func TestBanditSelector_SelectEmpty(t *testing.T) {
	b := NewBanditSelector(42)
	if got := b.Select(); got != "" {
		t.Errorf("Select() on empty bandit = %q, want empty string", got)
	}
}

func TestBanditSelector_ConcurrentSafety(t *testing.T) {
	b := NewBanditSelector(42)
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "arm-" + string(rune('a'+id))
			for i := 0; i < 100; i++ {
				b.Record(key, i%3 == 0)
				b.Select()
				b.RankAll()
				b.ArmCount()
			}
		}(g)
	}
	wg.Wait()

	// Verify state is consistent
	if b.ArmCount() != 10 {
		t.Errorf("ArmCount = %d after concurrent access, want 10", b.ArmCount())
	}
}
