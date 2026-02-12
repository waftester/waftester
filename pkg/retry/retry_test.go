package retry

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSleeper records delays without actually sleeping.
type fakeSleeper struct {
	delays []time.Duration
}

func (f *fakeSleeper) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.delays = append(f.delays, d)
	return nil
}

// --- Tests ---

func TestDo_SucceedsFirstTry(t *testing.T) {
	t.Parallel()
	s := &fakeSleeper{}
	err := doWithSleeper(context.Background(), DefaultConfig(), func() error {
		return nil
	}, s)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if len(s.delays) != 0 {
		t.Fatalf("expected 0 sleeps, got %d", len(s.delays))
	}
}

func TestDo_SucceedsAfterRetry(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	s := &fakeSleeper{}
	cfg := Config{MaxAttempts: 3, InitDelay: time.Second, MaxDelay: 30 * time.Second, Strategy: Exponential}

	err := doWithSleeper(context.Background(), cfg, func() error {
		if calls.Add(1) < 3 {
			return errors.New("temporary")
		}
		return nil
	}, s)

	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 calls, got %d", got)
	}
	if len(s.delays) != 2 {
		t.Fatalf("expected 2 sleeps, got %d", len(s.delays))
	}
}

func TestDo_AllFail(t *testing.T) {
	t.Parallel()
	s := &fakeSleeper{}
	sentinel := errors.New("always fail")
	cfg := Config{MaxAttempts: 3, InitDelay: time.Second, MaxDelay: 30 * time.Second, Strategy: Constant}

	err := doWithSleeper(context.Background(), cfg, func() error {
		return sentinel
	}, s)

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if len(s.delays) != 2 {
		t.Fatalf("expected 2 sleeps (no sleep after last attempt), got %d", len(s.delays))
	}
}

func TestDo_RespectsContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	err := Do(ctx, DefaultConfig(), func() error {
		t.Fatal("fn should not be called when context is cancelled")
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDo_ExponentialBackoff(t *testing.T) {
	t.Parallel()
	s := &fakeSleeper{}
	cfg := Config{
		MaxAttempts: 4,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    Exponential,
		Jitter:      false, // deterministic
	}

	_ = doWithSleeper(context.Background(), cfg, func() error {
		return errors.New("fail")
	}, s)

	// Expected: 1s, 2s, 4s (3 sleeps between 4 attempts)
	want := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}
	if len(s.delays) != len(want) {
		t.Fatalf("expected %d delays, got %d: %v", len(want), len(s.delays), s.delays)
	}
	for i, w := range want {
		if s.delays[i] != w {
			t.Errorf("delay[%d] = %v, want %v", i, s.delays[i], w)
		}
	}
}

func TestDo_LinearBackoff(t *testing.T) {
	t.Parallel()
	s := &fakeSleeper{}
	cfg := Config{
		MaxAttempts: 4,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    Linear,
		Jitter:      false,
	}

	_ = doWithSleeper(context.Background(), cfg, func() error {
		return errors.New("fail")
	}, s)

	// Expected: 1s, 2s, 3s
	want := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second}
	if len(s.delays) != len(want) {
		t.Fatalf("expected %d delays, got %d: %v", len(want), len(s.delays), s.delays)
	}
	for i, w := range want {
		if s.delays[i] != w {
			t.Errorf("delay[%d] = %v, want %v", i, s.delays[i], w)
		}
	}
}

func TestDo_MaxDelayCap(t *testing.T) {
	t.Parallel()
	s := &fakeSleeper{}
	cfg := Config{
		MaxAttempts: 5,
		InitDelay:   1 * time.Second,
		MaxDelay:    3 * time.Second, // cap at 3s
		Strategy:    Exponential,
		Jitter:      false,
	}

	_ = doWithSleeper(context.Background(), cfg, func() error {
		return errors.New("fail")
	}, s)

	// Exponential: 1, 2, 4(capped to 3), 8(capped to 3) -> 4 sleeps
	for i, d := range s.delays {
		if d > cfg.MaxDelay {
			t.Errorf("delay[%d] = %v, exceeds max %v", i, d, cfg.MaxDelay)
		}
	}
	// Verify the cap is applied
	if s.delays[2] != 3*time.Second {
		t.Errorf("delay[2] = %v, want %v (capped)", s.delays[2], 3*time.Second)
	}
}

func TestDo_JitterRandomness(t *testing.T) {
	t.Parallel()
	cfg := Config{
		MaxAttempts: 2,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    Constant,
		Jitter:      true,
	}

	seen := make(map[time.Duration]bool)
	for range 100 {
		delay := CalcDelay(cfg, 0)
		seen[delay] = true
		// With ±25% jitter on 1s, range is [750ms, 1250ms].
		if delay < 750*time.Millisecond || delay > 1250*time.Millisecond {
			t.Fatalf("delay %v outside expected jitter range [750ms, 1250ms]", delay)
		}
	}

	// With 100 runs and 500ms range, we should see more than 1 unique value.
	if len(seen) < 2 {
		t.Fatal("jitter produced no variation across 100 runs")
	}
}

func TestDo_ZeroAttempts(t *testing.T) {
	t.Parallel()
	called := false
	err := Do(context.Background(), Config{MaxAttempts: 0}, func() error {
		called = true
		return errors.New("should not run")
	})
	if err != nil {
		t.Fatalf("expected nil for zero attempts, got %v", err)
	}
	if called {
		t.Fatal("fn should not be called with MaxAttempts=0")
	}
}

func TestDo_StopError(t *testing.T) {
	t.Parallel()
	var calls int
	s := &fakeSleeper{}
	permanent := errors.New("client error: 403")
	cfg := Config{MaxAttempts: 5, InitDelay: time.Second, Strategy: Constant}

	err := doWithSleeper(context.Background(), cfg, func() error {
		calls++
		return Stop(permanent)
	}, s)

	if calls != 1 {
		t.Fatalf("expected 1 call (stop on first), got %d", calls)
	}
	if !errors.Is(err, permanent) {
		t.Fatalf("expected permanent error, got %v", err)
	}
	if len(s.delays) != 0 {
		t.Fatalf("expected 0 sleeps, got %d", len(s.delays))
	}
}

func TestCalcDelay_AllStrategies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		strategy Strategy
		attempt  int
		want     time.Duration
	}{
		{"exponential_0", Exponential, 0, 1 * time.Second},
		{"exponential_1", Exponential, 1, 2 * time.Second},
		{"exponential_2", Exponential, 2, 4 * time.Second},
		{"linear_0", Linear, 0, 1 * time.Second},
		{"linear_1", Linear, 1, 2 * time.Second},
		{"linear_2", Linear, 2, 3 * time.Second},
		{"constant_0", Constant, 0, 1 * time.Second},
		{"constant_3", Constant, 3, 1 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Config{
				InitDelay: 1 * time.Second,
				MaxDelay:  30 * time.Second,
				Strategy:  tt.strategy,
				Jitter:    false,
			}
			got := CalcDelay(cfg, tt.attempt)
			if got != tt.want {
				t.Errorf("CalcDelay(%s, %d) = %v, want %v", tt.name, tt.attempt, got, tt.want)
			}
		})
	}
}

func TestDo_ContextCancelledDuringSleep(t *testing.T) {
	t.Parallel()
	// Use real sleeper with a short timeout to test context cancellation during delay.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := Config{
		MaxAttempts: 5,
		InitDelay:   10 * time.Second, // long delay — will be interrupted
		MaxDelay:    10 * time.Second,
		Strategy:    Constant,
		Jitter:      false,
	}

	start := time.Now()
	err := Do(ctx, cfg, func() error {
		return errors.New("fail")
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
	// Should complete quickly (within ~200ms), not wait for 10s.
	if elapsed > 1*time.Second {
		t.Fatalf("took %v, expected <1s (context should cancel sleep)", elapsed)
	}
}

func TestCalcDelay_ExponentialOverflow(t *testing.T) {
	t.Parallel()
	// Large attempt number should be capped by MaxDelay, not overflow.
	cfg := Config{
		InitDelay: 1 * time.Second,
		MaxDelay:  30 * time.Second,
		Strategy:  Exponential,
		Jitter:    false,
	}
	delay := CalcDelay(cfg, 100) // 2^100 seconds would overflow
	if delay > cfg.MaxDelay {
		t.Errorf("delay %v exceeds max %v", delay, cfg.MaxDelay)
	}
}

func TestCalcDelay_ExponentialFormula(t *testing.T) {
	t.Parallel()
	cfg := Config{
		InitDelay: 500 * time.Millisecond,
		MaxDelay:  1 * time.Minute,
		Strategy:  Exponential,
		Jitter:    false,
	}
	for attempt := 0; attempt < 5; attempt++ {
		got := CalcDelay(cfg, attempt)
		want := cfg.InitDelay * time.Duration(math.Pow(2, float64(attempt)))
		if want > cfg.MaxDelay {
			want = cfg.MaxDelay
		}
		if got != want {
			t.Errorf("attempt %d: got %v, want %v", attempt, got, want)
		}
	}
}
