package exitcode

import (
	"sync"
	"testing"

	"github.com/waftester/waftester/pkg/output/events"
)

func TestNew(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		cfg := DefaultConfig()
		m := New(cfg)

		if m.cfg.BypassCode != 1 {
			t.Errorf("expected BypassCode=1, got %d", m.cfg.BypassCode)
		}
		if m.cfg.ErrorThreshold != 10 {
			t.Errorf("expected ErrorThreshold=10, got %d", m.cfg.ErrorThreshold)
		}
		if !m.cfg.ExitOnError {
			t.Error("expected ExitOnError=true")
		}
	})

	t.Run("zero values get defaults", func(t *testing.T) {
		m := New(Config{})

		if m.cfg.BypassCode != 1 {
			t.Errorf("expected BypassCode=1, got %d", m.cfg.BypassCode)
		}
		if m.cfg.ErrorThreshold != 10 {
			t.Errorf("expected ErrorThreshold=10, got %d", m.cfg.ErrorThreshold)
		}
	})

	t.Run("custom config preserved", func(t *testing.T) {
		m := New(Config{
			BypassCode:     5,
			ErrorThreshold: 20,
			ExitOnError:    false,
		})

		if m.cfg.BypassCode != 5 {
			t.Errorf("expected BypassCode=5, got %d", m.cfg.BypassCode)
		}
		if m.cfg.ErrorThreshold != 20 {
			t.Errorf("expected ErrorThreshold=20, got %d", m.cfg.ErrorThreshold)
		}
		if m.cfg.ExitOnError {
			t.Error("expected ExitOnError=false")
		}
	})
}

func TestRecord(t *testing.T) {
	tests := []struct {
		name         string
		outcomes     []events.Outcome
		wantBypasses int
		wantErrors   int
	}{
		{
			name:         "single bypass",
			outcomes:     []events.Outcome{events.OutcomeBypass},
			wantBypasses: 1,
			wantErrors:   0,
		},
		{
			name:         "single error",
			outcomes:     []events.Outcome{events.OutcomeError},
			wantBypasses: 0,
			wantErrors:   1,
		},
		{
			name:         "timeout counts as error",
			outcomes:     []events.Outcome{events.OutcomeTimeout},
			wantBypasses: 0,
			wantErrors:   1,
		},
		{
			name:         "blocked does not count",
			outcomes:     []events.Outcome{events.OutcomeBlocked},
			wantBypasses: 0,
			wantErrors:   0,
		},
		{
			name:         "pass does not count",
			outcomes:     []events.Outcome{events.OutcomePass},
			wantBypasses: 0,
			wantErrors:   0,
		},
		{
			name: "mixed outcomes",
			outcomes: []events.Outcome{
				events.OutcomeBypass,
				events.OutcomeBypass,
				events.OutcomeBlocked,
				events.OutcomeError,
				events.OutcomeTimeout,
				events.OutcomePass,
			},
			wantBypasses: 2,
			wantErrors:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(DefaultConfig())

			for _, outcome := range tt.outcomes {
				m.Record(outcome)
			}

			bypasses, errors := m.Stats()
			if bypasses != tt.wantBypasses {
				t.Errorf("bypasses = %d, want %d", bypasses, tt.wantBypasses)
			}
			if errors != tt.wantErrors {
				t.Errorf("errors = %d, want %d", errors, tt.wantErrors)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	t.Run("success when no issues", func(t *testing.T) {
		m := New(DefaultConfig())
		code, _ := m.ExitCode()
		if code != Success {
			t.Errorf("expected Success(0), got %d", code)
		}
	})

	t.Run("bypasses detected", func(t *testing.T) {
		m := New(DefaultConfig())
		m.Record(events.OutcomeBypass)

		code, reason := m.ExitCode()
		if code != Bypasses {
			t.Errorf("expected Bypasses(1), got %d", code)
		}
		if reason == "" {
			t.Error("expected non-empty reason")
		}
	})

	t.Run("custom bypass code", func(t *testing.T) {
		m := New(Config{BypassCode: 42, ErrorThreshold: 10})
		m.Record(events.OutcomeBypass)

		code, _ := m.ExitCode()
		if code != 42 {
			t.Errorf("expected custom code 42, got %d", code)
		}
	})

	t.Run("error threshold reached", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    true,
			ErrorThreshold: 5,
		})

		for i := 0; i < 5; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Errors {
			t.Errorf("expected Errors(2), got %d", code)
		}
	})

	t.Run("error threshold not reached", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    true,
			ErrorThreshold: 5,
		})

		for i := 0; i < 4; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Success {
			t.Errorf("expected Success(0), got %d", code)
		}
	})

	t.Run("exit on error disabled", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    false,
			ErrorThreshold: 5,
		})

		for i := 0; i < 10; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Success {
			t.Errorf("expected Success(0), got %d", code)
		}
	})

	t.Run("bypasses take precedence over errors below threshold", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    true,
			ErrorThreshold: 10,
		})

		m.Record(events.OutcomeBypass)
		for i := 0; i < 5; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Bypasses {
			t.Errorf("expected Bypasses(1), got %d", code)
		}
	})

	t.Run("errors above threshold take precedence over bypasses", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    true,
			ErrorThreshold: 5,
		})

		m.Record(events.OutcomeBypass)
		for i := 0; i < 5; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Errors {
			t.Errorf("expected Errors(2), got %d", code)
		}
	})
}

func TestSpecialStates(t *testing.T) {
	t.Run("configuration error", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetConfigError()

		code, _ := m.ExitCode()
		if code != Configuration {
			t.Errorf("expected Configuration(3), got %d", code)
		}
	})

	t.Run("target error", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetTargetError()

		code, _ := m.ExitCode()
		if code != Target {
			t.Errorf("expected Target(4), got %d", code)
		}
	})

	t.Run("interrupted", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetInterrupted()

		code, _ := m.ExitCode()
		if code != Interrupted {
			t.Errorf("expected Interrupted(5), got %d", code)
		}
	})

	t.Run("license error", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetLicenseError()

		code, _ := m.ExitCode()
		if code != License {
			t.Errorf("expected License(6), got %d", code)
		}
	})
}

func TestStatePriority(t *testing.T) {
	// Priority: License > Interrupted > Config > Target > Errors > Bypasses > Success

	t.Run("license highest priority", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetLicenseError()
		m.SetInterrupted()
		m.SetConfigError()
		m.SetTargetError()
		m.Record(events.OutcomeBypass)
		for i := 0; i < 15; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != License {
			t.Errorf("expected License(6), got %d", code)
		}
	})

	t.Run("interrupted over config", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetInterrupted()
		m.SetConfigError()

		code, _ := m.ExitCode()
		if code != Interrupted {
			t.Errorf("expected Interrupted(5), got %d", code)
		}
	})

	t.Run("config over target", func(t *testing.T) {
		m := New(DefaultConfig())
		m.SetConfigError()
		m.SetTargetError()

		code, _ := m.ExitCode()
		if code != Configuration {
			t.Errorf("expected Configuration(3), got %d", code)
		}
	})

	t.Run("target over errors", func(t *testing.T) {
		m := New(Config{
			BypassCode:     1,
			ExitOnError:    true,
			ErrorThreshold: 5,
		})
		m.SetTargetError()
		for i := 0; i < 10; i++ {
			m.Record(events.OutcomeError)
		}

		code, _ := m.ExitCode()
		if code != Target {
			t.Errorf("expected Target(4), got %d", code)
		}
	})
}

func TestString(t *testing.T) {
	m := New(DefaultConfig())

	tests := []struct {
		code Code
		want string
	}{
		{Success, "success"},
		{Bypasses, "bypasses_detected"},
		{Errors, "too_many_errors"},
		{Configuration, "invalid_configuration"},
		{Target, "target_unreachable"},
		{Interrupted, "scan_interrupted"},
		{License, "license_error"},
		{Code(99), "unknown_code_99"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := m.String(tt.code)
			if got != tt.want {
				t.Errorf("String(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestCodeString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{Success, "success"},
		{Bypasses, "bypasses_detected"},
		{Code(100), "unknown_code_100"},
	}

	for _, tt := range tests {
		got := CodeString(tt.code)
		if got != tt.want {
			t.Errorf("CodeString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestCodeDescription(t *testing.T) {
	tests := []struct {
		code     Code
		contains string
	}{
		{Success, "no bypasses"},
		{Bypasses, "bypasses were detected"},
		{License, "License"},
		{Code(100), "Unknown exit code"},
	}

	for _, tt := range tests {
		got := CodeDescription(tt.code)
		if got == "" {
			t.Errorf("CodeDescription(%d) returned empty string", tt.code)
		}
	}
}

func TestReset(t *testing.T) {
	m := New(DefaultConfig())

	// Set everything
	m.Record(events.OutcomeBypass)
	m.Record(events.OutcomeError)
	m.SetConfigError()
	m.SetTargetError()
	m.SetInterrupted()
	m.SetLicenseError()

	// Verify state is set
	code, _ := m.ExitCode()
	if code != License {
		t.Errorf("expected License before reset, got %d", code)
	}

	// Reset
	m.Reset()

	// Verify everything is cleared
	code, _ = m.ExitCode()
	if code != Success {
		t.Errorf("expected Success after reset, got %d", code)
	}

	bypasses, errors := m.Stats()
	if bypasses != 0 || errors != 0 {
		t.Errorf("expected 0 bypasses and 0 errors after reset, got %d/%d", bypasses, errors)
	}
}

func TestConcurrency(t *testing.T) {
	m := New(Config{
		BypassCode:     1,
		ExitOnError:    true,
		ErrorThreshold: 1000,
	})

	var wg sync.WaitGroup
	iterations := 100

	// Spawn multiple goroutines recording outcomes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.Record(events.OutcomeBypass)
				m.Record(events.OutcomeError)
			}
		}()
	}

	// Also read stats concurrently
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = m.ExitCode()
				_, _ = m.Stats()
			}
		}()
	}

	wg.Wait()

	bypasses, errors := m.Stats()
	expectedBypasses := 10 * iterations
	expectedErrors := 10 * iterations

	if bypasses != expectedBypasses {
		t.Errorf("bypasses = %d, want %d", bypasses, expectedBypasses)
	}
	if errors != expectedErrors {
		t.Errorf("errors = %d, want %d", errors, expectedErrors)
	}
}

func TestRecordBypassAndError(t *testing.T) {
	m := New(DefaultConfig())

	m.RecordBypass()
	m.RecordBypass()
	m.RecordError()

	bypasses, errors := m.Stats()
	if bypasses != 2 {
		t.Errorf("bypasses = %d, want 2", bypasses)
	}
	if errors != 1 {
		t.Errorf("errors = %d, want 1", errors)
	}
}
