// Package retry provides a shared retry engine with configurable backoff
// strategies. It replaces 5+ independent retry implementations across the
// codebase with a single, tested, context-aware engine.
//
// Three strategies are supported:
//   - Exponential: delay doubles each attempt (1s, 2s, 4s, …)
//   - Linear: delay grows linearly (1s, 2s, 3s, …)
//   - Constant: delay stays the same each attempt
//
// Usage:
//
//	err := retry.Do(ctx, retry.DefaultConfig(), func() error {
//	    resp, err := client.Do(req)
//	    if err != nil {
//	        return err
//	    }
//	    return nil
//	})
package retry

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"time"
)

// Strategy defines the backoff algorithm.
type Strategy int

const (
	// Exponential doubles the delay each attempt: initDelay * 2^attempt.
	Exponential Strategy = iota
	// Linear increases the delay linearly: initDelay * (attempt+1).
	Linear
	// Constant uses the same delay between every attempt.
	Constant
)

// Config controls retry behaviour.
type Config struct {
	MaxAttempts int           // Total attempts (including the first). 0 means no-op.
	InitDelay   time.Duration // Base delay before first retry.
	MaxDelay    time.Duration // Upper bound on any single delay.
	Strategy    Strategy      // Backoff algorithm.
	Jitter      bool          // Add ±25% random jitter to each delay.
}

// DefaultConfig returns a sensible default: 3 attempts, exponential backoff
// from 1 s to 30 s with jitter enabled.
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		InitDelay:   1 * time.Second,
		MaxDelay:    30 * time.Second,
		Strategy:    Exponential,
		Jitter:      true,
	}
}

// StopError wraps an error to signal that retrying should stop immediately.
// Use this when the caller knows the error is permanent (e.g. 4xx HTTP status).
type StopError struct {
	Err error
}

func (e *StopError) Error() string { return e.Err.Error() }
func (e *StopError) Unwrap() error { return e.Err }

// Stop wraps err so that Do returns it without further retries.
func Stop(err error) error {
	return &StopError{Err: err}
}

// sleeper is an interface for waiting, allowing tests to override time.After.
type sleeper interface {
	sleep(ctx context.Context, d time.Duration) error
}

// realSleeper uses time.After for production code.
type realSleeper struct{}

func (realSleeper) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Do executes fn up to cfg.MaxAttempts times, sleeping between failures
// according to the configured strategy. It returns nil on the first
// successful call, or the last error if all attempts fail. If the context
// is cancelled, ctx.Err() is returned immediately.
//
// If fn returns a StopError, Do returns the wrapped error without retrying.
func Do(ctx context.Context, cfg Config, fn func() error) error {
	return doWithSleeper(ctx, cfg, fn, realSleeper{})
}

func doWithSleeper(ctx context.Context, cfg Config, fn func() error, s sleeper) error {
	if cfg.MaxAttempts <= 0 {
		return nil
	}

	var lastErr error
	for attempt := range cfg.MaxAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}

		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Check for StopError — caller says don't retry.
		var stop *StopError
		if errors.As(lastErr, &stop) {
			return stop.Err
		}

		// Sleep before next attempt (skip after final attempt).
		if attempt < cfg.MaxAttempts-1 {
			delay := CalcDelay(cfg, attempt)
			if err := s.sleep(ctx, delay); err != nil {
				return err
			}
		}
	}
	return lastErr
}

// CalcDelay computes the sleep duration for a given attempt (0-indexed).
func CalcDelay(cfg Config, attempt int) time.Duration {
	var delay time.Duration
	switch cfg.Strategy {
	case Exponential:
		delay = cfg.InitDelay * time.Duration(math.Pow(2, float64(attempt)))
	case Linear:
		delay = cfg.InitDelay * time.Duration(attempt+1)
	case Constant:
		delay = cfg.InitDelay
	}
	if delay > cfg.MaxDelay {
		delay = cfg.MaxDelay
	}
	if cfg.Jitter && delay > 0 {
		quarter := int64(delay) / 4
		if quarter > 0 {
			j := time.Duration(rand.Int64N(quarter))
			if rand.IntN(2) == 0 {
				delay += j
			} else {
				delay -= j
			}
		}
	}
	return delay
}
