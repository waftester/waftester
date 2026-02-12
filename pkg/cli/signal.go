package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// SignalContext returns a context cancelled on SIGINT/SIGTERM.
// If a second signal arrives during gracePeriod, os.Exit(1) is called.
//
// Usage:
//
//	ctx, cancel := cli.SignalContext(30 * time.Second)
//	defer cancel()
//
// For commands that also need a timeout:
//
//	ctx, cancel := cli.SignalContext(30 * time.Second)
//	defer cancel()
//	ctx, tCancel := context.WithTimeout(ctx, 30*time.Minute)
//	defer tCancel()
func SignalContext(gracePeriod time.Duration) (context.Context, context.CancelFunc) {
	return signalContextWithNotifier(gracePeriod, nil, nil)
}

// signalContextWithNotifier is the internal implementation for testing.
// sigChan, if non-nil, overrides the real signal channel.
// exitFn, if non-nil, overrides os.Exit for testing.
func signalContextWithNotifier(
	gracePeriod time.Duration,
	sigChan chan os.Signal,
	exitFn func(int),
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	ownChannel := sigChan == nil
	if ownChannel {
		sigChan = make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	}

	if exitFn == nil {
		exitFn = os.Exit
	}

	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "Interrupt received, shutting down gracefully...")
			cancel()

			// Wait for a second signal or grace period.
			select {
			case <-sigChan:
				exitFn(1)
			case <-time.After(gracePeriod):
			}
		case <-ctx.Done():
		}
		if ownChannel {
			signal.Stop(sigChan)
		}
	}()

	return ctx, cancel
}
