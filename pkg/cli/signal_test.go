package cli

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignalContext_CancelOnInterrupt(t *testing.T) {
	sigChan := make(chan os.Signal, 1)
	ctx, cancel := signalContextWithNotifier(5*time.Second, sigChan, nil)
	defer cancel()

	// Send SIGINT.
	sigChan <- os.Interrupt

	select {
	case <-ctx.Done():
		// Success — context was cancelled by signal.
	case <-time.After(2 * time.Second):
		t.Fatal("context was not cancelled after signal")
	}
}

func TestSignalContext_ManualCancel(t *testing.T) {
	sigChan := make(chan os.Signal, 1)
	ctx, cancel := signalContextWithNotifier(5*time.Second, sigChan, nil)

	// Manual cancel — goroutine should exit cleanly via ctx.Done().
	cancel()

	select {
	case <-ctx.Done():
		// Success.
	case <-time.After(2 * time.Second):
		t.Fatal("context was not cancelled after manual cancel")
	}
}

func TestSignalContext_GracePeriod_SecondSignalExits(t *testing.T) {
	sigChan := make(chan os.Signal, 2) // buffered for two signals
	var exitCode atomic.Int32
	exitCode.Store(-1) // sentinel: not called

	exitFn := func(code int) {
		exitCode.Store(int32(code))
	}

	ctx, cancel := signalContextWithNotifier(5*time.Second, sigChan, exitFn)
	defer cancel()

	// First signal — cancels context.
	sigChan <- os.Interrupt

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context was not cancelled after first signal")
	}

	// Second signal during grace period — should call exitFn(1).
	sigChan <- os.Interrupt

	// Wait briefly for exit to be called.
	deadline := time.After(2 * time.Second)
	for {
		if exitCode.Load() == 1 {
			return // Success
		}
		select {
		case <-deadline:
			t.Fatal("exitFn was not called after second signal")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestSignalContext_GracePeriod_Expires(t *testing.T) {
	sigChan := make(chan os.Signal, 1)
	var exitCalled atomic.Bool

	exitFn := func(int) {
		exitCalled.Store(true)
	}

	_, cancel := signalContextWithNotifier(50*time.Millisecond, sigChan, exitFn)
	defer cancel()

	// First signal — cancels context.
	sigChan <- os.Interrupt

	// Wait for grace period to expire (50ms + margin).
	time.Sleep(200 * time.Millisecond)

	// Exit should NOT have been called — only one signal was sent.
	if exitCalled.Load() {
		t.Error("exitFn should not be called when grace period expires without second signal")
	}
}

func TestSignalContext_NoSignal_ContextUsable(t *testing.T) {
	sigChan := make(chan os.Signal, 1)
	ctx, cancel := signalContextWithNotifier(5*time.Second, sigChan, nil)
	defer cancel()

	// Context should not be done.
	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled without signal or cancel")
	default:
		// Good.
	}
}
