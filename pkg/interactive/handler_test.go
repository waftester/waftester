// Package interactive provides tests for interactive mode
package interactive

import (
	"testing"
)

// TestStateStruct tests the State struct
func TestStateStruct(t *testing.T) {
	state := State{
		Paused:      true,
		FilterCodes: "403,404",
		MatchCodes:  "200",
		RateLimit:   100,
	}

	if !state.Paused {
		t.Error("expected Paused to be true")
	}
	if state.FilterCodes != "403,404" {
		t.Errorf("expected FilterCodes '403,404', got %s", state.FilterCodes)
	}
	if state.MatchCodes != "200" {
		t.Errorf("expected MatchCodes '200', got %s", state.MatchCodes)
	}
	if state.RateLimit != 100 {
		t.Errorf("expected RateLimit 100, got %d", state.RateLimit)
	}
}

// TestNewState tests creating a new State
func TestNewState(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit int
	}{
		{"default rate", 50},
		{"high rate", 1000},
		{"low rate", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewState(tt.rateLimit)
			if state == nil {
				t.Fatal("expected state, got nil")
			}
			if state.RateLimit != tt.rateLimit {
				t.Errorf("expected RateLimit %d, got %d", tt.rateLimit, state.RateLimit)
			}
			if state.Paused {
				t.Error("expected Paused to be false by default")
			}
			if state.pauseChan == nil {
				t.Error("expected pauseChan to be initialized")
			}
			if state.resumeChan == nil {
				t.Error("expected resumeChan to be initialized")
			}
		})
	}
}

// TestNewHandler tests creating a new Handler
func TestNewHandler(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	if handler == nil {
		t.Fatal("expected handler, got nil")
	}
	if handler.state != state {
		t.Error("expected handler.state to be the provided state")
	}
	if handler.done == nil {
		t.Error("expected done channel to be initialized")
	}
	if handler.running {
		t.Error("expected running to be false by default")
	}
}

// TestHandlerStartStop tests Start and Stop methods
func TestHandlerStartStop(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Start handler
	handler.Start()

	// Verify running is true
	handler.mu.Lock()
	running := handler.running
	handler.mu.Unlock()

	if !running {
		t.Error("expected running to be true after Start")
	}

	// Start again should be no-op
	handler.Start()

	// Stop handler
	handler.Stop()

	// Verify running is false
	handler.mu.Lock()
	running = handler.running
	handler.mu.Unlock()

	if running {
		t.Error("expected running to be false after Stop")
	}
}

// TestHandlerIsPaused tests the IsPaused method
func TestHandlerIsPaused(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Initially not paused
	if handler.IsPaused() {
		t.Error("expected IsPaused to return false initially")
	}

	// Set paused
	state.mu.Lock()
	state.Paused = true
	state.mu.Unlock()

	if !handler.IsPaused() {
		t.Error("expected IsPaused to return true after setting Paused")
	}
}

// TestHandlerWaitIfPausedNotPaused tests WaitIfPaused when not paused
func TestHandlerWaitIfPausedNotPaused(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Should return immediately when not paused
	handler.WaitIfPaused()
	// If we get here, it returned (as expected when not paused)
}

// TestStateDefaultValues tests State with default values
func TestStateDefaultValues(t *testing.T) {
	state := State{}

	if state.Paused {
		t.Error("expected default Paused to be false")
	}
	if state.FilterCodes != "" {
		t.Error("expected default FilterCodes to be empty")
	}
	if state.MatchCodes != "" {
		t.Error("expected default MatchCodes to be empty")
	}
	if state.RateLimit != 0 {
		t.Errorf("expected default RateLimit 0, got %d", state.RateLimit)
	}
}

// TestHandlerHandleInputHelp tests handling help command
func TestHandlerHandleInputHelp(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// These should not panic
	handler.handleInput("help")
	handler.handleInput("?")
}

// TestHandlerHandleInputResume tests handling resume command
func TestHandlerHandleInputResume(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Should not panic when not paused
	handler.handleInput("resume")
}

// TestHandlerHandleInputFC tests handling fc command
func TestHandlerHandleInputFC(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Set filter code
	handler.handleInput("fc 403,404")
	if state.FilterCodes != "403,404" {
		t.Errorf("expected FilterCodes '403,404', got %s", state.FilterCodes)
	}

	// Clear filter code
	handler.handleInput("fc none")
	if state.FilterCodes != "" {
		t.Errorf("expected FilterCodes empty, got %s", state.FilterCodes)
	}

	// No argument should not panic
	handler.handleInput("fc")
}

// TestHandlerHandleInputMC tests handling mc command
func TestHandlerHandleInputMC(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Set match code
	handler.handleInput("mc 200")
	if state.MatchCodes != "200" {
		t.Errorf("expected MatchCodes '200', got %s", state.MatchCodes)
	}

	// Clear match code
	handler.handleInput("mc none")
	if state.MatchCodes != "" {
		t.Errorf("expected MatchCodes empty, got %s", state.MatchCodes)
	}

	// No argument should not panic
	handler.handleInput("mc")
}

// TestHandlerHandleInputRate tests handling rate command
func TestHandlerHandleInputRate(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Set rate
	handler.handleInput("rate 100")
	if state.RateLimit != 100 {
		t.Errorf("expected RateLimit 100, got %d", state.RateLimit)
	}

	// Invalid rate should not change
	handler.handleInput("rate invalid")
	if state.RateLimit != 100 {
		t.Errorf("expected RateLimit 100 after invalid, got %d", state.RateLimit)
	}

	// Negative rate should not change
	handler.handleInput("rate -5")
	if state.RateLimit != 100 {
		t.Errorf("expected RateLimit 100 after negative, got %d", state.RateLimit)
	}

	// No argument shows current (should not panic)
	handler.handleInput("rate")
}

// TestHandlerHandleInputShow tests handling show command
func TestHandlerHandleInputShow(t *testing.T) {
	state := NewState(50)
	state.FilterCodes = "403"
	state.MatchCodes = "200"
	handler := NewHandler(state)

	// Should not panic
	handler.handleInput("show")
}

// TestHandlerHandleInputUnknown tests handling unknown command
func TestHandlerHandleInputUnknown(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Should not panic
	handler.handleInput("unknowncommand")
}

// TestHandlerHandleInputEmpty tests handling empty input (toggle pause)
func TestHandlerHandleInputEmpty(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Empty should toggle pause
	handler.handleInput("")
	if !state.Paused {
		t.Error("expected Paused to be true after empty input")
	}

	// Another empty should toggle back
	// Note: This requires handling the resumeChan properly, skip for now
}

// TestHandlerTogglePause tests togglePause
func TestHandlerTogglePause(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Initially not paused
	if state.Paused {
		t.Error("expected not paused initially")
	}

	// Toggle to paused
	handler.togglePause()
	if !state.Paused {
		t.Error("expected paused after toggle")
	}
}

// TestHandlerResume tests resume function
func TestHandlerResume(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Resume when not paused should be no-op
	handler.resume()

	// Set paused
	state.mu.Lock()
	state.Paused = true
	state.mu.Unlock()

	// Resume in goroutine (since it sends on channel)
	go handler.resume()
}

// TestHandlerSetFilterCode tests setFilterCode
func TestHandlerSetFilterCode(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	handler.setFilterCode("404")
	if state.FilterCodes != "404" {
		t.Errorf("expected '404', got %s", state.FilterCodes)
	}

	handler.setFilterCode("403,404,500")
	if state.FilterCodes != "403,404,500" {
		t.Errorf("expected '403,404,500', got %s", state.FilterCodes)
	}

	handler.setFilterCode("none")
	if state.FilterCodes != "" {
		t.Errorf("expected empty, got %s", state.FilterCodes)
	}
}

// TestHandlerSetMatchCode tests setMatchCode
func TestHandlerSetMatchCode(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	handler.setMatchCode("200")
	if state.MatchCodes != "200" {
		t.Errorf("expected '200', got %s", state.MatchCodes)
	}

	handler.setMatchCode("200,201,202")
	if state.MatchCodes != "200,201,202" {
		t.Errorf("expected '200,201,202', got %s", state.MatchCodes)
	}

	handler.setMatchCode("none")
	if state.MatchCodes != "" {
		t.Errorf("expected empty, got %s", state.MatchCodes)
	}
}

// TestHandlerSetRate tests setRate
func TestHandlerSetRate(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	handler.setRate("100")
	if state.RateLimit != 100 {
		t.Errorf("expected 100, got %d", state.RateLimit)
	}

	handler.setRate("500")
	if state.RateLimit != 500 {
		t.Errorf("expected 500, got %d", state.RateLimit)
	}

	// Invalid should not change
	oldRate := state.RateLimit
	handler.setRate("invalid")
	if state.RateLimit != oldRate {
		t.Errorf("expected %d unchanged, got %d", oldRate, state.RateLimit)
	}

	// Zero should not change
	handler.setRate("0")
	if state.RateLimit != oldRate {
		t.Errorf("expected %d unchanged after 0, got %d", oldRate, state.RateLimit)
	}
}

// TestHandlerShowStatus tests showStatus
func TestHandlerShowStatus(t *testing.T) {
	state := NewState(50)
	state.FilterCodes = "403"
	state.MatchCodes = "200"
	handler := NewHandler(state)

	// Should not panic
	handler.showStatus()
}

// TestHandlerPrintBanner tests printBanner
func TestHandlerPrintBanner(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Should not panic
	handler.printBanner()
}

// TestHandlerPrintHelp tests printHelp
func TestHandlerPrintHelp(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Should not panic
	handler.printHelp()
}

// TestStateConcurrentAccess tests concurrent access to State
func TestStateConcurrentAccess(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Run concurrent operations
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			handler.setFilterCode("403")
			handler.setMatchCode("200")
			handler.setRate("100")
			handler.IsPaused()
		}
		close(done)
	}()

	// Run more concurrent reads
	for i := 0; i < 100; i++ {
		_ = handler.IsPaused()
		state.mu.Lock()
		_ = state.FilterCodes
		_ = state.MatchCodes
		state.mu.Unlock()
	}

	<-done
}

// TestHandlerStopMultipleTimes tests calling Stop multiple times
func TestHandlerStopMultipleTimes(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)
	handler.Start()

	// Stop multiple times should not panic
	handler.Stop()
	handler.Stop() // Second stop should be safe (already stopped)
}

// TestNewStateWithZeroRate tests NewState with zero rate
func TestNewStateWithZeroRate(t *testing.T) {
	state := NewState(0)
	if state.RateLimit != 0 {
		t.Errorf("expected RateLimit 0, got %d", state.RateLimit)
	}
}

// TestHandlerCaseSensitivity tests command case insensitivity
func TestHandlerCaseSensitivity(t *testing.T) {
	state := NewState(50)
	handler := NewHandler(state)

	// Commands should be case insensitive
	handler.handleInput("FC 403")
	if state.FilterCodes != "403" {
		t.Errorf("expected '403' with uppercase FC, got %s", state.FilterCodes)
	}

	handler.handleInput("MC 200")
	if state.MatchCodes != "200" {
		t.Errorf("expected '200' with uppercase MC, got %s", state.MatchCodes)
	}

	handler.handleInput("RATE 75")
	if state.RateLimit != 75 {
		t.Errorf("expected 75 with uppercase RATE, got %d", state.RateLimit)
	}

	handler.handleInput("HELP")
	handler.handleInput("SHOW")
	handler.handleInput("RESUME")
}
