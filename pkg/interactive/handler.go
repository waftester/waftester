package interactive

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/waftester/waftester/pkg/ui"
)

// State represents the current interactive state
type State struct {
	Paused      bool
	FilterCodes string
	MatchCodes  string
	RateLimit   int
	mu          sync.Mutex
	pauseChan   chan struct{}
	resumeChan  chan struct{}
}

// NewState creates a new interactive state
func NewState(rateLimit int) *State {
	return &State{
		RateLimit:  rateLimit,
		pauseChan:  make(chan struct{}),
		resumeChan: make(chan struct{}),
	}
}

// Handler manages interactive mode (ffuf-style)
type Handler struct {
	state   *State
	done    chan struct{}
	running bool
	mu      sync.Mutex
}

// NewHandler creates a new interactive handler
func NewHandler(state *State) *Handler {
	return &Handler{
		state: state,
		done:  make(chan struct{}),
	}
}

// Start begins listening for keyboard input
func (h *Handler) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.mu.Unlock()

	go h.inputLoop()
}

// Stop halts the interactive handler
func (h *Handler) Stop() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.running {
		close(h.done)
		h.running = false
	}
}

// IsPaused returns whether execution is paused
func (h *Handler) IsPaused() bool {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	return h.state.Paused
}

// WaitIfPaused blocks until resumed if currently paused
func (h *Handler) WaitIfPaused() {
	h.state.mu.Lock()
	if !h.state.Paused {
		h.state.mu.Unlock()
		return
	}
	h.state.mu.Unlock()
	<-h.state.resumeChan
}

// inputLoop reads user input from stdin
// NOTE: This goroutine cannot be cleanly terminated when blocked on ReadString.
// When Stop() is called, if the goroutine is blocked reading stdin, it will
// only exit after the next newline is received. This is a known limitation
// of blocking I/O in Go. For long-running processes, this is acceptable as
// the goroutine will terminate when the process exits.
func (h *Handler) inputLoop() {
	reader := bufio.NewReader(os.Stdin)

	for {
		select {
		case <-h.done:
			return
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				// Check if we should exit before continuing
				select {
				case <-h.done:
					return
				default:
				}
				continue
			}
			h.handleInput(strings.TrimSpace(line))
		}
	}
}

func (h *Handler) handleInput(input string) {
	args := strings.Fields(input)

	// Empty input = toggle pause
	if len(args) == 0 || input == "" {
		h.togglePause()
		return
	}

	cmd := strings.ToLower(args[0])

	switch cmd {
	case "help", "?":
		h.printHelp()
	case "resume":
		h.resume()
	case "fc":
		if len(args) >= 2 {
			h.setFilterCode(args[1])
		} else {
			fmt.Println("  [!] Usage: fc <code> (e.g., fc 404 or fc none)")
		}
	case "mc":
		if len(args) >= 2 {
			h.setMatchCode(args[1])
		} else {
			fmt.Println("  [!] Usage: mc <code> (e.g., mc 403 or mc none)")
		}
	case "rate":
		if len(args) >= 2 {
			h.setRate(args[1])
		} else {
			fmt.Printf("  [i] Current rate: %d req/sec\n", h.state.RateLimit)
		}
	case "show":
		h.showStatus()
	default:
		fmt.Printf("  [!] Unknown command: %s (type 'help' for commands)\n", cmd)
	}
}

func (h *Handler) togglePause() {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if h.state.Paused {
		h.state.Paused = false
		fmt.Println()
		ui.PrintInfo("Resuming execution...")
		// Signal resume
		select {
		case h.state.resumeChan <- struct{}{}:
		default:
		}
	} else {
		h.state.Paused = true
		fmt.Println()
		h.printBanner()
	}
}

func (h *Handler) resume() {
	h.state.mu.Lock()
	if !h.state.Paused {
		h.state.mu.Unlock()
		return
	}
	h.state.Paused = false
	h.state.mu.Unlock()

	ui.PrintInfo("Resuming execution...")
	select {
	case h.state.resumeChan <- struct{}{}:
	default:
	}
}

func (h *Handler) printBanner() {
	fmt.Println("  entering interactive mode")
	fmt.Println("  type \"help\" for a list of commands, or ENTER to resume.")
	fmt.Print("  > ")
}

func (h *Handler) printHelp() {
	help := `
  available commands:
    fc   [value]     - (re)configure status code filter (e.g., fc 404,500 or fc none)
    mc   [value]     - (re)configure status code matcher (e.g., mc 403 or mc none)
    rate [value]     - adjust rate of requests per second (current: %d)
    show             - show current configuration
    resume           - resume execution (or: ENTER)
    help             - show this help
`
	fmt.Printf(help, h.state.RateLimit)
	fmt.Print("  > ")
}

func (h *Handler) setFilterCode(value string) {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if value == "none" {
		h.state.FilterCodes = ""
		fmt.Println("  [+] Filter codes cleared")
	} else {
		h.state.FilterCodes = value
		fmt.Printf("  [+] Filter codes set to: %s\n", value)
	}
	fmt.Print("  > ")
}

func (h *Handler) setMatchCode(value string) {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	if value == "none" {
		h.state.MatchCodes = ""
		fmt.Println("  [+] Match codes cleared")
	} else {
		h.state.MatchCodes = value
		fmt.Printf("  [+] Match codes set to: %s\n", value)
	}
	fmt.Print("  > ")
}

func (h *Handler) setRate(value string) {
	rate, err := strconv.Atoi(value)
	if err != nil || rate <= 0 {
		fmt.Println("  [!] Invalid rate value")
		fmt.Print("  > ")
		return
	}

	h.state.mu.Lock()
	h.state.RateLimit = rate
	h.state.mu.Unlock()

	fmt.Printf("  [+] Rate limit set to: %d req/sec\n", rate)
	fmt.Print("  > ")
}

func (h *Handler) showStatus() {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	fmt.Println()
	fmt.Println("  Current Configuration:")
	fmt.Printf("    Rate Limit:   %d req/sec\n", h.state.RateLimit)
	if h.state.FilterCodes != "" {
		fmt.Printf("    Filter Codes: %s\n", h.state.FilterCodes)
	}
	if h.state.MatchCodes != "" {
		fmt.Printf("    Match Codes:  %s\n", h.state.MatchCodes)
	}
	fmt.Println()
	fmt.Print("  > ")
}
