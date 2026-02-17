package ui

import (
	"time"
)

// SpinnerType represents different spinner animation styles
type SpinnerType int

const (
	SpinnerDots SpinnerType = iota
	SpinnerLine
	SpinnerCircle
	SpinnerArc
	SpinnerBounce
	SpinnerBox
)

// Spinner holds spinner animation frames
type Spinner struct {
	Frames   []string
	Interval time.Duration
}

// Spinners provides various spinner animation styles
var Spinners = map[SpinnerType]Spinner{
	SpinnerDots: {
		Frames:   []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		Interval: 80 * time.Millisecond,
	},
	SpinnerLine: {
		Frames:   []string{"-", "\\", "|", "/"},
		Interval: 100 * time.Millisecond,
	},
	SpinnerCircle: {
		Frames:   []string{"◐", "◓", "◑", "◒"},
		Interval: 100 * time.Millisecond,
	},
	SpinnerArc: {
		Frames:   []string{"◜", "◠", "◝", "◞", "◡", "◟"},
		Interval: 100 * time.Millisecond,
	},
	SpinnerBounce: {
		Frames:   []string{"⠁", "⠂", "⠄", "⡀", "⢀", "⠠", "⠐", "⠈"},
		Interval: 120 * time.Millisecond,
	},
	SpinnerBox: {
		Frames:   []string{"▖", "▘", "▝", "▗"},
		Interval: 100 * time.Millisecond,
	},
}

// GetSpinner returns a spinner by type with a default fallback.
// On terminals that cannot render Unicode (legacy Windows consoles),
// Unicode-heavy spinners are replaced with SpinnerLine.
func GetSpinner(t SpinnerType) Spinner {
	if !UnicodeTerminal() {
		// Only SpinnerLine is pure ASCII; all others use Unicode glyphs.
		return Spinners[SpinnerLine]
	}
	if s, ok := Spinners[t]; ok {
		return s
	}
	return Spinners[SpinnerDots]
}

// Symbols provides consistent icons/symbols throughout the UI
var Symbols = struct {
	Success   string
	Error     string
	Warning   string
	Info      string
	Blocked   string
	Bullet    string
	Arrow     string
	Check     string
	Cross     string
	Shield    string
	Target    string
	Lightning string
	Fire      string
}{
	Success:   "+",
	Error:     "x",
	Warning:   "!",
	Info:      "i",
	Blocked:   "[B]",
	Bullet:    "*",
	Arrow:     "->",
	Check:     "+",
	Cross:     "x",
	Shield:    "[S]",
	Target:    "@",
	Lightning: "!",
	Fire:      "*",
}

// Box drawing characters for borders
var Box = struct {
	TopLeft     string
	TopRight    string
	BottomLeft  string
	BottomRight string
	Horizontal  string
	Vertical    string
	MiddleLeft  string
	MiddleRight string
	Cross       string
}{
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
	Horizontal:  "-",
	Vertical:    "|",
	MiddleLeft:  "+",
	MiddleRight: "+",
	Cross:       "+",
}

// Heavy box drawing for emphasis
var HeavyBox = struct {
	TopLeft     string
	TopRight    string
	BottomLeft  string
	BottomRight string
	Horizontal  string
	Vertical    string
}{
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
	Horizontal:  "=",
	Vertical:    "|",
}

// Double box for extra emphasis
var DoubleBox = struct {
	TopLeft     string
	TopRight    string
	BottomLeft  string
	BottomRight string
	Horizontal  string
	Vertical    string
}{
	TopLeft:     "+",
	TopRight:    "+",
	BottomLeft:  "+",
	BottomRight: "+",
	Horizontal:  "=",
	Vertical:    "|",
}
