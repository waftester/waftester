package ui

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

var (
	unicodeOnce sync.Once
	unicodeOK   bool
)

// UnicodeTerminal reports whether stderr can render Unicode glyphs
// (braille spinners, emoji). Returns false when output is piped,
// redirected, TERM is "dumb", or on Windows without Windows Terminal.
//
// On Windows, legacy consoles (conhost, older PowerShell) cannot render
// braille or emoji even with SetConsoleOutputCP(65001) because the
// default fonts lack those glyphs. Windows Terminal (detected via
// WT_SESSION) handles them correctly.
func UnicodeTerminal() bool {
	unicodeOnce.Do(func() {
		if os.Getenv("TERM") == "dumb" {
			return
		}
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			return
		}
		if runtime.GOOS == "windows" {
			// Windows Terminal sets WT_SESSION; legacy conhost does not.
			unicodeOK = os.Getenv("WT_SESSION") != ""
			return
		}
		unicodeOK = true
	})
	return unicodeOK
}

// DefaultSpinner returns a braille-dot spinner on Unicode terminals,
// ASCII line spinner (-\|/) otherwise.
func DefaultSpinner() Spinner {
	if UnicodeTerminal() {
		return Spinners[SpinnerDots]
	}
	return Spinners[SpinnerLine]
}

// Icon returns unicode when the terminal supports it, ascii otherwise.
// Use at every call site that renders emoji or special characters to
// stderr/stdout: ui.Icon("✅", "[+]")
func Icon(unicode, ascii string) string {
	if UnicodeTerminal() {
		return unicode
	}
	return ascii
}

// SanitizeString strips emoji and multi-byte Unicode symbols from s
// when the terminal cannot render them. On Unicode-capable terminals,
// returns s unchanged.
//
// This is applied automatically by Print* functions so callers can
// embed emoji directly without wrapping each one in Icon().
func SanitizeString(s string) string {
	if UnicodeTerminal() {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r < 0x80:
			// ASCII — always safe
			b.WriteByte(s[i])
		case isVariationSelector(r):
			// Variation selectors (U+FE00–U+FE0F) — drop silently
		case isSafeForLegacy(r):
			b.WriteRune(r)
		default:
			// Emoji, braille, block chars, symbols — drop
		}
		i += size
	}
	return b.String()
}

// Sanitizef formats a string and sanitizes it for the current terminal.
// Drop-in replacement for fmt.Sprintf when the result goes to the terminal.
func Sanitizef(format string, args ...interface{}) string {
	return SanitizeString(fmt.Sprintf(format, args...))
}

// Printf writes to stdout with terminal-appropriate sanitization.
// Drop-in replacement for fmt.Printf when output may contain emoji.
func Printf(format string, args ...interface{}) {
	fmt.Print(Sanitizef(format, args...))
}

// Fprintf writes to w with terminal-appropriate sanitization.
// Drop-in replacement for fmt.Fprintf when output may contain emoji.
func Fprintf(w io.Writer, format string, args ...interface{}) {
	fmt.Fprint(w, Sanitizef(format, args...))
}

// isVariationSelector returns true for Unicode variation selectors
// that modify the preceding character's display (e.g., U+FE0F emoji style).
func isVariationSelector(r rune) bool {
	return r >= 0xFE00 && r <= 0xFE0F
}

// isSafeForLegacy returns true for runes that legacy Windows consoles
// can typically render: Latin scripts, common punctuation, box-drawing
// from the CP437/CP850 range. Excludes emoji, braille, block elements,
// and other glyphs that require modern font support.
func isSafeForLegacy(r rune) bool {
	if r <= 0xFF {
		// Latin-1 Supplement — accented letters, common symbols
		return true
	}
	// Allow common typographic characters that render in most fonts
	if unicode.Is(unicode.Latin, r) {
		return true
	}
	// Box-drawing (U+2500–U+257F) and block elements (U+2580–U+259F)
	// are hit-or-miss on legacy consoles. Exclude them — they're the
	// exact characters causing the garbled progress bars.
	return false
}
