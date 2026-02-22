//go:build windows

package writers

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

// unicodeSupported checks if the current Windows console can render
// UTF-8 box-drawing characters. Returns false when output is piped
// through PowerShell (which re-encodes bytes using [Console]::OutputEncoding,
// typically the system OEM codepage) or the console output codepage isn't UTF-8.
func unicodeSupported(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		// Programmatic writer (bytes.Buffer, strings.Builder, etc.) —
		// bytes go directly to the consumer without console re-encoding.
		return true
	}

	// If output isn't a terminal (piped), PowerShell re-encodes bytes
	// using its own encoding, not the console codepage. UTF-8 box-drawing
	// characters won't survive the translation.
	if !term.IsTerminal(int(f.Fd())) {
		return false
	}

	// Verify the console output codepage is actually UTF-8 (65001).
	// SetConsoleOutputCP(65001) is called in init(), but may not stick
	// in all terminal environments.
	const cpUTF8 = 65001
	cp, err := windows.GetConsoleOutputCP()
	return err == nil && cp == cpUTF8
}
