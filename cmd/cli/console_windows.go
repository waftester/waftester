//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func init() {
	// Set console code page to UTF-8 so emojis and Unicode characters
	// render correctly on Windows terminals. This works when the Go
	// program writes directly to the console (cmd.exe, Windows Terminal,
	// or PowerShell without output redirection). When PowerShell pipes
	// output (e.g., 2>&1), it uses [Console]::OutputEncoding which
	// must be set separately by the user/profile.
	const cpUTF8 = 65001
	windows.SetConsoleOutputCP(cpUTF8)
	windows.SetConsoleCP(cpUTF8)

	// Enable virtual terminal processing for ANSI escape sequences
	// (colors, bold, etc.) on Windows 10+ terminals.
	for _, stdHandle := range []uint32{windows.STD_ERROR_HANDLE, windows.STD_OUTPUT_HANDLE} {
		if h, err := windows.GetStdHandle(stdHandle); err == nil {
			var mode uint32
			if windows.GetConsoleMode(h, &mode) == nil {
				_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
			}
		}
	}
}
