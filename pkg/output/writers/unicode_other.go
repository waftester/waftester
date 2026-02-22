//go:build !windows

package writers

import "io"

// unicodeSupported returns true on non-Windows platforms.
// Modern Unix terminals universally support UTF-8.
func unicodeSupported(_ io.Writer) bool {
	return true
}
