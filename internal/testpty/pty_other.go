//go:build !linux && !windows

package testpty

import (
	"os"

	"github.com/creack/pty"
)

// Open returns a PTY pair. The caller owns both files.
func Open() (*os.File, *os.File, error) {
	return pty.Open()
}
