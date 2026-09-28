//go:build !windows

package testpty

import (
	"fmt"
	"os"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

type Winsize = pty.Winsize

// Setsize keeps the window-size buffer reachable through the ioctl call.
func Setsize(file *os.File, size *Winsize) error {
	err := unix.IoctlSetWinsize(int(file.Fd()), unix.TIOCSWINSZ, &unix.Winsize{
		Row: size.Rows, Col: size.Cols, Xpixel: size.X, Ypixel: size.Y,
	})
	if err != nil {
		return fmt.Errorf("set PTY window size: %w", err)
	}
	return nil
}
