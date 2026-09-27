package mcpserver

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Winsock uses different error numbers from syscall.ECONNRESET/ECONNABORTED.
// These errors are expected when this fixture's SSH peer tears down a tunnel.
func platformTunnelFixtureClose(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED)
}

func TestWindowsTunnelFixtureConnectionCloseErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{windows.WSAECONNRESET, true}, {windows.WSAECONNABORTED, true},
		{windows.WSAETIMEDOUT, false}, {windows.WSAECONNREFUSED, false},
		{windows.WSAEACCES, false}, {windows.ERROR_ACCESS_DENIED, false},
	} {
		wrapped := &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{Syscall: "wsasend", Err: tc.err}}
		for _, err := range []error{tc.err, wrapped} {
			if got := expectedTunnelFixtureClose(err); got != tc.want {
				t.Errorf("close classification for %v = %t, want %t", err, got, tc.want)
			}
		}
	}
}
