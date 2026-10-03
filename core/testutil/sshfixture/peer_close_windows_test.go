package sshfixture

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRecordWindowsPeerClosure(t *testing.T) {
	unexpected := errors.New("unexpected fixture failure")
	for _, tc := range []struct {
		err    error
		retain bool
	}{
		{windows.WSAECONNRESET, false}, {windows.WSAECONNABORTED, false},
		{windows.WSAETIMEDOUT, true}, {windows.WSAECONNREFUSED, true},
		{windows.WSAEACCES, true}, {windows.ERROR_ACCESS_DENIED, true},
		{errors.Join(windows.WSAECONNRESET, unexpected), true},
	} {
		wrapped := &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{Syscall: "wsasend", Err: tc.err}}
		for _, err := range []error{tc.err, wrapped} {
			server := &Server{ctx: t.Context()}
			server.record(err)
			if tc.retain {
				if len(server.errors) != 1 || !errors.Is(server.errors[0], err) {
					t.Errorf("lost fixture error %v: %v", err, server.errors)
				}
			} else if len(server.errors) != 0 {
				t.Errorf("peer closure %v became a fixture failure: %v", err, server.errors)
			}
		}
	}
}
