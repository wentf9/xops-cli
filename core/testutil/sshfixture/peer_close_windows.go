package sshfixture

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Winsock reset/abort codes differ from the portable syscall error constants.
func platformPeerClosure(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNABORTED)
}
