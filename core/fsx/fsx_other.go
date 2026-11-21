//go:build !unix && !windows

package fsx

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

func openRegularOS(path string, l Limits, cfg openConfig) (*RegularFile, error) {
	if cfg.allowDevNull && IsDevNullPath(path) {
		return newDevNullRegularFile(path, l.MaxBytes, nil), nil
	}
	return nil, fmt.Errorf("%w: OpenRegular on %s", ErrUnsupported, runtime.GOOS)
}

func createExclusiveOS(_ string, _ os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("%w: CreateExclusive on %s", ErrUnsupported, runtime.GOOS)
}

func openExistingRegularForLockOS(_ string, _ bool) (*os.File, error) {
	return nil, fmt.Errorf("%w: OpenLocked on %s", ErrUnsupported, runtime.GOOS)
}

func lockFileOS(_ *os.File, _ bool) error {
	return fmt.Errorf("%w: file locking on %s", ErrUnsupported, runtime.GOOS)
}

func unlockFileOS(_ *os.File) error {
	return nil
}

func bindSocketSlotOS(_ string, _ ListenFunc, _ bool, _ func() bool) (*SocketSlot, error) {
	return nil, fmt.Errorf("%w: SocketSlot on %s", ErrUnsupported, runtime.GOOS)
}

func pruneStaleSocketOS(_ string, _ os.FileInfo, _ func() bool) (StaleSocketOutcome, error) {
	return StaleSocketLive, fmt.Errorf("%w: SocketSlot on %s", ErrUnsupported, runtime.GOOS)
}

func releaseSocketSlotOS(_ string, _ os.FileInfo, ln net.Listener) error {
	if ln != nil {
		return ln.Close()
	}
	return nil
}

func isConnRefusedOS(_ error) bool {
	return false
}
