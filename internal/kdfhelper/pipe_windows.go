//go:build windows && (amd64 || arm64)

package kdfhelper

import (
	"golang.org/x/sys/windows"
	"os"
	"time"
)

func pollablePipe(file *os.File) (*os.File, error) {
	st, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeNamedPipe == 0 {
		return nil, ErrProtocol
	}
	process := windows.CurrentProcess()
	var handle windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(file.Fd()), process, &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), "private-kdf-pipe"), nil
}

// Inherited Windows anonymous pipes are synchronous. The parent enforces the
// request deadline and parent-death cleanup through its kill-on-close job.
func setWorkerDeadlines(*os.File, *os.File, time.Time) error { return nil }
