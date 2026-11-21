//go:build linux

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func prepareFileOutput(ctx context.Context, source *os.File, perWrite time.Duration) (io.Writer, func() error, error) {
	owned, err := reopenNonBlockingWriteFile(source)
	if err != nil {
		return nil, nil, err
	}
	return bindOwnedFileOutput(ctx, owned, source, perWrite)
}

func reopenNonBlockingWriteFile(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, fmt.Errorf("terminal output is nil")
	}
	info, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect terminal output: %w", err)
	}
	if info.Mode()&(os.ModeNamedPipe|os.ModeCharDevice) == 0 {
		return nil, fmt.Errorf("cancelable PTY output requires a terminal or pipe; use a ContextWriter for regular files")
	}
	// Reopen inside raw.Control so Go's poll.FD reference count pins descriptor
	// against concurrent Close()+FD-reuse while /proc/self/fd/%d is opened.
	var (
		owned   *os.File
		openErr error
	)
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("access terminal output descriptor: %w", err)
	}
	if err := raw.Control(func(fd uintptr) {
		owned, openErr = os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", fd), os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0) //nolint:forbidigo // reopen pinned terminal /proc/self/fd descriptor with independent non-blocking file description
	}); err != nil {
		if owned != nil {
			_ = owned.Close()
		}
		return nil, fmt.Errorf("inspect terminal output descriptor: %w", err)
	}
	if openErr != nil {
		return nil, fmt.Errorf("open owned terminal output: %w", openErr)
	}
	openedInfo, statErr := owned.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		return nil, errors.Join(
			fmt.Errorf("native output identity changed while opening"),
			statErr,
			closeResource(owned, "owned terminal output"),
		)
	}
	return owned, nil
}
