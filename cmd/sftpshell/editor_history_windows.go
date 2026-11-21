//go:build windows

package sftpshell

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func renameCommandHistory(ctx context.Context, source, destination string) error {
	return retryHistoryRename(ctx, func() error { return os.Rename(source, destination) }, isHistoryRenameRetryable)
}

func isHistoryRenameRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
