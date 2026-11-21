//go:build !windows

package sftpshell

import (
	"context"
	"os"
)

func renameCommandHistory(_ context.Context, source, destination string) error {
	return os.Rename(source, destination)
}
