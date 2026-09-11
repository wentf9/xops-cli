//go:build linux && (amd64 || arm64)

package credentialfile

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type renameNoReplaceFunc func(int, string, int, string, uint) error

// Replacement already has POSIX rename semantics and needs no renameat2.
// Exclusive publication must preserve atomic no-replace semantics; unsupported
// kernels are identified explicitly, never emulated with a racy existence check.
func renameVaultEntry(fromFD int, from string, toFD int, to string, exclusive bool) error {
	if !exclusive {
		return unix.Renameat(fromFD, from, toFD, to)
	}
	return renameExclusiveWith(unix.Renameat2, fromFD, from, toFD, to)
}

func renameExclusiveWith(rename renameNoReplaceFunc, fromFD int, from string, toFD int, to string) error {
	err := rename(fromFD, from, toFD, to, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("filesystem cannot atomically publish without replacement: %w", errors.Join(ErrUnsupported, err))
	}
	return err
}
