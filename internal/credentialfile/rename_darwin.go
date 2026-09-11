//go:build darwin && (amd64 || arm64)

package credentialfile

import "golang.org/x/sys/unix"

func renameVaultEntry(fromFD int, from string, toFD int, to string, exclusive bool) error {
	if !exclusive {
		return unix.Renameat(fromFD, from, toFD, to)
	}
	return unix.RenameatxNp(fromFD, from, toFD, to, unix.RENAME_EXCL)
}
