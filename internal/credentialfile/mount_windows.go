//go:build windows && (amd64 || arm64)

package credentialfile

import (
	"github.com/wentf9/xops-cli/internal/vaultsys"
	"os"
)

// Reparse points are rejected on every opened path component. Volume identity
// therefore also detects crossing onto another mounted volume.
func mountID(file *os.File) (uint64, error) {
	var st vaultsys.Stat_t
	err := vaultsys.Fstat(int(file.Fd()), &st)
	return st.Dev, err
}
func renameVaultEntry(fromFD int, from string, toFD int, to string, exclusive bool) error {
	return vaultsys.RenameEntry(fromFD, from, toFD, to, exclusive)
}
