//go:build darwin && (amd64 || arm64)

package credentialfile

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func mountID(file *os.File) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &st); err != nil {
		return 0, fmt.Errorf("identify vault filesystem: %w", err)
	}
	return uint64(uint32(st.Fsid.Val[0]))<<32 | uint64(uint32(st.Fsid.Val[1])), nil
}
