//go:build !windows

package ssh

import (
	"io"

	"github.com/wentf9/xops-cli/core/fsx"
)

// openGlobalKnownHostsFile opens a read-only global known_hosts file handle-first
// using fsx.OpenRegular with fsx.FollowSymlinks() because system-wide global
// known_hosts files (such as /etc/ssh/ssh_known_hosts on Linux/NixOS) may be
// legitimately symlinked.
func openGlobalKnownHostsFile(filename string, limit int64) (io.ReadCloser, error) {
	return fsx.OpenRegular(filename, fsx.Limits{MaxBytes: limit}, fsx.FollowSymlinks())
}
