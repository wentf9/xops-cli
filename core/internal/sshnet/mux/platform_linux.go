//go:build linux

package mux

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/osfs"
)

// formatPeerDetail 将 Linux SO_PEERCRED 对端凭据格式化为非敏感诊断标签。
func formatPeerDetail(cred osfs.PeerCred) string {
	uid, _ := cred.UID()
	pid, hasPID := cred.PID()
	if hasPID {
		return fmt.Sprintf("linux(uid=%d,pid=%d)", uid, pid)
	}
	return fmt.Sprintf("linux(uid=%d)", uid)
}
