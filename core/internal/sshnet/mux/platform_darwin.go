//go:build darwin

package mux

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/osfs"
)

// formatPeerDetail 将 macOS LOCAL_PEERCRED/LOCAL_PEERPID 对端凭据格式化为非敏感诊断标签。
func formatPeerDetail(cred osfs.PeerCred) string {
	uid, _ := cred.UID()
	pid, hasPID := cred.PID()
	if hasPID {
		return fmt.Sprintf("darwin(uid=%d,pid=%d)", uid, pid)
	}
	return fmt.Sprintf("darwin(uid=%d)", uid)
}
