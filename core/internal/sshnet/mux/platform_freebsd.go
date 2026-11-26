//go:build freebsd

package mux

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/osfs"
)

// formatPeerDetail 将 FreeBSD LOCAL_PEERCRED 对端凭据格式化为非敏感诊断标签。
func formatPeerDetail(cred osfs.PeerCred) string {
	uid, _ := cred.UID()
	return fmt.Sprintf("freebsd(uid=%d)", uid)
}
