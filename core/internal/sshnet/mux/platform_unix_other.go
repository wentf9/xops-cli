//go:build unix && !linux && !darwin && !freebsd

package mux

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/osfs"
)

// formatPeerDetail 为其他 Unix 平台提供统一对端凭据诊断标签。
func formatPeerDetail(cred osfs.PeerCred) string {
	uid, _ := cred.UID()
	return fmt.Sprintf("unix(uid=%d)", uid)
}
