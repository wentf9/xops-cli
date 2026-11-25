//go:build linux

package osfs

import (
	"fmt"
	"golang.org/x/sys/unix"
)

func maxUnixSocketPathBytesOS() int { return 107 } // Linux sockaddr_un.sun_path = 108 - 1
func isBSDFileTypeErr(error) bool   { return false }

// queryPeerCredFD 在 Linux 上经 SO_PEERCRED 查询本地 AF_UNIX 对端 UID/GID/PID。
func queryPeerCredFD(fd uintptr) (PeerCred, error) {
	ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return PeerCred{}, fmt.Errorf("%w: getsockopt(SO_PEERCRED) 失败: %w", ErrUnauthorizedPeer, err)
	}
	return PeerCred{uid: ucred.Uid, gid: ucred.Gid, pid: uint32(ucred.Pid), hasUID: true, hasGID: true, hasPID: ucred.Pid > 0, valid: true}, nil
}
