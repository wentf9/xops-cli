//go:build freebsd

package osfs

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
)

func maxUnixSocketPathBytesOS() int   { return 103 } // FreeBSD sockaddr_un.sun_path = 104 - 1
func isBSDFileTypeErr(err error) bool { return errors.Is(err, unix.EFTYPE) }

// queryPeerCredFD 在 FreeBSD 上经 LOCAL_PEERCRED 查询本地 AF_UNIX 对端 UID/GID。
func queryPeerCredFD(fd uintptr) (PeerCred, error) {
	xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerCred{}, fmt.Errorf("%w: getsockopt(LOCAL_PEERCRED) 失败: %w", ErrUnauthorizedPeer, err)
	}
	cred := PeerCred{uid: xucred.Uid, hasUID: true, valid: true}
	if xucred.Ngroups > 0 {
		cred.gid, cred.hasGID = xucred.Groups[0], true
	}
	return cred, nil
}
