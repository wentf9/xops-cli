//go:build darwin

package osfs

import (
	"errors"
	"golang.org/x/sys/unix"
)

func maxUnixSocketPathBytesOS() int   { return 103 } // Darwin sockaddr_un.sun_path = 104 - 1
func isBSDFileTypeErr(err error) bool { return errors.Is(err, unix.EFTYPE) }

// queryPeerCredFD 在 macOS 上经 LOCAL_PEERCRED 与 LOCAL_PEERPID 查询本地 AF_UNIX 对端凭据。
func queryPeerCredFD(fd uintptr) (PeerCred, error) {
	xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerCred{}, wrapOp(ErrUnauthorizedPeer, err, "getsockopt(LOCAL_PEERCRED)")
	}
	cred := PeerCred{uid: xucred.Uid, hasUID: true, valid: true}
	if xucred.Ngroups > 0 {
		cred.gid, cred.hasGID = xucred.Groups[0], true
	}
	if pid, pidErr := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); pidErr == nil && pid > 0 {
		cred.pid, cred.hasPID = uint32(pid), true
	}
	return cred, nil
}
