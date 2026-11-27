//go:build unix

package osfs

import (
	"context"
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"golang.org/x/sys/unix"
	"io/fs"
	"net"
	"os"
	"syscall"
)

type socketFileID = os.FileInfo

func sameSocketFileID(a, b socketFileID) bool { return a != nil && b != nil && os.SameFile(a, b) }
func validateControlSocketPathOS(raw string) (ControlSocketPath, error) {
	return ValidateUnixControlSocketPath(raw, maxUnixSocketPathBytesOS())
}
func isConnRefusedOS(err error) bool       { return errors.Is(err, syscall.ECONNREFUSED) }
func isAddrInUseOS(err error) bool         { return errors.Is(err, syscall.EADDRINUSE) }
func isSocketUnlinkRetryableOS(error) bool { return false }
func inspectSocketEntryOS(nativePath string) (socketFileID, SocketProbeStatus, error) {
	fi, err := os.Lstat(nativePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, SocketProbeMissing, nil
		}
		return nil, SocketProbeUnknown, mapOSError(err)
	}
	return fi, pickIf(fi.Mode()&fs.ModeSocket == 0, SocketProbeNotSocket, SocketProbeUnknown), nil
}
func verifySocketTargetBeforeDialOS(nativePath string) error {
	_, status, err := inspectSocketEntryOS(nativePath)
	switch {
	case err != nil:
		return err
	case status == SocketProbeMissing:
		return mapOSError(os.ErrNotExist)
	case status == SocketProbeNotSocket:
		return domi18n.EF(ErrNotSocket, domi18n.KeyOSFSNotUnixSocket, domi18n.BoundStr("path", nativePath))
	}
	return nil
}

//xops:syncclosure
func withSocketDirLockOS(ctx context.Context, dir string, createDir bool, fn func() error) error {
	if createDir {
		if err := ensureDirRawUnix(dir, defaultDirPerm); err != nil {
			return err
		}
	}
	dirFile, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapOSError(err)
	}
	defer func() { _ = dirFile.Close() }()
	if err := lockFileWithContext(ctx, dirFile, true); err != nil {
		return err
	}
	defer func() { _ = unlockFileOS(dirFile) }()
	return fn()
}
func listenSocketLockedOS(ctx context.Context, path ControlSocketPath) (*net.UnixListener, socketFileID, error) {
	target := path.NativePath()
	tok, err := randomHexToken(4)
	if err != nil {
		return nil, nil, err
	}
	if tmpPath := target + "." + tok; len(tmpPath) <= maxUnixSocketPathBytesOS() {
		uln, origID, err := bindUnixDirect(ctx, tmpPath)
		if err != nil {
			return nil, nil, err
		}
		if lErr := os.Link(tmpPath, target); lErr != nil {
			return nil, nil, cleanupSocketBind(uln, tmpPath, pickIf(errors.Is(lErr, os.ErrExist), domi18n.EF(ErrSlotOccupied, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "link_socket"), domi18n.BoundStr("target", target)), mapOSError(lErr)))
		}
		_ = os.Remove(tmpPath)
		return uln, origID, nil
	}
	return bindUnixDirect(ctx, target)
}
func bindUnixDirect(ctx context.Context, addr string) (*net.UnixListener, socketFileID, error) {
	uln, err := listenUnixNoAutoUnlink(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(addr, defaultFilePerm); err != nil {
		return nil, nil, cleanupSocketBind(uln, addr, mapOSError(err))
	}
	origID, err := os.Lstat(addr)
	if err != nil {
		return nil, nil, cleanupSocketBind(uln, addr, mapOSError(err))
	}
	return uln, origID, nil
}

// verifyPeerCurrentUserFD 在 Unix 上核验本地 AF_UNIX 对端 UID 与当前进程 EUID 一致。
func verifyPeerCurrentUserFD(fd uintptr) (PeerCred, error) {
	cred, err := queryPeerCredFD(fd)
	if err != nil {
		return PeerCred{}, err
	}
	if !cred.IsValid() || !cred.hasUID {
		return PeerCred{}, domi18n.EF(ErrUnauthorizedPeer, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "peer_uid"))
	}
	if wantUID := uint32(os.Geteuid()); cred.uid != wantUID {
		return PeerCred{}, domi18n.EF(ErrUnauthorizedPeer, domi18n.KeyOSFSPeerUIDMismatch, domi18n.Uint64("actual", uint64(cred.uid)), domi18n.Uint64("expected", uint64(wantUID)))
	}
	return cred, nil
}
