//go:build unix

package osfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
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
	if fi.Mode()&fs.ModeSocket == 0 {
		return fi, SocketProbeNotSocket, nil
	}
	return fi, SocketProbeUnknown, nil
}

func verifySocketTargetBeforeDialOS(nativePath string) error {
	switch _, status, err := inspectSocketEntryOS(nativePath); {
	case err != nil:
		return err
	case status == SocketProbeMissing:
		return mapOSError(os.ErrNotExist)
	case status == SocketProbeNotSocket:
		return fmt.Errorf("%w: %q 不是 Unix 套接字", ErrNotSocket, nativePath)
	default:
		return nil
	}
}

//xops:syncclosure
func withSocketDirLockOS(ctx context.Context, dir string, _ bool, fn func() error) error {
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
		if err := os.Link(tmpPath, target); err != nil {
			if errors.Is(err, os.ErrExist) {
				err = fmt.Errorf("%w: %q", ErrSlotOccupied, target)
			} else {
				err = mapOSError(err)
			}
			return nil, nil, cleanupSocketBind(uln, tmpPath, err)
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
		return PeerCred{}, fmt.Errorf("%w: 对端凭据缺少有效 UID", ErrUnauthorizedPeer)
	}
	if wantUID := uint32(os.Geteuid()); cred.uid != wantUID {
		return PeerCred{}, fmt.Errorf("%w: 对端 UID %d 与当前 EUID %d 不匹配", ErrUnauthorizedPeer, cred.uid, wantUID)
	}
	return cred, nil
}
