//go:build windows

package osfs

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"unsafe"
)

const (
	windowsSocketDirLockName        = ".xops-socket-slot.lock"
	sioAFUnixGetPeerPID      uint32 = windows.IOC_OUT | windows.IOC_VENDOR | 256
)

func maxUnixSocketPathBytesOS() int { return 107 } // Windows <afunix.h> UNIX_PATH_MAX - 1

// socketFileID 在 Windows 上以急切读取的 (VolumeSerialNumber, FileIndexHigh, FileIndexLow)
// 锚定套接字身份，规避 Go os.Lstat 延迟 loadFileId 的 TOCTOU 竞态。
type socketFileID struct {
	vol, idxHi, idxLo uint32
	valid             bool
}

func sameSocketFileID(a, b socketFileID) bool { return a.valid && b.valid && a == b }
func validateControlSocketPathOS(raw string) (ControlSocketPath, error) {
	return ValidateWindowsControlSocketPath(raw, maxUnixSocketPathBytesOS())
}
func verifySocketTargetBeforeDialOS(nativePath string) error {
	return VerifyOwnerOnlySocketByHandle(nativePath)
}
func isConnRefusedOS(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }
func isAddrInUseOS(err error) bool   { return errors.Is(err, windows.WSAEADDRINUSE) }
func isSocketUnlinkRetryableOS(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
func inspectSocketEntryOS(nativePath string) (socketFileID, SocketProbeStatus, error) {
	handle, info, openErr := openObjectHandleInfoNoFollow(nativePath, windows.READ_CONTROL)
	if openErr != nil {
		if mapped := mapWindowsOpenError(nativePath, openErr); errors.Is(mapped, ports.ErrNotFound) {
			return socketFileID{}, SocketProbeMissing, nil
		} else {
			return socketFileID{}, SocketProbeUnknown, mapped
		}
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	id := socketFileID{vol: info.VolumeSerialNumber, idxHi: info.FileIndexHigh, idxLo: info.FileIndexLow, valid: true}
	return id, pickIf(verifyAFUnixReparseHandle(handle, nativePath) != nil, SocketProbeNotSocket, SocketProbeUnknown), nil
}

//xops:syncclosure
func withSocketDirLockOS(ctx context.Context, dir string, createDir bool, fn func() error) error {
	if createDir {
		if err := EnsureOwnerOnlyDirectory(dir); err != nil {
			return err
		}
	} else if err := verifyOwnerOnlyPathByHandle(dir, true, false, nil); err != nil {
		return err
	}
	f, err := createWindowsOwnerOnlyFile(filepath.Join(dir, windowsSocketDirLockName), windows.OPEN_ALWAYS)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if err := lockFileWithContext(ctx, f, true); err != nil {
		return err
	}
	defer func() { _ = unlockFileOS(f) }()
	return fn()
}
func listenSocketLockedOS(ctx context.Context, path ControlSocketPath) (*net.UnixListener, socketFileID, error) {
	addr := path.NativePath()
	uln, err := listenUnixNoAutoUnlink(ctx, addr)
	if err != nil {
		return nil, socketFileID{}, err
	}
	if err := errors.Join(HardenSocketOwnerOnly(addr), VerifyOwnerOnlySocketByHandle(addr)); err != nil {
		return nil, socketFileID{}, cleanupSocketBind(uln, addr, err)
	}
	origID, status, err := inspectSocketEntryOS(addr)
	if err != nil || status != SocketProbeUnknown || !origID.valid {
		return nil, socketFileID{}, cleanupSocketBind(uln, addr, pickIf[error](err != nil, err, ErrNotSocket))
	}
	return uln, origID, nil
}

// queryPeerCredFD 在 Windows 上经 WSAIoctl(SIO_AF_UNIX_GETPEERPID) 查询对端 PID。
// Windows afunix.sys/afd.sys 写入 4 字节 ULONG PID 后可能保持 bytesReturned == 0，
// 因此仅当调用成功、bytesReturned 为 0 或 4 且 peerPID != 0 时放行，其余一律 fail-closed。
func queryPeerCredFD(fd uintptr) (PeerCred, error) {
	var peerPID, bytesReturned uint32
	err := windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
		(*byte)(unsafe.Pointer(&peerPID)), uint32(unsafe.Sizeof(peerPID)), &bytesReturned, nil, 0)
	if err != nil {
		if errors.Is(err, windows.WSAEOPNOTSUPP) || errors.Is(err, windows.WSAEINVAL) || errors.Is(err, windows.WSAENOPROTOOPT) {
			return PeerCred{}, fmt.Errorf("%w: %w: %w", ErrUnauthorizedPeer, ErrUnsupportedPeerCred, err)
		}
		return PeerCred{}, fmt.Errorf("%w: WSAIoctl(SIO_AF_UNIX_GETPEERPID) 失败: %w", ErrUnauthorizedPeer, err)
	}
	if (bytesReturned != 0 && bytesReturned != uint32(unsafe.Sizeof(peerPID))) || peerPID == 0 {
		return PeerCred{}, fmt.Errorf("%w: SIO_AF_UNIX_GETPEERPID 返回异常 (bytes=%d, pid=%d)", ErrUnauthorizedPeer, bytesReturned, peerPID)
	}
	return PeerCred{pid: peerPID, hasPID: true, valid: true}, nil
}

// verifyPeerCurrentUserFD 在 Windows 上核验对端进程令牌用户 SID 与当前进程一致（fail-closed）。
func verifyPeerCurrentUserFD(fd uintptr) (PeerCred, error) {
	cred, err := queryPeerCredFD(fd)
	if err != nil || cred.pid == uint32(os.Getpid()) {
		return cred, err
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return PeerCred{}, fmt.Errorf("%w: 查询当前用户 SID 失败: %w", ErrUnauthorizedPeer, err)
	}
	peerSID, err := ProcessUserSID(cred.pid)
	if err != nil {
		return PeerCred{}, fmt.Errorf("%w: 查询对端 PID %d SID 失败: %w", ErrUnauthorizedPeer, cred.pid, err)
	}
	if !peerSID.IsValid() || !currSID.IsValid() || !peerSID.Equals(currSID) {
		return PeerCred{}, fmt.Errorf("%w: 对端进程 PID %d 用户 SID 不匹配", ErrUnauthorizedPeer, cred.pid)
	}
	return cred, nil
}
