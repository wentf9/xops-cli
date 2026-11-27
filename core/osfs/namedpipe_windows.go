//go:build windows

package osfs

import (
	"context"
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/osfs/internal/winpipe"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
	"net"
	"strings"
)

const winPipePrefix, winPipeOpenFlags = `\\.\pipe\`, windows.FILE_FLAG_OVERLAPPED | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION

// DialWindowsNamedPipeVerified 以受控 QoS 与服务端所有者/DACL 强校验拨号本地 Windows 命名管道（\\.\pipe\<name>），
// 并以全双工独立重叠 I/O 封装为无数据竞争的 net.Conn。
func DialWindowsNamedPipeVerified(ctx context.Context, pipePath string) (net.Conn, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	norm, pathPtr, err := parseWindowsPipeUTF16(pipePath)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	if err = retryLockBackoff(ctx, func() (bool, error) {
		handle, cErr := windows.CreateFile(pathPtr, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, winPipeOpenFlags, 0)
		h = handle
		return cErr == nil, pickIf[error](cErr == nil || errors.Is(cErr, windows.ERROR_PIPE_BUSY), nil, mapWindowsOpenError(norm, cErr))
	}); err != nil {
		return nil, err
	}
	if err = verifyNamedPipeHandle(h, norm); err == nil {
		var conn *winpipe.Conn
		if conn, err = winpipe.NewConn(h, norm); err == nil {
			return conn, nil
		}
		err = mapOSError(err)
	}
	_ = windows.CloseHandle(h)
	return nil, err
}

func parseWindowsPipeUTF16(raw string) (string, *uint16, error) {
	slashed := strings.ReplaceAll(raw, "/", `\`)
	if raw == "" || hasForbiddenControlPathRune(raw) || len(slashed) <= len(winPipePrefix) || !strings.EqualFold(slashed[:len(winPipePrefix)], winPipePrefix) || strings.ContainsRune(slashed[len(winPipePrefix):], ':') {
		return "", nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyOSFSNamedPipeInvalid, domi18n.BoundStr("path", raw))
	}
	rest := slashed[len(winPipePrefix):]
	for seg := range strings.SplitSeq(rest, `\`) {
		if seg == "" || seg == "." || seg == ".." || strings.TrimRight(seg, ". ") == "" || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return "", nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyOSFSNamedPipeInvalid, domi18n.BoundStr("path", seg))
		}
	}
	norm := winPipePrefix + rest
	ptr, err := windows.UTF16PtrFromString(norm)
	return norm, ptr, pickIf[error](err != nil, wrapS(ports.ErrInvalidArgument, err), nil)
}

func verifyNamedPipeHandle(h windows.Handle, norm string) error {
	if ft, err := windows.GetFileType(h); err != nil || ft != windows.FILE_TYPE_PIPE {
		return pickIf[error](err != nil, mapOSError(err), domi18n.EF(ErrNotSocket, domi18n.KeyOSFSNamedPipeInvalid, domi18n.BoundStr("path", norm)))
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return wrapOp(ErrUnauthorizedPeer, err, "CurrentProcessUserSID")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return wrapOp(ErrUnauthorizedPeer, pickIf[error](err != nil, err, ErrInsecurePermissions), "GetSecurityInfo")
	}
	owner, _, oErr := sd.Owner()
	dacl, _, dErr := sd.DACL()
	if oErr != nil || owner == nil || dErr != nil || dacl == nil {
		return domi18n.EF(ErrUnauthorizedPeer, domi18n.KeyOSFSDACLCheckFailed, domi18n.BoundStr("path", norm))
	}
	if aces, aErr := parseWindowsACL(dacl, currSID); aErr != nil || EvaluateWindowsObjectACL(WindowsACLInput{Mode: WindowsACLPipeServerSafe, OwnerTrusted: IsTrustedPrincipalSID(owner, currSID), HasDACL: true, ACEs: aces}) != security.VerdictAllow {
		return domi18n.WrapS(ErrUnauthorizedPeer, pickIf[error](aErr != nil, aErr, ErrInsecurePermissions), domi18n.KeyOSFSDACLCheckFailed, domi18n.BoundStr("path", norm))
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err == nil && pid != 0 {
		if peerSID, pErr := ProcessUserSID(pid); pErr == nil && !IsTrustedPrincipalSID(peerSID, currSID) {
			return domi18n.EF(ErrUnauthorizedPeer, domi18n.KeyOSFSPeerSIDMismatch, domi18n.Uint64("pid", uint64(pid)))
		}
	}
	return nil
}
