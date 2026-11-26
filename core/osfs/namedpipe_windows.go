//go:build windows

package osfs

import (
	"context"
	"errors"
	"fmt"
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
		return "", nil, fmt.Errorf("%w: 仅允许本地 \\\\.\\pipe\\<name> 路径", ports.ErrInvalidArgument)
	}
	rest := slashed[len(winPipePrefix):]
	for seg := range strings.SplitSeq(rest, `\`) {
		if seg == "" || seg == "." || seg == ".." || strings.TrimRight(seg, ". ") == "" || strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return "", nil, fmt.Errorf("%w: 命名管道段 %q 非法", ports.ErrInvalidArgument, seg)
		}
	}
	norm := winPipePrefix + rest
	ptr, err := windows.UTF16PtrFromString(norm)
	return norm, ptr, pickIf[error](err != nil, fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err), nil)
}

func verifyNamedPipeHandle(h windows.Handle, norm string) error {
	if ft, err := windows.GetFileType(h); err != nil || ft != windows.FILE_TYPE_PIPE {
		return pickIf[error](err != nil, mapOSError(err), fmt.Errorf("%w: %q 不是命名管道", ErrNotSocket, norm))
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("%w: 查询当前用户 SID 失败: %w", ErrUnauthorizedPeer, err)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: 查询管道安全描述符失败: %w", ErrUnauthorizedPeer, pickIf[error](err != nil, err, ErrInsecurePermissions))
	}
	owner, _, oErr := sd.Owner()
	dacl, _, dErr := sd.DACL()
	if oErr != nil || owner == nil || dErr != nil || dacl == nil {
		return fmt.Errorf("%w: 管道 %q 缺少所有者或 DACL", ErrUnauthorizedPeer, norm)
	}
	if aces, aErr := parseWindowsACL(dacl, currSID); aErr != nil || EvaluateWindowsObjectACL(WindowsACLInput{Mode: WindowsACLPipeServerSafe, OwnerTrusted: IsTrustedPrincipalSID(owner, currSID), HasDACL: true, ACEs: aces}) != security.VerdictAllow {
		return fmt.Errorf("%w: 管道 %q 未通过安全策略校验: %w", ErrUnauthorizedPeer, norm, pickIf[error](aErr != nil, aErr, ErrInsecurePermissions))
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err == nil && pid != 0 {
		if peerSID, pErr := ProcessUserSID(pid); pErr == nil && !IsTrustedPrincipalSID(peerSID, currSID) {
			return fmt.Errorf("%w: 管道服务端 PID %d 用户 SID 不受信任", ErrUnauthorizedPeer, pid)
		}
	}
	return nil
}
