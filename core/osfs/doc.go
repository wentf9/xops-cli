// Package osfs 提供 XOps v2 句柄安全的三平台本地文件系统、旁路文件锁、Windows DACL/超长路径
// 与受控本地 AF_UNIX 套接字原语（公开契约 4，ADR-007 / INV-A1..A5）。
package osfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io/fs"
	"os"
	"slices"
)

const defaultFilePerm, defaultDirPerm fs.FileMode = 0o600, 0o700

// rootLeafOp 标识沙箱根内打开常规叶文件的跨平台操作意图（供各平台 openLeafInRootOS 统一分发）。
type rootLeafOp uint8

const (
	leafOpRead, leafOpCreateExcl, leafOpAppend, leafOpWriteChunk rootLeafOp = iota, 1, 2, 3
	leafOpLockRO, leafOpLockRW, leafOpLockCreate                 rootLeafOp = 4, 5, 6
)

// 本包导出的规范化哨兵错误（供调用方以 errors.Is 精确判定）。
var (
	ErrSlotOccupied        = domi18n.Sentinel(domi18n.KeyOSFSSlotOccupied)
	ErrNotSocket           = domi18n.Sentinel(domi18n.KeyOSFSNotSocket)
	ErrInvalidControlPath  = domi18n.Sentinel(domi18n.KeyOSFSInvalidControlPath)
	ErrControlPathTooLong  = domi18n.Sentinel(domi18n.KeyOSFSControlPathTooLong)
	ErrUnauthorizedPeer    = domi18n.Sentinel(domi18n.KeyOSFSUnauthorizedPeer)
	ErrUnsupportedPeerCred = domi18n.Sentinel(domi18n.KeyOSFSUnsupportedPeerCred)
	ErrInsecurePermissions = domi18n.Sentinel(domi18n.KeyOSFSInsecurePermissions)
	ErrSameFileMismatch    = domi18n.Sentinel(domi18n.KeyOSFSSameFileMismatch)
)

func wrapS(s, c error) error { return domi18n.WrapSentinel(s, c) }
func errField(s error, f string) error {
	return domi18n.EF(s, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", f))
}
func errFieldNil(s error, f string) error {
	return domi18n.EF(s, domi18n.KeyCommonFieldNil, domi18n.Str("field", f))
}
func wrapOp(s, c error, op string) error {
	return domi18n.WrapS(s, c, domi18n.KeyCommonOpFailed, domi18n.Str("op", op))
}
func errWrongKind(p string, wantDir bool) error {
	if wantDir {
		return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotDirectory, domi18n.BoundStr("path", p))
	}
	return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotRegularFile, domi18n.BoundStr("path", p))
}

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](ok bool, yes, no T) T {
	if ok {
		return yes
	}
	return no
}
func orZero[T any](ok bool, v T) T { return pickIf(ok, v, zeroVal[T]()) }

// mapOSError 将标准库 OS 错误归一化包装为 ports 规范哨兵错误并保留底层错误链。
func mapOSError(err error) error {
	if err == nil || isAlreadyNormalizedError(err) {
		return err
	}
	for _, m := range [4]struct{ osErr, portErr error }{
		{os.ErrNotExist, ports.ErrNotFound}, {os.ErrExist, ports.ErrAlreadyExists},
		{os.ErrPermission, ports.ErrPermissionDenied}, {os.ErrClosed, ports.ErrClosed},
	} {
		if errors.Is(err, m.osErr) {
			return wrapS(m.portErr, err)
		}
	}
	return err
}
func isAlreadyNormalizedError(err error) bool {
	return slices.ContainsFunc([]error{
		ports.ErrNotFound, ports.ErrAlreadyExists, ports.ErrPermissionDenied, ports.ErrNotRegularFile,
		ports.ErrSymlinkRejected, ports.ErrLimitExceeded, ports.ErrLockBusy, ports.ErrHandleExpired,
		ports.ErrInvalidArgument, ports.ErrUnsupported, context.Canceled, context.DeadlineExceeded,
	}, func(t error) bool { return errors.Is(err, t) })
}
func sanitizeFilePerm(p, fb fs.FileMode) fs.FileMode { return pickIf(p.Perm() != 0, p.Perm(), fb) }
func fileInfoToLocalFileInfo(name string, fi os.FileInfo) (ports.LocalFileInfo, error) {
	if fi == nil {
		return zeroVal[ports.LocalFileInfo](), errFieldNil(ports.ErrInvalidArgument, "file_info")
	}
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: name, Size: fi.Size(), Mode: fi.Mode(), ModTime: fi.ModTime()})
}
func siblingDest(dest pathalg.LocalRootedDest, name string) (pathalg.LocalRootedDest, error) {
	if parent, ok := dest.Parent(); ok {
		return parent.JoinComponent(name)
	}
	return pathalg.ParseLocalRootedDest(name)
}
func randomHexToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "random_hex"))
	}
	return hex.EncodeToString(buf), nil
}
func makeTempDestInSameDir(dest pathalg.LocalRootedDest) (pathalg.LocalRootedDest, error) {
	tok, err := randomHexToken(8)
	if err != nil {
		return zeroVal[pathalg.LocalRootedDest](), err
	}
	return siblingDest(dest, ".xops-tmp-"+tok)
}
