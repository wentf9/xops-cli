// Package osfs 提供 XOps v2 句柄安全的三平台本地文件系统、旁路文件锁、Windows DACL/超长路径
// 与受控本地 AF_UNIX 套接字原语（公开契约 4，ADR-007 / INV-A1..A5）。
package osfs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultFilePerm fs.FileMode = 0o600
	defaultDirPerm  fs.FileMode = 0o700
)

// 本包导出的规范化哨兵错误（供调用方以 errors.Is 精确判定）。
var (
	ErrSlotOccupied        = errors.New("osfs: 控制套接字槽位已被占用")
	ErrNotSocket           = errors.New("osfs: 目标路径不是本地 AF_UNIX 套接字")
	ErrInvalidControlPath  = errors.New("osfs: 控制套接字路径非法")
	ErrControlPathTooLong  = errors.New("osfs: 控制套接字路径超过平台 sun_path 长度上限")
	ErrUnauthorizedPeer    = errors.New("osfs: 本地 AF_UNIX 对端身份校验未通过")
	ErrUnsupportedPeerCred = errors.New("osfs: 当前平台不支持查询本地 AF_UNIX 对端凭据")
	ErrInsecurePermissions = errors.New("osfs: 对象权限或 DACL 不满足安全不变量")
	ErrSameFileMismatch    = errors.New("osfs: 句柄与路径 SameFile 锚定校验失败")
)

func zeroVal[T any]() (z T) { return z }

// mapOSError 将标准库 OS 错误归一化包装为 ports 规范哨兵错误并保留底层错误链。
func mapOSError(err error) error {
	if err == nil || isAlreadyNormalizedError(err) {
		return err
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %w", ports.ErrNotFound, err)
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("%w: %w", ports.ErrAlreadyExists, err)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w: %w", ports.ErrPermissionDenied, err)
	case errors.Is(err, os.ErrClosed):
		return fmt.Errorf("%w: %w", ports.ErrClosed, err)
	default:
		return err
	}
}

func isAlreadyNormalizedError(err error) bool {
	return errors.Is(err, ports.ErrNotFound) || errors.Is(err, ports.ErrAlreadyExists) ||
		errors.Is(err, ports.ErrPermissionDenied) || errors.Is(err, ports.ErrNotRegularFile) ||
		errors.Is(err, ports.ErrSymlinkRejected) || errors.Is(err, ports.ErrLimitExceeded) ||
		errors.Is(err, ports.ErrLockBusy) || errors.Is(err, ports.ErrHandleExpired) ||
		errors.Is(err, ports.ErrInvalidArgument) || errors.Is(err, ports.ErrUnsupported) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func sanitizeFilePerm(perm, fallback fs.FileMode) fs.FileMode {
	if p := perm.Perm(); p != 0 {
		return p
	}
	return fallback
}

func fileInfoToLocalFileInfo(name string, fi os.FileInfo) (ports.LocalFileInfo, error) {
	if fi == nil {
		return zeroVal[ports.LocalFileInfo](), fmt.Errorf("%w: FileInfo 为空", ports.ErrInvalidArgument)
	}
	return ports.NewLocalFileInfo(ports.LocalFileInfoSpec{Name: name, Size: fi.Size(), Mode: fi.Mode(), ModTime: fi.ModTime()})
}

func randomHexToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("osfs: 生成随机后缀失败: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func siblingDest(dest pathalg.LocalRootedDest, name string) (pathalg.LocalRootedDest, error) {
	if parent, ok := dest.Parent(); ok {
		return parent.JoinComponent(name)
	}
	return pathalg.ParseLocalRootedDest(name)
}

func makeTempDestInSameDir(dest pathalg.LocalRootedDest) (pathalg.LocalRootedDest, error) {
	tok, err := randomHexToken(8)
	if err != nil {
		return zeroVal[pathalg.LocalRootedDest](), err
	}
	return siblingDest(dest, ".xops-tmp-"+tok)
}
