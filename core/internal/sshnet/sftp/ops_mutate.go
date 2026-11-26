package sftp

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// RenameAtomic 按已校验 RemoteRenameSpec（互斥的 NoClobber 或 FSTAT ExpectedAnchor）执行远端原子重命名。
func (c *Client) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec ports.RemoteRenameSpec) error {
	if err := c.checkRenameArgs(ctx, oldPath, newPath, spec); err != nil {
		return err
	}
	srcStat, err := c.Lstat(ctx, oldPath)
	if err != nil {
		return err
	}
	if err := c.validateRenameTarget(ctx, oldPath, newPath, srcStat, spec); err != nil {
		return err
	}
	if oldPath.Equal(newPath) {
		return nil
	}
	if spec.NoClobber() {
		return c.renameNoClobber(ctx, oldPath, newPath, srcStat)
	}
	return c.atomicRenameOverwrite(ctx, oldPath, newPath)
}

func (c *Client) checkRenameArgs(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec ports.RemoteRenameSpec) error {
	if err := c.checkPathOp(ctx, oldPath); err != nil {
		return err
	}
	if !newPath.IsValid() || !spec.IsValid() {
		return fmt.Errorf("%w: RenameAtomic 目标路径或规格无效", ports.ErrInvalidArgument)
	}
	if oldPath.IsRoot() || newPath.IsRoot() {
		return ports.ErrPermissionDenied
	}
	return nil
}

func (c *Client) renameNoClobber(ctx context.Context, oldPath, newPath pathalg.RemotePath, srcStat ports.RemoteFileStat) error {
	if srcStat.IsRegular() {
		return c.commitNoClobber(ctx, oldPath, newPath)
	}
	body := appendString(appendString(nil, oldPath.String()), newPath.String())
	if rErr := c.expectStatusOK(ctx, sshFXPRename, body); rErr != nil {
		if _, lErr := c.Lstat(ctx, newPath); lErr == nil {
			return ports.ErrAlreadyExists
		}
		return rErr
	}
	return nil
}

func (c *Client) validateRenameTarget(ctx context.Context, oldPath, newPath pathalg.RemotePath, srcStat ports.RemoteFileStat, spec ports.RemoteRenameSpec) error {
	if srcStat.IsDir() && strings.HasPrefix(newPath.String(), strings.TrimRight(oldPath.String(), "/")+"/") {
		return ports.ErrInvalidArgument
	}
	if expected, ok := spec.ExpectedAnchor().Get(); ok {
		if err := c.verifyRemoteAnchorByFstat(ctx, newPath, expected); err != nil {
			return err
		}
	}
	if oldPath.Equal(newPath) {
		return nil
	}
	return c.validateRenameDestKind(ctx, newPath, srcStat, spec.NoClobber())
}

func (c *Client) validateRenameDestKind(ctx context.Context, newPath pathalg.RemotePath, srcStat ports.RemoteFileStat, noClobber bool) error {
	dstStat, err := c.Lstat(ctx, newPath)
	if errors.Is(err, ports.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if noClobber {
		return ports.ErrAlreadyExists
	}
	if !srcStat.IsDir() && dstStat.IsDir() {
		return ports.ErrRemoteIsDir
	}
	if srcStat.IsDir() && !dstStat.IsDir() {
		return ports.ErrInvalidArgument
	}
	return nil
}

// Chmod 修改远端对象标准权限位（仅允许 0o001..0o777，拒绝零值及特殊权限位）。
func (c *Client) Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error {
	if err := c.checkPathOp(ctx, p); err != nil {
		return err
	}
	if perm == 0 || perm != perm.Perm() {
		return fmt.Errorf("%w: Chmod 权限位 %#o 非法", ports.ErrInvalidArgument, perm)
	}
	body := appendAttrs(appendString(nil, p.String()), wireAttrs{flags: attrFlagPermissions, perm: uint32(perm)})
	return c.expectStatusOK(ctx, sshFXPSetstat, body)
}

// Chtimes 修改远端对象访问与修改时间（拒绝零值、越界年份或超出 SFTP v3 uint32 时间戳范围的值）。
func (c *Client) Chtimes(ctx context.Context, p pathalg.RemotePath, atime, mtime time.Time) error {
	if err := c.checkPathOp(ctx, p); err != nil {
		return err
	}
	if !isValidSFTPTimestamp(atime) || !isValidSFTPTimestamp(mtime) {
		return fmt.Errorf("%w: Chtimes 时间戳无效或超出 SFTP v3 范围", ports.ErrInvalidArgument)
	}
	body := appendAttrs(appendString(nil, p.String()), wireAttrs{
		flags: attrFlagACModTime,
		atime: uint32(atime.UTC().Unix()),
		mtime: uint32(mtime.UTC().Unix()),
	})
	return c.expectStatusOK(ctx, sshFXPSetstat, body)
}

// MkdirAll 递归创建远端目录链（已存在目录幂等成功，遇到同名非目录对象返回 ErrAlreadyExists）。
func (c *Client) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	if err := c.checkPathOp(ctx, dir); err != nil {
		return err
	}
	if dir.IsRoot() {
		return nil
	}
	if st, err := c.Stat(ctx, dir); err == nil {
		if st.IsDir() {
			return nil
		}
		return ports.ErrAlreadyExists
	} else if !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	mode := perm.Perm()
	if mode == 0 {
		mode = 0o755
	}
	return c.mkdirPrefixes(ctx, dir.String(), mode)
}

func (c *Client) mkdirPrefixes(ctx context.Context, cleanPath string, perm fs.FileMode) error {
	isAbs := strings.HasPrefix(cleanPath, "/")
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	cur := ""
	if isAbs {
		cur = "/"
	}
	for _, seg := range parts {
		if seg == "" || seg == "." {
			continue
		}
		cur = joinRemotePrefix(cur, seg)
		if err := c.ensureSingleRemoteDir(ctx, cur, perm); err != nil {
			return err
		}
	}
	return nil
}

func joinRemotePrefix(cur, seg string) string {
	if cur == "" {
		return seg
	}
	return path.Join(cur, seg)
}

func (c *Client) ensureSingleRemoteDir(ctx context.Context, rawDir string, perm fs.FileMode) error {
	rp, err := pathalg.ParseRemotePath(rawDir)
	if err != nil {
		return err
	}
	if st, sErr := c.Stat(ctx, rp); sErr == nil {
		if st.IsDir() {
			return nil
		}
		return ports.ErrAlreadyExists
	} else if !errors.Is(sErr, ports.ErrNotFound) {
		return sErr
	}
	body := appendAttrs(appendString(nil, rawDir), wireAttrs{flags: attrFlagPermissions, perm: uint32(perm)})
	if mErr := c.expectStatusOK(ctx, sshFXPMkdir, body); mErr != nil {
		if st, sErr := c.Stat(ctx, rp); sErr == nil && st.IsDir() {
			return nil
		}
		return mErr
	}
	return nil
}

// Remove 仅删除远端常规文件或符号链接（SSH_FXP_REMOVE）；若目标为目录则返回 ports.ErrRemoteIsDir。
func (c *Client) Remove(ctx context.Context, p pathalg.RemotePath) error {
	if err := c.checkPathOp(ctx, p); err != nil {
		return err
	}
	if p.IsRoot() {
		return ports.ErrRemoteIsDir
	}
	err := c.expectStatusOK(ctx, sshFXPRemove, appendString(nil, p.String()))
	if err != nil && (isStatusCode(err, sshFXFailure) || isStatusCode(err, sshFXPermissionDenied)) {
		if st, sErr := c.Lstat(ctx, p); sErr == nil && st.IsDir() {
			return ports.ErrRemoteIsDir
		}
	}
	return err
}

// RemoveDir 仅删除远端空目录（SSH_FXP_RMDIR）；非目录或非空目录返回 ports.ErrInvalidArgument，缺失返回 ErrNotFound。
func (c *Client) RemoveDir(ctx context.Context, dir pathalg.RemotePath) error {
	if err := c.checkPathOp(ctx, dir); err != nil {
		return err
	}
	if dir.IsRoot() {
		return ports.ErrPermissionDenied
	}
	err := c.expectStatusOK(ctx, sshFXPRmdir, appendString(nil, dir.String()))
	if err != nil && isStatusCode(err, sshFXFailure) {
		if _, sErr := c.Lstat(ctx, dir); errors.Is(sErr, ports.ErrNotFound) {
			return ports.ErrNotFound
		}
		return fmt.Errorf("%w: 远端目标不是空目录: %w", ports.ErrInvalidArgument, err)
	}
	return err
}
