package sftp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// WriteFileAtomic 执行 ADR-016 SFTP v3 纵深防护原子写入：
//  1. 前置 Lstat 拦截目录覆写与 NoClobber 冲突；
//  2. 若携带 ExpectedAnchor，先以严格非截断方式打开并经 SSH_FXP_FSTAT 校验文件类型与可选 (dev, ino) 锚点；
//  3. 在目标同目录独占创建随机临时文件（O_CREAT|O_EXCL），经 FSTAT 确认常规文件后流式写入、FSETSTAT 校正权限并尽力 fsync；
//  4. 落盘提交前复核锚点，NoClobber 优先采用内核原子 hardlink@openssh.com（回退 SFTP v3 独占 RENAME），
//     覆写采用原子 posix-rename@openssh.com；任何阶段失败立即在有界超时内清理临时文件，零残留。
func (c *Client) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, r io.Reader) (ports.RemoteFileStat, error) {
	if err := c.checkPathOp(ctx, p); err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	if !spec.IsValid() || r == nil {
		return zeroVal[ports.RemoteFileStat](), fmt.Errorf("%w: WriteFileAtomic 规格或输入流无效", ports.ErrInvalidArgument)
	}
	if p.IsRoot() {
		return zeroVal[ports.RemoteFileStat](), ports.ErrRemoteIsDir
	}
	if err := c.verifyWritePreconditions(ctx, p, spec.NoClobber(), spec.ExpectedAnchor()); err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	tmpPath, err := c.stageTempFile(ctx, p, spec.Perm(), r)
	if err != nil {
		return zeroVal[ports.RemoteFileStat](), err
	}
	if err := c.commitStagedFile(ctx, tmpPath, p, spec.NoClobber(), spec.ExpectedAnchor()); err != nil {
		_ = c.removeQuiet(ctx, tmpPath)
		return zeroVal[ports.RemoteFileStat](), err
	}
	return c.Lstat(ctx, p)
}

func (c *Client) verifyWritePreconditions(ctx context.Context, p pathalg.RemotePath, noClobber bool, expectedOpt algebraic.Option[ports.RemoteFileAnchor]) error {
	if st, err := c.Lstat(ctx, p); err == nil {
		if noClobber {
			return ports.ErrAlreadyExists
		}
		if st.IsDir() {
			return ports.ErrRemoteIsDir
		}
	} else if !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	if expected, ok := expectedOpt.Get(); ok {
		return c.verifyRemoteAnchorByFstat(ctx, p, expected)
	}
	return nil
}

// verifyRemoteAnchorByFstat 以严格非截断只读模式打开目标并执行 SSH_FXP_FSTAT 校验锚点（ADR-016）。
// 若目标不是可打开常规文件（例如符号链接），则结合 Lstat 锚点校验并在任何不匹配或缺失时失败关闭。
func (c *Client) verifyRemoteAnchorByFstat(ctx context.Context, p pathalg.RemotePath, expected ports.RemoteFileAnchor) error {
	lstat, lErr := c.Lstat(ctx, p)
	if errors.Is(lErr, ports.ErrNotFound) {
		return ports.ErrRemoteAnchorMismatch
	}
	if lErr != nil {
		return lErr
	}
	if lstat.IsSymlink() {
		if expected.Matches(lstat.Anchor()) {
			return nil
		}
		return ports.ErrRemoteAnchorMismatch
	}
	handle, err := c.openHandle(ctx, p.String(), sshFXFRead, wireAttrs{})
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			return ports.ErrRemoteAnchorMismatch
		}
		return err
	}
	defer c.closeHandle(ctx, handle)
	attrs, err := c.fstatHandle(ctx, handle)
	if err != nil {
		return err
	}
	obsAnchor, _, err := attrsToAnchor(attrs)
	if err != nil || !expected.Matches(obsAnchor) {
		return ports.ErrRemoteAnchorMismatch
	}
	return nil
}

func (c *Client) stageTempFile(ctx context.Context, target pathalg.RemotePath, perm fs.FileMode, r io.Reader) (pathalg.RemotePath, error) {
	suffix, err := randomTempSuffix(c.entropy)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	tmpName, err := pathalg.ParseRemoteName(suffix)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	tmpPath, err := target.Dir().Join(tmpName)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	openAttrs := wireAttrs{flags: attrFlagPermissions, perm: uint32(perm.Perm())}
	handle, err := c.openHandle(ctx, tmpPath.String(), sshFXFWrite|sshFXFCreat|sshFXFExcl, openAttrs)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	cleanup := func(cause error) (pathalg.RemotePath, error) {
		c.closeHandle(ctx, handle)
		_ = c.removeQuiet(ctx, tmpPath)
		return zeroVal[pathalg.RemotePath](), cause
	}
	if err := c.verifyTempHandleRegular(ctx, handle); err != nil {
		return cleanup(err)
	}
	if err := c.writeAllToHandle(ctx, handle, r); err != nil {
		return cleanup(err)
	}
	if err := c.fsetstatPerm(ctx, handle, perm); err != nil {
		return cleanup(err)
	}
	c.tryFsyncHandle(ctx, handle)
	if err := c.expectStatusOK(ctx, sshFXPClose, appendBytes(nil, handle)); err != nil {
		_ = c.removeQuiet(ctx, tmpPath)
		return zeroVal[pathalg.RemotePath](), err
	}
	return tmpPath, nil
}

func (c *Client) verifyTempHandleRegular(ctx context.Context, handle []byte) error {
	attrs, err := c.fstatHandle(ctx, handle)
	if err != nil {
		return err
	}
	ft, _ := posixModeToRemote(attrs)
	if ft != ports.RemoteFileRegular {
		return ports.ErrNotRegularFile
	}
	return nil
}

func (c *Client) writeAllToHandle(ctx context.Context, handle []byte, r io.Reader) error {
	buf := make([]byte, c.maxWriteLen)
	var offset uint64
	for {
		n, rErr := r.Read(buf)
		if n > 0 {
			if err := c.writeHandleAt(ctx, handle, offset, buf[:n]); err != nil {
				return err
			}
			offset += uint64(n)
		}
		if rErr != nil {
			if errors.Is(rErr, io.EOF) {
				return nil
			}
			return rErr
		}
	}
}

func (c *Client) commitStagedFile(ctx context.Context, tmpPath, destPath pathalg.RemotePath, noClobber bool, expectedOpt algebraic.Option[ports.RemoteFileAnchor]) error {
	if noClobber {
		return c.commitNoClobber(ctx, tmpPath, destPath)
	}
	if expected, ok := expectedOpt.Get(); ok {
		// 提交前再次通过非截断 FSTAT 核验锚点，在 SFTP v3 协议边界内将 TOCTOU 窗口收窄至最小。
		if err := c.verifyRemoteAnchorByFstat(ctx, destPath, expected); err != nil {
			return err
		}
	}
	return c.atomicRenameOverwrite(ctx, tmpPath, destPath)
}

func (c *Client) commitNoClobber(ctx context.Context, src, dst pathalg.RemotePath) error {
	if c.hasHardlink {
		body := appendString(appendString(appendString(nil, extHardlink), src.String()), dst.String())
		if err := c.expectStatusOK(ctx, sshFXPExtended, body); err != nil {
			if _, lErr := c.Lstat(ctx, dst); lErr == nil {
				return ports.ErrAlreadyExists
			}
			return err
		}
		return c.removeQuiet(ctx, src)
	}
	if _, err := c.Lstat(ctx, dst); err == nil {
		return ports.ErrAlreadyExists
	} else if !errors.Is(err, ports.ErrNotFound) {
		return err
	}
	body := appendString(appendString(nil, src.String()), dst.String())
	if err := c.expectStatusOK(ctx, sshFXPRename, body); err != nil {
		if _, lErr := c.Lstat(ctx, dst); lErr == nil {
			return ports.ErrAlreadyExists
		}
		return err
	}
	return nil
}

func (c *Client) atomicRenameOverwrite(ctx context.Context, src, dst pathalg.RemotePath) error {
	if c.hasPosixRename {
		body := appendString(appendString(appendString(nil, extPosixRename), src.String()), dst.String())
		return c.expectStatusOK(ctx, sshFXPExtended, body)
	}
	body := appendString(appendString(nil, src.String()), dst.String())
	if err := c.expectStatusOK(ctx, sshFXPRename, body); err != nil {
		if isStatusCode(err, sshFXFailure) {
			if rErr := c.Remove(ctx, dst); rErr == nil {
				return c.expectStatusOK(ctx, sshFXPRename, body)
			}
		}
		return err
	}
	return nil
}

// WriteChunk 向远端常规文件 p 的 offset 处严格非截断写入 length 字节（绝不使用 SSH_FXF_TRUNC）。
func (c *Client) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, r io.Reader, length int64) error {
	if err := c.checkPathOp(ctx, p); err != nil {
		return err
	}
	if offset < 0 || length < 0 || r == nil {
		return fmt.Errorf("%w: WriteChunk 参数非法", ports.ErrInvalidArgument)
	}
	openAttrs := wireAttrs{flags: attrFlagPermissions, perm: 0o600}
	handle, err := c.openHandle(ctx, p.String(), sshFXFWrite|sshFXFCreat, openAttrs)
	if err != nil {
		return err
	}
	defer c.closeHandle(ctx, handle)

	if err := c.verifyTempHandleRegular(ctx, handle); err != nil {
		return err
	}
	return c.streamWriteChunk(ctx, handle, uint64(offset), r, length)
}

func (c *Client) streamWriteChunk(ctx context.Context, handle []byte, off uint64, r io.Reader, length int64) error {
	buf := make([]byte, min(int64(c.maxWriteLen), max(length, 1)))
	var written int64
	for written < length {
		step := min(int64(len(buf)), length-written)
		if _, err := io.ReadFull(r, buf[:step]); err != nil {
			return err
		}
		if err := c.writeHandleAt(ctx, handle, off+uint64(written), buf[:step]); err != nil {
			return err
		}
		written += step
	}
	return nil
}

func (c *Client) writeHandleAt(ctx context.Context, handle []byte, offset uint64, data []byte) error {
	body := appendBytes(nil, handle)
	body = appendUint64(body, offset)
	body = appendBytes(body, data)
	return c.expectStatusOK(ctx, sshFXPWrite, body)
}

func (c *Client) fsetstatPerm(ctx context.Context, handle []byte, perm fs.FileMode) error {
	body := appendAttrs(appendBytes(nil, handle), wireAttrs{flags: attrFlagPermissions, perm: uint32(perm.Perm())})
	return c.expectStatusOK(ctx, sshFXPFsetstat, body)
}

func (c *Client) tryFsyncHandle(ctx context.Context, handle []byte) {
	if !c.hasFsync {
		return
	}
	body := appendBytes(appendString(nil, extFsync), handle)
	_ = c.expectStatusOK(ctx, sshFXPExtended, body)
}

func (c *Client) removeQuiet(parentCtx context.Context, p pathalg.RemotePath) error {
	if c.closed.Load() {
		return ports.ErrClosed
	}
	cCtx, cancel := cleanupContext(parentCtx)
	defer cancel()
	return c.expectStatusOK(cCtx, sshFXPRemove, appendString(nil, p.String()))
}

func attrsModTime(a wireAttrs) time.Time {
	if a.flags&attrFlagACModTime != 0 && a.mtime > 0 {
		return time.Unix(int64(a.mtime), 0).UTC()
	}
	return time.Time{}
}
