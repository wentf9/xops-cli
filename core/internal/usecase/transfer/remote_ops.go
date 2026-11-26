package transfer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

//xops:syncclosure
func runSFTPMut(ctx context.Context, s *Service, base CallBase, action string, p pathalg.RemotePath, params map[string]string, preCheck func() error, fn func(context.Context, ports.RemoteFSPort) error) error {
	_, err := runRemotePathOp[security.CapFileMut](ctx, s, base, "sftp", action, p, security.RiskModerate, params, preCheck, func(opCtx context.Context, rfs ports.RemoteFSPort) (struct{}, error) {
		return struct{}{}, fn(opCtx, rfs)
	})
	return err
}

// ListDir 枚举远端目录并按 RemoteName 字典序返回确定性列表（零本地 FS 依赖）。
func (s *Service) ListDir(ctx context.Context, req ListDirRequest) (ListDirResult, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "list_dir", req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (ListDirResult, error) {
		entries, err := rfs.ReadDir(opCtx, req.Path)
		if err != nil {
			return ListDirResult{}, err
		}
		sorted := slices.Clone(entries)
		slices.SortFunc(sorted, func(a, b ports.RemoteDirEntry) int { return a.Name().Compare(b.Name()) })
		return ListDirResult{Path: req.Path, Entries: sorted}, nil
	})
}

// Stat 查询远端对象元信息（FollowSymlinks 控制 Stat / Lstat）。
func (s *Service) Stat(ctx context.Context, req StatRequest) (ports.RemoteFileStat, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", pickIf(req.FollowSymlinks, "stat", "lstat"), req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (ports.RemoteFileStat, error) {
		return pickIf(req.FollowSymlinks, rfs.Stat, rfs.Lstat)(opCtx, req.Path)
	})
}

// RealPath 解析远端规范真实 POSIX 路径。
func (s *Service) RealPath(ctx context.Context, req RealPathRequest) (pathalg.RemotePath, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "realpath", req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (pathalg.RemotePath, error) {
		return rfs.RealPath(opCtx, req.Path)
	})
}

// ReadLink 读取远端符号链接目标文本。
func (s *Service) ReadLink(ctx context.Context, req ReadLinkRequest) (string, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "readlink", req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (string, error) {
		return rfs.ReadLink(opCtx, req.Path)
	})
}

// MkdirAll 递归创建远端目录。
func (s *Service) MkdirAll(ctx context.Context, req MkdirAllRequest) error {
	var perm fs.FileMode
	return runSFTPMut(ctx, s, req.CallBase, "mkdir_all", req.Path, nil, func() (err error) { perm, err = resolvePerm(req.Perm, defaultDirPerm); return err }, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.MkdirAll(opCtx, req.Path, perm) })
}

// Remove 仅删除远端常规文件或符号链接（SSH_FXP_REMOVE），严格与 RemoveDir 隔离。
func (s *Service) Remove(ctx context.Context, req RemoveRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "remove", req.Path, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.Remove(opCtx, req.Path) })
}

// RemoveDir 仅删除远端空目录（SSH_FXP_RMDIR），严格与 Remove 隔离。
func (s *Service) RemoveDir(ctx context.Context, req RemoveDirRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "remove_dir", req.Path, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.RemoveDir(opCtx, req.Path) })
}

// Chmod 修改远端对象标准 POSIX 权限位（仅允许 0o001..0o777）。
func (s *Service) Chmod(ctx context.Context, req ChmodRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "chmod", req.Path, map[string]string{"perm": fmt.Sprintf("%#o", req.Perm)}, func() error {
		return pickIf[error](req.Perm != 0 && req.Perm == req.Perm.Perm(), nil, fmt.Errorf("%w: Chmod 权限位 %#o 非法", ErrInvalidRequest, req.Perm))
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.Chmod(opCtx, req.Path, req.Perm) })
}

// Chtimes 修改远端对象访问与修改时间（拒绝零值与越界 RFC 3339 时间戳）。
func (s *Service) Chtimes(ctx context.Context, req ChtimesRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "chtimes", req.Path, nil, func() error {
		return pickIf[error](isValidRFC3339Time(req.Atime) && isValidRFC3339Time(req.Mtime), nil, fmt.Errorf("%w: Chtimes 时间戳非法", ErrInvalidRequest))
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) error {
		return rfs.Chtimes(opCtx, req.Path, req.Atime, req.Mtime)
	})
}

// ReadFile 在门控与租约保护下有界读取远端常规文件，返回内容、摘要与 RemoteFileAnchor 快照。
func (s *Service) ReadFile(ctx context.Context, req ReadFileRequest) (ReadFileResult, error) {
	var limits ports.ReadLimits
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "file", "read", req.Path, security.RiskSafe, nil, func() (err error) { limits, err = s.resolveReadLimits(req.MaxBytes); return err }, func(opCtx context.Context, rfs ports.RemoteFSPort) (ReadFileResult, error) {
		st, data, dig, rErr := readBoundedRemoteFile(opCtx, rfs, req.Path, limits)
		return ReadFileResult{Stat: st, Content: data, Digest: dig}, rErr
	})
}

// WriteFile 消费冻结 RemoteWriteSpec（互斥 NoClobber/ExpectedAnchor）执行远端原子写入（ADR-016）。
func (s *Service) WriteFile(ctx context.Context, req WriteFileRequest) (WriteFileResult, error) {
	var writeSpec ports.RemoteWriteSpec
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "write", req.Path, security.RiskModerate, nil, func() error {
		perm, e1 := resolvePerm(req.Perm, defaultRemoteFilePerm)
		var e2 error
		if e1 == nil {
			writeSpec, e2 = ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: perm, ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber, AtomicRename: true})
		}
		return firstErr(e1, e2, pickIf[error](int64(len(req.Content)) > maxAtomicReadBytes, fmt.Errorf("%w: 载荷超限 %d", ports.ErrLimitExceeded, maxAtomicReadBytes), nil))
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) (WriteFileResult, error) {
		if req.CreateParents && !req.Path.Dir().IsRoot() {
			if mErr := rfs.MkdirAll(opCtx, req.Path.Dir(), defaultDirPerm); mErr != nil {
				return WriteFileResult{}, mErr
			}
		}
		st, wErr := rfs.WriteFileAtomic(opCtx, req.Path, writeSpec, bytes.NewReader(req.Content))
		return pickIf(wErr == nil, WriteFileResult{Stat: st, BytesWritten: int64(len(req.Content)), Digest: security.DigestBytes(req.Content)}, WriteFileResult{}), wErr
	})
}

// PatchFile 执行 FSTAT 锚定防并发覆写（Lost Update）的远端原子文本补丁（ADR-016）。
func (s *Service) PatchFile(ctx context.Context, req PatchFileRequest) (PatchFileResult, error) {
	var limits ports.ReadLimits
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "patch", req.Path, security.RiskModerate, nil, func() error {
		anc, okA := req.ExpectedAnchor.Get()
		dig, okD := req.ExpectedDigest.Get()
		if len(req.Edits) == 0 || slices.ContainsFunc(req.Edits, func(ed TextEdit) bool { return !ed.IsValid() }) || (okA && !anc.IsValid()) || (okD && !dig.IsValid()) {
			return fmt.Errorf("%w: PatchFile Edits/ExpectedAnchor/ExpectedDigest 无效", ErrInvalidRequest)
		}
		var lErr error
		limits, lErr = s.resolveReadLimits(req.MaxBytes)
		return lErr
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) (PatchFileResult, error) {
		return executeAnchoredPatch(opCtx, rfs, req, limits)
	})
}
func executeAnchoredPatch(ctx context.Context, rfs ports.RemoteFSPort, req PatchFileRequest, limits ports.ReadLimits) (PatchFileResult, error) {
	beforeStat, origBytes, beforeDigest, err := readBoundedRemoteFile(ctx, rfs, req.Path, limits)
	if err != nil {
		return PatchFileResult{}, err
	}
	if expAnc, ok := req.ExpectedAnchor.Get(); ok && !expAnc.Matches(beforeStat.Anchor()) {
		return PatchFileResult{}, fmt.Errorf("%w: 补丁前置锚点不匹配", ports.ErrRemoteAnchorMismatch)
	}
	if expDig, ok := req.ExpectedDigest.Get(); ok && !expDig.Equal(beforeDigest) {
		return PatchFileResult{}, fmt.Errorf("%w: %w", ErrPatchConflict, ErrDigestMismatch)
	}
	patched, replacements, err := applyTextEdits(string(origBytes), req.Edits)
	if err != nil {
		return PatchFileResult{}, err
	}
	patchedBytes := []byte(patched)
	if int64(len(patchedBytes)) > maxAtomicReadBytes {
		return PatchFileResult{}, fmt.Errorf("%w: 补丁后大小超限 %d", ports.ErrLimitExceeded, maxAtomicReadBytes)
	}
	writeSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: pickIf(beforeStat.Perm() != 0, beforeStat.Perm(), defaultRemoteFilePerm), ExpectedAnchor: algebraic.Some(beforeStat.Anchor()), AtomicRename: true})
	if err != nil {
		return PatchFileResult{}, err
	}
	afterStat, err := rfs.WriteFileAtomic(ctx, req.Path, writeSpec, bytes.NewReader(patchedBytes))
	return pickIf(err == nil, PatchFileResult{BeforeStat: beforeStat, AfterStat: afterStat, BeforeDigest: beforeDigest, AfterDigest: security.DigestBytes(patchedBytes), Replacements: replacements, BytesWritten: int64(len(patchedBytes))}, PatchFileResult{}), err
}

func applyTextEdits(content string, edits []TextEdit) (string, int, error) {
	cur, total := content, 0
	for i, ed := range edits {
		oldStr, count := ed.OldText(), strings.Count(cur, ed.OldText())
		if count == 0 {
			return "", 0, fmt.Errorf("%w: %w: Edits[%d]", ErrPatchConflict, ErrPatchNoMatch, i)
		}
		if !ed.ReplaceAll() && count > 1 {
			return "", 0, fmt.Errorf("%w: %w: Edits[%d] 命中 %d 处", ErrPatchConflict, ErrPatchAmbiguous, i, count)
		}
		cur = strings.Replace(cur, oldStr, ed.NewText(), pickIf(ed.ReplaceAll(), -1, 1))
		total += pickIf(ed.ReplaceAll(), count, 1)
	}
	return cur, total, nil
}

// RenameFile 消费互斥 NoClobber / ExpectedAnchor 的冻结 RemoteRenameSpec 执行远端原子重命名。
func (s *Service) RenameFile(ctx context.Context, req RenameFileRequest) error {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	if err != nil {
		return err
	}
	if !req.OldPath.IsValid() || !req.NewPath.IsValid() {
		return fmt.Errorf("%w: RenameFile 源/目标路径无效", ErrInvalidRequest)
	}
	renameSpec, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber})
	if err != nil {
		return err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "file", action: "rename", paths: []pathalg.RemotePath{req.OldPath, req.NewPath}, defaultRisk: security.RiskModerate, summary: "file rename " + req.OldPath.String() + " -> " + req.NewPath.String(), canonicalize: true}
	_, err = runAuthorizedRemoteFS[security.CapFileMut](ctx, s, spec, func(opCtx context.Context, _ gate.Authorized[security.CapFileMut], rfs ports.RemoteFSPort, _ *transferEmitter) (struct{}, error) {
		return struct{}{}, rfs.RenameAtomic(opCtx, req.OldPath, req.NewPath, renameSpec)
	})
	return err
}
func readBoundedRemoteFile(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, limits ports.ReadLimits) (ports.RemoteFileStat, []byte, security.Digest, error) {
	st, err := rfs.Stat(ctx, p)
	if err != nil || !st.IsRegular() {
		return zeroVal[ports.RemoteFileStat](), nil, zeroVal[security.Digest](), pickIf[error](err != nil, err, pickIf(st.IsDir(), ports.ErrRemoteIsDir, ports.ErrNotRegularFile))
	}
	var data []byte
	if err = rfs.WithReadFile(ctx, p, limits, func(r io.Reader, size int64) error {
		if size > limits.MaxBytes() {
			return ports.ErrLimitExceeded
		}
		var rErr error
		if data, rErr = io.ReadAll(io.LimitReader(r, limits.MaxBytes()+1)); rErr != nil {
			return rErr
		}
		return pickIf[error](int64(len(data)) > limits.MaxBytes(), ports.ErrLimitExceeded, nil)
	}); err != nil {
		return zeroVal[ports.RemoteFileStat](), nil, zeroVal[security.Digest](), err
	}
	afterSt, err := rfs.Stat(ctx, p)
	if err != nil || !st.Anchor().Equal(afterSt.Anchor()) || afterSt.Size() != int64(len(data)) {
		return zeroVal[ports.RemoteFileStat](), nil, zeroVal[security.Digest](), pickIf[error](err != nil, err, ports.ErrRemoteAnchorMismatch)
	}
	return st, data, security.DigestBytes(data), nil
}
