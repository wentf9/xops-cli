package transfer

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer/remotecanon"
	"github.com/wentf9/xops-cli/core/ports"
)

func canonSentinels() remotecanon.Sentinels {
	return remotecanon.Sentinels{Invalid: ErrInvalidRequest, Symlink: ErrSymlinkPolicyDenied}
}

//xops:syncclosure
func runSFTPMut(ctx context.Context, s *Service, base CallBase, action string, p pathalg.RemotePath, params map[string]string, preErr error, fn func(context.Context, ports.RemoteFSPort) error) error {
	_, err := runRemotePathOp[security.CapFileMut](ctx, s, base, "sftp", action, p, security.RiskModerate, params, preErr, func(c context.Context, rfs ports.RemoteFSPort) (struct{}, error) { return struct{}{}, fn(c, rfs) })
	return err
}
func runSFTPPathRead[T any](ctx context.Context, s *Service, req RemotePathRequest, action string, fn func(ports.RemoteFSPort, context.Context, pathalg.RemotePath) (T, error)) (T, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", action, req.Path, security.RiskSafe, nil, nil, func(c context.Context, rfs ports.RemoteFSPort) (T, error) { return fn(rfs, c, req.Path) })
}
func runSFTPPathMut(ctx context.Context, s *Service, req RemotePathRequest, action string, fn func(ports.RemoteFSPort, context.Context, pathalg.RemotePath) error) error {
	return runSFTPMut(ctx, s, req.CallBase, action, req.Path, nil, nil, func(c context.Context, rfs ports.RemoteFSPort) error { return fn(rfs, c, req.Path) })
}

// ListDir / Stat / RealPath / ReadLink 枚举远端目录并查询元信息、规范路径与软链目标（零本地 FS 依赖）。
func (s *Service) ListDir(ctx context.Context, req ListDirRequest) (ListDirResult, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "list_dir", req.Path, security.RiskSafe, nil, nil, func(c context.Context, rfs ports.RemoteFSPort) (ListDirResult, error) {
		entries, err := rfs.ReadDir(c, req.Path)
		if err != nil {
			return ListDirResult{}, err
		}
		sorted := slices.Clone(entries)
		slices.SortFunc(sorted, func(a, b ports.RemoteDirEntry) int { return a.Name().Compare(b.Name()) })
		return ListDirResult{Path: req.Path, Entries: sorted}, nil
	})
}
func (s *Service) Stat(ctx context.Context, req StatRequest) (ports.RemoteFileStat, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", pickIf(req.FollowSymlinks, "stat", "lstat"), req.Path, security.RiskSafe, nil, nil, func(c context.Context, rfs ports.RemoteFSPort) (ports.RemoteFileStat, error) {
		return pickIf(req.FollowSymlinks, rfs.Stat, rfs.Lstat)(c, req.Path)
	})
}
func (s *Service) RealPath(ctx context.Context, req RealPathRequest) (pathalg.RemotePath, error) {
	return runSFTPPathRead(ctx, s, req, "realpath", ports.RemoteFSPort.RealPath)
}
func (s *Service) ReadLink(ctx context.Context, req ReadLinkRequest) (string, error) {
	return runSFTPPathRead(ctx, s, req, "readlink", ports.RemoteFSPort.ReadLink)
}

// MkdirAll / Remove / RemoveDir / Chmod / Chtimes 执行远端工作区变更（严格隔离 Remove 与 RemoveDir）。
func (s *Service) MkdirAll(ctx context.Context, req MkdirAllRequest) error {
	perm, err := resolvePerm(req.Perm, defaultDirPerm)
	return runSFTPMut(ctx, s, req.CallBase, "mkdir_all", req.Path, nil, err, func(c context.Context, rfs ports.RemoteFSPort) error { return rfs.MkdirAll(c, req.Path, perm) })
}
func (s *Service) Remove(ctx context.Context, req RemoveRequest) error {
	return runSFTPPathMut(ctx, s, req, "remove", ports.RemoteFSPort.Remove)
}
func (s *Service) RemoveDir(ctx context.Context, req RemoveDirRequest) error {
	return runSFTPPathMut(ctx, s, req, "remove_dir", ports.RemoteFSPort.RemoveDir)
}
func (s *Service) Chmod(ctx context.Context, req ChmodRequest) error {
	preErr := pickIf[error](req.Perm != 0 && req.Perm == req.Perm.Perm(), nil, fmt.Errorf("%w: Chmod 权限位 %#o 非法", ErrInvalidRequest, req.Perm))
	return runSFTPMut(ctx, s, req.CallBase, "chmod", req.Path, map[string]string{"perm": fmt.Sprintf("%#o", req.Perm)}, preErr, func(c context.Context, rfs ports.RemoteFSPort) error { return rfs.Chmod(c, req.Path, req.Perm) })
}
func (s *Service) Chtimes(ctx context.Context, req ChtimesRequest) error {
	preErr := pickIf[error](validRFC3339(req.Atime) && validRFC3339(req.Mtime), nil, fmt.Errorf("%w: Chtimes 时间戳非法", ErrInvalidRequest))
	return runSFTPMut(ctx, s, req.CallBase, "chtimes", req.Path, nil, preErr, func(c context.Context, rfs ports.RemoteFSPort) error {
		return rfs.Chtimes(c, req.Path, req.Atime, req.Mtime)
	})
}

// ReadFile / WriteFile / PatchFile / RenameFile 在门控与租约保护下执行有界读取与 FSTAT 锚定远端原子变更（ADR-016）。
func (s *Service) ReadFile(ctx context.Context, req ReadFileRequest) (ReadFileResult, error) {
	limits, preErr := s.resolveReadLimits(req.MaxBytes)
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "file", "read", req.Path, security.RiskSafe, nil, preErr, func(c context.Context, rfs ports.RemoteFSPort) (ReadFileResult, error) {
		st, data, dig, err := remotecanon.ReadBoundedFile(c, rfs, req.Path, limits)
		return pickIf(err == nil, ReadFileResult{Stat: st, Content: data, Digest: dig}, ReadFileResult{}), err
	})
}
func (s *Service) WriteFile(ctx context.Context, req WriteFileRequest) (WriteFileResult, error) {
	perm, e1 := resolvePerm(req.Perm, defaultRemoteFilePerm)
	e2 := pickIf[error](int64(len(req.Content)) > maxAtomicReadBytes, fmt.Errorf("%w: 载荷超限 %d", ports.ErrLimitExceeded, maxAtomicReadBytes), nil)
	writeSpec, e3 := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: perm, ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber, AtomicRename: true})
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "write", req.Path, security.RiskModerate, nil, firstErr(e1, e2, e3), func(c context.Context, rfs ports.RemoteFSPort) (WriteFileResult, error) {
		if dir := req.Path.Dir(); req.CreateParents && !dir.IsRoot() && dir.String() != "." {
			if mErr := rfs.MkdirAll(c, dir, defaultDirPerm); mErr != nil {
				return WriteFileResult{}, mErr
			}
		}
		st, wErr := rfs.WriteFileAtomic(c, req.Path, writeSpec, bytes.NewReader(req.Content))
		return pickIf(wErr == nil, WriteFileResult{Stat: st, BytesWritten: int64(len(req.Content)), Digest: security.DigestBytes(req.Content)}, WriteFileResult{}), wErr
	})
}
func (s *Service) PatchFile(ctx context.Context, req PatchFileRequest) (PatchFileResult, error) {
	anc, okA := req.ExpectedAnchor.Get()
	dig, okD := req.ExpectedDigest.Get()
	bad := len(req.Edits) == 0 || slices.ContainsFunc(req.Edits, func(ed TextEdit) bool { return !ed.IsValid() }) || (okA && !anc.IsValid()) || (okD && !dig.IsValid())
	limits, e2 := s.resolveReadLimits(req.MaxBytes)
	preErr := firstErr(pickIf[error](bad, fmt.Errorf("%w: PatchFile Edits/ExpectedAnchor/ExpectedDigest 无效", ErrInvalidRequest), nil), e2)
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "patch", req.Path, security.RiskModerate, nil, preErr, func(c context.Context, rfs ports.RemoteFSPort) (PatchFileResult, error) {
		return executeAnchoredPatch(c, rfs, req, limits)
	})
}
func executeAnchoredPatch(ctx context.Context, rfs ports.RemoteFSPort, req PatchFileRequest, limits ports.ReadLimits) (PatchFileResult, error) {
	beforeStat, origBytes, beforeDigest, err := remotecanon.ReadBoundedFile(ctx, rfs, req.Path, limits)
	if err != nil {
		return PatchFileResult{}, err
	}
	if expAnc, okA := req.ExpectedAnchor.Get(); okA && !expAnc.Matches(beforeStat.Anchor()) {
		return PatchFileResult{}, fmt.Errorf("%w: 补丁前置锚点不匹配", ports.ErrRemoteAnchorMismatch)
	} else if expDig, okD := req.ExpectedDigest.Get(); okD && !expDig.Equal(beforeDigest) {
		return PatchFileResult{}, fmt.Errorf("%w: %w", ErrPatchConflict, ErrDigestMismatch)
	}
	patched, replacements, err := applyTextEdits(string(origBytes), req.Edits)
	if err != nil || int64(len(patched)) > maxAtomicReadBytes {
		return PatchFileResult{}, pickIf[error](err != nil, err, fmt.Errorf("%w: 补丁后大小超限 %d", ports.ErrLimitExceeded, maxAtomicReadBytes))
	}
	writeSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: pickIf(beforeStat.Perm() != 0, beforeStat.Perm(), defaultRemoteFilePerm), ExpectedAnchor: algebraic.Some(beforeStat.Anchor()), AtomicRename: true})
	var afterStat ports.RemoteFileStat
	patchedBytes := []byte(patched)
	if err == nil {
		afterStat, err = rfs.WriteFileAtomic(ctx, req.Path, writeSpec, bytes.NewReader(patchedBytes))
	}
	return pickIf(err == nil, PatchFileResult{BeforeStat: beforeStat, AfterStat: afterStat, BeforeDigest: beforeDigest, AfterDigest: security.DigestBytes(patchedBytes), Replacements: replacements, BytesWritten: int64(len(patchedBytes))}, PatchFileResult{}), err
}
func applyTextEdits(content string, edits []TextEdit) (string, int, error) {
	cur, total := content, 0
	for i, ed := range edits {
		oldStr, count := ed.OldText(), strings.Count(cur, ed.OldText())
		if count == 0 || (!ed.ReplaceAll() && count > 1) {
			return "", 0, pickIf(count == 0, fmt.Errorf("%w: %w: Edits[%d]", ErrPatchConflict, ErrPatchNoMatch, i), fmt.Errorf("%w: %w: Edits[%d] 命中 %d 处", ErrPatchConflict, ErrPatchAmbiguous, i, count))
		}
		cur, total = strings.Replace(cur, oldStr, ed.NewText(), pickIf(ed.ReplaceAll(), -1, 1)), total+pickIf(ed.ReplaceAll(), count, 1)
	}
	return cur, total, nil
}
func (s *Service) RenameFile(ctx context.Context, req RenameFileRequest) error {
	defer closeStream(req.OperationStream)
	hop, e1 := s.validateBaseCall(ctx, req.CallBase)
	renameSpec, e2 := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber})
	if err := firstErr(e1, pickIf[error](req.OldPath.IsValid() && req.NewPath.IsValid(), nil, fmt.Errorf("%w: RenameFile 源/目标路径无效", ErrInvalidRequest)), e2); err != nil {
		return err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "file", action: "rename", paths: []pathalg.RemotePath{req.OldPath, req.NewPath}, defaultRisk: security.RiskModerate, summary: "file rename " + req.OldPath.String() + " -> " + req.NewPath.String(), canonicalize: true}
	_, err := runAuthorizedRemoteFS[security.CapFileMut](ctx, s, spec, func(c context.Context, _ gate.Authorized[security.CapFileMut], rfs ports.RemoteFSPort, _ *transferEmitter) (struct{}, error) {
		return struct{}{}, rfs.RenameAtomic(c, req.OldPath, req.NewPath, renameSpec)
	})
	return err
}

// canonicalizeRemoteTargets 执行 Gate Round-2 远端规范化探测（ADR-016 / INV-E5），委托 remotecanon 展开相对路径、软链与容器展开目标。
func (s *Service) canonicalizeRemoteTargets(ctx context.Context, capKind security.CapabilityKind, spec authOpSpec, nodeID string, rpaths, recPaths []pathalg.RemotePath, extra []string) (gate.CanonicalizeResult, error) {
	resolved, resolvedRec, sent := extra, []string(nil), canonSentinels()
	if len(rpaths) > 0 || len(recPaths) > 0 {
		if err := s.withLeasedRemoteFS(ctx, spec.base.Plan, func(leaseCtx context.Context, rfs ports.RemoteFSPort) (rErr error) {
			if resolved, rErr = remotecanon.ResolveCanonicalList(leaseCtx, rfs, rpaths, spec.expandBase, extra, sent); rErr == nil && len(recPaths) > 0 {
				resolvedRec, rErr = remotecanon.ResolveCanonicalList(leaseCtx, rfs, recPaths, pickIf(len(rpaths) == 0, spec.expandBase, ""), nil, sent)
			}
			return rErr
		}); err != nil {
			return gate.CanonicalizeResult{}, err
		}
	}
	canBind, err := buildOperationBinding(capKind, spec, nodeID, resolved, resolvedRec)
	return gate.CanonicalizeResult{Binding: canBind, Paths: resolved, RecursivePaths: resolvedRec}, err
}
