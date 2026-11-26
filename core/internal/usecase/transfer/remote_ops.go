package transfer

import (
	"bytes"
	"context"
	"errors"
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

// Stat / RealPath / ReadLink 查询远端对象元信息、规范路径与软链目标。
func (s *Service) Stat(ctx context.Context, req StatRequest) (ports.RemoteFileStat, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", pickIf(req.FollowSymlinks, "stat", "lstat"), req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (ports.RemoteFileStat, error) {
		return pickIf(req.FollowSymlinks, rfs.Stat, rfs.Lstat)(opCtx, req.Path)
	})
}
func (s *Service) RealPath(ctx context.Context, req RealPathRequest) (pathalg.RemotePath, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "realpath", req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (pathalg.RemotePath, error) {
		return rfs.RealPath(opCtx, req.Path)
	})
}
func (s *Service) ReadLink(ctx context.Context, req ReadLinkRequest) (string, error) {
	return runRemotePathOp[security.CapFileRead](ctx, s, req.CallBase, "sftp", "readlink", req.Path, security.RiskSafe, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) (string, error) {
		return rfs.ReadLink(opCtx, req.Path)
	})
}

// MkdirAll / Remove / RemoveDir / Chmod / Chtimes 执行远端工作区变更（严格隔离 Remove 与 RemoveDir）。
func (s *Service) MkdirAll(ctx context.Context, req MkdirAllRequest) error {
	var perm fs.FileMode
	return runSFTPMut(ctx, s, req.CallBase, "mkdir_all", req.Path, nil, func() (err error) { perm, err = resolvePerm(req.Perm, defaultDirPerm); return err }, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.MkdirAll(opCtx, req.Path, perm) })
}
func (s *Service) Remove(ctx context.Context, req RemoveRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "remove", req.Path, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.Remove(opCtx, req.Path) })
}
func (s *Service) RemoveDir(ctx context.Context, req RemoveDirRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "remove_dir", req.Path, nil, nil, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.RemoveDir(opCtx, req.Path) })
}
func (s *Service) Chmod(ctx context.Context, req ChmodRequest) error {
	return runSFTPMut(ctx, s, req.CallBase, "chmod", req.Path, map[string]string{"perm": fmt.Sprintf("%#o", req.Perm)}, func() error {
		return pickIf[error](req.Perm != 0 && req.Perm == req.Perm.Perm(), nil, fmt.Errorf("%w: Chmod 权限位 %#o 非法", ErrInvalidRequest, req.Perm))
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) error { return rfs.Chmod(opCtx, req.Path, req.Perm) })
}
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
		return pickIf(rErr == nil, ReadFileResult{Stat: st, Content: data, Digest: dig}, ReadFileResult{}), rErr
	})
}

// WriteFile 消费冻结 RemoteWriteSpec（互斥 NoClobber/ExpectedAnchor）执行远端原子写入（ADR-016）。
func (s *Service) WriteFile(ctx context.Context, req WriteFileRequest) (WriteFileResult, error) {
	var writeSpec ports.RemoteWriteSpec
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "write", req.Path, security.RiskModerate, nil, func() error {
		perm, err := resolvePerm(req.Perm, defaultRemoteFilePerm)
		if err != nil || int64(len(req.Content)) > maxAtomicReadBytes {
			return pickIf[error](err != nil, err, fmt.Errorf("%w: 载荷超限 %d", ports.ErrLimitExceeded, maxAtomicReadBytes))
		}
		writeSpec, err = ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: perm, ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber, AtomicRename: true})
		return err
	}, func(opCtx context.Context, rfs ports.RemoteFSPort) (WriteFileResult, error) {
		if dir := req.Path.Dir(); req.CreateParents && !dir.IsRoot() && dir.String() != "." {
			if mErr := rfs.MkdirAll(opCtx, dir, defaultDirPerm); mErr != nil {
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
	return runRemotePathOp[security.CapFileMut](ctx, s, req.CallBase, "file", "patch", req.Path, security.RiskModerate, nil, func() (err error) {
		anc, okA := req.ExpectedAnchor.Get()
		dig, okD := req.ExpectedDigest.Get()
		if len(req.Edits) == 0 || slices.ContainsFunc(req.Edits, func(ed TextEdit) bool { return !ed.IsValid() }) || (okA && !anc.IsValid()) || (okD && !dig.IsValid()) {
			return fmt.Errorf("%w: PatchFile Edits/ExpectedAnchor/ExpectedDigest 无效", ErrInvalidRequest)
		}
		limits, err = s.resolveReadLimits(req.MaxBytes)
		return err
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

// RenameFile 消费互斥 NoClobber / ExpectedAnchor 的冻结 RemoteRenameSpec 执行远端原子重命名。
func (s *Service) RenameFile(ctx context.Context, req RenameFileRequest) error {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, e1 := s.validateBaseCall(ctx, req.CallBase)
	renameSpec, e2 := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber})
	if err := firstErr(e1, pickIf[error](req.OldPath.IsValid() && req.NewPath.IsValid(), nil, fmt.Errorf("%w: RenameFile 源/目标路径无效", ErrInvalidRequest)), e2); err != nil {
		return err
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "file", action: "rename", paths: []pathalg.RemotePath{req.OldPath, req.NewPath}, defaultRisk: security.RiskModerate, summary: "file rename " + req.OldPath.String() + " -> " + req.NewPath.String(), canonicalize: true}
	_, err := runAuthorizedRemoteFS[security.CapFileMut](ctx, s, spec, func(opCtx context.Context, _ gate.Authorized[security.CapFileMut], rfs ports.RemoteFSPort, _ *transferEmitter) (struct{}, error) {
		return struct{}{}, rfs.RenameAtomic(opCtx, req.OldPath, req.NewPath, renameSpec)
	})
	return err
}
func readBoundedRemoteFile(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, limits ports.ReadLimits) (st ports.RemoteFileStat, data []byte, dig security.Digest, err error) {
	if st, err = rfs.Stat(ctx, p); err != nil || !st.IsRegular() {
		return zeroVal[ports.RemoteFileStat](), nil, dig, pickIf[error](err != nil, err, pickIf(st.IsDir(), ports.ErrRemoteIsDir, ports.ErrNotRegularFile))
	}
	if err = rfs.WithReadFile(ctx, p, limits, func(r io.Reader, size int64) (rErr error) {
		if size > limits.MaxBytes() {
			return ports.ErrLimitExceeded
		}
		if data, rErr = io.ReadAll(io.LimitReader(r, limits.MaxBytes()+1)); rErr == nil && int64(len(data)) > limits.MaxBytes() {
			rErr = ports.ErrLimitExceeded
		}
		return rErr
	}); err != nil {
		return zeroVal[ports.RemoteFileStat](), nil, dig, err
	}
	afterSt, err := rfs.Stat(ctx, p)
	if err != nil || !st.Anchor().Equal(afterSt.Anchor()) || afterSt.Size() != int64(len(data)) || !st.ModTime().Equal(afterSt.ModTime()) {
		return zeroVal[ports.RemoteFileStat](), nil, dig, pickIf[error](err != nil, err, ports.ErrRemoteAnchorMismatch)
	}
	return st, data, security.DigestBytes(data), nil
}

// makeRemoteCanonicalizer 构造 Gate Round-2 远端规范化探测回调（ADR-016 / INV-E5），
// 覆盖相对路径工作目录锚定、多跳/中间悬空软链展开及 SCPUpload(ExpandIntoDir) 容器展开子目标。
func (s *Service) makeRemoteCanonicalizer(capKind security.CapabilityKind, spec authOpSpec, nodeID string) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		return s.canonicalizeRemoteTargets(ctx, capKind, spec, nodeID, spec.paths, spec.recursivePaths, spec.extraPaths)
	}
}
func (s *Service) canonicalizeRemoteTargets(ctx context.Context, capKind security.CapabilityKind, spec authOpSpec, nodeID string, rpaths, recPaths []pathalg.RemotePath, extra []string) (gate.CanonicalizeResult, error) {
	resolved, resolvedRec := extra, []string(nil)
	if len(rpaths) > 0 || len(recPaths) > 0 {
		if err := s.withLeasedRemoteFS(ctx, spec.base.Plan, func(leaseCtx context.Context, rfs ports.RemoteFSPort) (rErr error) {
			if resolved, rErr = resolveCanonicalList(leaseCtx, rfs, rpaths, spec.expandBase, extra); rErr == nil && len(recPaths) > 0 {
				resolvedRec, rErr = resolveCanonicalList(leaseCtx, rfs, recPaths, "", nil)
			}
			return rErr
		}); err != nil {
			return gate.CanonicalizeResult{}, err
		}
	}
	canBind, err := buildOperationBinding(capKind, spec, nodeID, resolved, resolvedRec)
	return gate.CanonicalizeResult{Binding: canBind, Paths: resolved, RecursivePaths: resolvedRec}, err
}
func resolveCanonicalList(ctx context.Context, rfs ports.RemoteFSPort, rpaths []pathalg.RemotePath, expandBase string, extra []string) ([]string, error) {
	out := make([]string, 0, len(rpaths)*2+len(extra))
	for _, p := range rpaths {
		if !p.IsValid() {
			continue
		}
		canon, err := resolveCanonicalRemotePath(ctx, rfs, p)
		if err != nil {
			return nil, err
		}
		out = append(out, p.String())
		if !canon.Equal(p) {
			out = append(out, canon.String())
		}
		if expandBase != "" {
			exp, ok, eErr := resolveExpandedUploadCandidate(ctx, rfs, p, expandBase)
			if eErr != nil {
				return nil, eErr
			}
			if ok {
				out = append(out, exp)
			}
		}
	}
	return append(out, slices.DeleteFunc(slices.Clone(extra), func(s string) bool { return s == "" })...), nil
}
func resolveExpandedUploadCandidate(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, baseName string) (string, bool, error) {
	exists, isDir, err := inspectRemoteUploadTarget(ctx, rfs, dest)
	if err != nil || !exists || !isDir {
		return "", false, err
	}
	expanded, err := joinRemoteBase(dest, baseName)
	if err != nil {
		return "", false, err
	}
	canon, err := resolveCanonicalRemotePath(ctx, rfs, expanded)
	return canon.String(), err == nil, err
}

// resolveCanonicalRemotePath 在有界跳数预算（pathalg.MaxSymlinkHops）内解析远端真实 POSIX 路径：
// 先经 RealPath(".") 锚定相对路径，再在统一祖先回溯循环中逐级展开末端及中间悬空软链（0 path/filepath）。
func resolveCanonicalRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	cur, err := anchorRemotePath(ctx, rfs, p)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	var suffix []pathalg.RemoteName
	for hops := 0; len(suffix) < maxRemoteCanonicalDepth; {
		if realCur, rErr := rfs.RealPath(ctx, cur); rErr == nil {
			return rejoinRemoteSuffix(realCur, suffix)
		} else if !errors.Is(rErr, ports.ErrNotFound) {
			return zeroVal[pathalg.RemotePath](), rErr
		}
		if nextCur, jumped, jErr := expandDanglingSymlinkStep(ctx, rfs, cur, suffix, &hops); jErr != nil {
			return zeroVal[pathalg.RemotePath](), jErr
		} else if jumped {
			cur, suffix = nextCur, suffix[:0]
			continue
		}
		base, ok := cur.Base()
		if !ok || cur.IsRoot() || cur.Dir().Equal(cur) {
			return rejoinRemoteSuffix(cur, suffix)
		}
		suffix, cur = append(suffix, base), cur.Dir()
	}
	return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 远端路径规范化超限 %d", ErrInvalidRequest, maxRemoteCanonicalDepth)
}
func anchorRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	if p.IsAbs() {
		return p, nil
	}
	dot, _ := pathalg.ParseRemotePath(".")
	cwd, err := rfs.RealPath(ctx, dot)
	if err != nil || !cwd.IsAbs() {
		return zeroVal[pathalg.RemotePath](), pickIf[error](err != nil, err, fmt.Errorf("%w: 远端工作目录非绝对路径", ErrInvalidRequest))
	}
	return cwd.Resolve(p)
}
func expandDanglingSymlinkStep(ctx context.Context, rfs ports.RemoteFSPort, cur pathalg.RemotePath, suffix []pathalg.RemoteName, hops *int) (pathalg.RemotePath, bool, error) {
	lst, err := rfs.Lstat(ctx, cur)
	if errors.Is(err, ports.ErrNotFound) || (err == nil && !lst.IsSymlink()) {
		return zeroVal[pathalg.RemotePath](), false, nil
	}
	if err != nil || *hops >= pathalg.MaxSymlinkHops {
		return zeroVal[pathalg.RemotePath](), false, pickIf[error](err != nil, err, fmt.Errorf("%w: 远端软链展开跳数超过上限 %d", ErrSymlinkPolicyDenied, pathalg.MaxSymlinkHops))
	}
	*hops++
	raw, err := rfs.ReadLink(ctx, cur)
	var targetP, nextBase pathalg.RemotePath
	if err == nil {
		targetP, err = pathalg.ParseRemotePath(raw)
	}
	if err == nil {
		nextBase, err = cur.Dir().Resolve(targetP)
	}
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	nextFull, err := rejoinRemoteSuffix(nextBase, suffix)
	return nextFull, err == nil, err
}
func rejoinRemoteSuffix(base pathalg.RemotePath, revSuffix []pathalg.RemoteName) (pathalg.RemotePath, error) {
	if len(revSuffix) == 0 {
		return base, nil
	}
	ordered := slices.Clone(revSuffix)
	slices.Reverse(ordered)
	return base.Join(ordered...)
}

// verifyRemotePathAuthorized 在非 DirectOperator 配置档下复核远端目标真实路径未漂移出授权 CanonicalPaths。
func verifyRemotePathAuthorized(ctx context.Context, enforce bool, rfs ports.RemoteFSPort, binding security.OperationBinding, target pathalg.RemotePath) error {
	if !enforce {
		return nil
	}
	canon, err := resolveCanonicalRemotePath(ctx, rfs, target)
	return firstErr(err, pickIf[error](slices.Contains(binding.CanonicalPaths(), canon.String()), nil, fmt.Errorf("%w: 远端路径 %s 规范化漂移至未授权目标 %s", gate.ErrScopeEscalated, target, canon)))
}
