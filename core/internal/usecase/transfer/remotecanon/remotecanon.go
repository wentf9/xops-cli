// Package remotecanon 提供与远端 SFTP/POSIX 路径相关的纯无状态规范化、作用域漂移复核、
// INV-B4 单次上传容器展开与有界读取原语，供 core/internal/usecase/transfer 复用（ADR-016 / INV-B4 / INV-E5）。
package remotecanon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

const maxRemoteCanonicalDepth = 128

// Sentinels 注入调用包语义错误哨兵，确保全路径保链兼容 transfer.ErrInvalidRequest 与 ErrSymlinkPolicyDenied。
type Sentinels struct {
	Invalid error
	Symlink error
}

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}

// JoinRemoteBase 校验并拼接单个远端文件名至目录路径（严禁引入 path/filepath）。
func JoinRemoteBase(dir pathalg.RemotePath, base string, invalidErr error) (pathalg.RemotePath, error) {
	name, err := pathalg.ParseRemoteName(path.Base(base))
	if err != nil {
		return zeroVal[pathalg.RemotePath](), domi18n.WrapS(invalidErr, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "remote_name"), domi18n.BoundStr("value", base))
	}
	return dir.Join(name)
}

// ReadChunkExact 从远端文件偏移处精确读取 want 字节，读短即返回 io.ErrUnexpectedEOF。
func ReadChunkExact(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, offset, want int64) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(int(want))
	got, err := rfs.ReadChunk(ctx, p, offset, &buf, want)
	if (err != nil && !errors.Is(err, io.EOF)) || got != want {
		return nil, pickIf[error](err != nil && !errors.Is(err, io.EOF), err, domi18n.EF(io.ErrUnexpectedEOF, domi18n.KeyCommonMismatch, domi18n.Str("field", "remote_chunk_bytes"), domi18n.Int64("expected", want), domi18n.Int64("actual", got)))
	}
	return buf.Bytes(), nil
}

// ReadBoundedFile 执行有界读取并在读写前后复核远端 Stat 锚点、大小与修改时间，防止并发篡改。
func ReadBoundedFile(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, limits ports.ReadLimits) (st ports.RemoteFileStat, data []byte, dig security.Digest, err error) {
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

// InspectUploadTarget 经 Lstat 与必要时 Stat 识别远端目标存在性（含悬空软链）及是否为目录。
func InspectUploadTarget(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (exists, isDir bool, err error) {
	lstat, err := rfs.Lstat(ctx, p)
	if errors.Is(err, ports.ErrNotFound) {
		return false, false, nil
	}
	if err != nil || lstat.IsDir() || !lstat.IsSymlink() {
		return err == nil, err == nil && lstat.IsDir(), err
	}
	st, err := rfs.Stat(ctx, p)
	return true, err == nil && st.IsDir(), pickIf[error](errors.Is(err, ports.ErrNotFound), nil, err)
}

// ResolveUploadTarget 严守 INV-B4：至多一次远端容器目录展开，经 Lstat 识别悬空软链与目录/文件类型冲突。
func ResolveUploadTarget(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, sourceBase string, expandIntoDir, noClobber, wantDir bool, invalidErr error) (pathalg.RemotePath, error) {
	exists, isDir, err := InspectUploadTarget(ctx, rfs, dest)
	if err == nil && exists && isDir && expandIntoDir {
		dest, exists, isDir, err = expandUploadContainer(ctx, rfs, dest, sourceBase, invalidErr)
	}
	if err != nil {
		return zeroVal[pathalg.RemotePath](), err
	}
	if exists && isDir != wantDir {
		return zeroVal[pathalg.RemotePath](), pickIf(wantDir, domi18n.EF(ports.ErrAlreadyExists, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", dest.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonExistsNonDir))), domi18n.EF(ports.ErrRemoteIsDir, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", dest.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonTargetIsDir))))
	}
	return dest, pickIf[error](exists && noClobber, domi18n.EF(ports.ErrAlreadyExists, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", dest.String()), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyUCTransferReasonNoClobber))), nil)
}
func expandUploadContainer(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, sourceBase string, invalidErr error) (pathalg.RemotePath, bool, bool, error) {
	joined, err := JoinRemoteBase(dest, sourceBase, invalidErr)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, false, err
	}
	exists, isDir, err := InspectUploadTarget(ctx, rfs, joined)
	return joined, exists, isDir, err
}

// ResolveCanonicalList 展开目标列表对应的远端真实 POSIX 路径及可选单次容器展开候选，用于 Gate Round-2 规范化。
func ResolveCanonicalList(ctx context.Context, rfs ports.RemoteFSPort, rpaths []pathalg.RemotePath, expandBase string, extra []string, s Sentinels) ([]string, error) {
	out := make([]string, 0, len(rpaths)*2+len(extra))
	for _, p := range rpaths {
		if !p.IsValid() {
			continue
		}
		canon, err := ResolveCanonicalPath(ctx, rfs, p, s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.String())
		if !canon.Equal(p) {
			out = append(out, canon.String())
		}
		if expandBase != "" {
			if exp, ok, eErr := resolveExpandedCandidate(ctx, rfs, p, expandBase, s); eErr != nil {
				return nil, eErr
			} else if ok {
				out = append(out, exp)
			}
		}
	}
	return append(out, slices.DeleteFunc(slices.Clone(extra), func(str string) bool { return str == "" })...), nil
}
func resolveExpandedCandidate(ctx context.Context, rfs ports.RemoteFSPort, dest pathalg.RemotePath, baseName string, s Sentinels) (string, bool, error) {
	exists, isDir, err := InspectUploadTarget(ctx, rfs, dest)
	if err != nil || !exists || !isDir {
		return "", false, err
	}
	expanded, err := JoinRemoteBase(dest, baseName, s.Invalid)
	var canon pathalg.RemotePath
	if err == nil {
		canon, err = ResolveCanonicalPath(ctx, rfs, expanded, s)
	}
	return canon.String(), err == nil, err
}

// ResolveCanonicalPath 在有界跳数预算（pathalg.MaxSymlinkHops）内解析远端真实 POSIX 路径：
// 先经 RealPath(".") 锚定相对路径，再在统一祖先回溯循环中逐级展开末端及中间悬空软链（零本地路径库依赖）。
func ResolveCanonicalPath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, s Sentinels) (pathalg.RemotePath, error) {
	cur, err := anchorRemotePath(ctx, rfs, p, s.Invalid)
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
		if nextCur, jumped, jErr := expandDanglingSymlinkStep(ctx, rfs, cur, suffix, &hops, s); jErr != nil {
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
	return zeroVal[pathalg.RemotePath](), domi18n.EF(s.Invalid, domi18n.KeyCommonFieldMaxExceeded, domi18n.Str("field", "canonical_depth"), domi18n.Int("value", maxRemoteCanonicalDepth), domi18n.Int("max", maxRemoteCanonicalDepth))
}
func anchorRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, invalidErr error) (pathalg.RemotePath, error) {
	if p.IsAbs() {
		return p, nil
	}
	dot, _ := pathalg.ParseRemotePath(".")
	cwd, err := rfs.RealPath(ctx, dot)
	if err != nil || !cwd.IsAbs() {
		return zeroVal[pathalg.RemotePath](), pickIf[error](err != nil, err, domi18n.EF(invalidErr, domi18n.KeyUCTransferRemoteAbs))
	}
	return cwd.Resolve(p)
}
func expandDanglingSymlinkStep(ctx context.Context, rfs ports.RemoteFSPort, cur pathalg.RemotePath, suffix []pathalg.RemoteName, hops *int, s Sentinels) (pathalg.RemotePath, bool, error) {
	lst, err := rfs.Lstat(ctx, cur)
	if errors.Is(err, ports.ErrNotFound) || (err == nil && !lst.IsSymlink()) {
		return zeroVal[pathalg.RemotePath](), false, nil
	}
	if err != nil || *hops >= pathalg.MaxSymlinkHops {
		return zeroVal[pathalg.RemotePath](), false, pickIf[error](err != nil, err, domi18n.EF(s.Symlink, domi18n.KeyUCTransferRemoteHops, domi18n.Int("limit", pathalg.MaxSymlinkHops)))
	}
	*hops++
	raw, err := rfs.ReadLink(ctx, cur)
	var targetP, nextBase pathalg.RemotePath
	if err == nil {
		targetP, err = pathalg.ParseRemotePath(raw)
	}
	if err == nil && targetP.IsAbs() {
		nextBase = targetP
	} else if err == nil {
		nextBase, err = resolveRelativeLinkBase(ctx, rfs, cur.Dir(), targetP, s.Invalid)
	}
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	nextFull, err := rejoinRemoteSuffix(nextBase, suffix)
	return nextFull, err == nil, err
}
func resolveRelativeLinkBase(ctx context.Context, rfs ports.RemoteFSPort, parent, rel pathalg.RemotePath, invalidErr error) (pathalg.RemotePath, error) {
	realParent, err := rfs.RealPath(ctx, parent)
	if err != nil || !realParent.IsAbs() {
		return zeroVal[pathalg.RemotePath](), pickIf[error](err != nil, err, domi18n.EF(invalidErr, domi18n.KeyUCTransferRemoteAbs))
	}
	return realParent.Resolve(rel)
}
func rejoinRemoteSuffix(base pathalg.RemotePath, revSuffix []pathalg.RemoteName) (pathalg.RemotePath, error) {
	if len(revSuffix) == 0 {
		return base, nil
	}
	ordered := slices.Clone(revSuffix)
	slices.Reverse(ordered)
	return base.Join(ordered...)
}

// VerifyPathAuthorized 在非 DirectOperator 配置档下复核远端目标真实路径未漂移出授权 CanonicalPaths/RecursivePaths。
func VerifyPathAuthorized(ctx context.Context, enforce bool, rfs ports.RemoteFSPort, binding security.OperationBinding, target pathalg.RemotePath, s Sentinels) error {
	if !enforce {
		return nil
	}
	canon, err := ResolveCanonicalPath(ctx, rfs, target, s)
	if err != nil {
		return err
	}
	cs := canon.String()
	ok := slices.Contains(binding.CanonicalPaths(), cs) || slices.ContainsFunc(binding.RecursivePaths(), func(root string) bool { return root == "/" || cs == root || strings.HasPrefix(cs, root+"/") })
	return pickIf[error](ok, nil, domi18n.EF(gate.ErrScopeEscalated, domi18n.KeyUCTransferRemoteDrift, domi18n.BoundStr("path", target.String()), domi18n.BoundStr("target", canon.String())))
}

// VerifyDownloadSource 复核远端下载源未发生软链漂移且 Lstat 锚点/大小/修改时间与起始快照完全一致。
func VerifyDownloadSource(ctx context.Context, enforce bool, rfs ports.RemoteFSPort, binding security.OperationBinding, rs pathalg.RemotePath, expAnchor ports.RemoteFileAnchor, expSize int64, expModTime time.Time, s Sentinels) error {
	if err := VerifyPathAuthorized(ctx, enforce, rfs, binding, rs, s); err != nil {
		return err
	}
	st, err := rfs.Lstat(ctx, rs)
	if err != nil || !st.IsRegular() {
		return pickIf[error](err != nil, err, pickIf(st.IsSymlink(), ports.ErrSymlinkRejected, pickIf(st.IsDir(), ports.ErrRemoteIsDir, ports.ErrNotRegularFile)))
	}
	return pickIf[error](expAnchor.Equal(st.Anchor()) && st.Size() == expSize && expModTime.Equal(st.ModTime()), nil, ports.ErrRemoteAnchorMismatch)
}

// HashRemoteStage 经 SFTP 分片顺序回读远端暂存文件并计算完整 SHA-256 摘要，校验文件类型与预期总字节数。
func HashRemoteStage(ctx context.Context, rfs ports.RemoteFSPort, stageOpt algebraic.Option[pathalg.RemotePath], totalBytes uint64, chunkSize int64, invalidErr error) (security.Digest, error) {
	stagePath, ok := stageOpt.Get()
	if !ok {
		return zeroVal[security.Digest](), domi18n.EF(invalidErr, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "remote_stage_path"))
	}
	if st, err := rfs.Lstat(ctx, stagePath); err != nil || !st.IsRegular() || uint64(st.Size()) != totalBytes {
		return zeroVal[security.Digest](), pickIf[error](err != nil, err, pickIf(!st.IsRegular(), ports.ErrNotRegularFile, domi18n.EF(io.ErrUnexpectedEOF, domi18n.KeyCommonMismatch, domi18n.Str("field", "remote_stage_size"), domi18n.Uint64("expected", totalBytes), domi18n.Int64("actual", st.Size()))))
	}
	h := sha256.New()
	for offset := int64(0); uint64(offset) < totalBytes; {
		data, err := ReadChunkExact(ctx, rfs, stagePath, offset, min(chunkSize, int64(totalBytes)-offset))
		if err != nil {
			return zeroVal[security.Digest](), err
		}
		_, _ = h.Write(data)
		offset += int64(len(data))
	}
	return security.DigestFromSHA256([sha256.Size]byte(h.Sum(nil))), nil
}
