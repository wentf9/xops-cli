package tck

import (
	"bytes"
	"context"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// RemoteFSFixture 描述 RemoteFSPort（SFTP v3 协议无关安全文件端口）契约测试夹具。
type RemoteFSFixture struct {
	// NewRemoteFS 返回隔离的 RemoteFSPort 与测试工作目录路径（如 "/tmp/tck"）。
	NewRemoteFS func(t *testing.T) (ports.RemoteFSPort, pathalg.RemotePath)
	// CheckDevInoAnchor 为 true 时使用携带 (dev, ino) 的失配锚点验证 FSTAT 锚定拦截（ADR-016）。
	CheckDevInoAnchor bool
}

// RunRemoteFSSuite 验证 RemoteFSPort 的全部安全读写、有界读取、NoClobber、FSTAT 锚点校验、原子重命名、Chtimes 与目录删除契约（ADR-016）。
func RunRemoteFSSuite(t *testing.T, fx RemoteFSFixture) {
	t.Helper()
	requireTrue(t, fx.NewRemoteFS != nil, "RemoteFSFixture.NewRemoteFS 不能为 nil")
	t.Run("ValidationAndCRUD", func(t *testing.T) {
		defer VerifyNoLeaks(t)
		ctx := context.Background()
		rfs, workDir := fx.NewRemoteFS(t)
		requireTrue(t, workDir.IsValid(), "workDir 必须为有效 RemotePath")
		verifyRemoteFSGuards(t, ctx, rfs)
		verifyRemoteFSWriteReadAnchor(t, ctx, rfs, workDir, fx.CheckDevInoAnchor)
		verifyRemoteFSChunkAndRename(t, ctx, rfs, workDir)
		verifyRemoteFSDirRemove(t, ctx, rfs, workDir)
		requireNoErr(t, rfs.Close(), "RemoteFSPort.Close(1)")
		requireNoErr(t, rfs.Close(), "RemoteFSPort.Close(2, idempotent)")
	})
}
func verifyRemoteFSGuards(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort) {
	t.Helper()
	var nilCtx context.Context
	var zeroPath pathalg.RemotePath
	var zeroSpec ports.RemoteWriteSpec
	var zeroRename ports.RemoteRenameSpec
	lim, err := ports.NewReadLimits(1024)
	requireNoErr(t, err, "NewReadLimits")
	_, err = rfs.Stat(nilCtx, zeroPath)
	requireErrIs(t, err, ports.ErrNilContext, "Stat(nil ctx)")
	_, err = rfs.Stat(ctx, zeroPath)
	requireErr(t, err, "Stat(zero path)")
	requireErrIs(t, rfs.WithReadFile(ctx, zeroPath, lim, nil), ports.ErrNilCallback, "WithReadFile(nil fn)")
	_, err = rfs.WriteFileAtomic(ctx, zeroPath, zeroSpec, strings.NewReader("x"))
	requireErr(t, err, "WriteFileAtomic(zero path/spec)")
	requireErrIs(t, rfs.RenameAtomic(ctx, zeroPath, zeroPath, zeroRename), ports.ErrInvalidArgument, "RenameAtomic(zero spec)")
	requireErrIs(t, rfs.Chtimes(nilCtx, zeroPath, BaseTime(), BaseTime()), ports.ErrNilContext, "Chtimes(nil ctx)")
	requireErrIs(t, rfs.RemoveDir(nilCtx, zeroPath), ports.ErrNilContext, "RemoveDir(nil ctx)")
}
func verifyRemoteFSWriteReadAnchor(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, workDir pathalg.RemotePath, checkDevIno bool) {
	t.Helper()
	requireNoErr(t, rfs.MkdirAll(ctx, workDir, 0o755), "MkdirAll(workDir)")
	realDir, err := rfs.RealPath(ctx, workDir)
	requireNoErr(t, err, "RealPath(workDir)")
	requireTrue(t, realDir.IsValid(), "RealPath 须返回有效路径")
	filePath, err := pathalg.ParseRemotePath(strings.TrimRight(realDir.String(), "/") + "/hello.txt")
	requireNoErr(t, err, "ParseRemotePath(hello.txt)")
	createSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644, NoClobber: true, AtomicRename: true})
	requireNoErr(t, err, "NewRemoteWriteSpec(noClobber)")
	stat1, err := rfs.WriteFileAtomic(ctx, filePath, createSpec, strings.NewReader("remote-v1"))
	requireNoErr(t, err, "WriteFileAtomic(v1)")
	requireTrue(t, stat1.IsValid() && stat1.IsRegular() && stat1.Size() == 9, "WriteFileAtomic 返回元信息不匹配")
	_, err = rfs.WriteFileAtomic(ctx, filePath, createSpec, strings.NewReader("overwrite-blocked"))
	requireErrIs(t, err, ports.ErrAlreadyExists, "NoClobber 必须阻止覆盖已有文件")
	matchSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o644, ExpectedAnchor: algebraic.Some(stat1.Anchor()), AtomicRename: true,
	})
	requireNoErr(t, err, "NewRemoteWriteSpec(matchAnchor)")
	stat2, err := rfs.WriteFileAtomic(ctx, filePath, matchSpec, strings.NewReader("remote-v2-ok"))
	requireNoErr(t, err, "WriteFileAtomic(matching anchor)")
	requireTrue(t, stat2.Size() == 12, "匹配锚点覆写后大小不符")
	badAnchor, err := ports.NewRemoteFileAnchor(ports.RemoteFileDir, false, 0, 0)
	if checkDevIno && stat2.Anchor().HasDevIno() {
		badAnchor, err = ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, stat2.Anchor().Dev()+1, stat2.Anchor().Ino()+1)
	}
	requireNoErr(t, err, "NewRemoteFileAnchor(mismatch)")
	badSpec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{
		Perm: 0o644, ExpectedAnchor: algebraic.Some(badAnchor),
	})
	requireNoErr(t, err, "NewRemoteWriteSpec(badAnchor)")
	_, err = rfs.WriteFileAtomic(ctx, filePath, badSpec, strings.NewReader("must-fail"))
	requireErrIs(t, err, ports.ErrRemoteAnchorMismatch, "失配锚点必须返回 ErrRemoteAnchorMismatch")
	lim, err := ports.NewReadLimits(64)
	requireNoErr(t, err, "NewReadLimits")
	var got []byte
	err = rfs.WithReadFile(ctx, filePath, lim, func(r io.Reader, size int64) error {
		requireTrue(t, size == 12, "WithReadFile size 不符")
		var rErr error
		got, rErr = io.ReadAll(r)
		return rErr
	})
	requireNoErr(t, err, "WithReadFile")
	requireTrue(t, bytes.Equal(got, []byte("remote-v2-ok")), "WithReadFile 内容不匹配")
	tinyLim, err := ports.NewReadLimits(4)
	requireNoErr(t, err, "NewReadLimits(4)")
	err = rfs.WithReadFile(ctx, filePath, tinyLim, func(r io.Reader, _ int64) error {
		_, rErr := io.ReadAll(r)
		return rErr
	})
	requireErrIs(t, err, ports.ErrLimitExceeded, "超出 ReadLimits 须拒绝")
	entries, err := rfs.ReadDir(ctx, realDir)
	requireNoErr(t, err, "ReadDir")
	requireTrue(t, len(entries) >= 1 && entries[0].IsValid(), "ReadDir 须返回有效 RemoteDirEntry")
}
func verifyRemoteFSChunkAndRename(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, workDir pathalg.RemotePath) {
	t.Helper()
	base := strings.TrimRight(workDir.String(), "/")
	stagePath, err := pathalg.ParseRemotePath(base + "/upload.part")
	requireNoErr(t, err, "ParseRemotePath(stage)")
	finalPath, err := pathalg.ParseRemotePath(base + "/upload.bin")
	requireNoErr(t, err, "ParseRemotePath(final)")
	overwriteSpec, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{})
	requireNoErr(t, err, "NewRemoteRenameSpec(overwrite)")
	noClobberSpec, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{NoClobber: true})
	requireNoErr(t, err, "NewRemoteRenameSpec(noClobber)")
	requireNoErr(t, rfs.WriteChunk(ctx, stagePath, 0, strings.NewReader("chunk-1-"), 8), "WriteChunk(0)")
	requireNoErr(t, rfs.WriteChunk(ctx, stagePath, 8, strings.NewReader("chunk-2"), 7), "WriteChunk(8)")
	var zeroRename ports.RemoteRenameSpec
	requireErrIs(t, rfs.RenameAtomic(ctx, stagePath, finalPath, zeroRename), ports.ErrInvalidArgument, "RenameAtomic 零值规格必须失败关闭")
	requireNoErr(t, rfs.RenameAtomic(ctx, stagePath, finalPath, overwriteSpec), "RenameAtomic")
	st, err := rfs.Lstat(ctx, finalPath)
	requireNoErr(t, err, "Lstat(final)")
	requireTrue(t, st.IsValid() && st.IsRegular() && st.Size() == 15, "分片合并重命名后大小应为 15")
	verifyRemoteFSReadChunkAndMeta(t, ctx, rfs, finalPath)
	// 验证 NoClobber、锚点失配拦截与匹配锚点覆盖语义（ADR-016）。
	stage2Path, err := pathalg.ParseRemotePath(base + "/upload2.part")
	requireNoErr(t, err, "ParseRemotePath(stage2)")
	requireNoErr(t, rfs.WriteChunk(ctx, stage2Path, 0, strings.NewReader("new!"), 4), "WriteChunk(stage2)")
	requireErrIs(t, rfs.RenameAtomic(ctx, stage2Path, finalPath, noClobberSpec), ports.ErrAlreadyExists, "RenameAtomic(NoClobber) 须阻止覆盖既有目标")
	wrongAnc, err := ports.NewRemoteFileAnchor(ports.RemoteFileDir, false, 0, 0)
	requireNoErr(t, err, "NewRemoteFileAnchor(wrong)")
	badAnchorSpec, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: algebraic.Some(wrongAnc)})
	requireNoErr(t, err, "NewRemoteRenameSpec(wrong)")
	requireErrIs(t, rfs.RenameAtomic(ctx, stage2Path, finalPath, badAnchorSpec), ports.ErrRemoteAnchorMismatch, "RenameAtomic 锚点失配须返回 ErrRemoteAnchorMismatch")
	stAfter, err := rfs.Lstat(ctx, finalPath)
	requireNoErr(t, err, "Lstat(final after rejected rename)")
	requireTrue(t, stAfter.Size() == 15, "被拒 RenameAtomic 不得覆盖既有目标文件")
	matchAnchorSpec, err := ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: algebraic.Some(stAfter.Anchor())})
	requireNoErr(t, err, "NewRemoteRenameSpec(match)")
	requireNoErr(t, rfs.RenameAtomic(ctx, stage2Path, finalPath, matchAnchorSpec), "RenameAtomic(匹配锚点覆盖)")
	stReplaced, err := rfs.Lstat(ctx, finalPath)
	requireNoErr(t, err, "Lstat(final after match rename)")
	requireTrue(t, stReplaced.Size() == 4, "匹配锚点 RenameAtomic 应原子替换为新文件")
	requireNoErr(t, rfs.Remove(ctx, finalPath), "Remove(final)")
	requireErrIs(t, rfs.Remove(ctx, finalPath), ports.ErrNotFound, "重复 Remove 须返回 ErrNotFound")
}
func verifyRemoteFSReadChunkAndMeta(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) {
	t.Helper()
	var buf bytes.Buffer
	_, err := rfs.ReadChunk(ctx, p, -1, &buf, 4)
	requireErr(t, err, "ReadChunk(负偏移)")
	_, err = rfs.ReadChunk(ctx, p, 0, nil, 4)
	requireErr(t, err, "ReadChunk(nil dst)")
	n1, err := rfs.ReadChunk(ctx, p, 0, &buf, 8)
	requireNoErr(t, err, "ReadChunk(0..8)")
	requireTrue(t, n1 == 8 && buf.String() == "chunk-1-", "ReadChunk 首片内容不匹配")
	buf.Reset()
	n2, err := rfs.ReadChunk(ctx, p, 8, &buf, 16)
	requireErrIs(t, err, io.EOF, "ReadChunk 越尾读取须返回 io.EOF")
	requireTrue(t, n2 == 7 && buf.String() == "chunk-2", "ReadChunk 尾片内容不匹配")
	buf.Reset()
	n3, err := rfs.ReadChunk(ctx, p, 15, &buf, 4)
	requireErrIs(t, err, io.EOF, "ReadChunk 精确在 EOF 处须返回 io.EOF")
	requireTrue(t, n3 == 0, "EOF 处 ReadChunk 须返回 0 字节")
	requireErr(t, rfs.Chmod(ctx, p, 0), "Chmod(0)")
	requireErr(t, rfs.Chmod(ctx, p, fs.ModeSetuid|0o755), "Chmod(特殊权限位)")
	requireNoErr(t, rfs.Chmod(ctx, p, 0o640), "Chmod(0640)")
	st, err := rfs.Stat(ctx, p)
	requireNoErr(t, err, "Stat(after Chmod)")
	requireTrue(t, st.Perm() == 0o640, "Chmod 后 Stat.Perm 须为 0640")
	// 验证 Chtimes 零值/越界年份时间戳拒绝、缺失对象返回 ErrNotFound 与有效时间戳更新。
	requireErrIs(t, rfs.Chtimes(ctx, p, time.Time{}, BaseTime()), ports.ErrInvalidArgument, "Chtimes(zero atime)")
	requireErrIs(t, rfs.Chtimes(ctx, p, BaseTime(), time.Time{}), ports.ErrInvalidArgument, "Chtimes(zero mtime)")
	requireErrIs(t, rfs.Chtimes(ctx, p, BaseTime(), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)), ports.ErrInvalidArgument, "Chtimes(year > 9999)")
	missingP, err := pathalg.ParseRemotePath(p.String() + ".absent")
	requireNoErr(t, err, "ParseRemotePath(absent)")
	requireErrIs(t, rfs.Chtimes(ctx, missingP, BaseTime(), BaseTime()), ports.ErrNotFound, "Chtimes(missing)")
	wantTS := BaseTime().Add(2 * time.Hour)
	requireNoErr(t, rfs.Chtimes(ctx, p, wantTS, wantTS), "Chtimes(valid)")
	stTS, err := rfs.Stat(ctx, p)
	requireNoErr(t, err, "Stat(after Chtimes)")
	requireTrue(t, stTS.ModTime().Truncate(time.Second).Equal(wantTS.Truncate(time.Second)), "Chtimes 后 Stat.ModTime 须反映目标修改时间")
}
func verifyRemoteFSDirRemove(t *testing.T, ctx context.Context, rfs ports.RemoteFSPort, workDir pathalg.RemotePath) {
	t.Helper()
	base := strings.TrimRight(workDir.String(), "/")
	subDir, err := pathalg.ParseRemotePath(base + "/rmdir-sub")
	requireNoErr(t, err, "ParseRemotePath(rmdir-sub)")
	childFile, err := pathalg.ParseRemotePath(base + "/rmdir-sub/item.txt")
	requireNoErr(t, err, "ParseRemotePath(child)")
	requireNoErr(t, rfs.MkdirAll(ctx, subDir, 0o755), "MkdirAll(subDir)")
	ws, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644})
	requireNoErr(t, err, "NewRemoteWriteSpec")
	_, err = rfs.WriteFileAtomic(ctx, childFile, ws, strings.NewReader("v"))
	requireNoErr(t, err, "WriteFileAtomic(child)")
	requireErrIs(t, rfs.Remove(ctx, subDir), ports.ErrRemoteIsDir, "Remove 目录必须返回 ErrRemoteIsDir")
	requireErrIs(t, rfs.RemoveDir(ctx, childFile), ports.ErrInvalidArgument, "RemoveDir 常规文件必须拒绝")
	requireErrIs(t, rfs.RemoveDir(ctx, subDir), ports.ErrInvalidArgument, "RemoveDir 非空目录必须拒绝")
	requireNoErr(t, rfs.Remove(ctx, childFile), "Remove(child)")
	requireNoErr(t, rfs.RemoveDir(ctx, subDir), "RemoveDir(empty)")
	requireErrIs(t, rfs.RemoveDir(ctx, subDir), ports.ErrNotFound, "重复 RemoveDir 须返回 ErrNotFound")
}
