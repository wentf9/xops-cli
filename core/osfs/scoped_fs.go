package osfs

import (
	"bytes"
	"cmp"
	"errors"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"io"
	"io/fs"
	"math"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// ScopedFS 是基于 Go *os.Root 的沙箱本地文件系统适配器，仅实现 ports.ScopedRootFS（零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type ScopedFS struct{ valid bool }

// NewScopedRootFS 构造可用的沙箱本地文件系统实例（ports.ScopedRootFS 生产实现）。
func NewScopedRootFS() *ScopedFS { return &ScopedFS{valid: true} }

// EnsureRoot 实现 ports.ScopedRootFS.EnsureRoot，在 WithRoot 前安全引导沙箱根目录存在。
func (s *ScopedFS) EnsureRoot(dir pathalg.LocalDir, perm fs.FileMode) error {
	if s == nil || !s.valid {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "ScopedFS"))
	}
	return EnsureDir(dir, perm)
}

// WithRoot 打开绑定至 dir 的 *os.Root 沙箱句柄并在同步闭包 fn 内借出；退出前无条件失效并关闭。
//
//xops:syncclosure
//xops:borrowed
func (s *ScopedFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) (retErr error) {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if s == nil || !s.valid || !dir.IsValid() {
		return errField(ports.ErrInvalidArgument, "root_dir")
	}
	nativeDir, err := localPathToNativeOS(dir.Kind(), dir.String())
	if err != nil {
		return err
	}
	osRoot, err := os.OpenRoot(nativeDir)
	if err != nil {
		return mapOSError(err)
	}
	handle := &rootHandle{root: osRoot}
	handle.active.Store(true)
	defer func() {
		handle.active.Store(false)
		if closeErr := osRoot.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			retErr = errors.Join(retErr, mapOSError(closeErr))
		}
	}()
	return fn(handle)
}

type rootHandle struct {
	root   *os.Root
	active atomic.Bool
}

func (h *rootHandle) checkActive() error {
	return pickIf[error](h != nil && h.active.Load() && h.root != nil, nil, ports.ErrHandleExpired)
}
func (h *rootHandle) checkActiveDest(dest pathalg.LocalRootedDest) error {
	if err := h.checkActive(); err != nil {
		return err
	}
	return pickIf[error](dest.IsValid(), nil, errField(ports.ErrInvalidArgument, "dest"))
}
func (h *rootHandle) prepareDest(dest pathalg.LocalRootedDest) error {
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	segs := dest.Segments()
	for i := range len(segs) - 1 {
		if _, err := checkLstatKind(h.root, strings.Join(segs[:i+1], "/"), true, false); err != nil {
			return err
		}
	}
	return nil
}

// ReadAllBounded 在 limits 上限内无跟随读取沙箱常规文件的全部字节。
func (h *rootHandle) ReadAllBounded(dest pathalg.LocalRootedDest, limits ports.ReadLimits) (data []byte, err error) {
	err = h.WithReadRegular(dest, limits, func(r ports.BoundedReadHandle, _ int64) (rErr error) {
		data, rErr = io.ReadAll(r)
		return mapOSError(rErr)
	})
	return data, err
}
func (h *rootHandle) checkDestCB(d pathalg.LocalRootedDest, fnNil bool) error {
	return pickIf[error](fnNil, ports.ErrNilCallback, h.checkActiveDest(d))
}

// WithReadRegular 以有界随机只读句柄在同步回调内借出沙箱常规文件（支持顺序读与并发安全 ReadAt），退出即失效关闭。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) WithReadRegular(dest pathalg.LocalRootedDest, limits ports.ReadLimits, fn func(r ports.BoundedReadHandle, size int64) error) error {
	if err := h.checkDestCB(dest, fn == nil); err != nil {
		return err
	}
	if !limits.IsValid() {
		return ports.ErrInvalidReadLimits
	}
	f, err := openLeafInRootOS(h.root, dest, leafOpRead, 0)
	if err != nil {
		return err
	}
	var active atomic.Bool
	defer func() { active.Store(false); _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return mapOSError(err)
	}
	if st.Size() > limits.MaxBytes() {
		return domi18n.EF(ports.ErrLimitExceeded, domi18n.KeyCommonSizeLimit, domi18n.BoundStr("kind", dest.String()), domi18n.Int64("size", st.Size()), domi18n.Int64("limit", limits.MaxBytes()))
	}
	active.Store(true)
	return fn(&borrowedReader{r: f, remaining: limits.MaxBytes(), maxBytes: limits.MaxBytes(), limited: true, active: &active}, st.Size())
}

// CreateExclusive 以 O_CREAT|O_EXCL|O_NOFOLLOW（Windows 含根锚定 Owner-Only DACL）独占创建新文件，失败自动回滚。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error {
	if err := h.checkDestCB(dest, fn == nil); err != nil {
		return err
	}
	f, err := openLeafInRootOS(h.root, dest, leafOpCreateExcl, sanitizeFilePerm(perm, defaultFilePerm))
	if err != nil {
		return err
	}
	return h.writeScopedFile(f, dest, zeroVal[pathalg.LocalRootedDest](), fn)
}

// AtomicReplace 在同目录下经随机临时文件刷盘后原子替换目标文件（绝不锁目标文件本身）。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) AtomicReplace(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := h.prepareDest(dest); err != nil {
		return err
	}
	if _, err := checkLstatKind(h.root, dest.String(), false, true); err != nil {
		return err
	}
	tmpDest, err := makeTempDestInSameDir(dest)
	if err != nil {
		return err
	}
	f, err := openLeafInRootOS(h.root, tmpDest, leafOpCreateExcl, sanitizeFilePerm(perm, defaultFilePerm))
	if err != nil {
		return err
	}
	return h.writeScopedFile(f, tmpDest, dest, fn)
}

// WriteChunk 向沙箱常规暂存文件 dest 的 offset 处非截断写入精确 length 字节并刷盘（不跟随软链）。
func (h *rootHandle) WriteChunk(dest pathalg.LocalRootedDest, offset int64, r io.Reader, length int64, perm fs.FileMode) (int64, error) {
	if err := h.checkActiveDest(dest); err != nil {
		return 0, err
	}
	if r == nil || offset < 0 || length < 0 || offset > math.MaxInt64-length || perm == 0 || perm != perm.Perm() {
		return 0, errField(ports.ErrInvalidArgument, "write_chunk")
	}
	f, err := openLeafInRootOS(h.root, dest, leafOpWriteChunk, perm)
	if err != nil {
		return 0, err
	}
	var written int64
	if length > 0 {
		if _, err = f.Seek(offset, io.SeekStart); err == nil {
			written, err = io.CopyN(f, r, length)
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
		}
	}
	syncErr, closeErr := f.Sync(), f.Close()
	if err != nil {
		return written, mapOSError(err)
	}
	return written, mapOSError(errors.Join(syncErr, closeErr))
}

// Rename 在沙箱根内原子重命名 oldDest -> newDest（非软链校验 + os.Root.Rename + 父目录同步）。
func (h *rootHandle) Rename(oldDest, newDest pathalg.LocalRootedDest) error {
	if err := errors.Join(h.prepareDest(oldDest), h.prepareDest(newDest)); err != nil {
		return err
	}
	srcInfo, err := h.root.Lstat(oldDest.String())
	if err != nil {
		return mapOSError(err)
	}
	if srcInfo.Mode()&fs.ModeSymlink != 0 {
		return domi18n.EF(ports.ErrSymlinkRejected, domi18n.KeyOSFSSymlinkDetected, domi18n.BoundStr("path", oldDest.String()))
	}
	if _, err := checkLstatKind(h.root, newDest.String(), srcInfo.IsDir(), true); err != nil {
		return err
	}
	if err := h.root.Rename(oldDest.String(), newDest.String()); err != nil {
		return mapOSError(err)
	}
	err = syncRootParentDirOS(h.root, newDest)
	oldP, hasOld := oldDest.Parent()
	if newP, hasNew := newDest.Parent(); hasOld != hasNew || (hasOld && !oldP.Equal(newP)) {
		err = errors.Join(err, syncRootParentDirOS(h.root, oldDest))
	}
	return err
}

//xops:syncclosure
func (h *rootHandle) writeScopedFile(f *os.File, writeDest, renameTarget pathalg.LocalRootedDest, fn func(w io.Writer) error) error {
	var active atomic.Bool
	active.Store(true)
	openFile, committed := f, false
	defer func() {
		active.Store(false)
		if openFile != nil {
			_ = openFile.Close()
		}
		if !committed {
			_ = h.root.Remove(writeDest.String())
		}
	}()
	if err := fn(&borrowedWriter{w: f, active: &active}); err != nil {
		return err
	}
	active.Store(false)
	syncErr := f.Sync()
	openFile = nil
	if err := errors.Join(syncErr, f.Close()); err != nil {
		return mapOSError(err)
	}
	syncDest := writeDest
	if renameTarget.IsValid() {
		if err := h.root.Rename(writeDest.String(), renameTarget.String()); err != nil {
			return mapOSError(err)
		}
		syncDest = renameTarget
	}
	committed = true
	return syncRootParentDirOS(h.root, syncDest)
}

// AppendLine 以只追加语义向常规文件末尾单次写入 line + '\n'，严格拒绝内嵌 '\r' 或 '\n'。
func (h *rootHandle) AppendLine(dest pathalg.LocalRootedDest, perm fs.FileMode, line []byte) error {
	if bytes.ContainsAny(line, "\r\n") {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyOSFSAppendNewline)
	}
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	f, err := openLeafInRootOS(h.root, dest, leafOpAppend, sanitizeFilePerm(perm, defaultFilePerm))
	if err != nil {
		return err
	}
	frame := append(bytes.Clone(line), '\n')
	if n, wErr := f.Write(frame); wErr != nil {
		err = wErr
	} else if n != len(frame) {
		err = io.ErrShortWrite
	} else {
		err = f.Sync()
	}
	return mapOSError(errors.Join(err, f.Close()))
}
func (h *rootHandle) Stat(d pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statDest(d, false)
}
func (h *rootHandle) Lstat(d pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statDest(d, true)
}
func (h *rootHandle) statDest(dest pathalg.LocalRootedDest, lstat bool) (ports.LocalFileInfo, error) {
	if err := h.checkActiveDest(dest); err != nil {
		return zeroVal[ports.LocalFileInfo](), err
	}
	fi, err := pickIf(lstat, h.root.Lstat, h.root.Stat)(dest.String())
	if err != nil {
		return zeroVal[ports.LocalFileInfo](), mapOSError(err)
	}
	return fileInfoToLocalFileInfo(dest.Base(), fi)
}

// ReadDir 按名称升序确定性列举沙箱目录内容；dir 为 None 时列举根目录自身，并发消失条目自动跳过。
func (h *rootHandle) ReadDir(dir algebraic.Option[pathalg.LocalRootedDest]) ([]ports.LocalDirEntry, error) {
	if err := h.checkActive(); err != nil {
		return nil, err
	}
	rel := "."
	if d, ok := dir.Get(); ok {
		if err := h.prepareDest(d); err != nil {
			return nil, err
		}
		if _, err := checkLstatKind(h.root, d.String(), true, false); err != nil {
			return nil, err
		}
		rel = d.String()
	}
	f, err := h.root.Open(rel)
	if err != nil {
		return nil, mapOSError(err)
	}
	defer func() { _ = f.Close() }()
	raw, err := f.ReadDir(-1)
	if err != nil {
		return nil, mapOSError(err)
	}
	return collectDirEntries(raw)
}
func collectDirEntries(raw []os.DirEntry) ([]ports.LocalDirEntry, error) {
	out := make([]ports.LocalDirEntry, 0, len(raw))
	for _, de := range raw {
		info, iErr := de.Info()
		if errors.Is(iErr, os.ErrNotExist) {
			continue
		}
		if iErr != nil {
			return nil, mapOSError(iErr)
		}
		entry, eErr := ports.NewLocalDirEntry(de.Name(), info.Mode(), info.Size())
		if eErr != nil {
			return nil, eErr
		}
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b ports.LocalDirEntry) int { return cmp.Compare(a.Name(), b.Name()) })
	return out, nil
}

// MkdirAll 在沙箱根内逐段安全创建子目录树，拒绝穿透符号链接。
func (h *rootHandle) MkdirAll(dir pathalg.LocalRootedDest, perm fs.FileMode) error {
	if err := h.checkActiveDest(dir); err != nil {
		return err
	}
	mode, segs := sanitizeFilePerm(perm, defaultDirPerm), dir.Segments()
	for i := range segs {
		if err := mkdirSegmentInRootOS(h.root, segs[:i], segs[i], mode); err == nil {
			continue
		} else if !errors.Is(err, os.ErrExist) && !errors.Is(err, ports.ErrAlreadyExists) {
			return mapOSError(err)
		}
		if _, err := checkLstatKind(h.root, strings.Join(segs[:i+1], "/"), true, false); err != nil {
			return err
		}
	}
	return nil
}

// CreateSymlink 在沙箱根内创建经策略 (b) 校验的相对 POSIX 符号链接（绝不允许绝对或逃逸目标）。
func (h *rootHandle) CreateSymlink(link pathalg.LocalRootedDest, target string) error {
	if err := h.prepareDest(link); err != nil {
		return err
	}
	if err := pathalg.ValidateContainedSymlink(target, link.Depth()-1); err != nil {
		return wrapS(ports.ErrInvalidArgument, err)
	}
	return mapOSError(h.root.Symlink(target, link.String()))
}

func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}

// Chtimes 修改沙箱内常规文件或目录的访问与修改时间（拒绝零值、越界年份与符号链接，支撑 scp -p）。
func (h *rootHandle) Chtimes(dest pathalg.LocalRootedDest, atime, mtime time.Time) error {
	if err := h.prepareDest(dest); err != nil {
		return err
	}
	if !isValidRFC3339Time(atime) || !isValidRFC3339Time(mtime) {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyPortsModTimeOutOfRange)
	}
	if lst, err := h.root.Lstat(dest.String()); err != nil {
		return mapOSError(err)
	} else if lst.Mode()&fs.ModeSymlink != 0 {
		return domi18n.EF(ports.ErrSymlinkRejected, domi18n.KeyOSFSSymlinkDetected, domi18n.BoundStr("path", dest.String()))
	} else if !lst.Mode().IsRegular() && !lst.IsDir() {
		return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotRegularFile, domi18n.BoundStr("path", dest.String()))
	}
	return mapOSError(h.root.Chtimes(dest.String(), atime, mtime))
}

// Remove 删除沙箱内单个文件或空目录；目标不存在时返回 ports.ErrNotFound。
func (h *rootHandle) Remove(dest pathalg.LocalRootedDest) error {
	if err := h.prepareDest(dest); err != nil {
		return err
	}
	return mapOSError(h.root.Remove(dest.String()))
}
func checkLstatKind(root *os.Root, rel string, wantDir, allowMissing bool) (os.FileInfo, error) {
	lst, err := root.Lstat(rel)
	if err != nil {
		return nil, pickIf[error](allowMissing && errors.Is(err, os.ErrNotExist), nil, mapOSError(err))
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		return nil, domi18n.EF(ports.ErrSymlinkRejected, domi18n.KeyOSFSSymlinkDetected, domi18n.BoundStr("path", rel))
	}
	if wantDir != lst.IsDir() || (!wantDir && !lst.Mode().IsRegular()) {
		return nil, errWrongKind(rel, wantDir)
	}
	return lst, nil
}
func verifyRegularSameFile(root *os.Root, rel string, f *os.File, allowMissing bool) (bool, error) {
	openSt, err := f.Stat()
	if err != nil {
		return false, mapOSError(err)
	}
	if !openSt.Mode().IsRegular() {
		return false, domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotRegularFile, domi18n.BoundStr("path", rel))
	}
	pathSt, err := checkLstatKind(root, rel, false, allowMissing)
	if err != nil || pathSt == nil {
		return false, err
	}
	return os.SameFile(openSt, pathSt), nil
}
