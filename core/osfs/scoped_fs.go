package osfs

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
)

// ScopedFS 是基于 Go *os.Root 的沙箱本地文件系统适配器，仅实现 ports.ScopedRootFS（零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type ScopedFS struct{ valid bool }

// NewScopedRootFS 构造可用的沙箱本地文件系统实例（ports.ScopedRootFS 生产实现）。
func NewScopedRootFS() *ScopedFS { return &ScopedFS{valid: true} }

// WithRoot 打开绑定至 dir 的 *os.Root 沙箱句柄并在同步闭包 fn 内借出；退出前无条件失效并关闭。
//
//xops:syncclosure
//xops:borrowed
func (s *ScopedFS) WithRoot(dir pathalg.LocalDir, fn func(root ports.RootHandle) error) (retErr error) {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if s == nil || !s.valid || !dir.IsValid() {
		return fmt.Errorf("%w: ScopedFS 未初始化或根目录无效", ports.ErrInvalidArgument)
	}
	nativeDir, err := localDirToNativePath(dir)
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
	if h == nil || !h.active.Load() || h.root == nil {
		return ports.ErrHandleExpired
	}
	return nil
}

func (h *rootHandle) checkActiveDest(dest pathalg.LocalRootedDest) error {
	if err := h.checkActive(); err != nil {
		return err
	}
	if !dest.IsValid() {
		return fmt.Errorf("%w: 无效沙箱目标路径", ports.ErrInvalidArgument)
	}
	return nil
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

// ReadAllBounded 在 limits 上限内无跟随读取沙箱常规文件的全部字节（通过 WithReadRegular 复用溢出安全有界读取器）。
func (h *rootHandle) ReadAllBounded(dest pathalg.LocalRootedDest, limits ports.ReadLimits) ([]byte, error) {
	var data []byte
	err := h.WithReadRegular(dest, limits, func(r io.Reader, _ int64) error {
		var rErr error
		data, rErr = io.ReadAll(r)
		return mapOSError(rErr)
	})
	return data, err
}

// WithReadRegular 以有界只读流方式在同步回调内借出沙箱常规文件读取器，退出时立即失效并关闭。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) WithReadRegular(dest pathalg.LocalRootedDest, limits ports.ReadLimits, fn func(r io.Reader, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	if !limits.IsValid() {
		return ports.ErrInvalidReadLimits
	}
	f, err := openRegularFDInRootOS(h.root, dest)
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
		return fmt.Errorf("%w: %q 大小超限", ports.ErrLimitExceeded, dest.String())
	}
	active.Store(true)
	return fn(&borrowedReader{r: f, remaining: limits.MaxBytes(), limited: true, active: &active}, st.Size())
}

// CreateExclusive 以 O_CREAT|O_EXCL|O_NOFOLLOW（Windows 含根锚定 Owner-Only DACL）独占创建新文件，失败自动回滚。
//
//xops:syncclosure
//xops:borrowed
func (h *rootHandle) CreateExclusive(dest pathalg.LocalRootedDest, perm fs.FileMode, fn func(w io.Writer) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	f, err := createExclusiveInRootOS(h.root, dest, sanitizeFilePerm(perm, defaultFilePerm))
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
	f, err := createExclusiveInRootOS(h.root, tmpDest, sanitizeFilePerm(perm, defaultFilePerm))
	if err != nil {
		return err
	}
	return h.writeScopedFile(f, tmpDest, dest, fn)
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
	if err := f.Sync(); err != nil {
		return mapOSError(err)
	}
	openFile = nil
	if err := f.Close(); err != nil {
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
		return fmt.Errorf("%w: AppendLine 严禁包含内嵌换行符", ports.ErrInvalidArgument)
	}
	if err := h.checkActiveDest(dest); err != nil {
		return err
	}
	f, err := openForAppendInRootOS(h.root, dest, sanitizeFilePerm(perm, defaultFilePerm))
	if err != nil {
		return err
	}
	frame := append(bytes.Clone(line), '\n')
	n, err := f.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return mapOSError(errors.Join(err, f.Close()))
}

// Stat / Lstat 返回沙箱内目标路径元信息快照（Lstat 不跟随末段符号链接）。
func (h *rootHandle) Stat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statDest(dest, false)
}
func (h *rootHandle) Lstat(dest pathalg.LocalRootedDest) (ports.LocalFileInfo, error) {
	return h.statDest(dest, true)
}

func (h *rootHandle) statDest(dest pathalg.LocalRootedDest, lstat bool) (ports.LocalFileInfo, error) {
	if err := h.checkActiveDest(dest); err != nil {
		return zeroVal[ports.LocalFileInfo](), err
	}
	statFn := h.root.Stat
	if lstat {
		statFn = h.root.Lstat
	}
	fi, err := statFn(dest.String())
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
		// 多终端启动对账并发删除已退役 .lock 文件时跳过已消失条目，避免整次扫描中止。
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
		prefix := strings.Join(segs[:i+1], "/")
		if err := mkdirSegmentInRootOS(h.root, segs[:i], segs[i], mode); err == nil {
			continue
		} else if !errors.Is(err, os.ErrExist) && !errors.Is(err, ports.ErrAlreadyExists) {
			return mapOSError(err)
		}
		if _, err := checkLstatKind(h.root, prefix, true, false); err != nil {
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
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return mapOSError(h.root.Symlink(target, link.String()))
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
		if allowMissing && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, mapOSError(err)
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: 路径 %q 为符号链接", ports.ErrSymlinkRejected, rel)
	}
	if wantDir != lst.IsDir() || (!wantDir && !lst.Mode().IsRegular()) {
		return nil, fmt.Errorf("%w: 路径 %q 类型不符合预期", ports.ErrNotRegularFile, rel)
	}
	return lst, nil
}

func verifyRegularSameFile(root *os.Root, rel string, f *os.File, allowMissing bool) (bool, error) {
	openSt, err := f.Stat()
	if err != nil {
		return false, mapOSError(err)
	}
	if !openSt.Mode().IsRegular() {
		return false, fmt.Errorf("%w: 目标 %q 不是常规文件", ports.ErrNotRegularFile, rel)
	}
	pathSt, err := checkLstatKind(root, rel, false, allowMissing)
	if err != nil || pathSt == nil {
		return false, err
	}
	return os.SameFile(openSt, pathSt), nil
}

// borrowedReader / borrowedWriter 在作用域关闭后拒绝一切读写，并对读取施加溢出安全字节上限。
type borrowedReader struct {
	r         io.Reader
	remaining int64
	limited   bool
	active    *atomic.Bool
}

func (b *borrowedReader) Read(p []byte) (int, error) {
	if b == nil || b.active == nil || !b.active.Load() {
		return 0, ports.ErrHandleExpired
	}
	if !b.limited {
		return b.r.Read(p)
	}
	if b.remaining <= 0 {
		var probe [1]byte
		if n, err := b.r.Read(probe[:]); n > 0 {
			return 0, ports.ErrLimitExceeded
		} else if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= int64(n)
	return n, err
}

type borrowedWriter struct {
	w      io.Writer
	active *atomic.Bool
}

func (b *borrowedWriter) Write(p []byte) (int, error) {
	if b == nil || b.active == nil || !b.active.Load() {
		return 0, ports.ErrHandleExpired
	}
	return b.w.Write(p)
}
