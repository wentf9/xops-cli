package fsx

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	pathpkg "path"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Limits bounds regular-file open and read operations.
//
// Zero value fails closed: MaxBytes must be strictly greater than 0, otherwise
// OpenRegular and ReadAllBounded return ErrInvalidLimit.
type Limits struct {
	MaxBytes int64
}

type openConfig struct {
	allowDevNull   bool
	followSymlinks bool
}

// OpenOption configures optional, explicit deviations from OpenRegular's
// strictest defaults (regular files only, no trailing symlinks, no os.DevNull).
type OpenOption func(*openConfig)

// AllowDevNull permits opening os.DevNull as an empty, read-only RegularFile
// (returning IsDevNull() == true and immediate io.EOF on Read). Without this
// explicit option, os.DevNull is rejected with ErrNonRegular.
func AllowDevNull() OpenOption {
	return func(c *openConfig) {
		c.allowDevNull = true
	}
}

// FollowSymlinks permits OpenRegular / ReadAllBounded to follow a trailing
// symlink (for example a NixOS /etc/ssh/ssh_known_hosts symlink) while still
// opening handle-first without Stat-then-Open and rejecting FIFOs, devices,
// directories, and oversized targets.
//
// By default OpenRegular rejects trailing symlinks and Windows reparse points
// with ErrSymlink.
func FollowSymlinks() OpenOption {
	return func(c *openConfig) {
		c.followSymlinks = true
	}
}

// RegularFile is an owned, bounded read-only handle to a verified regular disk
// file (or an explicitly allowed os.DevNull sentinel).
//
// Ownership: the caller owns *RegularFile and must call Close when finished.
// Close is safe to call multiple times (idempotent).
type RegularFile struct {
	mu       sync.Mutex
	file     *os.File
	info     os.FileInfo
	path     string
	maxBytes int64
	read     int64
	devNull  bool
	closed   bool
}

// OpenRegular opens path handle-first (never Stat-then-Open), verifies on the
// open handle that it is a regular disk file within l.MaxBytes, and returns an
// owned *RegularFile whose Read method also enforces l.MaxBytes.
//
// On Unix, the descriptor is opened with O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|O_NOCTTY
// (omitting O_NOFOLLOW only if FollowSymlinks() is explicitly passed), validated
// via fstat, and then cleared of O_NONBLOCK.
//
// On Windows, the handle is opened via CreateFile with
// FILE_FLAG_OPEN_REPARSE_POINT (omitted only if FollowSymlinks() is explicitly
// passed), FILE_FLAG_BACKUP_SEMANTICS, and SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,
// validated via GetFileType == FILE_TYPE_DISK and GetFileInformationByHandle.
func OpenRegular(path string, l Limits, opts ...OpenOption) (*RegularFile, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	if l.MaxBytes <= 0 {
		return nil, fmt.Errorf("%w: MaxBytes=%d must be > 0", ErrInvalidLimit, l.MaxBytes)
	}
	var cfg openConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return openRegularOS(path, l, cfg)
}

// OpenRegularUnbounded opens path handle-first (never Stat-then-Open), verifies
// on the open handle that it is a regular disk file, and returns the owned raw
// *os.File together with its handle-verified os.FileInfo.
//
// Unlike OpenRegular, OpenRegularUnbounded does not enforce a byte limit and
// returns the raw *os.File so streaming callers can use ReadAt and Seek
// directly on arbitrarily large files without blocking on FIFOs or following
// symlinks/reparse points (unless FollowSymlinks() is explicitly passed).
//
// Ownership: the caller owns the returned *os.File and must call Close.
func OpenRegularUnbounded(path string, opts ...OpenOption) (*os.File, os.FileInfo, error) {
	if path == "" {
		return nil, nil, ErrEmptyPath
	}
	var cfg openConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return openRegularUnboundedOS(path, cfg)
}

// OpenStagingFile opens or creates a local regular staging file strictly
// without O_TRUNC and without following symlinks or Windows reparse points.
//
// It attempts CreateExclusive(path, perm) first; if the entry already exists,
// it opens the existing entry handle-first (O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|O_NOCTTY
// on Unix, CreateFile(OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS)
// on Windows), verifies on the open handle that it is a regular disk file, and
// clears O_NONBLOCK on Unix. Callers that are not resuming must truncate via
// f.Truncate(0) only after receiving the verified handle.
//
// Ownership: the caller owns the returned *os.File and must call Close.
func OpenStagingFile(path string, perm os.FileMode) (*os.File, os.FileInfo, bool, error) {
	if path == "" {
		return nil, nil, false, ErrEmptyPath
	}
	for attempt := 0; attempt < DefaultLockRetries; attempt++ {
		f, err := createExclusiveOS(path, perm)
		if err == nil {
			info, statErr := verifyRegularHandleInfo(f, path)
			if statErr != nil {
				_ = f.Close()
				return nil, nil, false, statErr
			}
			return f, info, true, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, nil, false, err
		}

		existing, openErr := openExistingRegularOS(path, true)
		if openErr == nil {
			info, statErr := verifyRegularHandleInfo(existing, path)
			if statErr != nil {
				_ = existing.Close()
				return nil, nil, false, statErr
			}
			return existing, info, false, nil
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			return nil, nil, false, openErr
		}
	}
	return nil, nil, false, fmt.Errorf("%w: open staging file %q", ErrRetryExhausted, path)
}

// OpenAppendRegular opens or creates an append-only regular file strictly
// without following symlinks, FIFOs, devices, or Windows reparse points.
//
// On Unix, existing files are opened with O_WRONLY|O_APPEND|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|O_NOCTTY,
// verified as S_IFREG via fstat, and cleared of O_NONBLOCK; missing files are
// created exclusively with O_CREAT|O_EXCL|O_NOFOLLOW|O_APPEND.
//
// On Windows, existing files are opened with FILE_APPEND_DATA (without
// FILE_WRITE_DATA) and FILE_FLAG_OPEN_REPARSE_POINT|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS
// and verified as FILE_TYPE_DISK non-reparse regular files; missing files are
// created with CREATE_NEW and a protected owner-only SECURITY_DESCRIPTOR when
// perm.Perm()&0o077 == 0.
//
// Ownership: the caller owns the returned *os.File and must call Close.
func OpenAppendRegular(path string, perm os.FileMode) (*os.File, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	return openAppendRegularOS(path, perm)
}

func verifyRegularHandleInfo(f *os.File, path string) (os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	return info, nil
}

// ReadAllBounded opens path via OpenRegular, reads all bytes bounded to
// l.MaxBytes, and closes the handle before returning. If the file contains more
// than l.MaxBytes bytes (even if it grew concurrently after open), ReadAllBounded
// returns ErrTooLarge.
//
// Callers reading secrets (such as private keys) remain responsible for clearing
// the returned slice when no longer needed.
func ReadAllBounded(path string, l Limits, opts ...OpenOption) ([]byte, error) {
	rf, err := OpenRegular(path, l, opts...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rf.Close() }()
	return rf.ReadAll()
}

// Read reads up to len(p) bytes from the regular file, failing with ErrTooLarge
// if the file yields more than Limits.MaxBytes bytes in total.
// For an allowed os.DevNull handle, Read immediately returns (0, io.EOF).
func (r *RegularFile) Read(p []byte) (int, error) {
	if r == nil {
		return 0, os.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}
	if r.devNull {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	remaining := r.maxBytes - r.read
	if remaining <= 0 {
		var probe [1]byte
		n, err := r.file.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: %q exceeds %d bytes", ErrTooLarge, r.path, r.maxBytes)
		}
		return 0, err
	}
	buf := p
	if int64(len(buf)) > remaining && remaining < math.MaxInt64 {
		// Allow reading 1 byte past remaining to detect concurrent growth.
		buf = p[:remaining+1]
	}
	n, err := r.file.Read(buf)
	if int64(n) > remaining {
		// Discard the overflow byte from the caller's view and report ErrTooLarge.
		r.read = r.maxBytes
		return int(remaining), fmt.Errorf("%w: %q exceeds %d bytes", ErrTooLarge, r.path, r.maxBytes)
	}
	r.read += int64(n)
	return n, err
}

// ReadAll reads all remaining bytes from r up to Limits.MaxBytes.
func (r *RegularFile) ReadAll() ([]byte, error) {
	if r == nil {
		return nil, os.ErrInvalid
	}
	if r.IsDevNull() {
		return []byte{}, nil
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []byte{}, nil
	}
	return data, nil
}

// Close releases the underlying OS file handle. Close is idempotent; subsequent
// calls return nil.
func (r *RegularFile) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// Stat returns file metadata from the open handle (or synthetic zero-size metadata
// when IsDevNull() is true).
func (r *RegularFile) Stat() (os.FileInfo, error) {
	if r == nil {
		return nil, os.ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, os.ErrClosed
	}
	if r.devNull {
		return r.info, nil
	}
	return r.file.Stat()
}

// Size returns the file size observed on the open handle at open time (0 for os.DevNull).
func (r *RegularFile) Size() int64 {
	if r == nil || r.info == nil {
		return 0
	}
	return r.info.Size()
}

// Name returns the path passed to OpenRegular.
func (r *RegularFile) Name() string {
	if r == nil {
		return ""
	}
	return r.path
}

// IsDevNull reports whether r represents an explicitly allowed os.DevNull target.
func (r *RegularFile) IsDevNull() bool {
	return r != nil && r.devNull
}

func newDevNullRegularFile(path string, maxBytes int64, info os.FileInfo) *RegularFile {
	if info == nil {
		info = devNullFileInfo{name: os.DevNull}
	}
	return &RegularFile{
		info:     info,
		path:     path,
		maxBytes: maxBytes,
		devNull:  true,
	}
}

// IsDevNullSentinel reports whether path is an explicit null-device sentinel
// recognized when AllowDevNull() is enabled: "/dev/null" on all operating
// systems, plus "NUL" and `\\.\NUL` (case-insensitive) on Windows.
func IsDevNullSentinel(path string) bool {
	return isDevNullSentinelForOS(runtime.GOOS, path)
}

// IsDevNullPath reports whether path canonically names the null-device
// sentinel (matching "NUL" and `\\.\NUL` case-insensitively on Windows, and
// "/dev/null" on all operating systems).
func IsDevNullPath(path string) bool {
	return IsDevNullSentinel(path)
}

func isDevNullSentinelForOS(goos, raw string) bool {
	if raw == "" {
		return false
	}
	if goos == "windows" {
		winNorm := strings.ReplaceAll(raw, "/", `\`)
		if strings.EqualFold(winNorm, "NUL") || strings.EqualFold(winNorm, `\\.\NUL`) {
			return true
		}
		if !strings.HasPrefix(winNorm, `\\`) {
			slash := strings.ReplaceAll(raw, `\`, "/")
			if strings.HasPrefix(slash, "/") && pathpkg.Clean(slash) == "/dev/null" {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(raw, "/") && pathpkg.Clean(raw) == "/dev/null" {
		return true
	}
	return raw == os.DevNull
}

type devNullFileInfo struct {
	name string
}

func (d devNullFileInfo) Name() string       { return d.name }
func (d devNullFileInfo) Size() int64        { return 0 }
func (d devNullFileInfo) Mode() os.FileMode  { return os.ModeDevice | os.ModeCharDevice | 0o666 }
func (d devNullFileInfo) ModTime() time.Time { return time.Time{} }
func (d devNullFileInfo) IsDir() bool        { return false }
func (d devNullFileInfo) Sys() any           { return nil }
