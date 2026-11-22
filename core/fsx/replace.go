package fsx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// ReplaceResult describes the observable persistence outcome of AtomicReplace.
// Applied reports whether the destination pathname was atomically replaced.
// Durable reports whether the parent directory was also synchronized after
// replacement (always false when WithoutDirSync is used, or if SyncDir fails).
//
// Callers must not blindly retry a call that returned Applied=true with a
// non-nil error: the new file is already visible at destination while crash
// durability of the directory entry is uncertain.
type ReplaceResult struct {
	Applied bool
	Durable bool
}

type replaceConfig struct {
	withoutDirSync bool
}

// ReplaceOption configures AtomicReplace behavior.
type ReplaceOption func(*replaceConfig)

// WithoutDirSync skips the post-rename SyncDir step in AtomicReplace.
// Callers that manage directory durability separately (for example under an
// existing sync seam or non-durable cache files) may pass this option.
func WithoutDirSync() ReplaceOption {
	return func(c *replaceConfig) {
		c.withoutDirSync = true
	}
}

// replaceBeforeCleanupHook is a package-private test hook invoked on error
// paths immediately before verifying temp-file handle identity and unlinking.
// Nil in production.
var replaceBeforeCleanupHook func(tempPath string)

// replaceTempWriteHook is a package-private test hook invoked right after
// writing data to the temporary file to inject a post-create error for testing
// error-path SameFile cleanup. Nil in production.
var replaceTempWriteHook func(tempPath string) error

var replaceTempSeq atomic.Uint64

const replaceTempCreateRetries = 16

// AtomicReplace writes data to path atomically via an exclusive no-follow
// temporary file created in filepath.Dir(path), fsyncs the temporary file,
// closes it, atomically replaces path, and (unless WithoutDirSync is set)
// synchronizes the parent directory via SyncDir.
//
// On Unix, the temporary file is created with O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC
// and its mode is set to perm.Perm() via fchmod on the open handle.
// On Windows, the temporary file is created with CREATE_NEW and
// FILE_FLAG_OPEN_REPARSE_POINT; when perm.Perm()&0o077 == 0, a protected
// owner-only SECURITY_DESCRIPTOR is applied atomically at creation time, and
// replacement uses MoveFileExW(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH).
//
// On every error path prior to atomic replacement, cleanup unlinks the
// temporary pathname ONLY after verifying os.SameFile against the handle
// metadata captured at creation time.
func AtomicReplace(path string, data []byte, perm os.FileMode, opts ...ReplaceOption) (result ReplaceResult, retErr error) {
	if strings.TrimSpace(path) == "" {
		return ReplaceResult{}, ErrEmptyPath
	}
	var cfg replaceConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	dir := filepath.Dir(path)
	tempFile, tempPath, err := createTempForReplace(dir, perm)
	if err != nil {
		return ReplaceResult{}, err
	}

	// Capture handle identity immediately so error-path cleanup never unlinks a
	// path that was concurrently replaced by another entry.
	tempInfo, statErr := tempFile.Stat()
	committed := false
	closed := false
	defer func() {
		if !closed {
			if closeErr := tempFile.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("fsx: close temp file %q: %w", tempPath, closeErr))
			}
		}
		if !committed {
			if hook := replaceBeforeCleanupHook; hook != nil {
				hook(tempPath)
			}
			if rmErr := removeTempIfSameFile(tempPath, tempInfo); rmErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("fsx: remove temp file %q: %w", tempPath, rmErr))
			}
		}
	}()

	if statErr != nil {
		return ReplaceResult{}, fmt.Errorf("fsx: stat temp file %q: %w", tempPath, statErr)
	}
	if err := writeAllToFile(tempFile, data); err != nil {
		return ReplaceResult{}, fmt.Errorf("fsx: write temp file %q: %w", tempPath, err)
	}
	if hook := replaceTempWriteHook; hook != nil {
		if hookErr := hook(tempPath); hookErr != nil {
			return ReplaceResult{}, hookErr
		}
	}
	if err := tempFile.Sync(); err != nil {
		return ReplaceResult{}, fmt.Errorf("fsx: sync temp file %q: %w", tempPath, err)
	}
	closed = true
	if err := tempFile.Close(); err != nil {
		return ReplaceResult{}, fmt.Errorf("fsx: close temp file %q: %w", tempPath, err)
	}

	if err := replaceFileOS(tempPath, path); err != nil {
		return ReplaceResult{}, fmt.Errorf("fsx: replace %q: %w", path, err)
	}
	committed = true
	result.Applied = true

	if cfg.withoutDirSync {
		return result, nil
	}
	if err := SyncDir(dir); err != nil {
		return result, err
	}
	result.Durable = true
	return result, nil
}

// SyncDir flushes directory metadata for dir to stable storage.
//
// On Unix, SyncDir opens dir with O_RDONLY|O_DIRECTORY|O_CLOEXEC and calls
// Sync on the directory handle. On Windows, SyncDir opens dir with
// FILE_FLAG_BACKUP_SEMANTICS|SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,
// verifies on the open handle that it is a FILE_TYPE_DISK directory, and calls
// FlushFileBuffers.
func SyncDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return ErrEmptyPath
	}
	return syncDirOS(dir)
}

func createTempForReplace(dir string, perm os.FileMode) (*os.File, string, error) {
	var lastErr error
	for attempt := 0; attempt < replaceTempCreateRetries; attempt++ {
		tempPath := filepath.Join(dir, ".xops-tmp-"+nextReplaceTempToken())
		f, err := createReplaceTempOS(tempPath, perm)
		if err == nil {
			return f, tempPath, nil
		}
		lastErr = err
		if !errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("fsx: create temp file in %q: %w", dir, err)
		}
	}
	return nil, "", fmt.Errorf("fsx: create temp file in %q: %w", dir, lastErr)
}

func nextReplaceTempToken() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	seq := replaceTempSeq.Add(1)
	return fmt.Sprintf("%x-%x", os.Getpid(), seq)
}

func writeAllToFile(f *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := f.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func removeTempIfSameFile(tempPath string, origInfo os.FileInfo) error {
	if tempPath == "" || origInfo == nil {
		return nil
	}
	currInfo, err := os.Lstat(tempPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !os.SameFile(origInfo, currInfo) {
		return nil
	}
	if rmErr := os.Remove(tempPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return rmErr
	}
	return nil
}
