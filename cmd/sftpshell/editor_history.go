package sftpshell

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/fsx"
)

const (
	commandHistoryLimit    = 500
	maxCommandHistoryBytes = 16 << 20
)

type commandHistory struct {
	mu      sync.Mutex
	path    string
	lines   []string
	pending []string
}

func newCommandHistory(path string) (*commandHistory, error) {
	h := &commandHistory{path: path}
	if path == "" {
		return h, nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect command history failed: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("command history is not a regular file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = h.withFileLock(ctx, func() error {
		var readErr error
		h.lines, readErr = readCommandHistory(path)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *commandHistory) Lines() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}
func appendHistoryLine(lines []string, line string) []string {
	if line == "" || len(lines) > 0 && lines[len(lines)-1] == line {
		return lines
	}
	lines = append(lines, line)
	if len(lines) > commandHistoryLimit {
		lines = append([]string(nil), lines[len(lines)-commandHistoryLimit:]...)
	}
	return lines
}
func (h *commandHistory) Append(line string) error {
	line = strings.TrimSpace(normalizePastedText(line))
	if line == "" {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = appendHistoryLine(h.lines, line)
	if h.path == "" {
		return nil
	}
	h.pending = appendHistoryLine(h.pending, line)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return h.withFileLock(ctx, func() error {
		lines, err := readCommandHistory(h.path)
		if err != nil {
			return err
		}
		for _, pending := range h.pending {
			lines = appendHistoryLine(lines, pending)
		}
		if err := writeCommandHistory(ctx, h.path, lines); err != nil {
			return err
		}
		h.lines = lines
		// The replacement committed; an unlock/close error must not replay it.
		h.pending = nil
		return nil
	})
}
func readCommandHistory(path string) (lines []string, retErr error) {
	if path == "" {
		return nil, nil
	}
	file, err := fsx.OpenRegular(path, fsx.Limits{MaxBytes: maxCommandHistoryBytes})
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open command history failed: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, file.Close()) }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4*1024*1024+1)
	for scanner.Scan() {
		lines = appendHistoryLine(lines, strings.TrimSpace(normalizePastedText(scanner.Text())))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read command history failed: %w", err)
	}
	return lines, nil
}
func (h *commandHistory) withFileLock(ctx context.Context, operation func() error) (retErr error) {
	// Lock a stable sidecar: replacing the history file must not change the
	// inode/handle on which concurrent sessions synchronize.
	lock, err := fsx.OpenLockedContext(ctx, h.path+".lock", fsx.LockExclusive, true, fsx.OwnerOnlyPerm)
	if err != nil {
		return fmt.Errorf("lock history failed: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	return operation()
}

const historyStagingRetries = 16

func createHistoryStagingFile(dir string) (*os.File, string, error) {
	var lastErr error
	for range historyStagingRetries {
		var token [8]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, "", fmt.Errorf("generate history staging filename: %w", err)
		}
		tempPath := filepath.Join(dir, ".xops-history-"+hex.EncodeToString(token[:]))
		file, err := fsx.CreateExclusive(tempPath, fsx.OwnerOnlyPerm)
		if err == nil {
			return file, tempPath, nil
		}
		lastErr = err
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", lastErr
}

func writeCommandHistory(ctx context.Context, path string, lines []string) (retErr error) {
	// Create the staging file handle-first with fsx.CreateExclusive so Unix gets
	// 0600 O_NOFOLLOW|O_EXCL|O_CLOEXEC and Windows applies an explicit
	// SE_DACL_PROTECTED owner-only SECURITY_DESCRIPTOR at creation time rather
	// than inheriting parent directory ACEs via os.CreateTemp.
	file, tempPath, err := createHistoryStagingFile(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("create history temporary file failed: %w", err)
	}
	stagingInfo, statErr := file.Stat()
	committed := false
	closed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, file.Close())
		}
		if !committed && stagingInfo != nil {
			currInfo, lstatErr := os.Lstat(tempPath)
			if lstatErr == nil && os.SameFile(stagingInfo, currInfo) {
				if rmErr := os.Remove(tempPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) { //nolint:forbidigo // cleanup own handle-verified staging file if write or Windows-retryable rename fails
					retErr = errors.Join(retErr, rmErr)
				}
			}
		}
	}()
	if statErr != nil {
		return fmt.Errorf("stat history temporary file failed: %w", statErr)
	}
	if _, err = file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return fmt.Errorf("write history failed: %w", err)
	}
	if err = file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close history failed: %w", err)
	}
	closed = true
	if err = renameCommandHistory(ctx, tempPath, path); err != nil {
		return fmt.Errorf("replace history failed: %w", err)
	}
	committed = true
	return nil
}

// Windows metadata readers and scanners can briefly deny replacement even when
// cooperating writers hold the sidecar lock. Keep the temporary file and the
// writer lock until replacement succeeds or the existing history deadline ends.
func retryHistoryRename(parent context.Context, rename func() error, retryable func(error) bool) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(lastErr, err)
		}
		lastErr = rename()
		if lastErr == nil || !retryable(lastErr) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return errors.Join(lastErr, ctx.Err())
		case <-ticker.C:
		}
	}
}
