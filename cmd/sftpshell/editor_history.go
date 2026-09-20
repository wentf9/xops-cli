package sftpshell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const commandHistoryLimit = 500

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
		if err := writeCommandHistory(h.path, lines); err != nil {
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
	file, err := os.Open(path)
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
	lock, err := os.OpenFile(h.path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open history lock failed: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, lock.Close()) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		acquired, err := tryHistoryLock(lock)
		if err != nil {
			return fmt.Errorf("lock history failed: %w", err)
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for history lock failed: %w", ctx.Err())
		case <-ticker.C:
		}
	}
	defer func() { retErr = errors.Join(retErr, unlockHistory(lock)) }()
	return operation()
}
func writeCommandHistory(path string, lines []string) (retErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".xops-history-*")
	if err != nil {
		return fmt.Errorf("create history temporary file failed: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			retErr = errors.Join(retErr, file.Close())
		}
		if err := os.Remove(file.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, err)
		}
	}()
	if _, err = file.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return fmt.Errorf("write history failed: %w", err)
	}
	if err = file.Close(); err != nil {
		closed = true
		return fmt.Errorf("close history failed: %w", err)
	}
	closed = true
	if err = os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("replace history failed: %w", err)
	}
	return nil
}
