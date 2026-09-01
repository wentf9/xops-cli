package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const configLockRetryInterval = 20 * time.Millisecond

// ensureConfigLockDirectory is a test seam for the crash-durable directory
// creation required before the permanent lock file is opened.
var ensureConfigLockDirectory = ensureParentDirectory

// configLock is an advisory, process-wide lock for one configuration path.
// Its lock file is intentionally permanent: deleting it would permit a
// concurrent process to lock a different inode and defeat mutual exclusion.
type configLock struct {
	file *os.File
}

func acquireConfigLock(ctx context.Context, configPath string) (lock *configLock, retErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("configuration lock context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("acquire configuration lock canceled: %w", err)
	}
	lockPath := configPath + ".lock"
	if err := ensureConfigLockDirectory(filepath.Dir(lockPath)); err != nil {
		return nil, fmt.Errorf("create configuration lock directory failed: %w", err)
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open configuration lock file %q failed: %w", lockPath, err)
	}
	closeFile := true
	defer func() {
		if closeFile {
			if closeErr := file.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close configuration lock file after failed acquisition: %w", closeErr))
			}
		}
	}()

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		if err := tryLockConfigFile(file); err == nil {
			closeFile = false
			return &configLock{file: file}, nil
		} else if !isConfigLockContended(err) {
			return nil, fmt.Errorf("lock configuration file %q failed: %w", lockPath, err)
		}

		timer.Reset(configLockRetryInterval)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for configuration lock %q failed: %w", lockPath, ctx.Err())
		case <-timer.C:
		}
	}
}

func (l *configLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockConfigFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil && closeErr != nil {
		return errors.Join(
			fmt.Errorf("unlock configuration file failed: %w", unlockErr),
			fmt.Errorf("close configuration lock file failed: %w", closeErr),
		)
	}
	if unlockErr != nil {
		return fmt.Errorf("unlock configuration file failed: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close configuration lock file failed: %w", closeErr)
	}
	return nil
}
