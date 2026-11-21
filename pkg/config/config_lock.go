package config

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/wentf9/xops-cli/core/fsx"
)

// ensureConfigLockDirectory is a test seam for the crash-durable directory
// creation required before the permanent lock file is opened.
var ensureConfigLockDirectory = ensureParentDirectory

// configLock is an advisory, process-wide lock for one configuration path.
// Its lock file is intentionally permanent: deleting it would permit a
// concurrent process to lock a different inode and defeat mutual exclusion.
type configLock struct {
	file *fsx.LockedFile
}

func acquireConfigLock(ctx context.Context, configPath string) (*configLock, error) {
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
	file, err := fsx.OpenLockedContext(ctx, lockPath, fsx.LockExclusive, true, fsx.OwnerOnlyPerm)
	if err != nil {
		return nil, fmt.Errorf("acquire configuration lock %q failed: %w", lockPath, err)
	}
	return &configLock{file: file}, nil
}

func (l *configLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("release configuration lock file failed: %w", err)
	}
	return nil
}
