package credential

import (
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/fsx"
)

// ErrLockContended 表示事务锁已被其他并发进程持有。
var ErrLockContended = errors.New("transaction lock contended")

// EntryLock 包装单个事务条目的跨平台排他文件锁。
type EntryLock struct {
	path string
	file *fsx.LockedFile
}

// Close 释放并关闭文件锁。
func (l *EntryLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("release lock file failed: %w", err)
	}
	return nil
}
