package credential

import (
	"errors"
	"fmt"
	"os"
)

// ErrLockContended 表示事务锁已被其他并发进程持有。
var ErrLockContended = errors.New("transaction lock contended")

// EntryLock 包装单个事务条目的跨平台排他文件锁。
type EntryLock struct {
	path string
	file *os.File
}

// Close 释放并关闭文件锁。
func (l *EntryLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := unlockFile(l.file)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil && closeErr != nil {
		return errors.Join(
			fmt.Errorf("unlock file failed: %w", unlockErr),
			fmt.Errorf("close lock file failed: %w", closeErr),
		)
	}
	if unlockErr != nil {
		return fmt.Errorf("unlock file failed: %w", unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close lock file failed: %w", closeErr)
	}
	return nil
}
