package file

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CreateFileRecursive 递归创建文件并写入内容
func CreateFileRecursive(filePath string, content []byte, perm os.FileMode) (retErr error) {
	// 创建目录
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create parent directory %q failed: %w", dir, err)
	}

	// 创建文件（使用指定权限）
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open file %q for writing failed: %w", filePath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close file %q failed: %w", filePath, err))
		}
	}()

	// 写入内容
	if content != nil {
		if _, err := file.Write(content); err != nil {
			return fmt.Errorf("write file %q failed: %w", filePath, err)
		}
	}

	return nil
}

// ToAbsolutePath expands a leading home-directory marker and converts a
// relative path to an absolute path. It preserves the input if resolution is
// unavailable so callers can still report the underlying file error later.
func ToAbsolutePath(path string) string {
	if path == "" {
		return path
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			rest := path[1:]
			if len(rest) > 0 && (rest[0] == '/' || rest[0] == '\\') {
				rest = rest[1:]
			}
			if rest == "" {
				return home
			}
			return filepath.Join(home, rest)
		}
	}
	if filepath.IsAbs(path) {
		return path
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absPath
}
