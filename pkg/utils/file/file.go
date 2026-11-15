package file

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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
		rest := path[1:]
		userPart := rest
		subPath := ""
		if sepIdx := strings.IndexAny(rest, `/\`); sepIdx >= 0 {
			userPart = rest[:sepIdx]
			subPath = rest[sepIdx+1:]
		}
		var home string
		if userPart == "" {
			resolvedHome, err := os.UserHomeDir()
			if err != nil || resolvedHome == "" {
				return path
			}
			home = resolvedHome
		} else {
			u, err := user.Lookup(userPart)
			if err != nil || u == nil || u.HomeDir == "" {
				return path
			}
			home = u.HomeDir
		}
		if subPath == "" {
			return filepath.Clean(home)
		}
		return filepath.Join(home, subPath)
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
