package file

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func isDirectoryTargetPath(p string) bool {
	if p == "" {
		return false
	}
	last := p[len(p)-1]
	if os.IsPathSeparator(last) || last == '/' || last == '\\' {
		return true
	}
	if p == "." || p == ".." {
		return true
	}
	for _, suffix := range []string{"/.", "\\.", "/..", "\\.."} {
		if strings.HasSuffix(p, suffix) {
			return true
		}
	}
	return false
}

// CreateFileRecursive 递归创建文件并以原子替换方式写入内容
func CreateFileRecursive(filePath string, content []byte, perm os.FileMode) (retErr error) {
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file path must not be empty")
	}
	if isDirectoryTargetPath(filePath) {
		return fmt.Errorf("target path %q is a directory", filePath)
	}
	if info, err := os.Lstat(filePath); err == nil && info.IsDir() {
		return fmt.Errorf("target path %q is a directory", filePath)
	}

	// 根据目标文件权限派生父目录权限：私密文件使用 0700，其他使用 0755
	dirPerm := os.FileMode(0o755)
	if perm&0o077 == 0 {
		dirPerm = 0o700
	}
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create parent directory %q failed: %w", dir, err)
	}
	if info, err := os.Lstat(filePath); err == nil && info.IsDir() {
		return fmt.Errorf("target path %q is a directory", filePath)
	}

	tmpFile, err := os.CreateTemp(dir, ".xops-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file in %q failed: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	renamed := false
	defer func() {
		if !renamed {
			if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf("remove temp file %q failed: %w", tmpPath, removeErr))
			}
		}
	}()
	closed := false
	defer func() {
		if !closed {
			if closeErr := tmpFile.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close temp file %q failed: %w", tmpPath, closeErr))
			}
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file %q failed: %w", tmpPath, err)
	}
	if len(content) > 0 {
		if _, err := tmpFile.Write(content); err != nil {
			return fmt.Errorf("write temp file %q failed: %w", tmpPath, err)
		}
	}
	closed = true
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file %q failed: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("rename temp file %q to %q failed: %w", tmpPath, filePath, err)
	}
	renamed = true
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
