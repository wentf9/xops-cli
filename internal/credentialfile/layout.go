package credentialfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LayoutPresence is a read-only snapshot, never authorization to initialize.
// Actual writes must repeat validation under the native vault lock.
type LayoutPresence struct{ Vault, Key bool }

// InspectLayout checks both paths without following symlinks or creating files.
// Existing vault contents must still be inspected using Store.Inspect.
func InspectLayout(ctx context.Context, vaultPath, keyPath string) (LayoutPresence, error) {
	vault, err := inspectPathPresence(ctx, vaultPath)
	if err != nil {
		return LayoutPresence{}, err
	}
	key, err := inspectPathPresence(ctx, keyPath)
	if err != nil {
		return LayoutPresence{}, err
	}
	return LayoutPresence{Vault: vault, Key: key}, nil
}

func inspectPathPresence(ctx context.Context, path string) (bool, error) {
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("inspect layout requires absolute path")
	}
	var components []string
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		components = append(components, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(components) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("inspect layout cancelled: %w", err)
		}
		info, err := os.Lstat(components[i])
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("inspect layout path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("inspect layout rejects symbolic links")
		}
		if i > 0 && !info.IsDir() {
			return false, fmt.Errorf("inspect layout parent is not a directory")
		}
	}
	return true, nil
}
