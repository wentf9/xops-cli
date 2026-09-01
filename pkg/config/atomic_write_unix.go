//go:build !windows

package config

import (
	"errors"
	"fmt"
	"os"
)

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return fmt.Errorf("rename temporary configuration file failed: %w", err)
	}
	return nil
}

func syncParentDirectory(directoryPath string) (retErr error) {
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open directory failed: %w", err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close directory failed: %w", closeErr))
		}
	}()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync directory failed: %w", err)
	}
	return nil
}
