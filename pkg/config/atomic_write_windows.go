//go:build windows

package config

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(source, destination string) error {
	sourcePath, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return fmt.Errorf("encode temporary configuration path: %w", err)
	}
	destinationPath, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return fmt.Errorf("encode configuration path: %w", err)
	}
	result, _, callErr := moveFileEx.Call(
		uintptr(unsafe.Pointer(sourcePath)),
		uintptr(unsafe.Pointer(destinationPath)),
		moveFileReplaceExisting|moveFileWriteThrough,
	)
	if result == 0 {
		return fmt.Errorf("replace configuration file: %w", callErr)
	}
	return nil
}

func syncParentDirectory(directoryPath string) (retErr error) {
	directory, err := windows.UTF16PtrFromString(directoryPath)
	if err != nil {
		return fmt.Errorf("encode directory path: %w", err)
	}
	handle, err := windows.CreateFile(
		directory,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("open directory handle: %w", err)
	}
	defer func() {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close directory handle failed: %w", closeErr))
		}
	}()
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("flush directory buffers: %w", err)
	}
	return nil
}
