//go:build windows

package mcphost

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func openRegularCertFile(certPath string) (*os.File, os.FileInfo, bool, error) {
	safePath := fixLongPathWindows(certPath)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, nil, false, err
	}
	const flags = uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_ANONYMOUS)
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, nil, true, err
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_CANT_ACCESS_FILE) {
			if probeNonRegularWindows(pathPtr) {
				return nil, nil, true, err
			}
		}
		return nil, nil, false, err
	}

	fileType, typeErr := windows.GetFileType(handle)
	if typeErr != nil || fileType != windows.FILE_TYPE_DISK {
		_ = windows.CloseHandle(handle)
		return nil, nil, true, nil
	}

	f := os.NewFile(uintptr(handle), certPath)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, false, errors.New("os.NewFile returned nil for certificate handle")
	}
	fInfo, statErr := f.Stat()
	if statErr != nil || !fInfo.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, true, nil
	}
	return f, fInfo, false, nil
}

func isExtendedOrDeviceWindowsPath(path string) bool {
	if len(path) < 4 {
		return false
	}
	isSlash := func(b byte) bool { return b == '\\' || b == '/' }
	p0, p1, p2, p3 := path[0], path[1], path[2], path[3]
	if p0 == '\\' && p1 == '?' && p2 == '?' && p3 == '\\' {
		return true
	}
	return isSlash(p0) && isSlash(p1) && (p2 == '?' || p2 == '.') && isSlash(p3)
}

func isDriveRelativeWindowsPath(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	isDriveLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	if !isDriveLetter {
		return false
	}
	return len(path) == 2 || (path[2] != '\\' && path[2] != '/')
}

func fixLongPathWindows(path string) string {
	if path == "" || isExtendedOrDeviceWindowsPath(path) {
		return path
	}
	var precomputedFull string
	effectiveLen := len(path)
	if isDriveRelativeWindowsPath(path) {
		full, err := windows.FullPath(path)
		if err != nil || full == "" {
			return path
		}
		precomputedFull = full
		effectiveLen = len(full)
	} else if !filepath.IsAbs(path) {
		if wd, err := os.Getwd(); err == nil {
			effectiveLen += len(wd) + 1
		}
	}
	if effectiveLen < 248 {
		return path
	}
	full := precomputedFull
	if full == "" {
		var err error
		full, err = windows.FullPath(path)
		if err != nil || full == "" {
			return path
		}
	}
	if isExtendedOrDeviceWindowsPath(full) {
		return full
	}
	if strings.HasPrefix(full, `\\`) && !strings.HasPrefix(full, `\\?\`) {
		return `\\?\UNC\` + full[2:]
	}
	return `\\?\` + full
}

func probeNonRegularWindows(pathPtr *uint16) bool {
	nonRegular, _ := probeZeroAccessSQOS(pathPtr, true)
	return nonRegular
}

func probeZeroAccessSQOS(pathPtr *uint16, openReparsePoint bool) (nonRegular bool, decided bool) {
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_ANONYMOUS)
	if openReparsePoint {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(
		pathPtr,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_PIPE_BUSY) || (!openReparsePoint && errors.Is(err, windows.ERROR_CANT_ACCESS_FILE)) {
			return true, true
		}
		return false, false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	fileType, typeErr := windows.GetFileType(h)
	if typeErr != nil || fileType != windows.FILE_TYPE_DISK {
		return true, true
	}
	var info windows.ByHandleFileInformation
	if infoErr := windows.GetFileInformationByHandle(h, &info); infoErr != nil {
		if errors.Is(infoErr, windows.ERROR_ACCESS_DENIED) {
			return false, false
		}
		return true, true
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return true, true
	}
	if openReparsePoint && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return probeZeroAccessSQOS(pathPtr, false)
	}
	return false, true
}
