//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"os"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func openKnownHostsFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	if attrs, ok := winsec.GetFileAttributesNoFollow(path); ok {
		if attrs&winsec.FileAttributeReparsePoint != 0 {
			return nil, fmt.Errorf("refusing symlink or reparse point %q", path)
		}
		if attrs&(winsec.FileAttributeDirectory|winsec.FileAttributeDevice) != 0 {
			return nil, fmt.Errorf("refusing non-regular file %q", path)
		}
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if infoErr := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); infoErr != nil {
		_ = f.Close()
		return nil, infoErr
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("refusing non-regular file %q", path)
	}
	st, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return nil, statErr
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("refusing non-regular file %q (mode %s)", path, st.Mode().Type())
	}
	return f, nil
}

func openKnownHostsReadOnlyFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func lockKnownHostsFile(f *os.File, exclusive bool) error {
	if f == nil {
		return errors.New("known_hosts file is nil")
	}
	var flags uint32
	if exclusive {
		flags = windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, ^uint32(0), ^uint32(0), &ol)
}

func unlockKnownHostsFile(f *os.File) error {
	if f == nil {
		return nil
	}
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
}

func hardenNewKnownHostsFile(path string) error {
	return winsec.HardenFileOwnerOnly(path)
}

func withControlSocketDirLock(_ string, fn func() error) error {
	return fn()
}
