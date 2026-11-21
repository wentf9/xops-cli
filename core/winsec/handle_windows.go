//go:build windows

package winsec

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ioReparseTagAFUnix is WinSDK winnt.h IO_REPARSE_TAG_AF_UNIX (0x80000023),
// which identifies NTFS AF_UNIX socket reparse points.
const ioReparseTagAFUnix uint32 = 0x80000023

// fileAttributeTagInfo mirrors Win32 FILE_ATTRIBUTE_TAG_INFO for
// GetFileInformationByHandleEx(FileAttributeTagInfo).
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// OpenObjectHandleNoFollow opens path without dereferencing a trailing reparse
// point (FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS) and without
// allowing server impersonation (SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS).
// It verifies on the open handle that GetFileType == FILE_TYPE_DISK and returns
// the handle together with its handle-queried Win32 file attributes.
//
// Ownership: on success the caller owns the returned windows.Handle and MUST
// close it via windows.CloseHandle.
func OpenObjectHandleNoFollow(path string, desiredAccess uint32) (windows.Handle, uint32, error) {
	if strings.TrimSpace(path) == "" {
		return windows.InvalidHandle, InvalidFileAttributes, errors.New("path is empty")
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, InvalidFileAttributes, fmt.Errorf("encode Windows path %q: %w", path, err)
	}
	const flags = uint32(
		windows.FILE_FLAG_OPEN_REPARSE_POINT |
			windows.FILE_FLAG_BACKUP_SEMANTICS |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)
	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)

	h, err := windows.CreateFile(pathPtr, desiredAccess, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return windows.InvalidHandle, InvalidFileAttributes, err
	}
	fileType, typeErr := windows.GetFileType(h)
	if typeErr != nil || fileType != windows.FILE_TYPE_DISK {
		_ = windows.CloseHandle(h)
		if typeErr != nil {
			return windows.InvalidHandle, InvalidFileAttributes, fmt.Errorf("GetFileType(%q): %w", path, typeErr)
		}
		return windows.InvalidHandle, InvalidFileAttributes, fmt.Errorf("%q is not a disk object (type=%d)", path, fileType)
	}
	var info windows.ByHandleFileInformation
	if infoErr := windows.GetFileInformationByHandle(h, &info); infoErr != nil {
		_ = windows.CloseHandle(h)
		return windows.InvalidHandle, InvalidFileAttributes, fmt.Errorf("GetFileInformationByHandle(%q): %w", path, infoErr)
	}
	return h, info.FileAttributes, nil
}

// GetSecurityInfoByHandle queries the owner and DACL security descriptor
// directly from an already-open file/directory handle via GetSecurityInfo,
// avoiding path-based GetNamedSecurityInfo TOCTOU windows.
func GetSecurityInfoByHandle(handle windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return nil, errors.New("invalid Windows handle")
	}
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, err
	}
	if sd == nil {
		return nil, errors.New("GetSecurityInfo returned nil security descriptor")
	}
	return sd, nil
}

// VerifyAncestorChainNoReparse walks every existing ancestor directory strictly
// above path up to (but excluding) the volume root, opening each directory
// handle with FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS and
// rejecting any ancestor that is a reparse point, device, or non-directory.
func VerifyAncestorChainNoReparse(path string) error {
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve absolute path %q: %w", path, err)
	}
	cur := filepath.Dir(absPath)
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			// Volume root (e.g. C:\): stop walking.
			return nil
		}
		h, attrs, openErr := OpenObjectHandleNoFollow(cur, windows.FILE_READ_ATTRIBUTES)
		if openErr != nil {
			return fmt.Errorf("verify ancestor directory %q: %w", cur, openErr)
		}
		_ = windows.CloseHandle(h)
		if !EvaluateAttributes(attrs, true) {
			return fmt.Errorf("%w: ancestor directory %q is a reparse point, device, or non-directory", ErrInsecureControlDir, cur)
		}
		cur = parent
	}
}

// isAFUnixSocketHandle reports whether the open handle h refers to an NTFS
// AF_UNIX socket reparse point (IO_REPARSE_TAG_AF_UNIX).
func isAFUnixSocketHandle(h windows.Handle) (bool, error) {
	var tagInfo fileAttributeTagInfo
	err := windows.GetFileInformationByHandleEx(
		h,
		windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&tagInfo)),
		uint32(unsafe.Sizeof(tagInfo)),
	)
	if err != nil {
		return false, err
	}
	isSocket := tagInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 &&
		tagInfo.ReparseTag == ioReparseTagAFUnix
	return isSocket, nil
}

// HardenFileOwnerOnlyByHandle applies a protected owner-only DACL (current
// user + SYSTEM, no inherited ACEs) directly to an already-open handle via
// SetSecurityInfo. The handle must have WRITE_DAC access.
//
// Ownership: this function borrows handle and never closes it.
func HardenFileOwnerOnlyByHandle(handle windows.Handle) error {
	if handle == 0 || handle == windows.InvalidHandle {
		return errors.New("invalid Windows handle")
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID failed: %w", err)
	}
	dacl, err := NewOwnerOnlyACL(currSID, windows.NO_INHERITANCE)
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	runtime.KeepAlive(dacl)
	if err != nil {
		return fmt.Errorf("SetSecurityInfo owner-only DACL failed: %w", err)
	}
	return nil
}

// HardenSocketOwnerOnlyByHandle opens socketPath without dereferencing reparse
// points, verifies on the handle that it is an AF_UNIX socket reparse point
// (IO_REPARSE_TAG_AF_UNIX), and applies a protected owner-only DACL directly to
// that handle via SetSecurityInfo.
func HardenSocketOwnerOnlyByHandle(socketPath string) error {
	h, _, err := OpenObjectHandleNoFollow(socketPath, windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("%w: open socket %q for DACL hardening failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	isSock, tagErr := isAFUnixSocketHandle(h)
	if tagErr != nil {
		return fmt.Errorf("%w: inspect socket tag for %q failed: %w", ErrInsecureControlDir, socketPath, tagErr)
	}
	if !isSock {
		return fmt.Errorf("%w: %q is not an AF_UNIX socket", ErrInsecureControlDir, socketPath)
	}
	return HardenFileOwnerOnlyByHandle(h)
}

// VerifyOwnerOnlyDirectoryByHandle verifies dirPath strictly through an open
// no-follow directory handle (GetSecurityInfo) and checks every ancestor
// directory for reparse points. It never modifies permissions.
func VerifyOwnerOnlyDirectoryByHandle(dirPath string, currSID *windows.SID) error {
	if err := VerifyAncestorChainNoReparse(dirPath); err != nil {
		return err
	}
	h, attrs, err := OpenObjectHandleNoFollow(dirPath, windows.READ_CONTROL)
	if err != nil {
		return fmt.Errorf("%w: open directory %q failed: %w", ErrInsecureControlDir, dirPath, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if !EvaluateAttributes(attrs, true) {
		return fmt.Errorf("%w: %q is not a secure directory", ErrInsecureControlDir, dirPath)
	}
	sd, err := GetSecurityInfoByHandle(h)
	if err != nil {
		return fmt.Errorf("%w: query directory security descriptor for %q failed: %w", ErrInsecureControlDir, dirPath, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: query directory owner for %q failed: %w", ErrInsecureControlDir, dirPath, err)
	}
	ownerTrusted := IsTrustedPrincipalSID(owner, currSID)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: directory %q has missing or nil DACL", ErrInsecureControlDir, dirPath)
	}
	aces, ok := ParseACL(dacl, currSID)
	if !ok {
		return fmt.Errorf("%w: parse directory DACL for %q failed", ErrInsecureControlDir, dirPath)
	}
	if !EvaluateOwnerOnlyDirectorySecurity(attrs, ownerTrusted, true, aces) {
		return fmt.Errorf("%w: directory %q permits untrusted local access", ErrInsecureControlDir, dirPath)
	}
	return nil
}

// VerifyOwnerOnlySocketByHandle opens socketPath without dereferencing reparse
// points, verifies on the handle that it is an AF_UNIX socket reparse point
// (IO_REPARSE_TAG_AF_UNIX), and evaluates its owner and DACL from that same
// handle via GetSecurityInfo.
func VerifyOwnerOnlySocketByHandle(socketPath string) error {
	if err := VerifyAncestorChainNoReparse(socketPath); err != nil {
		return err
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID failed: %w", err)
	}
	h, _, err := OpenObjectHandleNoFollow(socketPath, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return fmt.Errorf("%w: open socket %q failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	isSock, tagErr := isAFUnixSocketHandle(h)
	if tagErr != nil {
		return fmt.Errorf("%w: inspect socket tag for %q failed: %w", ErrInsecureControlDir, socketPath, tagErr)
	}
	if !isSock {
		return fmt.Errorf("%w: %q is not an AF_UNIX socket", ErrInsecureControlDir, socketPath)
	}
	sd, err := GetSecurityInfoByHandle(h)
	if err != nil {
		return fmt.Errorf("%w: query socket security descriptor for %q failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: query socket owner for %q failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	ownerTrusted := IsTrustedPrincipalSID(owner, currSID)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: socket %q has missing or nil DACL", ErrInsecureControlDir, socketPath)
	}
	aces, ok := ParseACL(dacl, currSID)
	if !ok {
		return fmt.Errorf("%w: parse socket DACL for %q failed", ErrInsecureControlDir, socketPath)
	}
	if !EvaluateOwnerOnlySocketSecurity(true, ownerTrusted, true, aces) {
		return fmt.Errorf("%w: socket %q permits untrusted local access", ErrInsecureControlDir, socketPath)
	}
	return nil
}

// IsSecureSystemSSHObjectByHandle is the handle-based equivalent of
// IsSecureSystemSSHObject: it verifies that no ancestor directory is a reparse
// point, opens path with FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,
// and evaluates the handle's attributes and GetSecurityInfo descriptor.
func IsSecureSystemSSHObjectByHandle(path string, expectDir bool, currSID *windows.SID) bool {
	if err := VerifyAncestorChainNoReparse(path); err != nil {
		return false
	}
	h, attrs, err := OpenObjectHandleNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if !EvaluateAttributes(attrs, expectDir) {
		return false
	}
	sd, err := GetSecurityInfoByHandle(h)
	if err != nil {
		return false
	}
	return IsSecureSecurityDescriptor(attrs, expectDir, sd, currSID)
}

// IsSecureSystemAncestorDirByHandle is the handle-based equivalent of
// IsSecureSystemAncestorDir: it verifies ancestor reparse points and evaluates
// the directory handle's attributes and GetSecurityInfo descriptor.
func IsSecureSystemAncestorDirByHandle(path string) bool {
	if err := VerifyAncestorChainNoReparse(path); err != nil {
		return false
	}
	h, attrs, err := OpenObjectHandleNoFollow(path, windows.READ_CONTROL)
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if !EvaluateAttributes(attrs, true) {
		return false
	}
	sd, err := GetSecurityInfoByHandle(h)
	if err != nil {
		return false
	}
	return IsSecureSystemAncestorDirDescriptor(attrs, sd)
}
