//go:build windows

package vaultsys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Stat_t struct {
	Dev, Ino, Nlink uint64
	Mode, Uid       uint32
	Size            int64
}

const (
	O_RDONLY            = 0
	O_WRONLY            = 1
	O_RDWR              = 2
	O_CREAT             = 0x40
	O_EXCL              = 0x80
	O_CLOEXEC           = 0x80000
	O_DIRECTORY         = 0x10000
	O_NOFOLLOW          = 0x20000
	O_NONBLOCK          = 0x800
	S_IFREG             = 0x8000
	S_IFDIR             = 0x4000
	S_ISVTX             = 0x200
	AT_REMOVEDIR        = 0x200
	AT_SYMLINK_NOFOLLOW = 0x100
	LOCK_SH             = 1
	LOCK_EX             = 2
	LOCK_NB             = 4
	LOCK_UN             = 8
)

var (
	EAGAIN      = windows.ERROR_LOCK_VIOLATION
	EWOULDBLOCK = windows.ERROR_LOCK_VIOLATION
	EEXIST      = os.ErrExist
	EINVAL      = windows.ERROR_INVALID_PARAMETER
	ELOOP       = os.ErrPermission
	ENOSYS      = windows.ERROR_CALL_NOT_IMPLEMENTED
	ENOTDIR     = windows.ERROR_DIRECTORY
	EOPNOTSUPP  = windows.ERROR_NOT_SUPPORTED
)
var currentSID = sync.OnceValues(func() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
})

func nativeError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.Join(os.ErrExist, err)
	}
	return err
}

func Openat(fd int, name string, flags int, mode uint32) (int, error) {
	if name == "." || name == ".." {
		path, err := handlePath(fd)
		if err != nil {
			return -1, err
		}
		if name == ".." {
			path = filepath.Dir(path)
		}
		parent, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return -1, err
		}
		handle, err := windows.CreateFile(parent, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		return int(handle), err
	}
	if name != "." && (strings.ContainsAny(name, "/\\:") || strings.TrimRight(name, " .") != name) {
		return -1, os.ErrPermission
	}
	return openRelative(windows.Handle(fd), name, flags, mode, 0)
}

func openRelative(parent windows.Handle, name string, flags int, mode uint32, extra uint32) (int, error) {
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return -1, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE}
	access := uint32(windows.FILE_GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE) | extra
	if flags&(O_WRONLY|O_RDWR) != 0 {
		access |= windows.FILE_GENERIC_WRITE
	}
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if flags&O_DIRECTORY != 0 {
		options |= windows.FILE_DIRECTORY_FILE
	}
	disposition := uint32(windows.FILE_OPEN)
	var descriptor *windows.SECURITY_DESCRIPTOR
	if flags&O_CREAT != 0 {
		disposition = windows.FILE_OPEN_IF
		if flags&O_EXCL != 0 {
			disposition = windows.FILE_CREATE
		}
		sid, e := currentSID()
		if e != nil {
			return -1, e
		}
		descriptor, e = windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)")
		if e != nil {
			return -1, e
		}
		oa.SecurityDescriptor = descriptor
		options |= windows.FILE_WRITE_THROUGH
	}
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options, 0, 0)
	if err != nil {
		return -1, nativeError(err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return -1, errors.Join(err, windows.CloseHandle(handle))
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return -1, errors.Join(os.ErrPermission, windows.CloseHandle(handle))
	}
	return int(handle), nil
}

func Fstat(fd int, st *Stat_t) error {
	handle := windows.Handle(fd)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.ErrPermission
	}
	directory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	mode, uid, err := securityMode(handle, directory)
	if err != nil {
		return err
	}
	if directory {
		mode |= S_IFDIR
	} else {
		mode |= S_IFREG
	}
	*st = Stat_t{Dev: uint64(info.VolumeSerialNumber), Ino: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow), Nlink: uint64(info.NumberOfLinks), Mode: mode, Uid: uid, Size: int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))}
	return nil
}

func securityMode(handle windows.Handle, directory bool) (uint32, uint32, error) {
	sid, err := currentSID()
	if err != nil {
		return 0, 0, err
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, 0, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return 0, 0, err
	}
	if owner == nil {
		return 0, 0, os.ErrPermission
	}
	uid, err := windowsOwnerID(owner, sid)
	if err != nil {
		return 0, 0, err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return 0, 0, err
	}
	if acl == nil {
		return 0, 0, os.ErrPermission
	}
	mode := uint32(0600)
	if directory {
		mode = 0700
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return 0, 0, err
		}
		if ace.Header.AceFlags&0x8 != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return 0, 0, os.ErrPermission
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if trustedSID(trustee, sid) {
			continue
		}
		mask := uint32(ace.Mask)
		if mask&(windows.GENERIC_ALL|windows.GENERIC_READ|windows.FILE_READ_DATA) != 0 {
			mode |= 0044
		}
		danger := uint32(windows.GENERIC_ALL | windows.WRITE_DAC | windows.WRITE_OWNER)
		if directory {
			danger |= 0x40 /* FILE_DELETE_CHILD */
		} else {
			danger |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE
		}
		if mask&danger != 0 {
			mode |= 0022
		}
	}
	return mode, uid, nil
}

func Fstatat(fd int, name string, st *Stat_t, flags int) (err error) {
	h, err := Openat(fd, name, O_RDONLY|O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(windows.Handle(h))) }()
	return Fstat(h, st)
}
func Mkdirat(fd int, name string, mode uint32) error {
	h, err := Openat(fd, name, O_RDONLY|O_DIRECTORY|O_CREAT|O_EXCL, mode)
	if err != nil {
		return err
	}
	return windows.CloseHandle(windows.Handle(h))
}
func Unlinkat(fd int, name string, flags int) (err error) {
	openFlags := O_RDONLY | O_NOFOLLOW
	if flags&AT_REMOVEDIR != 0 {
		openFlags |= O_DIRECTORY
	}
	h, err := openRelative(windows.Handle(fd), name, openFlags, 0, windows.DELETE)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(windows.Handle(h))) }()
	var iosb windows.IO_STATUS_BLOCK
	value := byte(1)
	return nativeError(windows.NtSetInformationFile(windows.Handle(h), &iosb, &value, 1, windows.FileDispositionInformation))
}
func Flock(fd, flags int) error {
	var overlapped windows.Overlapped
	if flags&LOCK_UN != 0 {
		return windows.UnlockFileEx(windows.Handle(fd), 0, 1, 0, &overlapped)
	}
	native := uint32(0)
	if flags&LOCK_NB != 0 {
		native |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if flags&LOCK_EX != 0 {
		native |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	return windows.LockFileEx(windows.Handle(fd), native, 0, 1, 0, &overlapped)
}

// Windows persists rename metadata with MOVEFILE_WRITE_THROUGH. Directory
// handles cannot be flushed using FlushFileBuffers; regular files are flushed.
func SyncFile(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil
	}
	if err := file.Sync(); err == nil {
		return nil
	}
	// FlushFileBuffers requires write access, even for a metadata-only flush.
	reopened, _, callErr := reopenFile.Call(file.Fd(), windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_FLAG_WRITE_THROUGH)
	if reopened == uintptr(windows.InvalidHandle) || reopened == 0 {
		return fmt.Errorf("reopen file for durable flush: %w", callErr)
	}
	return errors.Join(windows.FlushFileBuffers(windows.Handle(reopened)), windows.CloseHandle(windows.Handle(reopened)))
}

var reopenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

func handlePath(fd int) (string, error) {
	buffer := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(fd), &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buffer)) {
		return "", fmt.Errorf("vault path exceeds Windows limit")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}
func RenameEntry(fromFD int, from string, toFD int, to string, exclusive bool) error {
	if strings.ContainsAny(from, "/\\:") || strings.ContainsAny(to, "/\\:") {
		return os.ErrPermission
	}
	source, err := handlePath(fromFD)
	if err != nil {
		return err
	}
	destination, err := handlePath(toFD)
	if err != nil {
		return err
	}
	oldName, err := windows.UTF16PtrFromString(filepath.Join(source, from))
	if err != nil {
		return err
	}
	newName, err := windows.UTF16PtrFromString(filepath.Join(destination, to))
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if !exclusive {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return nativeError(windows.MoveFileEx(oldName, newName, flags))
}

func trustedSID(trustee, current string) bool {
	return trustee == current || trustee == "S-1-5-18" || trustee == "S-1-5-32-544" || trustee == "S-1-3-4"
}

func windowsOwnerID(owner *windows.SID, sid string) (uint32, error) {
	uid := uint32(1) // unknown owners remain observable but never pass private checks
	if owner.String() == sid {
		uid = ^uint32(0)
	} else if owner.String() == "S-1-5-32-544" {
		elevated, e := windows.Token(0).IsMember(owner)
		if e != nil {
			return 0, e
		}
		if elevated {
			uid = ^uint32(0)
		} else {
			uid = 0
		}
	} else if owner.String() == "S-1-5-18" {
		uid = 0
	}

	return uid, nil
}

// A read-only pre-provisioned key is an input, not a vault-owned writable file.
// Newly generated keys always use SyncFile before atomic publication.
func SyncKeyFile(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		return nil
	}
	err := SyncFile(file)
	// This path only imports an existing, validated key. ACL-read-only keys and
	// keys on read-only media must not require write access merely to be reused.
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_WRITE_PROTECT) {
		return nil
	}
	return err
}
