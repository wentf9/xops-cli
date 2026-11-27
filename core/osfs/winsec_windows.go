//go:build windows

package osfs

import (
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

const (
	ioReparseTagAFUnix uint32 = 0x80000023
	winShareAll        uint32 = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	winNoFollowFlags   uint32 = windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_ANONYMOUS
)

type winFileAttributeTagInfo struct{ FileAttributes, ReparseTag uint32 }

// CurrentProcessUserSID 返回当前进程访问令牌用户 SID 的独立副本。
func CurrentProcessUserSID() (*windows.SID, error) {
	return tokenUserSIDForProcess(windows.CurrentProcess())
}

// ProcessUserSID 查询目标 PID 对应进程访问令牌的用户 SID。
func ProcessUserSID(pid uint32) (*windows.SID, error) {
	if pid == 0 {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "pid"))
	}
	if pid == uint32(os.Getpid()) {
		return CurrentProcessUserSID()
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "OpenProcess"))
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return tokenUserSIDForProcess(h)
}
func tokenUserSIDForProcess(procHandle windows.Handle) (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "OpenProcessToken"))
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil || tu == nil || tu.User.Sid == nil {
		return nil, domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "GetTokenUser"))
	}
	return tu.User.Sid.Copy()
}

// IsTrustedPrincipalSID 判定 sid 是否属于 LocalSystem、Builtin\Administrators 或当前用户。
func IsTrustedPrincipalSID(sid, currentUserSID *windows.SID) bool {
	return sid != nil && sid.IsValid() && (sid.IsWellKnown(windows.WinLocalSystemSid) ||
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		(currentUserSID != nil && currentUserSID.IsValid() && sid.Equals(currentUserSID)))
}
func sidAccessEntry(sid *windows.SID, t windows.TRUSTEE_TYPE, inh uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.SET_ACCESS, Inheritance: inh,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: t, TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}
}

// NewOwnerOnlySecurityDescriptor 构造 GC 安全的自相对（self-relative）受保护 Owner-Only 安全描述符。
func NewOwnerOnlySecurityDescriptor(ownerSID *windows.SID, inheritance uint32) (*windows.SECURITY_DESCRIPTOR, error) {
	if ownerSID == nil || !ownerSID.IsValid() {
		return nil, errField(ErrInsecurePermissions, "owner_sid")
	}
	sysSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		sidAccessEntry(ownerSID, windows.TRUSTEE_IS_USER, inheritance),
		sidAccessEntry(sysSID, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, inheritance),
	}, nil)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := errors.Join(sd.SetOwner(ownerSID, false), sd.SetDACL(dacl, true, false), sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED)); err != nil {
		return nil, err
	}
	relSD, err := sd.ToSelfRelative()
	runtime.KeepAlive(ownerSID)
	runtime.KeepAlive(sysSID)
	runtime.KeepAlive(dacl)
	runtime.KeepAlive(sd)
	return relSD, err
}
func currentOwnerOnlySD(inheritance uint32) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return nil, nil, wrapOp(ErrInsecurePermissions, err, "CurrentProcessUserSID")
	}
	sd, err := NewOwnerOnlySecurityDescriptor(currSID, inheritance)
	if err != nil {
		return nil, nil, wrapOp(ErrInsecurePermissions, err, "NewOwnerOnlySecurityDescriptor")
	}
	return sd, currSID, nil
}
func createWindowsOwnerOnlyFile(fullPath string, disposition uint32) (*os.File, error) {
	sd, _, err := currentOwnerOnlySD(windows.NO_INHERITANCE)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(NormalizeWin32LongPath(fullPath))
	if err != nil {
		return nil, mapOSError(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	handle, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.GENERIC_WRITE, winShareAll, sa, disposition, windows.FILE_ATTRIBUTE_NORMAL|winNoFollowFlags, 0)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(sa)
	if err != nil {
		return nil, mapWindowsOpenError(fullPath, err)
	}
	f, _, err := wrapValidatedWindowsFile(handle, fullPath, true)
	return f, err
}

// OpenObjectHandleNoFollow 以无跟随重解析点、阻断命名管道冒充且支持 \\?\ 长路径打开对象句柄（INV-A4）。
func OpenObjectHandleNoFollow(path string, desiredAccess uint32) (windows.Handle, uint32, error) {
	h, info, err := openObjectHandleInfoNoFollow(path, desiredAccess)
	return h, info.FileAttributes, err
}
func openObjectHandleInfoNoFollow(path string, desiredAccess uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if strings.TrimSpace(path) == "" {
		return windows.InvalidHandle, info, domi18n.EF(ErrInsecurePermissions, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "path"))
	}
	pathPtr, err := windows.UTF16PtrFromString(NormalizeWin32LongPath(path))
	if err != nil {
		return windows.InvalidHandle, info, err
	}
	handle, err := windows.CreateFile(pathPtr, desiredAccess, winShareAll, nil, windows.OPEN_EXISTING, winNoFollowFlags|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return windows.InvalidHandle, info, err
	}
	if ft, fErr := windows.GetFileType(handle); fErr != nil {
		err = fErr
	} else if ft != windows.FILE_TYPE_DISK {
		err = errField(ErrInsecurePermissions, "file_type")
	} else {
		err = windows.GetFileInformationByHandle(handle, &info)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, info, err
	}
	return handle, info, nil
}

// EnsureOwnerOnlyDirectory 确保目录树逐级以受保护 Owner-Only DACL 创建并经句柄校验（INV-A4）。
func EnsureOwnerOnlyDirectory(dir string) error {
	sd, currSID, err := currentOwnerOnlySD(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	absDir, toCreate, err := collectMissingDirs(dir)
	if err != nil {
		return err
	}
	if len(toCreate) == 0 {
		return VerifyOwnerOnlyDirectoryByHandle(absDir, currSID)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return createMissingDirsWin(toCreate, sa, sd, currSID)
}
func checkDirAttrsNoFollowWin(p string) error {
	h, attrs, err := OpenObjectHandleNoFollow(p, windows.READ_CONTROL)
	if err != nil {
		return mapWindowsOpenError(p, err)
	}
	_ = windows.CloseHandle(h)
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return wrapS(ErrInsecurePermissions, domi18n.EF(ports.ErrSymlinkRejected, domi18n.KeyOSFSSymlinkDetected, domi18n.BoundStr("path", p)))
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return wrapS(ErrInsecurePermissions, domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotDirectory, domi18n.BoundStr("path", p)))
	}
	return nil
}
func createMissingDirsWin(toCreate []string, sa *windows.SecurityAttributes, sd *windows.SECURITY_DESCRIPTOR, ownerSID *windows.SID) error {
	for i := len(toCreate) - 1; i >= 0; i-- {
		p := toCreate[i]
		dirPtr, ptrErr := windows.UTF16PtrFromString(NormalizeWin32LongPath(p))
		if ptrErr != nil {
			return mapOSError(ptrErr)
		}
		createErr := windows.CreateDirectory(dirPtr, sa)
		runtime.KeepAlive(sd)
		runtime.KeepAlive(sa)
		if createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
			return mapWindowsOpenError(p, createErr)
		}
		if err := pickIf(ownerSID != nil, func() error { return VerifyOwnerOnlyDirectoryByHandle(p, ownerSID) }, func() error { return checkDirAttrsNoFollowWin(p) })(); err != nil {
			return err
		}
	}
	return nil
}
func collectMissingDirs(dir string) (string, []string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", nil, err
	}
	var toCreate []string
	for cur := absDir; ; {
		if checkErr := checkDirAttrsNoFollowWin(cur); checkErr == nil {
			return absDir, toCreate, nil
		} else if !errors.Is(checkErr, ports.ErrNotFound) {
			return "", nil, wrapTarget(ErrInsecurePermissions, checkErr, "check_dir", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil, domi18n.EF(ErrInsecurePermissions, domi18n.KeyCommonOpTargetFailed, domi18n.Str("op", "access_root"), domi18n.BoundStr("target", cur))
		}
		toCreate, cur = append(toCreate, cur), parent
	}
}
func openWinSecHandleChecked(path string, access uint32, expectDir, expectSocket bool) (windows.Handle, uint32, error) {
	handle, attrs, err := OpenObjectHandleNoFollow(path, access)
	if err != nil {
		return windows.InvalidHandle, 0, mapWindowsOpenError(path, err)
	}
	if expectSocket {
		err = verifyAFUnixReparseHandle(handle, path)
	} else if !isSafeWin32ObjectAttrs(attrs, expectDir, false) {
		err = domi18n.EF(ErrInsecurePermissions, domi18n.KeyOSFSDACLCheckFailed, domi18n.BoundStr("path", path))
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, 0, err
	}
	return handle, attrs, nil
}

// HardenDirectoryOwnerOnly / HardenSocketOwnerOnly 通过无跟随句柄应用受保护 Owner-Only DACL。
func HardenDirectoryOwnerOnly(d string) error {
	return hardenObjectOwnerOnlyByHandle(d, true, false, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
}
func HardenSocketOwnerOnly(p string) error {
	return hardenObjectOwnerOnlyByHandle(p, false, true, windows.NO_INHERITANCE)
}
func hardenObjectOwnerOnlyByHandle(path string, expectDir, expectSocket bool, inheritance uint32) error {
	sd, _, err := currentOwnerOnlySD(inheritance)
	if err != nil {
		return err
	}
	handle, _, err := openWinSecHandleChecked(path, windows.READ_CONTROL|windows.WRITE_DAC, expectDir, expectSocket)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errField(ErrInsecurePermissions, "dacl")
	}
	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	return pickIf[error](err == nil, nil, wrapOp(ErrInsecurePermissions, err, "SetSecurityInfo"))
}

// VerifyOwnerOnlyDirectoryByHandle / VerifyOwnerOnlyFileByHandle / VerifyOwnerOnlySocketByHandle 通过无跟随句柄校验 Owner-Only DACL。
func VerifyOwnerOnlyDirectoryByHandle(d string, s *windows.SID) error {
	return verifyOwnerOnlyPathByHandle(d, true, false, s)
}
func VerifyOwnerOnlyFileByHandle(f string, s *windows.SID) error {
	return verifyOwnerOnlyPathByHandle(f, false, false, s)
}
func VerifyOwnerOnlySocketByHandle(p string) error {
	return verifyOwnerOnlyPathByHandle(p, false, true, nil)
}
func verifyOwnerOnlyPathByHandle(path string, expectDir, expectSocket bool, currSID *windows.SID) error {
	if currSID == nil {
		var err error
		if currSID, err = CurrentProcessUserSID(); err != nil {
			return wrapOp(ErrInsecurePermissions, err, "CurrentProcessUserSID")
		}
	}
	handle, attrs, err := openWinSecHandleChecked(path, windows.READ_CONTROL, expectDir, expectSocket)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return wrapTarget(ErrInsecurePermissions, err, "GetSecurityInfo", path)
	}
	owner, _, oErr := sd.Owner()
	dacl, _, dErr := sd.DACL()
	if oErr != nil || owner == nil || dErr != nil || dacl == nil {
		return domi18n.EF(ErrInsecurePermissions, domi18n.KeyOSFSDACLCheckFailed, domi18n.BoundStr("path", path))
	}
	aces, err := parseWindowsACL(dacl, currSID)
	if err != nil {
		return err
	}
	if EvaluateWindowsObjectACL(WindowsACLInput{Mode: WindowsACLOwnerOnly, Attrs: attrs, ExpectDir: expectDir, AllowReparse: expectSocket, OwnerTrusted: IsTrustedPrincipalSID(owner, currSID), HasDACL: true, ACEs: aces}) != security.VerdictAllow {
		return domi18n.EF(ErrInsecurePermissions, domi18n.KeyOSFSDACLCheckFailed, domi18n.BoundStr("path", path))
	}
	return nil
}
func verifyAFUnixReparseHandle(handle windows.Handle, path string) error {
	var tag winFileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return wrapOp(ErrNotSocket, err, "GetFileInformationByHandleEx")
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || tag.ReparseTag != ioReparseTagAFUnix {
		return domi18n.EF(ErrNotSocket, domi18n.KeyOSFSNotUnixSocket, domi18n.BoundStr("path", path))
	}
	return nil
}
func parseWindowsACL(dacl *windows.ACL, currSID *windows.SID) ([]ParsedWindowsACE, error) {
	aces := make([]ParsedWindowsACE, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return nil, domi18n.EF(ErrInsecurePermissions, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "dacl_ace"), domi18n.Uint64("index", uint64(i)))
		}
		parsed, err := decodeSingleWindowsACE(ace, currSID)
		if err != nil {
			return nil, err
		}
		aces = append(aces, parsed)
	}
	return aces, nil
}
func decodeSingleWindowsACE(ace *windows.ACCESS_ALLOWED_ACE, currSID *windows.SID) (ParsedWindowsACE, error) {
	if uintptr(ace.Header.AceSize) < unsafe.Sizeof(windows.ACE_HEADER{}) {
		return ParsedWindowsACE{}, errField(ErrInsecurePermissions, "ace_header")
	}
	parsed := ParsedWindowsACE{ACEType: ace.Header.AceType, ACEFlags: ace.Header.AceFlags}
	if parsed.ACEType != WinACETypeAllow {
		return parsed, nil
	}
	const minSIDBytes = uintptr(8)
	sidOffset := unsafe.Offsetof(ace.SidStart)
	if uintptr(ace.Header.AceSize) < sidOffset+minSIDBytes {
		return ParsedWindowsACE{}, errField(ErrInsecurePermissions, "ace_sid")
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.IsValid() || aceSID.Len() < int(minSIDBytes) || uintptr(ace.Header.AceSize) < sidOffset+uintptr(aceSID.Len()) {
		return ParsedWindowsACE{}, errField(ErrInsecurePermissions, "ace_sid")
	}
	parsed.Mask, parsed.SIDValid, parsed.SIDTrusted = uint32(ace.Mask), true, IsTrustedPrincipalSID(aceSID, currSID)
	return parsed, nil
}
