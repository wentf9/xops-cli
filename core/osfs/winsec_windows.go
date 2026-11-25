//go:build windows

package osfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
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
		return nil, errors.New("osfs: 目标进程 PID 不能为 0")
	}
	if pid == uint32(os.Getpid()) {
		return CurrentProcessUserSID()
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("osfs: OpenProcess(%d) 失败: %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return tokenUserSIDForProcess(h)
}

func tokenUserSIDForProcess(procHandle windows.Handle) (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("osfs: OpenProcessToken 失败: %w", err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil || tu == nil || tu.User.Sid == nil {
		return nil, fmt.Errorf("osfs: 查询进程令牌用户 SID 失败: %w", err)
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
		return nil, fmt.Errorf("%w: 无效所有者 SID", ErrInsecurePermissions)
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
		return nil, nil, fmt.Errorf("%w: 查询当前用户 SID 失败: %w", ErrInsecurePermissions, err)
	}
	sd, err := NewOwnerOnlySecurityDescriptor(currSID, inheritance)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: 构造 Owner-Only DACL 失败: %w", ErrInsecurePermissions, err)
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
		return windows.InvalidHandle, info, fmt.Errorf("%w: Windows 对象路径不能为空", ErrInsecurePermissions)
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
		err = fmt.Errorf("%w: 非磁盘对象句柄类型 %d", ErrInsecurePermissions, ft)
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
		return fmt.Errorf("%w: %w: %q 为重解析点", ErrInsecurePermissions, ports.ErrSymlinkRejected, p)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%w: %w: %q 不是目录", ErrInsecurePermissions, ports.ErrNotRegularFile, p)
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
		var vErr error
		if ownerSID != nil {
			vErr = VerifyOwnerOnlyDirectoryByHandle(p, ownerSID)
		} else {
			vErr = checkDirAttrsNoFollowWin(p)
		}
		if vErr != nil {
			return vErr
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
			return "", nil, fmt.Errorf("%w: 检查祖先目录 %q 失败: %w", ErrInsecurePermissions, cur, checkErr)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", nil, fmt.Errorf("%w: 卷根目录 %q 不可访问", ErrInsecurePermissions, cur)
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
		err = fmt.Errorf("%w: 对象 %q 属性不满足预期", ErrInsecurePermissions, path)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, 0, err
	}
	return handle, attrs, nil
}

// HardenDirectoryOwnerOnly / HardenSocketOwnerOnly 通过无跟随句柄应用受保护 Owner-Only DACL。
func HardenDirectoryOwnerOnly(dir string) error {
	return hardenObjectOwnerOnlyByHandle(dir, true, false, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
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
		return fmt.Errorf("%w: 提取受保护 DACL 失败", ErrInsecurePermissions)
	}
	err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	return pickIf[error](err == nil, nil, fmt.Errorf("%w: SetSecurityInfo 失败: %w", ErrInsecurePermissions, err))
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
			return fmt.Errorf("%w: 查询当前用户 SID 失败: %w", ErrInsecurePermissions, err)
		}
	}
	handle, attrs, err := openWinSecHandleChecked(path, windows.READ_CONTROL, expectDir, expectSocket)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: GetSecurityInfo(%q) 失败: %w", ErrInsecurePermissions, path, err)
	}
	owner, _, oErr := sd.Owner()
	dacl, _, dErr := sd.DACL()
	if oErr != nil || owner == nil || dErr != nil || dacl == nil {
		return fmt.Errorf("%w: %q 缺少有效所有者或 DACL", ErrInsecurePermissions, path)
	}
	aces, err := parseWindowsACL(dacl, currSID)
	if err != nil {
		return err
	}
	if EvaluateWindowsObjectACL(WindowsACLInput{Mode: WindowsACLOwnerOnly, Attrs: attrs, ExpectDir: expectDir, AllowReparse: expectSocket, OwnerTrusted: IsTrustedPrincipalSID(owner, currSID), HasDACL: true, ACEs: aces}) != security.VerdictAllow {
		return fmt.Errorf("%w: %q 未通过 Owner-Only DACL 校验", ErrInsecurePermissions, path)
	}
	return nil
}

func verifyAFUnixReparseHandle(handle windows.Handle, path string) error {
	var tag winFileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return fmt.Errorf("%w: 查询重解析标签失败: %w", ErrNotSocket, err)
	}
	if tag.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || tag.ReparseTag != ioReparseTagAFUnix {
		return fmt.Errorf("%w: %q 不是 AF_UNIX 套接字 (tag=0x%x)", ErrNotSocket, path, tag.ReparseTag)
	}
	return nil
}

func parseWindowsACL(dacl *windows.ACL, currSID *windows.SID) ([]ParsedWindowsACE, error) {
	aces := make([]ParsedWindowsACE, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return nil, fmt.Errorf("%w: 解码 DACL ACE #%d 失败", ErrInsecurePermissions, i)
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
		return ParsedWindowsACE{}, fmt.Errorf("%w: ACE 头部畸形", ErrInsecurePermissions)
	}
	parsed := ParsedWindowsACE{ACEType: ace.Header.AceType, ACEFlags: ace.Header.AceFlags}
	if parsed.ACEType != WinACETypeAllow {
		return parsed, nil
	}
	const minSIDBytes = uintptr(8)
	sidOffset := unsafe.Offsetof(ace.SidStart)
	if uintptr(ace.Header.AceSize) < sidOffset+minSIDBytes {
		return ParsedWindowsACE{}, fmt.Errorf("%w: ACE SID 越界", ErrInsecurePermissions)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.IsValid() || aceSID.Len() < int(minSIDBytes) || uintptr(ace.Header.AceSize) < sidOffset+uintptr(aceSID.Len()) {
		return ParsedWindowsACE{}, fmt.Errorf("%w: ACE SID 无效", ErrInsecurePermissions)
	}
	parsed.Mask, parsed.SIDValid, parsed.SIDTrusted = uint32(ace.Mask), true, IsTrustedPrincipalSID(aceSID, currSID)
	return parsed, nil
}
