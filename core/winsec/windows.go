//go:build windows

package winsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Compile-time assertions keeping eval.go constants in exact lockstep with
// golang.org/x/sys/windows.
const (
	_ = uint(InvalidFileAttributes - windows.INVALID_FILE_ATTRIBUTES)
	_ = uint(windows.INVALID_FILE_ATTRIBUTES - InvalidFileAttributes)
	_ = uint(FileAttributeDirectory - windows.FILE_ATTRIBUTE_DIRECTORY)
	_ = uint(windows.FILE_ATTRIBUTE_DIRECTORY - FileAttributeDirectory)
	_ = uint(FileAttributeDevice - windows.FILE_ATTRIBUTE_DEVICE)
	_ = uint(windows.FILE_ATTRIBUTE_DEVICE - FileAttributeDevice)
	_ = uint(FileAttributeReparsePoint - windows.FILE_ATTRIBUTE_REPARSE_POINT)
	_ = uint(windows.FILE_ATTRIBUTE_REPARSE_POINT - FileAttributeReparsePoint)

	_ = uint(ObjectInheritACEFlag - windows.OBJECT_INHERIT_ACE)
	_ = uint(windows.OBJECT_INHERIT_ACE - ObjectInheritACEFlag)
	_ = uint(ContainerInheritACEFlag - windows.CONTAINER_INHERIT_ACE)
	_ = uint(windows.CONTAINER_INHERIT_ACE - ContainerInheritACEFlag)
	_ = uint(NoPropagateInheritACEFlag - windows.NO_PROPAGATE_INHERIT_ACE)
	_ = uint(windows.NO_PROPAGATE_INHERIT_ACE - NoPropagateInheritACEFlag)
	_ = uint(InheritOnlyACEFlag - windows.INHERIT_ONLY_ACE)
	_ = uint(windows.INHERIT_ONLY_ACE - InheritOnlyACEFlag)
	_ = uint(AccessAllowedACEType - windows.ACCESS_ALLOWED_ACE_TYPE)
	_ = uint(windows.ACCESS_ALLOWED_ACE_TYPE - AccessAllowedACEType)
	_ = uint(AccessDeniedACEType - windows.ACCESS_DENIED_ACE_TYPE)
	_ = uint(windows.ACCESS_DENIED_ACE_TYPE - AccessDeniedACEType)

	_ = uint(AccessFileWriteData - windows.FILE_WRITE_DATA)
	_ = uint(windows.FILE_WRITE_DATA - AccessFileWriteData)
	_ = uint(AccessFileAppendData - windows.FILE_APPEND_DATA)
	_ = uint(windows.FILE_APPEND_DATA - AccessFileAppendData)
	_ = uint(AccessDelete - windows.DELETE)
	_ = uint(windows.DELETE - AccessDelete)
	_ = uint(AccessWriteDAC - windows.WRITE_DAC)
	_ = uint(windows.WRITE_DAC - AccessWriteDAC)
	_ = uint(AccessWriteOwner - windows.WRITE_OWNER)
	_ = uint(windows.WRITE_OWNER - AccessWriteOwner)
	_ = uint(AccessGenericAll - windows.GENERIC_ALL)
	_ = uint(windows.GENERIC_ALL - AccessGenericAll)
	_ = uint(AccessGenericWrite - windows.GENERIC_WRITE)
	_ = uint(windows.GENERIC_WRITE - AccessGenericWrite)

	_ = uint(SIOAFUnixGetPeerPID - (windows.IOC_OUT | windows.IOC_VENDOR | 256))
	_ = uint((windows.IOC_OUT | windows.IOC_VENDOR | 256) - SIOAFUnixGetPeerPID)
)

// CurrentProcessUserSID returns a Go-heap copy of the current process token user SID.
func CurrentProcessUserSID() (*windows.SID, error) {
	return tokenUserSIDForProcess(windows.CurrentProcess())
}

// ProcessUserSID returns a Go-heap copy of the TokenUser SID for the process
// identified by pid using PROCESS_QUERY_LIMITED_INFORMATION.
func ProcessUserSID(pid uint32) (*windows.SID, error) {
	if pid == 0 {
		return nil, errors.New("process PID is zero")
	}
	if pid == uint32(os.Getpid()) {
		return CurrentProcessUserSID()
	}
	procHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess: %w", err)
	}
	defer func() { _ = windows.CloseHandle(procHandle) }()
	return tokenUserSIDForProcess(procHandle)
}

func tokenUserSIDForProcess(procHandle windows.Handle) (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &tok); err != nil {
		return nil, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	if tu == nil || tu.User.Sid == nil {
		return nil, errors.New("empty process token user SID")
	}
	return tu.User.Sid.Copy()
}

// IsTrustedPrincipalSID reports whether sid is LocalSystem, Builtin\Administrators,
// or equal to currentUserSID. Passing currentUserSID == nil restricts trust
// strictly to LocalSystem and Builtin\Administrators (never trusting the current
// non-admin user).
func IsTrustedPrincipalSID(sid, currentUserSID *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	allowCurrentUser := currentUserSID != nil && currentUserSID.IsValid()
	matchesCurrentUser := allowCurrentUser && sid.Equals(currentUserSID)
	return EvaluatePrincipalTrust(
		true,
		sid.IsWellKnown(windows.WinLocalSystemSid),
		sid.IsWellKnown(windows.WinBuiltinAdministratorsSid),
		matchesCurrentUser,
		allowCurrentUser,
	)
}

// GetFileAttributesNoFollow queries Win32 file attributes without traversing reparse points.
func GetFileAttributesNoFollow(path string) (uint32, bool) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.INVALID_FILE_ATTRIBUTES, false
	}
	var data windows.Win32FileAttributeData
	if err := windows.GetFileAttributesEx(pathPtr, windows.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&data))); err != nil {
		return windows.INVALID_FILE_ATTRIBUTES, false
	}
	return data.FileAttributes, true
}

// ParseACL decodes all ACEs in dacl into platform-independent ParsedACE entries.
func ParseACL(dacl *windows.ACL, currSID *windows.SID) ([]ParsedACE, bool) {
	if dacl == nil {
		return nil, false
	}
	aces := make([]ParsedACE, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return nil, false
		}
		if uintptr(ace.Header.AceSize) < unsafe.Sizeof(windows.ACE_HEADER{}) {
			return nil, false
		}
		parsed := ParsedACE{
			ACEType:  ace.Header.AceType,
			ACEFlags: ace.Header.AceFlags,
		}
		if IsStandardLayoutAllowACEType(parsed.ACEType) {
			const minWindowsSIDHeaderSize = uintptr(8)
			sidOffset := unsafe.Offsetof(ace.SidStart)
			if uintptr(ace.Header.AceSize) < sidOffset+minWindowsSIDHeaderSize {
				return nil, false
			}
			aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !aceSID.IsValid() {
				return nil, false
			}
			sidLen := aceSID.Len()
			if sidLen < int(minWindowsSIDHeaderSize) || uintptr(ace.Header.AceSize) < sidOffset+uintptr(sidLen) {
				return nil, false
			}
			parsed.Mask = uint32(ace.Mask)
			parsed.SIDValid = true
			parsed.SIDTrusted = IsTrustedPrincipalSID(aceSID, currSID)
		}
		aces = append(aces, parsed)
	}
	return aces, true
}

// IsSecureSecurityDescriptor evaluates sd against Win32-OpenSSH write-restricted
// object security rules (used for global ssh_known_hosts).
func IsSecureSecurityDescriptor(
	attrs uint32,
	expectDir bool,
	sd *windows.SECURITY_DESCRIPTOR,
	currSID *windows.SID,
) bool {
	if sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	ownerTrusted := IsTrustedPrincipalSID(owner, currSID)
	if !ownerTrusted {
		return false
	}
	dacl, _, err := sd.DACL()
	// A nil DACL on Windows means unrestricted full access to Everyone; reject.
	if err != nil || dacl == nil {
		return false
	}
	aces, ok := ParseACL(dacl, currSID)
	if !ok {
		return false
	}
	return EvaluateObjectSecurity(attrs, expectDir, ownerTrusted, true, aces)
}

// IsSecureSystemSSHObject checks that path is not a reparse point/device and
// satisfies IsSecureSecurityDescriptor before and after querying the descriptor.
func IsSecureSystemSSHObject(path string, expectDir bool, currSID *windows.SID) bool {
	attrs, ok := GetFileAttributesNoFollow(path)
	if !ok || !EvaluateAttributes(attrs, expectDir) {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		return false
	}
	if !IsSecureSecurityDescriptor(attrs, expectDir, sd, currSID) {
		return false
	}
	attrsAfter, ok := GetFileAttributesNoFollow(path)
	return ok && EvaluateAttributes(attrsAfter, expectDir)
}

// IsSecureSystemGlobalSSHObject checks that path is a non-reparse, non-device
// system-global SSH object (such as %ProgramData%\ssh or
// %ProgramData%\ssh\ssh_known_hosts) owned strictly by SYSTEM or
// Builtin\Administrators with write/mutate DACL entries restricted to those
// same system principals (currSID == nil; never trusts the current user).
func IsSecureSystemGlobalSSHObject(path string, expectDir bool) bool {
	return IsSecureSystemSSHObject(path, expectDir, nil)
}

// IsSecureSystemAncestorDirDescriptor evaluates sd for a shared system ancestor
// directory (such as C:\ProgramData), trusting strictly LocalSystem and
// Builtin\Administrators (currSID == nil).
func IsSecureSystemAncestorDirDescriptor(attrs uint32, sd *windows.SECURITY_DESCRIPTOR) bool {
	if sd == nil {
		return false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	ownerTrusted := IsTrustedPrincipalSID(owner, nil)
	if !ownerTrusted {
		return false
	}
	dacl, _, err := sd.DACL()
	// A nil DACL on Windows means unrestricted full access to Everyone; reject.
	if err != nil || dacl == nil {
		return false
	}
	aces, ok := ParseACL(dacl, nil)
	if !ok {
		return false
	}
	return EvaluateSystemAncestorDirSecurity(attrs, ownerTrusted, true, aces)
}

// IsSecureSystemAncestorDir checks that path is a real directory (not a reparse
// point or device, verified before and after reading its security descriptor)
// owned strictly by SYSTEM or Builtin\Administrators with a non-nil DACL that
// denies destructive/takeover rights to untrusted principals. This accepts
// standard Windows C:\ProgramData ACLs while rejecting junctions, user-owned
// roots, nil DACLs, and delete/takeover permissions.
func IsSecureSystemAncestorDir(path string) bool {
	attrs, ok := GetFileAttributesNoFollow(path)
	if !ok || !EvaluateAttributes(attrs, true) {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		return false
	}
	if !IsSecureSystemAncestorDirDescriptor(attrs, sd) {
		return false
	}
	attrsAfter, ok := GetFileAttributesNoFollow(path)
	return ok && EvaluateAttributes(attrsAfter, true)
}

// NewOwnerOnlyACL creates a DACL containing only GENERIC_ALL entries for
// currSID and NT AUTHORITY\SYSTEM.
func NewOwnerOnlyACL(currSID *windows.SID, inheritance uint32) (*windows.ACL, error) {
	if currSID == nil || !currSID.IsValid() {
		return nil, errors.New("current user SID is invalid")
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("create SYSTEM SID failed: %w", err)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(currSID)
	pinner.Pin(systemSID)

	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, fmt.Errorf("build owner-only ACL failed: %w", err)
	}
	return acl, nil
}

// NewOwnerOnlySecurityDescriptor constructs a self-relative SECURITY_DESCRIPTOR
// with a protected DACL granting GENERIC_ALL solely to currSID and SYSTEM
// (blocking inherited ACEs via SE_DACL_PROTECTED).
func NewOwnerOnlySecurityDescriptor(currSID *windows.SID, inheritance uint32) (*windows.SECURITY_DESCRIPTOR, error) {
	acl, err := NewOwnerOnlyACL(currSID, inheritance)
	if err != nil {
		return nil, err
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("create security descriptor failed: %w", err)
	}
	if err := sd.SetDACL(acl, true, false); err != nil {
		return nil, fmt.Errorf("set owner-only DACL failed: %w", err)
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, fmt.Errorf("protect owner-only DACL failed: %w", err)
	}
	selfRel, err := sd.ToSelfRelative()
	runtime.KeepAlive(acl)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, fmt.Errorf("convert security descriptor to self-relative failed: %w", err)
	}
	return selfRel, nil
}

// VerifyOwnerOnlyDirectory verifies that dirPath is a real directory (not a
// reparse point or device), owned by a trusted principal, with a non-nil DACL
// granting zero access bits to any untrusted principal. It never modifies
// existing directory permissions.
func VerifyOwnerOnlyDirectory(dirPath string, currSID *windows.SID) error {
	attrs, ok := GetFileAttributesNoFollow(dirPath)
	if !ok || !EvaluateAttributes(attrs, true) {
		return fmt.Errorf("%w: %q is not a secure directory", ErrInsecureControlDir, dirPath)
	}
	sd, err := windows.GetNamedSecurityInfo(
		dirPath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%w: query directory security descriptor for %q failed: %w", ErrInsecureControlDir, dirPath, err)
	}
	if sd == nil {
		return fmt.Errorf("%w: query directory security descriptor for %q returned nil", ErrInsecureControlDir, dirPath)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%w: query directory owner for %q failed: %w", ErrInsecureControlDir, dirPath, err)
	}
	if owner == nil {
		return fmt.Errorf("%w: query directory owner for %q returned nil", ErrInsecureControlDir, dirPath)
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
	attrsAfter, ok := GetFileAttributesNoFollow(dirPath)
	if !ok || !EvaluateAttributes(attrsAfter, true) {
		return fmt.Errorf("%w: directory %q changed during verification", ErrInsecureControlDir, dirPath)
	}
	return nil
}

// EnsureOwnerOnlyDirectory creates any missing leaf directories under dirPath
// with a protected owner-only DACL (current user + SYSTEM, no inheritance) and
// verifies that dirPath satisfies VerifyOwnerOnlyDirectory. Existing
// directories with overly permissive ACLs are rejected fail-closed without
// modifying their permissions.
func EnsureOwnerOnlyDirectory(dirPath string) error {
	cleaned := filepath.Clean(strings.TrimSpace(dirPath))
	if cleaned == "" || cleaned == "." {
		var err error
		cleaned, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve control socket directory failed: %w", err)
		}
	}
	absDir, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("resolve absolute control socket directory %q failed: %w", dirPath, err)
	}

	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID failed: %w", err)
	}

	// Find missing trailing directories from absDir upward.
	var toCreate []string
	cur := absDir
	for {
		attrs, ok := GetFileAttributesNoFollow(cur)
		if ok {
			if !EvaluateAttributes(attrs, true) {
				return fmt.Errorf("%w: ancestor %q is not a secure directory", ErrInsecureControlDir, cur)
			}
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return fmt.Errorf("%w: volume root %q is inaccessible", ErrInsecureControlDir, cur)
		}
		toCreate = append(toCreate, cur)
		cur = parent
	}

	if len(toCreate) > 0 {
		sd, sdErr := NewOwnerOnlySecurityDescriptor(currSID, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
		if sdErr != nil {
			return fmt.Errorf("create owner-only directory security descriptor failed: %w", sdErr)
		}
		sa := &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		}
		for i := len(toCreate) - 1; i >= 0; i-- {
			dir := toCreate[i]
			dirPtr, ptrErr := windows.UTF16PtrFromString(dir)
			if ptrErr != nil {
				return fmt.Errorf("encode control socket directory %q failed: %w", dir, ptrErr)
			}
			createErr := windows.CreateDirectory(dirPtr, sa)
			runtime.KeepAlive(sd)
			if createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
				return fmt.Errorf("create control socket directory %q failed: %w", dir, createErr)
			}
			// Verify every created or concurrently-existing directory level so a
			// raced intermediate directory with weak ACLs is rejected fail-closed.
			if err := VerifyOwnerOnlyDirectory(dir, currSID); err != nil {
				return err
			}
		}
		return nil
	}

	return VerifyOwnerOnlyDirectory(absDir, currSID)
}

// HardenFileOwnerOnly applies a protected owner-only DACL (current user +
// SYSTEM, no inherited ACEs) to path as defense-in-depth.
func HardenFileOwnerOnly(path string) error {
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID failed: %w", err)
	}
	dacl, err := NewOwnerOnlyACL(currSID, windows.NO_INHERITANCE)
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	runtime.KeepAlive(dacl)
	if err != nil {
		return fmt.Errorf("set owner-only DACL on %q failed: %w", path, err)
	}
	return nil
}

// VerifyOwnerOnlySocketFile verifies that socketPath is an AF_UNIX socket
// (before and after reading its security descriptor, with matching file
// identity to close symlink-swap TOCTOU), has a trusted owner, and has a
// non-nil owner-only DACL permitting zero access bits for untrusted SIDs.
func VerifyOwnerOnlySocketFile(socketPath string) error {
	fiBefore, err := os.Lstat(socketPath)
	if err != nil || fiBefore == nil || fiBefore.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%w: %q is not an AF_UNIX socket", ErrInsecureControlDir, socketPath)
	}
	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("query current Windows user SID failed: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		socketPath,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%w: query socket security descriptor for %q failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	if sd == nil {
		return fmt.Errorf("%w: query socket security descriptor for %q returned nil", ErrInsecureControlDir, socketPath)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%w: query socket owner for %q failed: %w", ErrInsecureControlDir, socketPath, err)
	}
	if owner == nil {
		return fmt.Errorf("%w: query socket owner for %q returned nil", ErrInsecureControlDir, socketPath)
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
	fiAfter, err := os.Lstat(socketPath)
	if err != nil || fiAfter == nil || fiAfter.Mode()&os.ModeSocket == 0 || !os.SameFile(fiBefore, fiAfter) {
		return fmt.Errorf("%w: socket %q changed during verification", ErrInsecureControlDir, socketPath)
	}
	return nil
}

// VerifyAFUnixPeerCurrentUser queries the connected AF_UNIX peer PID via
// WSAIoctl(SIO_AF_UNIX_GETPEERPID) and verifies via ProcessUserSID that the
// peer runs under the current user's SID. Any failure fails closed with
// ErrUnauthorizedControlPeer (and additionally wraps ErrUnsupportedPeerPID
// when the IOCTL is unsupported on legacy Windows).
func VerifyAFUnixPeerCurrentUser(fd uintptr) error {
	var (
		peerPID       uint32
		bytesReturned uint32
	)
	ioctlErr := windows.WSAIoctl(
		windows.Handle(fd),
		SIOAFUnixGetPeerPID,
		nil,
		0,
		(*byte)(unsafe.Pointer(&peerPID)),
		uint32(unsafe.Sizeof(peerPID)),
		&bytesReturned,
		nil,
		0,
	)
	if ioctlErr != nil {
		unsupported := errors.Is(ioctlErr, windows.WSAEOPNOTSUPP) || errors.Is(ioctlErr, windows.WSAEINVAL)
		return EvaluatePeerProcessIdentity(0, ioctlErr, unsupported, false, false, nil)
	}
	if bytesReturned != uint32(unsafe.Sizeof(peerPID)) || peerPID == 0 {
		return EvaluatePeerProcessIdentity(0, fmt.Errorf("unexpected SIO_AF_UNIX_GETPEERPID reply (bytes=%d, pid=%d)", bytesReturned, peerPID), false, false, false, nil)
	}
	if peerPID == uint32(os.Getpid()) {
		return nil
	}

	currSID, err := CurrentProcessUserSID()
	if err != nil {
		return EvaluatePeerProcessIdentity(peerPID, nil, false, false, false, fmt.Errorf("query current user SID: %w", err))
	}

	peerSID, err := ProcessUserSID(peerPID)
	if err != nil {
		return EvaluatePeerProcessIdentity(peerPID, nil, false, false, false, err)
	}
	sidValid := peerSID != nil && peerSID.IsValid()
	matches := sidValid && currSID != nil && currSID.IsValid() && peerSID.Equals(currSID)
	return EvaluatePeerProcessIdentity(peerPID, nil, false, sidValid, matches, nil)
}
