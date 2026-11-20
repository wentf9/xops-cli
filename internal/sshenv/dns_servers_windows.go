//go:build windows

package sshenv

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Compile-time assertions keeping windows_security_eval.go constants in lockstep
// with golang.org/x/sys/windows.
const (
	_ = uint(windowsInvalidFileAttributes - windows.INVALID_FILE_ATTRIBUTES)
	_ = uint(windows.INVALID_FILE_ATTRIBUTES - windowsInvalidFileAttributes)
	_ = uint(windowsFileAttributeDirectory - windows.FILE_ATTRIBUTE_DIRECTORY)
	_ = uint(windows.FILE_ATTRIBUTE_DIRECTORY - windowsFileAttributeDirectory)
	_ = uint(windowsFileAttributeDevice - windows.FILE_ATTRIBUTE_DEVICE)
	_ = uint(windows.FILE_ATTRIBUTE_DEVICE - windowsFileAttributeDevice)
	_ = uint(windowsFileAttributeReparsePoint - windows.FILE_ATTRIBUTE_REPARSE_POINT)
	_ = uint(windows.FILE_ATTRIBUTE_REPARSE_POINT - windowsFileAttributeReparsePoint)

	_ = uint(windowsInheritOnlyACEFlag - windows.INHERIT_ONLY_ACE)
	_ = uint(windows.INHERIT_ONLY_ACE - windowsInheritOnlyACEFlag)
	_ = uint(windowsAccessAllowedACEType - windows.ACCESS_ALLOWED_ACE_TYPE)
	_ = uint(windows.ACCESS_ALLOWED_ACE_TYPE - windowsAccessAllowedACEType)
	_ = uint(windowsAccessDeniedACEType - windows.ACCESS_DENIED_ACE_TYPE)
	_ = uint(windows.ACCESS_DENIED_ACE_TYPE - windowsAccessDeniedACEType)

	_ = uint(windowsAccessFileWriteData - windows.FILE_WRITE_DATA)
	_ = uint(windows.FILE_WRITE_DATA - windowsAccessFileWriteData)
	_ = uint(windowsAccessFileAppendData - windows.FILE_APPEND_DATA)
	_ = uint(windows.FILE_APPEND_DATA - windowsAccessFileAppendData)
	_ = uint(windowsAccessDelete - windows.DELETE)
	_ = uint(windows.DELETE - windowsAccessDelete)
	_ = uint(windowsAccessWriteDAC - windows.WRITE_DAC)
	_ = uint(windows.WRITE_DAC - windowsAccessWriteDAC)
	_ = uint(windowsAccessWriteOwner - windows.WRITE_OWNER)
	_ = uint(windows.WRITE_OWNER - windowsAccessWriteOwner)
	_ = uint(windowsAccessGenericAll - windows.GENERIC_ALL)
	_ = uint(windows.GENERIC_ALL - windowsAccessGenericAll)
	_ = uint(windowsAccessGenericWrite - windows.GENERIC_WRITE)
	_ = uint(windows.GENERIC_WRITE - windowsAccessGenericWrite)
)

func systemDNSConfig() dnsConfig {
	return dnsConfig{servers: systemDNSServers(), trustAD: false}
}

// systemDNSServers reads DNS servers of operational adapters via
// GetAdaptersAddresses (pure Go, no Cgo), preserving IPv6 link-local ScopeId zones
// and deduplicating repeated adapter DNS addresses before the 3-server cap.
func systemDNSServers() []string {
	size := uint32(15000)
	for range 3 {
		if size == 0 {
			return nil
		}
		buf := make([]byte, size)
		addrs := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, addrs, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil
		}
		var servers []string
		for a := addrs; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if srv, ok := formatWindowsSocketAddressDNS(d.Address); ok && !slices.Contains(servers, srv) {
					servers = append(servers, srv)
				}
			}
		}
		return servers
	}
	return nil
}

func formatWindowsSocketAddressDNS(sockAddr windows.SocketAddress) (string, bool) {
	if sockAddr.Sockaddr == nil || sockAddr.SockaddrLength <= 0 ||
		uintptr(sockAddr.SockaddrLength) < unsafe.Sizeof(sockAddr.Sockaddr.Addr.Family) {
		return "", false
	}
	switch sockAddr.Sockaddr.Addr.Family {
	case windows.AF_INET:
		if uintptr(sockAddr.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet4{}) {
			return "", false
		}
		sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sockAddr.Sockaddr))
		addr := netip.AddrFrom4(sa4.Addr)
		if !addr.IsValid() || addr.IsUnspecified() {
			return "", false
		}
		return net.JoinHostPort(addr.String(), "53"), true
	case windows.AF_INET6:
		if uintptr(sockAddr.SockaddrLength) < unsafe.Sizeof(windows.RawSockaddrInet6{}) {
			return "", false
		}
		sa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(sockAddr.Sockaddr))
		return formatWindowsDNSServerIPv6(sa6.Addr, sa6.Scope_id)
	default:
		return "", false
	}
}

func defaultGlobalKnownHostsFiles() []string {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		programData = `C:\ProgramData`
	}
	candidate, ok := resolveSecureWindowsGlobalKnownHostsPath(programData)
	if !ok {
		return nil
	}
	return []string{candidate}
}

func resolveSecureWindowsGlobalKnownHostsPath(programData string) (string, bool) {
	cleanedProgramData := filepath.Clean(programData)
	if cleanedProgramData == "" || !filepath.IsAbs(cleanedProgramData) {
		return "", false
	}
	pdAttrs, ok := getWindowsFileAttributesNoFollow(cleanedProgramData)
	if !ok || !evaluateWindowsAttributes(pdAttrs, true) {
		return "", false
	}
	sshDir := filepath.Join(cleanedProgramData, "ssh")
	candidate := filepath.Join(sshDir, "ssh_known_hosts")
	currSID, _ := currentWindowsProcessUserSID()
	if !isSecureWindowsSystemSSHObject(sshDir, true, currSID) {
		return "", false
	}
	if !isSecureWindowsSystemSSHObject(candidate, false, currSID) {
		return "", false
	}
	return candidate, true
}

// isSecureWindowsGlobalKnownHostsFile mirrors Win32-OpenSSH file permission
// checks without following reparse points: the ancestor directory, parent
// directory (%ProgramData%\ssh), and file (%ProgramData%\ssh\ssh_known_hosts)
// must be free of reparse points, and both the parent directory and target file
// must be owned by SYSTEM, Administrators, or the current user with every
// write/delete/DACL/owner allow ACE restricted to that same trusted allowlist.
func isSecureWindowsGlobalKnownHostsFile(path string) bool {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || !filepath.IsAbs(cleaned) {
		return false
	}
	parentDir := filepath.Dir(cleaned)
	if parentDir == "" || parentDir == cleaned {
		return false
	}
	if grandParent := filepath.Dir(parentDir); grandParent != "" && grandParent != parentDir {
		gpAttrs, ok := getWindowsFileAttributesNoFollow(grandParent)
		if !ok || !evaluateWindowsAttributes(gpAttrs, true) {
			return false
		}
	}
	currSID, _ := currentWindowsProcessUserSID()
	if !isSecureWindowsSystemSSHObject(parentDir, true, currSID) {
		return false
	}
	return isSecureWindowsSystemSSHObject(cleaned, false, currSID)
}

func getWindowsFileAttributesNoFollow(path string) (uint32, bool) {
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

func isSecureWindowsSystemSSHObject(path string, expectDir bool, currSID *windows.SID) bool {
	attrs, ok := getWindowsFileAttributesNoFollow(path)
	if !ok || !evaluateWindowsAttributes(attrs, expectDir) {
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
	if !isSecureWindowsSecurityDescriptor(attrs, expectDir, sd, currSID) {
		return false
	}
	attrsAfter, ok := getWindowsFileAttributesNoFollow(path)
	return ok && evaluateWindowsAttributes(attrsAfter, expectDir)
}

func isSecureWindowsSecurityDescriptor(
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
	ownerTrusted := isTrustedWindowsPrincipalSID(owner, currSID)
	if !ownerTrusted {
		return false
	}
	dacl, _, err := sd.DACL()
	// A nil DACL on Windows means unrestricted full access to Everyone; reject.
	if err != nil || dacl == nil {
		return false
	}
	aces, ok := parseWindowsACL(dacl, currSID)
	if !ok {
		return false
	}
	return evaluateWindowsObjectSecurity(attrs, expectDir, ownerTrusted, true, aces)
}

func parseWindowsACL(dacl *windows.ACL, currSID *windows.SID) ([]windowsParsedACE, bool) {
	if dacl == nil {
		return nil, false
	}
	aces := make([]windowsParsedACE, 0, dacl.AceCount)
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return nil, false
		}
		if uintptr(ace.Header.AceSize) < unsafe.Sizeof(windows.ACE_HEADER{}) {
			return nil, false
		}
		parsed := windowsParsedACE{
			aceType:  ace.Header.AceType,
			aceFlags: ace.Header.AceFlags,
		}
		if parsed.aceFlags&windowsInheritOnlyACEFlag == 0 && isStandardLayoutWindowsAllowACEType(parsed.aceType) {
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
			parsed.mask = uint32(ace.Mask)
			parsed.sidValid = true
			parsed.sidTrusted = isTrustedWindowsPrincipalSID(aceSID, currSID)
		}
		aces = append(aces, parsed)
	}
	return aces, true
}

func currentWindowsProcessUserSID() (*windows.SID, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return nil, err
	}
	defer func() { _ = tok.Close() }()
	tu, err := tok.GetTokenUser()
	if err != nil || tu == nil || tu.User.Sid == nil {
		return nil, errors.New("empty process token user SID")
	}
	return tu.User.Sid.Copy()
}

func isTrustedWindowsPrincipalSID(sid, currentUserSID *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return currentUserSID != nil && currentUserSID.IsValid() && sid.Equals(currentUserSID)
}
