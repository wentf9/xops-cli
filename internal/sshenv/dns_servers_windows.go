//go:build windows

package sshenv

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func systemDNSConfig() dnsConfig {
	return dnsConfig{servers: systemDNSServers(), trustAD: false}
}

// systemDNSServers reads DNS servers of operational adapters via
// GetAdaptersAddresses (pure Go, no Cgo), preserving IPv6 link-local ScopeId zones.
func systemDNSServers() []string {
	size := uint32(15000)
	for range 3 {
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
				if srv, ok := formatWindowsSocketAddressDNS(d.Address); ok {
					servers = append(servers, srv)
				}
			}
		}
		return servers
	}
	return nil
}

func formatWindowsSocketAddressDNS(sockAddr windows.SocketAddress) (string, bool) {
	if sockAddr.Sockaddr == nil {
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
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	candidate := filepath.Join(programData, "ssh", "ssh_known_hosts")
	if !isSecureWindowsGlobalKnownHostsFile(candidate) {
		return nil
	}
	return []string{candidate}
}

const (
	windowsAccessAllowedCallbackAceType = 9
	windowsInsecureKnownHostsWriteMask  = windows.ACCESS_MASK(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)
)

// isSecureWindowsGlobalKnownHostsFile mirrors Win32-OpenSSH file permission
// checks: %ProgramData%\ssh\ssh_known_hosts is trusted only if owned by SYSTEM,
// Administrators, or the current user AND no allow ACE grants write/DACL/owner
// permissions to Everyone, Builtin\Users, or Authenticated Users.
func isSecureWindowsGlobalKnownHostsFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
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
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}
	currSID, _ := currentWindowsProcessUserSID()
	if !isTrustedWindowsPrincipalSID(owner, currSID) {
		return false
	}
	dacl, _, err := sd.DACL()
	// A nil DACL on Windows means unrestricted full access to Everyone; reject.
	if err != nil || dacl == nil {
		return false
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
			ace.Header.AceType != windowsAccessAllowedCallbackAceType {
			continue
		}
		if ace.Mask&windowsInsecureKnownHostsWriteMask == 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if isBroadWindowsPrincipalSID(aceSID) {
			return false
		}
	}
	return true
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
	return tu.User.Sid, nil
}

func isTrustedWindowsPrincipalSID(sid, currentUserSID *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}
	return currentUserSID != nil && sid.Equals(currentUserSID)
}

func isBroadWindowsPrincipalSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	return sid.IsWellKnown(windows.WinWorldSid) ||
		sid.IsWellKnown(windows.WinBuiltinUsersSid) ||
		sid.IsWellKnown(windows.WinAuthenticatedUserSid)
}
