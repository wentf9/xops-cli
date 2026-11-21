//go:build windows

package sshenv

import (
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"unsafe"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
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
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return nil
	}
	programData = strings.TrimSpace(programData)
	if programData == "" || !filepath.IsAbs(programData) {
		return nil
	}
	candidate, ok := resolveSecureWindowsGlobalKnownHostsPath(programData)
	if !ok {
		return nil
	}
	return []string{candidate}
}

func resolveSecureWindowsGlobalKnownHostsPath(programData string) (string, bool) {
	trimmed := strings.TrimSpace(programData)
	if trimmed == "" {
		return "", false
	}
	cleanedProgramData := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleanedProgramData) {
		return "", false
	}
	if !isSecureWindowsSystemAncestorDir(cleanedProgramData) {
		return "", false
	}
	sshDir := filepath.Join(cleanedProgramData, "ssh")
	candidate := filepath.Join(sshDir, "ssh_known_hosts")
	if !isSecureWindowsSystemGlobalSSHObject(sshDir, true) {
		return "", false
	}
	if !isSecureWindowsSystemGlobalSSHObject(candidate, false) {
		return "", false
	}
	return candidate, true
}

// isSecureWindowsGlobalKnownHostsFile enforces strict system-global trust
// without following reparse points: the ancestor directory (e.g. %ProgramData%)
// must be a non-reparse directory owned by SYSTEM or Administrators without
// destructive/takeover rights for untrusted principals, and both the parent
// directory (%ProgramData%\ssh) and target file (%ProgramData%\ssh\ssh_known_hosts)
// must be non-reparse objects owned strictly by SYSTEM or Administrators with
// every write/delete/DACL/owner allow ACE restricted to SYSTEM or Administrators
// (never trusting the current non-admin user SID).
func isSecureWindowsGlobalKnownHostsFile(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}
	cleaned := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleaned) {
		return false
	}
	parentDir := filepath.Dir(cleaned)
	if parentDir == "" || parentDir == cleaned {
		return false
	}
	if grandParent := filepath.Dir(parentDir); grandParent != "" && grandParent != parentDir {
		if !isSecureWindowsSystemAncestorDir(grandParent) {
			return false
		}
	}
	if !isSecureWindowsSystemGlobalSSHObject(parentDir, true) {
		return false
	}
	return isSecureWindowsSystemGlobalSSHObject(cleaned, false)
}

func isSecureWindowsSystemAncestorDir(path string) bool {
	return winsec.IsSecureSystemAncestorDir(path)
}

func isSecureWindowsSystemGlobalSSHObject(path string, expectDir bool) bool {
	return winsec.IsSecureSystemGlobalSSHObject(path, expectDir)
}

func parseWindowsACL(dacl *windows.ACL, currSID *windows.SID) ([]windowsParsedACE, bool) {
	return winsec.ParseACL(dacl, currSID)
}

func currentWindowsProcessUserSID() (*windows.SID, error) {
	return winsec.CurrentProcessUserSID()
}

func isTrustedWindowsPrincipalSID(sid, currentUserSID *windows.SID) bool {
	return winsec.IsTrustedPrincipalSID(sid, currentUserSID)
}
