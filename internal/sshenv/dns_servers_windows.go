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
	return winsec.GetFileAttributesNoFollow(path)
}

func isSecureWindowsSystemSSHObject(path string, expectDir bool, currSID *windows.SID) bool {
	return winsec.IsSecureSystemSSHObject(path, expectDir, currSID)
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
