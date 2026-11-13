//go:build windows

package sshenv

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemDNSServers reads DNS servers of operational adapters via
// GetAdaptersAddresses (pure Go, no Cgo).
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
				ip := d.Address.IP()
				if ip == nil || ip.IsUnspecified() {
					continue
				}
				// Skip IPv6 site-local "fec0::" defaults Windows reports when unconfigured.
				if ip.To4() == nil && ip[0] == 0xfe && ip[1] == 0xc0 {
					continue
				}
				servers = append(servers, net.JoinHostPort(ip.String(), "53"))
			}
		}
		return servers
	}
	return nil
}

func defaultGlobalKnownHostsFiles() []string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return []string{filepath.Join(programData, "ssh", "ssh_known_hosts")}
}
