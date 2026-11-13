//go:build !windows

package sshenv

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

const resolvConfPath = "/etc/resolv.conf"

func systemDNSServers() []string {
	return parseResolvConf(resolvConfPath)
}

func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"127.0.0.1:53"}
	}
	defer func() { _ = f.Close() }()
	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := fields[1]
		if _, err := netip.ParseAddr(host); err != nil {
			continue
		}
		servers = append(servers, net.JoinHostPort(host, "53"))
	}
	if len(servers) == 0 {
		return []string{"127.0.0.1:53"}
	}
	return servers
}

func defaultGlobalKnownHostsFiles() []string {
	return []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}
}
