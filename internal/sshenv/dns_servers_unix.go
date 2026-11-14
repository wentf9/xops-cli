//go:build !windows

package sshenv

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
)

const resolvConfPath = "/etc/resolv.conf"

func systemDNSConfig() dnsConfig {
	return parseResolvConf(resolvConfPath)
}

func parseResolvConf(path string) dnsConfig {
	f, err := os.Open(path)
	if err != nil {
		return dnsConfig{servers: []string{"127.0.0.1:53"}}
	}
	defer func() { _ = f.Close() }()

	var cfg dnsConfig
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if cut := strings.IndexAny(line, "#;"); cut >= 0 {
			line = line[:cut]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			addr, err := netip.ParseAddr(fields[1])
			if err != nil {
				continue
			}
			srv := net.JoinHostPort(addr.String(), "53")
			if !slices.Contains(cfg.servers, srv) {
				cfg.servers = append(cfg.servers, srv)
			}
		case "options":
			for _, opt := range fields[1:] {
				if opt == "trust-ad" {
					cfg.trustAD = true
				}
			}
		}
	}
	if len(cfg.servers) == 0 {
		cfg.servers = []string{"127.0.0.1:53"}
	}
	return cfg
}

func defaultGlobalKnownHostsFiles() []string {
	return []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}
}
