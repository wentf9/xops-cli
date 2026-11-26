//go:build windows

package sshfp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
)

func loadSystemDNSConfigOS(_ context.Context, _ ports.OperatorReadFS) (dnsSystemConfig, error) {
	flags := uint32(windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME)
	buf, err := queryAdaptersBuffer(flags)
	if err != nil {
		return dnsSystemConfig{}, fmt.Errorf("查询 Windows 网卡 DNS 服务器列表失败: %w", err)
	}
	servers := collectWindowsDNSServers((*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])))
	if len(servers) == 0 {
		return dnsSystemConfig{}, fmt.Errorf("%w: 未发现可用本机 DNS 服务器", ports.ErrNotFound)
	}
	// Windows 本地 DNS 桩默认不透传上游 DNSSEC AD 信任标记，保持 TrustAD=false 失败关闭。
	return dnsSystemConfig{servers: servers, trustAD: false}, nil
}

func queryAdaptersBuffer(flags uint32) ([]byte, error) {
	bufLen := uint32(15000)
	buf := make([]byte, bufLen)
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &bufLen)
	if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
		buf = make([]byte, bufLen)
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &bufLen)
	}
	return buf, err
}

func collectWindowsDNSServers(head *windows.IpAdapterAddresses) []string {
	var servers []string
	seen := make(map[string]bool)
	for cur := head; cur != nil && len(servers) < maxDNSServers; cur = cur.Next {
		if cur.OperStatus != windows.IfOperStatusUp {
			continue
		}
		servers = appendAdapterDNSServers(servers, seen, cur.FirstDnsServerAddress)
	}
	return servers
}

func appendAdapterDNSServers(servers []string, seen map[string]bool, head *windows.IpAdapterDnsServerAdapter) []string {
	for dns := head; dns != nil && len(servers) < maxDNSServers; dns = dns.Next {
		addr, ok := parseWindowsDNSAddr(&dns.Address)
		if !ok {
			continue
		}
		hp := net.JoinHostPort(addr.String(), "53")
		if !seen[hp] {
			seen[hp] = true
			servers = append(servers, hp)
		}
	}
	return servers
}

func parseWindowsDNSAddr(sa *windows.SocketAddress) (netip.Addr, bool) {
	ip := sa.IP()
	if ip == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	// 跳过 Windows 未配置 IPv6 DNS 时自动填充的 fec0:0:0:ffff::1..3 站点本地伪地址。
	if addr.Is6() && isWindowsSiteLocalFEC0(addr) {
		return netip.Addr{}, false
	}
	return addr, true
}

func isWindowsSiteLocalFEC0(addr netip.Addr) bool {
	b := addr.As16()
	return b[0] == 0xfe && b[1] == 0xc0 && b[2] == 0x00 && b[3] == 0x00 && b[4] == 0x00 && b[5] == 0x00 && b[6] == 0xff && b[7] == 0xff
}
