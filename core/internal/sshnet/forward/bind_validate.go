package forward

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

func validateLocalTCPBind(raw string, allowGateway bool) (string, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", fmt.Errorf("%w: 非法本地 TCP 绑定地址 %q: %w", ports.ErrInvalidArgument, raw, err)
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return "", fmt.Errorf("%w: 非法本地 TCP 绑定端口 %q: %w", ports.ErrInvalidArgument, portStr, err)
	}
	if host == "*" {
		host = ""
	}
	if !allowGateway {
		if err := checkLoopbackBindHost(host, raw); err != nil {
			return "", err
		}
	}
	return net.JoinHostPort(host, portStr), nil
}

// verifyBoundLoopback 在真实内核绑定完成后二次核验实际监听 IP 必为回环地址，
// 防止 /etc/hosts 污染将 "localhost" 解析到非回环网卡从而绕过 GatewayPorts=no。
func verifyBoundLoopback(ln net.Listener) error {
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("%w: 实际绑定地址 %v 非回环地址（需显式开启 GatewayPorts）", ports.ErrPermissionDenied, ln.Addr())
	}
	return nil
}

func validateRemoteTCPBind(raw string) error {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return fmt.Errorf("%w: 非法远端 TCP 绑定地址 %q: %w", ports.ErrInvalidArgument, raw, err)
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return fmt.Errorf("%w: 非法远端 TCP 绑定端口 %q: %w", ports.ErrInvalidArgument, portStr, err)
	}
	if host != "" && host != "*" {
		if _, pErr := netaddr.ParseCanonicalHost(host); pErr != nil {
			return fmt.Errorf("%w: 非法远端绑定主机 %q: %w", ports.ErrInvalidArgument, host, pErr)
		}
	}
	return nil
}

func parseTCPBindPort(raw string) (uint16, error) {
	if raw == "" || strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
		return 0, ports.ErrInvalidArgument
	}
	v, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(v), nil
}

func checkLoopbackBindHost(host, raw string) error {
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return fmt.Errorf("%w: 默认禁止绑定非回环本地地址 %q（需显式开启 GatewayPorts）", ports.ErrPermissionDenied, raw)
	}
	return nil
}

func mapUnixSlotErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, osfs.ErrSlotOccupied) {
		return fmt.Errorf("%w: %w", ports.ErrAlreadyExists, err)
	}
	if errors.Is(err, osfs.ErrInvalidControlPath) || errors.Is(err, osfs.ErrControlPathTooLong) || errors.Is(err, osfs.ErrNotSocket) {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	return err
}
