package forward

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
)

func validateLocalTCPBind(raw string, allowGateway bool) (string, error) {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "local TCP bind address"), domi18n.BoundStr("value", raw))
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return "", domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "local TCP bind port"), domi18n.BoundStr("value", portStr))
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
		addrStr := "<nil>"
		if ln.Addr() != nil {
			addrStr = ln.Addr().String()
		}
		return domi18n.EF(ports.ErrPermissionDenied, domi18n.KeyForwardNonLoopback, domi18n.BoundStr("addr", addrStr))
	}
	return nil
}

func validateRemoteTCPBind(raw string) error {
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		return domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "remote TCP bind address"), domi18n.BoundStr("value", raw))
	}
	if _, err := parseTCPBindPort(portStr); err != nil {
		return domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "remote TCP bind port"), domi18n.BoundStr("value", portStr))
	}
	if host != "" && host != "*" {
		if _, pErr := netaddr.ParseCanonicalHost(host); pErr != nil {
			return domi18n.WrapS(ports.ErrInvalidArgument, pErr, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "remote bind host"), domi18n.BoundStr("value", host))
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
		return domi18n.EF(ports.ErrPermissionDenied, domi18n.KeyForwardNonLoopback, domi18n.BoundStr("addr", raw))
	}
	return nil
}

func mapUnixSlotErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, osfs.ErrSlotOccupied) {
		return domi18n.WrapSentinel(ports.ErrAlreadyExists, err)
	}
	if errors.Is(err, osfs.ErrInvalidControlPath) || errors.Is(err, osfs.ErrControlPathTooLong) || errors.Is(err, osfs.ErrNotSocket) {
		return domi18n.WrapSentinel(ports.ErrInvalidArgument, err)
	}
	return err
}
