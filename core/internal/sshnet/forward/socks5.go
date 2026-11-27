package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

// RFC 1928 SOCKS5 协议常量。
const (
	socks5Version byte = 0x05

	socks5MethodNoAuth       byte = 0x00
	socks5MethodNoAcceptable byte = 0xFF

	socks5CmdConnect byte = 0x01

	socks5AtypIPv4   byte = 0x01
	socks5AtypDomain byte = 0x03
	socks5AtypIPv6   byte = 0x04

	socks5RepSucceeded       byte = 0x00
	socks5RepGeneralFailure  byte = 0x01
	socks5RepHostUnreachable byte = 0x04
	socks5RepConnRefused     byte = 0x05
	socks5RepCmdUnsupported  byte = 0x07
	socks5RepAddrUnsupported byte = 0x08
)

// serveSOCKS5Conn 执行严格 RFC 1928 SOCKS5 握手并通过上游 SSH direct-tcpip 建立零 DNS 泄露隧道。
// 握手阶段受 chanconn.RunWithAbortWatchdog 监督，确保慢速或停滞客户端在 Handle.Close() 时 O(1) 解阻。
func (f *Forwarder) serveSOCKS5Conn(ctx context.Context, client net.Conn, transport ports.TunnelTransport) error {
	target, err := f.handshakeSOCKS5(ctx, client)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, f.socksTimeout)
	defer cancel()
	remote, err := transport.DialTCP(dialCtx, target)
	if err != nil {
		_ = writeSOCKS5Reply(client, mapDialErrToSOCKS5Rep(err))
		return err
	}
	defer func() { _ = remote.Close() }()

	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = client.Close() }, func() error {
		return writeSOCKS5Reply(client, socks5RepSucceeded)
	}); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	return bridgeStreams(ctx, client, remote)
}

func (f *Forwarder) handshakeSOCKS5(ctx context.Context, client net.Conn) (netaddr.HostPort, error) {
	// net.Conn.SetDeadline 由 OS 内核按系统墙钟解释，绝不使用虚拟时钟偏移。
	dl := time.Now().Add(f.socksTimeout)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		dl = ctxDL
	}
	_ = client.SetDeadline(dl)
	var target netaddr.HostPort
	err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = client.Close() }, func() error {
		if err := negotiateSOCKS5Method(client); err != nil {
			return err
		}
		hp, err := readSOCKS5ConnectTarget(client)
		if err != nil {
			return err
		}
		target = hp
		return nil
	})
	if err != nil {
		return zeroVal[netaddr.HostPort](), err
	}
	return target, nil
}

func negotiateSOCKS5Method(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != socks5Version || hdr[1] == 0 {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyForwardSOCKS5Header)
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == socks5MethodNoAuth {
			_, err := conn.Write([]byte{socks5Version, socks5MethodNoAuth})
			return err
		}
	}
	_, _ = conn.Write([]byte{socks5Version, socks5MethodNoAcceptable})
	return domi18n.EF(ports.ErrPermissionDenied, domi18n.KeyForwardSOCKS5NoAuth)
}

// readSOCKS5ConnectTarget 解析 SOCKS5 请求并强制只接受 CONNECT 命令（拒绝 BIND 与 UDP ASSOCIATE）；
// 对 DOMAINNAME（0x03）严禁本机 DNS 解析，直接构造 netaddr.HostPort 透传至远端 SSH 服务端。
func readSOCKS5ConnectTarget(conn net.Conn) (netaddr.HostPort, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return zeroVal[netaddr.HostPort](), err
	}
	if hdr[0] != socks5Version || hdr[2] != 0x00 {
		_ = writeSOCKS5Reply(conn, socks5RepGeneralFailure)
		return zeroVal[netaddr.HostPort](), domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyForwardSOCKS5Header)
	}
	if hdr[1] != socks5CmdConnect {
		_ = writeSOCKS5Reply(conn, socks5RepCmdUnsupported)
		return zeroVal[netaddr.HostPort](), domi18n.EF(ports.ErrUnsupported, domi18n.KeyForwardSOCKS5CmdReject, domi18n.Str("cmd", fmt.Sprintf("%#x", hdr[1])))
	}
	host, repCode, err := readSOCKS5Address(conn, hdr[3])
	if err != nil {
		_ = writeSOCKS5Reply(conn, repCode)
		return zeroVal[netaddr.HostPort](), err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return zeroVal[netaddr.HostPort](), err
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	hp, err := netaddr.NewHostPort(host, port)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5RepAddrUnsupported)
		return zeroVal[netaddr.HostPort](), domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "socks5_port"))
	}
	return hp, nil
}

func readSOCKS5Address(conn net.Conn, atyp byte) (netaddr.CanonicalHost, byte, error) {
	switch atyp {
	case socks5AtypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return zeroVal[netaddr.CanonicalHost](), socks5RepGeneralFailure, err
		}
		h, err := netaddr.CanonicalHostFromAddr(netip.AddrFrom4(raw))
		return h, socks5RepAddrUnsupported, err
	case socks5AtypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(conn, raw[:]); err != nil {
			return zeroVal[netaddr.CanonicalHost](), socks5RepGeneralFailure, err
		}
		h, err := netaddr.CanonicalHostFromAddr(netip.AddrFrom16(raw))
		return h, socks5RepAddrUnsupported, err
	case socks5AtypDomain:
		return readSOCKS5Domain(conn)
	default:
		return zeroVal[netaddr.CanonicalHost](), socks5RepAddrUnsupported, domi18n.EF(ports.ErrUnsupported, domi18n.KeyForwardSOCKS5ATYP, domi18n.Str("atyp", fmt.Sprintf("%#x", atyp)))
	}
}

func readSOCKS5Domain(conn net.Conn) (netaddr.CanonicalHost, byte, error) {
	var lenBuf [1]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return zeroVal[netaddr.CanonicalHost](), socks5RepGeneralFailure, err
	}
	if lenBuf[0] == 0 {
		return zeroVal[netaddr.CanonicalHost](), socks5RepAddrUnsupported, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "socks5_domain"))
	}
	raw := make([]byte, lenBuf[0])
	if _, err := io.ReadFull(conn, raw); err != nil {
		return zeroVal[netaddr.CanonicalHost](), socks5RepGeneralFailure, err
	}
	// 仅执行纯数学域名规范化，零 net.LookupHost 调用，确保 100% 域名解析发生在远端 SSH 出口。
	h, err := netaddr.ParseCanonicalHost(string(raw))
	if err != nil {
		return zeroVal[netaddr.CanonicalHost](), socks5RepAddrUnsupported, domi18n.WrapS(ports.ErrInvalidArgument, err, domi18n.KeyForwardSOCKS5DomainInvalid, domi18n.BoundStr("domain", string(raw)))
	}
	return h, socks5RepAddrUnsupported, nil
}

func writeSOCKS5Reply(conn net.Conn, rep byte) error {
	reply := [10]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply[:])
	return err
}

func mapDialErrToSOCKS5Rep(err error) byte {
	if errors.Is(err, ports.ErrPermissionDenied) {
		return socks5RepGeneralFailure
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return socks5RepHostUnreachable
	}
	return socks5RepConnRefused
}
