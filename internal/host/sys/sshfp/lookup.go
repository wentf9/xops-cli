package sshfp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/sys"
)

type dnsSystemConfig struct {
	servers []string
	trustAD bool
}

// Spec 是构造本机 SystemLookup（ports.SSHFPLookupPort）的显式入参规格（非持久化 DTO）。
type Spec struct {
	// Servers 可选显式指定 DNS 服务器列表（host:port 或纯 IP，默认 53 端口）；留空时按平台读取本机 DNS 配置。
	Servers []string
	// TrustAD 仅在显式配置 Servers 时生效，声明所连解析器是否经过本地可信 DNSSEC 校验（零值 false 失败关闭）。
	TrustAD bool
	// OperatorFS 为 Unix 读取 /etc/resolv.conf 注入的只读文件系统端口；nil 时默认使用 osfs.NewOperatorReadFS()。
	OperatorFS ports.OperatorReadFS
	// Entropy 为 DNS 事务 ID 生成注入的显式熵源；nil 时默认使用 sys.NewCryptoEntropy()。
	Entropy ports.Entropy
	// PerTryTimeout 可选单次 DNS 尝试超时时长；未设置时默认 2s。
	PerTryTimeout algebraic.Option[algebraic.Duration]
}

// SystemLookup 实现 ports.SSHFPLookupPort，执行带 EDNS0（DO=1）与 TCP 截断回退的 SSHFP 查询；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SystemLookup struct {
	servers    []string
	trustAD    bool
	opFS       ports.OperatorReadFS
	entropy    ports.Entropy
	perTryWait time.Duration
	valid      bool
}

// NewSystemLookup 校验显式服务器地址与超时规格并构造可用的 SSHFP DNS 查询适配器。
func NewSystemLookup(spec Spec) (*SystemLookup, error) {
	servers, err := normalizeExplicitServers(spec.Servers)
	if err != nil {
		return nil, err
	}
	wait := defaultPerTryWait
	if d, ok := spec.PerTryTimeout.Get(); ok {
		if !d.IsPositive() {
			return nil, fmt.Errorf("%w: PerTryTimeout 必须大于 0", ports.ErrInvalidArgument)
		}
		wait = d.Std()
	}
	opFS := spec.OperatorFS
	if opFS == nil {
		opFS = osfs.NewOperatorReadFS()
	}
	ent := spec.Entropy
	if ent == nil {
		ent = sys.NewCryptoEntropy()
	}
	return &SystemLookup{
		servers:    servers,
		trustAD:    spec.TrustAD,
		opFS:       opFS,
		entropy:    ent,
		perTryWait: wait,
		valid:      true,
	}, nil
}

// LookupSSHFP 查询指定规范主机的 DNS SSHFP 记录；IP 字面量按 RFC 4255 直接返回空切片且无错误。
func (l *SystemLookup) LookupSSHFP(ctx context.Context, host netaddr.CanonicalHost) ([]ports.SSHFPRecord, error) {
	if err := l.checkArgs(ctx, host); err != nil {
		return nil, err
	}
	if host.IsIP() {
		return nil, nil
	}
	cfg, err := l.resolveDNSConfig(ctx)
	if err != nil {
		return nil, err
	}
	txid, err := l.nextTXID()
	if err != nil {
		return nil, err
	}
	query, err := buildSSHFPQuery(txid, host.String())
	if err != nil {
		return nil, err
	}
	return l.queryServers(ctx, cfg, txid, host.String(), query)
}

func (l *SystemLookup) checkArgs(ctx context.Context, host netaddr.CanonicalHost) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || !l.valid {
		return fmt.Errorf("%w: SystemLookup 未初始化", ports.ErrInvalidArgument)
	}
	if !host.IsValid() {
		return fmt.Errorf("%w: CanonicalHost 无效", ports.ErrInvalidArgument)
	}
	return nil
}

func (l *SystemLookup) resolveDNSConfig(ctx context.Context) (dnsSystemConfig, error) {
	if len(l.servers) > 0 {
		return dnsSystemConfig{servers: l.servers, trustAD: l.trustAD}, nil
	}
	return loadSystemDNSConfigOS(ctx, l.opFS)
}

func (l *SystemLookup) nextTXID() (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(l.entropy, raw[:]); err != nil {
		return 0, fmt.Errorf("%w: %w", ports.ErrEntropyShortRead, err)
	}
	return binary.BigEndian.Uint16(raw[:]), nil
}

func (l *SystemLookup) queryServers(ctx context.Context, cfg dnsSystemConfig, txid uint16, qname string, query []byte) ([]ports.SSHFPRecord, error) {
	var lastErr error
	for _, srv := range cfg.servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		msg, err := l.exchangeServer(ctx, srv, txid, qname, query)
		if err != nil {
			if cErr := ctx.Err(); cErr != nil {
				return nil, cErr
			}
			lastErr = err
			continue
		}
		if msg.rcode == dnsRcodeNXDomain {
			return nil, ports.ErrNotFound
		}
		if msg.rcode != dnsRcodeNoError {
			lastErr = fmt.Errorf("DNS 服务器 %s 返回错误码 RCODE=%d", srv, msg.rcode)
			continue
		}
		return extractSSHFPRecords(msg, qname, msg.ad && cfg.trustAD)
	}
	if lastErr == nil {
		return nil, fmt.Errorf("%w: 未配置可用 DNS 服务器", ports.ErrNotFound)
	}
	return nil, lastErr
}

func (l *SystemLookup) exchangeServer(ctx context.Context, server string, txid uint16, qname string, query []byte) (parsedDNSMessage, error) {
	tryCtx, cancel := context.WithTimeout(ctx, l.perTryWait)
	defer cancel()

	rawUDP, err := exchangeUDP(tryCtx, server, query)
	if err != nil {
		return parsedDNSMessage{}, err
	}
	msg, err := parseDNSResponse(rawUDP, txid, qname)
	if err != nil {
		return parsedDNSMessage{}, err
	}
	if !msg.truncated {
		return msg, nil
	}
	rawTCP, err := exchangeTCP(tryCtx, server, query)
	if err != nil {
		return parsedDNSMessage{}, err
	}
	return parseDNSResponse(rawTCP, txid, qname)
}

func exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	defer func() { _ = conn.Close() }()
	// 仅通过 context.AfterFunc 关闭连接以响应取消与截止时间，避免 netpoller SetDeadline 与 context 定时器竞态先报 i/o timeout。
	defer bindContextClose(ctx, conn)()
	if _, err := conn.Write(query); err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	buf := make([]byte, dnsEDNSUDPPayload+64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	defer func() { _ = conn.Close() }()
	defer bindContextClose(ctx, conn)()

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < dnsHeaderBytes || respLen > maxDNSTCPMessageLen {
		return nil, fmt.Errorf("%w: DNS TCP 应答帧长度非法 (%d)", ports.ErrCorruptData, respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, mapCancelOrErr(ctx, err)
	}
	return resp, nil
}

func bindContextClose(ctx context.Context, conn net.Conn) func() {
	afterDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(afterDone)
		_ = conn.Close()
	})
	return func() {
		if !stop() {
			<-afterDone
		}
	}
}

func mapCancelOrErr(ctx context.Context, err error) error {
	if cErr := ctx.Err(); cErr != nil {
		return cErr
	}
	return err
}

func normalizeExplicitServers(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		hp, err := normalizeServerAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, hp)
	}
	return out, nil
}

func normalizeServerAddr(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: DNS 服务器地址不能为空", ports.ErrInvalidArgument)
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return net.JoinHostPort(addr.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return "", fmt.Errorf("%w: 非法 DNS 服务器地址 %q", ports.ErrInvalidArgument, raw)
	}
	return net.JoinHostPort(host, port), nil
}

// ParseResolvConf 解析 POSIX /etc/resolv.conf 文本，提取最多 3 个规范 nameserver 与 options trust-ad 标志。
func ParseResolvConf(raw []byte) (servers []string, trustAD bool) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	seen := make(map[string]bool)
	for sc.Scan() {
		fields := strings.Fields(stripResolvComment(sc.Text()))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			servers = appendResolvNameserver(servers, seen, fields[1])
		case "options":
			if containsTrustADOption(fields[1:]) {
				trustAD = true
			}
		}
	}
	return servers, trustAD
}

func appendResolvNameserver(servers []string, seen map[string]bool, rawIP string) []string {
	if len(servers) >= maxDNSServers {
		return servers
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return servers
	}
	hp := net.JoinHostPort(addr.Unmap().String(), "53")
	if seen[hp] {
		return servers
	}
	seen[hp] = true
	return append(servers, hp)
}

func containsTrustADOption(opts []string) bool {
	for _, opt := range opts {
		if opt == "trust-ad" {
			return true
		}
	}
	return false
}

func stripResolvComment(line string) string {
	if idx := strings.IndexAny(line, "#;"); idx >= 0 {
		return line[:idx]
	}
	return line
}
