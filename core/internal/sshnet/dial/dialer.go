package dial

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

// DialHop 按不可变 HopSpec 与 Merkle HopDigest 建立单跳或多跳（经 parent.DialTCP 隧道）SSH 传输连接。
// 所有底层拨号与 SSH 握手均受 core/conc.RunScoped 取消/超时看门狗监督，多跳通道自动封装为 chanconn.WatchedConn。
func (d *Dialer) DialHop(ctx context.Context, hop plan.HopSpec, hopDigest plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if err := d.checkDialArgs(ctx, hop, hopDigest, parent); err != nil {
		return nil, err
	}
	dialCtx, cancel := withHopConnectTimeout(ctx, hop.Transport())
	defer cancel()

	sshCfg, err := d.buildClientConfig(dialCtx, hop)
	if err != nil {
		return nil, err
	}
	rawConn, err := d.dialUnderlyingConn(dialCtx, hop, parent)
	if err != nil {
		return nil, err
	}
	sshConn, chans, reqs, err := performSSHHandshake(dialCtx, rawConn, hop.Endpoint().String(), sshCfg)
	if err != nil {
		_ = rawConn.Close()
		return nil, classifyHandshakeErr(dialCtx, err)
	}
	return newTransportConn(sshConn, chans, reqs, rawConn, hopDigest, hop.Endpoint(), d.clock, d.openRemoteFS)
}

func (d *Dialer) checkDialArgs(ctx context.Context, hop plan.HopSpec, hopDigest plan.HopDigest, parent ports.TransportConn) error {
	if d == nil || !d.valid {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "Dialer"))
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !hop.IsValid() || !hopDigest.IsValid() {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "HopSpec/HopDigest"))
	}
	if parent == nil {
		if hop.HopIndex() > 0 {
			return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyDialParentRequired)
		}
		if _, isJump := hop.Transport().ProxyRoute().(*option.ProxyJumpChain); isJump {
			return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyDialParentRequired)
		}
	}
	return nil
}

func withHopConnectTimeout(ctx context.Context, tp plan.TransportPolicySpec) (context.Context, context.CancelFunc) {
	if ct, ok := tp.ConnectTimeout().Get(); ok && ct.IsPositive() {
		return context.WithTimeout(ctx, ct.Std())
	}
	return context.WithCancel(ctx)
}

func (d *Dialer) buildClientConfig(ctx context.Context, hop plan.HopSpec) (*ssh.ClientConfig, error) {
	tp := hop.Transport()
	ciphers, macs, kex, hostKeyAlgos, err := resolveSupportedSSHAlgos(tp)
	if err != nil {
		return nil, err
	}
	preferred, err := d.hostTrust.PreferredAlgorithms(ctx, hop.Endpoint(), tp.UserKnownHostsFiles())
	if err != nil {
		return nil, err
	}
	authMethods, err := d.buildAuthMethods(ctx, hop)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		Config: ssh.Config{
			Ciphers:      ciphers,
			MACs:         macs,
			KeyExchanges: kex,
		},
		User:              hop.Username().String(),
		Auth:              authMethods,
		HostKeyCallback:   d.buildHostKeyCallback(ctx, hop),
		HostKeyAlgorithms: orderHostKeyAlgorithms(hostKeyAlgos, preferred),
		ClientVersion:     d.clientVersion,
	}, nil
}

// resolveSupportedSSHAlgos 将策略求解结果与 golang.org/x/crypto/ssh 支持的算法集求有序交集；
// 保持策略优先级顺序（绝不私自注入未在策略中启用的不安全算法），任一集合交集为空均失败关闭。
func resolveSupportedSSHAlgos(tp plan.TransportPolicySpec) (ciphers, macs, kex, hostKey []string, err error) {
	sup, insec := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()
	ciphers = filterAlgorithms(tp.Ciphers(), sup.Ciphers, insec.Ciphers)
	macs = filterAlgorithms(tp.MACs(), sup.MACs, insec.MACs)
	kex = filterAlgorithms(tp.KexAlgorithms(), sup.KeyExchanges, insec.KeyExchanges)
	hostKey = filterAlgorithms(tp.HostKeyAlgos(), sup.HostKeys, insec.HostKeys)
	if len(ciphers) == 0 || len(macs) == 0 || len(kex) == 0 || len(hostKey) == 0 {
		return nil, nil, nil, nil, domi18n.EF(ports.ErrDialFailed, domi18n.KeyDialEmptyAlgoIntersect)
	}
	return ciphers, macs, kex, hostKey, nil
}

func filterAlgorithms(policy, supported, insecure []string) []string {
	out := make([]string, 0, len(policy))
	for _, algo := range policy {
		if (slices.Contains(supported, algo) || slices.Contains(insecure, algo)) && !slices.Contains(out, algo) {
			out = append(out, algo)
		}
	}
	return out
}

func (d *Dialer) dialUnderlyingConn(ctx context.Context, hop plan.HopSpec, parent ports.TransportConn) (net.Conn, error) {
	if parent != nil {
		if !parent.IsAlive() {
			return nil, domi18n.EF(ports.ErrDialFailed, domi18n.KeyDialParentRequired)
		}
		conn, err := parent.DialTCP(ctx, hop.Endpoint().HostPort())
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyDialDirectTCPIPFailed)
		}
		return conn, nil
	}
	if hop.HopIndex() > 0 {
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyDialParentRequired)
	}
	switch route := hop.Transport().ProxyRoute().(type) {
	case nil, *option.ProxyUnset, *option.ProxyDisabled:
		return d.dialDirectTCP(ctx, hop)
	case *option.ProxyCommandSpec:
		if !route.IsValid() {
			return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ProxyCommandSpec"))
		}
		return d.dialProxyCommand(ctx, hop, route)
	case *option.ProxyJumpChain:
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyDialParentRequired)
	default:
		return nil, domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonUnsupportedVariant, domi18n.Str("type", "ProxyRoute"))
	}
}

func (d *Dialer) dialDirectTCP(ctx context.Context, hop plan.HopSpec) (net.Conn, error) {
	conn, err := d.dialContext(ctx, "tcp", hop.Endpoint().String())
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyDialTCPFailed, domi18n.BoundStr("addr", hop.Endpoint().String()))
	}
	return conn, nil
}

func (d *Dialer) dialProxyCommand(ctx context.Context, hop plan.HopSpec, cmdSpec *option.ProxyCommandSpec) (net.Conn, error) {
	if d.process == nil {
		return nil, domi18n.EF(ports.ErrDialFailed, domi18n.KeyCommonMissingDep, domi18n.Str("component", "ProcessPort"))
	}
	tc := d.buildHopTokenContext(hop)
	expanded, err := option.ExpandTokens(cmdSpec.Command().String(), tc)
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyDialProxyCmdExpandFailed)
	}
	parts, err := splitProxyCommandTokens(expanded)
	if err != nil {
		return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyDialProxyCmdParseFailed)
	}
	if len(parts) == 0 {
		return nil, domi18n.EF(ports.ErrDialFailed, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "ProxyCommand"))
	}
	procSpec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command: parts[0],
		Args:    parts[1:],
	})
	if err != nil {
		return nil, domi18n.WrapSentinel(ports.ErrDialFailed, err)
	}
	conn, err := d.process.DialStdio(ctx, procSpec)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, domi18n.WrapS(ports.ErrDialFailed, err, domi18n.KeyDialProxyCmdStartFailed)
	}
	return conn, nil
}

func (d *Dialer) buildHopTokenContext(hop plan.HopSpec) option.TokenContext {
	tc := option.TokenContext{
		TargetHost:   hop.Endpoint().Host().String(),
		Port:         hop.Endpoint().Port(),
		RemoteUser:   hop.Username().String(),
		OriginalHost: hop.OriginalHost().String(),
	}
	if d.env != nil {
		if id, err := d.env.LookupLocalIdentity(); err == nil {
			tc = id.ApplyToTokenContext(tc)
		}
	}
	return tc
}

// splitProxyCommandTokens 对 ProxyCommand 整行命令执行引号感知分词：
// 支持单引号与双引号（双引号内仅转义 \" 与 \\，不破坏 Windows 反斜杠路径），未闭合引号严格失败关闭。
func splitProxyCommandTokens(raw string) ([]string, error) {
	var out []string
	for i := 0; i < len(raw); {
		if isProxySpace(raw[i]) {
			i++
			continue
		}
		tok, next, err := readProxyToken(raw, i)
		if err != nil {
			return nil, err
		}
		out, i = append(out, tok), next
	}
	return out, nil
}

func isProxySpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func readProxyToken(raw string, start int) (string, int, error) {
	var b strings.Builder
	for i := start; i < len(raw); {
		if isProxySpace(raw[i]) {
			return b.String(), i, nil
		}
		if raw[i] == '"' || raw[i] == '\'' {
			seg, next, err := scanProxyQuote(raw, i)
			if err != nil {
				return "", 0, err
			}
			b.WriteString(seg)
			i = next
			continue
		}
		b.WriteByte(raw[i])
		i++
	}
	return b.String(), len(raw), nil
}

func scanProxyQuote(raw string, start int) (string, int, error) {
	q := raw[start]
	var b strings.Builder
	for i := start + 1; i < len(raw); i++ {
		if q == '"' && raw[i] == '\\' && i+1 < len(raw) && (raw[i+1] == '"' || raw[i+1] == '\\') {
			i++
			b.WriteByte(raw[i])
			continue
		}
		if raw[i] == q {
			return b.String(), i + 1, nil
		}
		b.WriteByte(raw[i])
	}
	return "", 0, domi18n.E(domi18n.KeyDialProxyCmdUnclosedQuote)
}

// performSSHHandshake 在 core/conc.RunScoped 取消看门狗保护下执行 ssh.NewClientConn，
// 确保即使底层是无原生 SetDeadline 的 ssh.Channel 连接，取消或超时也能立即关闭 rawConn 解阻。
func performSSHHandshake(ctx context.Context, rawConn net.Conn, addr string, cfg *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	var sshConn ssh.Conn
	var chans <-chan ssh.NewChannel
	var reqs <-chan *ssh.Request
	var hsErr error
	err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = rawConn.Close() }, func() error {
		sshConn, chans, reqs, hsErr = ssh.NewClientConn(rawConn, addr, cfg)
		return nil
	})
	if hsErr != nil {
		return nil, nil, nil, hsErr
	}
	if err != nil {
		if sshConn != nil {
			_ = sshConn.Close()
		}
		return nil, nil, nil, err
	}
	if ctx.Err() != nil {
		if sshConn != nil {
			_ = sshConn.Close()
		}
		return nil, nil, nil, ctx.Err()
	}
	return sshConn, chans, reqs, nil
}

func classifyHandshakeErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, ports.ErrHostKeyMismatch) || errors.Is(err, ports.ErrHostKeyUnknown) ||
		errors.Is(err, ports.ErrHostKeyRevoked) || errors.Is(err, ports.ErrAuthFailed) ||
		errors.Is(err, ports.ErrSignerUnavailable) || errors.Is(err, ports.ErrDialFailed) {
		return err
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return domi18n.WrapSentinel(ports.ErrAuthFailed, err)
	}
	return domi18n.WrapSentinel(ports.ErrDialFailed, err)
}
