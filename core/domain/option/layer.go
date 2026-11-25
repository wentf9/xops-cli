package option

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// OptionLayer 表示四层 OpenSSH 选项总幺半群 (OptionLayer, Compose, Unset) 的不可变层值对象。
// 零值代表单位元 UnsetOptionLayer；Compose 按正交分量复合，严格满足结合律与双侧单位元律。
//
//xops:opaque
//xops:failclosed
type OptionLayer struct {
	hostName              algebraic.FirstWins[HostNameSpec]
	port                  algebraic.FirstWins[uint16]
	user                  algebraic.FirstWins[Username]
	proxy                 ProxyRoute
	control               ControlPolicy
	connectTimeout        algebraic.FirstWins[algebraic.Duration]
	serverAliveInterval   algebraic.FirstWins[algebraic.Duration]
	serverAliveCountMax   algebraic.FirstWins[uint32]
	ciphers               AlgoPolicy
	macs                  AlgoPolicy
	kexAlgorithms         AlgoPolicy
	hostKeyAlgorithms     AlgoPolicy
	identityFiles         PathList
	certificateFiles      PathList
	identitiesOnly        algebraic.FirstWins[bool]
	batchMode             algebraic.FirstWins[bool]
	strictHostKeyChecking algebraic.FirstWins[StrictHostKeyCheckingMode]
	userKnownHostsFiles   KnownHostsList
	forwardAgent          algebraic.FirstWins[bool]
	sendEnv               EnvFilter
	permitLocalCommand    algebraic.FirstWins[bool]
	localCommand          algebraic.FirstWins[SanitizedCmd]
}

// UnsetOptionLayer 返回总幺半群单位元（全未设置零值）。
func UnsetOptionLayer() OptionLayer { return OptionLayer{} }

func setFW[T any](dst *algebraic.FirstWins[T], v T, ok bool) {
	if ok {
		*dst = algebraic.NewFirstWins(v)
	}
}

// OptionLayer 不可变构造器链：所有 With* 返回新副本，绝不修改接收者。
func (l OptionLayer) WithHostName(h HostNameSpec) OptionLayer {
	setFW(&l.hostName, h, h.IsValid())
	return l
}
func (l OptionLayer) WithPort(p uint16) OptionLayer                 { setFW(&l.port, p, p != 0); return l }
func (l OptionLayer) WithUser(u Username) OptionLayer               { setFW(&l.user, u, u.IsValid()); return l }
func (l OptionLayer) WithProxyRoute(r ProxyRoute) OptionLayer       { l.proxy = r; return l }
func (l OptionLayer) WithControlPolicy(c ControlPolicy) OptionLayer { l.control = c; return l }
func (l OptionLayer) WithCiphers(p AlgoPolicy) OptionLayer          { l.ciphers = p.clone(); return l }
func (l OptionLayer) WithMACs(p AlgoPolicy) OptionLayer             { l.macs = p.clone(); return l }
func (l OptionLayer) WithKexAlgorithms(p AlgoPolicy) OptionLayer {
	l.kexAlgorithms = p.clone()
	return l
}
func (l OptionLayer) WithHostKeyAlgorithms(p AlgoPolicy) OptionLayer {
	l.hostKeyAlgorithms = p.clone()
	return l
}
func (l OptionLayer) WithIdentityFiles(p PathList) OptionLayer { l.identityFiles = p.clone(); return l }
func (l OptionLayer) WithCertificateFiles(p PathList) OptionLayer {
	l.certificateFiles = p.clone()
	return l
}
func (l OptionLayer) WithUserKnownHostsFiles(p KnownHostsList) OptionLayer {
	l.userKnownHostsFiles = p.clone()
	return l
}
func (l OptionLayer) WithSendEnv(f EnvFilter) OptionLayer { l.sendEnv = f.clone(); return l }
func (l OptionLayer) WithIdentitiesOnly(v bool) OptionLayer {
	setFW(&l.identitiesOnly, v, true)
	return l
}
func (l OptionLayer) WithBatchMode(v bool) OptionLayer    { setFW(&l.batchMode, v, true); return l }
func (l OptionLayer) WithForwardAgent(v bool) OptionLayer { setFW(&l.forwardAgent, v, true); return l }
func (l OptionLayer) WithPermitLocalCommand(v bool) OptionLayer {
	setFW(&l.permitLocalCommand, v, true)
	return l
}
func (l OptionLayer) WithConnectTimeout(d algebraic.Duration) OptionLayer {
	setFW(&l.connectTimeout, d, !d.IsNegative())
	return l
}
func (l OptionLayer) WithServerAliveInterval(d algebraic.Duration) OptionLayer {
	setFW(&l.serverAliveInterval, d, !d.IsNegative())
	return l
}
func (l OptionLayer) WithServerAliveCountMax(n uint32) OptionLayer {
	setFW(&l.serverAliveCountMax, n, true)
	return l
}
func (l OptionLayer) WithStrictHostKeyChecking(m StrictHostKeyCheckingMode) OptionLayer {
	setFW(&l.strictHostKeyChecking, m, m.String() != "")
	return l
}
func (l OptionLayer) WithLocalCommand(c SanitizedCmd) OptionLayer {
	setFW(&l.localCommand, c, c.IsValid())
	return l
}

// ApplyParsedOption 按同层自上而下 OpenSSH 语义将单条已解析选项合入当前层。
func (l OptionLayer) ApplyParsedOption(opt ParsedOption) OptionLayer {
	if !opt.valid {
		return l
	}
	if opt.key == KeySendEnv {
		out := l.clone()
		out.sendEnv = opt.layer.sendEnv.Compose(out.sendEnv)
		return out
	}
	return l.Compose(opt.layer)
}

// OptionLayer 只读访问器（容器字段返回防御性拷贝，Proxy 永不返回 nil）。
func (l OptionLayer) HostName() algebraic.Option[HostNameSpec] { return l.hostName.ToOption() }
func (l OptionLayer) Port() algebraic.Option[uint16]           { return l.port.ToOption() }
func (l OptionLayer) User() algebraic.Option[Username]         { return l.user.ToOption() }
func (l OptionLayer) Control() ControlPolicy                   { return l.control }
func (l OptionLayer) ConnectTimeout() algebraic.Option[algebraic.Duration] {
	return l.connectTimeout.ToOption()
}
func (l OptionLayer) ServerAliveInterval() algebraic.Option[algebraic.Duration] {
	return l.serverAliveInterval.ToOption()
}
func (l OptionLayer) ServerAliveCountMax() algebraic.Option[uint32] {
	return l.serverAliveCountMax.ToOption()
}
func (l OptionLayer) Ciphers() AlgoPolicy                    { return l.ciphers.clone() }
func (l OptionLayer) MACs() AlgoPolicy                       { return l.macs.clone() }
func (l OptionLayer) KexAlgorithms() AlgoPolicy              { return l.kexAlgorithms.clone() }
func (l OptionLayer) HostKeyAlgorithms() AlgoPolicy          { return l.hostKeyAlgorithms.clone() }
func (l OptionLayer) IdentityFiles() PathList                { return l.identityFiles.clone() }
func (l OptionLayer) CertificateFiles() PathList             { return l.certificateFiles.clone() }
func (l OptionLayer) IdentitiesOnly() algebraic.Option[bool] { return l.identitiesOnly.ToOption() }
func (l OptionLayer) BatchMode() algebraic.Option[bool]      { return l.batchMode.ToOption() }
func (l OptionLayer) StrictHostKeyChecking() algebraic.Option[StrictHostKeyCheckingMode] {
	return l.strictHostKeyChecking.ToOption()
}
func (l OptionLayer) UserKnownHostsFiles() KnownHostsList  { return l.userKnownHostsFiles.clone() }
func (l OptionLayer) ForwardAgent() algebraic.Option[bool] { return l.forwardAgent.ToOption() }
func (l OptionLayer) SendEnv() EnvFilter                   { return l.sendEnv.clone() }
func (l OptionLayer) PermitLocalCommand() algebraic.Option[bool] {
	return l.permitLocalCommand.ToOption()
}
func (l OptionLayer) LocalCommand() algebraic.Option[SanitizedCmd] { return l.localCommand.ToOption() }
func (l OptionLayer) IsUnset() bool                                { return l.Equal(UnsetOptionLayer()) }
func (l OptionLayer) IsZero() bool                                 { return l.IsUnset() }
func (l OptionLayer) Proxy() ProxyRoute {
	if l.proxy == nil {
		return NewProxyUnset()
	}
	return l.proxy
}

func (l OptionLayer) clone() OptionLayer {
	out := l
	out.proxy = ComposeProxyRoute(l.proxy, nil)
	out.ciphers, out.macs = l.ciphers.clone(), l.macs.clone()
	out.kexAlgorithms, out.hostKeyAlgorithms = l.kexAlgorithms.clone(), l.hostKeyAlgorithms.clone()
	out.identityFiles, out.certificateFiles = l.identityFiles.clone(), l.certificateFiles.clone()
	out.userKnownHostsFiles, out.sendEnv = l.userKnownHostsFiles.clone(), l.sendEnv.clone()
	return out
}

// Validate 校验当前层所有内部值对象的合法性。
func (l OptionLayer) Validate() error {
	if err := ValidateProxyRoute(l.proxy); err != nil {
		return err
	}
	if l.hasInvalidScalar() {
		return fmt.Errorf("%w: OptionLayer 含无效字段值", ErrInvalidOption)
	}
	if cmd, ok := l.localCommand.Get(); ok && (!cmd.IsValid() || !hasValidTemplateTokens(cmd.raw, allowedPathPercentTokens, false)) {
		return fmt.Errorf("%w: OptionLayer.LocalCommand 非法", ErrInvalidOption)
	}
	return nil
}

func (l OptionLayer) hasInvalidScalar() bool {
	return (l.port.IsSet() && l.port.OrElse(0) == 0) ||
		(l.hostName.IsSet() && !l.hostName.OrElse(HostNameSpec{}).IsValid()) ||
		(l.user.IsSet() && !l.user.OrElse(Username{}).IsValid()) ||
		(l.connectTimeout.IsSet() && l.connectTimeout.OrElse(algebraic.ZeroDuration()).IsNegative()) ||
		(l.serverAliveInterval.IsSet() && l.serverAliveInterval.OrElse(algebraic.ZeroDuration()).IsNegative()) ||
		(l.strictHostKeyChecking.IsSet() && l.strictHostKeyChecking.OrElse(StrictHostKeyCheckingUnset).String() == "")
}

// Compose 执行高优先级 l 覆合低优先级 lower 的总幺半群运算（l ⊕ lower）。
func (l OptionLayer) Compose(lower OptionLayer) OptionLayer {
	return OptionLayer{
		l.hostName.Combine(lower.hostName), l.port.Combine(lower.port), l.user.Combine(lower.user),
		ComposeProxyRoute(l.proxy, lower.proxy), l.control.Compose(lower.control),
		l.connectTimeout.Combine(lower.connectTimeout), l.serverAliveInterval.Combine(lower.serverAliveInterval),
		l.serverAliveCountMax.Combine(lower.serverAliveCountMax),
		l.ciphers.Compose(lower.ciphers), l.macs.Compose(lower.macs),
		l.kexAlgorithms.Compose(lower.kexAlgorithms), l.hostKeyAlgorithms.Compose(lower.hostKeyAlgorithms),
		l.identityFiles.Compose(lower.identityFiles), l.certificateFiles.Compose(lower.certificateFiles),
		l.identitiesOnly.Combine(lower.identitiesOnly), l.batchMode.Combine(lower.batchMode),
		l.strictHostKeyChecking.Combine(lower.strictHostKeyChecking),
		l.userKnownHostsFiles.Compose(lower.userKnownHostsFiles), l.forwardAgent.Combine(lower.forwardAgent),
		l.sendEnv.Compose(lower.sendEnv), l.permitLocalCommand.Combine(lower.permitLocalCommand),
		l.localCommand.Combine(lower.localCommand),
	}
}

// FoldOptionLayers 按从高优先级到低优先级顺序折叠多个 OptionLayer。
func FoldOptionLayers(layers ...OptionLayer) OptionLayer {
	return foldMonoid(UnsetOptionLayer(), OptionLayer.Compose, layers)
}

// FilterForNonOpenSSHOrigin 按 INV-D2 对非 OpenSSH 来源节点的 t4（~/.ssh/config 层）执行安全裁剪：
// 严格仅保留 OptionClassMux ∪ OptionClassTransport（多路复用、超时/保活与算法协商），
// 完整剥离 Target、Auth（含 BatchMode 与 IdentitiesOnly）、Trust、Forward、Session 与 LocalExec。
func (l OptionLayer) FilterForNonOpenSSHOrigin() OptionLayer {
	return OptionLayer{
		control: l.control, connectTimeout: l.connectTimeout,
		serverAliveInterval: l.serverAliveInterval, serverAliveCountMax: l.serverAliveCountMax,
		ciphers: l.ciphers.clone(), macs: l.macs.clone(),
		kexAlgorithms: l.kexAlgorithms.clone(), hostKeyAlgorithms: l.hostKeyAlgorithms.clone(),
	}
}

// Equal 判断两个 OptionLayer 是否代表同一总幺半群元素。
func (l OptionLayer) Equal(o OptionLayer) bool {
	return algebraic.EqualFirstWins(l.hostName, o.hostName) && algebraic.EqualFirstWins(l.port, o.port) &&
		algebraic.EqualFirstWins(l.user, o.user) && EqualProxyRoute(l.proxy, o.proxy) &&
		l.control.Equal(o.control) && algebraic.EqualFirstWins(l.connectTimeout, o.connectTimeout) &&
		algebraic.EqualFirstWins(l.serverAliveInterval, o.serverAliveInterval) &&
		algebraic.EqualFirstWins(l.serverAliveCountMax, o.serverAliveCountMax) &&
		l.ciphers.Equal(o.ciphers) && l.macs.Equal(o.macs) &&
		l.kexAlgorithms.Equal(o.kexAlgorithms) && l.hostKeyAlgorithms.Equal(o.hostKeyAlgorithms) &&
		l.identityFiles.Equal(o.identityFiles) && l.certificateFiles.Equal(o.certificateFiles) &&
		algebraic.EqualFirstWins(l.identitiesOnly, o.identitiesOnly) &&
		algebraic.EqualFirstWins(l.batchMode, o.batchMode) &&
		algebraic.EqualFirstWins(l.strictHostKeyChecking, o.strictHostKeyChecking) &&
		l.userKnownHostsFiles.Equal(o.userKnownHostsFiles) &&
		algebraic.EqualFirstWins(l.forwardAgent, o.forwardAgent) && l.sendEnv.Equal(o.sendEnv) &&
		algebraic.EqualFirstWins(l.permitLocalCommand, o.permitLocalCommand) &&
		algebraic.EqualFirstWins(l.localCommand, o.localCommand)
}
