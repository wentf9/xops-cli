package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/forward"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux"
	"github.com/wentf9/xops-cli/core/internal/sshnet/priv"
	"github.com/wentf9/xops-cli/core/internal/sshnet/probe"
	"github.com/wentf9/xops-cli/core/internal/sshnet/sftp"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// GuardrailConfig 描述 Engine 内部能力门控（gate.GuardrailPolicy）的公开构造规格；
// 所有时长字段统一使用 algebraic.Duration，零值默认触发失败关闭校验。
type GuardrailConfig struct {
	ApprovalThreshold                      security.RiskLevel                       // 必填：全局基础审批风险阈值（如 RiskModerate）
	NoElicitFallback                       NoElicitFallback                         // 不可交互审批回退策略（零值为 Deny）
	NodeOverrides                          algebraic.Option[security.NodeOverrides] // 可选：节点通配符覆写格
	ProtectedRules                         []pathalg.ProtectedRule                  // 可选：已编译受保护路径规则
	ProtectedPatterns                      []string                                 // 可选：原始受保护路径模式串
	ProtectedPathRisk                      algebraic.Option[security.RiskLevel]     // 可选：命中受保护路径最低风险（默认 RiskDangerous）
	ApprovalTTL                            algebraic.Option[algebraic.Duration]     // 可选：审批信封有效期（默认 5m）
	MaxPendingChallenges, MaxReplayHistory int                                      // 可选：挂起审批挑战与防重放容量
}

// DefaultGuardrailConfig 返回遵循 RFC §4.2 的推荐默认护栏配置。
func DefaultGuardrailConfig() GuardrailConfig {
	return GuardrailConfig{ApprovalThreshold: security.RiskModerate, NoElicitFallback: NoElicitFallbackDeny, ProtectedPatterns: gate.StrictDefaultProtectedPatterns()}
}

// DialContextFunc 与 RemoteFSFunc 定义底层网络拨号与外置自定义/仿真传输的远端文件系统工厂签名。
// 注意：RemoteFSFunc 仅接收协议无关的 ports.TransportConn（不可访问未导出 *ssh.Client），专用于自定义或仿真 Dialer 覆写；
// 真实 sshnet/sftp 已在 buildRealDialer 中直接经 dial.Config.OpenRemoteFS 注入 sftp.Open。
type (
	DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	RemoteFSFunc    func(ctx context.Context, conn ports.TransportConn) (ports.RemoteFSPort, error)
)

// Config 定义 Engine 的全显式依赖注入配置（零全局单例、零隐式 OS/环境变量读取）。
type Config struct {
	Profile   PolicyProfile
	Guardrail GuardrailConfig

	// 核心基础设施端口：Clock / Entropy / AuditSink 为必填（ADR-008 零 nil 逃生口）；Reconciler 供启动期 O(1) 崩溃对账。
	Clock      ports.Clock
	Entropy    ports.Entropy
	AuditSink  ports.AuditSink
	Reconciler ports.AuditReconciler

	// 双模态本地文件系统与主机信任库（未注入 HostTrust 时必须提供 ScopedFS 以装配真实 KnownHostsDB）。
	ScopedFS               ports.ScopedRootFS
	OperatorReadFS         ports.OperatorReadFS
	HostTrust              ports.HostTrustPort
	KnownHostsDir, HomeDir algebraic.Option[pathalg.LocalDir]
	KnownHostsFileName     string
	KnownHostsMaxBytes     int64
	HashKnownHosts         bool
	SSHFPLookup            ports.SSHFPLookupPort

	// 可选本机/交互/凭据/资产/传输/隧道/复用与底层拨号端口（Phase 3/4 解耦注入槽位）。
	Env                 ports.EnvPort
	Terminal            ports.TerminalPort
	Process             ports.ProcessPort
	OpenSSH             ports.OpenSSHConfigSource
	Interaction         ports.InteractionPort
	Vault               ports.SecretVault
	KeySigner           ports.KeySignerPort // 为 nil 且已注入 OperatorReadFS/Agent 时默认装配真实 sshnet/dial.NewKeySigner
	Agent               ports.SSHAgentPort
	VaultControl        ports.VaultControlPort
	InventoryStore      ports.InventoryStore
	JournalStore        ports.JournalStore
	Importers           []ports.FormatImporter
	KnownStores         []string
	DefaultEnrollTTL    algebraic.Option[algebraic.Duration]
	PrivilegeEscalation ports.PrivilegeEscalationPort // 为 nil 时默认装配真实 sshnet/priv.NewEscalator
	ShellProbe          ports.ShellProbePort          // 为 nil 时默认装配真实 sshnet/probe.NewProber
	Forwarder           ports.ForwarderPort           // 为 nil 时默认装配真实 sshnet/forward.NewForwarder
	TUNDevice           ports.TUNDevicePort
	MuxSocket           ports.MuxSocketPort // 为 nil 时默认装配真实 sshnet/mux.NewMuxSocket
	Dialer              ports.DialerPort    // 为 nil 时默认装配真实 sshnet/dial（含 sftp.Open）+ sshnet/hostkey
	RemoteFS            RemoteFSFunc        // 仅用于外部自定义/仿真 Dialer 覆写 OpenRemoteFS；真实路径由 buildRealDialer 注入 sftp.Open

	// 拨号、全局选项、跳板深度、转发安全开关、限流分片、事件总线与连接池调优参数（全可选，0/false/None 取安全失败关闭默认值）。
	DialContext                                                                  DialContextFunc
	ClientVersion                                                                string
	GlobalOptions                                                                option.OptionLayer
	ForwardAllowGatewayPorts, ForwardReplaceStaleUnix                            bool // 默认 false：遵循 GatewayPorts=no 且不自动接管过期本地 Unix 转发套接字
	MaxJumpDepth, TransferDefaultConcurrency, AutomationDefaultConcurrency       int
	TransferDefaultChunkSize, TransferDefaultMaxReadBytes                        int64
	AutomationMaxScriptBytes, AutomationMaxTemplateBytes, AutomationMaxCopyBytes int64
	SystemBus                                                                    *events.SystemBus
	SystemBusBuffer, PoolAcquireBuffer, PoolMaxConns, PoolMaxHandles             int
	PoolTeardownGrace, PoolIdleTTL, PoolKeepaliveInterval                        algebraic.Option[algebraic.Duration]
	OnHalt                                                                       OnHaltFunc // 熔断后触发至多一次（位于 pool.GateHalted 之后）
}

func compileGuardrailPolicy(cfg GuardrailConfig) (gate.GuardrailPolicy, error) {
	fb, err := cfg.NoElicitFallback.toGateFallback()
	if err != nil {
		return zeroVal[gate.GuardrailPolicy](), wrapCfgErr("NoElicitFallback 无效", err)
	}
	rules := append(make([]pathalg.ProtectedRule, 0, len(cfg.ProtectedRules)+len(cfg.ProtectedPatterns)), cfg.ProtectedRules...)
	for _, pat := range cfg.ProtectedPatterns {
		r, pErr := pathalg.ParseProtectedRule(pat)
		if pErr != nil {
			return zeroVal[gate.GuardrailPolicy](), fmt.Errorf("%w: 受保护路径模式 %q 无效: %w", ErrInvalidConfig, pat, pErr)
		}
		rules = append(rules, r)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: cfg.ApprovalThreshold, NoElicitFallback: fb, NodeOverrides: cfg.NodeOverrides,
		ProtectedRules: rules, ProtectedPathRisk: cfg.ProtectedPathRisk, ApprovalTTL: cfg.ApprovalTTL,
		MaxPendingChallenges: cfg.MaxPendingChallenges, MaxReplayHistory: cfg.MaxReplayHistory,
	})
	return pol, wrapCfgErr("护栏策略无效", err)
}
func validateBaseConfig(cfg Config) (gate.PolicyProfileKind, gate.GuardrailPolicy, error) {
	zeroPol := zeroVal[gate.GuardrailPolicy]()
	prof, err := cfg.Profile.toGateProfile()
	if err != nil {
		return gate.PolicyProfileInvalid, zeroPol, wrapCfgErr("PolicyProfile 无效", err)
	}
	pol, err := compileGuardrailPolicy(cfg.Guardrail)
	if err != nil {
		return gate.PolicyProfileInvalid, zeroPol, err
	}
	if cfg.Clock == nil || cfg.Entropy == nil || cfg.AuditSink == nil {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: Clock/Entropy/AuditSink 均不能为 nil", ErrInvalidConfig)
	}
	if (cfg.SystemBus != nil && cfg.SystemBus.IsClosed()) || cfg.SystemBusBuffer < 0 {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: SystemBus 已关闭或 SystemBusBuffer 为负", ErrInvalidConfig)
	}
	return prof, pol, nil
}

// hostTrustObserver 在 ports.HostTrustPort 外层只读记录最近经校验通过或合法登记的 (Endpoint -> KeyFingerprint)，
// 遇冲突或吊销立即驱逐旧记录，支撑 INV-F2 首连暂存探测返回真实服务端指纹（零伪造）。
type hostTrustObserver struct {
	inner ports.HostTrustPort
	mu    sync.Mutex
	byEP  map[string]inventory.KeyFingerprint
}

func newHostTrustObserver(inner ports.HostTrustPort) *hostTrustObserver {
	return &hostTrustObserver{inner: inner, byEP: map[string]inventory.KeyFingerprint{}}
}
func (o *hostTrustObserver) PreferredAlgorithms(ctx context.Context, ep netaddr.Endpoint, kh option.KnownHostsList) ([]string, error) {
	return o.inner.PreferredAlgorithms(ctx, ep, kh)
}
func (o *hostTrustObserver) VerifyHostKey(ctx context.Context, req ports.HostTrustRequest) (ports.HostTrustCheck, error) {
	chk, err := o.inner.VerifyHostKey(ctx, req)
	if err == nil && chk.Endpoint().IsValid() {
		switch chk.Status() {
		case ports.HostTrustTrusted:
			o.set(chk.Endpoint(), chk.Presented().Fingerprint(), chk.Presented().IsValid())
		case ports.HostTrustMismatch, ports.HostTrustRevoked:
			o.set(chk.Endpoint(), zeroVal[inventory.KeyFingerprint](), false)
		}
	}
	return chk, err
}
func (o *hostTrustObserver) RecordHostKey(ctx context.Context, ep netaddr.Endpoint, key ports.PublicKeyInfo, kh option.KnownHostsList) error {
	err := o.inner.RecordHostKey(ctx, ep, key, kh)
	if err == nil && ep.IsValid() && key.IsValid() {
		o.set(ep, key.Fingerprint(), true)
	}
	return err
}
func (o *hostTrustObserver) set(ep netaddr.Endpoint, fp inventory.KeyFingerprint, keep bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if keep {
		o.byEP[ep.String()] = fp
		return
	}
	delete(o.byEP, ep.String())
}
func (o *hostTrustObserver) lookup(ep netaddr.Endpoint) (inventory.KeyFingerprint, bool) {
	if o == nil || !ep.IsValid() {
		return zeroVal[inventory.KeyFingerprint](), false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	fp, ok := o.byEP[ep.String()]
	return fp, ok && fp.IsValid()
}
func buildHostTrustPort(cfg Config) (*hostTrustObserver, error) {
	if cfg.HostTrust != nil {
		return newHostTrustObserver(cfg.HostTrust), nil
	}
	if cfg.ScopedFS == nil {
		return nil, fmt.Errorf("%w: 未注入 HostTrust 时必须提供 ScopedFS", ErrInvalidConfig)
	}
	homeOpt, khDir, err := resolveHostTrustDirs(cfg)
	if err != nil {
		return nil, err
	}
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS: cfg.ScopedFS, DefaultDir: khDir, DefaultFileName: cfg.KnownHostsFileName, HomeDir: homeOpt,
		MaxFileBytes: cfg.KnownHostsMaxBytes, SSHFPLookup: cfg.SSHFPLookup, HashHostnames: cfg.HashKnownHosts,
		Entropy: cfg.Entropy, Clock: cfg.Clock,
	})
	return validOrZero(err == nil, newHostTrustObserver(db)), wrapCfgErr("初始化 KnownHostsDB 失败", err)
}
func resolveHostTrustDirs(cfg Config) (homeOpt algebraic.Option[pathalg.LocalDir], khDir pathalg.LocalDir, err error) {
	if home, ok := cfg.HomeDir.Get(); ok {
		if !home.IsValid() {
			return homeOpt, khDir, fmt.Errorf("%w: HomeDir 无效", ErrInvalidConfig)
		}
		homeOpt = algebraic.Some(home)
	} else if cfg.Env != nil {
		if id, lErr := cfg.Env.LookupLocalIdentity(); lErr == nil && id.IsValid() && id.HomeDir() != "" {
			parsed, pErr := pathalg.ParseLocalDir(id.HomeDir())
			if pErr != nil {
				return homeOpt, khDir, wrapCfgErr("Env.LookupLocalIdentity.HomeDir 无效", pErr)
			}
			homeOpt = algebraic.Some(parsed)
		}
	}
	if dir, ok := cfg.KnownHostsDir.Get(); ok {
		return homeOpt, dir, validOrZero(!dir.IsValid(), fmt.Errorf("%w: KnownHostsDir 无效", ErrInvalidConfig))
	}
	home, ok := homeOpt.Get()
	if !ok {
		return homeOpt, khDir, fmt.Errorf("%w: 缺少 KnownHostsDir 且无法从 HomeDir/Env 推导默认 ~/.ssh 目录", ErrInvalidConfig)
	}
	sshDir, jErr := home.JoinComponent(".ssh")
	return homeOpt, sshDir, wrapCfgErr("推导 ~/.ssh 目录失败", jErr)
}

type resolvedPorts struct {
	keySigner  ports.KeySignerPort
	escalator  ports.PrivilegeEscalationPort
	shellProbe ports.ShellProbePort
	forwarder  ports.ForwarderPort
	muxSocket  ports.MuxSocketPort
}

func resolveDefaultKeySigner(cfg Config) (ports.KeySignerPort, error) {
	if cfg.KeySigner != nil || (cfg.OperatorReadFS == nil && cfg.Agent == nil) {
		return cfg.KeySigner, nil
	}
	ks, err := dial.NewKeySigner(dial.KeySignerConfig{
		ReadFS: cfg.OperatorReadFS, Vault: cfg.Vault, Agent: cfg.Agent, Env: cfg.Env, Entropy: cfg.Entropy,
	})
	return ks, wrapCfgErr("初始化 sshnet/dial/keysigner 失败", err)
}

// resolveDefaultPorts 为未显式注入的可选协议端口装配真实 sshnet/* 生产默认实现；
// 凡调用方显式注入的端口槽位均原样保留，确保仿真测试与上层宿主覆写 100% 兼容。
func resolveDefaultPorts(cfg Config, activity *muxActivityHub) (rp resolvedPorts, err error) {
	if rp.keySigner, err = resolveDefaultKeySigner(cfg); err != nil {
		return resolvedPorts{}, err
	}
	rp.escalator = cfg.PrivilegeEscalation
	if rp.escalator == nil {
		if rp.escalator, err = priv.NewEscalator(priv.Config{Entropy: cfg.Entropy, Clock: cfg.Clock}); err != nil {
			return resolvedPorts{}, wrapCfgErr("初始化 sshnet/priv 失败", err)
		}
	}
	rp.shellProbe = cfg.ShellProbe
	if rp.shellProbe == nil {
		if rp.shellProbe, err = probe.NewProber(probe.Config{}); err != nil {
			return resolvedPorts{}, wrapCfgErr("初始化 sshnet/probe 失败", err)
		}
	}
	rp.forwarder = cfg.Forwarder
	if rp.forwarder == nil {
		rp.forwarder = forward.NewForwarder(forward.Config{
			TUNDevice: cfg.TUNDevice, AllowGatewayPorts: cfg.ForwardAllowGatewayPorts,
			ReplaceStaleUnix: cfg.ForwardReplaceStaleUnix, Clock: cfg.Clock,
		})
	}
	rp.muxSocket = cfg.MuxSocket
	if rp.muxSocket == nil {
		var onSocketActivity func(context.Context, string)
		if activity != nil {
			onSocketActivity = activity.notify
		}
		rp.muxSocket = mux.NewMuxSocket(mux.Config{Clock: cfg.Clock, OnSocketActivity: onSocketActivity})
	}
	return rp, nil
}
func buildDialerPort(cfg Config, rp resolvedPorts) (ports.DialerPort, *hostTrustObserver, error) {
	base := cfg.Dialer
	var obs *hostTrustObserver
	if base == nil {
		var err error
		if obs, err = buildHostTrustPort(cfg); err == nil {
			base, err = buildRealDialer(cfg, obs, rp.keySigner)
		}
		if err != nil {
			return nil, nil, err
		}
	}
	// 透明客户端 ControlMaster 复用适配器：位于真实/仿真拨号器外层、RemoteFS 覆写内层，确保 Exec 与 SFTP 统一复用活跃主进程。
	if rp.muxSocket != nil {
		base = &muxClientDialer{inner: base, mux: rp.muxSocket, env: cfg.Env, interaction: cfg.Interaction}
	}
	if cfg.RemoteFS != nil {
		base = &remoteFSDialer{inner: base, openFS: cfg.RemoteFS}
	}
	return base, obs, nil
}

type (
	muxClientDialer struct {
		inner       ports.DialerPort
		mux         ports.MuxSocketPort
		env         ports.EnvPort
		interaction ports.InteractionPort
	}
	remoteFSDialer struct {
		inner  ports.DialerPort
		openFS RemoteFSFunc
	}
	remoteFSConn struct {
		ports.TransportConn
		openFS RemoteFSFunc
	}
)

func (d *muxClientDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if conn, used, err := ucsess.TryDialMuxClient(ctx, d.mux, d.env, d.interaction, hop, dig); err != nil || used {
		return conn, err
	}
	return d.inner.DialHop(ctx, hop, dig, parent)
}
func (d *remoteFSDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, parent ports.TransportConn) (ports.TransportConn, error) {
	if wrapped, ok := parent.(*remoteFSConn); ok {
		parent = wrapped.TransportConn
	}
	conn, err := d.inner.DialHop(ctx, hop, dig, parent)
	if err != nil {
		return nil, err
	}
	return &remoteFSConn{TransportConn: conn, openFS: d.openFS}, nil
}

type (
	waitDoneProvider      interface{ WaitDone() <-chan struct{} }
	subsystemStreamOpener interface {
		OpenSubsystemStream(ctx context.Context, subsystem string) (io.ReadWriteCloser, error)
	}
)

func (c *remoteFSConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	return c.openFS(ctx, c.TransportConn)
}
func (c *remoteFSConn) WaitDone() <-chan struct{} {
	if wp, ok := c.TransportConn.(waitDoneProvider); ok {
		return wp.WaitDone()
	}
	return nil
}
func (c *remoteFSConn) OpenSubsystemStream(ctx context.Context, subsystem string) (io.ReadWriteCloser, error) {
	if sso, ok := c.TransportConn.(subsystemStreamOpener); ok {
		return sso.OpenSubsystemStream(ctx, subsystem)
	}
	return nil, ports.ErrUnsupported
}
func buildRealDialer(cfg Config, hostTrust ports.HostTrustPort, keySigner ports.KeySignerPort) (*dial.Dialer, error) {
	d, err := dial.NewDialer(dial.Config{
		HostTrust: hostTrust, Vault: cfg.Vault, KeySigner: keySigner, Agent: cfg.Agent,
		ReadFS: cfg.OperatorReadFS, Process: cfg.Process, Interaction: cfg.Interaction,
		Clock: cfg.Clock, Env: cfg.Env, DialContext: dial.DialContextFunc(cfg.DialContext),
		OpenRemoteFS: sftp.Open, ClientVersion: cfg.ClientVersion,
	})
	return d, wrapCfgErr("初始化 sshnet/dial 失败", err)
}
func optPosStdDuration(opt algebraic.Option[algebraic.Duration], name string) (time.Duration, error) {
	if d, ok := opt.Get(); ok {
		if !d.IsPositive() {
			return 0, fmt.Errorf("%w: %s 必须为正时长", ErrInvalidConfig, name)
		}
		return d.Std(), nil
	}
	return 0, nil
}
func buildPoolConfig(cfg Config, d ports.DialerPort, bus *events.SystemBus) (pool.PoolConfig, error) {
	td, e1 := optPosStdDuration(cfg.PoolTeardownGrace, "PoolTeardownGrace")
	idle, e2 := optPosStdDuration(cfg.PoolIdleTTL, "PoolIdleTTL")
	ka, e3 := optPosStdDuration(cfg.PoolKeepaliveInterval, "PoolKeepaliveInterval")
	if err := errors.Join(e1, e2, e3); err != nil {
		return pool.PoolConfig{}, err
	}
	return pool.PoolConfig{
		Dialer: d, Clock: cfg.Clock, Entropy: cfg.Entropy, Bus: bus,
		AcquireBuffer: cfg.PoolAcquireBuffer, MaxConns: cfg.PoolMaxConns, MaxHandles: cfg.PoolMaxHandles,
		TeardownGrace: td, IdleTTL: idle, DefaultKeepaliveInterval: ka,
	}, nil
}
