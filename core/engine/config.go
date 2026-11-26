package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
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

// DialContextFunc / RemoteFSFunc 定义可选底层传输拨号与远端文件系统工厂签名。
type (
	DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	RemoteFSFunc    func(ctx context.Context, conn ports.TransportConn) (ports.RemoteFSPort, error)
)

// Config 定义 Engine 的全显式依赖注入配置（零全局单例、零隐式 OS/环境变量读取）。
type Config struct {
	// 安全策略配置档与护栏配置（均必填）。
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
	KeySigner           ports.KeySignerPort
	Agent               ports.SSHAgentPort
	VaultControl        ports.VaultControlPort
	InventoryStore      ports.InventoryStore
	JournalStore        ports.JournalStore
	Importers           []ports.FormatImporter
	KnownStores         []string
	DefaultEnrollTTL    algebraic.Option[algebraic.Duration]
	PrivilegeEscalation ports.PrivilegeEscalationPort
	ShellProbe          ports.ShellProbePort
	Forwarder           ports.ForwarderPort
	TUNDevice           ports.TUNDevicePort
	MuxSocket           ports.MuxSocketPort
	Dialer              ports.DialerPort // 为 nil 时默认装配真实 sshnet/dial + sshnet/hostkey
	RemoteFS            RemoteFSFunc     // 可选覆写 TransportConn.OpenRemoteFS

	// 拨号、全局选项、跳板深度、限流分片、事件总线与连接池调优参数（全可选，0/None 取安全默认值）。
	DialContext                                                                  DialContextFunc
	ClientVersion                                                                string
	GlobalOptions                                                                option.OptionLayer
	MaxJumpDepth, TransferDefaultConcurrency, AutomationDefaultConcurrency       int
	TransferDefaultChunkSize, TransferDefaultMaxReadBytes                        int64
	AutomationMaxScriptBytes, AutomationMaxTemplateBytes, AutomationMaxCopyBytes int64
	SystemBus                                                                    *events.SystemBus
	SystemBusBuffer, PoolAcquireBuffer, PoolMaxConns, PoolMaxHandles             int
	PoolTeardownGrace, PoolIdleTTL, PoolKeepaliveInterval                        algebraic.Option[algebraic.Duration]
	OnHalt                                                                       OnHaltFunc // 熔断后触发至多一次（位于 pool.GateHalted 之后）
}

func compileGuardrailPolicy(cfg GuardrailConfig) (gate.GuardrailPolicy, error) {
	zeroPol := zeroVal[gate.GuardrailPolicy]()
	fb, err := cfg.NoElicitFallback.toGateFallback()
	if err != nil {
		return zeroPol, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	rules := append(make([]pathalg.ProtectedRule, 0, len(cfg.ProtectedRules)+len(cfg.ProtectedPatterns)), cfg.ProtectedRules...)
	for _, pat := range cfg.ProtectedPatterns {
		r, pErr := pathalg.ParseProtectedRule(pat)
		if pErr != nil {
			return zeroPol, fmt.Errorf("%w: 受保护路径模式 %q 无效: %w", ErrInvalidConfig, pat, pErr)
		}
		rules = append(rules, r)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: cfg.ApprovalThreshold, NoElicitFallback: fb, NodeOverrides: cfg.NodeOverrides,
		ProtectedRules: rules, ProtectedPathRisk: cfg.ProtectedPathRisk, ApprovalTTL: cfg.ApprovalTTL,
		MaxPendingChallenges: cfg.MaxPendingChallenges, MaxReplayHistory: cfg.MaxReplayHistory,
	})
	if err != nil {
		return zeroPol, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return pol, nil
}

func validateBaseConfig(cfg Config) (gate.PolicyProfileKind, gate.GuardrailPolicy, error) {
	zeroPol := zeroVal[gate.GuardrailPolicy]()
	prof, err := cfg.Profile.toGateProfile()
	if err != nil {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	pol, err := compileGuardrailPolicy(cfg.Guardrail)
	if err != nil {
		return gate.PolicyProfileInvalid, zeroPol, err
	}
	switch {
	case cfg.Clock == nil || cfg.Entropy == nil || cfg.AuditSink == nil:
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: Clock/Entropy/AuditSink 均不能为 nil", ErrInvalidConfig)
	case cfg.SystemBus != nil && cfg.SystemBus.IsClosed():
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: 注入的 SystemBus 未初始化或已关闭", ErrInvalidConfig)
	case cfg.SystemBusBuffer < 0:
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: SystemBusBuffer 不能为负", ErrInvalidConfig)
	}
	return prof, pol, nil
}

func buildHostTrustPort(cfg Config) (ports.HostTrustPort, error) {
	if cfg.HostTrust != nil {
		return cfg.HostTrust, nil
	}
	if cfg.ScopedFS == nil {
		return nil, fmt.Errorf("%w: 未注入 HostTrust 时必须提供 ScopedFS", ErrInvalidConfig)
	}
	homeOpt, err := resolveConfigHomeDir(cfg)
	if err != nil {
		return nil, err
	}
	khDir, err := resolveKnownHostsDir(cfg.KnownHostsDir, homeOpt)
	if err != nil {
		return nil, err
	}
	db, err := hostkey.NewKnownHostsDB(hostkey.Config{
		RootFS: cfg.ScopedFS, DefaultDir: khDir, DefaultFileName: cfg.KnownHostsFileName, HomeDir: homeOpt,
		MaxFileBytes: cfg.KnownHostsMaxBytes, SSHFPLookup: cfg.SSHFPLookup, HashHostnames: cfg.HashKnownHosts,
		Entropy: cfg.Entropy, Clock: cfg.Clock,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 初始化 KnownHostsDB 失败: %w", ErrInvalidConfig, err)
	}
	return db, nil
}

func resolveConfigHomeDir(cfg Config) (algebraic.Option[pathalg.LocalDir], error) {
	if home, ok := cfg.HomeDir.Get(); ok {
		if !home.IsValid() {
			return algebraic.None[pathalg.LocalDir](), fmt.Errorf("%w: HomeDir 无效", ErrInvalidConfig)
		}
		return algebraic.Some(home), nil
	}
	if cfg.Env == nil {
		return algebraic.None[pathalg.LocalDir](), nil
	}
	id, err := cfg.Env.LookupLocalIdentity()
	if err != nil || !id.IsValid() || id.HomeDir() == "" {
		return algebraic.None[pathalg.LocalDir](), nil
	}
	parsed, pErr := pathalg.ParseLocalDir(id.HomeDir())
	if pErr != nil {
		return algebraic.None[pathalg.LocalDir](), fmt.Errorf("%w: Env.LookupLocalIdentity.HomeDir 无效: %w", ErrInvalidConfig, pErr)
	}
	return algebraic.Some(parsed), nil
}

func resolveKnownHostsDir(explicit, homeOpt algebraic.Option[pathalg.LocalDir]) (pathalg.LocalDir, error) {
	zeroDir := zeroVal[pathalg.LocalDir]()
	if dir, ok := explicit.Get(); ok {
		if !dir.IsValid() {
			return zeroDir, fmt.Errorf("%w: KnownHostsDir 无效", ErrInvalidConfig)
		}
		return dir, nil
	}
	home, ok := homeOpt.Get()
	if !ok {
		return zeroDir, fmt.Errorf("%w: 缺少 KnownHostsDir 且无法从 HomeDir/Env 推导默认 ~/.ssh 目录", ErrInvalidConfig)
	}
	sshDir, err := home.JoinComponent(".ssh")
	if err != nil {
		return zeroDir, fmt.Errorf("%w: 推导 ~/.ssh 目录失败: %w", ErrInvalidConfig, err)
	}
	return sshDir, nil
}

func buildDialerPort(cfg Config) (ports.DialerPort, error) {
	base := cfg.Dialer
	if base == nil {
		hostTrust, err := buildHostTrustPort(cfg)
		if err != nil {
			return nil, err
		}
		if base, err = buildRealDialer(cfg, hostTrust); err != nil {
			return nil, err
		}
	}
	if cfg.RemoteFS == nil {
		return base, nil
	}
	return &remoteFSDialer{inner: base, openFS: cfg.RemoteFS}, nil
}

type (
	remoteFSDialer struct {
		inner  ports.DialerPort
		openFS RemoteFSFunc
	}
	remoteFSConn struct {
		ports.TransportConn
		openFS RemoteFSFunc
	}
)

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
func (c *remoteFSConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	return c.openFS(ctx, c.TransportConn)
}

func buildRealDialer(cfg Config, hostTrust ports.HostTrustPort) (*dial.Dialer, error) {
	var dialFn dial.DialContextFunc
	if cfg.DialContext != nil {
		dialFn = dial.DialContextFunc(cfg.DialContext)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust: hostTrust, Vault: cfg.Vault, KeySigner: cfg.KeySigner, Agent: cfg.Agent,
		ReadFS: cfg.OperatorReadFS, Process: cfg.Process, Interaction: cfg.Interaction,
		Clock: cfg.Clock, Env: cfg.Env, DialContext: dialFn, ClientVersion: cfg.ClientVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 初始化 sshnet/dial 失败: %w", ErrInvalidConfig, err)
	}
	return d, nil
}

func optPosStdDuration(opt algebraic.Option[algebraic.Duration], name string) (time.Duration, error) {
	d, ok := opt.Get()
	if !ok {
		return 0, nil
	}
	if !d.IsPositive() {
		return 0, fmt.Errorf("%w: %s 必须为正时长", ErrInvalidConfig, name)
	}
	return d.Std(), nil
}

func buildPoolConfig(cfg Config, d ports.DialerPort, bus *events.SystemBus) (pool.PoolConfig, error) {
	td, err := optPosStdDuration(cfg.PoolTeardownGrace, "PoolTeardownGrace")
	idle, err2 := optPosStdDuration(cfg.PoolIdleTTL, "PoolIdleTTL")
	ka, err3 := optPosStdDuration(cfg.PoolKeepaliveInterval, "PoolKeepaliveInterval")
	if first := errors.Join(err, err2, err3); first != nil {
		return pool.PoolConfig{}, first
	}
	return pool.PoolConfig{
		Dialer: d, Clock: cfg.Clock, Entropy: cfg.Entropy, Bus: bus,
		AcquireBuffer: cfg.PoolAcquireBuffer, MaxConns: cfg.PoolMaxConns, MaxHandles: cfg.PoolMaxHandles,
		TeardownGrace: td, IdleTTL: idle, DefaultKeepaliveInterval: ka,
	}, nil
}
