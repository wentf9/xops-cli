package engine

import (
	"context"
	"fmt"
	"net"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial"
	"github.com/wentf9/xops-cli/core/internal/sshnet/hostkey"
	"github.com/wentf9/xops-cli/core/ports"
)

// GuardrailConfig 描述 Engine 内部能力门控（gate.GuardrailPolicy）的公开构造规格。
// 所有时长字段统一使用 algebraic.Duration，零值默认触发失败关闭校验。
type GuardrailConfig struct {
	// ApprovalThreshold 是必填的全局基础审批风险阈值（如 security.RiskModerate）。
	ApprovalThreshold security.RiskLevel
	// NoElicitFallback 定义不可交互时的审批回退行为（零值为 NoElicitFallbackDeny）。
	NoElicitFallback NoElicitFallback
	// NodeOverrides 可选注入节点通配符覆写格（None 等价空规则集）。
	NodeOverrides algebraic.Option[security.NodeOverrides]
	// ProtectedRules 可选注入已编译的受保护路径规则集。
	ProtectedRules []pathalg.ProtectedRule
	// ProtectedPatterns 可选注入原始受保护路径模式串（自动经 pathalg.ParseProtectedRule 编译）。
	ProtectedPatterns []string
	// ProtectedPathRisk 可选指定命中受保护路径时提升的最低风险等级（None 默认 RiskDangerous）。
	ProtectedPathRisk algebraic.Option[security.RiskLevel]
	// ApprovalTTL 可选指定审批信封有效期（None 默认 5m，范围 (0, 24h]）。
	ApprovalTTL algebraic.Option[algebraic.Duration]
	// MaxPendingChallenges 可选限制挂起审批挑战容量（0 取默认 256，负值拒绝）。
	MaxPendingChallenges int
	// MaxReplayHistory 可选限制防重放记录容量（0 取默认 4096，负值拒绝）。
	MaxReplayHistory int
}

// DefaultGuardrailConfig 返回遵循 RFC §4.2 的推荐默认护栏配置
// （阈值 RiskModerate、不可交互回退 Deny、启用默认高危受保护路径模式）。
func DefaultGuardrailConfig() GuardrailConfig {
	return GuardrailConfig{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  NoElicitFallbackDeny,
		ProtectedPatterns: gate.StrictDefaultProtectedPatterns(),
	}
}

// DialContextFunc 定义底层流传输拨号函数签名（为空时由 sshnet/dial 默认使用标准 TCP 拨号器）。
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config 定义 Engine 的全显式依赖注入配置（零全局单例、零隐式 OS/环境变量读取）。
type Config struct {
	// Profile 是必填的安全策略配置档（DirectOperator / StrictOperator / StrictAgent）。
	Profile PolicyProfile
	// Guardrail 是必填的安全护栏配置（可使用 DefaultGuardrailConfig 快速初始化）。
	Guardrail GuardrailConfig

	// Clock 是必填的时钟与定时器端口。
	Clock ports.Clock
	// Entropy 是必填的并发安全显式密码学/确定性熵源端口。
	Entropy ports.Entropy
	// AuditSink 是必填的同步 Fail-Closed 审计落盘与活跃操作登记端口（ADR-008：严禁 nil 逃生口）。
	AuditSink ports.AuditSink
	// Reconciler 可选注入启动期 O(1) 跨进程崩溃审计对账端口（调用 ReconcileCrashedAudits 时必填）。
	Reconciler ports.AuditReconciler

	// ScopedFS 是沙箱本地文件系统端口（未显式注入 HostTrust 时必填，用于构建真实 KnownHostsDB）。
	ScopedFS ports.ScopedRootFS
	// OperatorReadFS 可选注入操作员本地只读文件端口（供 sshnet/dial 按策略读取私钥与证书）。
	OperatorReadFS ports.OperatorReadFS
	// HostTrust 可选覆写主机密钥信任库端口；为空时自动基于 ScopedFS 装配真实 sshnet/hostkey.KnownHostsDB。
	HostTrust ports.HostTrustPort
	// KnownHostsDir 可选指定默认 known_hosts 所在沙箱根目录；为空时自动回退至 HomeDir/.ssh。
	KnownHostsDir algebraic.Option[pathalg.LocalDir]
	// KnownHostsFileName 可选指定默认 known_hosts 文件名（留空默认 "known_hosts"）。
	KnownHostsFileName string
	// KnownHostsMaxBytes 可选指定单个 known_hosts 文件读取上限字节数（<= 0 默认 16 MiB）。
	KnownHostsMaxBytes int64
	// HomeDir 可选显式提供本机主目录（为空且注入了 Env 时自动从 Env.LookupLocalIdentity 派生）。
	HomeDir algebraic.Option[pathalg.LocalDir]
	// HashKnownHosts 控制 TOFU 记录 known_hosts 时是否以 OpenSSH HMAC-SHA1 哈希格式写入主机名。
	HashKnownHosts bool
	// SSHFPLookup 可选注入 DNSSEC SSHFP 只读查询端口。
	SSHFPLookup ports.SSHFPLookupPort

	// Env 可选注入只读环境与本机身份快照端口（用于默认用户名回退、SendEnv 过滤、TERM 与模板展开）。
	Env ports.EnvPort
	// Terminal 可选注入本机原始终端端口（用于交互式 SSH PTY 分配与窗口缩放中继）。
	Terminal ports.TerminalPort
	// Process 可选注入子进程端口（用于 ProxyCommand 与 Keyboard-Interactive RuleCommand）。
	Process ports.ProcessPort
	// OpenSSH 可选注入 ~/.ssh/config 只读虚拟主机与 Tier-4 选项源。
	OpenSSH ports.OpenSSHConfigSource
	// Interaction 可选注入人工确认与审批交互端口。
	Interaction ports.InteractionPort
	// Vault 可选注入凭据库端口（用于密码、加密私钥口令及 TOTP 消费）。
	Vault ports.SecretVault
	// KeySigner 可选注入外部公钥签名器端口。
	KeySigner ports.KeySignerPort
	// Agent 可选注入本机 SSH Agent 端口。
	Agent ports.SSHAgentPort

	// DialContext 可选覆盖底层 TCP 拨号器（生产默认直连 TCP，集成测试可路由至 127.0.0.1 回环桩）。
	DialContext DialContextFunc
	// ClientVersion 可选覆盖 SSH 客户端版本标识串（须以 "SSH-2.0-" 开头且不含换行）。
	ClientVersion string
	// GlobalOptions 可选注入 XOps 全局选项层（t3）。
	GlobalOptions option.OptionLayer
	// MaxJumpDepth 可选限制 ProxyJump 递归最大跳板深度（0 默认 16）。
	MaxJumpDepth int

	// SystemBus 可选注入外部共享诊断事件总线（外部注入时由外部负责关闭；为 nil 时由 Engine 创建并随 Close 关闭）。
	SystemBus *events.SystemBus
	// SystemBusBuffer 仅在 SystemBus 为 nil 时生效，用于配置 Engine 自建总线的订阅者缓冲容量（0 默认 64）。
	SystemBusBuffer int

	// 连接池容量与超时调优参数（全可选，0/None 取连接池安全默认值）。
	PoolAcquireBuffer     int
	PoolMaxConns          int
	PoolMaxHandles        int
	PoolTeardownGrace     algebraic.Option[algebraic.Duration]
	PoolIdleTTL           algebraic.Option[algebraic.Duration]
	PoolKeepaliveInterval algebraic.Option[algebraic.Duration]

	// OnHalt 可选注册不可逆 Halted 熔断外部回调（保证在连接池收到 GateHalted 通知后触发）。
	OnHalt OnHaltFunc
}

func compileGuardrailPolicy(cfg GuardrailConfig) (gate.GuardrailPolicy, error) {
	zeroPol := zeroVal[gate.GuardrailPolicy]()
	fb, err := cfg.NoElicitFallback.toGateFallback()
	if err != nil {
		return zeroPol, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	rules := make([]pathalg.ProtectedRule, 0, len(cfg.ProtectedRules)+len(cfg.ProtectedPatterns))
	rules = append(rules, cfg.ProtectedRules...)
	for _, pat := range cfg.ProtectedPatterns {
		r, pErr := pathalg.ParseProtectedRule(pat)
		if pErr != nil {
			return zeroPol, fmt.Errorf("%w: 受保护路径模式 %q 无效: %w", ErrInvalidConfig, pat, pErr)
		}
		rules = append(rules, r)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold:    cfg.ApprovalThreshold,
		NoElicitFallback:     fb,
		NodeOverrides:        cfg.NodeOverrides,
		ProtectedRules:       rules,
		ProtectedPathRisk:    cfg.ProtectedPathRisk,
		ApprovalTTL:          cfg.ApprovalTTL,
		MaxPendingChallenges: cfg.MaxPendingChallenges,
		MaxReplayHistory:     cfg.MaxReplayHistory,
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
	if cfg.Clock == nil {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: Clock 不能为 nil", ErrInvalidConfig)
	}
	if cfg.Entropy == nil {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: Entropy 不能为 nil", ErrInvalidConfig)
	}
	if cfg.AuditSink == nil {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: AuditSink 不能为 nil", ErrInvalidConfig)
	}
	if cfg.SystemBus != nil && cfg.SystemBus.IsClosed() {
		return gate.PolicyProfileInvalid, zeroPol, fmt.Errorf("%w: 注入的 SystemBus 未初始化或已关闭", ErrInvalidConfig)
	}
	if cfg.SystemBusBuffer < 0 {
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
		RootFS:          cfg.ScopedFS,
		DefaultDir:      khDir,
		DefaultFileName: cfg.KnownHostsFileName,
		HomeDir:         homeOpt,
		MaxFileBytes:    cfg.KnownHostsMaxBytes,
		SSHFPLookup:     cfg.SSHFPLookup,
		HashHostnames:   cfg.HashKnownHosts,
		Entropy:         cfg.Entropy,
		Clock:           cfg.Clock,
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

func resolveKnownHostsDir(
	explicit algebraic.Option[pathalg.LocalDir],
	homeOpt algebraic.Option[pathalg.LocalDir],
) (pathalg.LocalDir, error) {
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

func buildRealDialer(cfg Config, hostTrust ports.HostTrustPort) (*dial.Dialer, error) {
	var dialFn dial.DialContextFunc
	if cfg.DialContext != nil {
		dialFn = dial.DialContextFunc(cfg.DialContext)
	}
	d, err := dial.NewDialer(dial.Config{
		HostTrust:     hostTrust,
		Vault:         cfg.Vault,
		KeySigner:     cfg.KeySigner,
		Agent:         cfg.Agent,
		ReadFS:        cfg.OperatorReadFS,
		Process:       cfg.Process,
		Interaction:   cfg.Interaction,
		Clock:         cfg.Clock,
		Env:           cfg.Env,
		DialContext:   dialFn,
		ClientVersion: cfg.ClientVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: 初始化 sshnet/dial 失败: %w", ErrInvalidConfig, err)
	}
	return d, nil
}

func buildPoolConfig(cfg Config, d ports.DialerPort, bus *events.SystemBus) (pool.PoolConfig, error) {
	pCfg := pool.PoolConfig{
		Dialer:        d,
		Clock:         cfg.Clock,
		Entropy:       cfg.Entropy,
		Bus:           bus,
		AcquireBuffer: cfg.PoolAcquireBuffer,
		MaxConns:      cfg.PoolMaxConns,
		MaxHandles:    cfg.PoolMaxHandles,
	}
	if td, ok := cfg.PoolTeardownGrace.Get(); ok {
		if !td.IsPositive() {
			return pool.PoolConfig{}, fmt.Errorf("%w: PoolTeardownGrace 必须为正时长", ErrInvalidConfig)
		}
		pCfg.TeardownGrace = td.Std()
	}
	if idle, ok := cfg.PoolIdleTTL.Get(); ok {
		if !idle.IsPositive() {
			return pool.PoolConfig{}, fmt.Errorf("%w: PoolIdleTTL 必须为正时长", ErrInvalidConfig)
		}
		pCfg.IdleTTL = idle.Std()
	}
	if ka, ok := cfg.PoolKeepaliveInterval.Get(); ok {
		if !ka.IsPositive() {
			return pool.PoolConfig{}, fmt.Errorf("%w: PoolKeepaliveInterval 必须为正时长", ErrInvalidConfig)
		}
		pCfg.DefaultKeepaliveInterval = ka.Std()
	}
	return pCfg, nil
}
