package inventory

import (
	"context"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/ports"
)

// ServiceConfig 定义只读目标解析服务 Service 的显式出站依赖配置。
type ServiceConfig struct {
	// OpenSSH 可选注入 ~/.ssh/config 只读虚拟主机与 Tier-4 选项源。
	OpenSSH ports.OpenSSHConfigSource
	// Env 可选注入本机环境与身份快照端口（用于默认用户名回退、模板变量展开与默认私钥路径检测）。
	Env ports.EnvPort
	// GlobalOptions 可选注入 XOps 全局选项层（t3）。
	GlobalOptions option.OptionLayer
	// MaxJumpDepth 限制 ProxyJump 递归解析最大跳板深度；0 使用默认 16，负值或超限失败关闭。
	MaxJumpDepth int
}

// Service 是 XOps v2 目标与连接计划解析用例服务（Phase 2.5 Walking Skeleton 只读切片）；
// 零值恒未初始化并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	openSSH       ports.OpenSSHConfigSource
	env           ports.EnvPort
	globalOptions option.OptionLayer
	maxJumpDepth  int
	valid         bool
}

// NewService 校验全局选项层与最大跳板深度上限并构造只读目标解析 Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := cfg.GlobalOptions.Validate(); err != nil {
		return nil, fmt.Errorf("%w: GlobalOptions 无效: %w", ErrInvalidConfig, err)
	}
	maxDepth := cfg.MaxJumpDepth
	if maxDepth == 0 {
		maxDepth = defaultMaxJumpDepth
	}
	if maxDepth < 0 || maxDepth > maxAllowedJumpDepth {
		return nil, fmt.Errorf("%w: MaxJumpDepth=%d 必须落在 [1, %d]", ErrInvalidConfig, cfg.MaxJumpDepth, maxAllowedJumpDepth)
	}
	return &Service{
		openSSH:       cfg.OpenSSH,
		env:           cfg.Env,
		globalOptions: cfg.GlobalOptions.Compose(option.UnsetOptionLayer()),
		maxJumpDepth:  maxDepth,
		valid:         true,
	}, nil
}

// ResolveTargetRequest 描述单次目标解析与 Merkle 连接计划编译的强类型入参。
type ResolveTargetRequest struct {
	// Target 为目标连接字符串（[user@]host[:port]、[ipv6][:port]、裸 IPv6 或 OpenSSH 别名）。
	Target string
	// CLIOptions 为最高优先级 CLI 选项层（t1：-l/-p/-i/-J/-o 等）。
	CLIOptions option.OptionLayer
	// ExplicitOrigin 可选强制指定目标来源（仅支持 OriginAdHoc 与 OriginOpenSSHVirtual；None 自动判定）。
	ExplicitOrigin algebraic.Option[option.OriginKind]
	// ExplicitAuth 可选覆盖末跳认证方式（为 nil 时依据 EffectivePolicy 自动编译）。
	ExplicitAuth inventory.AuthMethod
}

// ResolvedTarget 封装目标解析产出的不可变来源证明、末跳生效策略与 Merkle 链式连接计划；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ResolvedTarget struct {
	nodeID string
	origin inventory.NodeOrigin
	policy option.EffectivePolicy
	plan   plan.SealedConnectionPlan
	valid  bool
}

// ResolvedTarget 零值安全只读访问器。
func (r ResolvedTarget) IsValid() bool {
	return r.valid && r.nodeID != "" && r.origin != nil && r.origin.IsValid() && r.policy.IsValid() && r.plan.IsValid()
}
func (r ResolvedTarget) IsZero() bool { return !r.IsValid() }
func (r ResolvedTarget) NodeID() string {
	if !r.IsValid() {
		return ""
	}
	return r.nodeID
}
func (r ResolvedTarget) Origin() inventory.NodeOrigin {
	if !r.IsValid() {
		return nil
	}
	return r.origin
}
func (r ResolvedTarget) OriginKind() option.OriginKind {
	if !r.IsValid() {
		return option.OriginInvalid
	}
	return r.origin.Kind()
}
func (r ResolvedTarget) Policy() option.EffectivePolicy {
	if !r.IsValid() {
		return zeroVal[option.EffectivePolicy]()
	}
	return r.policy
}
func (r ResolvedTarget) Plan() plan.SealedConnectionPlan {
	if !r.IsValid() {
		return zeroVal[plan.SealedConnectionPlan]()
	}
	return r.plan
}

type resolveState struct {
	virtualIndex        map[string]ports.OpenSSHVirtualHost
	cliJumpPolicy       option.OptionLayer
	cliJumpAuthFallback option.OptionLayer
	activeStack         map[string]bool
	hops                []plan.HopSpec
	maxJumpDepth        int
}

// ResolveTarget 将目标规格、CLI 选项层与可选 OpenSSH 只读配置解析为不可变 ResolvedTarget
// 与多跳 Merkle plan.SealedConnectionPlan（带环路检测与跳板深度上限护栏）。
func (s *Service) ResolveTarget(ctx context.Context, req ResolveTargetRequest) (ResolvedTarget, error) {
	if err := s.validateResolveInputs(ctx, req); err != nil {
		return ResolvedTarget{}, err
	}
	parsed, err := parseTargetSpec(req.Target)
	if err != nil {
		return ResolvedTarget{}, err
	}
	vhIndex, err := s.loadVirtualHostIndex(ctx)
	if err != nil {
		return ResolvedTarget{}, err
	}
	st := &resolveState{
		virtualIndex:        vhIndex,
		cliJumpPolicy:       extractCLIJumpPolicy(req.CLIOptions),
		cliJumpAuthFallback: extractCLIJumpAuthFallback(req.CLIOptions),
		activeStack:         make(map[string]bool),
		maxJumpDepth:        s.maxJumpDepth,
	}
	origin, policy, err := s.resolveHopRecursive(ctx, st, parsed, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth, 0)
	if err != nil {
		return ResolvedTarget{}, err
	}
	sealed, err := plan.SealConnectionPlan(st.hops...)
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{
		nodeID: parsed.origHost.String(),
		origin: origin,
		policy: policy,
		plan:   sealed,
		valid:  true,
	}, nil
}

func (s *Service) validateResolveInputs(ctx context.Context, req ResolveTargetRequest) error {
	if s == nil || !s.valid {
		return ErrServiceNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := req.CLIOptions.Validate(); err != nil {
		return fmt.Errorf("%w: CLIOptions 无效: %w", ErrInvalidTarget, err)
	}
	if expOrigin, ok := req.ExplicitOrigin.Get(); ok {
		if expOrigin != option.OriginAdHoc && expOrigin != option.OriginOpenSSHVirtual {
			return fmt.Errorf("%w: 仅支持 OriginAdHoc 与 OriginOpenSSHVirtual，实际=%s", ErrUnsupportedOrigin, expOrigin)
		}
	}
	if req.ExplicitAuth != nil && !req.ExplicitAuth.IsValid() {
		return fmt.Errorf("%w: ExplicitAuth 无效", ErrNoAuthMethod)
	}
	return nil
}

func (s *Service) loadVirtualHostIndex(ctx context.Context) (map[string]ports.OpenSSHVirtualHost, error) {
	if s.openSSH == nil {
		return nil, nil
	}
	hosts, err := s.openSSH.ListVirtualHosts(ctx)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, nil
	}
	idx := make(map[string]ports.OpenSSHVirtualHost, len(hosts))
	for _, h := range hosts {
		if h.IsValid() {
			if _, exists := idx[h.Alias()]; !exists {
				idx[h.Alias()] = h
			}
		}
	}
	return idx, nil
}

func (s *Service) resolveHopRecursive(
	ctx context.Context,
	st *resolveState,
	pt parsedTarget,
	cliOpts option.OptionLayer,
	explicitOrigin algebraic.Option[option.OriginKind],
	explicitAuth inventory.AuthMethod,
	depth int,
) (inventory.NodeOrigin, option.EffectivePolicy, error) {
	var zeroPolicy option.EffectivePolicy
	if err := ctx.Err(); err != nil {
		return nil, zeroPolicy, err
	}
	if depth > st.maxJumpDepth {
		return nil, zeroPolicy, fmt.Errorf("%w: %w: ProxyJump 深度 %d 超过上限 %d", ErrProxyJumpDepthExceeded, inventory.ErrProxyJumpDepthExceeded, depth, st.maxJumpDepth)
	}
	origin, t4, t1, err := s.resolveHopOriginAndTiers(ctx, st, pt, cliOpts, explicitOrigin, depth)
	if err != nil {
		return nil, zeroPolicy, err
	}
	policy, err := option.ResolveEffectivePolicyWithOriginalHost(
		origin.Kind(), pt.origHost, netaddr.DefaultSSHPort, t1, option.UnsetOptionLayer(), s.globalOptions, t4,
	)
	if err != nil {
		return nil, zeroPolicy, err
	}
	aliasKey, epKey := hopCycleKeys(origin.Kind(), pt.origHost, policy.Endpoint())
	if st.activeStack[aliasKey] || st.activeStack[epKey] {
		return nil, zeroPolicy, fmt.Errorf("%w: %w: 跳板目标 %s (%s) 存在循环引用", ErrProxyJumpCycle, inventory.ErrProxyJumpCycle, pt.origHost.String(), policy.Endpoint())
	}
	st.activeStack[aliasKey], st.activeStack[epKey] = true, true
	defer func() {
		delete(st.activeStack, aliasKey)
		delete(st.activeStack, epKey)
	}()
	if err := s.expandUpstreamJumps(ctx, st, policy.Proxy(), depth); err != nil {
		return nil, zeroPolicy, err
	}
	if err := s.appendResolvedHop(st, pt.origHost.String(), policy, explicitAuth); err != nil {
		return nil, zeroPolicy, err
	}
	return origin, policy, nil
}

func (s *Service) resolveHopOriginAndTiers(
	ctx context.Context,
	st *resolveState,
	pt parsedTarget,
	cliOpts option.OptionLayer,
	explicitOrigin algebraic.Option[option.OriginKind],
	depth int,
) (inventory.NodeOrigin, option.OptionLayer, option.OptionLayer, error) {
	originKind, vh, foundVH := classifyOriginKind(st.virtualIndex, pt.origHost, explicitOrigin)
	// 先以不含 AdHoc 认证兜底的轻量探测层解析 Tier-4，确保通配符虚拟别名在最终 originKind
	// 收敛前不会提前泄漏叶节点 IdentityFile/IdentitiesOnly 兜底。
	probeT1 := cliOpts.Compose(pt.inlineLayer())
	t4, err := s.resolveHopTier4(ctx, pt.origHost, originKind, probeT1)
	if err != nil {
		return nil, option.UnsetOptionLayer(), option.UnsetOptionLayer(), err
	}
	// 未显式指定来源且非具体虚拟别名时，若原始目标非标准 DNS/IP 但命中了通配符 Host 块的 HostName，
	// 则归入 OpenSSH 虚拟来源以便完成主机名展开；其余临时 user@host 一律保持 OriginAdHoc（INV-D2）。
	if explicitOrigin.IsNone() && originKind == option.OriginAdHoc && t4.HostName().IsSome() {
		if _, isCanon := pt.origHost.CanonicalHost(); !isCanon {
			originKind = option.OriginOpenSSHVirtual
		}
	}
	t1 := buildHopTier1(pt, cliOpts, st.cliJumpPolicy, st.cliJumpAuthFallback, originKind, depth)
	nodeOrigin, err := buildNodeOrigin(originKind, pt.origHost, vh, foundVH)
	if err != nil {
		return nil, option.UnsetOptionLayer(), option.UnsetOptionLayer(), err
	}
	return nodeOrigin, t4, t1, nil
}

func classifyOriginKind(
	vhIndex map[string]ports.OpenSSHVirtualHost,
	origHost option.OriginalHostSpec,
	explicit algebraic.Option[option.OriginKind],
) (option.OriginKind, ports.OpenSSHVirtualHost, bool) {
	vh, foundVH := vhIndex[origHost.String()]
	if exp, ok := explicit.Get(); ok {
		return exp, vh, foundVH
	}
	if foundVH {
		return option.OriginOpenSSHVirtual, vh, true
	}
	return option.OriginAdHoc, zeroVal[ports.OpenSSHVirtualHost](), false
}

func buildHopTier1(
	pt parsedTarget,
	cliOpts option.OptionLayer,
	cliJumpPolicy option.OptionLayer,
	cliJumpAuthFallback option.OptionLayer,
	originKind option.OriginKind,
	depth int,
) option.OptionLayer {
	inline := pt.inlineLayer()
	if depth == 0 {
		return cliOpts.Compose(inline)
	}
	// 多跳跳板遵循 INV-D3（t1 > t4）：所有跳板均继承 CLI 安全/非交互/信任/加密策略覆盖
	// （cliOpts 携带由右向左归约的 ProxyRoute 覆盖，inline 携带跳板行内 user/port）；
	// 仅临时 AdHoc 跳板额外继承 CLI 认证兜底（IdentityFile/CertificateFile/IdentitiesOnly），
	// OpenSSH 虚拟跳板保留自身 t4 密钥配置。
	base := cliOpts.Compose(inline).Compose(cliJumpPolicy)
	if originKind == option.OriginAdHoc {
		return base.Compose(cliJumpAuthFallback)
	}
	return base
}

func (s *Service) resolveHopTier4(
	ctx context.Context,
	origHost option.OriginalHostSpec,
	originKind option.OriginKind,
	t1 option.OptionLayer,
) (option.OptionLayer, error) {
	if s.openSSH == nil {
		return option.UnsetOptionLayer(), nil
	}
	epOpt := deriveTier4CandidateEndpoint(origHost, originKind, t1.Compose(s.globalOptions))
	return s.openSSH.ResolveTier4(ctx, origHost, epOpt)
}

func deriveTier4CandidateEndpoint(
	origHost option.OriginalHostSpec,
	originKind option.OriginKind,
	probe option.OptionLayer,
) algebraic.Option[netaddr.Endpoint] {
	var host netaddr.CanonicalHost
	var hasHost bool
	if hn, ok := probe.HostName().Get(); ok {
		if resolved, err := hn.ResolveHostFor(origHost); err == nil {
			host, hasHost = resolved, true
		}
	} else if originKind == option.OriginAdHoc {
		host, hasHost = origHost.CanonicalHost()
	}
	if !hasHost {
		return algebraic.None[netaddr.Endpoint]()
	}
	ep, err := netaddr.NewEndpoint(host, probe.Port().OrElse(netaddr.DefaultSSHPort))
	if err != nil {
		return algebraic.None[netaddr.Endpoint]()
	}
	return algebraic.Some(ep)
}

func buildNodeOrigin(
	kind option.OriginKind,
	origHost option.OriginalHostSpec,
	vh ports.OpenSSHVirtualHost,
	foundVH bool,
) (inventory.NodeOrigin, error) {
	switch kind {
	case option.OriginOpenSSHVirtual:
		srcFile := ""
		if foundVH {
			srcFile = vh.SourceFile()
		}
		return inventory.NewOriginOpenSSHVirtual(origHost.String(), srcFile)
	case option.OriginAdHoc:
		return inventory.NewOriginAdHoc(algebraic.None[inventory.NodeID]())
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedOrigin, kind)
	}
}

// expandUpstreamJumps 严格按 OpenSSH 由右向左归约 ProxyJump 逗号链：
// 对 ProxyJump h_1,...,h_k 剥离紧邻上游 h_k，当 k > 1 时将前缀 h_1,...,h_{k-1} 作为 CLI ProxyRoute
// 覆写传入 h_k（覆盖 h_k 自身 t4 ProxyJump、逐跳累加 depth 并保持完整 activeStack 环路检测与 %j/%C）。
func (s *Service) expandUpstreamJumps(ctx context.Context, st *resolveState, route option.ProxyRoute, depth int) error {
	switch v := route.(type) {
	case nil, *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		return nil
	case *option.ProxyJumpChain:
		if !v.IsValid() {
			return fmt.Errorf("%w: 无效 ProxyJumpChain", ErrInvalidTarget)
		}
		hops := v.Hops().Slice()
		lastParsed, err := parseHopTargetSpec(hops[len(hops)-1])
		if err != nil {
			return err
		}
		upstreamCLI := option.UnsetOptionLayer()
		if len(hops) > 1 {
			prefixNE, neErr := algebraic.NonEmptyFromSlice(hops[:len(hops)-1])
			if neErr != nil {
				return fmt.Errorf("%w: %w", ErrInvalidTarget, neErr)
			}
			prefixRoute, prErr := option.NewProxyJumpChain(prefixNE)
			if prErr != nil {
				return fmt.Errorf("%w: %w", ErrInvalidTarget, prErr)
			}
			upstreamCLI = upstreamCLI.WithProxyRoute(prefixRoute)
		}
		_, _, err = s.resolveHopRecursive(
			ctx, st, lastParsed, upstreamCLI, algebraic.None[option.OriginKind](), nil, depth+1,
		)
		return err
	default:
		return fmt.Errorf("%w: 不支持的 ProxyRoute 变体 %T", ErrInvalidTarget, route)
	}
}

func (s *Service) appendResolvedHop(
	st *resolveState,
	nodeLabel string,
	policy option.EffectivePolicy,
	explicitAuth inventory.AuthMethod,
) error {
	if len(st.hops) >= maxPlanHops {
		return fmt.Errorf("%w: %w: 连接计划跳数超过上限 %d", ErrProxyJumpDepthExceeded, inventory.ErrProxyJumpDepthExceeded, maxPlanHops)
	}
	user, err := s.resolveHopUsername(policy)
	if err != nil {
		return err
	}
	auth, err := compileHopAuth(policy, user, s.env, explicitAuth)
	if err != nil {
		return err
	}
	hopSpec, err := plan.NewHopSpecFromAuth(uint32(len(st.hops)), nodeLabel, user, auth, policy)
	if err != nil {
		return err
	}
	st.hops = append(st.hops, hopSpec)
	return nil
}

func (s *Service) resolveHopUsername(policy option.EffectivePolicy) (option.Username, error) {
	if u, ok := policy.User().Get(); ok && u.IsValid() {
		return u, nil
	}
	if s.env != nil {
		id, err := s.env.LookupLocalIdentity()
		if err == nil && id.IsValid() {
			u, uErr := option.ParseUsername(id.LocalUser())
			if uErr == nil {
				return u, nil
			}
		}
	}
	return zeroVal[option.Username](), fmt.Errorf("%w: 请通过 user@、-l 或 OpenSSH User 指定用户名", ErrMissingUsername)
}

func hopCycleKeys(kind option.OriginKind, origHost option.OriginalHostSpec, ep netaddr.Endpoint) (aliasKey, epKey string) {
	return kind.String() + ":host:" + origHost.String(), "ep:" + ep.String()
}
