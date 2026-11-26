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

// ResolveTargetRequest 描述一次目标解析请求（兼容 Phase 2.5 只读切片并支持托管资产与显式来源覆盖）。
type ResolveTargetRequest struct {
	Target         string
	CLIOptions     option.OptionLayer
	ExplicitOrigin algebraic.Option[option.OriginKind]
	ExplicitAuth   inventory.AuthMethod
}

// ResolvedTarget 封装目标解析产出的不可变目标标识、来源、生效策略与多跳 Merkle 连接计划；零值恒无效。
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

type (
	managedGraphIndex struct {
		hosts         map[inventory.HostID]inventory.Host
		identities    map[inventory.IdentityID]inventory.Identity
		byID, byAlias map[string]inventory.Node
	}
	resolveState struct {
		managedIndex                       *managedGraphIndex
		virtualIndex                       map[string]ports.OpenSSHVirtualHost
		cliJumpPolicy, cliJumpAuthFallback option.OptionLayer
		activeStack                        map[string]bool
		hops                               []plan.HopSpec
		maxJumpDepth                       int
	}
	resolvedHopInputs struct {
		nodeLabel   string
		origin      inventory.NodeOrigin
		defaultPort uint16
		t1, t2, t4  option.OptionLayer
		auth        inventory.AuthMethod
	}
)

// ResolvedTarget 零值安全只读访问器（无效零值恒返回零值/OriginInvalid）。
func (r ResolvedTarget) IsValid() bool {
	return r.valid && r.nodeID != "" && r.origin != nil && r.origin.IsValid() && r.policy.IsValid() && r.plan.IsValid()
}
func (r ResolvedTarget) IsZero() bool                    { return !r.IsValid() }
func (r ResolvedTarget) NodeID() string                  { return r.nodeID }
func (r ResolvedTarget) Origin() inventory.NodeOrigin    { return r.origin }
func (r ResolvedTarget) Policy() option.EffectivePolicy  { return r.policy }
func (r ResolvedTarget) Plan() plan.SealedConnectionPlan { return r.plan }
func (r ResolvedTarget) OriginKind() option.OriginKind {
	if !r.IsValid() {
		return option.OriginInvalid
	}
	return r.origin.Kind()
}

// ResolveTarget 将目标规格、CLI 选项层、可选托管资产图与可选 OpenSSH 只读配置解析为不可变
// ResolvedTarget 与多跳 Merkle plan.SealedConnectionPlan（带环路检测与跳板深度上限护栏）。
func (s *Service) ResolveTarget(ctx context.Context, req ResolveTargetRequest) (ResolvedTarget, error) {
	var parsed parsedTarget
	var managedIdx *managedGraphIndex
	var vhIndex map[string]ports.OpenSSHVirtualHost
	err := s.validateResolveInputs(ctx, req)
	if err == nil {
		parsed, err = parseTargetSpec(req.Target)
	}
	if err == nil {
		managedIdx, err = s.loadManagedGraphIndex(ctx)
	}
	if err == nil {
		vhIndex, err = s.loadVirtualHostIndex(ctx)
	}
	if err != nil {
		return ResolvedTarget{}, err
	}
	st := &resolveState{
		managedIndex: managedIdx, virtualIndex: vhIndex,
		cliJumpPolicy: extractCLIJumpPolicy(req.CLIOptions), cliJumpAuthFallback: extractCLIJumpAuthFallback(req.CLIOptions),
		activeStack: make(map[string]bool), maxJumpDepth: s.maxJumpDepth,
	}
	nodeLabel, origin, policy, err := s.resolveHopRecursive(ctx, st, parsed, req.CLIOptions, req.ExplicitOrigin, req.ExplicitAuth, 0, false)
	var sealed plan.SealedConnectionPlan
	if err == nil {
		sealed, err = plan.SealConnectionPlan(st.hops...)
	}
	if err != nil {
		return ResolvedTarget{}, err
	}
	return ResolvedTarget{nodeID: nodeLabel, origin: origin, policy: policy, plan: sealed, valid: true}, nil
}
func (s *Service) validateResolveInputs(ctx context.Context, req ResolveTargetRequest) error {
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	case ctx.Err() != nil:
		return ctx.Err()
	case req.ExplicitAuth != nil && !req.ExplicitAuth.IsValid():
		return fmt.Errorf("%w: ExplicitAuth 无效", ErrNoAuthMethod)
	}
	if err := req.CLIOptions.Validate(); err != nil {
		return fmt.Errorf("%w: CLIOptions 无效: %w", ErrInvalidTarget, err)
	}
	if exp, ok := req.ExplicitOrigin.Get(); ok && !s.supportsExplicitOrigin(exp) {
		return fmt.Errorf("%w: 当前配置不支持目标来源=%s", ErrUnsupportedOrigin, exp)
	}
	return nil
}
func (s *Service) supportsExplicitOrigin(exp option.OriginKind) bool {
	return exp == option.OriginAdHoc || exp == option.OriginOpenSSHVirtual || (s.store != nil && (exp == option.OriginManaged || exp == option.OriginOpenSSHDerived))
}
func (s *Service) loadManagedGraphIndex(ctx context.Context) (*managedGraphIndex, error) {
	if s.store == nil {
		return nil, nil
	}
	snap, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	g := snap.Graph()
	idx := &managedGraphIndex{
		hosts: make(map[inventory.HostID]inventory.Host, len(g.Hosts())), identities: make(map[inventory.IdentityID]inventory.Identity, len(g.Identities())),
		byID: make(map[string]inventory.Node, len(g.Nodes())), byAlias: make(map[string]inventory.Node, len(g.Nodes())),
	}
	for _, h := range g.Hosts() {
		idx.hosts[h.ID()] = h
	}
	for _, id := range g.Identities() {
		idx.identities[id.ID()] = id
	}
	for _, n := range g.Nodes() {
		idx.byID[n.ID().String()] = n
		for _, a := range n.Aliases() {
			idx.byAlias[a.String()] = n
		}
	}
	return idx, nil
}
func (idx *managedGraphIndex) lookupManagedEntities(name string) (node inventory.Node, host inventory.Host, ident inventory.Identity, found bool, err error) {
	if idx == nil {
		return node, host, ident, false, nil
	}
	if node, found = idx.byID[name]; !found {
		node, found = idx.byAlias[name]
	}
	if !found {
		return node, host, ident, false, nil
	}
	host, okH := idx.hosts[node.HostRef()]
	ident, okI := idx.identities[node.IdentityRef()]
	if !okH || !okI {
		return zeroVal[inventory.Node](), zeroVal[inventory.Host](), zeroVal[inventory.Identity](), false, fmt.Errorf("%w: 节点 %q 引用的 Host/Identity 缺失", inventory.ErrMissingAssetRef, node.ID())
	}
	return node, host, ident, true, nil
}
func (s *Service) loadVirtualHostIndex(ctx context.Context) (map[string]ports.OpenSSHVirtualHost, error) {
	if s.openSSH == nil {
		return nil, nil
	}
	hosts, err := s.openSSH.ListVirtualHosts(ctx)
	if err != nil || len(hosts) == 0 {
		return nil, err
	}
	idx := make(map[string]ports.OpenSSHVirtualHost, len(hosts))
	for _, h := range hosts {
		if _, exists := idx[h.Alias()]; h.IsValid() && !exists {
			idx[h.Alias()] = h
		}
	}
	return idx, nil
}
func (s *Service) resolveHopRecursive(ctx context.Context, st *resolveState, pt parsedTarget, cliOpts option.OptionLayer, explicitOrigin algebraic.Option[option.OriginKind], explicitAuth inventory.AuthMethod, depth int, preferOpenSSH bool) (z1 string, z2 inventory.NodeOrigin, zp option.EffectivePolicy, err error) {
	if err = ctx.Err(); err != nil {
		return "", nil, zp, err
	}
	if depth > st.maxJumpDepth {
		return "", nil, zp, fmt.Errorf("%w: %w: ProxyJump 深度 %d 超过上限 %d", ErrProxyJumpDepthExceeded, inventory.ErrProxyJumpDepthExceeded, depth, st.maxJumpDepth)
	}
	hopIn, err := s.resolveHopInputs(ctx, st, pt, cliOpts, explicitOrigin, explicitAuth, depth, preferOpenSSH)
	var policy option.EffectivePolicy
	if err == nil {
		policy, err = option.ResolveEffectivePolicyWithOriginalHost(hopIn.origin.Kind(), pt.origHost, hopIn.defaultPort, hopIn.t1, hopIn.t2, s.globalOptions, hopIn.t4)
	}
	if err != nil {
		return "", nil, zp, err
	}
	aliasKey, epKey := hopIn.origin.Kind().String()+":node:"+hopIn.nodeLabel, "ep:"+policy.Endpoint().String()
	if st.activeStack[aliasKey] || st.activeStack[epKey] {
		return "", nil, zp, fmt.Errorf("%w: %w: 跳板目标 %s (%s) 存在循环引用", ErrProxyJumpCycle, inventory.ErrProxyJumpCycle, pt.origHost.String(), policy.Endpoint())
	}
	st.activeStack[aliasKey], st.activeStack[epKey] = true, true
	defer func() {
		delete(st.activeStack, aliasKey)
		delete(st.activeStack, epKey)
	}()
	if err = s.expandUpstreamJumps(ctx, st, policy.Proxy(), depth, hopIn.origin.Kind() == option.OriginOpenSSHVirtual); err == nil {
		err = s.appendResolvedHop(st, hopIn.nodeLabel, policy, hopIn.auth)
	}
	if err != nil {
		return "", nil, zp, err
	}
	return hopIn.nodeLabel, hopIn.origin, policy, nil
}
func (s *Service) resolveHopInputs(ctx context.Context, st *resolveState, pt parsedTarget, cliOpts option.OptionLayer, explicitOrigin algebraic.Option[option.OriginKind], explicitAuth inventory.AuthMethod, depth int, preferOpenSSH bool) (resolvedHopInputs, error) {
	vh, foundVH := st.virtualIndex[pt.origHost.String()]
	if !preferOpenSSH || explicitOrigin.IsSome() || !foundVH {
		if managed, ok, err := s.tryResolveManagedHop(ctx, st, pt, cliOpts, explicitOrigin, explicitAuth, depth); err != nil || ok {
			return managed, err
		}
	}
	originKind := explicitOrigin.OrElse(pickIf(foundVH, option.OriginOpenSSHVirtual, option.OriginAdHoc))
	t4, err := s.resolveHopTier4(ctx, pt.origHost, originKind, cliOpts.Compose(pt.inlineLayer()))
	if err == nil && explicitOrigin.IsNone() && originKind == option.OriginAdHoc && t4.HostName().IsSome() {
		if _, isCanon := pt.origHost.CanonicalHost(); !isCanon {
			originKind = option.OriginOpenSSHVirtual
		}
	}
	var nodeOrigin inventory.NodeOrigin
	if err == nil {
		nodeOrigin, err = buildNodeOrigin(originKind, pt.origHost, vh, foundVH)
	}
	if err != nil {
		return resolvedHopInputs{}, err
	}
	return resolvedHopInputs{
		nodeLabel: pt.origHost.String(), origin: nodeOrigin, defaultPort: netaddr.DefaultSSHPort,
		t1: buildHopTier1(pt, cliOpts, st.cliJumpPolicy, st.cliJumpAuthFallback, originKind, depth), t2: option.UnsetOptionLayer(), t4: t4, auth: explicitAuth,
	}, nil
}
func (s *Service) tryResolveManagedHop(ctx context.Context, st *resolveState, pt parsedTarget, cliOpts option.OptionLayer, explicitOrigin algebraic.Option[option.OriginKind], explicitAuth inventory.AuthMethod, depth int) (resolvedHopInputs, bool, error) {
	exp, hasExp := explicitOrigin.Get()
	if hasExp && exp != option.OriginManaged && exp != option.OriginOpenSSHDerived {
		return resolvedHopInputs{}, false, nil
	}
	node, host, ident, found, err := st.managedIndex.lookupManagedEntities(pt.origHost.String())
	if err != nil {
		return resolvedHopInputs{}, false, err
	}
	if !found {
		if hasExp {
			return resolvedHopInputs{}, false, fmt.Errorf("%w: 未找到托管节点 %q", ErrAssetNotFound, pt.origHost.String())
		}
		return resolvedHopInputs{}, false, nil
	}
	if hasExp && node.Origin().Kind() != exp {
		return resolvedHopInputs{}, false, fmt.Errorf("%w: 节点 %q 实际来源=%s，期望=%s", ErrUnsupportedOrigin, node.ID(), node.Origin().Kind(), exp)
	}
	return s.buildManagedHopInputs(ctx, st, pt, cliOpts, explicitAuth, depth, node, host, ident)
}
func (s *Service) buildManagedHopInputs(ctx context.Context, st *resolveState, pt parsedTarget, cliOpts option.OptionLayer, explicitAuth inventory.AuthMethod, depth int, node inventory.Node, host inventory.Host, ident inventory.Identity) (resolvedHopInputs, bool, error) {
	hn, err := option.HostNameSpecFromHost(host.Endpoint().Host())
	if err != nil {
		return resolvedHopInputs{}, false, err
	}
	origin := node.Origin()
	t2 := option.UnsetOptionLayer().WithHostName(hn).WithPort(host.Endpoint().Port()).WithUser(ident.User()).WithProxyRoute(node.EffectiveProxy()).Compose(node.Options())
	t1 := buildHopTier1(pt, cliOpts, st.cliJumpPolicy, st.cliJumpAuthFallback, origin.Kind(), depth)
	t4Host := pt.origHost
	if derived, ok := origin.(*inventory.OriginOpenSSHDerived); ok && derived.IsValid() {
		if spec, pErr := option.ParseOriginalHost(derived.BaseAlias()); pErr == nil {
			t4Host = spec
		}
	}
	t4, err := s.resolveHopTier4(ctx, t4Host, origin.Kind(), t1.Compose(t2))
	if err != nil {
		return resolvedHopInputs{}, false, err
	}
	auth := explicitAuth
	if auth == nil && (depth > 0 || (!cliOpts.IdentityFiles().IsSet() && !cliOpts.IdentityFiles().IsDisabled())) {
		auth = ident.Auth()
	}
	return resolvedHopInputs{nodeLabel: node.ID().String(), origin: origin, defaultPort: host.Endpoint().Port(), t1: t1, t2: t2, t4: t4, auth: auth}, true, nil
}
func buildHopTier1(pt parsedTarget, cliOpts, cliJumpPolicy, cliJumpAuthFallback option.OptionLayer, originKind option.OriginKind, depth int) option.OptionLayer {
	if depth == 0 {
		return cliOpts.Compose(pt.inlineLayer())
	}
	base := cliOpts.Compose(pt.inlineLayer()).Compose(cliJumpPolicy)
	return pickIf(originKind == option.OriginAdHoc, base.Compose(cliJumpAuthFallback), base)
}
func (s *Service) resolveHopTier4(ctx context.Context, origHost option.OriginalHostSpec, originKind option.OriginKind, probeLayer option.OptionLayer) (option.OptionLayer, error) {
	if s.openSSH == nil {
		return option.UnsetOptionLayer(), nil
	}
	return s.openSSH.ResolveTier4(ctx, origHost, deriveTier4CandidateEndpoint(origHost, originKind, probeLayer.Compose(s.globalOptions)))
}
func deriveTier4CandidateEndpoint(origHost option.OriginalHostSpec, originKind option.OriginKind, probe option.OptionLayer) algebraic.Option[netaddr.Endpoint] {
	var host netaddr.CanonicalHost
	var ok bool
	if hn, hasHN := probe.HostName().Get(); hasHN {
		resolved, err := hn.ResolveHostFor(origHost)
		host, ok = resolved, err == nil
	} else if originKind == option.OriginAdHoc {
		host, ok = origHost.CanonicalHost()
	}
	if ep, err := netaddr.NewEndpoint(host, probe.Port().OrElse(netaddr.DefaultSSHPort)); ok && err == nil {
		return algebraic.Some(ep)
	}
	return algebraic.None[netaddr.Endpoint]()
}
func buildNodeOrigin(kind option.OriginKind, origHost option.OriginalHostSpec, vh ports.OpenSSHVirtualHost, foundVH bool) (inventory.NodeOrigin, error) {
	switch kind {
	case option.OriginOpenSSHVirtual:
		return inventory.NewOriginOpenSSHVirtual(origHost.String(), pickIf(foundVH, vh.SourceFile(), ""))
	case option.OriginAdHoc:
		return inventory.NewOriginAdHoc(algebraic.None[inventory.NodeID]())
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedOrigin, kind)
	}
}
func (s *Service) expandUpstreamJumps(ctx context.Context, st *resolveState, route option.ProxyRoute, depth int, preferOpenSSH bool) error {
	switch v := route.(type) {
	case nil, *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		return nil
	case *option.ProxyJumpChain:
		if !v.IsValid() {
			return fmt.Errorf("%w: 无效 ProxyJumpChain", ErrInvalidTarget)
		}
		hops := v.Hops().Slice()
		lastParsed, err := parseHopTargetSpec(hops[len(hops)-1])
		var upstreamCLI option.OptionLayer
		if err == nil {
			upstreamCLI, err = buildPrefixJumpLayer(hops[:len(hops)-1])
		}
		if err == nil {
			_, _, _, err = s.resolveHopRecursive(ctx, st, lastParsed, upstreamCLI, algebraic.None[option.OriginKind](), nil, depth+1, preferOpenSSH)
		}
		return err
	default:
		return fmt.Errorf("%w: 不支持的 ProxyRoute 变体 %T", ErrInvalidTarget, route)
	}
}
func buildPrefixJumpLayer(prefix []option.HopTarget) (option.OptionLayer, error) {
	if len(prefix) == 0 {
		return option.UnsetOptionLayer(), nil
	}
	ne, err := algebraic.NonEmptyFromSlice(prefix)
	var r *option.ProxyJumpChain
	if err == nil {
		r, err = option.NewProxyJumpChain(ne)
	}
	if err != nil {
		return option.UnsetOptionLayer(), fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	return option.UnsetOptionLayer().WithProxyRoute(r), nil
}
func (s *Service) appendResolvedHop(st *resolveState, nodeLabel string, policy option.EffectivePolicy, explicitAuth inventory.AuthMethod) error {
	if len(st.hops) >= maxPlanHops {
		return fmt.Errorf("%w: %w: 连接计划跳数超过上限 %d", ErrProxyJumpDepthExceeded, inventory.ErrProxyJumpDepthExceeded, maxPlanHops)
	}
	user, err := s.resolveHopUsername(policy)
	var auth inventory.AuthMethod
	var hopSpec plan.HopSpec
	if err == nil {
		auth, err = compileHopAuth(policy, user, s.env, explicitAuth)
	}
	if err == nil {
		hopSpec, err = plan.NewHopSpecFromAuth(uint32(len(st.hops)), nodeLabel, user, auth, policy)
	}
	if err == nil {
		st.hops = append(st.hops, hopSpec)
	}
	return err
}
func (s *Service) resolveHopUsername(policy option.EffectivePolicy) (option.Username, error) {
	if u, ok := policy.User().Get(); ok && u.IsValid() {
		return u, nil
	}
	if s.env != nil {
		if id, err := s.env.LookupLocalIdentity(); err == nil && id.IsValid() {
			if u, uErr := option.ParseUsername(id.LocalUser()); uErr == nil {
				return u, nil
			}
		}
	}
	return zeroVal[option.Username](), fmt.Errorf("%w: 请通过 user@、-l 或 OpenSSH User 指定用户名", ErrMissingUsername)
}
