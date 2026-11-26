package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// ServiceConfig 定义资产与目标解析用例服务 Service 的显式出站依赖配置；
// Phase 3 扩展依赖均可选，以 100% 兼容 Phase 2.5 最小只读 ResolveTarget 装配。
type ServiceConfig struct {
	OpenSSH          ports.OpenSSHConfigSource
	Env              ports.EnvPort
	GlobalOptions    option.OptionLayer
	MaxJumpDepth     int
	Store            ports.InventoryStore
	Gate             gate.Authorizer
	Vault            ports.SecretVault
	VaultControl     ports.VaultControlPort
	KeySigner        ports.KeySignerPort
	Interaction      ports.InteractionPort
	Credential       *credential.Service
	Clock            ports.Clock
	Entropy          ports.Entropy
	Importers        []ports.FormatImporter
	KnownStores      []string
	DefaultEnrollTTL algebraic.Duration
}

// Service 是 XOps v2 全量资产管理、目标解析与首连登记用例服务；
// 零值恒未初始化并失败关闭，同时实现 credential.PendingSecretRefProvider。
//
//xops:opaque
//xops:failclosed
type Service struct {
	openSSH          ports.OpenSSHConfigSource
	env              ports.EnvPort
	globalOptions    option.OptionLayer
	maxJumpDepth     int
	store            ports.InventoryStore
	gate             gate.Authorizer
	vault            ports.SecretVault
	vaultControl     ports.VaultControlPort
	keySigner        ports.KeySignerPort
	interaction      ports.InteractionPort
	credSvc          *credential.Service
	clock            ports.Clock
	entropy          ports.Entropy
	importers        map[string]ports.FormatImporter
	knownStores      []string
	defaultEnrollTTL algebraic.Duration
	pendingMu        sync.Mutex
	activePins       map[security.OperationID][]inventory.PendingSecretRef
	valid            bool
}

// NewService 校验配置项并构造资产与目标解析 Service；仅提供 Phase 2.5 最小配置时完全兼容。
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := cfg.GlobalOptions.Validate(); err != nil {
		return nil, fmt.Errorf("%w: GlobalOptions 无效: %w", ErrInvalidConfig, err)
	}
	maxDepth := pickIf(cfg.MaxJumpDepth == 0, defaultMaxJumpDepth, cfg.MaxJumpDepth)
	if maxDepth < 0 || maxDepth > maxAllowedJumpDepth || cfg.DefaultEnrollTTL.IsNegative() {
		return nil, fmt.Errorf("%w: MaxJumpDepth=%d 越界或 DefaultEnrollTTL 为负", ErrInvalidConfig, cfg.MaxJumpDepth)
	}
	importers, err := buildImporterRegistry(cfg.Importers)
	var knownStores []string
	if err == nil {
		knownStores, err = normalizeKnownStores(cfg.KnownStores)
	}
	if err != nil {
		return nil, err
	}
	svc := &Service{
		openSSH: cfg.OpenSSH, env: cfg.Env, globalOptions: cfg.GlobalOptions.Compose(option.UnsetOptionLayer()),
		maxJumpDepth: maxDepth, store: cfg.Store, gate: cfg.Gate, vault: cfg.Vault, vaultControl: cfg.VaultControl,
		keySigner: cfg.KeySigner, interaction: cfg.Interaction, credSvc: cfg.Credential, clock: cfg.Clock, entropy: cfg.Entropy,
		importers: importers, knownStores: knownStores,
		defaultEnrollTTL: pickIf(cfg.DefaultEnrollTTL.IsZero(), algebraic.FromStdDuration(defaultPendingEnrollTTL), cfg.DefaultEnrollTTL),
		activePins:       make(map[security.OperationID][]inventory.PendingSecretRef), valid: true,
	}
	if svc.credSvc == nil && svc.gate != nil && svc.vault != nil && svc.clock != nil && svc.entropy != nil {
		if svc.credSvc, err = credential.NewService(credential.ServiceConfig{
			Gate: svc.gate, Vault: svc.vault, VaultControl: svc.vaultControl, Store: svc.store,
			Interaction: svc.interaction, Clock: svc.clock, Entropy: svc.entropy, PendingRefs: svc,
		}); err != nil {
			return nil, fmt.Errorf("%w: 初始化内置 CredentialService 失败: %w", ErrInvalidConfig, err)
		}
	}
	return svc, nil
}

// ActivePendingSecretRefs 返回当前全部活跃或 Uncertain 首连暂存租约钉住的凭据引用快照（实现 credential.PendingSecretRefProvider）。
func (s *Service) ActivePendingSecretRefs() []inventory.PendingSecretRef {
	if s == nil || !s.valid {
		return nil
	}
	out, _ := s.mergePendingRefsExcluding(zeroVal[security.OperationID](), nil)
	return out
}

func validateExtraPending(extra []inventory.PendingSecretRef) error {
	for i, p := range extra {
		if !p.Ref.IsValid() {
			return fmt.Errorf("%w: ExtraPending[%d] 包含无效 secret.Ref", ErrInvalidRequest, i)
		}
	}
	return nil
}
func (s *Service) mergePendingRefsExcluding(exclude security.OperationID, extra []inventory.PendingSecretRef) ([]inventory.PendingSecretRef, error) {
	if err := validateExtraPending(extra); err != nil {
		return nil, err
	}
	var out []inventory.PendingSecretRef
	if s != nil {
		s.pendingMu.Lock()
		for leaseID, pins := range s.activePins {
			if !exclude.IsValid() || !leaseID.Equal(exclude) {
				out = append(out, pins...)
			}
		}
		s.pendingMu.Unlock()
	}
	out = append(out, extra...)
	slices.SortFunc(out, func(a, b inventory.PendingSecretRef) int {
		return cmp.Or(cmp.Compare(a.OwnerID, b.OwnerID), a.Ref.Compare(b.Ref))
	})
	return out, nil
}
func (s *Service) requireStoreAndGate(ctx context.Context, risk algebraic.Option[security.RiskLevel]) error {
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	case ctx.Err() != nil:
		return ctx.Err()
	case s.store == nil:
		return ErrStoreUnavailable
	case s.gate == nil:
		return ErrGateUnavailable
	case risk.IsSome() && !risk.OrElse(zeroVal[security.RiskLevel]()).IsValid():
		return fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return nil
}

//xops:syncclosure
func runInspect[T any](ctx context.Context, s *Service, action, summary string, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream, fn func(context.Context) (T, error)) (out T, err error) {
	defer closeIfNonNil(stream)
	if err = s.requireStoreAndGate(ctx, risk); err != nil {
		return out, err
	}
	gateReq, err := credential.BuildGateRequest[security.CapInspect](security.CapabilityInspect, toolInventory, action, "", nil, risk.OrElse(security.RiskSafe), summary, approval, stream)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	err = gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(c context.Context, _ gate.Authorized[security.CapInspect]) (rErr error) {
		out, rErr = fn(c)
		return rErr
	})
	return out, err // 保留受权回调返回的诊断结构体（如 ValidateDAG.Cycles）；门控拒绝时 out 保持零值
}

//xops:syncclosure
func runMutate[T any](ctx context.Context, s *Service, action, nodeID, summary string, risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream, fn func(context.Context, security.TraceID, security.OperationID) (T, string, string, error)) (out T, err error) {
	defer closeIfNonNil(stream)
	if err = s.requireStoreAndGate(ctx, risk); err != nil {
		return out, err
	}
	gateReq, err := credential.BuildGateRequest[security.CapMutate](security.CapabilityMutate, toolInventory, action, nodeID, nil, risk.OrElse(security.RiskModerate), summary, approval, stream)
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	err = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(c context.Context, auth gate.Authorized[security.CapMutate]) (rErr error) {
		var unkCode, unkDetail string
		out, unkCode, unkDetail, rErr = fn(c, auth.TraceID(), auth.OperationID())
		_ = credential.ReportOutcomeUnknown(auth, unkCode, unkDetail)
		return rErr
	})
	return out, err
}
func (s *Service) collectOpenSSHJumpNodes(ctx context.Context) ([]inventory.OpenSSHJumpNode, error) {
	if s.openSSH == nil {
		return nil, nil
	}
	vhs, err := s.openSSH.ListVirtualHosts(ctx)
	if err != nil {
		return nil, err
	}
	return virtualHostsToJumpNodes(vhs)
}
func virtualHostsToJumpNodes(vhs []ports.OpenSSHVirtualHost) ([]inventory.OpenSSHJumpNode, error) {
	out := make([]inventory.OpenSSHJumpNode, 0, len(vhs))
	for _, vh := range vhs {
		if vh.IsValid() {
			jn, err := vh.JumpNode()
			if err != nil {
				return nil, err
			}
			out = append(out, jn)
		}
	}
	return out, nil
}

// resolveAuthoritativeKnownStores 查询实时权威凭据存储白名单：
// 若配置了 VaultControlPort 且 Status 失败则严格失败关闭报错；仅无实时存储源时才回退 base.KnownStores()。
func (s *Service) resolveAuthoritativeKnownStores(ctx context.Context, base inventory.Graph) ([]string, error) {
	var vaultStores []string
	if s.vaultControl != nil {
		st, err := s.vaultControl.Status(ctx)
		if err != nil {
			return nil, fmt.Errorf("查询凭据库权威存储表失败: %w", err)
		}
		vaultStores = st.KnownStores()
	}
	if live := credential.MergeSortedUniqueStrings(s.knownStores, vaultStores); len(live) > 0 {
		return live, nil
	}
	return base.KnownStores(), nil
}
func (s *Service) buildValidatedGraph(ctx context.Context, base inventory.Graph, hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node) (inventory.Graph, error) {
	openSSH, err := s.collectOpenSSHJumpNodes(ctx)
	if err != nil {
		return zeroVal[inventory.Graph](), err
	}
	return s.buildValidatedGraphWithOpenSSH(ctx, base, hosts, idents, nodes, openSSH)
}
func (s *Service) buildValidatedGraphWithOpenSSH(ctx context.Context, base inventory.Graph, hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node, openSSH []inventory.OpenSSHJumpNode) (inventory.Graph, error) {
	knownStores, err := s.resolveAuthoritativeKnownStores(ctx, base)
	if err != nil {
		return zeroVal[inventory.Graph](), err
	}
	return inventory.NewGraph(inventory.GraphSpec{
		Hosts: hosts, Identities: idents, Nodes: nodes,
		OpenSSHNodes: filterReachableOpenSSHNodes(nodes, openSSH), KnownStores: knownStores, MaxJumpDepth: s.maxJumpDepth,
	})
}

// filterReachableOpenSSHNodes 提取从托管节点 ProxyJump 边按跨命名空间规则可达的 OpenSSH 节点闭包：
// 既完整阻断跨命名空间 Tarjan 环路、悬空跳板与间接引用删除，又避免外部未引用 ~/.ssh/config 条目死锁创建。
func filterReachableOpenSSHNodes(nodes []inventory.Node, all []inventory.OpenSSHJumpNode) []inventory.OpenSSHJumpNode {
	if len(nodes) == 0 || len(all) == 0 {
		return nil
	}
	managed, byAlias := indexManagedNames(nodes), make(map[string]inventory.OpenSSHJumpNode, len(all))
	for _, on := range all {
		byAlias[on.Alias()] = on
	}
	seen, queue := make(map[string]bool), make([]string, 0)
	enqueue := func(route option.ProxyRoute, skipManaged bool) {
		for _, h := range proxyJumpHopHosts(route) {
			if _, ok := byAlias[h]; ok && (!skipManaged || !managed[h]) && !seen[h] {
				seen[h], queue = true, append(queue, h)
			}
		}
	}
	for _, n := range nodes {
		enqueue(n.EffectiveProxy(), true)
	}
	for len(queue) > 0 {
		cur := byAlias[queue[0]]
		queue = queue[1:]
		enqueue(cur.Proxy(), false)
	}
	return slices.DeleteFunc(slices.Clone(all), func(on inventory.OpenSSHJumpNode) bool { return !seen[on.Alias()] })
}
func indexManagedNames(nodes []inventory.Node) map[string]bool {
	managed := make(map[string]bool, len(nodes)*2)
	for _, n := range nodes {
		managed[n.ID().String()] = true
		for _, a := range n.Aliases() {
			managed[a.String()] = true
		}
	}
	return managed
}
func proxyJumpHopHosts(route option.ProxyRoute) []string {
	chain, ok := route.(*option.ProxyJumpChain)
	if !ok || !chain.IsValid() {
		return nil
	}
	hops := chain.Hops().Slice()
	out := make([]string, len(hops))
	for i, h := range hops {
		out[i] = h.Host()
	}
	return out
}
func (s *Service) loadSnapshotAt(ctx context.Context, expRev algebraic.Option[ports.Revision]) (ports.InventorySnapshot, error) {
	snap, err := s.store.Load(ctx)
	if err != nil {
		return zeroVal[ports.InventorySnapshot](), err
	}
	if exp, ok := expRev.Get(); ok && !snap.Revision().Equal(exp) {
		return zeroVal[ports.InventorySnapshot](), ports.ErrRevisionConflict
	}
	return snap, nil
}
func (s *Service) commitGraphCAS(ctx context.Context, baseRev ports.Revision, nextGraph inventory.Graph, missingCode string) (fsm.DurabilityStatus, ports.Revision, ports.DurabilityOutcome, string, error) {
	status, newRev, out, reason, commitErr := credential.CommitGraphCAS(ctx, s.store, baseRev, nextGraph)
	switch status {
	case fsm.DurabilityCommitted:
		return status, newRev, out, "", nil
	case fsm.DurabilityNotApplied:
		if errors.Is(commitErr, ports.ErrRevisionConflict) {
			return status, zeroVal[ports.Revision](), out, "", commitErr
		}
		return status, zeroVal[ports.Revision](), out, "", wrapCommitError(ErrCommitNotApplied, reason, commitErr)
	case fsm.DurabilityAppliedNotDurable:
		return status, zeroVal[ports.Revision](), out, "uncertain_durability", wrapCommitError(ErrUncertainDurability, reason, commitErr)
	default:
		code := pickIf(out.IsValid() && out.Status() == fsm.DurabilityCommitted && !newRev.IsValid(), missingCode, "commit_outcome_unknown")
		return fsm.DurabilityOutcomeUnknown, zeroVal[ports.Revision](), out, code, wrapCommitError(ErrCommitOutcomeUnknown, reason, commitErr)
	}
}
func wrapCommitError(sentinel error, detail string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %w", sentinel, cause)
	}
	return pickIf(detail != "", fmt.Errorf("%w: %s", sentinel, detail), sentinel)
}
func buildImporterRegistry(raw []ports.FormatImporter) (map[string]ports.FormatImporter, error) {
	reg := make(map[string]ports.FormatImporter, len(raw))
	for i, imp := range raw {
		if imp == nil || strings.TrimSpace(imp.Format()) == "" {
			return nil, fmt.Errorf("%w: Importers[%d] 为空或 Format() 为空", ErrInvalidConfig, i)
		}
		name := strings.ToLower(strings.TrimSpace(imp.Format()))
		if _, dup := reg[name]; dup {
			return nil, fmt.Errorf("%w: 重复注册导入格式 %q", ErrInvalidConfig, name)
		}
		reg[name] = imp
	}
	return reg, nil
}
func normalizeKnownStores(raw []string) ([]string, error) {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		t := strings.TrimSpace(s)
		if t == "" {
			return nil, fmt.Errorf("%w: KnownStores 不能包含空字符串", ErrInvalidConfig)
		}
		out = append(out, t)
	}
	return credential.MergeSortedUniqueStrings(out, nil), nil
}
