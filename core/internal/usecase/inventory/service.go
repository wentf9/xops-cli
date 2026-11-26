package inventory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/usecase/credential"
	"github.com/wentf9/xops-cli/core/ports"
)

// ServiceConfig 定义资产与目标解析用例服务 Service 的显式出站依赖配置；Phase 3 扩展依赖均可选以保持 Phase 2.5 100% 兼容。
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

// Service 是 XOps v2 全量资产管理、目标解析与首连登记用例服务；零值恒未初始化并失败关闭，同时实现 credential.PendingSecretRefProvider。
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
	if err != nil {
		return nil, err
	}
	knownStores, err := normalizeKnownStores(cfg.KnownStores)
	if err != nil {
		return nil, err
	}
	svc := &Service{
		cfg.OpenSSH, cfg.Env, cfg.GlobalOptions.Compose(option.UnsetOptionLayer()), maxDepth,
		cfg.Store, cfg.Gate, cfg.Vault, cfg.VaultControl, cfg.KeySigner, cfg.Interaction, cfg.Credential,
		cfg.Clock, cfg.Entropy, importers, knownStores,
		pickIf(cfg.DefaultEnrollTTL.IsZero(), algebraic.FromStdDuration(defaultPendingEnrollTTL), cfg.DefaultEnrollTTL),
		sync.Mutex{}, make(map[security.OperationID][]inventory.PendingSecretRef), true,
	}
	if svc.credSvc == nil && svc.gate != nil && svc.vault != nil && svc.clock != nil && svc.entropy != nil {
		autoCred, cErr := credential.NewService(credential.ServiceConfig{
			Gate: svc.gate, Vault: svc.vault, VaultControl: svc.vaultControl, Store: svc.store,
			Interaction: svc.interaction, Clock: svc.clock, Entropy: svc.entropy, PendingRefs: svc,
		})
		if cErr != nil {
			return nil, fmt.Errorf("%w: 初始化内置 CredentialService 失败: %w", ErrInvalidConfig, cErr)
		}
		svc.credSvc = autoCred
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

func (s *Service) mergePendingRefsExcluding(exclude security.OperationID, extra []inventory.PendingSecretRef) ([]inventory.PendingSecretRef, error) {
	for i, p := range extra {
		if !p.Ref.IsValid() {
			return nil, fmt.Errorf("%w: ExtraPending[%d] 包含无效 secret.Ref", ErrInvalidRequest, i)
		}
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
	}
	if r, ok := risk.Get(); ok && !r.IsValid() {
		return fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return nil
}

//xops:syncclosure
func runInspect[T any](
	ctx context.Context, s *Service, action, summary string,
	risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream, fn func(authCtx context.Context) (T, error),
) (T, error) {
	defer closeIfNonNil(stream)
	if err := s.requireStoreAndGate(ctx, risk); err != nil {
		return zeroVal[T](), err
	}
	gateReq, err := buildGateReq[security.CapInspect](security.CapabilityInspect, action, "", nil, risk.OrElse(security.RiskSafe), summary, approval, stream)
	if err != nil {
		return zeroVal[T](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var out T
	err = gate.WithAuthorized[security.CapInspect](ctx, s.gate, gateReq, func(authCtx context.Context, _ gate.Authorized[security.CapInspect]) error {
		var runErr error
		out, runErr = fn(authCtx)
		return runErr
	})
	return pickIf(err == nil, out, zeroVal[T]()), err
}

//xops:syncclosure
func runMutate[T any](
	ctx context.Context, s *Service, action, nodeID, summary string,
	risk algebraic.Option[security.RiskLevel], approval algebraic.Option[gate.ApprovalSubmission],
	stream *events.OperationStream,
	fn func(authCtx context.Context, traceID security.TraceID, opID security.OperationID) (T, string, string, error),
) (T, error) {
	defer closeIfNonNil(stream)
	if err := s.requireStoreAndGate(ctx, risk); err != nil {
		return zeroVal[T](), err
	}
	gateReq, err := buildGateReq[security.CapMutate](security.CapabilityMutate, action, nodeID, nil, risk.OrElse(security.RiskModerate), summary, approval, stream)
	if err != nil {
		return zeroVal[T](), fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	var out T
	err = gate.WithAuthorized[security.CapMutate](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[security.CapMutate]) error {
		var unkCode, unkDetail string
		var runErr error
		out, unkCode, unkDetail, runErr = fn(authCtx, auth.TraceID(), auth.OperationID())
		reportUnknownOutcome(auth, unkCode, unkDetail)
		return runErr
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
		if !vh.IsValid() {
			continue
		}
		jn, err := vh.JumpNode()
		if err != nil {
			return nil, err
		}
		out = append(out, jn)
	}
	return out, nil
}
func (s *Service) buildValidatedGraph(ctx context.Context, base inventory.Graph, hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node) (inventory.Graph, error) {
	openSSHNodes, err := s.collectOpenSSHJumpNodes(ctx)
	if err != nil {
		return zeroVal[inventory.Graph](), err
	}
	var vaultStores []string
	if s.vaultControl != nil {
		if st, sErr := s.vaultControl.Status(ctx); sErr == nil && st.IsValid() {
			vaultStores = st.KnownStores()
		}
	}
	reachableOpenSSH := filterReachableOpenSSHNodes(nodes, openSSHNodes)
	return inventory.NewGraph(inventory.GraphSpec{Hosts: hosts, Identities: idents, Nodes: nodes, OpenSSHNodes: reachableOpenSSH, KnownStores: mergeUniqueStrings(base.KnownStores(), s.knownStores, vaultStores), MaxJumpDepth: s.maxJumpDepth})
}

// filterReachableOpenSSHNodes 仅提取从托管节点 ProxyJump 边按跨命名空间规则可达的 OpenSSH 节点闭包：
// 既保留跨命名空间 Tarjan 环路与悬空跳板强校验，又避免未被引用的外部 ~/.ssh/config 条目死锁托管资产创建。
func filterReachableOpenSSHNodes(nodes []inventory.Node, all []inventory.OpenSSHJumpNode) []inventory.OpenSSHJumpNode {
	if len(nodes) == 0 || len(all) == 0 {
		return nil
	}
	managed, byAlias := indexManagedNames(nodes), make(map[string]inventory.OpenSSHJumpNode, len(all))
	for _, on := range all {
		byAlias[on.Alias()] = on
	}
	seen, queue := seedReachableOpenSSH(nodes, managed, byAlias)
	for len(queue) > 0 {
		cur := byAlias[queue[0]]
		queue = queue[1:]
		for _, h := range proxyJumpHopHosts(cur.Proxy()) {
			if _, ok := byAlias[h]; ok && !seen[h] {
				seen[h], queue = true, append(queue, h)
			}
		}
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
func seedReachableOpenSSH(nodes []inventory.Node, managed map[string]bool, byAlias map[string]inventory.OpenSSHJumpNode) (map[string]bool, []string) {
	seen, queue := make(map[string]bool), make([]string, 0)
	for _, n := range nodes {
		for _, h := range proxyJumpHopHosts(n.EffectiveProxy()) {
			if _, ok := byAlias[h]; !managed[h] && ok && !seen[h] {
				seen[h], queue = true, append(queue, h)
			}
		}
	}
	return seen, queue
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
func mergeUniqueStrings(groups ...[]string) []string {
	out := slices.Concat(groups...)
	slices.Sort(out)
	return slices.Compact(out)
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
func (s *Service) commitGraphCAS(ctx context.Context, baseRev ports.Revision, nextGraph inventory.Graph, missingCode string) (ports.Revision, ports.DurabilityOutcome, string, error) {
	rawOut, commitErr := s.store.CommitCAS(ctx, baseRev, nextGraph)
	out, unkCode, err := interpretDurabilityOutcome(rawOut, commitErr)
	if err != nil {
		return zeroVal[ports.Revision](), out, unkCode, err
	}
	if newRev, ok := out.Revision().Get(); ok && newRev.IsValid() {
		return newRev, out, "", nil
	}
	return zeroVal[ports.Revision](), out, missingCode, fmt.Errorf("%w: DurabilityCommitted 缺少有效 Revision", ErrCommitOutcomeUnknown)
}
func buildGateReq[C security.Capability](capKind security.CapabilityKind, action, nodeID string, params map[string]string, risk security.RiskLevel, summary string, approval algebraic.Option[gate.ApprovalSubmission], stream *events.OperationStream) (gate.GateRequest[C], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{Capability: capKind, Tool: toolInventory, Action: action, NodeID: nodeID, Parameters: params})
	if err != nil {
		return zeroVal[gate.GateRequest[C]](), err
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{Binding: binding, Risk: risk, ScopeSummary: summary, Approval: approval, OperationStream: stream})
}
func interpretDurabilityOutcome(out ports.DurabilityOutcome, commitErr error) (ports.DurabilityOutcome, string, error) {
	if out.IsValid() {
		switch out.Status() {
		case fsm.DurabilityCommitted:
			return out, "", commitErr
		case fsm.DurabilityNotApplied:
			return out, "", wrapCommitError(ErrCommitNotApplied, out.Detail(), commitErr)
		case fsm.DurabilityAppliedNotDurable:
			return out, "uncertain_durability", wrapCommitError(ErrUncertainDurability, out.Detail(), commitErr)
		case fsm.DurabilityOutcomeUnknown:
			return out, "commit_outcome_unknown", wrapCommitError(ErrCommitOutcomeUnknown, out.Detail(), commitErr)
		}
	}
	if errors.Is(commitErr, ports.ErrRevisionConflict) {
		return zeroVal[ports.DurabilityOutcome](), "", commitErr
	}
	if errors.Is(commitErr, ports.ErrInvalidArgument) || errors.Is(commitErr, ports.ErrInvalidRevision) || errors.Is(commitErr, ports.ErrPermissionDenied) || errors.Is(commitErr, ports.ErrLimitExceeded) {
		return zeroVal[ports.DurabilityOutcome](), "", fmt.Errorf("%w: %w", ErrCommitNotApplied, commitErr)
	}
	return zeroVal[ports.DurabilityOutcome](), "commit_outcome_unknown", wrapCommitError(ErrCommitOutcomeUnknown, "invalid durability outcome", commitErr)
}
func reportUnknownOutcome(auth gate.Authorized[security.CapMutate], code, detail string) {
	if code != "" && auth.IsValid() {
		if unk, uErr := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, code, detail); uErr == nil {
			_ = auth.ReportOutcome(unk)
		}
	}
}
func wrapCommitError(sentinel error, detail string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %w", sentinel, cause)
	}
	return pickIf[error](detail != "", fmt.Errorf("%w: %s", sentinel, detail), sentinel)
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
	slices.Sort(out)
	return slices.Compact(out), nil
}

type invOpEmitter struct {
	stream  *events.OperationStream
	clock   ports.Clock
	traceID security.TraceID
	opID    security.OperationID
	nodeID  algebraic.Option[inventory.NodeID]
	seq     atomic.Uint64
}

func newInvOpEmitter(stream *events.OperationStream, clock ports.Clock, traceID security.TraceID, opID security.OperationID, nodeID inventory.NodeID) *invOpEmitter {
	if stream == nil || clock == nil {
		return nil
	}
	return &invOpEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, nodeID: algebraic.Some(nodeID)}
}
func (e *invOpEmitter) emit(ctx context.Context, build func(events.EventMeta) (events.Event, error)) {
	if e == nil || e.stream == nil || e.stream.IsClosed() {
		return
	}
	if meta, err := events.NewEventMeta(events.EventMetaSpec{TraceID: e.traceID, OperationID: algebraic.Some(e.opID), OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: e.nodeID}); err == nil {
		if ev, eErr := build(meta); eErr == nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}
func (e *invOpEmitter) emitLifecycle(ctx context.Context, action, summary string, startedAt algebraic.Option[time.Time], finalErr error) {
	if start, isDone := startedAt.Get(); isDone {
		emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
		defer cancel()
		e.emit(emitCtx, func(m events.EventMeta) (events.Event, error) {
			return events.NewOperationCompletedEvent(events.OperationCompletedSpec{
				Meta: m, Capability: security.CapabilityMutate, Duration: algebraic.FromStdDuration(max(e.clock.Since(start), 0)),
				Succeeded: finalErr == nil, Code: pickIf(finalErr == nil, "", "inventory_error"), Message: pickIf(finalErr == nil, "completed", fmt.Sprint(finalErr)),
			})
		})
		return
	}
	e.emit(ctx, func(m events.EventMeta) (events.Event, error) {
		return events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: m, Capability: security.CapabilityMutate, Tool: toolInventory, Action: action, Summary: summary})
	})
}
