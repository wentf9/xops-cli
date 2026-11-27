package transfer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

type transferHandleTable struct {
	mu    sync.Mutex
	items map[security.OperationID]plan.ManagedHandle[plan.KindTransfer]
}

func (t *transferHandleTable) get(tid security.OperationID) (plan.ManagedHandle[plan.KindTransfer], bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	h, ok := t.items[tid]
	return h, ok
}
func (t *transferHandleTable) tryPut(tid security.OperationID, h plan.ManagedHandle[plan.KindTransfer]) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, dup := t.items[tid]; dup {
		return false
	}
	t.items[tid] = h
	return true
}
func (t *transferHandleTable) drop(tid security.OperationID, h plan.ManagedHandle[plan.KindTransfer]) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.items[tid]; ok && cur.Equal(h) {
		delete(t.items, tid)
	}
}

// Service 是 XOps v2 全量文件传输与远端文件用例服务（ADR-007 / ADR-008 / ADR-009 / ADR-016 / Plan P3-T3）；
// 零值恒未初始化且全部导出方法均严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Service struct {
	gate                                  gate.Authorizer
	pool                                  *pool.Pool
	clock                                 ports.Clock
	entropy                               ports.Entropy
	scopedFS                              ports.ScopedRootFS
	operatorReadFS                        ports.OperatorReadFS
	journals                              ports.JournalStore
	bus                                   *events.SystemBus
	defaultChunkSize, defaultMaxReadBytes int64
	defaultConcurrency                    int
	handles                               *transferHandleTable
	valid                                 bool
}

// NewService 严格校验必填依赖与限流上下界，构造不可绕过能力门控的 transfer.Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil || cfg.Pool == nil || cfg.Pool.IsClosed() || cfg.Clock == nil || cfg.Entropy == nil || (cfg.SystemBus != nil && cfg.SystemBus.IsClosed()) {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonMissingDep, domi18n.Str("component", "Gate/Pool/Clock/Entropy"))
	}
	cs, conc, maxRead := pickIf(cfg.DefaultChunkSize == 0, defaultChunkSize, cfg.DefaultChunkSize), pickIf(cfg.DefaultConcurrency == 0, defaultConcurrency, cfg.DefaultConcurrency), pickIf(cfg.DefaultMaxReadBytes == 0, defaultMaxReadBytes, cfg.DefaultMaxReadBytes)
	if cs < minChunkSize || cs > int64(fsm.MaxTransferChunkBytes) || conc < 1 || conc > maxConcurrency || maxRead <= 0 || maxRead > maxAtomicReadBytes {
		return nil, domi18n.EF(ErrInvalidConfig, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "default_limits"))
	}
	return &Service{gate: cfg.Gate, pool: cfg.Pool, clock: cfg.Clock, entropy: cfg.Entropy, scopedFS: cfg.ScopedFS, operatorReadFS: cfg.OperatorReadFS, journals: cfg.Journals, bus: cfg.SystemBus, defaultChunkSize: cs, defaultConcurrency: conc, defaultMaxReadBytes: maxRead, handles: &transferHandleTable{items: map[security.OperationID]plan.ManagedHandle[plan.KindTransfer]{}}, valid: true}, nil
}

// WithoutOperatorReadFS 返回共享同一活跃受管句柄表但物理剥离 OperatorReadFS（恒为 nil）的沙箱视图，
// 消除同进程嵌入式 MCPServer 与 Engine 间的 InspectTransfer 视角分裂并维持 MCP 零 OperatorReadFS 物理隔离。
func (s *Service) WithoutOperatorReadFS() *Service {
	if s == nil || !s.valid || s.operatorReadFS == nil {
		return s
	}
	cp := *s
	cp.operatorReadFS = nil
	return &cp
}
func zeroVal[T any]() (z T) { return z }
func closeStream(st *events.OperationStream) {
	if st != nil {
		st.Close()
	}
}
func (s *Service) strictPaths() bool { return s.gate.Profile() != gate.PolicyProfileDirectOperator }
func validRFC3339(t time.Time) bool  { y := t.UTC().Year(); return !t.IsZero() && y >= 1 && y <= 9999 }
func pickIf[T any](c bool, yes, no T) T {
	if c {
		return yes
	}
	return no
}
func digestFromHash(h hash.Hash) security.Digest {
	return security.DigestFromSHA256([sha256.Size]byte(h.Sum(nil)))
}
func errText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
func sendOrDone[T any](ctx context.Context, ch chan<- T, v T) error {
	select {
	case ch <- v:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Service) checkReadyCtx(ctx context.Context) error {
	if s == nil || !s.valid || ctx == nil {
		return pickIf(s == nil || !s.valid, ErrServiceNotInitialized, ErrNilContext)
	}
	return ctx.Err()
}
func (s *Service) validateBaseCall(ctx context.Context, base CallBase) (plan.HopSpec, error) {
	hop, ok := base.Plan.Target()
	r, hasR := base.Risk.Get()
	err := firstErr(s.checkReadyCtx(ctx), pickIf[error](!base.Plan.IsValid() || !ok || !hop.IsValid() || (hasR && !r.IsValid()), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "SealedConnectionPlan/RiskLevel")), nil))
	return pickIf(err == nil, hop, zeroVal[plan.HopSpec]()), err
}
func (s *Service) validateRemotePathOp(ctx context.Context, base CallBase, p pathalg.RemotePath) (plan.HopSpec, error) {
	hop, err := s.validateBaseCall(ctx, base)
	return hop, firstErr(err, pickIf[error](p.IsValid(), nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "RemotePath"))))
}
func (s *Service) resolveChunkAndConcurrency(chunkSize int64, concurrency int) (int64, int, error) {
	cs, conc := pickIf(chunkSize == 0, s.defaultChunkSize, chunkSize), pickIf(concurrency == 0, s.defaultConcurrency, concurrency)
	return cs, conc, pickIf[error](cs < minChunkSize || cs > int64(fsm.MaxTransferChunkBytes) || conc < 1 || conc > maxConcurrency, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ChunkSize/Concurrency")), nil)
}
func (s *Service) resolveReadLimits(maxBytes int64) (ports.ReadLimits, error) {
	if s == nil || !s.valid {
		return zeroVal[ports.ReadLimits](), ErrServiceNotInitialized
	}
	if lim := pickIf(maxBytes == 0, s.defaultMaxReadBytes, maxBytes); lim > 0 && lim <= maxAtomicReadBytes {
		return ports.NewReadLimits(lim)
	}
	return zeroVal[ports.ReadLimits](), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldRange, domi18n.Str("field", "MaxBytes"), domi18n.Int64("value", maxBytes), domi18n.Int64("min", 1), domi18n.Int64("max", maxAtomicReadBytes))
}
func resolvePerm(opt algebraic.Option[fs.FileMode], fallback fs.FileMode) (fs.FileMode, error) {
	perm, ok := opt.Get()
	return pickIf(ok, perm, fallback), pickIf[error](ok && (perm == 0 || perm != perm.Perm()), domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonPermInvalid, domi18n.Str("perm", fmt.Sprintf("%#o", perm))), nil)
}

type authOpSpec struct {
	base                  CallBase
	targetHop             plan.HopSpec
	tool, action, summary string
	paths, recursivePaths []pathalg.RemotePath
	expandBase            string
	extraPaths            []string
	params                map[string]string
	defaultRisk           security.RiskLevel
	canonicalize          bool
	customCanon           gate.CanonicalizeFunc
}

// runAuthorizedVal 统一封装最外层 gate.WithAuthorized[C] 与 OperationStream 生命周期（Started/Completed + 确定性 EOF，含 panic 与无 Plan 的全局恢复路径）。
//
//xops:syncclosure
func runAuthorizedVal[C security.Capability, T any](ctx context.Context, s *Service, spec authOpSpec, fn func(context.Context, gate.Authorized[C], *transferEmitter) (T, error)) (out T, finalErr error) {
	defer closeStream(spec.base.OperationStream)
	capKind, nodeID := security.CapabilityKindOf[C](), pickIf(spec.base.NodeID != "", spec.base.NodeID, spec.targetHop.NodeID())
	gateReq, err := buildGateRequest[C](s, spec, capKind, nodeID)
	if err != nil {
		return out, err
	}
	var emitter *transferEmitter
	startedAt, entered := s.clock.Now().UTC().Round(0), false
	finalErr = gate.ErrOperationPanicked
	defer func() {
		if entered {
			emitter.emitCompleted(ctx, startedAt, finalErr)
		}
	}()
	planDig := pickIf(spec.base.Plan.IsValid(), algebraic.Some(spec.base.Plan.PlanDigest()), algebraic.None[plan.PlanDigest]())
	finalErr = gate.WithAuthorized[C](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[C]) (fErr error) {
		entered, startedAt, emitter = true, s.clock.Now().UTC().Round(0), newTransferEmitter(spec.base.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), capKind, nodeID)
		emitter.emitBuilt(authCtx, func(m events.EventMeta) (events.Event, error) {
			return events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: m, Capability: capKind, Tool: spec.tool, Action: spec.action, PlanDigest: planDig, Summary: spec.summary})
		})
		out, fErr = fn(authCtx, auth, emitter)
		return fErr
	})
	return out, finalErr
}

// withLeasedRemoteFS 在池租约作用域内借出 RemoteFSPort 并在退出前无条件关闭。
//
//xops:syncclosure
func (s *Service) withLeasedRemoteFS(ctx context.Context, p plan.SealedConnectionPlan, fn func(context.Context, ports.RemoteFSPort) error) error {
	return s.pool.WithLease(ctx, p, func(leaseCtx context.Context, lease *pool.Lease) error {
		rfs, err := lease.OpenRemoteFS(leaseCtx)
		if err != nil {
			return err
		}
		defer func() { _ = rfs.Close() }()
		return fn(leaseCtx, rfs)
	})
}

// runAuthorizedRemoteFS 强制执行 gate.WithAuthorized[C] -> pool.WithLease -> lease.OpenRemoteFS 嵌套序。
//
//xops:syncclosure
func runAuthorizedRemoteFS[C security.Capability, T any](ctx context.Context, s *Service, spec authOpSpec, fn func(context.Context, gate.Authorized[C], ports.RemoteFSPort, *transferEmitter) (T, error)) (T, error) {
	return runAuthorizedVal[C](ctx, s, spec, func(authCtx context.Context, auth gate.Authorized[C], emitter *transferEmitter) (out T, err error) {
		return out, s.withLeasedRemoteFS(authCtx, spec.base.Plan, func(leaseCtx context.Context, rfs ports.RemoteFSPort) error {
			out, err = fn(leaseCtx, auth, rfs, emitter)
			return err
		})
	})
}

// runRemotePathOp 统一承载单远端路径 SFTP/原子文件操作（预检 + 前置校验 + Round-2 规范化 + 门控 + 租约）。
//
//xops:syncclosure
func runRemotePathOp[C security.Capability, T any](ctx context.Context, s *Service, base CallBase, tool, action string, p pathalg.RemotePath, defaultRisk security.RiskLevel, params map[string]string, preErr error, fn func(context.Context, ports.RemoteFSPort) (T, error)) (T, error) {
	defer closeStream(base.OperationStream)
	hop, err := s.validateRemotePathOp(ctx, base, p)
	if err = firstErr(err, preErr); err != nil {
		return zeroVal[T](), err
	}
	spec := authOpSpec{base: base, targetHop: hop, tool: tool, action: action, paths: []pathalg.RemotePath{p}, params: params, defaultRisk: defaultRisk, summary: tool + " " + action + " " + p.String(), canonicalize: true}
	return runAuthorizedRemoteFS[C](ctx, s, spec, func(opCtx context.Context, _ gate.Authorized[C], rfs ports.RemoteFSPort, _ *transferEmitter) (T, error) {
		return fn(opCtx, rfs)
	})
}
func buildGateRequest[C security.Capability](s *Service, spec authOpSpec, capKind security.CapabilityKind, nodeID string) (gate.GateRequest[C], error) {
	pathStrs, recStrs := remotePathsToStrings(spec.paths, spec.extraPaths), remotePathsToStrings(spec.recursivePaths, nil)
	binding, err := buildOperationBinding(capKind, spec, nodeID, pathStrs, recStrs)
	if err != nil {
		return zeroVal[gate.GateRequest[C]](), err
	}
	canonFn := spec.customCanon
	if canonFn == nil && spec.canonicalize && s.strictPaths() && (len(spec.paths) > 0 || len(spec.recursivePaths) > 0) {
		canonFn = func(c context.Context) (gate.CanonicalizeResult, error) {
			return s.canonicalizeRemoteTargets(c, capKind, spec, nodeID, spec.paths, spec.recursivePaths, spec.extraPaths)
		}
	}
	effRisk := spec.base.Risk.OrElse(spec.defaultRisk)
	if rv, ok := spec.base.Risk.Get(); ok && !spec.base.Plan.IsValid() {
		effRisk = security.FoldRisks(spec.defaultRisk, rv)
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{Binding: binding, Risk: effRisk, ScopeSummary: spec.summary, Paths: pathStrs, RecursivePaths: recStrs, Canonicalize: canonFn, Approval: spec.base.Approval, OperationStream: spec.base.OperationStream})
}
func buildOperationBinding(capKind security.CapabilityKind, spec authOpSpec, nodeID string, canonicalPaths, recursivePaths []string) (security.OperationBinding, error) {
	bSpec := security.OperationBindingSpec{Capability: capKind, Tool: spec.tool, Action: spec.action, NodeID: nodeID, CanonicalPaths: canonicalPaths, RecursivePaths: recursivePaths, Parameters: spec.params}
	if spec.targetHop.IsValid() {
		bSpec.Endpoint = algebraic.Some(spec.targetHop.Endpoint())
	}
	if spec.base.Plan.IsValid() {
		bSpec.PlanDigest = algebraic.Some(spec.base.Plan.PlanDigest().SecurityDigest())
	}
	return security.NewOperationBinding(bSpec)
}
func remotePathsToStrings(rpaths []pathalg.RemotePath, extra []string) []string {
	out := make([]string, 0, len(rpaths)+len(extra))
	for _, p := range rpaths {
		if p.IsValid() {
			out = append(out, p.String())
		}
	}
	return append(out, slices.DeleteFunc(slices.Clone(extra), func(s string) bool { return s == "" })...)
}
func (s *Service) stageToken(domainTag, key string, deterministic bool) (string, error) {
	if deterministic {
		sum := sha256.Sum256([]byte(domainTag + "\x00" + key))
		return fmt.Sprintf("%x", sum[:12]), nil
	}
	buf := make([]byte, 12)
	_, err := io.ReadFull(s.entropy, buf)
	return pickIf(err == nil, fmt.Sprintf("%x", buf), ""), pickIf[error](err != nil, domi18n.WrapSentinel(ports.ErrEntropyShortRead, err), nil)
}
func makeLocalStageDest(finalDest pathalg.LocalRootedDest, token string) (pathalg.LocalRootedDest, error) {
	if parent, ok := finalDest.Parent(); ok {
		return parent.JoinComponent(".xops-stage-" + token + ".part")
	}
	return pathalg.ParseLocalRootedDest(".xops-stage-" + token + ".part")
}

// transferEmitter 封装受权传输向可选 OperationStream 发射结构化事件的逻辑；stream 为 nil 时静默空转。
type transferEmitter struct {
	stream     *events.OperationStream
	clock      ports.Clock
	traceID    security.TraceID
	opID       security.OperationID
	capability security.CapabilityKind
	nodeID     algebraic.Option[inventory.NodeID]
	seq        atomic.Uint64
}

func newTransferEmitter(stream *events.OperationStream, clock ports.Clock, traceID security.TraceID, opID security.OperationID, capKind security.CapabilityKind, nodeLabel string) *transferEmitter {
	if stream == nil {
		return nil
	}
	nid, err := inventory.ParseNodeID(nodeLabel)
	return &transferEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, capability: capKind, nodeID: pickIf(err == nil, algebraic.Some(nid), algebraic.None[inventory.NodeID]())}
}

//xops:syncclosure
func (e *transferEmitter) emitBuilt(ctx context.Context, build func(events.EventMeta) (events.Event, error)) {
	if e == nil || e.stream == nil || e.stream.IsClosed() {
		return
	}
	if meta, e1 := events.NewEventMeta(events.EventMetaSpec{TraceID: e.traceID, OperationID: algebraic.Some(e.opID), OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: e.nodeID}); e1 == nil {
		if ev, e2 := build(meta); e2 == nil && ev != nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}
func (e *transferEmitter) emitProgress(ctx context.Context, transferID security.OperationID, dir fsm.TransferDirection, transferred, total, chunks uint64, startedAt time.Time, stage string) {
	if e == nil || !transferID.IsValid() || !dir.IsValid() {
		return
	}
	transferred, elapsed, rate := pickIf(total > 0 && transferred > total, total, transferred), max(e.clock.Since(startedAt), 0), uint64(0)
	if elapsed > 0 && transferred > 0 {
		rateF := float64(transferred) / elapsed.Seconds()
		rate = pickIf(rateF >= float64(math.MaxUint64) || math.IsInf(rateF, 0) || math.IsNaN(rateF), uint64(math.MaxUint64), uint64(rateF))
	}
	e.emitBuilt(ctx, func(m events.EventMeta) (events.Event, error) {
		return events.NewTransferProgressEvent(events.TransferProgressSpec{Meta: m, TransferID: transferID, Direction: dir, BytesTransferred: transferred, TotalBytes: total, ChunksCompleted: chunks, Elapsed: algebraic.FromStdDuration(elapsed), RateBytesPerSec: rate, Stage: stage})
	})
}
func (e *transferEmitter) emitFSMTransitions(ctx context.Context, from fsm.TransferStateKind, to fsm.TransferState, evs []fsm.TransferEvent) {
	if e == nil || to == nil || !to.IsValid() {
		return
	}
	for _, ev := range evs {
		e.emitBuilt(ctx, func(m events.EventMeta) (events.Event, error) {
			return events.NewTransferTransitionEvent(m, from, to.Kind(), ev, to.IsTerminal())
		})
	}
}
func (e *transferEmitter) emitCompleted(ctx context.Context, startedAt time.Time, finalErr error) {
	if e == nil {
		return
	}
	code, msg := pickIf(finalErr != nil, classifyTransferErrorCode(finalErr), ""), pickIf(finalErr != nil, errText(finalErr), "completed")
	var outcomeOpt algebraic.Option[execution.ExecutionOutcome]
	if errors.Is(finalErr, ErrUncertainCommit) {
		if unk, uErr := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, code, msg); uErr == nil {
			outcomeOpt = algebraic.Some[execution.ExecutionOutcome](unk)
		}
	}
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
	defer cancel()
	e.emitBuilt(emitCtx, func(m events.EventMeta) (events.Event, error) {
		return events.NewOperationCompletedEvent(events.OperationCompletedSpec{Meta: m, Capability: e.capability, Duration: algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)), Outcome: outcomeOpt, Succeeded: finalErr == nil, Code: code, Message: msg})
	})
}
func classifyTransferErrorCode(err error) string {
	for _, m := range [...]struct {
		t error
		c string
	}{{ErrUncertainCommit, "uncertain_commit"}, {ErrCorruptJournal, "corrupt_journal"}, {ports.ErrRemoteAnchorMismatch, "remote_anchor_mismatch"}, {ErrPatchConflict, "patch_conflict"}, {ports.ErrAuditPostWrite, "audit_post_write_failed"}, {gate.ErrGateHalted, "gate_halted"}, {gate.ErrScopeEscalated, "scope_escalated"}} {
		if errors.Is(err, m.t) {
			return m.c
		}
	}
	return "transfer_error"
}
func (s *Service) emitDiagnostic(opID algebraic.Option[security.OperationID], sev events.Severity, code, msg string, attrs map[string]string) {
	if s.bus == nil || s.bus.IsClosed() {
		return
	}
	tid, e1 := security.ParseTraceID("transfer-service")
	meta, e2 := events.NewEventMeta(events.EventMetaSpec{TraceID: tid, OperationID: opID, OccurredAt: s.clock.Now().UTC().Round(0)})
	if ev, e3 := events.NewDiagnosticEvent(events.DiagnosticSpec{Meta: meta, Scope: events.DiagnosticScopeTransfer, Severity: sev, Code: code, Message: msg, Attrs: attrs}); firstErr(e1, e2, e3) == nil {
		_ = s.bus.Publish(ev)
	}
}
