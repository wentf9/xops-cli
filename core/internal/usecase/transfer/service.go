package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

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
	handleMu                              sync.Mutex
	activeHandles                         map[security.OperationID]plan.ManagedHandle[plan.KindTransfer]
	valid                                 bool
}

// NewService 严格校验必填依赖与限流上下界，构造不可绕过能力门控的 transfer.Service。
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Gate == nil || cfg.Pool == nil || cfg.Pool.IsClosed() || cfg.Clock == nil || cfg.Entropy == nil || (cfg.SystemBus != nil && cfg.SystemBus.IsClosed()) {
		return nil, fmt.Errorf("%w: Gate/Pool/Clock/Entropy 必填且不可关闭", ErrInvalidConfig)
	}
	cs, conc, maxRead := pickIf(cfg.DefaultChunkSize == 0, defaultChunkSize, cfg.DefaultChunkSize), pickIf(cfg.DefaultConcurrency == 0, defaultConcurrency, cfg.DefaultConcurrency), pickIf(cfg.DefaultMaxReadBytes == 0, defaultMaxReadBytes, cfg.DefaultMaxReadBytes)
	if cs < minChunkSize || cs > int64(fsm.MaxTransferChunkBytes) || conc < 1 || conc > maxConcurrency || maxRead <= 0 || maxRead > maxAtomicReadBytes {
		return nil, fmt.Errorf("%w: 默认分片/并发/读上限越界", ErrInvalidConfig)
	}
	return &Service{
		gate: cfg.Gate, pool: cfg.Pool, clock: cfg.Clock, entropy: cfg.Entropy,
		scopedFS: cfg.ScopedFS, operatorReadFS: cfg.OperatorReadFS, journals: cfg.Journals, bus: cfg.SystemBus,
		defaultChunkSize: cs, defaultConcurrency: conc, defaultMaxReadBytes: maxRead,
		activeHandles: make(map[security.OperationID]plan.ManagedHandle[plan.KindTransfer]), valid: true,
	}, nil
}

func (s *Service) checkReadyCtx(ctx context.Context) error {
	switch {
	case s == nil || !s.valid:
		return ErrServiceNotInitialized
	case ctx == nil:
		return ErrNilContext
	default:
		return ctx.Err()
	}
}
func (s *Service) validateBaseCall(ctx context.Context, base CallBase) (plan.HopSpec, error) {
	if err := s.checkReadyCtx(ctx); err != nil {
		return zeroVal[plan.HopSpec](), err
	}
	hop, ok := base.Plan.Target()
	if !base.Plan.IsValid() || !ok || !hop.IsValid() {
		return zeroVal[plan.HopSpec](), fmt.Errorf("%w: SealedConnectionPlan 无效", ErrInvalidRequest)
	}
	if r, hasR := base.Risk.Get(); hasR && !r.IsValid() {
		return zeroVal[plan.HopSpec](), fmt.Errorf("%w: RiskLevel 无效", ErrInvalidRequest)
	}
	return hop, nil
}
func (s *Service) validateRemotePathOp(ctx context.Context, base CallBase, p pathalg.RemotePath) (plan.HopSpec, error) {
	hop, err := s.validateBaseCall(ctx, base)
	if err != nil {
		return hop, err
	}
	return hop, pickIf[error](p.IsValid(), nil, fmt.Errorf("%w: RemotePath 无效", ErrInvalidRequest))
}
func (s *Service) resolveChunkAndConcurrency(chunkSize int64, concurrency int) (int64, int, error) {
	cs, conc := pickIf(chunkSize == 0, s.defaultChunkSize, chunkSize), pickIf(concurrency == 0, s.defaultConcurrency, concurrency)
	if cs < minChunkSize || cs > int64(fsm.MaxTransferChunkBytes) || conc < 1 || conc > maxConcurrency {
		return 0, 0, fmt.Errorf("%w: ChunkSize/Concurrency 越界", ErrInvalidRequest)
	}
	return cs, conc, nil
}
func (s *Service) resolveReadLimits(maxBytes int64) (ports.ReadLimits, error) {
	lim := pickIf(maxBytes == 0, s.defaultMaxReadBytes, maxBytes)
	if lim <= 0 || lim > maxAtomicReadBytes {
		return zeroVal[ports.ReadLimits](), fmt.Errorf("%w: MaxBytes 越界", ErrInvalidRequest)
	}
	return ports.NewReadLimits(lim)
}
func resolvePerm(opt algebraic.Option[fs.FileMode], fallback fs.FileMode) (fs.FileMode, error) {
	perm, ok := opt.Get()
	if !ok {
		return fallback, nil
	}
	return perm, pickIf[error](perm != 0 && perm == perm.Perm(), nil, fmt.Errorf("%w: 权限位 %#o 非法", ErrInvalidRequest, perm))
}

type authOpSpec struct {
	base                  CallBase
	targetHop             plan.HopSpec
	tool, action, summary string
	paths, recursivePaths []pathalg.RemotePath
	extraPaths            []string
	params                map[string]string
	defaultRisk           security.RiskLevel
	canonicalize          bool
}

func closeStreamIfNonNil(st *events.OperationStream) {
	if st != nil {
		st.Close()
	}
}

// runAuthorizedVal 封装最外层 gate.WithAuthorized[C] 与 OperationStream 生命周期（Started/Completed + 确定性 EOF）。
// 严格注册 defer closeStreamIfNonNil 在前、defer emitCompleted 在后（LIFO），确保即使回调 panic 也能先发终态事件再闭合流。
//
//xops:syncclosure
func runAuthorizedVal[C security.Capability, T any](ctx context.Context, s *Service, spec authOpSpec, fn func(context.Context, gate.Authorized[C], *transferEmitter) (T, error)) (T, error) {
	defer closeStreamIfNonNil(spec.base.OperationStream)
	capKind, nodeID := security.CapabilityKindOf[C](), pickIf(spec.base.NodeID != "", spec.base.NodeID, spec.targetHop.NodeID())
	gateReq, err := buildGateRequest[C](s, spec, capKind, nodeID)
	if err != nil {
		return zeroVal[T](), err
	}
	var out T
	var emitter *transferEmitter
	startedAt, entered := s.clock.Now().UTC().Round(0), false
	finalErr := gate.ErrOperationPanicked
	defer func() {
		if entered && emitter != nil {
			emitter.emitCompleted(ctx, startedAt, finalErr)
		}
	}()
	gateErr := gate.WithAuthorized[C](ctx, s.gate, gateReq, func(authCtx context.Context, auth gate.Authorized[C]) (fErr error) {
		entered, startedAt = true, s.clock.Now().UTC().Round(0)
		emitter = newTransferEmitter(spec.base.OperationStream, s.clock, auth.TraceID(), auth.OperationID(), capKind, nodeID)
		emitter.emitStarted(authCtx, spec.tool, spec.action, spec.base.Plan.PlanDigest(), spec.summary)
		out, fErr = fn(authCtx, auth, emitter)
		return fErr
	})
	finalErr = gateErr
	return out, gateErr
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
		err = s.withLeasedRemoteFS(authCtx, spec.base.Plan, func(leaseCtx context.Context, rfs ports.RemoteFSPort) (fErr error) {
			out, fErr = fn(leaseCtx, auth, rfs, emitter)
			return fErr
		})
		return out, err
	})
}

// runRemotePathOp 统一承载单远端路径 SFTP/原子文件操作（预检 + 前置校验 + Round-2 规范化 + 门控 + 租约）。
//
//xops:syncclosure
func runRemotePathOp[C security.Capability, T any](ctx context.Context, s *Service, base CallBase, tool, action string, p pathalg.RemotePath, defaultRisk security.RiskLevel, params map[string]string, preCheck func() error, fn func(context.Context, ports.RemoteFSPort) (T, error)) (T, error) {
	defer closeStreamIfNonNil(base.OperationStream)
	hop, err := s.validateRemotePathOp(ctx, base, p)
	if err != nil {
		return zeroVal[T](), err
	}
	if preCheck != nil {
		if err = preCheck(); err != nil {
			return zeroVal[T](), err
		}
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
	var canonFn gate.CanonicalizeFunc
	if spec.canonicalize && s.gate.Profile() != gate.PolicyProfileDirectOperator && (len(spec.paths) > 0 || len(spec.recursivePaths) > 0) {
		canonFn = s.makeRemoteCanonicalizer(capKind, spec, nodeID)
	}
	return gate.NewGateRequest[C](gate.GateRequestSpec[C]{
		Binding: binding, Risk: spec.base.Risk.OrElse(spec.defaultRisk), ScopeSummary: spec.summary,
		Paths: pathStrs, RecursivePaths: recStrs, Canonicalize: canonFn, Approval: spec.base.Approval, OperationStream: spec.base.OperationStream,
	})
}
func buildOperationBinding(capKind security.CapabilityKind, spec authOpSpec, nodeID string, canonicalPaths, recursivePaths []string) (security.OperationBinding, error) {
	return security.NewOperationBinding(security.OperationBindingSpec{
		Capability: capKind, Tool: spec.tool, Action: spec.action, NodeID: nodeID,
		Endpoint: algebraic.Some(spec.targetHop.Endpoint()), CanonicalPaths: canonicalPaths, RecursivePaths: recursivePaths,
		PlanDigest: algebraic.Some(spec.base.Plan.PlanDigest().SecurityDigest()), Parameters: spec.params,
	})
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

// makeRemoteCanonicalizer 构造 Gate Round-2 远端规范化探测回调（ADR-016 / INV-E5），拦截软链重定向绕过。
func (s *Service) makeRemoteCanonicalizer(capKind security.CapabilityKind, spec authOpSpec, nodeID string) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		var resolved, resolvedRec []string
		if err := s.withLeasedRemoteFS(ctx, spec.base.Plan, func(leaseCtx context.Context, rfs ports.RemoteFSPort) (rErr error) {
			if resolved, rErr = resolveCanonicalList(leaseCtx, rfs, spec.paths, spec.extraPaths); rErr != nil {
				return rErr
			}
			resolvedRec, rErr = resolveCanonicalList(leaseCtx, rfs, spec.recursivePaths, nil)
			return rErr
		}); err != nil {
			return gate.CanonicalizeResult{}, err
		}
		canBind, err := buildOperationBinding(capKind, spec, nodeID, resolved, resolvedRec)
		return gate.CanonicalizeResult{Binding: canBind, Paths: resolved, RecursivePaths: resolvedRec}, err
	}
}
func resolveCanonicalList(ctx context.Context, rfs ports.RemoteFSPort, rpaths []pathalg.RemotePath, extra []string) ([]string, error) {
	out := make([]string, 0, len(rpaths)*2+len(extra))
	for _, p := range rpaths {
		if !p.IsValid() {
			continue
		}
		out = append(out, p.String())
		canon, err := resolveCanonicalRemotePath(ctx, rfs, p)
		if err != nil {
			return nil, err
		}
		if !canon.Equal(p) {
			out = append(out, canon.String())
		}
	}
	return append(out, slices.DeleteFunc(slices.Clone(extra), func(s string) bool { return s == "" })...), nil
}

// resolveCanonicalRemotePath 解析远端真实路径（含悬空软链与缺失祖先，严禁使用 path/filepath）。
func resolveCanonicalRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	if realP, err := rfs.RealPath(ctx, p); err == nil || !errors.Is(err, ports.ErrNotFound) {
		return realP, err
	}
	if lst, lErr := rfs.Lstat(ctx, p); lErr == nil && lst.IsSymlink() {
		raw, e1 := rfs.ReadLink(ctx, p)
		targetP, e2 := pathalg.ParseRemotePath(raw)
		if err := firstErr(e1, e2); err != nil {
			return zeroVal[pathalg.RemotePath](), err
		}
		var rErr error
		if p, rErr = p.Dir().Resolve(targetP); rErr != nil {
			return zeroVal[pathalg.RemotePath](), rErr
		}
	}
	return walkMissingAncestorCanonical(ctx, rfs, p)
}
func walkMissingAncestorCanonical(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	var suffix []pathalg.RemoteName
	for cur := p; len(suffix) < maxRemoteCanonicalDepth; {
		if realCur, err := rfs.RealPath(ctx, cur); err == nil {
			slices.Reverse(suffix)
			return realCur.Join(suffix...)
		} else if !errors.Is(err, ports.ErrNotFound) {
			return zeroVal[pathalg.RemotePath](), err
		}
		base, ok := cur.Base()
		if !ok || cur.IsRoot() || cur.Dir().Equal(cur) {
			return p, nil
		}
		suffix, cur = append(suffix, base), cur.Dir()
	}
	return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 远端路径规范化超限 %d", ErrInvalidRequest, maxRemoteCanonicalDepth)
}
func readRemoteChunkExact(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath, offset, want int64) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(int(want))
	got, err := rfs.ReadChunk(ctx, p, offset, &buf, want)
	if (err != nil && !errors.Is(err, io.EOF)) || got != want {
		return nil, pickIf[error](err != nil && !errors.Is(err, io.EOF), err, fmt.Errorf("%w: 远端分片 offset=%d 期望 %d 实际 %d", io.ErrUnexpectedEOF, offset, want, got))
	}
	return buf.Bytes(), nil
}
func digestFromHash(h hash.Hash) security.Digest {
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return security.DigestFromSHA256(sum)
}
func (s *Service) stageToken(domainTag, key string, deterministic bool) (string, error) {
	if deterministic {
		sum := sha256.Sum256([]byte(domainTag + "\x00" + key))
		return hex.EncodeToString(sum[:12]), nil
	}
	buf := make([]byte, 12)
	_, err := io.ReadFull(s.entropy, buf)
	return pickIf(err == nil, hex.EncodeToString(buf), ""), pickIf[error](err != nil, fmt.Errorf("%w: %w", ports.ErrEntropyShortRead, err), nil)
}
func makeRemoteStagePath(finalDest pathalg.RemotePath, token string) (pathalg.RemotePath, error) {
	return joinRemoteBase(finalDest.Dir(), ".xops-stage-"+token+".part")
}
func makeLocalStageDest(finalDest pathalg.LocalRootedDest, token string) (pathalg.LocalRootedDest, error) {
	if parent, ok := finalDest.Parent(); ok {
		return parent.JoinComponent(".xops-stage-" + token + ".part")
	}
	return pathalg.ParseLocalRootedDest(".xops-stage-" + token + ".part")
}
func joinRemoteBase(dir pathalg.RemotePath, base string) (pathalg.RemotePath, error) {
	name, err := pathalg.ParseRemoteName(path.Base(base))
	if err != nil {
		return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 非法远端文件名 %q: %w", ErrInvalidRequest, base, err)
	}
	return dir.Join(name)
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
	var nodeOpt algebraic.Option[inventory.NodeID]
	if nid, err := inventory.ParseNodeID(nodeLabel); err == nil {
		nodeOpt = algebraic.Some(nid)
	}
	return &transferEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, capability: capKind, nodeID: nodeOpt}
}
func (e *transferEmitter) nextMeta() (events.EventMeta, error) {
	if e == nil || e.stream == nil || e.stream.IsClosed() {
		return zeroVal[events.EventMeta](), ports.ErrClosed
	}
	return events.NewEventMeta(events.EventMetaSpec{TraceID: e.traceID, OperationID: algebraic.Some(e.opID), OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: e.nodeID})
}
func (e *transferEmitter) emitStarted(ctx context.Context, tool, action string, planDigest plan.PlanDigest, summary string) {
	if meta, err := e.nextMeta(); err == nil {
		if ev, err := events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: meta, Capability: e.capability, Tool: tool, Action: action, PlanDigest: algebraic.Some(planDigest), Summary: summary}); err == nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}
func (e *transferEmitter) emitProgress(ctx context.Context, transferID security.OperationID, dir fsm.TransferDirection, transferred, total, chunks uint64, startedAt time.Time, stage string) {
	meta, err := e.nextMeta()
	if err != nil || !transferID.IsValid() || !dir.IsValid() {
		return
	}
	transferred = pickIf(total > 0 && transferred > total, total, transferred)
	elapsed := max(e.clock.Since(startedAt), 0)
	rate := pickIf(elapsed.Seconds() > 0, uint64(float64(transferred)/max(elapsed.Seconds(), 1e-9)), uint64(0))
	if ev, err := events.NewTransferProgressEvent(events.TransferProgressSpec{
		Meta: meta, TransferID: transferID, Direction: dir, BytesTransferred: transferred, TotalBytes: total,
		ChunksCompleted: chunks, Elapsed: algebraic.FromStdDuration(elapsed), RateBytesPerSec: rate, Stage: stage,
	}); err == nil {
		_ = e.stream.Emit(ctx, ev)
	}
}
func (e *transferEmitter) emitFSMTransitions(ctx context.Context, from fsm.TransferStateKind, to fsm.TransferState, evs []fsm.TransferEvent) {
	if to == nil || !to.IsValid() {
		return
	}
	for _, ev := range evs {
		if meta, err := e.nextMeta(); err == nil {
			if trEv, err := events.NewTransferTransitionEvent(meta, from, to.Kind(), ev, to.IsTerminal()); err == nil {
				_ = e.stream.Emit(ctx, trEv)
			}
		}
	}
}
func (e *transferEmitter) emitCompleted(ctx context.Context, startedAt time.Time, finalErr error) {
	meta, err := e.nextMeta()
	if err != nil {
		return
	}
	code, msg := pickIf(finalErr != nil, classifyTransferErrorCode(finalErr), ""), pickIf(finalErr != nil, fmtErr(finalErr), "completed")
	if ev, err := events.NewOperationCompletedEvent(events.OperationCompletedSpec{
		Meta: meta, Capability: e.capability, Duration: algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)),
		Succeeded: finalErr == nil, Code: code, Message: msg,
	}); err == nil {
		emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventEmitTimeout)
		defer cancel()
		_ = e.stream.Emit(emitCtx, ev)
	}
}
func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func classifyTransferErrorCode(err error) string {
	for _, m := range [...]struct {
		t error
		c string
	}{
		{ErrUncertainCommit, "uncertain_commit"}, {ErrCorruptJournal, "corrupt_journal"},
		{ports.ErrRemoteAnchorMismatch, "remote_anchor_mismatch"}, {ErrPatchConflict, "patch_conflict"},
		{ports.ErrAuditPostWrite, "audit_post_write_failed"}, {gate.ErrGateHalted, "gate_halted"},
	} {
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
	if tid, err := security.ParseTraceID("transfer-service"); err == nil {
		if meta, err := events.NewEventMeta(events.EventMetaSpec{TraceID: tid, OperationID: opID, OccurredAt: s.clock.Now().UTC().Round(0)}); err == nil {
			if ev, err := events.NewDiagnosticEvent(events.DiagnosticSpec{Meta: meta, Scope: events.DiagnosticScopeTransfer, Severity: sev, Code: code, Message: msg, Attrs: attrs}); err == nil {
				_ = s.bus.Publish(ev)
			}
		}
	}
}
