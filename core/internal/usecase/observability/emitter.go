package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// obsEmitter 封装向隔离 OperationStream 并发安全发射启动、分片输出、指标采样与终态事件的辅助器。
type obsEmitter struct {
	stream                    *events.OperationStream
	clock                     ports.Clock
	traceID                   security.TraceID
	opID                      security.OperationID
	nodeID                    algebraic.Option[inventory.NodeID]
	capability                security.CapabilityKind
	seq, stdoutSeq, stderrSeq atomic.Uint64
}

func newObsEmitter(stream *events.OperationStream, clock ports.Clock, traceID security.TraceID, opID security.OperationID, nodeID string, capKind security.CapabilityKind) *obsEmitter {
	if stream == nil || clock == nil {
		return nil
	}
	if stream.TraceID().IsValid() && stream.OperationID().IsValid() {
		traceID, opID = stream.TraceID(), stream.OperationID()
	}
	var nodeOpt algebraic.Option[inventory.NodeID]
	if parsed, err := inventory.ParseNodeID(nodeID); err == nil {
		nodeOpt = algebraic.Some(parsed)
	}
	return &obsEmitter{stream: stream, clock: clock, traceID: traceID, opID: opID, nodeID: nodeOpt, capability: capKind}
}

func (e *obsEmitter) active() bool { return e != nil && e.stream != nil && !e.stream.IsClosed() }
func (e *obsEmitter) nextMeta() (events.EventMeta, error) {
	if !e.active() {
		return zeroVal[events.EventMeta](), ports.ErrClosed
	}
	return events.NewEventMeta(events.EventMetaSpec{TraceID: e.traceID, OperationID: algebraic.Some(e.opID), OccurredAt: e.clock.Now().UTC().Round(0), Seq: e.seq.Add(1), NodeID: e.nodeID})
}
func (e *obsEmitter) emit(ctx context.Context, build func(events.EventMeta) (events.Event, error)) {
	if meta, err := e.nextMeta(); err == nil {
		if ev, bErr := build(meta); bErr == nil {
			_ = e.stream.Emit(ctx, ev)
		}
	}
}
func (e *obsEmitter) emitStarted(ctx context.Context, action string, planDigest algebraic.Option[plan.PlanDigest], summary string) {
	e.emit(ctx, func(m events.EventMeta) (events.Event, error) {
		return events.NewOperationStartedEvent(events.OperationStartedSpec{Meta: m, Capability: e.capability, Tool: toolObservability, Action: action, PlanDigest: planDigest, Summary: summary})
	})
}
func (e *obsEmitter) emitChunk(ctx context.Context, kind events.OutputStreamKind, data []byte) {
	if len(data) == 0 || !e.active() {
		return
	}
	counter := pickIf(kind == events.OutputStreamStderr, &e.stderrSeq, &e.stdoutSeq)
	for off := 0; off < len(data); off += outputChunkMaxSize {
		meta, err := e.nextMeta()
		if err != nil {
			return
		}
		ev, err := events.NewOutputChunkEvent(events.OutputChunkSpec{Meta: meta, Stream: kind, ChunkIndex: counter.Add(1) - 1, Data: data[off:min(off+outputChunkMaxSize, len(data))]})
		if err != nil || e.stream.Emit(ctx, ev) != nil {
			return
		}
	}
}
func (e *obsEmitter) emitMetric(ctx context.Context, name, unit string, value float64, interval algebraic.Duration, labels map[string]string) {
	e.emit(ctx, func(m events.EventMeta) (events.Event, error) {
		return events.NewMetricSampleEvent(events.MetricSampleSpec{Meta: m, MetricName: name, Unit: unit, Value: value, Interval: interval, Labels: labels})
	})
}
func (e *obsEmitter) emitCompleted(ctx context.Context, startedAt time.Time, outcome execution.ExecutionOutcome, succeeded bool, code, msg string) {
	outOpt, finalOK := normalizeObsCompleted(outcome, succeeded)
	emitCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), terminalEventTimeout)
	defer cancel()
	e.emit(emitCtx, func(m events.EventMeta) (events.Event, error) {
		return events.NewOperationCompletedEvent(events.OperationCompletedSpec{Meta: m, Capability: e.capability, Duration: algebraic.FromStdDuration(max(e.clock.Since(startedAt), 0)), Outcome: outOpt, Succeeded: finalOK, Code: code, Message: msg})
	})
}
func normalizeObsCompleted(outcome execution.ExecutionOutcome, succeeded bool) (algebraic.Option[execution.ExecutionOutcome], bool) {
	if outcome == nil || !outcome.IsValid() {
		return algebraic.None[execution.ExecutionOutcome](), succeeded
	}
	switch v := outcome.(type) {
	case *execution.OutcomeUnknown, *execution.OutcomeNotStarted:
		return algebraic.Some(outcome), false
	case *execution.OutcomeCompleted:
		if v.Succeeded() && !succeeded {
			return algebraic.None[execution.ExecutionOutcome](), false
		}
		return algebraic.Some(outcome), v.Succeeded()
	default:
		return algebraic.None[execution.ExecutionOutcome](), false
	}
}

// boundedOutputTee 在严格字节上限内同时捕获、流式转发至可选 io.Writer 并向 OperationStream 发射 OutputChunkEvent；
// 可选 onLimit 回调在首次触达字节上限后（且末片推送完成后）同步触发一次，供 Follow 日志流确定性停止。
type boundedOutputTee struct {
	ctx                   context.Context
	emitter               *obsEmitter
	kind                  events.OutputStreamKind
	mirror                io.Writer
	limit, total          uint64
	onLimit               func()
	mu                    sync.Mutex
	buf                   bytes.Buffer
	truncated, limitFired bool
}

func (w *boundedOutputTee) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	var takeBytes []byte
	var fireLimit func()
	if w.total < w.limit {
		take := min(uint64(len(p)), w.limit-w.total)
		_, _ = w.buf.Write(p[:take])
		w.total += take
		takeBytes = bytes.Clone(p[:take])
		w.truncated = w.truncated || take < uint64(len(p))
	} else {
		w.truncated = true
	}
	if w.total >= w.limit && !w.limitFired && w.onLimit != nil {
		w.limitFired, fireLimit = true, w.onLimit
	}
	w.mu.Unlock()
	if len(takeBytes) > 0 {
		if w.mirror != nil {
			_, _ = w.mirror.Write(takeBytes)
		}
		w.emitter.emitChunk(w.ctx, w.kind, takeBytes)
	}
	if fireLimit != nil {
		fireLimit()
	}
	return len(p), nil
}
func (w *boundedOutputTee) snapshot() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes()), w.truncated
}

// resolveCanonicalRemotePath 在有界跳数预算内规范化远端 POSIX 路径（全程 0 path/filepath）。
func resolveCanonicalRemotePath(ctx context.Context, rfs ports.RemoteFSPort, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	cur := p
	var suffix []pathalg.RemoteName
	rejoin := func(base pathalg.RemotePath, rev []pathalg.RemoteName) (pathalg.RemotePath, error) {
		if len(rev) == 0 {
			return base, nil
		}
		ord := slices.Clone(rev)
		slices.Reverse(ord)
		return base.Join(ord...)
	}
	for hops := 0; len(suffix) < maxRemoteCanonicalHops; {
		if realCur, rErr := rfs.RealPath(ctx, cur); rErr == nil {
			return rejoin(realCur, suffix)
		} else if !errors.Is(rErr, ports.ErrNotFound) {
			return zeroVal[pathalg.RemotePath](), rErr
		}
		if nextCur, jumped, jErr := expandDanglingSymlink(ctx, rfs, cur, &hops); jErr != nil {
			return zeroVal[pathalg.RemotePath](), jErr
		} else if jumped {
			nextFull, rErr := rejoin(nextCur, suffix)
			if rErr != nil {
				return zeroVal[pathalg.RemotePath](), rErr
			}
			cur, suffix = nextFull, suffix[:0]
			continue
		}
		base, ok := cur.Base()
		if !ok || cur.IsRoot() || cur.Dir().Equal(cur) {
			return rejoin(cur, suffix)
		}
		suffix, cur = append(suffix, base), cur.Dir()
	}
	return zeroVal[pathalg.RemotePath](), fmt.Errorf("%w: 远端路径规范化深度超限", ErrInvalidRequest)
}

func expandDanglingSymlink(ctx context.Context, rfs ports.RemoteFSPort, cur pathalg.RemotePath, hops *int) (pathalg.RemotePath, bool, error) {
	lst, err := rfs.Lstat(ctx, cur)
	if errors.Is(err, ports.ErrNotFound) || (err == nil && !lst.IsSymlink()) {
		return zeroVal[pathalg.RemotePath](), false, nil
	}
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	if *hops >= pathalg.MaxSymlinkHops {
		return zeroVal[pathalg.RemotePath](), false, fmt.Errorf("%w: 远端软链跳数超限 %d", ErrSymlinkPolicyDenied, pathalg.MaxSymlinkHops)
	}
	*hops++
	raw, err := rfs.ReadLink(ctx, cur)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	targetP, err := pathalg.ParseRemotePath(raw)
	if err != nil {
		return zeroVal[pathalg.RemotePath](), false, err
	}
	if !targetP.IsAbs() {
		realParent, pErr := rfs.RealPath(ctx, cur.Dir())
		if pErr != nil || !realParent.IsAbs() {
			return zeroVal[pathalg.RemotePath](), false, firstErr(pErr, ErrInvalidRequest)
		}
		targetP, err = realParent.Resolve(targetP)
	}
	return targetP, err == nil, err
}

func verifyRemotePathAuthorized(ctx context.Context, enforce bool, rfs ports.RemoteFSPort, binding security.OperationBinding, target pathalg.RemotePath) error {
	if !enforce {
		return nil
	}
	canon, err := resolveCanonicalRemotePath(ctx, rfs, target)
	if err != nil {
		return err
	}
	cs := canon.String()
	if !slices.Contains(binding.CanonicalPaths(), cs) && !slices.ContainsFunc(binding.RecursivePaths(), func(r string) bool { return r == "/" || cs == r || strings.HasPrefix(cs, r+"/") }) {
		return fmt.Errorf("%w: 远端路径 %s 规范化漂移至未授权目标 %s", gate.ErrScopeEscalated, target, canon)
	}
	return nil
}
