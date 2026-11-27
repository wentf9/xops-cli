package tui

import (
	"context"
	"errors"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

func startBackgroundWatchers(
	nursery *conc.Nursery,
	cfg Config,
	proj ProjectionSource,
	prog *tea.Program,
	actionCh <-chan actionRequest,
	ctrl *workbenchController,
	attachInitialStreams bool,
) error {
	if proj != nil {
		if err := nursery.Go(func(wCtx context.Context) error { return watchProjection(wCtx, proj, prog) }); err != nil {
			return err
		}
	}
	if bus := resolveRawSystemBus(cfg, proj); bus != nil {
		if err := nursery.Go(func(wCtx context.Context) error { return watchSystemBus(wCtx, bus, prog) }); err != nil {
			return err
		}
	}
	if cfg.ExternalMsgs != nil {
		if err := nursery.Go(func(wCtx context.Context) error { return watchExternalMsgs(wCtx, cfg.ExternalMsgs, prog) }); err != nil {
			return err
		}
	}
	if attachInitialStreams {
		for _, stream := range cfg.OperationStreams {
			st := stream
			if err := nursery.Go(func(wCtx context.Context) error { return watchOperationStream(wCtx, st, prog) }); err != nil {
				return err
			}
		}
	}
	return nursery.Go(func(wCtx context.Context) error { return ctrl.run(wCtx, actionCh) })
}

func resolveRawSystemBus(cfg Config, proj ProjectionSource) *events.SystemBus {
	if proj != nil {
		// 存在 Projection 时 SystemBus 已由 Projection 内部消费，避免重复订阅同一总线。
		return nil
	}
	if cfg.SystemBus != nil {
		return cfg.SystemBus
	}
	if cfg.Engine != nil {
		return cfg.Engine.SystemBus()
	}
	return nil
}

func watchProjection(ctx context.Context, proj ProjectionSource, prog *tea.Program) error {
	var since uint64
	if snap := proj.Snapshot(); snap.IsValid() {
		since = snap.Version()
		sendMsg(ctx, prog, ProjectionUpdatedMsg{Snapshot: snap})
	}
	for {
		snap, err := proj.WaitUpdate(ctx, since)
		if err != nil {
			return nil
		}
		if snap.IsValid() {
			since = snap.Version()
			sendMsg(ctx, prog, ProjectionUpdatedMsg{Snapshot: snap})
		}
	}
}

func watchSystemBus(ctx context.Context, bus *events.SystemBus, prog *tea.Program) error {
	sub, err := bus.Subscribe()
	if err != nil {
		return nil
	}
	defer sub.Close()
	for {
		ev, ok, nextErr := sub.Next(ctx)
		if delta := sub.DrainDroppedDelta(); delta > 0 {
			sendMsg(ctx, prog, SystemBusDroppedMsg{Delta: delta, Total: sub.Dropped()})
		}
		if nextErr != nil || !ok {
			return nil
		}
		if msg, pErr := ProjectEvent(ev); pErr == nil {
			sendMsg(ctx, prog, msg)
		}
	}
}

func watchOperationStream(ctx context.Context, stream *events.OperationStream, prog *tea.Program) error {
	for {
		ev, ok, err := stream.Next(ctx)
		if err != nil || !ok {
			return nil
		}
		if msg, pErr := ProjectEvent(ev); pErr == nil {
			sendMsg(ctx, prog, msg)
		}
	}
}

func watchExternalMsgs(ctx context.Context, ch <-chan tea.Msg, prog *tea.Program) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			sendMsg(ctx, prog, msg)
		}
	}
}

// workbenchController 集中管理按需触发的资产刷新与远端指标/日志流独立子作用域，
// 分别用独立 Nursery 监督 metrics 与 logs 流，确保重选目标或退出时旧流 100% 取消并排空。
type workbenchController struct {
	cfg  Config
	proj ProjectionSource
	prog *tea.Program
}

type streamSlots struct {
	metrics *conc.Nursery
	logs    *conc.Nursery
}

func (s *streamSlots) stopAll() {
	stopNurserySlot(&s.metrics)
	stopNurserySlot(&s.logs)
}

func stopNurserySlot(slot **conc.Nursery) {
	if *slot != nil {
		_ = (*slot).Close()
		*slot = nil
	}
}

func (c *workbenchController) run(ctx context.Context, actionCh <-chan actionRequest) error {
	var slots streamSlots
	defer slots.stopAll()

	for {
		select {
		case <-ctx.Done():
			return nil
		case req := <-actionCh:
			c.handleAction(ctx, req, &slots)
		}
	}
}

func (c *workbenchController) handleAction(ctx context.Context, req actionRequest, slots *streamSlots) {
	switch req.kind {
	case actionRefreshInventory:
		c.refreshInventory(ctx)
	case actionStopStreams:
		slots.stopAll()
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: "metrics", Active: false})
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: "logs", Active: false})
	case actionStartMetrics:
		c.replaceStreamSlot(ctx, &slots.metrics, func(wCtx context.Context) error {
			return c.runMetricsStream(wCtx, req.target, req.sortBy)
		})
	case actionStartLogs:
		c.replaceStreamSlot(ctx, &slots.logs, func(wCtx context.Context) error {
			return c.runLogsStream(wCtx, req.target)
		})
	}
}

// replaceStreamSlot 先取消并排空同类别旧流，再在新的受监督 Nursery 内启动新流，防止多路孤儿流堆积。
func (c *workbenchController) replaceStreamSlot(ctx context.Context, slot **conc.Nursery, fn func(context.Context) error) {
	if c.cfg.Engine == nil {
		return
	}
	stopNurserySlot(slot)
	n, err := conc.NewNursery(ctx)
	if err != nil {
		return
	}
	if err := n.Go(fn); err != nil {
		_ = n.Close()
		return
	}
	*slot = n
}

func (c *workbenchController) refreshInventory(ctx context.Context) {
	if c.cfg.Engine == nil {
		return
	}
	if c.cfg.Engine.IsHalted() {
		reason := "gate halted"
		if info, ok := c.cfg.Engine.HaltInfo(); ok && info.Reason() != "" {
			reason = info.Reason()
		}
		sendMsg(ctx, c.prog, HaltedStateMsg{Reason: reason})
	}
	q := engine.InventoryQueryRequest{}
	hosts, rev, err := c.cfg.Engine.ListHosts(ctx, q)
	if err != nil {
		c.reportInventoryErr(ctx, err)
		return
	}
	idents, _, err := c.cfg.Engine.ListIdentities(ctx, q)
	if err != nil {
		c.reportInventoryErr(ctx, err)
		return
	}
	nodes, nodeRev, err := c.cfg.Engine.ListNodes(ctx, q)
	if err != nil {
		c.reportInventoryErr(ctx, err)
		return
	}
	if nodeRev.IsValid() {
		rev = nodeRev
	}
	sendMsg(ctx, c.prog, InventoryLoadedMsg{
		Revision: rev.String(),
		Hosts:    BuildHostItemsFromEntities(hosts, idents, nodes),
	})
}

func (c *workbenchController) reportInventoryErr(ctx context.Context, err error) {
	if errors.Is(err, engine.ErrEngineHalted) {
		sendMsg(ctx, c.prog, HaltedStateMsg{Reason: err.Error()})
	}
	sendMsg(ctx, c.prog, InventoryLoadedMsg{Err: err})
}

func (c *workbenchController) runMetricsStream(ctx context.Context, target string, sortBy engine.ProcessSortBy) error {
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: "metrics", Target: target, Active: true})
	stream, err := c.openAndAttachOpStream(ctx)
	if err != nil {
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: "metrics", Target: target, Active: false, Err: err})
		return nil
	}
	topN := c.cfg.MetricsTopProcesses
	if topN <= 0 {
		topN = defaultTopProcesses
	}
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		defer closeStreamIfNonNil(stream)
		if stream != nil && c.proj == nil {
			if gErr := n.Go(func(pCtx context.Context) error { return watchOperationStream(pCtx, stream, c.prog) }); gErr != nil {
				return gErr
			}
		}
		_, sErr := c.cfg.Engine.StreamMetrics(wCtx, engine.MetricsStreamRequest{
			RemoteCall: engine.RemoteCall{
				TargetInput: engine.TargetInput{TargetSpec: target, CLIOptions: c.cfg.CLIOptions},
				CallOptions: engine.CallOptions{OperationStream: stream},
			},
			Interval:     c.cfg.MetricsInterval,
			TopProcesses: topN,
			SortBy:       algebraic.Some(sortBy),
			OnFrame: func(frame engine.HostMetricsFrame) {
				sendMsg(wCtx, c.prog, MetricsFrameMsg{Target: target, Frame: frame})
			},
		})
		return sErr
	})
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: "metrics", Target: target, Active: false, Err: runErr})
	return nil
}

func (c *workbenchController) runLogsStream(ctx context.Context, target string) error {
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: "logs", Target: target, Active: true})
	logTarget, err := resolveDefaultLogTarget(c.cfg)
	if err != nil {
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: "logs", Target: target, Active: false, Err: err})
		return nil
	}
	stream, err := c.openAndAttachOpStream(ctx)
	if err != nil {
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: "logs", Target: target, Active: false, Err: err})
		return nil
	}
	tailLines := c.cfg.LogTailLines
	if tailLines <= 0 {
		tailLines = defaultLogTailLines
	}
	writer := &logChunkWriter{ctx: ctx, prog: c.prog, target: target}
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		defer closeStreamIfNonNil(stream)
		if stream != nil && c.proj == nil {
			if gErr := n.Go(func(pCtx context.Context) error { return watchOperationStream(pCtx, stream, c.prog) }); gErr != nil {
				return gErr
			}
		}
		_, sErr := c.cfg.Engine.StreamLogs(wCtx, engine.LogStreamRequest{
			RemoteCall: engine.RemoteCall{
				TargetInput: engine.TargetInput{TargetSpec: target, CLIOptions: c.cfg.CLIOptions},
				CallOptions: engine.CallOptions{OperationStream: stream},
			},
			Target:    logTarget,
			TailLines: tailLines,
			Follow:    true,
			Output:    writer,
		})
		return sErr
	})
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: "logs", Target: target, Active: false, Err: runErr})
	return nil
}

func (c *workbenchController) openAndAttachOpStream(ctx context.Context) (*events.OperationStream, error) {
	buf := c.cfg.MaxStreamBuffer
	if buf <= 0 {
		buf = defaultStreamBuffer
	}
	stream, err := c.cfg.Engine.NewOperationStream(ctx, buf)
	if err != nil || stream == nil {
		return nil, err
	}
	if c.proj != nil {
		if aErr := c.proj.AttachOperationStream(stream); aErr != nil {
			stream.Close()
			return nil, aErr
		}
	}
	return stream, nil
}

func closeStreamIfNonNil(s *events.OperationStream) {
	if s != nil {
		s.Close()
	}
}

type logChunkWriter struct {
	ctx    context.Context
	prog   *tea.Program
	target string
}

func (w *logChunkWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	sendMsg(w.ctx, w.prog, LogChunkMsg{
		Target:     w.target,
		Stream:     events.OutputStreamStdout,
		Text:       string(p),
		OccurredAt: time.Now().UTC(),
	})
	return len(p), nil
}

func sendMsg(ctx context.Context, prog *tea.Program, msg tea.Msg) {
	if prog == nil || msg == nil || ctx.Err() != nil {
		return
	}
	prog.Send(msg)
}
