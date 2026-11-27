package tui

import (
	"context"
	"errors"

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
	// 当存在 Projection 时，初始 OperationStreams 已在 Run 中直接挂载至 Projection（避免双重消费）；
	// 仅在无 Projection 模式下由本控制器启动独立监督消费协程。
	if proj == nil && attachInitialStreams {
		if err := watchInitialOperationStreams(nursery, cfg.OperationStreams, prog); err != nil {
			return err
		}
	}
	return nursery.Go(func(wCtx context.Context) error { return ctrl.run(wCtx, actionCh) })
}

func watchInitialOperationStreams(nursery *conc.Nursery, streams []*events.OperationStream, prog *tea.Program) error {
	for _, stream := range streams {
		st := stream
		if err := nursery.Go(func(wCtx context.Context) error { return watchOperationStream(wCtx, st, prog) }); err != nil {
			return err
		}
	}
	return nil
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
	cfg        Config
	proj       ProjectionSource
	prog       *tea.Program
	metricsSeq uint64
	logsSeq    uint64
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
		c.metricsSeq++
		c.logsSeq++
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindMetrics, Active: false, Seq: c.metricsSeq})
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindLogs, Active: false, Seq: c.logsSeq})
	case actionStartMetrics:
		c.metricsSeq++
		seq := c.metricsSeq
		c.replaceStreamSlot(ctx, &slots.metrics, func(wCtx context.Context) error {
			return c.runMetricsStream(wCtx, req.target, req.sortBy, seq)
		})
	case actionStartLogs:
		c.logsSeq++
		seq := c.logsSeq
		c.replaceStreamSlot(ctx, &slots.logs, func(wCtx context.Context) error {
			return c.runLogsStream(wCtx, req.target, seq)
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
		var msg HaltedStateMsg
		if info, ok := c.cfg.Engine.HaltInfo(); ok {
			msg.Err = info.Cause()
			msg.Reason = info.Reason()
		}
		sendMsg(ctx, c.prog, msg)
	}
	q := engine.InventoryQueryRequest{}
	// 优先走单次原子 GetInventorySnapshot（1 条审计、0 撕裂读）；对最小测试桩回退三路列表查询。
	if sc, ok := c.cfg.Engine.(InventorySnapshotClient); ok {
		snap, err := sc.GetInventorySnapshot(ctx, q)
		if err != nil {
			c.reportInventoryErr(ctx, err)
			return
		}
		sendMsg(ctx, c.prog, InventoryLoadedMsg{
			Revision: snap.Revision().String(),
			Hosts:    BuildHostItems(snap),
		})
		return
	}
	c.refreshInventoryFallback(ctx, q)
}

func (c *workbenchController) refreshInventoryFallback(ctx context.Context, q engine.InventoryQueryRequest) {
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
		sendMsg(ctx, c.prog, HaltedStateMsg{Err: err})
	}
	sendMsg(ctx, c.prog, InventoryLoadedMsg{Err: err})
}

// runMetricsStream 以有界最大连续批次（默认 MaxSamples=10000）驱动实时指标流，
// 避免核心默认 MaxSamples=1 导致首帧 0% 增量 CPU 后立即退出的问题；单批完成后自动续接直至取消。
func (c *workbenchController) runMetricsStream(ctx context.Context, target string, sortBy engine.ProcessSortBy, seq uint64) error {
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindMetrics, Target: target, Active: true, Seq: seq})
	topN := c.cfg.MetricsTopProcesses
	if topN <= 0 {
		topN = defaultTopProcesses
	}
	batchSamples := c.cfg.MetricsMaxSamples
	if batchSamples <= 0 {
		batchSamples = metricsBatchMaxSamples
	}
	var finalErr error
	for ctx.Err() == nil {
		frames, bErr := c.runMetricsBatch(ctx, target, sortBy, topN, batchSamples)
		if bErr != nil {
			finalErr = bErr
			break
		}
		if frames == 0 {
			break
		}
	}
	if errors.Is(finalErr, context.Canceled) {
		finalErr = nil
	}
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindMetrics, Target: target, Active: false, Seq: seq, Err: finalErr})
	return nil
}

func (c *workbenchController) runMetricsBatch(
	ctx context.Context,
	target string,
	sortBy engine.ProcessSortBy,
	topN, maxSamples int,
) (int, error) {
	stream, err := c.openAndAttachOpStream(ctx)
	if err != nil {
		return 0, err
	}
	var frames int
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
			MaxSamples:   maxSamples,
			TopProcesses: topN,
			SortBy:       algebraic.Some(sortBy),
			OnFrame: func(frame engine.HostMetricsFrame) {
				frames++
				sendMsg(wCtx, c.prog, MetricsFrameMsg{Target: target, Frame: frame})
			},
		})
		return sErr
	})
	return frames, runErr
}

// runLogsStream 启动远端日志跟随流：存在 OperationStream 时统一经事件流单路径消费（避免与 Output 重复入队），
// 仅在无 OperationStream 的极简桩环境下使用绑定 wCtx 的行缓冲写入器回退。
func (c *workbenchController) runLogsStream(ctx context.Context, target string, seq uint64) error {
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindLogs, Target: target, Active: true, Seq: seq})
	logTarget, err := resolveDefaultLogTarget(c.cfg)
	if err != nil {
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindLogs, Target: target, Active: false, Seq: seq, Err: err})
		return nil
	}
	stream, err := c.openAndAttachOpStream(ctx)
	if err != nil {
		sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindLogs, Target: target, Active: false, Seq: seq, Err: err})
		return nil
	}
	tailLines := c.cfg.LogTailLines
	if tailLines <= 0 {
		tailLines = defaultLogTailLines
	}
	runErr := c.execLogStreamInNursery(ctx, stream, target, logTarget, tailLines)
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}
	sendMsg(ctx, c.prog, StreamStateMsg{Kind: StreamKindLogs, Target: target, Active: false, Seq: seq, Err: runErr})
	return nil
}

func (c *workbenchController) execLogStreamInNursery(
	ctx context.Context,
	stream *events.OperationStream,
	target string,
	logTarget engine.LogTarget,
	tailLines int,
) error {
	return conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		defer closeStreamIfNonNil(stream)
		req := engine.LogStreamRequest{
			RemoteCall: engine.RemoteCall{
				TargetInput: engine.TargetInput{TargetSpec: target, CLIOptions: c.cfg.CLIOptions},
				CallOptions: engine.CallOptions{OperationStream: stream},
			},
			Target:    logTarget,
			TailLines: tailLines,
			Follow:    true,
		}
		if stream == nil {
			writer := &lineBufferedLogWriter{ctx: wCtx, prog: c.prog, target: target}
			defer writer.flush()
			req.Output = writer
		} else if c.proj == nil {
			if gErr := n.Go(func(pCtx context.Context) error { return watchOperationStream(pCtx, stream, c.prog) }); gErr != nil {
				return gErr
			}
		}
		_, sErr := c.cfg.Engine.StreamLogs(wCtx, req)
		return sErr
	})
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

func sendMsg(ctx context.Context, prog *tea.Program, msg tea.Msg) {
	if prog == nil || msg == nil || ctx.Err() != nil {
		return
	}
	prog.Send(msg)
}
