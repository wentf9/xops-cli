package observability

import (
	"bufio"
	"cmp"
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
)

func isDockerNameStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isValidDockerContainerName(raw string) bool {
	if len(raw) == 0 || len(raw) > 128 || !isDockerNameStart(raw[0]) {
		return false
	}
	for i := 1; i < len(raw); i++ {
		b := raw[i]
		if !isDockerNameStart(b) && b != '_' && b != '.' && b != '-' {
			return false
		}
	}
	return true
}

// StreamLogs 在严格 POSIX Bourne 校验（INV-E4）与 CapInspect 能力门控下流式采集远端文件或 Docker 容器日志：
//   - 文件日志在非 DirectOperator 配置档下执行 Round-2 软链规范化防受保护文件（如 /etc/shadow）读取逃逸；
//   - Docker 容器名按白名单正则强校验并用 QuotePOSIX 转义，彻底阻断参数与 Shell 注入；
//   - 输出受有界字节上限保护并实时流向可选 OperationStream 与调用方 io.Writer。
func (s *Service) StreamLogs(ctx context.Context, req LogStreamRequest) (LogStreamResult, error) {
	defer closeStream(req.OperationStream)
	targetHop, explicitProf, hasProf, tailN, maxBytes, err := s.validateLogRequest(ctx, req)
	if err != nil {
		return LogStreamResult{}, err
	}
	nodeID := resolveNodeID(targetHop, req.NodeID)
	gateReq, err := s.buildLogGateRequest(req, targetHop, nodeID, tailN)
	if err != nil {
		return LogStreamResult{}, err
	}
	startedAt := s.clock.Now().UTC().Round(0)
	var captured []byte
	var truncated bool
	out, gateErr := runAuthorized[security.CapInspect](ctx, s, req.Plan.PlanDigest(), nodeID, "stream_logs", gateReq, req.OperationStream,
		func(authCtx context.Context, binding security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			tee := &boundedOutputTee{ctx: runCtx, emitter: emitter, kind: events.OutputStreamStdout, mirror: req.Output, limit: maxBytes}
			errTee := &boundedOutputTee{ctx: runCtx, emitter: emitter, kind: events.OutputStreamStderr, limit: maxBytes}
			var preCheck func(context.Context, *pool.Lease) error
			if req.Target.Kind() == LogTargetFile && s.enforceStrictPaths() {
				preCheck = func(lCtx context.Context, lease *pool.Lease) error {
					return verifyLogTargetInLease(lCtx, lease, binding, req.Target.FilePath())
				}
			}
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return buildLogCommandPlan(prof, req.Target, tailN, req.Follow)
			}
			execOut, execErr := s.execPOSIXInLease(runCtx, req.Plan, targetHop, explicitProf, hasProf, preCheck, buildCmd, tee, errTee)
			captured, truncated = tee.snapshot()
			return execOut, execErr
		})
	if gateErr != nil && (out == nil || !out.IsValid()) {
		return LogStreamResult{}, gateErr
	}
	return LogStreamResult{
		outcome: out, data: captured, truncated: truncated,
		duration: algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)), valid: out != nil && out.IsValid(),
	}, gateErr
}

func (s *Service) validateLogRequest(ctx context.Context, req LogStreamRequest) (plan.HopSpec, execution.LaunchProfile, bool, int, uint64, error) {
	hop, err := s.validatePlanCall(ctx, req.Plan, req.Risk)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, 0, 0, err
	}
	if !req.Target.IsValid() {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, 0, 0, ErrInvalidLogTarget
	}
	prof, hasProf, err := validateRequestedPOSIXProfile(req.Profile)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, 0, 0, err
	}
	if d, ok := req.Timeout.Get(); ok && !d.IsPositive() {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, 0, 0, fmt.Errorf("%w: Timeout 必须为正时长", ErrInvalidRequest)
	}
	tailN := pickIf(req.TailLines == 0, defaultLogTailLines, req.TailLines)
	maxBytes := pickIf(req.MaxBytes == 0, uint64(defaultLogMaxBytes), req.MaxBytes)
	if tailN < 1 || tailN > maxLogTailLines || maxBytes > maxAllowedLogBytes {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, 0, 0, fmt.Errorf("%w: tail_lines 或 max_bytes 越界", ErrInvalidRequest)
	}
	return hop, prof, hasProf, tailN, maxBytes, nil
}

func (s *Service) buildLogGateRequest(req LogStreamRequest, hop plan.HopSpec, nodeID string, tailN int) (gate.GateRequest[security.CapInspect], error) {
	var paths []string
	targetDesc := req.Target.Container()
	if req.Target.Kind() == LogTargetFile {
		paths = []string{req.Target.FilePath().String()}
		targetDesc = req.Target.FilePath().String()
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: toolObservability, Action: "stream_logs",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()), CanonicalPaths: paths,
		PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{
			"target_kind": req.Target.Kind().String(), "target": targetDesc,
			"tail_lines": strconv.Itoa(tailN), "follow": strconv.FormatBool(req.Follow),
		},
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapInspect]](), err
	}
	var canonFn gate.CanonicalizeFunc
	if s.enforceStrictPaths() && req.Target.Kind() == LogTargetFile {
		canonFn = s.makeLogFileCanonicalizer(req.Plan, binding, req.Target.FilePath())
	}
	return gate.NewGateRequest[security.CapInspect](gate.GateRequestSpec[security.CapInspect]{
		Binding: binding, Risk: req.Risk.OrElse(security.RiskSafe),
		ScopeSummary: fmt.Sprintf("stream %s logs %s on %s", req.Target.Kind(), targetDesc, nodeID),
		Paths:        paths, Canonicalize: canonFn, Approval: req.Approval, OperationStream: req.OperationStream,
	})
}

func (s *Service) makeLogFileCanonicalizer(connPlan plan.SealedConnectionPlan, base security.OperationBinding, target pathalg.RemotePath) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		var canon pathalg.RemotePath
		err := s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
			rfs, rErr := lease.OpenRemoteFS(leaseCtx)
			if rErr != nil {
				return rErr
			}
			defer func() { _ = rfs.Close() }()
			canon, rErr = resolveCanonicalRemotePath(leaseCtx, rfs, target)
			return rErr
		})
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		paths := []string{canon.String()}
		canBind, err := security.NewOperationBinding(security.OperationBindingSpec{
			Capability: base.Capability(), Tool: base.Tool(), Action: base.Action(),
			NodeID: base.NodeID(), Endpoint: base.Endpoint(), CanonicalPaths: paths,
			PlanDigest: base.PlanDigest(), Parameters: base.Parameters(),
		})
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		return gate.CanonicalizeResult{Binding: canBind, Paths: paths}, nil
	}
}

func verifyLogTargetInLease(ctx context.Context, lease *pool.Lease, binding security.OperationBinding, target pathalg.RemotePath) error {
	rfs, err := lease.OpenRemoteFS(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = rfs.Close() }()
	return verifyRemotePathAuthorized(ctx, true, rfs, binding, target)
}

func buildLogCommandPlan(prof execution.LaunchProfile, target LogTarget, tailN int, follow bool) (execution.CommandPlan, error) {
	var cmd string
	switch target.Kind() {
	case LogTargetFile:
		q, err := execution.QuotePOSIX(target.FilePath().String())
		if err != nil {
			return zeroVal[execution.CommandPlan](), err
		}
		cmd = fmt.Sprintf("tail -n %d %s-- %s", tailN, pickIf(follow, "-f ", ""), q)
	case LogTargetDocker:
		q, err := execution.QuotePOSIX(target.Container())
		if err != nil {
			return zeroVal[execution.CommandPlan](), err
		}
		cmd = fmt.Sprintf("docker logs --tail %d %s-- %s", tailN, pickIf(follow, "-f ", ""), q)
	default:
		return zeroVal[execution.CommandPlan](), ErrInvalidLogTarget
	}
	return execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: prof, Command: cmd})
}

// StreamMetrics 在严格 POSIX Bourne 校验与 CapInspect 门控下采集远端 /proc NDJSON 主机指标流，
// 计算 CPU 增量利用率、确定性排序 Top-N 进程，并将指标快照以 CoalesceLatest 背压发射至 OperationStream。
func (s *Service) StreamMetrics(ctx context.Context, req MetricsStreamRequest) (MetricsStreamResult, error) {
	defer closeStream(req.OperationStream)
	targetHop, explicitProf, hasProf, interval, maxSamples, topN, sortBy, err := s.validateMetricsRequest(ctx, req)
	if err != nil {
		return MetricsStreamResult{}, err
	}
	nodeID := resolveNodeID(targetHop, req.NodeID)
	gateReq, err := buildMetricsGateRequest(req, targetHop, nodeID, interval, maxSamples, topN, sortBy)
	if err != nil {
		return MetricsStreamResult{}, err
	}
	startedAt := s.clock.Now().UTC().Round(0)
	var frames []HostMetricsFrame
	out, gateErr := runAuthorized[security.CapInspect](ctx, s, req.Plan.PlanDigest(), nodeID, "stream_metrics", gateReq, req.OperationStream,
		func(authCtx context.Context, _ security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			var rawBuf strings.Builder
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return buildMetricsProbePlan(prof, interval, maxSamples, topN)
			}
			execOut, execErr := s.execPOSIXInLease(runCtx, req.Plan, targetHop, explicitProf, hasProf, nil, buildCmd, &rawBuf, nil)
			frames = parseMetricsNDJSON(runCtx, rawBuf.String(), nodeID, s.clock.Now().UTC().Round(0), interval, topN, sortBy, req.OnFrame, emitter)
			return execOut, execErr
		})
	if gateErr != nil && (out == nil || !out.IsValid()) {
		return MetricsStreamResult{}, gateErr
	}
	return MetricsStreamResult{
		frames: frames, outcome: out,
		duration: algebraic.FromStdDuration(max(s.clock.Since(startedAt), 0)), valid: out != nil && out.IsValid(),
	}, gateErr
}

func (s *Service) validateMetricsRequest(ctx context.Context, req MetricsStreamRequest) (plan.HopSpec, execution.LaunchProfile, bool, algebraic.Duration, int, int, ProcessSortBy, error) {
	hop, err := s.validatePlanCall(ctx, req.Plan, req.Risk)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, algebraic.ZeroDuration(), 0, 0, ProcessSortInvalid, err
	}
	prof, hasProf, err := validateRequestedPOSIXProfile(req.Profile)
	if err != nil {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, algebraic.ZeroDuration(), 0, 0, ProcessSortInvalid, err
	}
	interval := req.Interval.OrElse(algebraic.FromStdDuration(defaultMetricsInterval))
	maxSamples := pickIf(req.MaxSamples == 0, defaultMetricsMaxSamples, req.MaxSamples)
	topN := pickIf(req.TopProcesses == 0, defaultMetricsTopProcs, req.TopProcesses)
	sortBy := req.SortBy.OrElse(ProcessSortCPU)
	if interval.Std() < minMetricsInterval || interval.Std() > maxMetricsInterval ||
		maxSamples < 1 || maxSamples > maxMetricsSamples || topN < 0 || topN > maxMetricsTopProcs || !sortBy.IsValid() {
		return zeroVal[plan.HopSpec](), zeroVal[execution.LaunchProfile](), false, algebraic.ZeroDuration(), 0, 0, ProcessSortInvalid, fmt.Errorf("%w: metrics 参数越界", ErrInvalidRequest)
	}
	return hop, prof, hasProf, interval, maxSamples, topN, sortBy, nil
}

func buildMetricsGateRequest(req MetricsStreamRequest, hop plan.HopSpec, nodeID string, interval algebraic.Duration, maxSamples, topN int, sortBy ProcessSortBy) (gate.GateRequest[security.CapInspect], error) {
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: toolObservability, Action: "stream_metrics",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()),
		PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{
			"interval": interval.String(), "max_samples": strconv.Itoa(maxSamples),
			"top_processes": strconv.Itoa(topN), "sort_by": sortBy.String(),
		},
	})
	if err != nil {
		return zeroVal[gate.GateRequest[security.CapInspect]](), err
	}
	return gate.NewGateRequest[security.CapInspect](gate.GateRequestSpec[security.CapInspect]{
		Binding: binding, Risk: req.Risk.OrElse(security.RiskSafe),
		ScopeSummary: fmt.Sprintf("stream metrics (%d samples) on %s", maxSamples, nodeID),
		Approval:     req.Approval, OperationStream: req.OperationStream,
	})
}

func buildMetricsProbePlan(prof execution.LaunchProfile, interval algebraic.Duration, maxSamples, topN int) (execution.CommandPlan, error) {
	sec := max(int(interval.Std()/time.Second), 1)
	script := fmt.Sprintf("i=0; while [ \"$i\" -lt %d ]; do hostname; cat /proc/stat /proc/loadavg /proc/meminfo /proc/uptime 2>/dev/null; i=$((i+1)); [ \"$i\" -lt %d ] && sleep %d; done # top=%d", maxSamples, maxSamples, sec, topN)
	return execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: prof, Command: script})
}

type rawMetricsSample struct {
	Hostname  string          `json:"hostname"`
	CPUTotal  uint64          `json:"cpu_total"`
	CPUIdle   uint64          `json:"cpu_idle"`
	CPUPct    float64         `json:"cpu_percent"`
	Load1     float64         `json:"load_1"`
	Load5     float64         `json:"load_5"`
	Load15    float64         `json:"load_15"`
	MemUsed   uint64          `json:"mem_used_bytes"`
	MemTotal  uint64          `json:"mem_total_bytes"`
	UptimeSec float64         `json:"uptime_sec"`
	Disks     []DiskMetric    `json:"disks"`
	Processes []ProcessMetric `json:"processes"`
}

func parseMetricsNDJSON(ctx context.Context, raw, nodeID string, sampledAt time.Time, interval algebraic.Duration, topN int, sortBy ProcessSortBy, onFrame func(HostMetricsFrame), emitter *obsEmitter) []HostMetricsFrame {
	var frames []HostMetricsFrame
	var prevTotal, prevIdle uint64
	hasPrev := false
	sc := bufio.NewScanner(strings.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), 2<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var sample rawMetricsSample
		if err := jsonv2.Unmarshal([]byte(line), &sample); err != nil {
			continue
		}
		cpuPct := computeCPUPercent(sample, prevTotal, prevIdle, hasPrev)
		if sample.CPUTotal > 0 {
			prevTotal, prevIdle, hasPrev = sample.CPUTotal, sample.CPUIdle, true
		}
		frame := buildHostMetricsFrame(nodeID, sampledAt, sample, cpuPct, topN, sortBy)
		frames = append(frames, frame)
		emitMetricsFrameEvents(ctx, emitter, frame, interval)
		if onFrame != nil {
			onFrame(frame)
		}
	}
	return frames
}

func computeCPUPercent(s rawMetricsSample, prevTotal, prevIdle uint64, hasPrev bool) float64 {
	if hasPrev && s.CPUTotal > prevTotal && s.CPUIdle >= prevIdle {
		dt, di := float64(s.CPUTotal-prevTotal), float64(s.CPUIdle-prevIdle)
		return clampPercent((dt - di) * 100.0 / dt)
	}
	return clampPercent(s.CPUPct)
}

func clampPercent(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	return min(v, 100)
}

func buildHostMetricsFrame(nodeID string, sampledAt time.Time, s rawMetricsSample, cpuPct float64, topN int, sortBy ProcessSortBy) HostMetricsFrame {
	memPct := pickIf(s.MemTotal > 0, clampPercent(float64(s.MemUsed)*100.0/float64(max(s.MemTotal, 1))), 0.0)
	procs := slices.Clone(s.Processes)
	slices.SortFunc(procs, func(a, b ProcessMetric) int {
		if sortBy == ProcessSortMem {
			if c := cmp.Compare(b.MemPercent, a.MemPercent); c != 0 {
				return c
			}
		} else if c := cmp.Compare(b.CPUPercent, a.CPUPercent); c != 0 {
			return c
		}
		return cmp.Compare(a.PID, b.PID)
	})
	if len(procs) > topN {
		procs = procs[:topN]
	}
	return HostMetricsFrame{
		NodeID: nodeID, SampledAt: sampledAt, Hostname: s.Hostname,
		CPUPercent: cpuPct, Load1: s.Load1, Load5: s.Load5, Load15: s.Load15,
		MemUsed: s.MemUsed, MemTotal: s.MemTotal, MemPercent: memPct,
		Uptime: algebraic.FromStdDuration(time.Duration(max(s.UptimeSec, 0) * float64(time.Second))),
		Disks:  slices.Clone(s.Disks), Processes: procs,
	}
}

func emitMetricsFrameEvents(ctx context.Context, emitter *obsEmitter, f HostMetricsFrame, interval algebraic.Duration) {
	if emitter == nil {
		return
	}
	labels := map[string]string{"node": f.NodeID}
	emitter.emitMetric(ctx, "host.cpu.percent", "percent", f.CPUPercent, interval, labels)
	emitter.emitMetric(ctx, "host.mem.percent", "percent", f.MemPercent, interval, labels)
	emitter.emitMetric(ctx, "host.load.1m", "load", f.Load1, interval, labels)
}
