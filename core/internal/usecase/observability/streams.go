package observability

import (
	"bytes"
	"cmp"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

func isAlnumASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isValidDockerContainerName(raw string) bool {
	if len(raw) == 0 || len(raw) > 128 || !isAlnumASCII(raw[0]) {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if b := raw[i]; !isAlnumASCII(b) && b != '_' && b != '.' && b != '-' {
			return false
		}
	}
	return true
}

// StreamLogs 在严格 POSIX Bourne 校验（INV-E4）与 CapInspect 能力门控下流式采集远端文件或 Docker 容器日志：
//   - 文件日志在非 DirectOperator 配置档下执行 Round-2 软链规范化防受保护文件（如 /etc/shadow）读取逃逸；
//   - Docker 容器名按白名单正则强校验并用 QuotePOSIX 转义，彻底阻断参数与 Shell 注入；
//   - 输出受 MaxOutputBytes 与本地有界上限双重保护，Follow=true 触达 maxBytes 时确定性停止且流向 OperationStream。
type logReqPrepared struct {
	posixCallBase
	tailN    int
	maxBytes uint64
}

func (s *Service) StreamLogs(ctx context.Context, req LogStreamRequest) (LogStreamResult, error) {
	defer closeStream(req.OperationStream)
	prep, err := s.validateLogRequest(ctx, req)
	if err != nil {
		return LogStreamResult{}, err
	}
	nodeID := resolveNodeID(prep.hop, req.NodeID)
	gateReq, err := s.buildLogGateRequest(req, prep.hop, nodeID, prep.tailN)
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
			streamCtx, cancelLimit := context.WithCancelCause(runCtx)
			defer cancelLimit(nil)
			tee := &boundedOutputTee{ctx: streamCtx, emitter: emitter, kind: events.OutputStreamStdout, mirror: req.Output, limit: prep.maxBytes}
			if req.Follow {
				tee.onLimit = func() { cancelLimit(errLogLimitReached) }
			}
			errTee := &boundedOutputTee{ctx: streamCtx, emitter: emitter, kind: events.OutputStreamStderr, limit: prep.maxBytes}
			var preCheck func(context.Context, *pool.Lease) error
			if req.Target.Kind() == LogTargetFile && s.enforceStrictPaths() {
				preCheck = func(lCtx context.Context, lease *pool.Lease) error {
					return withLeaseRemoteFS(lCtx, lease, func(rfs ports.RemoteFSPort) error {
						return verifyRemotePathAuthorized(lCtx, true, rfs, binding, req.Target.FilePath())
					})
				}
			}
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return buildLogCommandPlan(prof, req.Target, prep.tailN, req.Follow, prep.maxBytes)
			}
			execOut, execErr := s.execPOSIXInLease(streamCtx, req.Plan, prep.hop, prep.prof, prep.hasProf, preCheck, buildCmd, tee, errTee)
			captured, truncated = tee.snapshot()
			if req.Follow && errors.Is(context.Cause(streamCtx), errLogLimitReached) {
				// 只读跟随日志主动达到 maxBytes 上限：收敛为确定性有界完成，避免触发 OutcomeUnknown 误报。
				truncated = true
				doneOut, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), true)
				return doneOut, nil
			}
			return execOut, execErr
		})
	if gateErr != nil && (out == nil || !out.IsValid()) {
		return LogStreamResult{}, gateErr
	}
	return LogStreamResult{outcome: out, data: captured, truncated: truncated, duration: s.elapsed(startedAt), valid: out != nil && out.IsValid()}, gateErr
}

func (s *Service) validateLogRequest(ctx context.Context, req LogStreamRequest) (logReqPrepared, error) {
	base, err := s.validatePOSIXCall(ctx, req.Plan, req.Risk, req.Profile, req.Timeout)
	if err != nil {
		return logReqPrepared{}, err
	}
	if !req.Target.IsValid() {
		return logReqPrepared{}, ErrInvalidLogTarget
	}
	tailN, maxBytes := pickIf(req.TailLines == 0, defaultLogTailLines, req.TailLines), pickIf(req.MaxBytes == 0, uint64(defaultLogMaxBytes), req.MaxBytes)
	if tailN < 1 || tailN > maxLogTailLines || maxBytes > maxAllowedLogBytes {
		return logReqPrepared{}, fmt.Errorf("%w: tail_lines 或 max_bytes 越界", ErrInvalidRequest)
	}
	return logReqPrepared{posixCallBase: base, tailN: tailN, maxBytes: maxBytes}, nil
}

func (s *Service) buildLogGateRequest(req LogStreamRequest, hop plan.HopSpec, nodeID string, tailN int) (gate.GateRequest[security.CapInspect], error) {
	var paths []string
	targetDesc := req.Target.Container()
	if req.Target.Kind() == LogTargetFile {
		targetDesc = req.Target.FilePath().String()
		paths = []string{targetDesc}
	}
	bindSpec := security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: toolObservability, Action: "stream_logs",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()), CanonicalPaths: paths,
		PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{"target_kind": req.Target.Kind().String(), "target": targetDesc, "tail_lines": strconv.Itoa(tailN), "follow": strconv.FormatBool(req.Follow)},
	}
	var canonFn gate.CanonicalizeFunc
	if s.enforceStrictPaths() && req.Target.Kind() == LogTargetFile {
		canonFn = s.makeLogFileCanonicalizer(req.Plan, bindSpec, req.Target.FilePath())
	}
	return newObsGateReq[security.CapInspect](bindSpec, req.Risk.OrElse(security.RiskSafe), fmt.Sprintf("stream %s logs %s on %s", req.Target.Kind(), targetDesc, nodeID), paths, canonFn, req.Approval, req.OperationStream)
}

func (s *Service) makeLogFileCanonicalizer(connPlan plan.SealedConnectionPlan, baseSpec security.OperationBindingSpec, target pathalg.RemotePath) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		var canon pathalg.RemotePath
		err := s.pool.WithLease(ctx, connPlan, func(leaseCtx context.Context, lease *pool.Lease) error {
			return withLeaseRemoteFS(leaseCtx, lease, func(rfs ports.RemoteFSPort) error {
				var rErr error
				canon, rErr = resolveCanonicalRemotePath(leaseCtx, rfs, target)
				return rErr
			})
		})
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		// 严格单调并集：同时保留词法路径与规范化真实路径，满足 Round-2 仅增不减策略约束（ADR-008）。
		paths := []string{target.String()}
		if cs := canon.String(); cs != target.String() {
			paths = append(paths, cs)
			slices.Sort(paths)
		}
		baseSpec.CanonicalPaths = paths
		canBind, err := security.NewOperationBinding(baseSpec)
		if err != nil {
			return gate.CanonicalizeResult{}, err
		}
		return gate.CanonicalizeResult{Binding: canBind, Paths: paths}, nil
	}
}

func buildLogCommandPlan(prof execution.LaunchProfile, target LogTarget, tailN int, follow bool, maxBytes uint64) (execution.CommandPlan, error) {
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
	return execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: prof, Command: cmd, MaxOutputBytes: algebraic.Some(maxBytes)})
}

type metricsReqPrepared struct {
	posixCallBase
	interval         algebraic.Duration
	maxSamples, topN int
	sortBy           ProcessSortBy
}

// StreamMetrics 在严格 POSIX Bourne 校验与 CapInspect 门控下流式采集远端 /proc NDJSON 主机指标，
// 逐行实时解析并盖采样时钟、计算 CPU 增量利用率、确定性排序 Top-N 进程并推送至 OperationStream 与 OnFrame。
func (s *Service) StreamMetrics(ctx context.Context, req MetricsStreamRequest) (MetricsStreamResult, error) {
	defer closeStream(req.OperationStream)
	prep, err := s.validateMetricsRequest(ctx, req)
	if err != nil {
		return MetricsStreamResult{}, err
	}
	nodeID := resolveNodeID(prep.hop, req.NodeID)
	gateReq, err := buildMetricsGateRequest(req, prep.hop, nodeID, prep)
	if err != nil {
		return MetricsStreamResult{}, err
	}
	startedAt := s.clock.Now().UTC().Round(0)
	var frames []HostMetricsFrame
	out, gateErr := runAuthorized[security.CapInspect](ctx, s, req.Plan.PlanDigest(), nodeID, "stream_metrics", gateReq, req.OperationStream,
		func(authCtx context.Context, _ security.OperationBinding, emitter *obsEmitter) (execution.ExecutionOutcome, error) {
			runCtx, cancel := applyOptionalTimeout(authCtx, req.Timeout)
			defer cancel()
			streamW := &metricsStreamWriter{ctx: runCtx, nodeID: nodeID, clock: s.clock, interval: prep.interval, maxSamples: prep.maxSamples, topN: prep.topN, sortBy: prep.sortBy, onFrame: req.OnFrame, emitter: emitter}
			buildCmd := func(prof execution.LaunchProfile) (execution.CommandPlan, error) {
				return buildMetricsProbePlan(prof, prep)
			}
			execOut, execErr := s.execPOSIXInLease(runCtx, req.Plan, prep.hop, prep.prof, prep.hasProf, nil, buildCmd, streamW, nil)
			streamW.flush()
			frames = streamW.snapshot()
			return execOut, execErr
		})
	if gateErr != nil && (out == nil || !out.IsValid()) {
		return MetricsStreamResult{}, gateErr
	}
	return MetricsStreamResult{frames: frames, outcome: out, duration: s.elapsed(startedAt), valid: out != nil && out.IsValid()}, gateErr
}

func (s *Service) validateMetricsRequest(ctx context.Context, req MetricsStreamRequest) (metricsReqPrepared, error) {
	base, err := s.validatePOSIXCall(ctx, req.Plan, req.Risk, req.Profile, req.Timeout)
	if err != nil {
		return metricsReqPrepared{}, err
	}
	interval := req.Interval.OrElse(algebraic.FromStdDuration(defaultMetricsInterval))
	maxSamples, topN, sortBy := pickIf(req.MaxSamples == 0, 1, req.MaxSamples), pickIf(req.TopProcesses == 0, defaultMetricsTopProcs, req.TopProcesses), req.SortBy.OrElse(ProcessSortCPU)
	if interval.Std() < minMetricsInterval || interval.Std() > maxMetricsInterval ||
		maxSamples < 1 || maxSamples > maxMetricsSamples || topN < 0 || topN > maxMetricsTopProcs || !sortBy.IsValid() {
		return metricsReqPrepared{}, fmt.Errorf("%w: metrics 参数越界", ErrInvalidRequest)
	}
	return metricsReqPrepared{posixCallBase: base, interval: interval, maxSamples: maxSamples, topN: topN, sortBy: sortBy}, nil
}

func buildMetricsGateRequest(req MetricsStreamRequest, hop plan.HopSpec, nodeID string, p metricsReqPrepared) (gate.GateRequest[security.CapInspect], error) {
	return newObsGateReq[security.CapInspect](security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: toolObservability, Action: "stream_metrics",
		NodeID: nodeID, Endpoint: algebraic.Some(hop.Endpoint()), PlanDigest: algebraic.Some(req.Plan.PlanDigest().SecurityDigest()),
		Parameters: map[string]string{"interval": p.interval.String(), "max_samples": strconv.Itoa(p.maxSamples), "top_processes": strconv.Itoa(p.topN), "sort_by": p.sortBy.String()},
	}, req.Risk.OrElse(security.RiskSafe), fmt.Sprintf("stream metrics (%d samples) on %s", p.maxSamples, nodeID), nil, nil, req.Approval, req.OperationStream)
}

// buildMetricsProbePlan 构造纯 POSIX Bourne + awk 的 NDJSON 主机指标采集脚本，
// 使用 LC_ALL=C 保证小数点格式与 JSON 合法性，无 /proc 节点自动退化输出 0 值字段。
func buildMetricsProbePlan(prof execution.LaunchProfile, p metricsReqPrepared) (execution.CommandPlan, error) {
	sortCol := pickIf(p.sortBy == ProcessSortMem, 4, 3)
	procSnippet := `PROCS=""`
	if p.topN > 0 {
		procSnippet = fmt.Sprintf(`PROCS=$(ps -eo pid=,user=,pcpu=,pmem=,comm= 2>/dev/null | sort -rn -k%d,%d 2>/dev/null | head -n %d | awk 'NF>=5&&$1+0>0{u=$2;c=$5;for(i=6;i<=NF;i++)c=c" "$i;gsub(/\\/,"\\\\",u);gsub(/"/,"\\\"",u);gsub(/\\/,"\\\\",c);gsub(/"/,"\\\"",c);printf "%%s{\"pid\":%%d,\"user\":\"%%s\",\"cpu_percent\":%%.2f,\"mem_percent\":%%.2f,\"command\":\"%%s\"}",(n++?",":""),$1+0,u,$3+0,$4+0,c}')`, sortCol, sortCol, p.topN)
	}
	sleepSec, fallbackSec := fmt.Sprintf("%.3f", p.interval.Std().Seconds()), max(int((p.interval.Std()+time.Second-1)/time.Second), 1)
	script := fmt.Sprintf(`LC_ALL=C; export LC_ALL
xops_sample() {
  H=$(hostname 2>/dev/null || uname -n 2>/dev/null || printf 'unknown')
  CPU=$(awk '/^cpu /{t=0;for(i=2;i<=NF;i++)t+=$i;printf "%%.0f %%.0f",t,($5+0)+($6+0);exit}' /proc/stat 2>/dev/null || printf '0 0')
  LOAD=$(awk '{printf "%%.2f %%.2f %%.2f",$1+0,$2+0,$3+0;exit}' /proc/loadavg 2>/dev/null || printf '0 0 0')
  MEM=$(awk '/^MemTotal:/{t=$2*1024}/^MemAvailable:/{a=$2*1024;ha=1}/^MemFree:/{f=$2*1024}/^Buffers:/{b=$2*1024}/^Cached:/{c=$2*1024}END{if(!ha)a=f+b+c;u=(t>a)?t-a:0;printf "%%.0f %%.0f",u,t}' /proc/meminfo 2>/dev/null || printf '0 0')
  UP=$(awk '{printf "%%.3f",$1+0;exit}' /proc/uptime 2>/dev/null || printf '0')
  DISKS=$(df -P -k 2>/dev/null | awk 'NR>1&&NF>=6&&$2+0>0{m=$6;for(i=7;i<=NF;i++)m=m" "$i;gsub(/\\/,"\\\\",m);gsub(/"/,"\\\"",m);t=$2*1024;u=$3*1024;p=(t>0)?u*100/t:0;printf "%%s{\"mount\":\"%%s\",\"used_bytes\":%%.0f,\"total_bytes\":%%.0f,\"used_percent\":%%.2f}",(n++?",":""),m,u,t,p}')
  %s
  awk -v h="$H" -v cpu="$CPU" -v ld="$LOAD" -v mem="$MEM" -v up="$UP" -v dk="$DISKS" -v pr="$PROCS" 'BEGIN{gsub(/\\/,"\\\\",h);gsub(/"/,"\\\"",h);split(cpu,c," ");split(ld,l," ");split(mem,m," ");printf "{\"hostname\":\"%%s\",\"cpu_total\":%%.0f,\"cpu_idle\":%%.0f,\"load_1\":%%.2f,\"load_5\":%%.2f,\"load_15\":%%.2f,\"mem_used_bytes\":%%.0f,\"mem_total_bytes\":%%.0f,\"uptime_sec\":%%s,\"disks\":[%%s],\"processes\":[%%s]}\n",h,c[1]+0,c[2]+0,l[1]+0,l[2]+0,l[3]+0,m[1]+0,m[2]+0,(up==""?"0":up),dk,pr}'
}
i=0; while [ "$i" -lt %d ]; do xops_sample; i=$((i+1)); if [ "$i" -lt %d ]; then sleep %s 2>/dev/null || sleep %d; fi; done`,
		procSnippet, p.maxSamples, p.maxSamples, sleepSec, fallbackSec)
	maxOut := min(max(uint64(p.maxSamples)*65536, uint64(defaultLogMaxBytes)), execution.MaxAllowedOutputBytes)
	return execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: prof, Command: script, MaxOutputBytes: algebraic.Some(maxOut)})
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

// metricsStreamWriter 实现有界单行缓冲的实时 NDJSON 流解析器：
// 每抵达一行立即盖采样时间戳、计算 CPU 增量并回调 OnFrame/OperationStream，超长单行安全丢弃防 OOM。
type metricsStreamWriter struct {
	ctx                 context.Context
	nodeID              string
	clock               ports.Clock
	interval            algebraic.Duration
	maxSamples, topN    int
	sortBy              ProcessSortBy
	onFrame             func(HostMetricsFrame)
	emitter             *obsEmitter
	mu                  sync.Mutex
	lineBuf             []byte
	prevTotal, prevIdl  uint64
	discarding, hasPrev bool
	frames              []HostMetricsFrame
}

func (w *metricsStreamWriter) Write(p []byte) (int, error) {
	for rest := p; len(rest) > 0; {
		if nl := bytes.IndexByte(rest, '\n'); nl < 0 {
			w.takeLine(rest, false)
			break
		} else {
			if line, ok := w.takeLine(rest[:nl], true); ok {
				w.handleLine(line)
			}
			rest = rest[nl+1:]
		}
	}
	return len(p), nil
}
func (w *metricsStreamWriter) takeLine(chunk []byte, eol bool) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.discarding {
		if eol {
			w.discarding = false
		}
		return "", false
	}
	if len(w.lineBuf)+len(chunk) > maxMetricsLineBytes {
		w.lineBuf = w.lineBuf[:0]
		w.discarding = !eol
		return "", false
	}
	w.lineBuf = append(w.lineBuf, chunk...)
	if !eol {
		return "", false
	}
	line := strings.TrimSpace(string(w.lineBuf))
	w.lineBuf = w.lineBuf[:0]
	return line, line != "" && line[0] == '{'
}

func (w *metricsStreamWriter) flush() {
	if line, ok := w.takeLine(nil, true); ok {
		w.handleLine(line)
	}
}

func (w *metricsStreamWriter) handleLine(line string) {
	var sample rawMetricsSample
	if jsonv2.Unmarshal([]byte(line), &sample) != nil {
		return
	}
	sampledAt := w.clock.Now().UTC().Round(0)
	w.mu.Lock()
	cpuPct := computeCPUPercent(sample, w.prevTotal, w.prevIdl, w.hasPrev)
	if sample.CPUTotal > 0 {
		w.prevTotal, w.prevIdl, w.hasPrev = sample.CPUTotal, sample.CPUIdle, true
	}
	frame := buildHostMetricsFrame(w.nodeID, sampledAt, sample, cpuPct, w.topN, w.sortBy)
	if len(w.frames) < w.maxSamples {
		w.frames = append(w.frames, frame)
	}
	w.mu.Unlock()
	emitMetricsFrameEvents(w.ctx, w.emitter, frame, w.interval)
	if w.onFrame != nil {
		w.onFrame(frame)
	}
}

func (w *metricsStreamWriter) snapshot() []HostMetricsFrame {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.frames)
}

func computeCPUPercent(s rawMetricsSample, prevTotal, prevIdle uint64, hasPrev bool) float64 {
	if hasPrev && s.CPUTotal > prevTotal && s.CPUIdle >= prevIdle {
		dt, di := float64(s.CPUTotal-prevTotal), float64(s.CPUIdle-prevIdle)
		return clampPercent((dt - di) * 100.0 / dt)
	}
	return clampPercent(s.CPUPct)
}
func clampPercent(v float64) float64 {
	return pickIf(math.IsNaN(v) || math.IsInf(v, 0) || v < 0, 0.0, min(v, 100.0))
}
func clampUptime(sec float64) algebraic.Duration {
	if math.IsNaN(sec) || sec <= 0 {
		return algebraic.ZeroDuration()
	}
	return algebraic.FromStdDuration(time.Duration(min(sec, float64(maxUptimeSeconds)) * float64(time.Second)))
}
func buildHostMetricsFrame(nodeID string, sampledAt time.Time, s rawMetricsSample, cpuPct float64, topN int, sortBy ProcessSortBy) HostMetricsFrame {
	memPct := pickIf(s.MemTotal > 0, clampPercent(float64(s.MemUsed)*100.0/float64(max(s.MemTotal, 1))), 0.0)
	procs := slices.Clone(s.Processes)
	slices.SortFunc(procs, func(a, b ProcessMetric) int {
		if c := pickIf(sortBy == ProcessSortMem, cmp.Compare(b.MemPercent, a.MemPercent), cmp.Compare(b.CPUPercent, a.CPUPercent)); c != 0 {
			return c
		}
		return cmp.Compare(a.PID, b.PID)
	})
	if len(procs) > topN {
		procs = procs[:topN]
	}
	return HostMetricsFrame{NodeID: nodeID, SampledAt: sampledAt, Hostname: s.Hostname, CPUPercent: cpuPct, Load1: s.Load1, Load5: s.Load5, Load15: s.Load15, MemUsed: s.MemUsed, MemTotal: s.MemTotal, MemPercent: memPct, Uptime: clampUptime(s.UptimeSec), Disks: slices.Clone(s.Disks), Processes: procs}
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
