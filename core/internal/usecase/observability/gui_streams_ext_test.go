package observability_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/observability"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口契约断言集中于外置测试文件，核验纯内存测试替身满足出站端口契约。
var (
	_ ports.DialerPort    = (*obsDialer)(nil)
	_ ports.TransportConn = (*obsConn)(nil)
	_ ports.RemoteSession = (*obsSession)(nil)
	_ ports.RemoteFSPort  = (*obsRemoteFS)(nil)
)

type obsCmdFunc func(ctx context.Context, cmd execution.CommandPlan, stdout, stderr io.Writer) (execution.ExecutionOutcome, error)

type obsDialer struct {
	mu           sync.Mutex
	onCmd        obsCmdFunc
	rfs          *sim.SimRemoteFS
	dialSawLease atomic.Bool
	sessSawLease atomic.Bool
	sessSawOpID  atomic.Bool
	openCount    atomic.Int64
}

func (d *obsDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	if trace.InLeaseScope(ctx) {
		d.dialSawLease.Store(true)
	}
	c := &obsConn{dialer: d, dig: dig, ep: hop.Endpoint()}
	c.alive.Store(true)
	return c, nil
}

type obsConn struct {
	dialer *obsDialer
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	alive  atomic.Bool
}

func (c *obsConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *obsConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *obsConn) IsAlive() bool                       { return c.alive.Load() }
func (c *obsConn) SendKeepalive(context.Context) error { return nil }
func (c *obsConn) Close() error                        { c.alive.Store(false); return nil }
func (c *obsConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (c *obsConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *obsConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (c *obsConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *obsConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return nil, ports.ErrUnsupported
}
func (c *obsConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	c.dialer.openCount.Add(1)
	if trace.InLeaseScope(ctx) {
		c.dialer.sessSawLease.Store(true)
	}
	if _, ok := trace.OpIDFromContext(ctx); ok {
		c.dialer.sessSawOpID.Store(true)
	}
	return &obsSession{dialer: c.dialer}, nil
}
func (c *obsConn) OpenRemoteFS(context.Context) (ports.RemoteFSPort, error) {
	return &obsRemoteFS{inner: c.dialer.rfs}, nil
}

type obsSession struct {
	dialer  *obsDialer
	cmd     execution.CommandPlan
	streams ports.ExecStreams
}

func (s *obsSession) StdinPipe() (io.WriteCloser, error) { return nil, ports.ErrUnsupported }
func (s *obsSession) StdoutPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *obsSession) StderrPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *obsSession) StartShell(context.Context, ports.ExecStreams) error {
	return ports.ErrUnsupported
}
func (s *obsSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (s *obsSession) Signal(context.Context, string) error                { return nil }
func (s *obsSession) Close() error                                        { return nil }
func (s *obsSession) Start(_ context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	s.cmd, s.streams = cmd, streams
	return nil
}
func (s *obsSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	s.dialer.mu.Lock()
	fn := s.dialer.onCmd
	s.dialer.mu.Unlock()
	if fn != nil {
		return fn(ctx, s.cmd, s.streams.Stdout, s.streams.Stderr)
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}

type obsRemoteFS struct{ inner *sim.SimRemoteFS }

func (r *obsRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	return r.inner.RealPath(ctx, p)
}
func (r *obsRemoteFS) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.inner.Stat(ctx, p)
}
func (r *obsRemoteFS) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.inner.Lstat(ctx, p)
}
func (r *obsRemoteFS) ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error) {
	return r.inner.ReadLink(ctx, p)
}
func (r *obsRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]ports.RemoteDirEntry, error) {
	return r.inner.ReadDir(ctx, dir)
}

//xops:syncclosure
//xops:borrowed
func (r *obsRemoteFS) WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ports.ReadLimits, fn func(rd io.Reader, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	var copied []byte
	var sz int64
	if err := r.inner.WithReadFile(ctx, p, limits, func(rd io.Reader, size int64) error {
		sz = size
		var rErr error
		copied, rErr = io.ReadAll(rd)
		return rErr
	}); err != nil {
		return err
	}
	return fn(bytes.NewReader(copied), sz)
}
func (r *obsRemoteFS) ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error) {
	return r.inner.ReadChunk(ctx, p, offset, dst, length)
}
func (r *obsRemoteFS) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, rd io.Reader) (ports.RemoteFileStat, error) {
	return r.inner.WriteFileAtomic(ctx, p, spec, rd)
}
func (r *obsRemoteFS) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, rd io.Reader, length int64) error {
	return r.inner.WriteChunk(ctx, p, offset, rd, length)
}
func (r *obsRemoteFS) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec ports.RemoteRenameSpec) error {
	return r.inner.RenameAtomic(ctx, oldPath, newPath, spec)
}
func (r *obsRemoteFS) Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error {
	return r.inner.Chmod(ctx, p, perm)
}
func (r *obsRemoteFS) Chtimes(ctx context.Context, p pathalg.RemotePath, a, m time.Time) error {
	return r.inner.Chtimes(ctx, p, a, m)
}
func (r *obsRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	return r.inner.MkdirAll(ctx, dir, perm)
}
func (r *obsRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	return r.inner.Remove(ctx, p)
}
func (r *obsRemoteFS) RemoveDir(ctx context.Context, dir pathalg.RemotePath) error {
	return r.inner.RemoveDir(ctx, dir)
}
func (r *obsRemoteFS) Close() error { return nil }

type obsRigOpts struct {
	profile      gate.PolicyProfileKind
	fallback     gate.NoElicitFallback
	omitScopedFS bool
	probeResult  ports.ShellProbeResult
}

type obsRig struct {
	clock      *sim.SimClock
	rng        *sim.SeededRand
	bus        *events.SystemBus
	auditClust *sim.SimAuditCluster
	auditSink  *sim.SimAuditSink
	rfs        *sim.SimRemoteFS
	dialer     *obsDialer
	scopedFS   *sim.SimScopedRootFS
	forwarder  *sim.SimForwarder
	probe      *sim.SimShellProbe
	pool       *pool.Pool
	gate       *gate.Gate
	svc        *observability.Service
	plan       plan.SealedConnectionPlan
}

func newObsRig(t *testing.T, opts obsRigOpts) *obsRig {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261126)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 64})
	mustNoErr(t, err, "NewSystemBus")
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	mustNoErr(t, err, "NewSinkFromEntropy")
	rfs := sim.NewSimRemoteFS(clk)
	dialer := &obsDialer{rfs: rfs}
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{Dialer: dialer, Clock: clk, Entropy: rng, Bus: bus})
	mustNoErr(t, err, "NewPool")

	prof := opts.profile
	if !prof.IsValid() {
		prof = gate.PolicyProfileDirectOperator
	}
	fb := opts.fallback
	if !fb.IsValid() {
		fb = gate.NoElicitFallbackDeny
	}
	rules := make([]pathalg.ProtectedRule, 0)
	for _, pat := range gate.StrictDefaultProtectedPatterns() {
		r, rErr := pathalg.ParseProtectedRule(pat)
		mustNoErr(t, rErr, "ParseProtectedRule")
		rules = append(rules, r)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous, NoElicitFallback: fb, ProtectedRules: rules,
	})
	mustNoErr(t, err, "NewGuardrailPolicy")
	g, err := gate.NewGate(gate.GateConfig{
		Profile: prof, Policy: pol, AuditSink: sink, Clock: clk, Entropy: rng, SystemBus: bus,
		OnHalt: func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	mustNoErr(t, err, "NewGate")

	scoped := sim.NewSimScopedRootFS(clk)
	fwd := sim.NewSimForwarder()
	var probe *sim.SimShellProbe
	if opts.probeResult.IsValid() {
		probe = sim.NewSimShellProbe(opts.probeResult)
	}
	cfg := observability.ServiceConfig{
		Gate: g, Pool: p, Clock: clk, Entropy: rng, Forwarder: fwd, SystemBus: bus,
	}
	if probe != nil {
		cfg.ShellProbe = probe
	}
	if !opts.omitScopedFS {
		cfg.ScopedFS = scoped
	}
	svc, err := observability.NewService(cfg)
	mustNoErr(t, err, "observability.NewService")
	return &obsRig{
		clock: clk, rng: rng, bus: bus, auditClust: cluster, auditSink: sink,
		rfs: rfs, dialer: dialer, scopedFS: scoped, forwarder: fwd, probe: probe,
		pool: p, gate: g, svc: svc, plan: makeObsPlan(t, "node-obs-1", "10.2.0.1"),
	}
}

func (r *obsRig) close() {
	if r.pool != nil {
		_ = r.pool.Close()
	}
	if r.auditSink != nil {
		_ = r.auditSink.Close()
	}
	if r.bus != nil {
		r.bus.Close()
	}
}

func makeObsPlan(t *testing.T, nodeID, host string) plan.SealedConnectionPlan {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	mustNoErr(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, 22)
	mustNoErr(t, err, "NewEndpoint")
	u, err := option.ParseUsername("ops")
	mustNoErr(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	mustNoErr(t, err, "NewAuthAgent")
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	mustNoErr(t, err, "ResolveEffectivePolicy")
	hop, err := plan.NewHopSpecFromAuth(0, nodeID, u, auth, eff)
	mustNoErr(t, err, "NewHopSpecFromAuth")
	pl, err := plan.SealConnectionPlan(hop)
	mustNoErr(t, err, "SealConnectionPlan")
	return pl
}

func makeApprovalForChal(t *testing.T, chalErr *gate.ApprovalChallengeError) gate.ApprovalSubmission {
	t.Helper()
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, chalErr.EnvelopeDigest(), "approved")
	mustNoErr(t, err, "NewApprovalDecisionResponse")
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: algebraic.Some(chalErr.Envelope()), Response: resp,
	})
	mustNoErr(t, err, "NewApprovalSubmission")
	return sub
}

func TestStreamLogsPOSIXValidationRound2AndDockerInjection(t *testing.T) {
	defer goleak.VerifyNone(t)
	// Docker 容器名称注入防护。
	for _, bad := range []string{"", "-flag", "web;id", "web $(whoami)", "a/b"} {
		if _, err := observability.NewDockerLogTarget(bad); !errors.Is(err, observability.ErrInvalidLogTarget) {
			t.Fatalf("expected ErrInvalidLogTarget for %q, got %v", bad, err)
		}
	}
	rig := newObsRig(t, obsRigOpts{profile: gate.PolicyProfileStrictAgent, fallback: gate.NoElicitFallbackDeny})
	defer rig.close()

	// 非 POSIX Shell Profile 立即失败关闭且 0 次会话打开。
	psProf, err := execution.NewLaunchProfile(execution.LaunchProfileSpec{
		Dialect: algebraic.Some(execution.DialectPowerShell), Interpreter: execution.InterpreterPwsh, Login: execution.LoginModeInherit,
	})
	mustNoErr(t, err, "NewLaunchProfile ps")
	dkTarget, err := observability.NewDockerLogTarget("api_svc.1")
	mustNoErr(t, err, "NewDockerLogTarget")
	if _, err := rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Profile: algebraic.Some(psProf), Target: dkTarget,
	}); !errors.Is(err, observability.ErrPOSIXShellRequired) || rig.dialer.openCount.Load() != 0 {
		t.Fatalf("expected ErrPOSIXShellRequired with 0 opens, err=%v", err)
	}

	// 文件日志指向软链 -> /etc/shadow，在 StrictAgent 下被 Round-2 规范化拦截。
	linkP, _ := pathalg.ParseRemotePath("/tmp/app.log")
	mustNoErr(t, rig.rfs.PutSymlink(linkP, "/etc/shadow"), "PutSymlink")
	fileTarget, err := observability.NewFileLogTarget(linkP)
	mustNoErr(t, err, "NewFileLogTarget")
	if _, err := rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Target: fileTarget,
	}); err == nil {
		t.Fatalf("expected symlink to /etc/shadow to be denied by Round-2")
	}

	// 文件日志指向安全软链 /tmp/safe.log -> /tmp/real.log，验证 StrictAgent 下 Round-2 单调并集放行。
	realLog, _ := pathalg.ParseRemotePath("/tmp/real.log")
	safeLink, _ := pathalg.ParseRemotePath("/tmp/safe.log")
	tmpDir, _ := pathalg.ParseRemotePath("/tmp")
	mustNoErr(t, rig.rfs.MkdirAll(context.Background(), tmpDir, 0o755), "MkdirAll /tmp")
	mustNoErr(t, rig.rfs.PutSymlink(safeLink, realLog.String()), "PutSymlink safe")
	safeFileTarget, err := observability.NewFileLogTarget(safeLink)
	mustNoErr(t, err, "NewFileLogTarget safe")
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, "safe-log\n")
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	safeRes, err := rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{Plan: rig.plan, Target: safeFileTarget})
	mustNoErr(t, err, "StreamLogs safe symlink Round-2 union")
	if string(safeRes.Data()) != "safe-log\n" {
		t.Fatalf("unexpected safe log data: %q", safeRes.Data())
	}

	// 正常 Docker 日志流，校验 ADR-008/009 嵌套顺序与输出镜像。
	rig.dialer.onCmd = func(_ context.Context, cmd execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		if !strings.Contains(cmd.Command(), "docker logs --tail 25 -- 'api_svc.1'") {
			return nil, errors.New("unexpected command: " + cmd.Command())
		}
		_, _ = io.WriteString(stdout, "line1\nline2\n")
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	var mirror bytes.Buffer
	res, err := rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Target: dkTarget, TailLines: 25, Output: &mirror,
	})
	mustNoErr(t, err, "StreamLogs docker")
	if string(res.Data()) != "line1\nline2\n" || mirror.String() != "line1\nline2\n" {
		t.Fatalf("unexpected log data: %q", res.Data())
	}
	if rig.dialer.dialSawLease.Load() || !rig.dialer.sessSawLease.Load() || !rig.dialer.sessSawOpID.Load() {
		t.Fatalf("unexpected lease/opID nesting")
	}
}

func TestStreamMetricsNDJSONDeltaProjectionAndShellProbe(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newObsRig(t, obsRigOpts{})
	defer rig.close()

	ndjson := strings.Join([]string{
		`{"hostname":"web1","cpu_total":1000,"cpu_idle":700,"load_1":0.5,"mem_used_bytes":500,"mem_total_bytes":1000,"uptime_sec":3600,"processes":[{"pid":20,"user":"app","cpu_percent":12.5,"mem_percent":30.0,"command":"java"},{"pid":10,"user":"root","cpu_percent":40.0,"mem_percent":5.0,"command":"nginx"}]}`,
		`{"hostname":"web1","cpu_total":2000,"cpu_idle":1200,"load_1":1.2,"mem_used_bytes":600,"mem_total_bytes":1000,"uptime_sec":3602,"processes":[{"pid":20,"user":"app","cpu_percent":12.5,"mem_percent":30.0,"command":"java"},{"pid":10,"user":"root","cpu_percent":40.0,"mem_percent":5.0,"command":"nginx"}]}`,
	}, "\n") + "\n"
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, ndjson)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}

	proj, err := observability.NewProjection(context.Background(), observability.ProjectionConfig{})
	mustNoErr(t, err, "NewProjection")
	defer func() { _ = proj.Close() }()

	tid, _ := security.ParseTraceID("trace-met")
	oid, _ := security.ParseOperationID("op-met")
	opStream, err := events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: 32})
	mustNoErr(t, err, "NewOperationStream")
	mustNoErr(t, proj.AttachOperationStream(opStream), "AttachOperationStream")

	var res observability.MetricsStreamResult
	var streamErr error
	mustNoErr(t, conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		return n.Go(func(c context.Context) error {
			res, streamErr = rig.svc.StreamMetrics(c, observability.MetricsStreamRequest{
				Plan: rig.plan, MaxSamples: 2, TopProcesses: 2, SortBy: algebraic.Some(observability.ProcessSortMem), OperationStream: opStream,
			})
			return nil
		})
	}), "RunWait")
	mustNoErr(t, streamErr, "StreamMetrics")
	frames := res.Frames()
	if len(frames) != 2 || frames[1].CPUPercent != 50.0 || frames[1].MemPercent != 60.0 || frames[1].Processes[0].PID != 20 {
		t.Fatalf("unexpected metrics frames: %+v", frames)
	}

	// ShellProbe 探测为 Windows cmd -> 失败关闭返回 ErrPOSIXShellRequired。
	cmdProbe, err := ports.NewShellProbeResult(ports.ShellProbeResultSpec{
		Dialect: execution.DialectCmd, Interpreter: execution.InterpreterCmd, OSFamily: "windows", ProbeStage: 1,
	})
	mustNoErr(t, err, "NewShellProbeResult cmd")
	winRig := newObsRig(t, obsRigOpts{probeResult: cmdProbe})
	defer winRig.close()
	if _, err := winRig.svc.StreamMetrics(context.Background(), observability.MetricsStreamRequest{Plan: winRig.plan}); !errors.Is(err, observability.ErrPOSIXShellRequired) {
		t.Fatalf("expected ErrPOSIXShellRequired on cmd probe, got %v", err)
	}
}

func encodeTestPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, G: 100, B: 50, A: 255})
	var buf bytes.Buffer
	mustNoErr(t, png.Encode(&buf, img), "png.Encode")
	return buf.Bytes()
}

func makeFakeBombPNGHeader(w, h uint32) []byte {
	// 构造含超大尺寸的 IHDR 魔数头以验证解压炸弹拦截（在像素解码前拒绝）。
	buf := bytes.NewBuffer([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	_ = binary.Write(buf, binary.BigEndian, uint32(13))
	buf.WriteString("IHDR")
	_ = binary.Write(buf, binary.BigEndian, w)
	_ = binary.Write(buf, binary.BigEndian, h)
	buf.Write([]byte{8, 2, 0, 0, 0, 0, 0, 0, 0})
	return buf.Bytes()
}

func TestGUIValidationAndImageProcessing(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 严格 POSIX 输入校验负向矩阵。
	if err := observability.ValidateX11Display(":0;id"); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected display injection rejected, got %v", err)
	}
	if err := observability.ValidateWaylandDisplay("../wayland-0"); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected wayland injection rejected, got %v", err)
	}
	for _, badKey := range []string{"", "--clearmodifiers", "ctrl+c;rm", "a+b+c+d+e+f"} {
		if err := observability.ValidateGUIKeySpec(badKey); !errors.Is(err, observability.ErrInvalidGUIInput) {
			t.Fatalf("expected key %q rejected, got %v", badKey, err)
		}
	}
	if err := observability.ValidateGUIAction(observability.GUIActionSpec{Action: observability.GUIActionClick, X: 1001, Y: 5}); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected coord overflow rejected, got %v", err)
	}

	// 纯 Go 图像压缩、WebP 透传与解压炸弹防护验证（1600x200 -> 1280x160 等比双线性压缩）。
	bigPNG := encodeTestPNG(t, 1600, 200)
	shot, err := observability.ProcessScreenshotBytes(bigPNG)
	mustNoErr(t, err, "ProcessScreenshotBytes 1600x200")
	if shot.MIMEType != "image/jpeg" || shot.Width != 1280 || shot.Height != 160 || shot.OrigWidth != 1600 {
		t.Fatalf("unexpected scaled shot: %+v", shot)
	}
	// type 文本控制字符/Bidi 须与 BuildGUIScript 一致拒绝。
	if err := observability.ValidateGUIAction(observability.GUIActionSpec{Action: observability.GUIActionType, Text: "abc\u202edef"}); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected Bidi char rejected in ValidateGUIAction, got %v", err)
	}
	assertWebPImageGuards(t)
}

func assertWebPImageGuards(t *testing.T) {
	t.Helper()
	makeWebP := func(fourCC string, payload []byte) []byte {
		var buf bytes.Buffer
		buf.WriteString("RIFF")
		_ = binary.Write(&buf, binary.LittleEndian, uint32(4+8+len(payload)))
		buf.WriteString("WEBP")
		buf.WriteString(fourCC)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(payload)))
		buf.Write(payload)
		return buf.Bytes()
	}
	vp8Payload := make([]byte, 10)
	vp8Payload[3], vp8Payload[4], vp8Payload[5] = 0x9d, 0x01, 0x2a
	binary.LittleEndian.PutUint16(vp8Payload[6:8], 320)
	binary.LittleEndian.PutUint16(vp8Payload[8:10], 240)
	if ws, wErr := observability.ProcessScreenshotBytes(makeWebP("VP8 ", vp8Payload)); wErr != nil || ws.MIMEType != "image/webp" || ws.Width != 320 || ws.Height != 240 {
		t.Fatalf("expected valid VP8 320x240, got %+v err=%v", ws, wErr)
	}
	vp8lPayload := make([]byte, 5)
	vp8lPayload[0] = 0x2f
	binary.LittleEndian.PutUint32(vp8lPayload[1:5], uint32(640-1)|(uint32(480-1)<<14))
	if ws, wErr := observability.ProcessScreenshotBytes(makeWebP("VP8L", vp8lPayload)); wErr != nil || ws.Width != 640 || ws.Height != 480 {
		t.Fatalf("expected valid VP8L 640x480, got %+v err=%v", ws, wErr)
	}
	makeVP8X := func(w, h uint32) []byte {
		p := make([]byte, 10)
		wm, hm := w-1, h-1
		p[4], p[5], p[6] = byte(wm), byte(wm>>8), byte(wm>>16)
		p[7], p[8], p[9] = byte(hm), byte(hm>>8), byte(hm>>16)
		return makeWebP("VP8X", p)
	}
	if ws, wErr := observability.ProcessScreenshotBytes(makeVP8X(1024, 768)); wErr != nil || ws.Width != 1024 || ws.Height != 768 {
		t.Fatalf("expected valid VP8X 1024x768, got %+v err=%v", ws, wErr)
	}
	for _, badWebP := range [][]byte{[]byte("RIFF\x10\x00\x00\x00WEBPfake"), makeVP8X(20000, 20000), makeFakeBombPNGHeader(20000, 20000)} {
		if _, err := observability.ProcessScreenshotBytes(badWebP); !errors.Is(err, observability.ErrScreenshotInvalid) {
			t.Fatalf("expected malformed/bomb image rejected, got %v", err)
		}
	}
}

func TestGUIScriptGenerationAll9Actions(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 验证 9 类 GUI 动作均产出硬化 POSIX Bourne 脚本（含 mktemp/trap、分辨率换算、Wayland/X11 双分支）。
	for _, spec := range []observability.GUIActionSpec{
		{Action: observability.GUIActionScreenshot, WaylandDisplay: "wayland-0"},
		{Action: observability.GUIActionClick, X: 100, Y: 200},
		{Action: observability.GUIActionDoubleClick, X: 10, Y: 20},
		{Action: observability.GUIActionRightClick, X: 10, Y: 20},
		{Action: observability.GUIActionMove, X: 50, Y: 60},
		{Action: observability.GUIActionDrag, StartX: 1, StartY: 2, EndX: 300, EndY: 400},
		{Action: observability.GUIActionScroll, X: 10, Y: 10, Direction: observability.ScrollDown, Clicks: 3},
		{Action: observability.GUIActionType, Text: "a'b"},
		{Action: observability.GUIActionKey, Key: "ctrl+c"},
	} {
		assertHardenedGUIScript(t, spec)
	}
}

func assertHardenedGUIScript(t *testing.T, spec observability.GUIActionSpec) {
	t.Helper()
	sc, sErr := observability.BuildGUIScript(spec)
	mustNoErr(t, sErr, "BuildGUIScript "+spec.Action.String())
	if !strings.Contains(sc, "mktemp -d") || !strings.Contains(sc, "trap 'rm -rf") {
		t.Fatalf("script missing hardened tmpdir/trap: %s", sc)
	}
	if spec.Action != observability.GUIActionScreenshot && (!strings.Contains(sc, "ydotool") || !strings.Contains(sc, "xdotool")) {
		t.Fatalf("input script missing Wayland/X11 dispatch: %s", sc)
	}
	if spec.Action >= observability.GUIActionClick && spec.Action <= observability.GUIActionScroll && !strings.Contains(sc, "xops_px") {
		t.Fatalf("pointer script missing normalized coord scaling: %s", sc)
	}
}

func TestExecuteGUIScreenshotApprovalAndArtifact(t *testing.T) {
	defer goleak.VerifyNone(t)
	bigPNG := encodeTestPNG(t, 1600, 200)
	// 端到端 ExecuteGUI：截图落盘至 ScopedRootFS + 两步审批绑定 type 文本。
	rig := newObsRig(t, obsRigOpts{profile: gate.PolicyProfileStrictAgent, fallback: gate.NoElicitFallbackChallenge})
	defer rig.close()
	framedShot := "XOPS_GUI_SHOT_BEGIN_V2\n" + base64.StdEncoding.EncodeToString(bigPNG) + "\nXOPS_GUI_SHOT_END_V2\n"
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, framedShot)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}

	rootDir, _ := pathalg.ParseLocalDir("/tmp/gui-artifacts")
	fileDest, _ := pathalg.ParseLocalRootedDest("screen.jpg")
	res, err := rig.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan:     rig.plan,
		Spec:     observability.GUIActionSpec{Action: observability.GUIActionScreenshot, Display: ":1"},
		Artifact: algebraic.Some(observability.GUIArtifactDest{RootDir: rootDir, File: fileDest}),
	})
	mustNoErr(t, err, "ExecuteGUI screenshot")
	gotShot, ok := res.Screenshot().Get()
	if !ok || gotShot.Width != 1280 || res.Artifact().IsNone() {
		t.Fatalf("expected scaled screenshot & saved artifact, got ok=%v art=%v", ok, res.Artifact())
	}
	if strings.Contains(res.Stdout(), "XOPS_GUI_SHOT_BEGIN_V2") {
		t.Fatalf("expected Base64 screenshot payload stripped from Stdout, got %q", res.Stdout())
	}

	// type 动作默认 RiskDangerous -> 两步审批，篡改 Artifact 或文本必拒，原文 Round 2 通过。
	_, err = rig.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan: rig.plan, Spec: observability.GUIActionSpec{Action: observability.GUIActionType, Text: "hello"},
		Artifact: algebraic.Some(observability.GUIArtifactDest{RootDir: rootDir, File: fileDest}),
	})
	var chalErr *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr) {
		t.Fatalf("expected ApprovalChallengeError on gui type, got %v", err)
	}
	otherFile, _ := pathalg.ParseLocalRootedDest("tampered.jpg")
	if _, err := rig.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan: rig.plan, Spec: observability.GUIActionSpec{Action: observability.GUIActionType, Text: "hello"},
		Artifact: algebraic.Some(observability.GUIArtifactDest{RootDir: rootDir, File: otherFile}),
		Approval: algebraic.Some(makeApprovalForChal(t, chalErr)),
	}); err == nil {
		t.Fatalf("expected tampered Artifact file rejected in Round 2")
	}
	_, err = rig.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan: rig.plan, Spec: observability.GUIActionSpec{Action: observability.GUIActionType, Text: "hello"},
	})
	var chalErr2 *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr2) {
		t.Fatalf("expected second ApprovalChallengeError, got %v", err)
	}
	resType, err := rig.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan: rig.plan, Spec: observability.GUIActionSpec{Action: observability.GUIActionType, Text: "hello"},
		Approval: algebraic.Some(makeApprovalForChal(t, chalErr2)),
	})
	mustNoErr(t, err, "ExecuteGUI type Round 2")
	if resType.Action() != observability.GUIActionType {
		t.Fatalf("unexpected action %v", resType.Action())
	}

	// 无 ScopedRootFS 时指定产物落盘必须 Fail-Closed（0 OperatorReadFS）。
	noFS := newObsRig(t, obsRigOpts{omitScopedFS: true})
	defer noFS.close()
	if _, err := noFS.svc.ExecuteGUI(context.Background(), observability.GUIExecRequest{
		Plan:     noFS.plan,
		Spec:     observability.GUIActionSpec{Action: observability.GUIActionScreenshot},
		Artifact: algebraic.Some(observability.GUIArtifactDest{RootDir: rootDir, File: fileDest}),
	}); !errors.Is(err, observability.ErrScopedFSUnavailable) {
		t.Fatalf("expected ErrScopedFSUnavailable, got %v", err)
	}
}

func TestGUISessionX11VNCLifecycleAndGateHaltedRevocation(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newObsRig(t, obsRigOpts{profile: gate.PolicyProfileStrictAgent, fallback: gate.NoElicitFallbackChallenge})
	defer rig.close()

	// 越界 displayNum 与默认非回环地址拒绝。
	if _, err := rig.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionVNC, DisplayNum: 100},
	}); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected display overflow rejected, got %v", err)
	}
	if _, err := rig.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionX11, DisplayNum: 0, LocalBindHost: "0.0.0.0"},
	}); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected non-loopback rejected by default, got %v", err)
	}

	// 显式允许非回环地址自动升级至 RiskDangerous 并触发两步审批。
	_, err := rig.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionVNC, DisplayNum: 1, LocalBindHost: "0.0.0.0", AllowNonLoopbackBind: true},
	})
	if !errors.Is(err, gate.ErrApprovalRequired) {
		t.Fatalf("expected non-loopback opt-in to require approval, got %v", err)
	}

	// 正常开启本机回环 X11 Unix 套接字会话并检查状态。
	info, err := rig.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionX11, DisplayNum: 2, UseUnixSocket: true},
	})
	mustNoErr(t, err, "OpenGUISession X11 unix")
	if info.RemoteTarget() != "/tmp/.X11-unix/X2" {
		t.Fatalf("unexpected remote target %q", info.RemoteTarget())
	}
	st, err := rig.svc.InspectGUISession(context.Background(), info.Handle())
	mustNoErr(t, err, "InspectGUISession")
	if !st.Active() || st.Kind() != observability.GUISessionX11 {
		t.Fatalf("expected active X11 session, got %+v", st)
	}

	// 触发 StrictAgent Gate Halted -> 立即吊销已开启的 GUI 隧道句柄并拒绝新请求。
	rig.auditClust.Faults().InjectOnce("audit.record.finalized", errors.New("audit disk fail"))
	_, _ = rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Target: func() observability.LogTarget { lt, _ := observability.NewDockerLogTarget("app"); return lt }(),
	})
	if !rig.gate.IsHalted() {
		t.Fatalf("expected gate halted")
	}
	if _, err := rig.svc.InspectGUISession(context.Background(), info.Handle()); !errors.Is(err, gate.ErrGateHalted) {
		t.Fatalf("expected ErrGateHalted on InspectGUISession, got %v", err)
	}
	_ = rig.svc.CloseGUISession(context.Background(), info.Handle())

	// VNC + UseUnixSocket 必须失败关闭拒绝；且 LocalBindPort 篡改必须触发审批校验拒绝。
	rig2 := newObsRig(t, obsRigOpts{profile: gate.PolicyProfileStrictAgent, fallback: gate.NoElicitFallbackChallenge})
	defer rig2.close()
	if _, err := rig2.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig2.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionVNC, DisplayNum: 1, UseUnixSocket: true},
	}); !errors.Is(err, observability.ErrInvalidGUIInput) {
		t.Fatalf("expected VNC+UseUnixSocket rejected, got %v", err)
	}
	_, err = rig2.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig2.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionVNC, DisplayNum: 1, LocalBindHost: "0.0.0.0", LocalBindPort: 15901, AllowNonLoopbackBind: true},
	})
	var chalSess *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalSess) {
		t.Fatalf("expected session approval challenge, got %v", err)
	}
	if _, err := rig2.svc.OpenGUISession(context.Background(), observability.OpenGUISessionRequest{
		Plan: rig2.plan, Spec: observability.GUISessionSpec{Kind: observability.GUISessionVNC, DisplayNum: 1, LocalBindHost: "0.0.0.0", LocalBindPort: 15902, AllowNonLoopbackBind: true},
		Approval: algebraic.Some(makeApprovalForChal(t, chalSess)),
	}); err == nil {
		t.Fatalf("expected tampered LocalBindPort rejected in Round 2")
	}
}

func TestStreamMetricsRealShellStreamingAndLogFollowStop(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newObsRig(t, obsRigOpts{})
	defer rig.close()

	// 1. StreamMetrics 校验非正 Timeout。
	if _, err := rig.svc.StreamMetrics(context.Background(), observability.MetricsStreamRequest{
		Plan: rig.plan, Timeout: algebraic.Some(algebraic.FromStdDuration(-time.Second)),
	}); !errors.Is(err, observability.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest for negative metrics Timeout, got %v", err)
	}

	// 2. 逐行实时流式解析、每帧独立时钟盖戳、超长行安全丢弃与 UptimeSec 溢出钳制。
	var seenTimes []time.Time
	rig.dialer.onCmd = func(_ context.Context, _ execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, strings.Repeat("x", 300<<10)+"\n")
		_, _ = io.WriteString(stdout, `{"hostname":"h1","cpu_total":100,"cpu_idle":50,"uptime_sec":1e30}`+"\n")
		rig.clock.Advance(2 * time.Second)
		_, _ = io.WriteString(stdout, `{"hostname":"h1","cpu_total":200,"cpu_idle":75,"uptime_sec":120}`+"\n")
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	mRes, err := rig.svc.StreamMetrics(context.Background(), observability.MetricsStreamRequest{
		Plan: rig.plan, MaxSamples: 2, OnFrame: func(f observability.HostMetricsFrame) { seenTimes = append(seenTimes, f.SampledAt) },
	})
	mustNoErr(t, err, "StreamMetrics live")
	if len(seenTimes) != 2 || seenTimes[1].Sub(seenTimes[0]) != 2*time.Second || mRes.Frames()[0].Uptime.IsNegative() || mRes.Frames()[1].CPUPercent != 75.0 {
		t.Fatalf("unexpected live streaming frames: times=%v frames=%+v", seenTimes, mRes.Frames())
	}

	// 3. 真实 /bin/sh 执行 StreamMetrics 探针脚本并端到端喂回解析器验证协议兼容性（经 stdin 传给 sh -s 避开 Windows CreateProcess/MSYS2 参数转义失真）。
	if shPath, lookErr := exec.LookPath("sh"); lookErr == nil {
		var rawOut, rawErr bytes.Buffer
		rig.dialer.onCmd = func(c context.Context, cmd execution.CommandPlan, stdout, stderr io.Writer) (execution.ExecutionOutcome, error) {
			return runShellProbeScript(c, shPath, cmd.Command(), stdout, stderr, &rawOut, &rawErr)
		}
		realRes, rErr := rig.svc.StreamMetrics(context.Background(), observability.MetricsStreamRequest{
			Plan: rig.plan, Interval: algebraic.Some(algebraic.FromStdDuration(200 * time.Millisecond)), MaxSamples: 2, TopProcesses: 3,
		})
		mustNoErr(t, rErr, "StreamMetrics real /bin/sh probe")
		if len(realRes.Frames()) != 2 || realRes.Frames()[0].Hostname == "" {
			t.Fatalf("expected 2 real parsed frames from /bin/sh probe, got %+v (stdout=%q stderr=%q)", realRes.Frames(), rawOut.String(), rawErr.String())
		}
		assertMetricsProbeCRLFAndEscaping(t, rig, shPath)
	}
}

func runShellProbeScript(ctx context.Context, shPath, script string, stdout, stderr io.Writer, rawOut, rawErr *bytes.Buffer) (execution.ExecutionOutcome, error) {
	ec := exec.CommandContext(ctx, shPath, "-s")
	ec.Stdin = strings.NewReader(script + "\n")
	ec.Stdout = io.MultiWriter(stdout, rawOut)
	ec.Stderr = rawErr
	if stderr != nil {
		ec.Stderr = io.MultiWriter(stderr, rawErr)
	}
	if rErr := ec.Run(); rErr != nil {
		return nil, fmt.Errorf("%w (stderr=%q)", rErr, rawErr.String())
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}

func assertMetricsProbeCRLFAndEscaping(t *testing.T, rig *obsRig, shPath string) {
	t.Helper()
	// 模拟 Windows hostname.exe 尾部 \r 以及含反斜杠/双引号的 df/ps 输出，验证 ENVIRON + [[:cntrl:]] 剥离保持合法 NDJSON。
	var rawOut, rawErr bytes.Buffer
	rig.dialer.onCmd = func(c context.Context, cmd execution.CommandPlan, stdout, stderr io.Writer) (execution.ExecutionOutcome, error) {
		shim := "hostname() { printf 'win-host\\r\\n'; }\ndf() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\nC: 100 40 60 40%% C:\\\\mnt\\\\\"a\"\\r\\n'; }\nps() { printf '42 ops\\r 1.5 2.5 C:\\\\app\\\\\"bin\"\\r\\n'; }\n" + cmd.Command()
		return runShellProbeScript(c, shPath, shim, stdout, stderr, &rawOut, &rawErr)
	}
	crlfRes, cErr := rig.svc.StreamMetrics(context.Background(), observability.MetricsStreamRequest{
		Plan: rig.plan, MaxSamples: 1, TopProcesses: 2,
	})
	mustNoErr(t, cErr, "StreamMetrics CRLF/backslash probe")
	if len(crlfRes.Frames()) != 1 || crlfRes.Frames()[0].Hostname != "win-host" || len(crlfRes.Frames()[0].Disks) != 1 || crlfRes.Frames()[0].Disks[0].Mount != `C:\mnt\"a"` || len(crlfRes.Frames()[0].Processes) != 1 || crlfRes.Frames()[0].Processes[0].Command != `C:\app\"bin"` {
		t.Fatalf("unexpected CRLF/backslash parsed frame: %+v (stdout=%q stderr=%q)", crlfRes.Frames(), rawOut.String(), rawErr.String())
	}
}

func TestStreamLogsFollowLimitAndMaxOutputBytes(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newObsRig(t, obsRigOpts{})
	defer rig.close()
	// StreamLogs 透传 >4MiB MaxOutputBytes 且 Follow=true 达 maxBytes 确定性停止（0 挂死 / 非 OutcomeUnknown）。
	dkTarget, _ := observability.NewDockerLogTarget("web-1")
	var gotMaxOut uint64
	rig.dialer.onCmd = func(c context.Context, cmd execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		gotMaxOut = cmd.MaxOutputBytes()
		for {
			if c.Err() != nil {
				return nil, c.Err()
			}
			_, _ = io.WriteString(stdout, "01234567")
		}
	}
	lRes, err := rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Target: dkTarget, Follow: true, MaxBytes: 16,
	})
	mustNoErr(t, err, "StreamLogs follow maxBytes")
	if gotMaxOut != 16 || !lRes.Truncated() || len(lRes.Data()) != 16 || lRes.Outcome().Kind() != execution.OutcomeKindCompleted {
		t.Fatalf("unexpected follow stop result: maxOut=%d trunc=%v len=%d out=%v", gotMaxOut, lRes.Truncated(), len(lRes.Data()), lRes.Outcome())
	}
	rig.dialer.onCmd = func(_ context.Context, cmd execution.CommandPlan, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		gotMaxOut = cmd.MaxOutputBytes()
		_, _ = io.WriteString(stdout, "ok")
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	_, err = rig.svc.StreamLogs(context.Background(), observability.LogStreamRequest{
		Plan: rig.plan, Target: dkTarget, MaxBytes: 8 << 20,
	})
	mustNoErr(t, err, "StreamLogs 8MiB")
	if gotMaxOut != 8<<20 {
		t.Fatalf("expected CommandPlan MaxOutputBytes=8MiB, got %d", gotMaxOut)
	}
}
