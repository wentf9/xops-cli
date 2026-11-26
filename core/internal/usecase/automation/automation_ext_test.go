package automation_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"io/fs"
	"net"
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
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/internal/usecase/automation"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期契约断言集中于外置测试文件，验证测试替身与端口/JSON 接口一致性。
var (
	_ ports.DialerPort    = (*scriptedDialer)(nil)
	_ ports.TransportConn = (*scriptedConn)(nil)
	_ ports.RemoteSession = (*scriptedSession)(nil)
	_ ports.RemoteFSPort  = (*scriptedRemoteFS)(nil)
	_ jsonv2.MarshalerTo  = (*automation.BatchNodeResult)(nil)
	_ jsonv2.MarshalerTo  = (*automation.BatchExecReport)(nil)
	_ jsonv2.MarshalerTo  = (*automation.PlaybookRunResult)(nil)
)

type cmdActionFunc func(ctx context.Context, nodeID string, cmd execution.CommandPlan, stdin []byte, stdout, stderr io.Writer) (execution.ExecutionOutcome, error)

type scriptedDialer struct {
	mu           sync.Mutex
	onCmd        cmdActionFunc
	remoteFSByID map[string]*sim.SimRemoteFS
	onWrite      func(ctx context.Context, nodeID string, p pathalg.RemotePath) error
	dialCount    atomic.Int64
	dialSawLease atomic.Bool
	sessSawLease atomic.Bool
	sessSawOpID  atomic.Bool
	openCount    atomic.Int64
	activeSess   atomic.Int64
	peakSess     atomic.Int64
}

func newScriptedDialer(clk ports.Clock) *scriptedDialer {
	return &scriptedDialer{remoteFSByID: make(map[string]*sim.SimRemoteFS)}
}

func (d *scriptedDialer) rfsFor(nodeID string, clk ports.Clock) *sim.SimRemoteFS {
	d.mu.Lock()
	defer d.mu.Unlock()
	if rfs, ok := d.remoteFSByID[nodeID]; ok {
		return rfs
	}
	rfs := sim.NewSimRemoteFS(clk)
	d.remoteFSByID[nodeID] = rfs
	return rfs
}

func (d *scriptedDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	d.dialCount.Add(1)
	if trace.InLeaseScope(ctx) {
		d.dialSawLease.Store(true)
	}
	c := &scriptedConn{dialer: d, nodeID: hop.NodeID(), dig: dig, ep: hop.Endpoint()}
	c.alive.Store(true)
	return c, nil
}

type scriptedConn struct {
	dialer *scriptedDialer
	nodeID string
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	alive  atomic.Bool
}

func (c *scriptedConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *scriptedConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *scriptedConn) IsAlive() bool                       { return c.alive.Load() }
func (c *scriptedConn) SendKeepalive(context.Context) error { return nil }
func (c *scriptedConn) Close() error                        { c.alive.Store(false); return nil }
func (c *scriptedConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *scriptedConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *scriptedConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *scriptedConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *scriptedConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return nil, ports.ErrUnsupported
}
func (c *scriptedConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	c.dialer.openCount.Add(1)
	if trace.InLeaseScope(ctx) {
		c.dialer.sessSawLease.Store(true)
	}
	if _, ok := trace.OpIDFromContext(ctx); ok {
		c.dialer.sessSawOpID.Store(true)
	}
	return &scriptedSession{dialer: c.dialer, nodeID: c.nodeID}, nil
}
func (c *scriptedConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	if trace.InLeaseScope(ctx) {
		c.dialer.sessSawLease.Store(true)
	}
	if _, ok := trace.OpIDFromContext(ctx); ok {
		c.dialer.sessSawOpID.Store(true)
	}
	return &scriptedRemoteFS{inner: c.dialer.rfsFor(c.nodeID, nil), dialer: c.dialer, nodeID: c.nodeID}, nil
}

type scriptedSession struct {
	dialer  *scriptedDialer
	nodeID  string
	cmd     execution.CommandPlan
	streams ports.ExecStreams
	stdin   []byte
	closed  atomic.Bool
}

func (s *scriptedSession) StdinPipe() (io.WriteCloser, error) { return nil, ports.ErrUnsupported }
func (s *scriptedSession) StdoutPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *scriptedSession) StderrPipe() (io.Reader, error)     { return nil, ports.ErrUnsupported }
func (s *scriptedSession) StartShell(context.Context, ports.ExecStreams) error {
	return ports.ErrUnsupported
}
func (s *scriptedSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (s *scriptedSession) Signal(context.Context, string) error                { return nil }
func (s *scriptedSession) Close() error                                        { s.closed.Store(true); return nil }
func (s *scriptedSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.cmd, s.streams = cmd, streams
	if streams.Stdin != nil {
		var err error
		if s.stdin, err = io.ReadAll(streams.Stdin); err != nil {
			return err
		}
	}
	return nil
}
func (s *scriptedSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	cur := s.dialer.activeSess.Add(1)
	for {
		prev := s.dialer.peakSess.Load()
		if cur <= prev || s.dialer.peakSess.CompareAndSwap(prev, cur) {
			break
		}
	}
	defer s.dialer.activeSess.Add(-1)

	s.dialer.mu.Lock()
	fn := s.dialer.onCmd
	s.dialer.mu.Unlock()
	if fn != nil {
		return fn(ctx, s.nodeID, s.cmd, s.stdin, s.streams.Stdout, s.streams.Stderr)
	}
	if s.streams.Stdout != nil {
		_, _ = io.WriteString(s.streams.Stdout, "ok:"+s.nodeID+"\n")
	}
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

type scriptedRemoteFS struct {
	inner  *sim.SimRemoteFS
	dialer *scriptedDialer
	nodeID string
	closed atomic.Bool
}

func (r *scriptedRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	return r.inner.RealPath(ctx, p)
}
func (r *scriptedRemoteFS) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.inner.Stat(ctx, p)
}
func (r *scriptedRemoteFS) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.inner.Lstat(ctx, p)
}
func (r *scriptedRemoteFS) ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error) {
	return r.inner.ReadLink(ctx, p)
}
func (r *scriptedRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]ports.RemoteDirEntry, error) {
	return r.inner.ReadDir(ctx, dir)
}

//xops:syncclosure
//xops:borrowed
func (r *scriptedRemoteFS) WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ports.ReadLimits, fn func(rd io.Reader, size int64) error) error {
	if fn == nil {
		return ports.ErrNilCallback
	}
	var copied []byte
	var fSize int64
	if err := r.inner.WithReadFile(ctx, p, limits, func(rd io.Reader, size int64) error {
		fSize = size
		var rErr error
		copied, rErr = io.ReadAll(rd)
		return rErr
	}); err != nil {
		return err
	}
	return fn(bytes.NewReader(copied), fSize)
}
func (r *scriptedRemoteFS) ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error) {
	return r.inner.ReadChunk(ctx, p, offset, dst, length)
}
func (r *scriptedRemoteFS) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, rd io.Reader) (ports.RemoteFileStat, error) {
	r.dialer.mu.Lock()
	hook := r.dialer.onWrite
	r.dialer.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, r.nodeID, p); err != nil {
			var z ports.RemoteFileStat
			return z, err
		}
	}
	return r.inner.WriteFileAtomic(ctx, p, spec, rd)
}
func (r *scriptedRemoteFS) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, rd io.Reader, length int64) error {
	return r.inner.WriteChunk(ctx, p, offset, rd, length)
}
func (r *scriptedRemoteFS) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec ports.RemoteRenameSpec) error {
	return r.inner.RenameAtomic(ctx, oldPath, newPath, spec)
}
func (r *scriptedRemoteFS) Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error {
	return r.inner.Chmod(ctx, p, perm)
}
func (r *scriptedRemoteFS) Chtimes(ctx context.Context, p pathalg.RemotePath, atime, mtime time.Time) error {
	return r.inner.Chtimes(ctx, p, atime, mtime)
}
func (r *scriptedRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	return r.inner.MkdirAll(ctx, dir, perm)
}
func (r *scriptedRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	return r.inner.Remove(ctx, p)
}
func (r *scriptedRemoteFS) RemoveDir(ctx context.Context, dir pathalg.RemotePath) error {
	return r.inner.RemoveDir(ctx, dir)
}
func (r *scriptedRemoteFS) Close() error { r.closed.Store(true); return nil }

type autoRigOpts struct {
	profile          gate.PolicyProfileKind
	approvalThresh   security.RiskLevel
	fallback         gate.NoElicitFallback
	omitScopedFS     bool
	omitOperatorRead bool
	withInventory    bool
}

type autoRig struct {
	clock      *sim.SimClock
	rng        *sim.SeededRand
	bus        *events.SystemBus
	auditClust *sim.SimAuditCluster
	auditSink  *sim.SimAuditSink
	dialer     *scriptedDialer
	scopedFS   *sim.SimScopedRootFS
	opReadFS   *sim.SimOperatorReadFS
	store      *sim.SimInventoryStore
	invSvc     *ucinv.Service
	pool       *pool.Pool
	gate       *gate.Gate
	svc        *automation.Service
}

func newAutoRig(t *testing.T, opts autoRigOpts) *autoRig {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261126)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 64})
	mustOK(t, err, "NewSystemBus")
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	mustOK(t, err, "NewSinkFromEntropy")
	dialer := newScriptedDialer(clk)
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{Dialer: dialer, Clock: clk, Entropy: rng, Bus: bus})
	mustOK(t, err, "NewPool")

	prof := opts.profile
	if !prof.IsValid() {
		prof = gate.PolicyProfileDirectOperator
	}
	thresh := opts.approvalThresh
	if !thresh.IsValid() {
		thresh = security.RiskDangerous
	}
	fb := opts.fallback
	if !fb.IsValid() {
		fb = gate.NoElicitFallbackDeny
	}
	rules := mustProtectedRules(t, gate.StrictDefaultProtectedPatterns())
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: thresh, NoElicitFallback: fb, ProtectedRules: rules,
	})
	mustOK(t, err, "NewGuardrailPolicy")
	g, err := gate.NewGate(gate.GateConfig{
		Profile: prof, Policy: pol, AuditSink: sink, Clock: clk, Entropy: rng, SystemBus: bus,
		OnHalt: func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	mustOK(t, err, "NewGate")

	scoped := sim.NewSimScopedRootFS(clk)
	opRead := sim.NewSimOperatorReadFS()
	var zeroID ports.LocalIdentityInfo
	cfg := automation.ServiceConfig{
		Gate: g, Pool: p, Clock: clk, Entropy: rng, SystemBus: bus,
		Env: sim.NewSimEnvPort(map[string]string{"LC_ALL": "C"}, zeroID),
	}
	if !opts.omitScopedFS {
		cfg.ScopedFS = scoped
	}
	if !opts.omitOperatorRead {
		cfg.OperatorReadFS = opRead
	}
	var store *sim.SimInventoryStore
	var invSvc *ucinv.Service
	if opts.withInventory {
		store, err = sim.NewSimInventoryStore(mustSeedInventoryGraph(t))
		mustOK(t, err, "NewSimInventoryStore")
		invSvc, err = ucinv.NewService(ucinv.ServiceConfig{Store: store, Gate: g, Clock: clk, Entropy: rng})
		mustOK(t, err, "inventory.NewService")
		cfg.Inventory = invSvc
	}
	svc, err := automation.NewService(cfg)
	mustOK(t, err, "automation.NewService")

	rig := &autoRig{
		clock: clk, rng: rng, bus: bus, auditClust: cluster, auditSink: sink,
		dialer: dialer, scopedFS: scoped, opReadFS: opRead, store: store, invSvc: invSvc,
		pool: p, gate: g, svc: svc,
	}
	return rig
}

func (r *autoRig) close() {
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

func mustSeedInventoryGraph(t *testing.T) inventory.Graph {
	t.Helper()
	hid, err := inventory.ParseHostID("h-web-1")
	mustOK(t, err, "ParseHostID")
	ch, err := netaddr.ParseCanonicalHost("10.0.4.1")
	mustOK(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, 22)
	mustOK(t, err, "NewEndpoint")
	host, err := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep})
	mustOK(t, err, "NewHost")

	iid, err := inventory.ParseIdentityID("id-ops")
	mustOK(t, err, "ParseIdentityID")
	user, err := option.ParseUsername("ops")
	mustOK(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	mustOK(t, err, "NewAuthAgent")
	ident, err := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	mustOK(t, err, "NewIdentity")

	nid, err := inventory.ParseNodeID("inv-web-1")
	mustOK(t, err, "ParseNodeID")
	tag, err := inventory.ParseTag("web")
	mustOK(t, err, "ParseTag")
	node, err := inventory.NewNode(inventory.NodeSpec{ID: nid, HostRef: hid, IdentityRef: iid, Tags: []inventory.Tag{tag}, Origin: inventory.NewOriginManaged()})
	mustOK(t, err, "NewNode")
	g, err := inventory.NewGraph(inventory.GraphSpec{
		Hosts: []inventory.Host{host}, Identities: []inventory.Identity{ident}, Nodes: []inventory.Node{node},
	})
	mustOK(t, err, "NewGraph")
	return g
}

func mustProtectedRules(t *testing.T, pats []string) []pathalg.ProtectedRule {
	t.Helper()
	rules := make([]pathalg.ProtectedRule, 0, len(pats))
	for _, pat := range pats {
		r, err := pathalg.ParseProtectedRule(pat)
		mustOK(t, err, "ParseProtectedRule")
		rules = append(rules, r)
	}
	return rules
}

func mustOK(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s failed: %v", label, err)
	}
}

func makeTargetNode(t *testing.T, nodeName, host string, tagNames ...string) automation.TargetNode {
	t.Helper()
	nid, err := inventory.ParseNodeID(nodeName)
	mustOK(t, err, "ParseNodeID")
	cleanHost := strings.TrimSuffix(host, ":22")
	ch, err := netaddr.ParseCanonicalHost(cleanHost)
	mustOK(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, 22)
	mustOK(t, err, "NewEndpoint")
	user, err := option.ParseUsername("ops")
	mustOK(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	mustOK(t, err, "NewAuthAgent")
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	mustOK(t, err, "ResolveEffectivePolicy")
	hop, err := plan.NewHopSpecFromAuth(0, nid.String(), user, auth, eff)
	mustOK(t, err, "NewHopSpecFromAuth")
	cp, err := plan.SealConnectionPlan(hop)
	mustOK(t, err, "SealConnectionPlan")
	tags := make([]inventory.Tag, 0, len(tagNames))
	for _, raw := range tagNames {
		tg, tErr := inventory.ParseTag(raw)
		mustOK(t, tErr, "ParseTag")
		tags = append(tags, tg)
	}
	tn, err := automation.NewTargetNode(automation.TargetNodeSpec{NodeID: nid, Plan: cp, Tags: tags})
	mustOK(t, err, "NewTargetNode")
	return tn
}

func makeApprovalSub(t *testing.T, chalErr *gate.ApprovalChallengeError) gate.ApprovalSubmission {
	t.Helper()
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, chalErr.EnvelopeDigest(), "approved-by-operator")
	mustOK(t, err, "NewApprovalDecisionResponse")
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: algebraic.Some(chalErr.Envelope()),
		Response: resp,
	})
	mustOK(t, err, "NewApprovalSubmission")
	return sub
}

func makeCmdPlan(t *testing.T, command string) execution.CommandPlan {
	t.Helper()
	cp, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:    execution.PlanKindCommand,
		Profile: execution.DefaultServerLaunchProfile(),
		Command: command,
	})
	mustOK(t, err, "NewCommandPlan")
	return cp
}

func makeOpStream(t *testing.T, label string) *events.OperationStream {
	t.Helper()
	tid, err := security.ParseTraceID("trace-" + label)
	mustOK(t, err, "ParseTraceID")
	oid, err := security.ParseOperationID("op-" + label)
	mustOK(t, err, "ParseOperationID")
	st, err := events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: 64})
	mustOK(t, err, "NewOperationStream")
	return st
}

func drainStream(ctx context.Context, st *events.OperationStream) []events.Event {
	var out []events.Event
	for {
		ev, ok, err := st.Next(ctx)
		if err != nil || !ok {
			return out
		}
		out = append(out, ev)
	}
}

func TestBatchExecConcurrencyFilteringAndNesting(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()

	gateCh := make(chan struct{})
	arrived := make(chan string, 2)
	rig.dialer.onCmd = func(_ context.Context, nodeID string, _ execution.CommandPlan, _ []byte, stdout, _ io.Writer) (execution.ExecutionOutcome, error) {
		select {
		case arrived <- nodeID:
		default:
		}
		<-gateCh
		_, _ = io.WriteString(stdout, "hello:"+nodeID)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}

	targets := []automation.TargetNode{
		makeTargetNode(t, "web-3", "10.0.0.3:22", "web"),
		makeTargetNode(t, "web-1", "10.0.0.1:22", "web"),
		makeTargetNode(t, "db-1", "10.0.0.4:22", "db"),
		makeTargetNode(t, "web-2", "10.0.0.2:22", "web", "canary"),
	}
	exNode, _ := inventory.ParseNodeID("web-3")
	exTag, _ := inventory.ParseTag("db")

	var report automation.BatchExecReport
	var execErr error
	runErr := conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		if err := n.Go(func(c context.Context) error {
			report, execErr = rig.svc.BatchExec(c, automation.BatchExecRequest{
				Targets:      targets,
				ExcludeNodes: []inventory.NodeID{exNode},
				ExcludeTags:  []inventory.Tag{exTag},
				Command:      makeCmdPlan(t, "uptime"),
				Concurrency:  2,
			})
			return nil
		}); err != nil {
			return err
		}
		return n.Go(func(context.Context) error {
			<-arrived
			<-arrived
			close(gateCh)
			return nil
		})
	})
	mustOK(t, runErr, "RunWait")
	mustOK(t, execErr, "BatchExec")

	if report.SucceededCount() != 2 || report.FailedCount() != 0 || report.HasUnknownOutcome() {
		t.Fatalf("unexpected report counts: ok=%d fail=%d unk=%v", report.SucceededCount(), report.FailedCount(), report.HasUnknownOutcome())
	}
	gotIDs := []string{report.Results()[0].NodeID().String(), report.Results()[1].NodeID().String()}
	if gotIDs[0] != "web-1" || gotIDs[1] != "web-2" {
		t.Fatalf("results not sorted by NodeID: %v", gotIDs)
	}
	if peak := rig.dialer.peakSess.Load(); peak != 2 {
		t.Fatalf("expected peak concurrency 2, got %d", peak)
	}
	// 验证 ADR-008/ADR-009 嵌套顺序：DialHop 不在 LeaseScope 内，OpenSession 在 LeaseScope 与 OpID 内。
	if rig.dialer.dialSawLease.Load() || !rig.dialer.sessSawLease.Load() || !rig.dialer.sessSawOpID.Load() {
		t.Fatalf("unexpected lease/opID nesting: dialLease=%v sessLease=%v sessOpID=%v",
			rig.dialer.dialSawLease.Load(), rig.dialer.sessSawLease.Load(), rig.dialer.sessSawOpID.Load())
	}
	rawJSON, err := report.CanonicalJSON()
	mustOK(t, err, "CanonicalJSON")
	if !bytes.Contains(rawJSON, []byte(`"web-1"`)) || !bytes.Contains(rawJSON, []byte(`"succeeded_count":2`)) {
		t.Fatalf("unexpected canonical JSON: %s", rawJSON)
	}
}

func TestBatchExecNodeStreamsAndOutDir(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()
	rig.dialer.onCmd = func(_ context.Context, nodeID string, _ execution.CommandPlan, _ []byte, stdout, stderr io.Writer) (execution.ExecutionOutcome, error) {
		_, _ = io.WriteString(stdout, "out-"+nodeID)
		_, _ = io.WriteString(stderr, "err-"+nodeID)
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}

	n1 := makeTargetNode(t, "app-1", "10.0.1.1:22")
	n2 := makeTargetNode(t, "con", "10.0.1.2:22")
	batchStream := makeOpStream(t, "batch-main")
	n1Stream := makeOpStream(t, "node-app1")
	n2Stream := makeOpStream(t, "node-con")
	outDir, err := pathalg.ParseLocalDir("/tmp/xops-batch-out")
	mustOK(t, err, "ParseLocalDir")

	var batchEvs, n1Evs, n2Evs []events.Event
	var rep automation.BatchExecReport
	var batchErr error
	err = conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error { batchEvs = drainStream(c, batchStream); return nil })
		_ = n.Go(func(c context.Context) error { n1Evs = drainStream(c, n1Stream); return nil })
		_ = n.Go(func(c context.Context) error { n2Evs = drainStream(c, n2Stream); return nil })
		return n.Go(func(c context.Context) error {
			rep, batchErr = rig.svc.BatchExec(c, automation.BatchExecRequest{
				Targets:         []automation.TargetNode{n1, n2},
				Command:         makeCmdPlan(t, "id"),
				OutputDir:       algebraic.Some(outDir),
				OperationStream: batchStream,
				NodeStreams:     map[inventory.NodeID]*events.OperationStream{n1.NodeID(): n1Stream},
				NodeStreamFactory: func(id inventory.NodeID, _ security.TraceID, _ security.OperationID) (*events.OperationStream, error) {
					if id == n2.NodeID() {
						return n2Stream, nil
					}
					return nil, nil
				},
			})
			return nil
		})
	})
	mustOK(t, err, "RunWait")
	mustOK(t, batchErr, "BatchExec")
	assertStreamHasTerminal(t, "batch", batchEvs, true)
	assertStreamHasTerminal(t, "app-1", n1Evs, true)
	assertStreamHasTerminal(t, "con", n2Evs, true)

	// 验证 ScopedRootFS 落盘内容（含 Windows 保留名节点 con -> node-con.stdout.log 防护）。
	limits, _ := ports.NewReadLimits(4096)
	for _, tc := range []struct{ file, want string }{
		{"node-app-1.stdout.log", "out-app-1"},
		{"node-con.stdout.log", "out-con"},
	} {
		dest, dErr := pathalg.ParseLocalRootedDest(tc.file)
		mustOK(t, dErr, "ParseLocalRootedDest "+tc.file)
		var saved []byte
		mustOK(t, rig.scopedFS.WithRoot(outDir, func(root ports.RootHandle) error {
			var rErr error
			saved, rErr = root.ReadAllBounded(dest, limits)
			return rErr
		}), "WithRoot read "+tc.file)
		if string(saved) != tc.want {
			t.Fatalf("file %s saved %q want %q", tc.file, saved, tc.want)
		}
	}
	if rep.Results()[0].StdoutFile().IsNone() || rep.Results()[1].StdoutFile().IsNone() {
		t.Fatalf("expected StdoutFile populated for all nodes")
	}

	// 缺少 ScopedRootFS 时指定 --out-dir 必须 Fail-Closed。
	noFS := newAutoRig(t, autoRigOpts{omitScopedFS: true})
	defer noFS.close()
	_, err = noFS.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: makeCmdPlan(t, "id"), OutputDir: algebraic.Some(outDir),
	})
	if !errors.Is(err, automation.ErrScopedFSUnavailable) {
		t.Fatalf("expected ErrScopedFSUnavailable, got %v", err)
	}
}

func assertStreamHasTerminal(t *testing.T, name string, evs []events.Event, wantOK bool) {
	t.Helper()
	if len(evs) < 2 {
		t.Fatalf("stream %s expected >=2 events, got %d", name, len(evs))
	}
	last, ok := evs[len(evs)-1].(*events.OperationCompletedEvent)
	if !ok {
		t.Fatalf("stream %s last event is %T, want *OperationCompletedEvent", name, evs[len(evs)-1])
	}
	if last.Succeeded() != wantOK {
		t.Fatalf("stream %s terminal succeeded=%v want %v", name, last.Succeeded(), wantOK)
	}
}

func TestBatchExecOutcomeUnknownAndAuditLedger(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()
	var unknownAttempts atomic.Int32
	rig.dialer.onCmd = func(_ context.Context, nodeID string, _ execution.CommandPlan, _ []byte, _ io.Writer, _ io.Writer) (execution.ExecutionOutcome, error) {
		switch nodeID {
		case "node-ok":
			return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		case "node-unk":
			unknownAttempts.Add(1)
			return nil, errors.New("tcp reset mid-command")
		default:
			out, _ := execution.NewOutcomeNotStarted(execution.StartPhaseRequestRejected, "denied", "rejected")
			return out, errors.New("rejected")
		}
	}

	rep, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{
			makeTargetNode(t, "node-ok", "10.0.2.1:22"),
			makeTargetNode(t, "node-pre", "10.0.2.2:22"),
			makeTargetNode(t, "node-unk", "10.0.2.3:22"),
		},
		Command: makeCmdPlan(t, "systemctl restart app"),
	})
	if !errors.Is(err, automation.ErrUncertainOutcome) {
		t.Fatalf("expected ErrUncertainOutcome, got %v", err)
	}
	if unknownAttempts.Load() != 1 {
		t.Fatalf("OutcomeUnknown must never retry, attempts=%d", unknownAttempts.Load())
	}
	if !rep.HasUnknownOutcome() || rep.UnknownCount() != 1 || rep.NotStartedCount() != 1 || rep.SucceededCount() != 1 {
		t.Fatalf("unexpected report breakdown: ok=%d fail=%d notStarted=%d unk=%d",
			rep.SucceededCount(), rep.FailedCount(), rep.NotStartedCount(), rep.UnknownCount())
	}
	if !hasAuditOutcome(rig.auditClust.Entries(), ports.AuditOutcomeUnknown) {
		t.Fatalf("expected AuditOutcomeUnknown in audit ledger")
	}
}

func hasAuditOutcome(entries []ports.AuditEntry, want ports.AuditOutcome) bool {
	for _, e := range entries {
		if e.Phase() == ports.AuditPhaseFinalized && e.Outcome() == want {
			return true
		}
	}
	return false
}

func TestBatchExecFailFastGateHaltedAndTwoStepApproval(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{
		profile:        gate.PolicyProfileStrictAgent,
		approvalThresh: security.RiskDangerous,
		fallback:       gate.NoElicitFallbackChallenge,
	})
	defer rig.close()
	n1 := makeTargetNode(t, "prod-1", "10.0.3.1:22")
	cmd := makeCmdPlan(t, "echo prod")

	// Round 1：触发两步审批挑战。
	_, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: cmd, Risk: algebraic.Some(security.RiskDangerous),
	})
	var chalErr *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr) {
		t.Fatalf("expected ApprovalChallengeError, got %v", err)
	}

	// 篡改命令后提交原挑战 -> 必须拒绝且作废原一次性挑战（防篡改 + 防重放）。
	sub := makeApprovalSub(t, chalErr)
	_, err = rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: makeCmdPlan(t, "echo tampered"),
		Risk: algebraic.Some(security.RiskDangerous), Approval: algebraic.Some(sub),
	})
	if err == nil {
		t.Fatalf("expected tampered request to be rejected")
	}

	// 新一轮挑战 + 完全相同的显式请求 -> 放行成功（验证两步审批确定性绑定）。
	_, err = rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: cmd, Risk: algebraic.Some(security.RiskDangerous),
	})
	var chalErr2 *gate.ApprovalChallengeError
	if !errors.Is(err, gate.ErrApprovalRequired) || !errors.As(err, &chalErr2) {
		t.Fatalf("expected second ApprovalChallengeError, got %v", err)
	}
	sub2 := makeApprovalSub(t, chalErr2)
	rep, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: cmd,
		Risk: algebraic.Some(security.RiskDangerous), Approval: algebraic.Some(sub2),
	})
	mustOK(t, err, "BatchExec Round 2")
	if rep.SucceededCount() != 1 {
		t.Fatalf("expected 1 succeeded node, got %d", rep.SucceededCount())
	}

	// 注入后置审计失败触发 StrictAgent Gate Halted，随后立即拒绝并 0 次拨号。
	rig.auditClust.Faults().InjectOnce("audit.record.finalized", errors.New("disk full"))
	_, err = rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: makeCmdPlan(t, "echo safe"),
		Risk: algebraic.Some(security.RiskSafe),
	})
	if err == nil || !rig.gate.IsHalted() {
		t.Fatalf("expected gate halted after finalized audit error, err=%v halted=%v", err, rig.gate.IsHalted())
	}
	beforeOpen := rig.dialer.openCount.Load()
	_, err = rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1}, Command: makeCmdPlan(t, "echo blocked"),
		Risk: algebraic.Some(security.RiskSafe),
	})
	if !errors.Is(err, gate.ErrGateHalted) || rig.dialer.openCount.Load() != beforeOpen {
		t.Fatalf("expected immediate ErrGateHalted with 0 sessions, err=%v", err)
	}
}

func TestBatchExecInventorySelectorAndZeroValueFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zeroSvc automation.Service
	if _, err := zeroSvc.BatchExec(context.Background(), automation.BatchExecRequest{}); !errors.Is(err, automation.ErrServiceNotInitialized) {
		t.Fatalf("expected ErrServiceNotInitialized, got %v", err)
	}
	var zeroRep automation.BatchExecReport
	if _, err := zeroRep.CanonicalJSON(); !errors.Is(err, automation.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest on zero report, got %v", err)
	}

	rig := newAutoRig(t, autoRigOpts{withInventory: true})
	defer rig.close()
	webTag, err := inventory.ParseTag("web")
	mustOK(t, err, "ParseTag")
	sel, err := playbook.NewTargetSelector(playbook.TargetSelectorSpec{Tags: []inventory.Tag{webTag}})
	mustOK(t, err, "NewTargetSelector")

	rep, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Selector: algebraic.Some(sel), Command: makeCmdPlan(t, "hostname"),
	})
	mustOK(t, err, "BatchExec via Inventory Selector")
	if rep.SucceededCount() != 1 || rep.Results()[0].NodeID().String() != "inv-web-1" {
		t.Fatalf("unexpected inventory target result: %+v", rep.Results())
	}

	// 验证显式 NodeID 选择器回退 ResolveTarget 兼容 ~/.ssh/config 虚拟主机，以及排除过滤提前生效。
	vhHost, _ := netaddr.ParseCanonicalHost("198.51.100.77")
	vhEP, _ := netaddr.NewEndpoint(vhHost, 22)
	vhUser, _ := option.ParseUsername("ops")
	vhSpecHost, _ := option.ParseHostNameSpec("198.51.100.77")
	vhLayer := option.UnsetOptionLayer().WithHostName(vhSpecHost).WithPort(22).WithUser(vhUser)
	vh, err := ports.NewOpenSSHVirtualHost(ports.OpenSSHVirtualHostSpec{
		Alias: "ssh-virtual-1", SourceFile: "/home/ops/.ssh/config",
		Endpoint: algebraic.Some(vhEP), User: algebraic.Some(vhUser), Layer: vhLayer,
	})
	mustOK(t, err, "NewOpenSSHVirtualHost")
	invWithSSH, err := ucinv.NewService(ucinv.ServiceConfig{
		Store: rig.store, OpenSSH: sim.NewSimOpenSSHConfigSource(vh), Gate: rig.gate, Clock: rig.clock, Entropy: rig.rng,
	})
	mustOK(t, err, "inventory.NewService with OpenSSH")
	svcWithSSH, err := automation.NewService(automation.ServiceConfig{
		Gate: rig.gate, Pool: rig.pool, Clock: rig.clock, Entropy: rig.rng, Inventory: invWithSSH,
	})
	mustOK(t, err, "automation.NewService with OpenSSH")
	vhNodeID, _ := inventory.ParseNodeID("ssh-virtual-1")
	selVH, err := playbook.NewTargetSelector(playbook.TargetSelectorSpec{Nodes: []inventory.NodeID{vhNodeID}})
	mustOK(t, err, "NewTargetSelector virtual")
	repVH, err := svcWithSSH.BatchExec(context.Background(), automation.BatchExecRequest{
		Selector: algebraic.Some(selVH), Command: makeCmdPlan(t, "hostname"),
	})
	mustOK(t, err, "BatchExec virtual ~/.ssh/config node")
	if repVH.SucceededCount() != 1 || repVH.Results()[0].NodeID() != vhNodeID {
		t.Fatalf("expected virtual host resolved and executed, got %+v", repVH.Results())
	}

	noInv := newAutoRig(t, autoRigOpts{withInventory: false})
	defer noInv.close()
	_, err = noInv.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Selector: algebraic.Some(sel), Command: makeCmdPlan(t, "hostname"),
	})
	if !errors.Is(err, automation.ErrInventoryUnavailable) {
		t.Fatalf("expected ErrInventoryUnavailable, got %v", err)
	}
}

func TestBatchExecPanicEmitsTerminalEventAndClosesStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newAutoRig(t, autoRigOpts{})
	defer rig.close()
	rig.dialer.onCmd = func(_ context.Context, _ string, _ execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		panic("boom-worker")
	}
	n1 := makeTargetNode(t, "panic-node", "10.0.5.1:22")
	nodeSt := makeOpStream(t, "panic-node-stream")

	var evs []events.Event
	var panicked any
	_ = conc.RunWait(context.Background(), func(wCtx context.Context, n *conc.Nursery) error {
		_ = n.Go(func(c context.Context) error { evs = drainStream(c, nodeSt); return nil })
		return n.Go(func(c context.Context) error {
			defer func() { panicked = recover() }()
			_, _ = rig.svc.BatchExec(c, automation.BatchExecRequest{
				Targets:     []automation.TargetNode{n1},
				Command:     makeCmdPlan(t, "boom"),
				NodeStreams: map[inventory.NodeID]*events.OperationStream{n1.NodeID(): nodeSt},
			})
			return nil
		})
	})
	if panicked == nil && !nodeSt.IsClosed() {
		t.Fatalf("expected panic propagation or stream close")
	}
	assertStreamHasTerminal(t, "panic-node", evs, false)
	last := evs[len(evs)-1].(*events.OperationCompletedEvent)
	if !strings.Contains(last.Code(), "panic") {
		t.Fatalf("expected panic terminal code, got %q", last.Code())
	}
}

func TestBatchExecWorkDirRound2ProfileInheritanceAndHaltedChain(t *testing.T) {
	defer goleak.VerifyNone(t)
	// 1. StrictAgent 下 Command.WorkDir 软链重定向至受保护路径 /etc -> Round-2 必须拦截且 0 会话打开。
	rig := newAutoRig(t, autoRigOpts{profile: gate.PolicyProfileStrictAgent, fallback: gate.NoElicitFallbackDeny})
	defer rig.close()
	node := makeTargetNode(t, "wd-1", "10.0.6.1:22")
	wdLink, _ := pathalg.ParseRemotePath("/tmp/wd-link")
	mustOK(t, rig.dialer.rfsFor("wd-1", rig.clock).PutSymlink(wdLink, "/etc"), "PutSymlink /etc")
	shProf, err := execution.POSIXLaunchProfile(execution.InterpreterSH, execution.LoginModeInherit)
	mustOK(t, err, "POSIXLaunchProfile sh")
	wdCmd, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: shProf,
		Command: "ls", WorkDir: algebraic.Some(wdLink),
	})
	mustOK(t, err, "NewCommandPlan wd")
	if _, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{node}, Command: wdCmd, Risk: algebraic.Some(security.RiskSafe),
	}); err == nil || rig.dialer.openCount.Load() != 0 {
		t.Fatalf("expected Round-2 WorkDir block with 0 sessions, err=%v opens=%d", err, rig.dialer.openCount.Load())
	}

	// 2. TargetNode.DefaultProfile 继承：当 Command.Profile 为默认服务配置时自动沿用节点默认 Profile。
	bashProf, err := execution.POSIXLaunchProfile(execution.InterpreterBash, execution.LoginModeLogin)
	mustOK(t, err, "POSIXLaunchProfile bash")
	customNode, err := automation.NewTargetNode(automation.TargetNodeSpec{
		NodeID: node.NodeID(), Plan: node.Plan(), DefaultProfile: algebraic.Some(bashProf),
	})
	mustOK(t, err, "NewTargetNode with DefaultProfile")
	var gotInterp execution.Interpreter
	rig.dialer.onCmd = func(_ context.Context, _ string, cmd execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		gotInterp = cmd.Profile().Interpreter()
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	rep, err := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{customNode}, Command: makeCmdPlan(t, "whoami"), Risk: algebraic.Some(security.RiskSafe),
	})
	mustOK(t, err, "BatchExec profile inherit")
	if rep.SucceededCount() != 1 || gotInterp != execution.InterpreterBash {
		t.Fatalf("expected inherited bash profile, got ok=%d interp=%v", rep.SucceededCount(), gotInterp)
	}

	// 3. 批量执行中途触发 Gate.Halted -> 保留 gate.ErrGateHalted 错误链且未执行节点标记 gate_halted。
	n1 := makeTargetNode(t, "halt-1", "10.0.6.2:22")
	n2 := makeTargetNode(t, "halt-2", "10.0.6.3:22")
	rig.dialer.onCmd = func(_ context.Context, nodeID string, _ execution.CommandPlan, _ []byte, _, _ io.Writer) (execution.ExecutionOutcome, error) {
		if nodeID == "halt-1" {
			rig.auditClust.Faults().InjectOnce("audit.record.finalized", errors.New("audit io err"))
			// 借用一次独立小调用触发 StrictAgent 熔断。
			_, _ = rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
				Targets: []automation.TargetNode{customNode}, Command: makeCmdPlan(t, "true"), Risk: algebraic.Some(security.RiskSafe),
			})
		}
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}
	repHalt, haltErr := rig.svc.BatchExec(context.Background(), automation.BatchExecRequest{
		Targets: []automation.TargetNode{n1, n2}, Command: makeCmdPlan(t, "true"), Concurrency: 1, Risk: algebraic.Some(security.RiskSafe),
	})
	if !errors.Is(haltErr, gate.ErrGateHalted) {
		t.Fatalf("expected gate.ErrGateHalted preserved in error chain, got %v", haltErr)
	}
	if !repHalt.IsValid() || !errors.Is(repHalt.Results()[1].Err(), gate.ErrGateHalted) {
		t.Fatalf("expected second node aborted with gate.ErrGateHalted, got %v", repHalt.Results()[1].Err())
	}
}
