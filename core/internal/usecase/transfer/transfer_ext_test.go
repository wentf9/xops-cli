package transfer_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
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
	"github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口契约断言集中于外置测试文件，校验测试替身与端口契约一致性。
var (
	_ ports.DialerPort    = (*sharedRemoteDialer)(nil)
	_ ports.TransportConn = (*sharedRemoteConn)(nil)
	_ ports.RemoteFSPort  = (*hookedRemoteFS)(nil)
	_ ports.JournalStore  = (*spyJournalStore)(nil)
)

type hookedRemoteFS struct {
	inner  *sim.SimRemoteFS
	dialer *sharedRemoteDialer
	closed atomic.Bool
}

func (h *hookedRemoteFS) recordCtx(ctx context.Context) {
	if _, ok := trace.LeaseScopeFromContext(ctx); ok {
		h.dialer.rfsSawLease.Store(true)
	}
	if _, ok := trace.OpIDFromContext(ctx); ok {
		h.dialer.rfsSawOpID.Store(true)
	}
}
func (h *hookedRemoteFS) checkOpen() error {
	if h.closed.Load() {
		return ports.ErrClosed
	}
	return nil
}
func (h *hookedRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		var z pathalg.RemotePath
		return z, err
	}
	h.dialer.mu.Lock()
	hook := h.dialer.onRealPath
	h.dialer.mu.Unlock()
	if hook != nil {
		if rp, handled, err := hook(ctx, p); handled {
			return rp, err
		}
	}
	return h.inner.RealPath(ctx, p)
}
func (h *hookedRemoteFS) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		var z ports.RemoteFileStat
		return z, err
	}
	return h.inner.Stat(ctx, p)
}
func (h *hookedRemoteFS) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		var z ports.RemoteFileStat
		return z, err
	}
	h.dialer.mu.Lock()
	ov := h.dialer.onLstatOverride
	h.dialer.mu.Unlock()
	if ov != nil {
		if st, ok, oErr := ov(p); oErr != nil || ok {
			return st, oErr
		}
	}
	return h.inner.Lstat(ctx, p)
}
func (h *hookedRemoteFS) ReadLink(ctx context.Context, p pathalg.RemotePath) (string, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return "", err
	}
	return h.inner.ReadLink(ctx, p)
}
func (h *hookedRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]ports.RemoteDirEntry, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return nil, err
	}
	return h.inner.ReadDir(ctx, dir)
}

//xops:syncclosure
//xops:borrowed
func (h *hookedRemoteFS) WithReadFile(ctx context.Context, p pathalg.RemotePath, limits ports.ReadLimits, fn func(r io.Reader, size int64) error) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	var copied []byte
	var fSize int64
	if err := h.inner.WithReadFile(ctx, p, limits, func(r io.Reader, size int64) error {
		fSize = size
		var rErr error
		copied, rErr = io.ReadAll(r)
		return rErr
	}); err != nil {
		return err
	}
	if err := fn(bytes.NewReader(copied), fSize); err != nil {
		return err
	}
	h.dialer.mu.Lock()
	afterHook := h.dialer.onAfterWithReadFile
	h.dialer.mu.Unlock()
	if afterHook != nil {
		return afterHook(ctx, p)
	}
	return nil
}
func (h *hookedRemoteFS) ReadChunk(ctx context.Context, p pathalg.RemotePath, offset int64, dst io.Writer, length int64) (int64, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return 0, err
	}
	h.dialer.mu.Lock()
	hook := h.dialer.onReadChunk
	h.dialer.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, p, offset, length); err != nil {
			return 0, err
		}
	}
	return h.inner.ReadChunk(ctx, p, offset, dst, length)
}
func (h *hookedRemoteFS) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, r io.Reader) (ports.RemoteFileStat, error) {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		var z ports.RemoteFileStat
		return z, err
	}
	h.dialer.mu.Lock()
	hook := h.dialer.onBeforeWriteAtomic
	h.dialer.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, p); err != nil {
			var z ports.RemoteFileStat
			return z, err
		}
	}
	return h.inner.WriteFileAtomic(ctx, p, spec, r)
}
func (h *hookedRemoteFS) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, r io.Reader, length int64) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	h.dialer.mu.Lock()
	hook := h.dialer.onWriteChunk
	h.dialer.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, p, offset, length); err != nil {
			return err
		}
	}
	return h.inner.WriteChunk(ctx, p, offset, r, length)
}
func (h *hookedRemoteFS) RenameAtomic(ctx context.Context, oldPath, newPath pathalg.RemotePath, spec ports.RemoteRenameSpec) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	h.dialer.mu.Lock()
	hook := h.dialer.onBeforeRenameAtomic
	h.dialer.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, oldPath, newPath); err != nil {
			return err
		}
	}
	return h.inner.RenameAtomic(ctx, oldPath, newPath, spec)
}
func (h *hookedRemoteFS) Chmod(ctx context.Context, p pathalg.RemotePath, perm fs.FileMode) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	return h.inner.Chmod(ctx, p, perm)
}
func (h *hookedRemoteFS) Chtimes(ctx context.Context, p pathalg.RemotePath, atime, mtime time.Time) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	return h.inner.Chtimes(ctx, p, atime, mtime)
}
func (h *hookedRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, perm fs.FileMode) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	return h.inner.MkdirAll(ctx, dir, perm)
}
func (h *hookedRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	return h.inner.Remove(ctx, p)
}
func (h *hookedRemoteFS) RemoveDir(ctx context.Context, dir pathalg.RemotePath) error {
	h.recordCtx(ctx)
	if err := h.checkOpen(); err != nil {
		return err
	}
	return h.inner.RemoveDir(ctx, dir)
}
func (h *hookedRemoteFS) Close() error { h.closed.Store(true); return nil }

type sharedRemoteDialer struct {
	remoteFS             *sim.SimRemoteFS
	dialCount            atomic.Int64
	dialSawLease         atomic.Bool
	rfsSawLease          atomic.Bool
	rfsSawOpID           atomic.Bool
	mu                   sync.Mutex
	onRealPath           func(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, bool, error)
	onAfterWithReadFile  func(ctx context.Context, p pathalg.RemotePath) error
	onReadChunk          func(ctx context.Context, p pathalg.RemotePath, offset, length int64) error
	onWriteChunk         func(ctx context.Context, p pathalg.RemotePath, offset, length int64) error
	onBeforeWriteAtomic  func(ctx context.Context, p pathalg.RemotePath) error
	onBeforeRenameAtomic func(ctx context.Context, oldP, newP pathalg.RemotePath) error
	onLstatOverride      func(p pathalg.RemotePath) (ports.RemoteFileStat, bool, error)
}

func (d *sharedRemoteDialer) DialHop(ctx context.Context, hop plan.HopSpec, dig plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	d.dialCount.Add(1)
	if _, ok := trace.LeaseScopeFromContext(ctx); ok {
		d.dialSawLease.Store(true)
	}
	c := &sharedRemoteConn{dialer: d, dig: dig, ep: hop.Endpoint()}
	c.alive.Store(true)
	return c, nil
}

type sharedRemoteConn struct {
	dialer *sharedRemoteDialer
	dig    plan.HopDigest
	ep     netaddr.Endpoint
	alive  atomic.Bool
}

func (c *sharedRemoteConn) HopDigest() plan.HopDigest           { return c.dig }
func (c *sharedRemoteConn) Endpoint() netaddr.Endpoint          { return c.ep }
func (c *sharedRemoteConn) IsAlive() bool                       { return c.alive.Load() }
func (c *sharedRemoteConn) SendKeepalive(context.Context) error { return nil }
func (c *sharedRemoteConn) Close() error                        { c.alive.Store(false); return nil }
func (c *sharedRemoteConn) OpenSession(context.Context) (ports.RemoteSession, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) DialStreamLocal(context.Context, pathalg.RemotePath) (net.Conn, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) ListenStreamLocal(context.Context, pathalg.RemotePath) (net.Listener, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) OpenTUN(context.Context, ports.TUNSpec) (io.ReadWriteCloser, error) {
	return nil, ports.ErrUnsupported
}
func (c *sharedRemoteConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &hookedRemoteFS{inner: c.dialer.remoteFS, dialer: c.dialer}, nil
}

type spyJournalStore struct {
	inner            *sim.SimJournalStore
	mu               sync.Mutex
	pruneCalls       int
	deleteCalls      int
	loadGenCalls     atomic.Int64
	failOnAppendKind fsm.JournalRecordKind
	appendErr        error
}

func (s *spyJournalStore) Append(ctx context.Context, rec fsm.TransferJournalRecord) error {
	s.mu.Lock()
	fk, fe := s.failOnAppendKind, s.appendErr
	s.mu.Unlock()
	if fe != nil && rec.Kind() == fk {
		return fe
	}
	return s.inner.Append(ctx, rec)
}
func (s *spyJournalStore) Load(ctx context.Context, id security.OperationID) ([]fsm.TransferJournalRecord, error) {
	return s.inner.Load(ctx, id)
}
func (s *spyJournalStore) LoadGenerations(ctx context.Context, id security.OperationID) ([]ports.JournalGenerationSnapshot, error) {
	s.loadGenCalls.Add(1)
	return s.inner.LoadGenerations(ctx, id)
}
func (s *spyJournalStore) PruneGeneration(ctx context.Context, id security.OperationID, gen uint64) error {
	s.mu.Lock()
	s.pruneCalls++
	s.mu.Unlock()
	return s.inner.PruneGeneration(ctx, id, gen)
}
func (s *spyJournalStore) ListActive(ctx context.Context) ([]security.OperationID, error) {
	return s.inner.ListActive(ctx)
}
func (s *spyJournalStore) Delete(ctx context.Context, id security.OperationID) error {
	s.mu.Lock()
	s.deleteCalls++
	s.mu.Unlock()
	return s.inner.Delete(ctx, id)
}
func (s *spyJournalStore) mutationCounts() (prunes, deletes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneCalls, s.deleteCalls
}

type rigOptions struct {
	profile          gate.PolicyProfileKind
	approvalThresh   security.RiskLevel
	protectedPats    []string
	nodeOverrides    algebraic.Option[security.NodeOverrides]
	omitOperatorRead bool
	omitScopedFS     bool
	omitJournals     bool
}

type transferTestRig struct {
	clock      *sim.SimClock
	rng        *sim.SeededRand
	bus        *events.SystemBus
	auditClust *sim.SimAuditCluster
	auditSink  *sim.SimAuditSink
	remoteFS   *sim.SimRemoteFS
	dialer     *sharedRemoteDialer
	scopedFS   *sim.SimScopedRootFS
	opReadFS   *sim.SimOperatorReadFS
	journals   *spyJournalStore
	pool       *pool.Pool
	gate       *gate.Gate
	svc        *transfer.Service
	plan       plan.SealedConnectionPlan
	localRoot  pathalg.LocalDir
}

func newTransferRig(t *testing.T, opts rigOptions) *transferTestRig {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261126)
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 64})
	requireNoErr(t, err, "NewSystemBus")
	cluster := sim.NewSimAuditCluster()
	sink, err := cluster.NewSinkFromEntropy(rng)
	requireNoErr(t, err, "NewSinkFromEntropy")
	rfs := sim.NewSimRemoteFS(clk)
	dialer := &sharedRemoteDialer{remoteFS: rfs}
	p, err := pool.NewPool(context.Background(), pool.PoolConfig{Dialer: dialer, Clock: clk, Entropy: rng, Bus: bus})
	requireNoErr(t, err, "NewPool")
	prof := opts.profile
	if !prof.IsValid() {
		prof = gate.PolicyProfileDirectOperator
	}
	thresh := opts.approvalThresh
	if !thresh.IsValid() {
		thresh = security.RiskDangerous
	}
	pats := opts.protectedPats
	if len(pats) == 0 {
		pats = gate.StrictDefaultProtectedPatterns()
	}
	rules := make([]pathalg.ProtectedRule, 0, len(pats))
	for _, pat := range pats {
		r, rErr := pathalg.ParseProtectedRule(pat)
		requireNoErr(t, rErr, "ParseProtectedRule")
		rules = append(rules, r)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: thresh, NoElicitFallback: gate.NoElicitFallbackDeny,
		NodeOverrides: opts.nodeOverrides, ProtectedRules: rules,
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g, err := gate.NewGate(gate.GateConfig{
		Profile: prof, Policy: pol, AuditSink: sink, Clock: clk, Entropy: rng, SystemBus: bus,
		OnHalt: func(info gate.HaltInfo) { p.GateHalted(info.Cause()) },
	})
	requireNoErr(t, err, "NewGate")
	scoped := sim.NewSimScopedRootFS(clk)
	opRead := sim.NewSimOperatorReadFS()
	jStore := &spyJournalStore{inner: sim.NewSimJournalStore()}
	cfg := transfer.ServiceConfig{Gate: g, Pool: p, Clock: clk, Entropy: rng, SystemBus: bus, DefaultChunkSize: 4096, DefaultConcurrency: 4}
	if !opts.omitScopedFS {
		cfg.ScopedFS = scoped
	}
	if !opts.omitOperatorRead {
		cfg.OperatorReadFS = opRead
	}
	if !opts.omitJournals {
		cfg.Journals = jStore
	}
	svc, err := transfer.NewService(cfg)
	requireNoErr(t, err, "NewService")
	lr := mustLocalDir(t, "/work/root")
	requireNoErr(t, scoped.EnsureRoot(lr, 0o700), "EnsureRoot")
	return &transferTestRig{
		clock: clk, rng: rng, bus: bus, auditClust: cluster, auditSink: sink,
		remoteFS: rfs, dialer: dialer, scopedFS: scoped, opReadFS: opRead,
		journals: jStore, pool: p, gate: g, svc: svc, plan: mustTestPlan(t, "198.51.100.42"), localRoot: lr,
	}
}
func (r *transferTestRig) close() {
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
func (r *transferTestRig) callBase(stream *events.OperationStream) transfer.CallBase {
	return transfer.CallBase{Plan: r.plan, NodeID: "node-transfer-1", OperationStream: stream}
}

func requireNoErr(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected err: %v", msg, err)
	}
}
func requireErrIs(t *testing.T, err, target error, msg string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got err=%v, want errors.Is(..., %v)", msg, err, target)
	}
}
func mustRemotePath(t *testing.T, raw string) pathalg.RemotePath {
	t.Helper()
	p, err := pathalg.ParseRemotePath(raw)
	requireNoErr(t, err, "ParseRemotePath("+raw+")")
	return p
}
func mustLocalDir(t *testing.T, raw string) pathalg.LocalDir {
	t.Helper()
	d, err := pathalg.ParseLocalDir(raw)
	requireNoErr(t, err, "ParseLocalDir("+raw+")")
	return d
}
func mustLocalDest(t *testing.T, raw string) pathalg.LocalRootedDest {
	t.Helper()
	d, err := pathalg.ParseLocalRootedDest(raw)
	requireNoErr(t, err, "ParseLocalRootedDest("+raw+")")
	return d
}
func mustLocalSource(t *testing.T, raw string) pathalg.LocalSourcePath {
	t.Helper()
	p, err := pathalg.ParseLocalSourcePath(raw)
	requireNoErr(t, err, "ParseLocalSourcePath("+raw+")")
	return p
}
func mustTestPlan(t *testing.T, host string) plan.SealedConnectionPlan {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	requireNoErr(t, err, "ParseCanonicalHost")
	ep, err := netaddr.NewEndpoint(ch, 22)
	requireNoErr(t, err, "NewEndpoint")
	u, err := option.ParseUsername("ops")
	requireNoErr(t, err, "ParseUsername")
	auth, err := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	requireNoErr(t, err, "NewAuthAgent")
	unset := option.UnsetOptionLayer()
	eff, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, unset, unset, unset, unset)
	requireNoErr(t, err, "ResolveEffectivePolicy")
	hop, err := plan.NewHopSpecFromAuth(0, "node-transfer-1", u, auth, eff)
	requireNoErr(t, err, "NewHopSpecFromAuth")
	pl, err := plan.SealConnectionPlan(hop)
	requireNoErr(t, err, "SealConnectionPlan")
	return pl
}
func mustWriteRemote(t *testing.T, rfs *sim.SimRemoteFS, rawPath string, data []byte) ports.RemoteFileStat {
	t.Helper()
	p := mustRemotePath(t, rawPath)
	if !p.Dir().IsRoot() {
		requireNoErr(t, rfs.MkdirAll(context.Background(), p.Dir(), 0o755), "MkdirAll("+rawPath+")")
	}
	spec, err := ports.NewRemoteWriteSpec(ports.RemoteWriteSpecInput{Perm: 0o644, AtomicRename: true})
	requireNoErr(t, err, "NewRemoteWriteSpec")
	st, err := rfs.WriteFileAtomic(context.Background(), p, spec, bytes.NewReader(data))
	requireNoErr(t, err, "WriteFileAtomic("+rawPath+")")
	return st
}
func mustReadRemote(t *testing.T, rfs *sim.SimRemoteFS, rawPath string) []byte {
	t.Helper()
	lim, err := ports.NewReadLimits(16 << 20)
	requireNoErr(t, err, "NewReadLimits")
	var out []byte
	err = rfs.WithReadFile(context.Background(), mustRemotePath(t, rawPath), lim, func(r io.Reader, _ int64) error {
		var rErr error
		out, rErr = io.ReadAll(r)
		return rErr
	})
	requireNoErr(t, err, "WithReadFile("+rawPath+")")
	return out
}
func mustReadLocal(t *testing.T, fsPort *sim.SimScopedRootFS, root pathalg.LocalDir, rel string) []byte {
	t.Helper()
	lim, err := ports.NewReadLimits(16 << 20)
	requireNoErr(t, err, "NewReadLimits")
	var out []byte
	err = fsPort.WithRoot(root, func(h ports.RootHandle) error {
		var rErr error
		out, rErr = h.ReadAllBounded(mustLocalDest(t, rel), lim)
		return rErr
	})
	requireNoErr(t, err, "ReadAllBounded("+rel+")")
	return out
}
func mustNewOpStream(t *testing.T, rng *sim.SeededRand) *events.OperationStream {
	t.Helper()
	tid, err := trace.NewTraceIDFrom(rng)
	requireNoErr(t, err, "NewTraceIDFrom")
	oid, err := security.NewOperationIDFrom(rng)
	requireNoErr(t, err, "NewOperationIDFrom")
	st, err := events.NewOperationStream(events.OperationStreamConfig{TraceID: tid, OperationID: oid, OperationBuffer: 64})
	requireNoErr(t, err, "NewOperationStream")
	return st
}
func drainOpStream(t *testing.T, st *events.OperationStream) []events.Event {
	t.Helper()
	var evs []events.Event
	for {
		ev, ok, err := st.Next(context.Background())
		requireNoErr(t, err, "OperationStream.Next")
		if !ok {
			return evs
		}
		evs = append(evs, ev)
	}
}
func makePatternPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 17) & 0xff)
	}
	return b
}

func TestZeroValueAndInvalidConfigFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zeroSvc transfer.Service
	var nilSvc *transfer.Service
	var zeroSrc transfer.LocalUploadSource
	var zeroEdit transfer.TextEdit
	if zeroSrc.IsValid() || !zeroSrc.IsZero() || zeroSrc.Kind().IsValid() || zeroSrc.BaseName() != "" {
		t.Fatalf("零值 LocalUploadSource 必须失败关闭")
	}
	if zeroEdit.IsValid() || zeroEdit.OldText() != "" || zeroEdit.ReplaceAll() {
		t.Fatalf("零值 TextEdit 必须失败关闭")
	}
	_, err := transfer.NewTextEdit("", "x", false)
	requireErrIs(t, err, transfer.ErrInvalidRequest, "空 OldText 必须拒绝")
	_, err = transfer.NewService(transfer.ServiceConfig{})
	requireErrIs(t, err, transfer.ErrInvalidConfig, "空 ServiceConfig 必须拒绝")

	ctx := context.Background()
	for _, s := range []*transfer.Service{&zeroSvc, nilSvc} {
		_, err = s.ListDir(ctx, transfer.ListDirRequest{Path: mustRemotePath(t, "/")})
		requireErrIs(t, err, transfer.ErrServiceNotInitialized, "未初始化 Service 必须失败关闭")
	}

	rig := newTransferRig(t, rigOptions{})
	defer rig.close()
	var nilCtx context.Context
	_, err = rig.svc.ListDir(nilCtx, transfer.ListDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/")})
	requireErrIs(t, err, transfer.ErrNilContext, "nil ctx 必须返回 ErrNilContext")
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = rig.svc.ListDir(canceledCtx, transfer.ListDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/")})
	requireErrIs(t, err, context.Canceled, "已取消 ctx 必须立即返回")
}

func TestSFTPWorkspaceOps_ZeroLocalFSAndStrictRemoveSeparation(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true, omitScopedFS: true, omitJournals: true})
	defer rig.close()
	ctx := context.Background()

	requireNoErr(t, rig.svc.MkdirAll(ctx, transfer.MkdirAllRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/sub")}), "MkdirAll")
	mustWriteRemote(t, rig.remoteFS, "/ws/z.txt", []byte("zeta"))
	mustWriteRemote(t, rig.remoteFS, "/ws/a.txt", []byte("alpha"))
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/ws/link"), "a.txt"), "PutSymlink")

	listRes, err := rig.svc.ListDir(ctx, transfer.ListDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws")})
	requireNoErr(t, err, "ListDir")
	if len(listRes.Entries) != 4 || listRes.Entries[0].Name().String() != "a.txt" || listRes.Entries[3].Name().String() != "z.txt" {
		t.Fatalf("ListDir 字典序结果异常: %+v", listRes.Entries)
	}
	lstatRes, err := rig.svc.Stat(ctx, transfer.StatRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/link"), FollowSymlinks: false})
	requireNoErr(t, err, "Lstat")
	statRes, err := rig.svc.Stat(ctx, transfer.StatRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/link"), FollowSymlinks: true})
	requireNoErr(t, err, "Stat")
	if !lstatRes.IsSymlink() || !statRes.IsRegular() {
		t.Fatalf("Stat/Lstat 语义不符: lstat=%s stat=%s", lstatRes.FileType(), statRes.FileType())
	}
	rp, err := rig.svc.RealPath(ctx, transfer.RealPathRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/link")})
	requireNoErr(t, err, "RealPath")
	if rp.String() != "/ws/a.txt" {
		t.Fatalf("RealPath=%s, want /ws/a.txt", rp)
	}
	target, err := rig.svc.ReadLink(ctx, transfer.ReadLinkRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/link")})
	requireNoErr(t, err, "ReadLink")
	if target != "a.txt" {
		t.Fatalf("ReadLink=%q, want a.txt", target)
	}

	// Chmod & Chtimes 正向与非法拦截
	requireNoErr(t, rig.svc.Chmod(ctx, transfer.ChmodRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt"), Perm: 0o600}), "Chmod")
	requireErrIs(t, rig.svc.Chmod(ctx, transfer.ChmodRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt"), Perm: 0}), transfer.ErrInvalidRequest, "Chmod 0 须拒绝")
	ts := time.Date(2025, time.March, 10, 8, 30, 0, 0, time.UTC)
	requireNoErr(t, rig.svc.Chtimes(ctx, transfer.ChtimesRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt"), Atime: ts, Mtime: ts}), "Chtimes")
	requireErrIs(t, rig.svc.Chtimes(ctx, transfer.ChtimesRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt")}), transfer.ErrInvalidRequest, "零时间戳须拒绝")
	updated, err := rig.svc.Stat(ctx, transfer.StatRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt")})
	requireNoErr(t, err, "Stat after chmod/chtimes")
	if updated.Perm() != 0o600 || !updated.ModTime().Equal(ts) {
		t.Fatalf("Chmod/Chtimes 未生效: perm=%#o mtime=%v", updated.Perm(), updated.ModTime())
	}

	// Remove 与 RemoveDir 严格分离
	requireErrIs(t, rig.svc.Remove(ctx, transfer.RemoveRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/sub")}), ports.ErrRemoteIsDir, "Remove 目录必须返回 ErrRemoteIsDir")
	requireErrIs(t, rig.svc.RemoveDir(ctx, transfer.RemoveDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt")}), ports.ErrInvalidArgument, "RemoveDir 文件必须拒绝")
	requireErrIs(t, rig.svc.RemoveDir(ctx, transfer.RemoveDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws")}), ports.ErrInvalidArgument, "RemoveDir 非空目录必须拒绝")
	requireNoErr(t, rig.svc.Remove(ctx, transfer.RemoveRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/link")}), "Remove 软链")
	requireNoErr(t, rig.svc.Remove(ctx, transfer.RemoveRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/a.txt")}), "Remove 文件")
	requireNoErr(t, rig.svc.RemoveDir(ctx, transfer.RemoveDirRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/ws/sub")}), "RemoveDir 空目录")
}

func TestGateWrapsPool_Round2CanonicalizationAndHaltedCircuitBreaker(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{
		profile:          gate.PolicyProfileStrictAgent,
		approvalThresh:   security.RiskDangerous,
		omitOperatorRead: true,
	})
	defer rig.close()
	ctx := context.Background()

	// 1. 合法操作验证 gate.WithAuthorized 包裹 pool.WithLease（拨号无租约、RemoteFS 持租约+OpID）
	mustWriteRemote(t, rig.remoteFS, "/tmp/ok.txt", []byte("hello"))
	_, err := rig.svc.ReadFile(ctx, transfer.ReadFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/ok.txt")})
	requireNoErr(t, err, "StrictAgent 安全读 /tmp/ok.txt")
	if rig.dialer.dialSawLease.Load() || !rig.dialer.rfsSawLease.Load() || !rig.dialer.rfsSawOpID.Load() {
		t.Fatalf("门控与租约嵌套序异常: dialSawLease=%v rfsSawLease=%v rfsSawOpID=%v",
			rig.dialer.dialSawLease.Load(), rig.dialer.rfsSawLease.Load(), rig.dialer.rfsSawOpID.Load())
	}

	// 2. Round-2 软链规范化拦截：/tmp/escape -> /etc/shadow 及悬空软链 /tmp/dangling -> /etc/newconf
	mustWriteRemote(t, rig.remoteFS, "/etc/shadow", []byte("root:*"))
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/escape"), "/etc/shadow"), "PutSymlink escape")
	requireNoErr(t, rig.remoteFS.PutSymlink(mustRemotePath(t, "/tmp/dangling"), "/etc/newconf"), "PutSymlink dangling")
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/escape"), Content: []byte("pwn")})
	if err == nil {
		t.Fatalf("Round-2 必须拦截经软链指向 /etc/shadow 的写入")
	}
	if string(mustReadRemote(t, rig.remoteFS, "/etc/shadow")) != "root:*" {
		t.Fatalf("/etc/shadow 绝不能被篡改")
	}
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/tmp/dangling"), Content: []byte("pwn")})
	if err == nil {
		t.Fatalf("Round-2 必须拦截悬空软链指向 /etc/newconf 的写入")
	}

	// 3. NodeOverrides=Deny 词法直接拒绝且 0 拨号；受保护路径 /etc/hosts 阻断并要求审批
	denyRule, err := security.NewNodeOverrideRuleWithFloor("node-*", security.RiskDangerous, security.DecisionKindDeny)
	requireNoErr(t, err, "NewNodeOverrideRule")
	denyOvr, err := security.NewNodeOverrides(denyRule)
	requireNoErr(t, err, "NewNodeOverrides")
	rigDeny := newTransferRig(t, rigOptions{
		profile: gate.PolicyProfileStrictAgent, approvalThresh: security.RiskDangerous,
		nodeOverrides: algebraic.Some(denyOvr), omitOperatorRead: true,
	})
	defer rigDeny.close()
	_, err = rigDeny.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rigDeny.callBase(nil), Path: mustRemotePath(t, "/tmp/denied.txt"), Content: []byte("x")})
	requireErrIs(t, err, gate.ErrAuthorizationDenied, "NodeOverrides=Deny 必须在词法阶段直接拒绝")
	if rigDeny.dialer.dialCount.Load() != 0 {
		t.Fatalf("词法直接拒绝前不应拨号，实际 dials=%d", rigDeny.dialer.dialCount.Load())
	}
	_, err = rig.svc.WriteFile(ctx, transfer.WriteFileRequest{CallBase: rig.callBase(nil), Path: mustRemotePath(t, "/etc/hosts"), Content: []byte("x")})
	requireErrIs(t, err, gate.ErrApprovalRequired, "受保护路径必须阻断并要求审批")

	// 4. StrictAgent AuditPostWriteError -> Halted 熔断 -> 吊销活跃 ManagedHandle 并拒绝后续调用
	dest, err := fsm.NewUploadDest(mustRemotePath(t, "/tmp/stream.bin"))
	requireNoErr(t, err, "NewUploadDest")
	info, err := rig.svc.StartTransfer(ctx, transfer.StartTransferRequest{CallBase: rig.callBase(nil), Dest: dest, TotalBytes: 8})
	requireNoErr(t, err, "StartTransfer")
	rig.auditSink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			rig.auditClust.SetENOSPC(true) // 在前置 Authorized 落盘后注入 ENOSPC，精准触发终态 AuditPostWriteError
		}
	})
	_, _ = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 0, Data: []byte("1234")})
	rig.auditSink.SetBoundaryHook(nil)
	if !rig.gate.IsHalted() {
		t.Fatalf("StrictAgent 终态审计写盘失败必须触发 Gate Halted")
	}
	rig.auditClust.SetENOSPC(false)
	_, err = rig.svc.WriteTransferChunk(ctx, transfer.WriteTransferChunkRequest{CallBase: rig.callBase(nil), Handle: info.Handle, Offset: 4, Data: []byte("5678")})
	requireErrIs(t, err, gate.ErrGateHalted, "Halted 后必须拒绝一切新请求")
	_, err = rig.svc.RecoverAllTransfers(ctx, transfer.RecoverAllRequest{})
	requireErrIs(t, err, gate.ErrGateHalted, "Halted 后 RecoverAllTransfers 必须拒绝")
	_, err = rig.svc.ResumeTransfer(ctx, transfer.ResumeTransferRequest{CallBase: rig.callBase(nil), TransferID: info.TransferID})
	requireErrIs(t, err, gate.ErrGateHalted, "Halted 后 ResumeTransfer 必须拒绝")
	if rig.pool.Stats().ActiveHandles != 0 {
		t.Fatalf("GateHalted 必须吊销全部活跃受管句柄，实际=%d", rig.pool.Stats().ActiveHandles)
	}
}

func TestEarlyValidationFailureClosesOperationStream(t *testing.T) {
	defer goleak.VerifyNone(t)
	rig := newTransferRig(t, rigOptions{omitOperatorRead: true})
	defer rig.close()
	ctx := context.Background()

	// 校验早退路径（例如缺 OperatorReadFS）仍必须闭合 OperationStream 满足 ADR-010 确定性 EOF 契约
	stream := mustNewOpStream(t, rig.rng)
	opSrc, err := transfer.NewOperatorUploadSource(mustLocalSource(t, "/local/f.bin"), pathalg.SymlinkReject)
	requireNoErr(t, err, "NewOperatorUploadSource")
	_, err = rig.svc.SCPUpload(ctx, transfer.SCPUploadRequest{CallBase: rig.callBase(stream), Source: opSrc, RemoteDest: mustRemotePath(t, "/srv/f.bin")})
	requireErrIs(t, err, transfer.ErrOperatorReadUnavailable, "缺 OperatorReadFS 必须失败关闭")
	if !stream.IsClosed() || len(drainOpStream(t, stream)) != 0 {
		t.Fatalf("早退错误必须闭合 OperationStream 并产生确定性 EOF")
	}
}
