package tck_test

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// 本文件通过纯内存参考桩适配器自测 Dialer、MuxSocket、RemoteFS、Audit、Clock、Entropy、Process、Terminal 与 Interaction TCK 套件。

type memDialer struct{}

func (memDialer) DialHop(ctx context.Context, hop plan.HopSpec, digest plan.HopDigest, _ ports.TransportConn) (ports.TransportConn, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !hop.IsValid() || !digest.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	c := &memTransportConn{digest: digest, endpoint: hop.Endpoint()}
	c.alive.Store(true)
	return c, nil
}

type memTransportConn struct {
	digest   plan.HopDigest
	endpoint netaddr.Endpoint
	alive    atomic.Bool
}

func (c *memTransportConn) HopDigest() plan.HopDigest  { return c.digest }
func (c *memTransportConn) Endpoint() netaddr.Endpoint { return c.endpoint }
func (c *memTransportConn) IsAlive() bool              { return c.alive.Load() }
func (c *memTransportConn) Close() error {
	c.alive.Store(false)
	return nil
}
func (c *memTransportConn) SendKeepalive(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !c.alive.Load() {
		return ports.ErrClosed
	}
	return nil
}
func (c *memTransportConn) OpenSession(ctx context.Context) (ports.RemoteSession, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	return &memRemoteSession{}, nil
}
func (c *memTransportConn) DialTCP(context.Context, netaddr.HostPort) (net.Conn, error) {
	return &memEchoConn{}, nil
}
func (c *memTransportConn) ListenTCP(context.Context, string) (net.Listener, error) {
	return &memListener{addr: memAddr("tcp:127.0.0.1:0")}, nil
}
func (c *memTransportConn) OpenRemoteFS(ctx context.Context) (ports.RemoteFSPort, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !c.alive.Load() {
		return nil, ports.ErrClosed
	}
	return newMemRemoteFS(), nil
}

type memRemoteSession struct{ closed atomic.Bool }

func (s *memRemoteSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !cmd.IsValid() {
		return ports.ErrInvalidArgument
	}
	if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, "tck-ok\n")
	}
	return nil
}
func (s *memRemoteSession) StartShell(context.Context, algebraic.Option[ports.PTYRequest], ports.ExecStreams) error {
	return nil
}
func (s *memRemoteSession) ResizePTY(context.Context, ports.TerminalSize) error { return nil }
func (s *memRemoteSession) Signal(context.Context, string) error                { return nil }
func (s *memRemoteSession) Wait(context.Context) (execution.ExecutionOutcome, error) {
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}
func (s *memRemoteSession) Close() error {
	s.closed.Store(true)
	return nil
}

type memAddr string

func (a memAddr) Network() string { return "unix" }
func (a memAddr) String() string  { return string(a) }

type memListener struct {
	addr   net.Addr
	closed atomic.Bool
}

func (l *memListener) Accept() (net.Conn, error) { return nil, ports.ErrClosed }
func (l *memListener) Close() error {
	l.closed.Store(true)
	return nil
}
func (l *memListener) Addr() net.Addr { return l.addr }

type memMuxSocket struct{}

func (memMuxSocket) Probe(ctx context.Context, p pathalg.LocalSourcePath) (ports.MuxControlResponse, error) {
	if ctx == nil {
		return zero[ports.MuxControlResponse](), ports.ErrNilContext
	}
	if !p.IsValid() {
		return zero[ports.MuxControlResponse](), ports.ErrInvalidArgument
	}
	return ports.NewMuxControlResponse(true, 1024, "alive")
}
func (memMuxSocket) Control(ctx context.Context, req ports.MuxControlRequest) (ports.MuxControlResponse, error) {
	if ctx == nil {
		return zero[ports.MuxControlResponse](), ports.ErrNilContext
	}
	if !req.IsValid() {
		return zero[ports.MuxControlResponse](), ports.ErrInvalidArgument
	}
	return ports.NewMuxControlResponse(true, 1024, req.Action().String())
}
func (memMuxSocket) DialMux(ctx context.Context, p pathalg.LocalSourcePath) (ports.TransportConn, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !p.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	return nil, ports.ErrUnsupported
}
func (memMuxSocket) WithListener(ctx context.Context, dir pathalg.LocalDir, name pathalg.LocalRootedDest, fn func(ln net.Listener) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !dir.IsValid() || !name.IsValid() {
		return ports.ErrInvalidArgument
	}
	ln := &memListener{addr: memAddr(dir.String() + "/" + name.String())}
	defer func() { _ = ln.Close() }()
	return fn(ln)
}

type memRemoteFile struct {
	data []byte
	mode fs.FileMode
	ino  uint64
}

type memRemoteFS struct {
	mu      sync.Mutex
	nextIno uint64
	dirs    map[string]bool
	files   map[string]memRemoteFile
}

func newMemRemoteFS() *memRemoteFS {
	return &memRemoteFS{nextIno: 100, dirs: map[string]bool{"/": true}, files: make(map[string]memRemoteFile)}
}

func (r *memRemoteFS) RealPath(ctx context.Context, p pathalg.RemotePath) (pathalg.RemotePath, error) {
	if ctx == nil {
		return zero[pathalg.RemotePath](), ports.ErrNilContext
	}
	if !p.IsValid() {
		return zero[pathalg.RemotePath](), ports.ErrInvalidArgument
	}
	return p, nil
}
func (r *memRemoteFS) Stat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	if ctx == nil {
		return zero[ports.RemoteFileStat](), ports.ErrNilContext
	}
	if !p.IsValid() {
		return zero[ports.RemoteFileStat](), ports.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.files[p.String()]; ok {
		anc, err := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 1, f.ino)
		if err != nil {
			return zero[ports.RemoteFileStat](), err
		}
		return ports.NewRemoteFileStat(ports.RemoteFileStatSpec{
			Path: p, Size: int64(len(f.data)), Mode: f.mode, ModTime: tck.BaseTime(), Anchor: anc,
		})
	}
	return zero[ports.RemoteFileStat](), ports.ErrNotFound
}
func (r *memRemoteFS) Lstat(ctx context.Context, p pathalg.RemotePath) (ports.RemoteFileStat, error) {
	return r.Stat(ctx, p)
}
func (r *memRemoteFS) ReadLink(context.Context, pathalg.RemotePath) (string, error) {
	return "", ports.ErrNotFound
}
func (r *memRemoteFS) ReadDir(ctx context.Context, dir pathalg.RemotePath) ([]ports.RemoteDirEntry, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	prefix := strings.TrimRight(dir.String(), "/") + "/"
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ports.RemoteDirEntry
	for k, f := range r.files {
		if rest, ok := strings.CutPrefix(k, prefix); ok && !strings.Contains(rest, "/") {
			nm, err := pathalg.ParseRemoteName(rest)
			if err != nil {
				return nil, err
			}
			e, err := ports.NewRemoteDirEntry(ports.RemoteDirEntrySpec{
				Name: nm, FileType: ports.RemoteFileRegular, Size: int64(len(f.data)), Mode: f.mode, ModTime: tck.BaseTime(),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	return out, nil
}
func (r *memRemoteFS) WithReadFile(ctx context.Context, p pathalg.RemotePath, lim ports.ReadLimits, fn func(io.Reader, int64) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !p.IsValid() || !lim.IsValid() {
		return ports.ErrInvalidArgument
	}
	r.mu.Lock()
	f, ok := r.files[p.String()]
	r.mu.Unlock()
	if !ok {
		return ports.ErrNotFound
	}
	if int64(len(f.data)) > lim.MaxBytes() {
		return ports.ErrLimitExceeded
	}
	return fn(bytes.NewReader(f.data), int64(len(f.data)))
}
func (r *memRemoteFS) WriteFileAtomic(ctx context.Context, p pathalg.RemotePath, spec ports.RemoteWriteSpec, src io.Reader) (ports.RemoteFileStat, error) {
	if ctx == nil {
		return zero[ports.RemoteFileStat](), ports.ErrNilContext
	}
	if !p.IsValid() || !spec.IsValid() || src == nil {
		return zero[ports.RemoteFileStat](), ports.ErrInvalidArgument
	}
	payload, err := io.ReadAll(src)
	if err != nil {
		return zero[ports.RemoteFileStat](), err
	}
	r.mu.Lock()
	existing, exists := r.files[p.String()]
	if err := checkRemoteWritePrecondition(spec, existing, exists); err != nil {
		r.mu.Unlock()
		return zero[ports.RemoteFileStat](), err
	}
	r.nextIno++
	r.files[p.String()] = memRemoteFile{data: payload, mode: spec.Perm(), ino: r.nextIno}
	r.mu.Unlock()
	return r.Stat(ctx, p)
}
func checkRemoteWritePrecondition(spec ports.RemoteWriteSpec, existing memRemoteFile, exists bool) error {
	if spec.NoClobber() && exists {
		return ports.ErrAlreadyExists
	}
	if want, ok := spec.ExpectedAnchor().Get(); ok {
		if !exists {
			return ports.ErrRemoteAnchorMismatch
		}
		obs, err := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 1, existing.ino)
		if err != nil || !want.Matches(obs) {
			return ports.ErrRemoteAnchorMismatch
		}
	}
	return nil
}
func (r *memRemoteFS) WriteChunk(ctx context.Context, p pathalg.RemotePath, offset int64, src io.Reader, length int64) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !p.IsValid() || offset < 0 || length < 0 || src == nil {
		return ports.ErrInvalidArgument
	}
	chunk := make([]byte, length)
	if _, err := io.ReadFull(src, chunk); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.files[p.String()]
	need := int(offset + length)
	if len(f.data) < need {
		grown := make([]byte, need)
		copy(grown, f.data)
		f.data = grown
	}
	copy(f.data[offset:], chunk)
	if f.ino == 0 {
		r.nextIno++
		f.ino, f.mode = r.nextIno, 0o600
	}
	r.files[p.String()] = f
	return nil
}
func (r *memRemoteFS) RenameAtomic(ctx context.Context, oldP, newP pathalg.RemotePath, expected algebraic.Option[ports.RemoteFileAnchor]) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.files[oldP.String()]
	if !ok {
		return ports.ErrNotFound
	}
	if want, hasWant := expected.Get(); hasWant {
		existing, exists := r.files[newP.String()]
		if !exists {
			return ports.ErrRemoteAnchorMismatch
		}
		obs, err := ports.NewRemoteFileAnchor(ports.RemoteFileRegular, true, 1, existing.ino)
		if err != nil || !want.Matches(obs) {
			return ports.ErrRemoteAnchorMismatch
		}
	}
	r.files[newP.String()] = f
	delete(r.files, oldP.String())
	return nil
}
func (r *memRemoteFS) MkdirAll(ctx context.Context, dir pathalg.RemotePath, _ fs.FileMode) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dirs[dir.String()] = true
	return nil
}
func (r *memRemoteFS) Remove(ctx context.Context, p pathalg.RemotePath) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.files[p.String()]; !ok {
		return ports.ErrNotFound
	}
	delete(r.files, p.String())
	return nil
}
func (r *memRemoteFS) Close() error { return nil }

type memAuditSystem struct {
	mu       sync.Mutex
	procID   ports.ProcessInstanceID
	live     bool
	staged   map[security.OperationID]bool
	deadOps  []security.OperationID
	entries  []ports.AuditEntry
	deadLock bool
}

func newMemAuditSystem(t *testing.T) *memAuditSystem {
	t.Helper()
	pid, err := ports.NewProcessInstanceIDFrom(tck.NewDeterministicEntropy(41))
	if err != nil {
		t.Fatal(err)
	}
	return &memAuditSystem{procID: pid, live: true, staged: make(map[security.OperationID]bool)}
}

func (a *memAuditSystem) ProcessInstanceID() ports.ProcessInstanceID { return a.procID }
func (a *memAuditSystem) StageOperation(ctx context.Context, opID security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !opID.IsValid() {
		return ports.ErrInvalidArgument
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.live {
		return ports.ErrClosed
	}
	a.staged[opID] = true
	return nil
}
func (a *memAuditSystem) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !opID.IsValid() {
		return ports.ErrInvalidArgument
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.live {
		return ports.ErrClosed
	}
	delete(a.staged, opID)
	return nil
}
func (a *memAuditSystem) Record(ctx context.Context, entry ports.AuditEntry) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !entry.IsValid() {
		return ports.ErrInvalidAuditEntry
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.live {
		return ports.ErrClosed
	}
	a.entries = append(a.entries, entry)
	return nil
}
func (a *memAuditSystem) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.live = false
	clear(a.staged)
	return nil
}
func (a *memAuditSystem) ReconcileCrashedAudits(ctx context.Context, now time.Time) (ports.CrashReconcileReport, error) {
	if ctx == nil {
		return zero[ports.CrashReconcileReport](), ports.ErrNilContext
	}
	if now.IsZero() {
		return zero[ports.CrashReconcileReport](), ports.ErrInvalidArgument
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	scanned, liveSkipped, deadClaimed := 0, 0, 0
	if a.live {
		scanned, liveSkipped = 1, 1
	}
	var aborted []security.OperationID
	if a.deadLock {
		scanned++
		deadClaimed = 1
		aborted = slices.Clone(a.deadOps)
		a.deadLock, a.deadOps = false, nil
	}
	return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks: scanned, LiveLocksSkipped: liveSkipped, DeadLocksClaimed: deadClaimed, AbortedOperations: aborted,
	})
}

// simClockStub 是纯内存确定性虚拟时钟桩，用于自测 RunClockSuite 在 fx.Advance != nil 下的无死锁同步推进契约。
type simClockStub struct {
	mu     sync.Mutex
	now    time.Time
	timers []*simTimerStub
}

type simTimerStub struct {
	clk    *simClockStub
	ch     chan time.Time
	fireAt time.Time
	active bool
}

func newSimClockStub() *simClockStub {
	return &simClockStub{now: tck.BaseTime()}
}

func (c *simClockStub) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *simClockStub) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}

func (c *simClockStub) NewTimer(d time.Duration) ports.Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	tm := &simTimerStub{clk: c, ch: make(chan time.Time, 1), fireAt: c.now.Add(d), active: true}
	if d <= 0 {
		tm.active = false
		tm.ch <- c.now
	}
	c.timers = append(c.timers, tm)
	return tm
}

func (c *simClockStub) Sleep(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tm := c.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C():
		return nil
	}
}

func (c *simClockStub) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, tm := range c.timers {
		if tm.active && !c.now.Before(tm.fireAt) {
			tm.active = false
			select {
			case tm.ch <- c.now:
			default:
			}
		}
	}
}

func (t *simTimerStub) C() <-chan time.Time { return t.ch }
func (t *simTimerStub) Stop() bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	was := t.active
	t.active = false
	return was
}
func (t *simTimerStub) Reset(d time.Duration) bool {
	t.clk.mu.Lock()
	defer t.clk.mu.Unlock()
	was := t.active
	select {
	case <-t.ch:
	default:
	}
	t.fireAt = t.clk.now.Add(d)
	if d <= 0 {
		t.active = false
		t.ch <- t.clk.now
	} else {
		t.active = true
	}
	return was
}

type realClockStub struct{}
type realTimerStub struct{ t *time.Timer }

func (t realTimerStub) C() <-chan time.Time        { return t.t.C }
func (t realTimerStub) Stop() bool                 { return t.t.Stop() }
func (t realTimerStub) Reset(d time.Duration) bool { return t.t.Reset(d) }
func (realClockStub) Now() time.Time               { return time.Now().UTC() }
func (realClockStub) Since(t time.Time) time.Duration {
	return time.Since(t)
}
func (realClockStub) NewTimer(d time.Duration) ports.Timer { return realTimerStub{t: time.NewTimer(d)} }
func (realClockStub) Sleep(ctx context.Context, d time.Duration) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

type memEchoConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *memEchoConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Read(p)
}
func (c *memEchoConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *memEchoConn) Close() error                     { return nil }
func (c *memEchoConn) LocalAddr() net.Addr              { return memAddr("mem-local") }
func (c *memEchoConn) RemoteAddr() net.Addr             { return memAddr("mem-remote") }
func (c *memEchoConn) SetDeadline(time.Time) error      { return nil }
func (c *memEchoConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memEchoConn) SetWriteDeadline(time.Time) error { return nil }

type memProcessPort struct{}

func (memProcessPort) Run(ctx context.Context, spec ports.ProcessSpec, stdin io.Reader) (ports.ProcessResult, error) {
	if ctx == nil {
		return zero[ports.ProcessResult](), ports.ErrNilContext
	}
	if !spec.IsValid() {
		return zero[ports.ProcessResult](), ports.ErrInvalidArgument
	}
	if spec.Command() == "false" {
		return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(1)})
	}
	var out []byte
	if stdin != nil {
		var err error
		out, err = io.ReadAll(stdin)
		if err != nil {
			return zero[ports.ProcessResult](), err
		}
	}
	return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(0), Stdout: out})
}
func (memProcessPort) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if !spec.IsValid() {
		return nil, ports.ErrInvalidArgument
	}
	return &memEchoConn{}, nil
}

type memTerminalHandle struct {
	buf    bytes.Buffer
	size   ports.TerminalSize
	resize chan ports.TerminalSize
}

func (h *memTerminalHandle) Read(p []byte) (int, error)              { return h.buf.Read(p) }
func (h *memTerminalHandle) Write(p []byte) (int, error)             { return h.buf.Write(p) }
func (h *memTerminalHandle) Size() (ports.TerminalSize, error)       { return h.size, nil }
func (h *memTerminalHandle) ResizeEvents() <-chan ports.TerminalSize { return h.resize }

type memTerminalPort struct{ size ports.TerminalSize }

func (p memTerminalPort) IsInteractive() bool               { return true }
func (p memTerminalPort) Size() (ports.TerminalSize, error) { return p.size, nil }
func (p memTerminalPort) CanSuspendProcessGroup() (security.Verdict, error) {
	return security.VerdictAllow, nil
}
func (p memTerminalPort) WithRawTerminal(ctx context.Context, fn func(ports.TerminalHandle) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	h := &memTerminalHandle{size: p.size, resize: make(chan ports.TerminalSize)}
	defer close(h.resize)
	return fn(h)
}

type memInteractionPort struct {
	secretText string
	replyText  string
}

func (m memInteractionPort) CanInteract() bool { return true }
func (m memInteractionPort) Confirm(ctx context.Context, req ports.ConfirmRequest) (security.Verdict, error) {
	if ctx == nil {
		return security.VerdictDeny, ports.ErrNilContext
	}
	if !req.IsValid() {
		return security.VerdictDeny, ports.ErrInvalidArgument
	}
	return security.VerdictAllow, nil
}
func (m memInteractionPort) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	if ctx == nil {
		return zero[ports.ApprovalDecisionResponse](), ports.ErrNilContext
	}
	if !env.IsValid() {
		return zero[ports.ApprovalDecisionResponse](), ports.ErrInvalidArgument
	}
	dig, err := env.Digest()
	if err != nil {
		return zero[ports.ApprovalDecisionResponse](), err
	}
	return ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "approved")
}
func (m memInteractionPort) PromptText(ctx context.Context, req ports.TextPromptRequest) (string, error) {
	if ctx == nil {
		return "", ports.ErrNilContext
	}
	if !req.IsValid() {
		return "", ports.ErrInvalidArgument
	}
	return m.replyText, nil
}
func (m memInteractionPort) PromptSecret(ctx context.Context, req ports.SecretPromptRequest, fn func(box *secret.SecretBox) error) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fn == nil {
		return ports.ErrNilCallback
	}
	if !req.IsValid() {
		return ports.ErrInvalidArgument
	}
	return secret.WithBytes([]byte(m.secretText), func(box *secret.SecretBox) error {
		return fn(box)
	})
}

func TestTCKTransportAuditAndSystemSuites(t *testing.T) {
	tck.RunDialerSuite(t, tck.DialerFixture{
		NewDialer:     func(*testing.T) ports.DialerPort { return memDialer{} },
		CheckMultiHop: true,
		CheckRemoteFS: true,
	})

	dir, err := pathalg.ParseLocalDir("/tmp/xops-tck-mux")
	if err != nil {
		t.Fatal(err)
	}
	sockName, err := pathalg.ParseLocalRootedDest("ctl.sock")
	if err != nil {
		t.Fatal(err)
	}
	existingSock, err := pathalg.ParseLocalSourcePath("/tmp/xops-tck-mux/ctl.sock")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunMuxSocketSuite(t, tck.MuxSocketFixture{
		NewMux: func(*testing.T) (ports.MuxSocketPort, pathalg.LocalDir, pathalg.LocalRootedDest) {
			return memMuxSocket{}, dir, sockName
		},
		ExistingSocket: algebraic.Some(existingSock),
	})

	workDir, err := pathalg.ParseRemotePath("/var/tmp/tck")
	if err != nil {
		t.Fatal(err)
	}
	tck.RunRemoteFSSuite(t, tck.RemoteFSFixture{
		NewRemoteFS:       func(*testing.T) (ports.RemoteFSPort, pathalg.RemotePath) { return newMemRemoteFS(), workDir },
		CheckDevInoAnchor: true,
	})

	var sharedAudit *memAuditSystem
	tck.RunAuditSuite(t, tck.AuditFixture{
		NewAudit: func(t *testing.T) (ports.AuditSink, ports.AuditReconciler) {
			sharedAudit = newMemAuditSystem(t)
			return sharedAudit, sharedAudit
		},
		SimulateCrash: func(t *testing.T) security.OperationID {
			opID, oErr := security.NewOperationIDFrom(tck.NewDeterministicEntropy(99))
			if oErr != nil {
				t.Fatal(oErr)
			}
			sharedAudit.mu.Lock()
			sharedAudit.deadLock = true
			sharedAudit.deadOps = []security.OperationID{opID}
			sharedAudit.mu.Unlock()
			return opID
		},
	})

	tck.RunClockSuite(t, tck.ClockFixture{
		NewClock:      func(*testing.T) ports.Clock { return realClockStub{} },
		SleepDuration: 5 * time.Millisecond,
	})
	var activeSimClk *simClockStub
	tck.RunClockSuite(t, tck.ClockFixture{
		NewClock: func(*testing.T) ports.Clock {
			activeSimClk = newSimClockStub()
			return activeSimClk
		},
		Advance:       func(d time.Duration) { activeSimClk.Advance(d) },
		SleepDuration: 50 * time.Millisecond,
	})
	tck.RunEntropySuite(t, func(*testing.T) ports.Entropy { return tck.NewDeterministicEntropy(13) })

	echoSpec, err := ports.NewProcessSpec(ports.ProcessSpecInput{Command: "cat"})
	if err != nil {
		t.Fatal(err)
	}
	failSpec, err := ports.NewProcessSpec(ports.ProcessSpecInput{Command: "false"})
	if err != nil {
		t.Fatal(err)
	}
	tck.RunProcessSuite(t, tck.ProcessFixture{
		NewProcess:    func(*testing.T) ports.ProcessPort { return memProcessPort{} },
		EchoSpec:      echoSpec,
		FailSpec:      failSpec,
		DialStdioSpec: echoSpec,
	})

	ttySize, err := ports.NewTerminalSize(120, 40)
	if err != nil {
		t.Fatal(err)
	}
	tck.RunTerminalSuite(t, tck.TerminalFixture{
		NewTerminal:       func(*testing.T) ports.TerminalPort { return memTerminalPort{size: ttySize} },
		ExpectInteractive: true,
	})

	tck.RunInteractionSuite(t, tck.InteractionFixture{
		NewInteraction: func(*testing.T) ports.InteractionPort {
			return memInteractionPort{secretText: tck.TestSecretTokenA, replyText: "prod-east"}
		},
		ExpectedSecret: tck.TestSecretTokenA,
		ExpectedText:   "prod-east",
	})
}
