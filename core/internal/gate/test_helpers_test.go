package gate

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

func baseTestTime() time.Time {
	return time.Date(2026, time.May, 15, 10, 0, 0, 0, time.UTC)
}

// fakeClock 提供并发安全的确定性测试时钟（零 time.Sleep / 零 time.Now）。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start.UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t.UTC()
	c.mu.Unlock()
}

func (c *fakeClock) NewTimer(time.Duration) ports.Timer { return fakeTimer{ch: make(chan time.Time)} }
func (c *fakeClock) Sleep(ctx context.Context, _ time.Duration) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	return ctx.Err()
}

type fakeTimer struct{ ch chan time.Time }

func (t fakeTimer) C() <-chan time.Time      { return t.ch }
func (t fakeTimer) Stop() bool               { return false }
func (t fakeTimer) Reset(time.Duration) bool { return false }

// fakeEntropy 提供并发安全的确定性非零熵源，兼容 ports.Entropy (io.Reader)。
type fakeEntropy struct {
	mu   sync.Mutex
	next byte
	err  error
}

func newFakeEntropy(seed byte) *fakeEntropy {
	if seed == 0 {
		seed = 1
	}
	return &fakeEntropy{next: seed}
}

func (e *fakeEntropy) Read(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.err != nil {
		return 0, e.err
	}
	for i := range p {
		e.next++
		if e.next == 0 {
			e.next = 1
		}
		p[i] = e.next
	}
	return len(p), nil
}

// fakeAuditSink 模拟同步 Fail-Closed 审计写入与只追加 .lock 登记表，支持顺序轨迹记录与故障注入。
type fakeAuditSink struct {
	procID ports.ProcessInstanceID

	mu              sync.Mutex
	closed          bool
	stageErr        error
	unstageErr      error
	authWriteErr    error
	finalWriteErr   error
	deniedWriteErr  error
	finalFailOnCall int // >0 时在第 N 次 Finalized 写入时注入 finalWriteErr
	finalCalls      int
	onRecord        func(entry ports.AuditEntry)

	trace   []string
	staged  map[security.OperationID]bool
	lockLog []string
	entries []ports.AuditEntry
}

func newFakeAuditSink(t *testing.T, procName string) *fakeAuditSink {
	t.Helper()
	pid, err := ports.ParseProcessInstanceID(procName)
	if err != nil {
		t.Fatalf("ParseProcessInstanceID(%q): %v", procName, err)
	}
	return &fakeAuditSink{
		procID: pid,
		staged: make(map[security.OperationID]bool),
	}
}

func (s *fakeAuditSink) ProcessInstanceID() ports.ProcessInstanceID {
	if s == nil {
		return zeroVal[ports.ProcessInstanceID]()
	}
	return s.procID
}

func (s *fakeAuditSink) StageOperation(ctx context.Context, opID security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !opID.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ports.ErrClosed
	}
	s.trace = append(s.trace, "stage:"+opID.String())
	if s.stageErr != nil {
		return s.stageErr
	}
	s.staged[opID] = true
	s.lockLog = append(s.lockLog, "+"+opID.String())
	return nil
}

func (s *fakeAuditSink) UnstageOperation(ctx context.Context, opID security.OperationID) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !opID.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ports.ErrClosed
	}
	s.trace = append(s.trace, "unstage:"+opID.String())
	if s.unstageErr != nil {
		return s.unstageErr
	}
	delete(s.staged, opID)
	s.lockLog = append(s.lockLog, "-"+opID.String())
	return nil
}

func (s *fakeAuditSink) Record(ctx context.Context, entry ports.AuditEntry) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if !entry.IsValid() {
		return ports.ErrInvalidAuditEntry
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ports.ErrClosed
	}
	s.trace = append(s.trace, "record:"+entry.Phase().String()+":"+entry.OperationID().String())
	err := s.injectedRecordErrLocked(entry)
	hook := s.onRecord
	if err == nil {
		s.entries = append(s.entries, entry)
	}
	s.mu.Unlock()

	if hook != nil {
		hook(entry)
	}
	return err
}

func (s *fakeAuditSink) injectedRecordErrLocked(entry ports.AuditEntry) error {
	switch entry.Phase() {
	case ports.AuditPhaseAuthorized:
		return s.authWriteErr
	case ports.AuditPhaseDenied:
		return s.deniedWriteErr
	case ports.AuditPhaseFinalized:
		s.finalCalls++
		if s.finalWriteErr != nil && (s.finalFailOnCall == 0 || s.finalCalls == s.finalFailOnCall) {
			return s.finalWriteErr
		}
	}
	return nil
}

func (s *fakeAuditSink) Close() error {
	s.mu.Lock()
	s.closed = true
	clear(s.staged)
	s.mu.Unlock()
	return nil
}

func (s *fakeAuditSink) recordEvent(tag string) {
	s.mu.Lock()
	s.trace = append(s.trace, tag)
	s.mu.Unlock()
}

func (s *fakeAuditSink) snapshotTrace() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.trace)
}

func (s *fakeAuditSink) snapshotEntries() []ports.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

func (s *fakeAuditSink) stagedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.staged)
}

func (s *fakeAuditSink) orphanOpIDs() []security.OperationID {
	s.mu.Lock()
	defer s.mu.Unlock()
	authOps := make(map[security.OperationID]bool)
	for _, e := range s.entries {
		switch e.Phase() {
		case ports.AuditPhaseAuthorized:
			authOps[e.OperationID()] = true
		case ports.AuditPhaseFinalized:
			delete(authOps, e.OperationID())
		}
	}
	out := make([]security.OperationID, 0, len(authOps))
	for opID := range authOps {
		out = append(out, opID)
	}
	return out
}

// fakeReconciler 模拟启动期 O(1) 快路径与慢路径崩溃对账端口。
type fakeReconciler struct {
	mu             sync.Mutex
	scannedLocks   int
	liveLocks      int
	deadLocks      int
	crashedOps     []security.OperationID
	auditScanCount int
	err            error
	returnInvalid  bool
}

func (r *fakeReconciler) ReconcileCrashedAudits(ctx context.Context, now time.Time) (ports.CrashReconcileReport, error) {
	zRep := zeroVal[ports.CrashReconcileReport]()
	if ctx == nil {
		return zRep, ports.ErrNilContext
	}
	if !isValidRFC3339Time(now) {
		return zRep, ports.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return zRep, r.err
	}
	if r.returnInvalid {
		return zRep, nil
	}
	if r.deadLocks == 0 && len(r.crashedOps) == 0 {
		return ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
			ScannedLocks:     r.scannedLocks,
			LiveLocksSkipped: r.liveLocks,
		})
	}
	// 仅在发现死亡锁时进入慢路径扫描 audit.jsonl，并幂等清零遗留状态。
	r.auditScanCount++
	rep, err := ports.NewCrashReconcileReport(ports.CrashReconcileReportSpec{
		ScannedLocks:      r.scannedLocks,
		LiveLocksSkipped:  r.liveLocks,
		DeadLocksClaimed:  r.deadLocks,
		AbortedOperations: r.crashedOps,
	})
	if err != nil {
		return zRep, err
	}
	r.deadLocks = 0
	r.crashedOps = nil
	return rep, nil
}

// fakeInteraction 模拟人工审批交互端口。
type fakeInteraction struct {
	canInteract bool
	promptFn    func(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error)
}

func (f *fakeInteraction) CanInteract() bool { return f != nil && f.canInteract }
func (f *fakeInteraction) Confirm(context.Context, ports.ConfirmRequest) (security.Verdict, error) {
	return security.VerdictDeny, ports.ErrInteractionUnavailable
}
func (f *fakeInteraction) PromptApproval(ctx context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
	if f == nil || !f.canInteract || f.promptFn == nil {
		return zeroVal[ports.ApprovalDecisionResponse](), ports.ErrInteractionUnavailable
	}
	return f.promptFn(ctx, env)
}
func (f *fakeInteraction) PromptText(context.Context, ports.TextPromptRequest) (string, error) {
	return "", ports.ErrInteractionUnavailable
}

// PromptSecret 满足 ports.InteractionPort 接口（测试桩不消费机密）。
//
//xops:syncclosure
//xops:borrowed
func (f *fakeInteraction) PromptSecret(context.Context, ports.SecretPromptRequest, func(*secret.SecretBox) error) error {
	return ports.ErrInteractionUnavailable
}

func mustEndpoint(t *testing.T, host string, port uint16) netaddr.Endpoint {
	t.Helper()
	ch, err := netaddr.ParseCanonicalHost(host)
	if err != nil {
		t.Fatalf("ParseCanonicalHost(%q): %v", host, err)
	}
	ep, err := netaddr.NewEndpoint(ch, port)
	if err != nil {
		t.Fatalf("NewEndpoint(%q,%d): %v", host, port, err)
	}
	return ep
}

func mustBinding(t *testing.T, capKind security.CapabilityKind, tool, action, nodeID string, paths ...string) security.OperationBinding {
	t.Helper()
	b, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability:     capKind,
		Tool:           tool,
		Action:         action,
		NodeID:         nodeID,
		Endpoint:       algebraic.Some(mustEndpoint(t, "198.51.100.20", 22)),
		CanonicalPaths: paths,
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	return b
}

func mustPolicy(t *testing.T, threshold security.RiskLevel, fallback NoElicitFallback, patterns ...string) GuardrailPolicy {
	t.Helper()
	pol, err := NewGuardrailPolicyFromPatterns(threshold, fallback, patterns)
	if err != nil {
		t.Fatalf("NewGuardrailPolicyFromPatterns: %v", err)
	}
	return pol
}

func mustClassifiedPolicy(t *testing.T, threshold security.RiskLevel, fallback NoElicitFallback, rules ...pathalg.ProtectedRule) GuardrailPolicy {
	t.Helper()
	pol, err := NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold: threshold,
		NoElicitFallback:  fallback,
		ProtectedRules:    rules,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	return pol
}

func mustGate(t *testing.T, cfg GateConfig) *Gate {
	t.Helper()
	g, err := NewGate(cfg)
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

func mustSystemBus(t *testing.T) *events.SystemBus {
	t.Helper()
	bus, err := events.NewSystemBus(events.SystemBusConfig{DefaultSubscriberBuffer: 16})
	if err != nil {
		t.Fatalf("NewSystemBus: %v", err)
	}
	return bus
}

// peekSingleActiveHandleFlag 在白盒测试中直接读取 Gate 内部唯一在途句柄的原子吊销哨兵，
// 在完全不让 //xops:borrowed 回调形参 auth 逃逸的前提下验证回调退场后 revoked==true。
func peekSingleActiveHandleFlag(t *testing.T, g *Gate) *atomic.Bool {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.activeHandles) != 1 {
		t.Fatalf("期望活跃句柄数=1，实际=%d", len(g.activeHandles))
	}
	for _, flag := range g.activeHandles {
		return flag
	}
	t.Fatal("未找到活跃句柄")
	return nil
}

func verifyNoGoroutineLeak(t *testing.T) {
	t.Helper()
	goleak.VerifyNone(t)
}

func requireNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s 返回非预期错误: %v", label, err)
	}
}

func requireErrIs(t *testing.T, err, target error, label string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s 期望匹配 %v，实际=%v", label, target, err)
	}
}

func requireTrue(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}

func mustNewRequest[C security.Capability](t *testing.T, spec GateRequestSpec[C]) GateRequest[C] {
	t.Helper()
	req, err := NewGateRequest(spec)
	requireNoErr(t, err, "NewGateRequest")
	return req
}

var errSimulatedENOSPC = errors.New("write audit.jsonl: no space left on device (ENOSPC)")
