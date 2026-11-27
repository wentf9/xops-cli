package muxdaemon

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
)

type fakeMaster struct {
	socketPath string
	reused     bool
	pid        uint32
	persist    option.ControlPersistSpec
	doneCh     chan struct{}
	closeOnce  sync.Once
	waitErr    error
	stopErr    error
	stopCalls  atomic.Int32
	onStop     func(ctx context.Context)
}

func newFakeMaster(sock string, reused bool, persist option.ControlPersistSpec) *fakeMaster {
	m := &fakeMaster{
		socketPath: sock,
		reused:     reused,
		pid:        4242,
		persist:    persist,
		doneCh:     make(chan struct{}),
	}
	if reused {
		close(m.doneCh)
	}
	return m
}

func (m *fakeMaster) finish(err error) {
	m.closeOnce.Do(func() {
		m.waitErr = err
		close(m.doneCh)
	})
}

func (m *fakeMaster) SocketPath() string                          { return m.socketPath }
func (m *fakeMaster) ReusedExisting() bool                        { return m.reused }
func (m *fakeMaster) MasterPID() uint32                           { return m.pid }
func (m *fakeMaster) EffectivePersist() option.ControlPersistSpec { return m.persist }
func (m *fakeMaster) Done() <-chan struct{}                       { return m.doneCh }
func (m *fakeMaster) Wait(ctx context.Context) error {
	select {
	case <-m.doneCh:
		return m.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (m *fakeMaster) Stop(ctx context.Context) error {
	m.stopCalls.Add(1)
	if m.onStop != nil {
		m.onStop(ctx)
	}
	m.finish(nil)
	return m.stopErr
}

type fakeForward struct {
	spec      engine.ForwardSpec
	boundAddr string
	doneCh    chan struct{}
	closeOnce sync.Once
	waitErr   error
	stopErr   error
	stopCalls atomic.Int32
	onStop    func(ctx context.Context)
}

func newFakeForward(spec engine.ForwardSpec, bound string) *fakeForward {
	return &fakeForward{spec: spec, boundAddr: bound, doneCh: make(chan struct{})}
}

func (f *fakeForward) finish(err error) {
	f.closeOnce.Do(func() {
		f.waitErr = err
		close(f.doneCh)
	})
}

func (f *fakeForward) Spec() engine.ForwardSpec { return f.spec }
func (f *fakeForward) BoundAddr() string        { return f.boundAddr }
func (f *fakeForward) Done() <-chan struct{}    { return f.doneCh }
func (f *fakeForward) Wait(ctx context.Context) error {
	select {
	case <-f.doneCh:
		return f.waitErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *fakeForward) Stop(ctx context.Context) error {
	f.stopCalls.Add(1)
	if f.onStop != nil {
		f.onStop(ctx)
	}
	f.finish(nil)
	return f.stopErr
}

type fakeBackend struct {
	master           *fakeMaster
	masterErr        error
	masterStartCalls atomic.Int32
	forwards         []*fakeForward
	failFwdAt        int
	failFwdErr       error
	startedFwds      atomic.Int32
	seenMasterRC     engine.RemoteCall
}

func (b *fakeBackend) StartMaster(_ context.Context, rc engine.RemoteCall) (masterLease, error) {
	b.masterStartCalls.Add(1)
	b.seenMasterRC = rc
	if b.masterErr != nil {
		return nil, b.masterErr
	}
	return b.master, nil
}

func (b *fakeBackend) StartForward(_ context.Context, _ engine.RemoteCall, _ engine.ForwardSpec) (forwardLease, error) {
	idx := int(b.startedFwds.Add(1)) - 1
	if b.failFwdErr != nil && idx == b.failFwdAt {
		return nil, b.failFwdErr
	}
	return b.forwards[idx], nil
}

func mustLocalFwdSpec(t *testing.T, bind, target string) engine.ForwardSpec {
	t.Helper()
	spec, err := engine.NewForwardSpec(engine.ForwardLocal, bind, target)
	if err != nil {
		t.Fatalf("NewForwardSpec: %v", err)
	}
	return spec
}

func TestRunWithBackend_SignalCancelReverseTeardown(t *testing.T) {
	defer goleak.VerifyNone(t)
	persist, _ := option.ParseControlPersist("60s")
	master := newFakeMaster("/tmp/cm-signal.sock", false, persist)
	spec1 := mustLocalFwdSpec(t, "127.0.0.1:10001", "10.0.0.1:80")
	spec2 := mustLocalFwdSpec(t, "127.0.0.1:10002", "10.0.0.2:443")
	fwd1 := newFakeForward(spec1, "127.0.0.1:10001")
	fwd2 := newFakeForward(spec2, "127.0.0.1:10002")

	var mu sync.Mutex
	var order []string
	var hadCleanDeadline bool
	recordStop := func(name string) func(context.Context) {
		return func(c context.Context) {
			_, dl := c.Deadline()
			mu.Lock()
			order = append(order, name)
			hadCleanDeadline = hadCleanDeadline || (dl && c.Err() == nil)
			mu.Unlock()
		}
	}
	fwd1.onStop = recordStop("fwd1")
	fwd2.onStop = recordStop("fwd2")
	master.onStop = recordStop("master")

	backend := &fakeBackend{master: master, forwards: []*fakeForward{fwd1, fwd2}}
	runCtx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan ReadyInfo, 1)
	var stdout bytes.Buffer
	var runErr error

	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = runWithBackend(runCtx, Config{
				TargetSpec: "deploy@example.internal",
				Forwards:   []engine.ForwardSpec{spec1, spec2},
				Stdout:     &stdout,
				OnReady:    func(info ReadyInfo) { readyCh <- info },
			}, backend)
			return nil
		}); gErr != nil {
			return gErr
		}
		ready := <-readyCh
		if ready.SocketPath != "/tmp/cm-signal.sock" || len(ready.Forwards) != 2 || ready.ReusedExisting {
			cancel()
			return errors.New("unexpected ready snapshot")
		}
		cancel()
		return nil
	})
	if err != nil || runErr != nil {
		t.Fatalf("信号取消期望返回 nil，实际 outer=%v run=%v", err, runErr)
	}
	wantOrder := []string{"fwd2", "fwd1", "master"}
	if !slices.Equal(order, wantOrder) {
		t.Fatalf("停机逆序失配: got=%v want=%v", order, wantOrder)
	}
	if !hadCleanDeadline {
		t.Fatal("停机清理必须使用剥离取消且带超时截止的上下文")
	}
	if !strings.Contains(stdout.String(), "mux daemon ready (master)") {
		t.Fatalf("Stdout 缺少就绪横幅: %q", stdout.String())
	}
}

func TestRunWithBackend_FiniteControlPersistIdleExit(t *testing.T) {
	defer goleak.VerifyNone(t)
	persist, _ := option.ParseControlPersist("5s")
	master := newFakeMaster("/tmp/cm-idle.sock", false, persist)
	// 模拟主控因有限 ControlPersist 空闲到期自退出，同时池句柄已自动释放（Stop 返回 ErrHandleNotFound）。
	master.stopErr = engine.ErrHandleNotFound
	spec1 := mustLocalFwdSpec(t, "127.0.0.1:10011", "10.0.0.1:80")
	fwd1 := newFakeForward(spec1, "127.0.0.1:10011")

	backend := &fakeBackend{master: master, forwards: []*fakeForward{fwd1}}
	readyCh := make(chan struct{})
	var runErr error
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = runWithBackend(context.Background(), Config{
				TargetSpec: "deploy@idle.internal",
				Forwards:   []engine.ForwardSpec{spec1},
				OnReady:    func(ReadyInfo) { close(readyCh) },
			}, backend)
			return nil
		}); gErr != nil {
			return gErr
		}
		<-readyCh
		// 触发主控空闲回收退出（Wait 返回 nil）。
		master.finish(nil)
		return nil
	})
	if err != nil || runErr != nil {
		t.Fatalf("ControlPersist 空闲回收期望干净退出 nil，实际 outer=%v run=%v", err, runErr)
	}
	if fwd1.stopCalls.Load() != 1 {
		t.Fatalf("主控空闲退出后必须关闭托管转发: stopCalls=%d", fwd1.stopCalls.Load())
	}
}

func TestRunWithBackend_ReusedExistingNeverStopsExternalMaster(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 复用外部主控且无本地转发：就绪后直接返回 nil 且永不停止外部主控。
	masterNoFwd := newFakeMaster("/tmp/cm-reused-0.sock", true, option.IndefiniteControlPersist())
	if err := runWithBackend(context.Background(), Config{
		TargetSpec: "deploy@reused.internal",
	}, &fakeBackend{master: masterNoFwd}); err != nil {
		t.Fatalf("复用主控无转发期望 nil，实际=%v", err)
	}
	if masterNoFwd.stopCalls.Load() != 0 {
		t.Fatalf("严禁停止外部既有 ControlMaster: stopCalls=%d", masterNoFwd.stopCalls.Load())
	}

	// 2. 复用外部主控并附带转发：长驻直至取消，仅清理转发，绝不停止外部主控。
	masterWithFwd := newFakeMaster("/tmp/cm-reused-1.sock", true, option.IndefiniteControlPersist())
	spec := mustLocalFwdSpec(t, "127.0.0.1:10021", "10.0.0.5:8080")
	fwd := newFakeForward(spec, "127.0.0.1:10021")
	runCtx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan struct{})
	var runErr error
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = runWithBackend(runCtx, Config{
				TargetSpec: "deploy@reused.internal",
				Forwards:   []engine.ForwardSpec{spec},
				OnReady:    func(ReadyInfo) { close(readyCh) },
			}, &fakeBackend{master: masterWithFwd, forwards: []*fakeForward{fwd}})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-readyCh
		cancel()
		return nil
	})
	if err != nil || runErr != nil {
		t.Fatalf("复用主控+转发取消期望 nil，实际 outer=%v run=%v", err, runErr)
	}
	if fwd.stopCalls.Load() != 1 || masterWithFwd.stopCalls.Load() != 0 {
		t.Fatalf("复用主控场景清理异常: fwdStops=%d masterStops=%d", fwd.stopCalls.Load(), masterWithFwd.stopCalls.Load())
	}
}

func TestRunWithBackend_PartialForwardRollbackAndCleanupErrors(t *testing.T) {
	defer goleak.VerifyNone(t)

	// 1. 第 2 条转发启动失败时，必须回滚第 1 条转发并停止自建主控，同时聚合清理错误。
	master := newFakeMaster("/tmp/cm-rollback.sock", false, option.IndefiniteControlPersist())
	wantStartErr := errors.New("bind port in use")
	wantCleanErr := errors.New("stop master io failed")
	master.stopErr = wantCleanErr
	spec1 := mustLocalFwdSpec(t, "127.0.0.1:10031", "10.0.0.1:80")
	spec2 := mustLocalFwdSpec(t, "127.0.0.1:10032", "10.0.0.2:80")
	fwd1 := newFakeForward(spec1, "127.0.0.1:10031")
	backend := &fakeBackend{
		master:     master,
		forwards:   []*fakeForward{fwd1},
		failFwdAt:  1,
		failFwdErr: wantStartErr,
	}
	err := runWithBackend(context.Background(), Config{
		TargetSpec: "deploy@rollback.internal",
		Forwards:   []engine.ForwardSpec{spec1, spec2},
	}, backend)
	if !errors.Is(err, wantStartErr) || !errors.Is(err, wantCleanErr) {
		t.Fatalf("应同时暴露启动错误与清理错误，实际=%v", err)
	}
	if fwd1.stopCalls.Load() != 1 || master.stopCalls.Load() != 1 {
		t.Fatalf("回滚调用计数异常: fwd1=%d master=%d", fwd1.stopCalls.Load(), master.stopCalls.Load())
	}

	// 2. 运行期间转发异常断连：立即触发全量清理并向调用方透传转发错误。
	master2 := newFakeMaster("/tmp/cm-fwd-drop.sock", false, option.IndefiniteControlPersist())
	fwdDrop := newFakeForward(spec1, "127.0.0.1:10041")
	wantDropErr := errors.New("tunnel upstream reset")
	readyCh := make(chan struct{})
	var runErr2 error
	err = conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr2 = runWithBackend(context.Background(), Config{
				TargetSpec:      "deploy@drop.internal",
				Forwards:        []engine.ForwardSpec{spec1},
				ShutdownTimeout: algebraic.Some(algebraic.FromStdDuration(2 * time.Second)),
				OnReady:         func(ReadyInfo) { close(readyCh) },
			}, &fakeBackend{master: master2, forwards: []*fakeForward{fwdDrop}})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-readyCh
		fwdDrop.finish(wantDropErr)
		return nil
	})
	if err != nil || !errors.Is(runErr2, wantDropErr) {
		t.Fatalf("转发异常断连必须透传原错: outer=%v run=%v", err, runErr2)
	}
	if master2.stopCalls.Load() != 1 {
		t.Fatalf("转发断连后必须停止自建主控: stopCalls=%d", master2.stopCalls.Load())
	}
}

func TestRunWithBackend_PureForwardFallbackAndExplicitMasterContract(t *testing.T) {
	defer goleak.VerifyNone(t)
	spec := mustLocalFwdSpec(t, "127.0.0.1:10051", "10.0.0.9:8080")

	// 1. ControlMaster=no + Forwards：跳过 StartMaster，进入纯转发监督模式并在取消后清理转发。
	assertPureForwardMode(t, "control_master_no", Config{
		TargetSpec: "deploy@fwd.internal",
		CLIOptions: option.UnsetOptionLayer().WithControlPolicy(option.UnsetControlPolicy().WithMaster(option.ControlMasterNo)),
		Forwards:   []engine.ForwardSpec{spec},
	}, 0, nil)

	// 2. ControlPath=none + Forwards：跳过 StartMaster，纯转发监督模式。
	assertPureForwardMode(t, "control_path_none", Config{
		TargetSpec: "deploy@fwd.internal",
		CLIOptions: option.UnsetOptionLayer().WithControlPolicy(option.UnsetControlPolicy().WithPath(option.DisabledControlPath())),
		Forwards:   []engine.ForwardSpec{spec},
	}, 0, nil)

	// 3. 未显式指定 -M/-S 且有 Forwards（典型 `ssh -f -N -L`）：StartMaster 返回 ErrControlMasterDisabled 时平滑降级纯转发。
	assertPureForwardMode(t, "unset_mux_fallback", Config{
		TargetSpec: "deploy@fwd.internal",
		Forwards:   []engine.ForwardSpec{spec},
	}, 1, engine.ErrControlMasterDisabled)

	// 4. 无 Forwards 时 ErrControlMasterDisabled 必须失败关闭（禁止静默退化）。
	if err := runWithBackend(context.Background(), Config{
		TargetSpec: "deploy@nomux.internal",
	}, &fakeBackend{masterErr: engine.ErrControlMasterDisabled}); !errors.Is(err, engine.ErrControlMasterDisabled) {
		t.Fatalf("无转发时 ErrControlMasterDisabled 必须失败关闭，实际=%v", err)
	}

	// 5. 显式要求 ControlMaster=yes 时，即便有 Forwards 也严禁静默降级。
	if err := runWithBackend(context.Background(), Config{
		TargetSpec: "deploy@explicit.internal",
		CLIOptions: option.UnsetOptionLayer().WithControlPolicy(option.UnsetControlPolicy().WithMaster(option.ControlMasterYes)),
		Forwards:   []engine.ForwardSpec{spec},
	}, &fakeBackend{masterErr: engine.ErrControlMasterDisabled}); !errors.Is(err, engine.ErrControlMasterDisabled) {
		t.Fatalf("显式 ControlMaster=yes 遇到 ErrControlMasterDisabled 必须失败关闭，实际=%v", err)
	}
}

func assertPureForwardMode(t *testing.T, name string, cfg Config, wantMasterStarts int32, masterErr error) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		fwd := newFakeForward(cfg.Forwards[0], "127.0.0.1:10051")
		backend := &fakeBackend{masterErr: masterErr, forwards: []*fakeForward{fwd}}
		runCtx, cancel := context.WithCancel(context.Background())
		readyCh := make(chan ReadyInfo, 1)
		var stdout bytes.Buffer
		cfg.Stdout = &stdout
		cfg.OnReady = func(info ReadyInfo) { readyCh <- info }

		var runErr error
		outerErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
			if gErr := n.Go(func(context.Context) error {
				runErr = runWithBackend(runCtx, cfg, backend)
				return nil
			}); gErr != nil {
				return gErr
			}
			ready := <-readyCh
			if ready.SocketPath != "" || len(ready.Forwards) != 1 {
				cancel()
				return errors.New("unexpected pure-forward ready info")
			}
			cancel()
			return nil
		})
		if outerErr != nil || runErr != nil {
			t.Fatalf("%s: 纯转发取消期望 nil，实际 outer=%v run=%v", name, outerErr, runErr)
		}
		if backend.masterStartCalls.Load() != wantMasterStarts || fwd.stopCalls.Load() != 1 {
			t.Fatalf("%s: 调用计数失配 masterStarts=%d want=%d fwdStops=%d",
				name, backend.masterStartCalls.Load(), wantMasterStarts, fwd.stopCalls.Load())
		}
		if !strings.Contains(stdout.String(), "mux daemon ready (forwards)") {
			t.Fatalf("%s: 纯转发横幅失配: %q", name, stdout.String())
		}
	})
}

func TestRunWithBackend_CleanupTOCTOUAndDeadlineExceeded(t *testing.T) {
	defer goleak.VerifyNone(t)
	spec := mustLocalFwdSpec(t, "127.0.0.1:10061", "10.0.0.8:80")

	// 1. TOCTOU 竞态：清理进入 Stop 前 Done() 尚未关闭，Stop 执行期间并发自退出关闭 Done() 并返回 ErrHandleNotFound/Revoked，
	// cleanupResources 二次核验 Done() 后应判定为良性自退出而非虚假清理错误。
	master := newFakeMaster("/tmp/cm-toctou.sock", false, option.IndefiniteControlPersist())
	master.stopErr = engine.ErrHandleRevoked
	fwd := newFakeForward(spec, "127.0.0.1:10061")
	fwd.stopErr = engine.ErrHandleNotFound
	runCtx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan struct{})
	var runErr error
	outerErr := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			runErr = runWithBackend(runCtx, Config{
				TargetSpec: "deploy@toctou.internal",
				Forwards:   []engine.ForwardSpec{spec},
				OnReady:    func(ReadyInfo) { close(readyCh) },
			}, &fakeBackend{master: master, forwards: []*fakeForward{fwd}})
			return nil
		}); gErr != nil {
			return gErr
		}
		<-readyCh
		cancel()
		return nil
	})
	if outerErr != nil || runErr != nil {
		t.Fatalf("并发自退出 TOCTOU 竞态下清理必须返回 nil，实际 outer=%v run=%v", outerErr, runErr)
	}

	// 2. 若资源未关闭（Done() 仍未闭合）而 Stop 返回 ErrHandleNotFound，则不得吞错。
	stuck := &stuckForwardLease{spec: spec, bound: "127.0.0.1:10062", doneCh: make(chan struct{}), stopErr: engine.ErrHandleNotFound}
	if err := cleanupResources(context.Background(), time.Second, []forwardLease{stuck}, nil, false); !errors.Is(err, engine.ErrHandleNotFound) {
		t.Fatalf("未自退出却返回 ErrHandleNotFound 必须失败关闭暴露错误，实际=%v", err)
	}

	// 3. 父上下文因超时终止（DeadlineExceeded）时，runWithBackend 必须透传 context.DeadlineExceeded 并完成全量清理。
	masterDL := newFakeMaster("/tmp/cm-dl.sock", false, option.IndefiniteControlPersist())
	fwdDL := newFakeForward(spec, "127.0.0.1:10063")
	dlCtx, dlCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer dlCancel()
	dlErr := runWithBackend(dlCtx, Config{
		TargetSpec: "deploy@deadline.internal",
		Forwards:   []engine.ForwardSpec{spec},
	}, &fakeBackend{master: masterDL, forwards: []*fakeForward{fwdDL}})
	if !errors.Is(dlErr, context.DeadlineExceeded) {
		t.Fatalf("超时截止必须透传 context.DeadlineExceeded，实际=%v", dlErr)
	}
	if fwdDL.stopCalls.Load() != 1 || masterDL.stopCalls.Load() != 1 {
		t.Fatalf("超时退出后必须完成资源清理: fwd=%d master=%d", fwdDL.stopCalls.Load(), masterDL.stopCalls.Load())
	}
}

type stuckForwardLease struct {
	spec    engine.ForwardSpec
	bound   string
	doneCh  chan struct{}
	stopErr error
}

func (s *stuckForwardLease) Spec() engine.ForwardSpec   { return s.spec }
func (s *stuckForwardLease) BoundAddr() string          { return s.bound }
func (s *stuckForwardLease) Done() <-chan struct{}      { return s.doneCh }
func (s *stuckForwardLease) Wait(context.Context) error { return nil }
func (s *stuckForwardLease) Stop(context.Context) error { return s.stopErr }
