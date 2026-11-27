package muxdaemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/engine"
)

const defaultShutdownTimeout = 5 * time.Second

// masterLease / forwardLease / daemonBackend 为包内可测试窄缝，
// 生产路径 100% 直接委托给 *engine.Engine、engine.ControlMasterInfo 与 engine.ForwardInfo。
type (
	masterLease interface {
		SocketPath() string
		ReusedExisting() bool
		MasterPID() uint32
		EffectivePersist() option.ControlPersistSpec
		Done() <-chan struct{}
		Wait(ctx context.Context) error
		Stop(ctx context.Context) error
	}
	forwardLease interface {
		Spec() engine.ForwardSpec
		BoundAddr() string
		Done() <-chan struct{}
		Wait(ctx context.Context) error
		Stop(ctx context.Context) error
	}
	daemonBackend interface {
		StartMaster(ctx context.Context, rc engine.RemoteCall) (masterLease, error)
		StartForward(ctx context.Context, rc engine.RemoteCall, spec engine.ForwardSpec) (forwardLease, error)
	}
)

type engineBackend struct {
	client DaemonClient
}

func (b engineBackend) StartMaster(ctx context.Context, rc engine.RemoteCall) (masterLease, error) {
	info, err := b.client.StartControlMaster(ctx, engine.ControlMasterRequest{RemoteCall: rc})
	if err != nil {
		return nil, err
	}
	return engineMasterLease{client: b.client, info: info}, nil
}

func (b engineBackend) StartForward(ctx context.Context, rc engine.RemoteCall, spec engine.ForwardSpec) (forwardLease, error) {
	info, err := b.client.StartForward(ctx, engine.StartForwardRequest{RemoteCall: rc, Spec: spec})
	if err != nil {
		return nil, err
	}
	return engineForwardLease{client: b.client, info: info}, nil
}

type engineMasterLease struct {
	client DaemonClient
	info   engine.ControlMasterInfo
}

func (l engineMasterLease) SocketPath() string { return l.info.SocketPath().String() }
func (l engineMasterLease) ReusedExisting() bool {
	return l.info.ReusedExisting()
}
func (l engineMasterLease) MasterPID() uint32 { return l.info.MasterPID() }
func (l engineMasterLease) EffectivePersist() option.ControlPersistSpec {
	return l.info.EffectivePersist()
}
func (l engineMasterLease) Done() <-chan struct{}          { return l.info.Done() }
func (l engineMasterLease) Wait(ctx context.Context) error { return l.info.Wait(ctx) }
func (l engineMasterLease) Stop(ctx context.Context) error {
	if l.info.ReusedExisting() {
		return nil
	}
	h, ok := l.info.Handle().Get()
	if !ok || !h.IsValid() {
		return nil
	}
	return l.client.StopControlMaster(ctx, h)
}

type engineForwardLease struct {
	client DaemonClient
	info   engine.ForwardInfo
}

func (l engineForwardLease) Spec() engine.ForwardSpec       { return l.info.Spec() }
func (l engineForwardLease) BoundAddr() string              { return l.info.BoundAddr() }
func (l engineForwardLease) Done() <-chan struct{}          { return l.info.Done() }
func (l engineForwardLease) Wait(ctx context.Context) error { return l.info.Wait(ctx) }
func (l engineForwardLease) Stop(ctx context.Context) error {
	h := l.info.Handle()
	if !h.IsValid() {
		return nil
	}
	return l.client.StopForward(ctx, h)
}

// Run 启动并监督 ControlMaster/ControlPersist 守护进程及其附带转发的完整生命周期：
//  1. 严格校验 ctx 与 Config 并补齐缺失的 ControlMaster/ControlPath 选项；
//  2. 启动 ControlMaster 与全部初始转发（部分失败时立即逆序回滚，绝不泄漏资源）；
//  3. 通告就绪状态并在 core/conc.Nursery 监督下响应式等待 ctx 取消、主控退出（含有限 ControlPersist 空闲回收）或转发异常；
//  4. 按「已启动转发（逆序）-> 自建 ControlMaster」执行有限超时确定性清理并聚合全部清理错误。
func Run(ctx context.Context, cfg Config) error {
	if cfg.Client == nil {
		if ctx == nil {
			return ErrNilContext
		}
		return fmt.Errorf("%w: Client 不能为 nil", ErrInvalidConfig)
	}
	return runWithBackend(ctx, cfg, engineBackend{client: cfg.Client})
}

func runWithBackend(ctx context.Context, cfg Config, backend daemonBackend) (retErr error) {
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("%w: backend 不能为 nil", ErrInvalidConfig)
	}
	rc, shutTimeout, err := prepareRemoteCall(cfg)
	if err != nil {
		return err
	}

	master, err := backend.StartMaster(ctx, rc)
	if err != nil {
		return err
	}
	var (
		forwards         []forwardLease
		masterSelfExited bool
	)
	defer func() {
		cleanErr := cleanupResources(ctx, shutTimeout, forwards, master, masterSelfExited)
		retErr = errors.Join(retErr, cleanErr)
	}()

	forwards, err = startForwards(ctx, backend, rc, cfg.Forwards)
	if err != nil {
		return err
	}

	ready := buildReadyInfo(cfg.TargetSpec, master, forwards)
	writeReadyBanner(cfg.Stdout, ready)
	if cfg.OnReady != nil {
		cfg.OnReady(ready)
	}

	var waitErr error
	masterSelfExited, waitErr = waitForTermination(ctx, master, forwards)
	return waitErr
}

func prepareRemoteCall(cfg Config) (engine.RemoteCall, time.Duration, error) {
	targetSpec := strings.TrimSpace(cfg.TargetSpec)
	if targetSpec == "" && !cfg.Target.IsValid() {
		return engine.RemoteCall{}, 0, fmt.Errorf("%w: TargetSpec 与 Target 至少需指定一项", ErrInvalidConfig)
	}
	for i, spec := range cfg.Forwards {
		if !spec.IsValid() {
			return engine.RemoteCall{}, 0, fmt.Errorf("%w: Forwards[%d] 无效", ErrInvalidConfig, i)
		}
	}
	shutTimeout := defaultShutdownTimeout
	if d, ok := cfg.ShutdownTimeout.Get(); ok {
		if !d.IsPositive() {
			return engine.RemoteCall{}, 0, fmt.Errorf("%w: ShutdownTimeout 必须为正时长", ErrInvalidConfig)
		}
		shutTimeout = d.Std()
	}
	opts, err := buildEffectiveCLIOptions(cfg)
	if err != nil {
		return engine.RemoteCall{}, 0, err
	}
	return engine.RemoteCall{
		TargetInput: engine.TargetInput{
			Target:     cfg.Target,
			TargetSpec: targetSpec,
			CLIOptions: opts,
		},
	}, shutTimeout, nil
}

func buildEffectiveCLIOptions(cfg Config) (option.OptionLayer, error) {
	opts := cfg.CLIOptions
	cp := opts.Control()
	if sock, ok := cfg.SocketPath.Get(); ok {
		if !sock.IsValid() {
			return option.UnsetOptionLayer(), fmt.Errorf("%w: SocketPath 无效", ErrInvalidConfig)
		}
		if cp.Path().IsUnset() {
			parsedPath, err := option.ParseControlPath(sock.String())
			if err != nil {
				return option.UnsetOptionLayer(), fmt.Errorf("%w: ControlPath 非法: %w", ErrInvalidConfig, err)
			}
			cp = cp.WithPath(parsedPath)
		}
	}
	if !cp.Master().IsSet() {
		cp = cp.WithMaster(option.ControlMasterYes)
	}
	opts = opts.WithControlPolicy(cp)
	if err := opts.Validate(); err != nil {
		return option.UnsetOptionLayer(), fmt.Errorf("%w: CLIOptions 校验失败: %w", ErrInvalidConfig, err)
	}
	return opts, nil
}

func startForwards(ctx context.Context, backend daemonBackend, rc engine.RemoteCall, specs []engine.ForwardSpec) ([]forwardLease, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	started := make([]forwardLease, 0, len(specs))
	for _, spec := range specs {
		fwd, err := backend.StartForward(ctx, rc, spec)
		if err != nil {
			return started, err
		}
		started = append(started, fwd)
	}
	return started, nil
}

type exitState struct {
	mu             sync.Mutex
	firstErr       error
	masterDoneSeen bool
}

func (s *exitState) record(isMaster bool, err error) {
	s.mu.Lock()
	if isMaster {
		s.masterDoneSeen = true
	}
	if s.firstErr == nil && err != nil {
		s.firstErr = err
	}
	s.mu.Unlock()
}

func (s *exitState) snapshot() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.masterDoneSeen, s.firstErr
}

func waitForTermination(ctx context.Context, master masterLease, forwards []forwardLease) (bool, error) {
	// 复用外部既有 ControlMaster 且没有受管转发时，无需常驻阻塞。
	if master.ReusedExisting() && len(forwards) == 0 {
		return false, nil
	}
	var st exitState
	scopeErr := conc.RunScoped(ctx, func(sCtx context.Context, n *conc.Nursery) error {
		watchCtx, cancelWatch := context.WithCancel(sCtx)
		defer cancelWatch()
		if err := spawnSessionWatchers(n, watchCtx, cancelWatch, master, forwards, &st); err != nil {
			return err
		}
		<-watchCtx.Done()
		return nil
	})
	if scopeErr != nil && ctx.Err() == nil {
		st.record(false, scopeErr)
	}
	return st.snapshot()
}

func spawnSessionWatchers(
	n *conc.Nursery,
	watchCtx context.Context,
	cancelWatch context.CancelFunc,
	master masterLease,
	forwards []forwardLease,
	st *exitState,
) error {
	if !master.ReusedExisting() {
		if err := spawnMasterWatcher(n, watchCtx, master, func(err error) {
			st.record(true, err)
			cancelWatch()
		}); err != nil {
			return err
		}
	}
	for _, fwd := range forwards {
		if err := spawnForwardWatcher(n, watchCtx, fwd, func(err error) {
			st.record(false, err)
			cancelWatch()
		}); err != nil {
			return err
		}
	}
	return nil
}

func spawnMasterWatcher(n *conc.Nursery, watchCtx context.Context, master masterLease, onExit func(error)) error {
	done := master.Done()
	if done == nil {
		return fmt.Errorf("%w: ControlMasterInfo.Done() 返回 nil", ErrInvalidConfig)
	}
	return n.Go(func(wCtx context.Context) error {
		select {
		case <-done:
			onExit(master.Wait(context.WithoutCancel(wCtx)))
		case <-watchCtx.Done():
		case <-wCtx.Done():
		}
		return nil
	})
}

func spawnForwardWatcher(n *conc.Nursery, watchCtx context.Context, fwd forwardLease, onExit func(error)) error {
	done := fwd.Done()
	if done == nil {
		return fmt.Errorf("%w: ForwardInfo.Done() 返回 nil", ErrInvalidConfig)
	}
	return n.Go(func(wCtx context.Context) error {
		select {
		case <-done:
			onExit(fwd.Wait(context.WithoutCancel(wCtx)))
		case <-watchCtx.Done():
		case <-wCtx.Done():
		}
		return nil
	})
}

func cleanupResources(ctx context.Context, timeout time.Duration, forwards []forwardLease, master masterLease, masterSelfExited bool) error {
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	var errs []error
	// 严格逆序关闭：先停止所有已启动的转发，再停止自建 ControlMaster（若 ReusedExisting 则永不停止外部主控）。
	for i := len(forwards) - 1; i >= 0; i-- {
		fwd := forwards[i]
		if fwd == nil {
			continue
		}
		fwdDone := isChanClosed(fwd.Done())
		if err := fwd.Stop(shutCtx); err != nil && !isIgnorableSelfExitStopErr(fwdDone, err) {
			errs = append(errs, fmt.Errorf("stop forward %s failed: %w", fwd.BoundAddr(), err))
		}
	}
	if master != nil && !master.ReusedExisting() {
		alreadyDone := masterSelfExited || isChanClosed(master.Done())
		if err := master.Stop(shutCtx); err != nil && !isIgnorableSelfExitStopErr(alreadyDone, err) {
			errs = append(errs, fmt.Errorf("stop control master %s failed: %w", master.SocketPath(), err))
		}
	}
	return errors.Join(errs...)
}

func isChanClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func isIgnorableSelfExitStopErr(alreadyExited bool, err error) bool {
	if !alreadyExited {
		return false
	}
	return errors.Is(err, engine.ErrHandleNotFound) || errors.Is(err, engine.ErrHandleRevoked)
}

func buildReadyInfo(targetSpec string, master masterLease, forwards []forwardLease) ReadyInfo {
	outFwds := make([]ReadyForward, 0, len(forwards))
	for _, f := range forwards {
		outFwds = append(outFwds, ReadyForward{
			Spec:      f.Spec(),
			BoundAddr: f.BoundAddr(),
		})
	}
	return ReadyInfo{
		TargetSpec:       strings.TrimSpace(targetSpec),
		SocketPath:       master.SocketPath(),
		ReusedExisting:   master.ReusedExisting(),
		MasterPID:        master.MasterPID(),
		EffectivePersist: master.EffectivePersist(),
		Forwards:         slices.Clone(outFwds),
	}
}

func writeReadyBanner(stdout io.Writer, info ReadyInfo) {
	if stdout == nil {
		return
	}
	mode := "master"
	if info.ReusedExisting {
		mode = "reused"
	}
	_, _ = fmt.Fprintf(stdout, "mux daemon ready (%s): socket=%s pid=%d persist=%s\n",
		mode, info.SocketPath, info.MasterPID, info.EffectivePersist.String())
	for _, f := range info.Forwards {
		_, _ = fmt.Fprintf(stdout, "  forward %s -> %s\n", f.Spec.Direction(), f.BoundAddr)
	}
}
