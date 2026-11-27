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
	"github.com/wentf9/xops-cli/internal/i18n"
)

const defaultShutdownTimeout = 5 * time.Second

type muxStartPlan struct {
	rc             engine.RemoteCall
	shutTimeout    time.Duration
	skipMaster     bool
	allowFwdOnlyFB bool
}

// Run 启动并监督 ControlMaster/ControlPersist 守护进程（或 `ssh -f -N -L` 纯后台转发）的完整生命周期：
//  1. 严格校验 ctx 与 Config，按显式标志与转发列表判定是否启动 ControlMaster 或退化为纯转发托管；
//  2. 启动 ControlMaster 与全部初始转发（部分失败时立即逆序回滚，绝不泄漏资源）；
//  3. 通告就绪状态并在 core/conc.Nursery 监督下响应式等待 ctx 取消、主控退出（含有限 ControlPersist 空闲回收）或转发异常；
//  4. 按「已启动转发（逆序）-> 自建 ControlMaster」执行有限超时确定性清理并聚合全部清理错误。
func Run(ctx context.Context, cfg Config) error {
	if cfg.Client == nil {
		if ctx == nil {
			return ErrNilContext
		}
		return i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonNilClient)
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
		return i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonNilBackend)
	}
	plan, err := prepareStartPlan(cfg)
	if err != nil {
		return err
	}

	master, err := startOptionalMaster(ctx, backend, plan)
	if err != nil {
		return err
	}
	var (
		forwards         []forwardLease
		masterSelfExited bool
	)
	defer func() {
		cleanErr := cleanupResources(ctx, plan.shutTimeout, forwards, master, masterSelfExited)
		retErr = errors.Join(retErr, cleanErr)
	}()

	forwards, err = startForwards(ctx, backend, plan.rc, cfg.Forwards)
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

func startOptionalMaster(ctx context.Context, backend daemonBackend, plan muxStartPlan) (masterLease, error) {
	if plan.skipMaster {
		return nil, nil
	}
	master, err := backend.StartMaster(ctx, plan.rc)
	if err != nil {
		if plan.allowFwdOnlyFB && errors.Is(err, engine.ErrControlMasterDisabled) {
			return nil, nil
		}
		return nil, err
	}
	return master, nil
}

func prepareStartPlan(cfg Config) (muxStartPlan, error) {
	targetSpec := strings.TrimSpace(cfg.TargetSpec)
	if targetSpec == "" && !cfg.Target.IsValid() {
		return muxStartPlan{}, i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonMissingTarget)
	}
	for i, spec := range cfg.Forwards {
		if !spec.IsValid() {
			return muxStartPlan{}, i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonInvalidForward, i18n.Int("index", i))
		}
	}
	shutTimeout := defaultShutdownTimeout
	if d, ok := cfg.ShutdownTimeout.Get(); ok {
		if !d.IsPositive() {
			return muxStartPlan{}, i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonShutdownTimeoutPositive)
		}
		shutTimeout = d.Std()
	}
	origCtrl := cfg.CLIOptions.Control()
	explicitMaster := origCtrl.Master()
	explicitPath := origCtrl.Path()
	explicitMuxRequested := cfg.SocketPath.IsSome() || (explicitMaster.IsSet() && explicitMaster != option.ControlMasterNo)
	explicitMuxDisabled := explicitMaster == option.ControlMasterNo || explicitPath.IsDisabled()
	hasForwards := len(cfg.Forwards) > 0

	opts, err := buildEffectiveCLIOptions(cfg, hasForwards, explicitMuxDisabled)
	if err != nil {
		return muxStartPlan{}, err
	}
	return muxStartPlan{
		rc: engine.RemoteCall{
			TargetInput: engine.TargetInput{
				Target:     cfg.Target,
				TargetSpec: targetSpec,
				CLIOptions: opts,
			},
		},
		shutTimeout:    shutTimeout,
		skipMaster:     hasForwards && explicitMuxDisabled,
		allowFwdOnlyFB: hasForwards && !explicitMuxRequested,
	}, nil
}

func buildEffectiveCLIOptions(cfg Config, hasForwards, explicitMuxDisabled bool) (option.OptionLayer, error) {
	opts := cfg.CLIOptions
	cp := opts.Control()
	if sock, ok := cfg.SocketPath.Get(); ok {
		if !sock.IsValid() {
			return option.UnsetOptionLayer(), i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonInvalidSocketPath)
		}
		if cp.Path().IsUnset() {
			parsedPath, err := option.ParseControlPath(sock.String())
			if err != nil {
				return option.UnsetOptionLayer(), i18n.WrapS(ErrInvalidConfig, err, i18n.KeyMuxDaemonInvalidControlPath)
			}
			cp = cp.WithPath(parsedPath)
		}
	}
	if !cp.Master().IsSet() && !explicitMuxDisabled && (!hasForwards || cp.Path().IsEnabled()) {
		cp = cp.WithMaster(option.ControlMasterYes)
	}
	opts = opts.WithControlPolicy(cp)
	if err := opts.Validate(); err != nil {
		return option.UnsetOptionLayer(), i18n.WrapS(ErrInvalidConfig, err, i18n.KeyMuxDaemonInvalidCLIOpts)
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
	// 复用外部既有 ControlMaster 且没有受管转发，或既无主控也无转发时，无需常驻阻塞。
	if (master == nil || master.ReusedExisting()) && len(forwards) == 0 {
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
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		st.record(false, ctx.Err())
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
	if master != nil && !master.ReusedExisting() {
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
		return i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonNilDoneChan, i18n.Str("source", "ControlMasterInfo"))
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
		return i18n.EF(ErrInvalidConfig, i18n.KeyMuxDaemonNilDoneChan, i18n.Str("source", "ForwardInfo"))
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
	// 并在 Stop 返回句柄失效错误后二次核验 Done() 通道，消除并发自退出与 SIGINT 间的 TOCTOU 竞态。
	for i := len(forwards) - 1; i >= 0; i-- {
		fwd := forwards[i]
		if fwd == nil {
			continue
		}
		fwdDone := isChanClosed(fwd.Done())
		if err := fwd.Stop(shutCtx); err != nil && !isIgnorableSelfExitStopErr(fwdDone || isChanClosed(fwd.Done()), err) {
			errs = append(errs, i18n.Wrap(err, i18n.KeyMuxDaemonStopForwardFailed, i18n.BoundStr("addr", fwd.BoundAddr())))
		}
	}
	if master != nil && !master.ReusedExisting() {
		alreadyDone := masterSelfExited || isChanClosed(master.Done())
		if err := master.Stop(shutCtx); err != nil && !isIgnorableSelfExitStopErr(alreadyDone || isChanClosed(master.Done()), err) {
			errs = append(errs, i18n.Wrap(err, i18n.KeyMuxDaemonStopMasterFailed, i18n.BoundStr("socket", master.SocketPath())))
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
	info := ReadyInfo{
		TargetSpec: strings.TrimSpace(targetSpec),
		Forwards:   slices.Clone(outFwds),
	}
	if master != nil {
		info.SocketPath = master.SocketPath()
		info.ReusedExisting = master.ReusedExisting()
		info.MasterPID = master.MasterPID()
		info.EffectivePersist = master.EffectivePersist()
	}
	return info
}

func writeReadyBanner(stdout io.Writer, info ReadyInfo) {
	if stdout == nil {
		return
	}
	if info.SocketPath == "" {
		_, _ = fmt.Fprintf(stdout, "mux daemon ready (forwards): count=%d\n", len(info.Forwards))
	} else {
		mode := "master"
		if info.ReusedExisting {
			mode = "reused"
		}
		_, _ = fmt.Fprintf(stdout, "mux daemon ready (%s): socket=%s pid=%d persist=%s\n",
			mode, info.SocketPath, info.MasterPID, info.EffectivePersist.String())
	}
	for _, f := range info.Forwards {
		_, _ = fmt.Fprintf(stdout, "  forward %s -> %s\n", f.Spec.Direction(), f.BoundAddr)
	}
}
