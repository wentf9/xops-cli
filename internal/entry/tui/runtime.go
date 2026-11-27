package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/conc"
)

// terminalGuard 保证宿主终端接管/释放/恢复钩子在正常退出、Ctrl+C、ctx 取消或错误路径下严格有序且幂等执行。
type terminalGuard struct {
	hooks    TerminalHooks
	mu       sync.Mutex
	entered  bool
	restored bool
}

func (g *terminalGuard) enter() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entered {
		return nil
	}
	if g.hooks.OnEnter != nil {
		if err := g.hooks.OnEnter(); err != nil {
			return err
		}
	}
	g.entered = true
	return nil
}

func (g *terminalGuard) release() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hooks.OnRelease != nil {
		return g.hooks.OnRelease()
	}
	return nil
}

func (g *terminalGuard) reenter() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hooks.OnEnter != nil {
		return g.hooks.OnEnter()
	}
	return nil
}

func (g *terminalGuard) restore() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.restored {
		return nil
	}
	g.restored = true
	if g.hooks.OnRestore != nil {
		if err := g.hooks.OnRestore(); err != nil {
			return fmt.Errorf("%w: %w", ErrTerminalRestore, err)
		}
	}
	return nil
}

// Run 启动受 core/conc.Nursery 全程监督的 Bubble Tea v2 实时流式工作台，
// 保证所有后台投影监听、事件流订阅、指标/日志流与终端接管/恢复在返回前 100% 确定性排空（0 裸 go、0 goroutine 泄漏）。
func Run(ctx context.Context, cfg Config) (retErr error) {
	if ctx == nil {
		return ErrNilContext
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	guard := &terminalGuard{hooks: cfg.TerminalHooks}
	if err := guard.enter(); err != nil {
		return err
	}
	defer func() {
		if restoreErr := guard.restore(); restoreErr != nil {
			retErr = errors.Join(retErr, restoreErr)
		}
	}()

	proj, ownsProj, err := resolveProjection(ctx, cfg)
	if err != nil {
		return err
	}
	if ownsProj && proj != nil {
		defer func() {
			if closeErr := proj.Close(); closeErr != nil {
				retErr = errors.Join(retErr, closeErr)
			}
		}()
	}

	return runWorkbenchLoop(ctx, cfg, proj, guard)
}

func resolveProjection(ctx context.Context, cfg Config) (ProjectionSource, bool, error) {
	if cfg.Projection != nil {
		return cfg.Projection, false, nil
	}
	if cfg.Engine == nil {
		return nil, false, nil
	}
	p, err := cfg.Engine.NewProjection(ctx, cfg.ProjectionConfig)
	if err != nil {
		return nil, false, err
	}
	if p == nil {
		return nil, false, nil
	}
	return p, true, nil
}

// runWorkbenchLoop 驱动工作台主循环与终端接管/恢复闭环：
// 当用户在主机视图触发交互接管时，先完整退出并排空 Bubble Tea 与全部 Nursery 协程，
// 再通过 OnRelease -> conc.RunScoped(OnTakeover) -> OnEnter 确定性归还与恢复终端控制权。
func runWorkbenchLoop(ctx context.Context, cfg Config, proj ProjectionSource, guard *terminalGuard) error {
	model := newModelWithActions(ModelOptions{
		InitialView:      cfg.InitialView,
		InitialWidth:     cfg.InitialWidth,
		InitialHeight:    cfg.InitialHeight,
		DisableAltScreen: cfg.DisableAltScreen,
		InitialTarget:    cfg.InitialTarget,
		MaxLogLines:      cfg.MaxLogLines,
		CanTakeover:      cfg.OnTakeover != nil,
	}, nil)
	firstPass := true

	for {
		nextModel, err := runSingleProgramPass(ctx, cfg, proj, model, firstPass)
		firstPass = false
		if err != nil {
			return err
		}
		model = nextModel
		takeoverReq, hasTakeover := model.PendingTakeover()
		if !hasTakeover {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		takeoverErr := runSupervisedTakeover(ctx, cfg.OnTakeover, takeoverReq, guard)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		model.quitting = false
		model.applyTakeoverResult(TakeoverResultMsg{Target: takeoverReq.TargetSpec, Err: takeoverErr})
	}
}

func runSupervisedTakeover(ctx context.Context, fn TakeoverFunc, req TakeoverRequest, guard *terminalGuard) error {
	if fn == nil {
		return ErrTakeoverDisabled
	}
	if err := guard.release(); err != nil {
		return err
	}
	runErr := conc.RunScoped(ctx, func(tCtx context.Context, _ *conc.Nursery) error {
		return fn(tCtx, req)
	})
	if ctx.Err() == nil {
		if reErr := guard.reenter(); reErr != nil {
			return errors.Join(runErr, reErr)
		}
	}
	return runErr
}

func runSingleProgramPass(
	ctx context.Context,
	cfg Config,
	proj ProjectionSource,
	seed Model,
	attachInitialStreams bool,
) (Model, error) {
	actionCh := make(chan actionRequest, defaultActionQueueCap)
	seed.actions = actionCh
	finalModel := seed

	scopeErr := conc.RunScoped(ctx, func(scopeCtx context.Context, nursery *conc.Nursery) error {
		prog := buildTeaProgram(scopeCtx, cfg, seed)
		ctrl := &workbenchController{
			cfg:  cfg,
			proj: proj,
			prog: prog,
		}
		if err := startBackgroundWatchers(nursery, cfg, proj, prog, actionCh, ctrl, attachInitialStreams); err != nil {
			return err
		}
		if cfg.Engine != nil {
			// 通过有界通道异步触发首次刷新与熔断态检测，严禁在 prog.Run() 启动前阻塞调用 prog.Send。
			actionCh <- actionRequest{kind: actionRefreshInventory}
		}
		outModel, runErr := prog.Run()
		if fm, ok := outModel.(Model); ok {
			finalModel = fm
		}
		return classifyProgramExitError(ctx, runErr)
	})
	return finalModel, scopeErr
}

func buildTeaProgram(scopeCtx context.Context, cfg Config, model Model) *tea.Program {
	opts := []tea.ProgramOption{tea.WithContext(scopeCtx)}
	if cfg.DisableInput {
		opts = append(opts, tea.WithInput(nil))
	} else if cfg.Input != nil {
		opts = append(opts, tea.WithInput(cfg.Input))
	}
	if cfg.Output != nil {
		opts = append(opts, tea.WithOutput(cfg.Output))
	}
	if len(cfg.Environment) > 0 {
		opts = append(opts, tea.WithEnvironment(cloneStrings(cfg.Environment)))
	}
	if cfg.DisableRenderer {
		opts = append(opts, tea.WithoutRenderer())
	}
	if cfg.DisableSignalHandler {
		opts = append(opts, tea.WithoutSignalHandler())
	}
	if cfg.InitialWidth > 0 && cfg.InitialHeight > 0 {
		opts = append(opts, tea.WithWindowSize(cfg.InitialWidth, cfg.InitialHeight))
	}
	return tea.NewProgram(model, opts...)
}

func classifyProgramExitError(parentCtx context.Context, runErr error) error {
	if runErr == nil {
		return nil
	}
	if parentCtx.Err() != nil && errors.Is(runErr, tea.ErrProgramKilled) {
		return parentCtx.Err()
	}
	if errors.Is(runErr, tea.ErrInterrupted) && parentCtx.Err() == nil {
		return nil
	}
	return runErr
}
