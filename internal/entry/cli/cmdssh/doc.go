// Package cmdssh 实现 XOps v2 的 SSH 会话、单/批量命令执行、端口/TUN 隧道转发与 ControlMaster 多路复用命令族
// （`ssh` / `exec` / `tunnel` / `forward` / `mux`）。
//
// 核心架构与安全不变量：
//   - 极薄入站适配：零业务逻辑、零 internal/host/** 导入、零 core/osfs 或 core/ports 导入、零 os.Exit；
//   - 全量保留 OpenSSH 标准短选项肌肉记忆（-p/-l/-i/-J/-L/-R/-D/-o/-O/-M/-S/-F/-t/-T/-N/-f/-W/-w）；
//   - 全部并发等待与流消费严格受 core/conc.Nursery 监督（0 裸 go、0 time.Sleep 同步、0 goleak）；
//   - 所有 JSON 输出均经 encoding/json/v2 Deterministic(true) 规范编码且严禁裸 time.Duration。
package cmdssh

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

const defaultCleanupTimeout = 5 * time.Second

func requireSSHClient(runner clikit.SessionRunner) (clikit.SSHClient, error) {
	c, ok := runner.(clikit.SSHClient)
	if !ok {
		return nil, fmt.Errorf("%w: 需要 SSHClient 能力接口", clikit.ErrUnsupportedRunner)
	}
	return c, nil
}

func requireAutomationClient(runner clikit.SessionRunner) (clikit.AutomationClient, error) {
	c, ok := runner.(clikit.AutomationClient)
	if !ok {
		return nil, fmt.Errorf("%w: 需要 AutomationClient 能力接口", clikit.ErrUnsupportedRunner)
	}
	return c, nil
}

// startForwards 依次启动全部请求的转发规则；任一规则失败时立即按逆序停止已启动句柄，防止资源泄漏。
func startForwards(ctx context.Context, client clikit.SSHClient, rc engine.RemoteCall, specs []engine.ForwardSpec) ([]engine.ForwardInfo, error) {
	infos := make([]engine.ForwardInfo, 0, len(specs))
	for _, spec := range specs {
		info, err := client.StartForward(ctx, engine.StartForwardRequest{
			RemoteCall: rc,
			Spec:       spec,
		})
		if err != nil {
			_ = stopForwards(ctx, client, infos)
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

// stopForwards 使用剥离取消但带有限超时的上下文按逆序停止已启动转发句柄。
func stopForwards(ctx context.Context, client clikit.SSHClient, infos []engine.ForwardInfo) error {
	if len(infos) == 0 {
		return nil
	}
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultCleanupTimeout)
	defer cancel()
	var errs []error
	for i := len(infos) - 1; i >= 0; i-- {
		if infos[i].IsValid() {
			if err := client.StopForward(stopCtx, infos[i].Handle()); err != nil && !errors.Is(err, engine.ErrHandleNotFound) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// waitForwards 在 core/conc.Nursery（RunScoped）监督下零轮询等待全部受管转发或主控结束：
//   - 当 ctx 取消（如 Ctrl+C）时正常返回 nil；
//   - 当任一转发非预期终止或返回传输错误时立即唤醒并取消其余等待协程，确保 0 goroutine 泄漏。
func waitForwards(ctx context.Context, infos []engine.ForwardInfo, master *engine.ControlMasterInfo) error {
	waiters := collectForwardWaiters(infos, master)
	if len(waiters) == 0 {
		<-ctx.Done()
		return nil
	}
	doneCh := make(chan error, len(waiters))
	var once sync.Once
	signalDone := func(err error) {
		once.Do(func() { doneCh <- err })
	}
	return conc.RunScoped(ctx, func(scopedCtx context.Context, n *conc.Nursery) error {
		if err := spawnWaiters(n, waiters, signalDone); err != nil {
			return err
		}
		select {
		case <-scopedCtx.Done():
			return nil
		case err := <-doneCh:
			return err
		}
	})
}

func collectForwardWaiters(infos []engine.ForwardInfo, master *engine.ControlMasterInfo) []func(context.Context) error {
	waiters := make([]func(context.Context) error, 0, len(infos)+1)
	// 仅等待本进程实际启动的 ControlMaster；ReusedExisting 外部主控的 Wait 会立即返回 nil，
	// 若纳入等待列表会误触发早退并撕毁刚建立的转发句柄。
	if master != nil && master.IsValid() && !master.ReusedExisting() {
		m := *master
		waiters = append(waiters, m.Wait)
	}
	for _, info := range infos {
		if info.IsValid() {
			fi := info
			waiters = append(waiters, fi.Wait)
		}
	}
	return waiters
}

// reportCleanupError 将隧道/主控清理故障输出至 stderr，并在业务原退出码为 0 时失败关闭提升为 ExitGeneral。
func reportCleanupError(rt *clikit.Runtime, err error, exitCode *int) {
	if err == nil {
		return
	}
	rt.WriteErr("cleanup failed: " + err.Error())
	if *exitCode == clikit.ExitOK {
		*exitCode = clikit.ExitGeneral
	}
}

// failAfterAnnounce 在 announceActiveSession 已输出启动信息后处理等待期故障：
// JSON 模式下绝不向 stdout 追加第二个 JSON 文档，仅将错误写入 stderr 并返回 ExitSSHError。
func failAfterAnnounce(rt *clikit.Runtime, jsonOut bool, err error) int {
	if jsonOut {
		rt.WriteErr(err.Error())
		return clikit.ExitSSHError
	}
	return rt.Fail(clikit.ExitSSHError, false, err)
}

func spawnWaiters(n *conc.Nursery, waiters []func(context.Context) error, signalDone func(error)) error {
	for _, w := range waiters {
		waitFn := w
		if err := n.Go(func(childCtx context.Context) error {
			err := waitFn(childCtx)
			if childCtx.Err() == nil {
				signalDone(err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
