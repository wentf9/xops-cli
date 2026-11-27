package sys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"slices"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
)

const processWaitDelay = time.Second

// SystemProcess 实现 ports.ProcessPort，提供受控本机外部子进程执行与 stdio 双向管道连接；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SystemProcess struct {
	valid bool
}

// NewSystemProcess 构造可用的本机子进程执行适配器。
func NewSystemProcess() *SystemProcess { return &SystemProcess{valid: true} }

// Run 执行一次性受控子进程，强制应用可选超时、有界 stdout/stderr 捕获与平台进程树清理。
// 非零退出码返回有效 ProcessResult（Succeeded()==false）与 nil error；启动失败或上下文取消返回错误。
func (p *SystemProcess) Run(ctx context.Context, spec ports.ProcessSpec, stdin io.Reader) (ports.ProcessResult, error) {
	if err := p.checkArgs(ctx, spec); err != nil {
		return zeroVal[ports.ProcessResult](), err
	}
	runCtx, cancel := applyProcessTimeout(ctx, spec)
	defer cancel()

	cmd := buildRunCmd(runCtx, spec)
	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit, stderrBuf.limit = spec.MaxOutputBytes(), spec.MaxOutputBytes()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &stdoutBuf, &stderrBuf

	if err := cmd.Start(); err != nil {
		return zeroVal[ports.ProcessResult](), err
	}
	cleanup := attachRunCleanup(cmd)
	// 在 runCtx 取消或超时时立即触发平台进程树清理（Windows 关闭 Job Object 终止整棵含孙进程树，
	// 防止孙进程持有 stdout/stderr 管道句柄阻塞 cmd.Wait）；Unix 取消路径已由 cmd.Cancel 杀整组，
	// attachRunCleanup 为空操作以避免 Wait 回收 PID 后的 PID 复用误杀风险。
	stopCancel := context.AfterFunc(runCtx, cleanup)
	defer stopCancel()
	defer cleanup()

	waitErr := cmd.Wait()
	return finalizeProcessResult(runCtx, cmd.ProcessState, waitErr, &stdoutBuf, &stderrBuf)
}

// DialStdio 启动子进程并将其 stdin/stdout 封装为可关闭的 net.Conn（供 ProxyCommand 等场景复用）。
// ctx 仅约束拨号启动阶段校验，不绑定至已建立连接的子进程生命周期；
// 调用 Close() 将关闭管道、在 Wait 前终止整棵子进程树并同步回收子进程，保证零僵尸与零协程泄漏。
func (p *SystemProcess) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	if err := p.checkArgs(ctx, spec); err != nil {
		return nil, err
	}
	cmd := buildDialCmd(spec)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdinPipe.Close()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		_ = errors.Join(stdinPipe.Close(), stdoutPipe.Close())
		return nil, err
	}
	cleanup := attachDialCleanup(cmd)
	return &processStdioConn{
		cmd:     cmd,
		stdin:   stdinPipe,
		stdout:  stdoutPipe,
		cleanup: cleanup,
		addr:    processAddr(spec.Command()),
	}, nil
}

func (p *SystemProcess) checkArgs(ctx context.Context, spec ports.ProcessSpec) error {
	if p == nil || !p.valid {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostNotInitialized, i18n.Str("component", "SystemProcess"))
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !spec.IsValid() {
		return i18n.EF(ports.ErrInvalidArgument, i18n.KeyHostInvalidField, i18n.Str("field", "ProcessSpec"))
	}
	return nil
}

func applyProcessTimeout(ctx context.Context, spec ports.ProcessSpec) (context.Context, context.CancelFunc) {
	if to, ok := spec.Timeout().Get(); ok {
		return context.WithTimeout(ctx, to.Std())
	}
	return ctx, func() {}
}

func buildRunCmd(ctx context.Context, spec ports.ProcessSpec) *exec.Cmd {
	cmd := exec.CommandContext(ctx, spec.Command(), spec.Args()...)
	applyCommonCmdSpec(cmd, spec, true)
	return cmd
}

func buildDialCmd(spec ports.ProcessSpec) *exec.Cmd {
	cmd := exec.Command(spec.Command(), spec.Args()...)
	applyCommonCmdSpec(cmd, spec, false)
	return cmd
}

func applyCommonCmdSpec(cmd *exec.Cmd, spec ports.ProcessSpec, bindCancel bool) {
	cmd.WaitDelay = processWaitDelay
	if wd, ok := spec.WorkDir().Get(); ok {
		cmd.Dir = wd.String()
	}
	if extra := spec.Env(); len(extra) > 0 {
		cmd.Env = mergeProcessEnv(os.Environ(), extra)
	}
	configureCmdPlatform(cmd, bindCancel)
}

// mergeProcessEnv 保留 base 原始顺序及 Windows 驱动器工作目录项（=C:=...），
// 并将排序后的 overrides 追加在末尾，确保 Go os/exec.dedupEnvCase（按末次出现覆盖，Windows 大小写不敏感）
// 始终令显式覆盖生效。
func mergeProcessEnv(base []string, overrides map[string]string) []string {
	out := slices.Clone(base)
	for _, k := range slices.Sorted(maps.Keys(overrides)) {
		out = append(out, k+"="+overrides[k])
	}
	return out
}

func finalizeProcessResult(runCtx context.Context, ps *os.ProcessState, waitErr error, outBuf, errBuf *limitedBuffer) (ports.ProcessResult, error) {
	if waitErr == nil {
		return ports.NewProcessResult(ports.ProcessResultSpec{
			ExitStatus: execution.NewExitCode(0),
			Stdout:     outBuf.Bytes(),
			Stderr:     errBuf.Bytes(),
			Truncated:  outBuf.truncated || errBuf.truncated,
		})
	}
	if ctxErr := runCtx.Err(); ctxErr != nil {
		return zeroVal[ports.ProcessResult](), ctxErr
	}
	if exitErr, ok := errors.AsType[*exec.ExitError](waitErr); ok {
		st, sErr := exitStatusFromState(exitErr.ProcessState)
		if sErr != nil {
			return zeroVal[ports.ProcessResult](), sErr
		}
		return ports.NewProcessResult(ports.ProcessResultSpec{
			ExitStatus: st,
			Stdout:     outBuf.Bytes(),
			Stderr:     errBuf.Bytes(),
			Truncated:  outBuf.truncated || errBuf.truncated,
		})
	}
	if ps != nil {
		st, sErr := exitStatusFromState(ps)
		if sErr == nil {
			return ports.NewProcessResult(ports.ProcessResultSpec{
				ExitStatus: st,
				Stdout:     outBuf.Bytes(),
				Stderr:     errBuf.Bytes(),
				Truncated:  outBuf.truncated || errBuf.truncated,
			})
		}
	}
	return zeroVal[ports.ProcessResult](), waitErr
}

// limitedBuffer 在 limit 上限内捕获输出字节，超限后静默丢弃并标记 truncated，避免反向 EPIPE 误杀子进程。
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     uint64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur := uint64(b.buf.Len())
	if cur >= b.limit {
		if len(p) > 0 {
			b.truncated = true
		}
		return len(p), nil
	}
	avail := b.limit - cur
	if uint64(len(p)) > avail {
		_, _ = b.buf.Write(p[:avail])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

type processAddr string

func (a processAddr) Network() string { return "stdio" }
func (a processAddr) String() string  { return string(a) }

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

type processStdioConn struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	cleanup   func()
	addr      processAddr
	closeOnce sync.Once
	closeErr  error
}

func (c *processStdioConn) Read(b []byte) (int, error)  { return c.stdout.Read(b) }
func (c *processStdioConn) Write(b []byte) (int, error) { return c.stdin.Write(b) }
func (c *processStdioConn) LocalAddr() net.Addr         { return c.addr }
func (c *processStdioConn) RemoteAddr() net.Addr        { return c.addr }

// Close 幂等关闭 stdio 管道、终止子进程树并同步等待子进程退出。
func (c *processStdioConn) Close() error {
	c.closeOnce.Do(func() {
		inErr := c.stdin.Close()
		outErr := c.stdout.Close()
		if c.cleanup != nil {
			c.cleanup()
		}
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.cmd.Wait()
		c.closeErr = errors.Join(ignoreAlreadyClosed(inErr), ignoreAlreadyClosed(outErr))
	})
	return c.closeErr
}

func ignoreAlreadyClosed(err error) error {
	if err == nil || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

func (c *processStdioConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *processStdioConn) SetReadDeadline(t time.Time) error {
	if ds, ok := c.stdout.(readDeadlineSetter); ok {
		return ds.SetReadDeadline(t)
	}
	return ports.ErrUnsupported
}

func (c *processStdioConn) SetWriteDeadline(t time.Time) error {
	if ds, ok := c.stdin.(writeDeadlineSetter); ok {
		return ds.SetWriteDeadline(t)
	}
	return ports.ErrUnsupported
}
