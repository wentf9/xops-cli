package sim

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
)

// ProcessHandler 定义 SimProcessPort 的可编程命令处理回调。
type ProcessHandler func(ctx context.Context, spec ports.ProcessSpec, stdin []byte) (ports.ProcessResult, error)

// SimProcessPort 是零 os/exec 的纯内存子进程与 stdio 管道仿真器，实现 ports.ProcessPort。
//
//xops:opaque
//xops:failclosed
type SimProcessPort struct {
	simBase
	handlers map[string]ProcessHandler
}

// NewSimProcessPort 创建纯内存子进程仿真器（"fail"/"false" 返回退出码 1，其余默认回显 stdin）。
func NewSimProcessPort() *SimProcessPort {
	return &SimProcessPort{simBase: newSimBase(nil), handlers: make(map[string]ProcessHandler)}
}

// RegisterCommand 注册或注销指定命令名的自定义处理回调。
func (p *SimProcessPort) RegisterCommand(cmd string, fn ProcessHandler) {
	if cmd != "" {
		p.withLock(func() {
			if fn == nil {
				delete(p.handlers, cmd)
			} else {
				p.handlers[cmd] = fn
			}
		})
	}
}
func (p *SimProcessPort) Run(ctx context.Context, spec ports.ProcessSpec, stdin io.Reader) (out ports.ProcessResult, err error) {
	if err = p.check(ctx, "proc.run", spec.IsValid()); err != nil {
		return out, err
	}
	var inBytes []byte
	if stdin != nil {
		if inBytes, err = io.ReadAll(stdin); err != nil {
			return out, err
		}
	}
	if h := withLockRet(&p.simBase, nil, func() ProcessHandler { return p.handlers[spec.Command()] }); h != nil {
		return h(ctx, spec, inBytes)
	}
	if spec.Command() == "fail" || spec.Command() == "false" {
		return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(1), Stderr: []byte("simulated non-zero exit")})
	}
	trunc := uint64(len(inBytes)) > spec.MaxOutputBytes()
	if trunc {
		inBytes = inBytes[:spec.MaxOutputBytes()]
	}
	return ports.NewProcessResult(ports.ProcessResultSpec{ExitStatus: execution.NewExitCode(0), Stdout: inBytes, Truncated: trunc})
}
func (p *SimProcessPort) DialStdio(ctx context.Context, spec ports.ProcessSpec) (net.Conn, error) {
	if err := p.check(ctx, "proc.dialstdio", spec.IsValid()); err != nil {
		return nil, err
	}
	return memtree.NewEchoConn(spec.Command()), nil
}

// SimTerminalPort 实现 ports.TerminalPort 的纯内存 PTY/ConPTY、双向 Relay 与孤儿进程组判定仿真器。
//
//xops:opaque
//xops:failclosed
type SimTerminalPort struct {
	simBase
	interactive bool
	size        ports.TerminalSize
	suspendErr  error
	suspendV    security.Verdict
	inData      []byte
	blockInput  bool
	outBuf      bytes.Buffer
	resizes     []ports.TerminalSize
}

// NewSimTerminalPort 创建纯内存终端仿真器（cols/rows 为 0 时默认 80x24）。
func NewSimTerminalPort(interactive bool, cols, rows uint16) *SimTerminalPort {
	sz, err := ports.NewTerminalSize(cols, rows)
	if err != nil {
		sz, _ = ports.NewTerminalSize(80, 24)
	}
	return &SimTerminalPort{simBase: newSimBase(nil), interactive: interactive, size: sz, suspendV: security.VerdictAllow}
}

// SetSuspendResult / SetInput / SetBlockInputAfterData / QueueResize / Output 配置测试夹具并观测终端写入输出。
func (t *SimTerminalPort) SetSuspendResult(v security.Verdict, err error) {
	t.withLock(func() { t.suspendV, t.suspendErr = v, err })
}
func (t *SimTerminalPort) SetInput(data []byte) {
	t.withLock(func() { t.inData = bytes.Clone(data) })
}
func (t *SimTerminalPort) SetBlockInputAfterData(block bool) {
	t.withLock(func() { t.blockInput = block })
}
func (t *SimTerminalPort) QueueResize(sizes ...ports.TerminalSize) {
	t.withLock(func() {
		for _, sz := range sizes {
			if sz.IsValid() {
				t.resizes = append(t.resizes, sz)
			}
		}
	})
}
func (t *SimTerminalPort) Output() []byte {
	return withLockRet(&t.simBase, nil, func() []byte { return bytes.Clone(t.outBuf.Bytes()) })
}
func (t *SimTerminalPort) IsInteractive() bool {
	return withLockRet(&t.simBase, false, func() bool { return t.interactive })
}
func (t *SimTerminalPort) Size() (out ports.TerminalSize, err error) {
	return out, withLockRet(&t.simBase, ErrSimNotInitialized, func() error {
		if !t.interactive {
			return ports.ErrUnsupported
		}
		out = t.size
		return nil
	})
}
func (t *SimTerminalPort) CanSuspendProcessGroup() (v security.Verdict, err error) {
	if !t.ok() {
		return security.VerdictDeny, ErrSimNotInitialized
	}
	t.withLock(func() { v, err = t.suspendV, t.suspendErr })
	if err != nil {
		return security.VerdictDeny, err
	}
	return v.Normalize(), nil
}

// WithRawTerminal 在同步作用域内借出带失效哨兵与双向 Relay 能力的 TerminalHandle，退出时关闭 ResizeEvents。
//
//xops:syncclosure
//xops:borrowed
func (t *SimTerminalPort) WithRawTerminal(ctx context.Context, fn func(term ports.TerminalHandle) error) error {
	if err := t.checkFn(ctx, fn != nil, "term.raw"); err != nil {
		return err
	}
	sz, err := t.Size()
	if err != nil {
		return err
	}
	var inSnap []byte
	var blockInput bool
	var resizeSnap []ports.TerminalSize
	t.withLock(func() {
		inSnap = bytes.Clone(t.inData)
		blockInput = t.blockInput
		resizeSnap = slices.Clone(t.resizes)
		t.resizes = nil
	})
	resizeCh := make(chan ports.TerminalSize, max(4, len(resizeSnap)))
	for _, rsz := range resizeSnap {
		resizeCh <- rsz
	}
	h := &simTerminalHandle{owner: t, size: sz, inR: bytes.NewReader(inSnap), blockAfter: blockInput, resizeCh: resizeCh, valid: true}
	defer func() { h.expired.Store(true); close(resizeCh) }()
	return fn(h)
}

type simTerminalHandle struct {
	owner      *SimTerminalPort
	size       ports.TerminalSize
	inMu       sync.Mutex
	inR        *bytes.Reader
	blockAfter bool
	stopMu     sync.Mutex
	stopCh     chan struct{}
	resizeCh   chan ports.TerminalSize
	valid      bool
	expired    atomic.Bool
}

func (h *simTerminalHandle) alive() bool                             { return h != nil && h.valid && !h.expired.Load() }
func (h *simTerminalHandle) ResizeEvents() <-chan ports.TerminalSize { return h.resizeCh }
func (h *simTerminalHandle) setStopCh(ch chan struct{}) {
	h.stopMu.Lock()
	h.stopCh = ch
	h.stopMu.Unlock()
}
func (h *simTerminalHandle) currentStopCh() chan struct{} {
	h.stopMu.Lock()
	ch := h.stopCh
	h.stopMu.Unlock()
	return ch
}
func (h *simTerminalHandle) Read(p []byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	h.inMu.Lock()
	var n int
	var err error
	if h.inR != nil {
		n, err = h.inR.Read(p)
	} else {
		err = io.EOF
	}
	h.inMu.Unlock()
	if n > 0 || err != io.EOF || !h.blockAfter {
		return n, err
	}
	if ch := h.currentStopCh(); ch != nil {
		<-ch
	}
	return 0, io.EOF
}
func (h *simTerminalHandle) Write(p []byte) (int, error) {
	if !h.alive() {
		return 0, ports.ErrHandleExpired
	}
	if h.owner != nil {
		h.owner.withLock(func() { _, _ = h.owner.outBuf.Write(p) })
	}
	return len(p), nil
}
func (h *simTerminalHandle) Size() (out ports.TerminalSize, err error) {
	if !h.alive() {
		return out, ports.ErrHandleExpired
	}
	return h.size, nil
}

// Relay 在同步作用域内经 core/conc.RunWait 并发驱动终端输入、远端输出与窗口缩放回调（零裸 go、零泄漏）。
//
//xops:syncclosure
func (h *simTerminalHandle) Relay(ctx context.Context, remoteIn io.Writer, remoteOut io.Reader, onResize func(ctx context.Context, size ports.TerminalSize) error) error {
	if !h.alive() {
		return ports.ErrHandleExpired
	}
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if remoteIn == nil || remoteOut == nil {
		return ports.ErrInvalidArgument
	}
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	triggerStop := func() { stopOnce.Do(func() { close(stopCh) }) }
	h.setStopCh(stopCh)
	defer func() { triggerStop(); h.setStopCh(nil) }()
	return memtree.RelayTerminalStreams(ctx, h, h, remoteIn, remoteOut, h.resizeCh, onResize, triggerStop)
}
