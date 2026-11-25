package sys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// StreamTerminalSpec 是构造面向确定性测试或自定义流的内存/管道 Terminal 的显式入参规格。
type StreamTerminalSpec struct {
	// In 指定终端本地输入流（Interactive 为 true 时必须非 nil）。
	In io.Reader
	// Out 指定终端本地输出流（Interactive 为 true 时必须非 nil）。
	Out io.Writer
	// Interactive 声明该终端流是否处于交互式 TTY 语义。
	Interactive bool
	// SizeFn 返回终端窗口尺寸（Interactive 为 true 时必须提供有效回调）。
	SizeFn func() (ports.TerminalSize, error)
	// ResizeCh 可选提供外部窗口尺寸事件通道。
	ResizeCh <-chan ports.TerminalSize
	// UnblockInput 可选提供在 Relay 结束或取消时立即唤醒阻塞 In.Read 的回调。
	UnblockInput func()
}

// Terminal 实现 ports.TerminalPort，支持真实 OS TTY/ConPTY 与自定义流两种绑定形态；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Terminal struct {
	inFile      *os.File
	outFile     *os.File
	streamIn    io.Reader
	streamOut   io.Writer
	sizeFn      func() (ports.TerminalSize, error)
	extResizeCh <-chan ports.TerminalSize
	unblockFn   func()
	interactive bool
	isFileMode  bool
	valid       bool
}

// NewSystemTerminal 构造绑定至当前进程 os.Stdin 与 os.Stdout 的真实本机终端适配器。
func NewSystemTerminal() *Terminal {
	inter, _ := probeFileInteractive(os.Stdin, os.Stdout)
	return &Terminal{
		inFile:      os.Stdin,
		outFile:     os.Stdout,
		interactive: inter,
		isFileMode:  true,
		valid:       true,
	}
}

// NewFileTerminal 构造绑定至指定本机文件句柄（如独立 PTY 从端或控制台句柄）的终端适配器。
func NewFileTerminal(in, out *os.File) (*Terminal, error) {
	if in == nil || out == nil {
		return nil, fmt.Errorf("%w: Terminal 输入输出文件句柄不能为 nil", ports.ErrInvalidArgument)
	}
	inter, err := probeFileInteractive(in, out)
	if err != nil {
		return nil, err
	}
	return &Terminal{
		inFile:      in,
		outFile:     out,
		interactive: inter,
		isFileMode:  true,
		valid:       true,
	}, nil
}

// NewStreamTerminal 构造基于自定义读写流与可选窗口事件的终端适配器（供无头环境与跨平台契约验证复用）。
func NewStreamTerminal(spec StreamTerminalSpec) (*Terminal, error) {
	if spec.Interactive && (spec.In == nil || spec.Out == nil || spec.SizeFn == nil) {
		return nil, fmt.Errorf("%w: 交互式流终端必须提供 In、Out 与 SizeFn", ports.ErrInvalidArgument)
	}
	return &Terminal{
		streamIn:    spec.In,
		streamOut:   spec.Out,
		sizeFn:      spec.SizeFn,
		extResizeCh: spec.ResizeCh,
		unblockFn:   spec.UnblockInput,
		interactive: spec.Interactive,
		isFileMode:  false,
		valid:       true,
	}, nil
}

// IsInteractive 报告当前终端是否处于交互式 TTY/ConPTY 模式；零值恒返回 false。
func (t *Terminal) IsInteractive() bool {
	return t != nil && t.valid && t.interactive
}

// Size 查询当前交互式终端窗口尺寸（列数、行数）；非交互或未初始化时返回错误。
func (t *Terminal) Size() (ports.TerminalSize, error) {
	if t == nil || !t.valid {
		return zeroVal[ports.TerminalSize](), fmt.Errorf("%w: Terminal 未初始化", ports.ErrInvalidArgument)
	}
	if !t.interactive {
		return zeroVal[ports.TerminalSize](), ports.ErrUnsupported
	}
	if t.isFileMode {
		return queryFileSize(t.inFile, t.outFile)
	}
	return t.sizeFn()
}

// CanSuspendProcessGroup 执行 POSIX 孤儿进程组安全挂起判定（INV-E1）：
// 任何系统调用错误或非支持平台（Windows）均失败关闭返回 security.VerdictDeny。
func (t *Terminal) CanSuspendProcessGroup() (security.Verdict, error) {
	if t == nil || !t.valid {
		return security.VerdictDeny, fmt.Errorf("%w: Terminal 未初始化", ports.ErrInvalidArgument)
	}
	return checkSuspendProcessGroupOS()
}

// WithRawTerminal 进入原始终端/ConPTY 模式，在同步作用域内借出带失效哨兵与窗口监听的 TerminalHandle，
// 退出前先收敛全部内部监听协程，再无条件恢复原始终端状态并使句柄失效。
//
//xops:syncclosure
//xops:borrowed
func (t *Terminal) WithRawTerminal(ctx context.Context, fn func(term ports.TerminalHandle) error) (retErr error) {
	if err := t.checkRawArgs(ctx, fn == nil); err != nil {
		return err
	}
	restore, err := t.enterRawMode()
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, restore())
	}()

	var ownedResizeCh chan ports.TerminalSize
	var handleResizeCh <-chan ports.TerminalSize
	if t.isFileMode {
		ownedResizeCh = make(chan ports.TerminalSize, 8)
		handleResizeCh = ownedResizeCh
		defer close(ownedResizeCh)
	} else {
		// 流模式直接透传调用方提供的事件通道，避免额外转发协程调度竞态导致预置尺寸事件在短命 Relay 中丢失。
		handleResizeCh = t.extResizeCh
	}

	return conc.RunScoped(ctx, func(_ context.Context, n *conc.Nursery) error {
		if ownedResizeCh != nil {
			if err := n.Go(func(c context.Context) error {
				return watchResizeOS(c, t.inFile, t.outFile, ownedResizeCh)
			}); err != nil {
				return err
			}
		}
		h := t.newHandle(handleResizeCh)
		defer h.expire()
		return fn(h)
	})
}

func (t *Terminal) checkRawArgs(ctx context.Context, fnNil bool) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if fnNil {
		return ports.ErrNilCallback
	}
	if t == nil || !t.valid {
		return fmt.Errorf("%w: Terminal 未初始化", ports.ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !t.interactive {
		return ports.ErrUnsupported
	}
	return nil
}

func (t *Terminal) enterRawMode() (func() error, error) {
	if !t.isFileMode {
		return func() error { return nil }, nil
	}
	return enterRawFileOS(t.inFile, t.outFile)
}

// pushLatestResize 以非阻塞 CoalesceLatest 策略写入最新终端尺寸：通道满时先弹出最旧快照再压入新尺寸，
// 避免慢消费端反向阻塞 OS 缩放监听协程。
func pushLatestResize(dst chan ports.TerminalSize, sz ports.TerminalSize) {
	select {
	case dst <- sz:
		return
	default:
	}
	select {
	case <-dst:
	default:
	}
	select {
	case dst <- sz:
	default:
	}
}
