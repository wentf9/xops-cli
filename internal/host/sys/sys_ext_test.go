package sys_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"go.uber.org/goleak"
)

// 编译期接口契约断言（ADR-002 / ADR-011）。
var (
	_ ports.Clock        = (*sys.SystemClock)(nil)
	_ ports.Entropy      = (*sys.CryptoEntropy)(nil)
	_ ports.EnvPort      = (*sys.SystemEnv)(nil)
	_ ports.ProcessPort  = (*sys.SystemProcess)(nil)
	_ ports.TerminalPort = (*sys.Terminal)(nil)
)

const (
	helperEnvModeKey = "XOPS_SYS_TEST_HELPER_MODE"
	helperReadyKey   = "XOPS_SYS_TEST_READY_FILE"
)

// TestHelperProcess 为跨平台 ProcessPort TCK（Linux / FreeBSD / macOS / Windows）提供自托管子进程桩。
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(helperEnvModeKey)
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin)
		os.Exit(0)
	case "fail":
		_, _ = io.WriteString(os.Stderr, "helper-nonzero")
		os.Exit(7)
	case "stdio":
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				_, _ = os.Stdout.Write(buf[:n])
			}
			if err != nil {
				os.Exit(0)
			}
		}
	case "flood":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("A"), 2048))
		os.Exit(0)
	case "grandchild-hold":
		runHelperGrandchildHold()
	case "hold-stdout":
		_, _ = io.WriteString(os.Stdout, "GRANDCHILD-READY\n")
		if p := os.Getenv(helperReadyKey); p != "" {
			_ = os.WriteFile(p, []byte("ready"), 0o600)
		}
		// 持续持有继承的 stdout/stderr 句柄并无限阻塞，直至被父进程组/Job Object 取消杀死。
		select {}
	default:
		os.Exit(2)
	}
}

func runHelperGrandchildHold() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(3)
	}
	sub := exec.Command(exe, "-test.run=^TestHelperProcess$")
	sub.Env = append(os.Environ(), helperEnvModeKey+"=hold-stdout")
	sub.Stdout = os.Stdout
	sub.Stderr = os.Stderr
	if err := sub.Start(); err != nil {
		os.Exit(5)
	}
	// 子进程同步等待持续持有 stdout/stderr 管道的孙进程，绝不因 stdin==os.DevNull 提前 EOF 退出。
	_ = sub.Wait()
	os.Exit(0)
}

func mustHelperSpec(t *testing.T, mode string, maxOut algebraic.Option[uint64]) ports.ProcessSpec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	spec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command:        exe,
		Args:           []string{"-test.run=^TestHelperProcess$"},
		Env:            map[string]string{helperEnvModeKey: mode},
		MaxOutputBytes: maxOut,
	})
	if err != nil {
		t.Fatalf("NewProcessSpec(%q) 失败: %v", mode, err)
	}
	return spec
}

// TestTCKClockEntropyEnvProcess 验证真实 Clock、Entropy、EnvPort 与 ProcessPort 全部通过 core/ports/tck。
func TestTCKClockEntropyEnvProcess(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("Clock", func(t *testing.T) {
		tck.RunClockSuite(t, tck.ClockFixture{
			NewClock:      func(*testing.T) ports.Clock { return sys.NewSystemClock() },
			SleepDuration: 15 * time.Millisecond,
		})
	})

	t.Run("Entropy", func(t *testing.T) {
		tck.RunEntropySuite(t, func(*testing.T) ports.Entropy { return sys.NewCryptoEntropy() })
	})

	t.Run("Env", func(t *testing.T) {
		t.Setenv("XOPS_TCK_ENV_KEY", "xops-env-val")
		tck.RunEnvSuite(t, tck.EnvFixture{
			NewEnv:         func(*testing.T) ports.EnvPort { return sys.NewSystemEnv() },
			KnownKey:       "XOPS_TCK_ENV_KEY",
			ExpectedValue:  "xops-env-val",
			MissingKey:     "XOPS_TCK_ENV_MISSING_KEY_NEVER_SET",
			ExpectIdentity: true,
		})
	})

	t.Run("Process", func(t *testing.T) {
		tck.RunProcessSuite(t, tck.ProcessFixture{
			NewProcess:    func(*testing.T) ports.ProcessPort { return sys.NewSystemProcess() },
			EchoSpec:      mustHelperSpec(t, "echo", algebraic.None[uint64]()),
			FailSpec:      mustHelperSpec(t, "fail", algebraic.None[uint64]()),
			DialStdioSpec: mustHelperSpec(t, "stdio", algebraic.None[uint64]()),
		})
	})
}

// TestProcessOutputTruncation 验证 ProcessPort.Run 的输出字节硬上限截断与 Truncated 标记。
func TestProcessOutputTruncation(t *testing.T) {
	defer goleak.VerifyNone(t)
	proc := sys.NewSystemProcess()
	spec := mustHelperSpec(t, "flood", algebraic.Some(uint64(128)))
	res, err := proc.Run(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("Process.Run(flood) 失败: %v", err)
	}
	if !res.Succeeded() || !res.Truncated() || len(res.Stdout()) != 128 {
		t.Fatalf("截断结果异常: ok=%v trunc=%v len=%d", res.Succeeded(), res.Truncated(), len(res.Stdout()))
	}
}

// TestProcessRunCancelWithPipeHoldingGrandchild 验证 Run 在子进程派生继承 stdout/stderr 的孙进程时，
// 等待孙进程确实就绪并持有管道句柄后触发取消，必须立即终止整棵进程树（Unix 进程组 + Windows Job Object）且返回 context.Canceled。
func TestProcessRunCancelWithPipeHoldingGrandchild(t *testing.T) {
	defer goleak.VerifyNone(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable 失败: %v", err)
	}
	readyPath := filepath.Join(t.TempDir(), "grandchild.ready")
	spec, err := ports.NewProcessSpec(ports.ProcessSpecInput{
		Command: exe,
		Args:    []string{"-test.run=^TestHelperProcess$"},
		Env: map[string]string{
			helperEnvModeKey: "grandchild-hold",
			helperReadyKey:   readyPath,
		},
	})
	if err != nil {
		t.Fatalf("NewProcessSpec 失败: %v", err)
	}

	proc := sys.NewSystemProcess()
	runCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var (
		runErr     error
		canceledAt time.Time
		returnedAt time.Time
		readySeen  bool
		waitDoneCh = make(chan struct{})
	)
	if err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			defer close(waitDoneCh)
			_, runErr = proc.Run(runCtx, spec, nil)
			returnedAt = time.Now()
			return nil
		}); gErr != nil {
			return gErr
		}
		return waitFileThenCancel(runCtx, waitDoneCh, readyPath, func() {
			readySeen = true
			canceledAt = time.Now()
			cancel()
		})
	}); err != nil {
		t.Fatalf("RunWait 失败: %v", err)
	}
	if !readySeen {
		t.Fatalf("孙进程未写出就绪信号即退出: runErr=%v", runErr)
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("Process.Run(grandchild-hold) = %v, 期望 context.Canceled", runErr)
	}
	if elapsed := returnedAt.Sub(canceledAt); elapsed > 5*time.Second {
		t.Fatalf("取消含孙进程子进程耗时过长 (%v)，疑似管道句柄未及时回收", elapsed)
	}
}

func waitFileThenCancel(ctx context.Context, done <-chan struct{}, path string, onReady func()) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			onReady()
			return nil
		}
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// TestProcessDialStdioSurvivesDialContextCancel 验证 DialStdio 返回的 net.Conn 在拨号阶段 ctx 取消后仍保持存活，
// 直至显式调用 conn.Close() 才终止并回收子进程树。
func TestProcessDialStdioSurvivesDialContextCancel(t *testing.T) {
	defer goleak.VerifyNone(t)
	proc := sys.NewSystemProcess()
	dialCtx, cancel := context.WithCancel(context.Background())
	conn, err := proc.DialStdio(dialCtx, mustHelperSpec(t, "stdio", algebraic.None[uint64]()))
	if err != nil {
		cancel()
		t.Fatalf("DialStdio 失败: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// 拨号成功后立即取消拨号上下文，已建立的 stdio 连接必须继续正常收发。
	cancel()
	msg := []byte("alive-after-dial-cancel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("dialCtx 取消后 Write 失败: %v", err)
	}
	reply := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("dialCtx 取消后 Read 失败: %v", err)
	}
	if !bytes.Equal(reply, msg) {
		t.Fatalf("回显失配: got=%q want=%q", string(reply), string(msg))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("conn.Close 失败: %v", err)
	}
}

type blockingStreamReader struct {
	unblockCh chan struct{}
	once      sync.Once
}

func newBlockingStreamReader() *blockingStreamReader {
	return &blockingStreamReader{unblockCh: make(chan struct{})}
}

func (b *blockingStreamReader) Read([]byte) (int, error) {
	<-b.unblockCh
	return 0, io.EOF
}

func (b *blockingStreamReader) Unblock() {
	b.once.Do(func() { close(b.unblockCh) })
}

// TestTCKTerminalInteractiveAndNonInteractive 验证 TerminalPort 与 TerminalHandle.Relay 通过全量 TCK 套件且零泄漏。
func TestTCKTerminalInteractiveAndNonInteractive(t *testing.T) {
	defer goleak.VerifyNone(t)

	szBase, err := ports.NewTerminalSize(100, 32)
	if err != nil {
		t.Fatalf("NewTerminalSize 失败: %v", err)
	}
	szResize, err := ports.NewTerminalSize(132, 43)
	if err != nil {
		t.Fatalf("NewTerminalSize(resize) 失败: %v", err)
	}

	t.Run("InteractiveStreamTCK", func(t *testing.T) {
		tck.RunTerminalSuite(t, tck.TerminalFixture{
			NewTerminal: func(t *testing.T) ports.TerminalPort {
				resizeCh := make(chan ports.TerminalSize, 2)
				resizeCh <- szResize
				close(resizeCh)
				var out bytes.Buffer
				term, tErr := sys.NewStreamTerminal(sys.StreamTerminalSpec{
					In:          strings.NewReader("local-input-ok"),
					Out:         &out,
					Interactive: true,
					SizeFn:      func() (ports.TerminalSize, error) { return szBase, nil },
					ResizeCh:    resizeCh,
				})
				if tErr != nil {
					t.Fatalf("NewStreamTerminal 失败: %v", tErr)
				}
				return term
			},
			NewBlockingInputTerminal: func(t *testing.T) ports.TerminalPort {
				blk := newBlockingStreamReader()
				var out bytes.Buffer
				term, tErr := sys.NewStreamTerminal(sys.StreamTerminalSpec{
					In:           blk,
					Out:          &out,
					Interactive:  true,
					SizeFn:       func() (ports.TerminalSize, error) { return szBase, nil },
					UnblockInput: blk.Unblock,
				})
				if tErr != nil {
					t.Fatalf("NewStreamTerminal(blocking) 失败: %v", tErr)
				}
				return term
			},
			ExpectInteractive:  true,
			ExpectedRelayInput: "local-input-ok",
			ExpectResizeCount:  1,
		})
	})

	t.Run("NonInteractiveStreamTCK", func(t *testing.T) {
		tck.RunTerminalSuite(t, tck.TerminalFixture{
			NewTerminal: func(t *testing.T) ports.TerminalPort {
				term, tErr := sys.NewStreamTerminal(sys.StreamTerminalSpec{Interactive: false})
				if tErr != nil {
					t.Fatalf("NewStreamTerminal(non-interactive) 失败: %v", tErr)
				}
				return term
			},
			ExpectInteractive: false,
		})
	})
}

// TestZeroValuesFailClosed 验证 sys 包所有导出适配器的零值均严格失败关闭。
func TestZeroValuesFailClosed(t *testing.T) {
	defer goleak.VerifyNone(t)
	var zeroClk sys.SystemClock
	if !zeroClk.Now().IsZero() || zeroClk.Sleep(context.Background(), time.Millisecond) == nil {
		t.Fatal("零值 SystemClock 必须失败关闭")
	}
	var zeroEnt sys.CryptoEntropy
	var buf [8]byte
	if _, err := zeroEnt.Read(buf[:]); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 CryptoEntropy.Read = %v, 期望 ErrInvalidArgument", err)
	}
	var zeroEnv sys.SystemEnv
	if _, ok := zeroEnv.LookupEnv("PATH"); ok || zeroEnv.Environ() != nil {
		t.Fatal("零值 SystemEnv 必须失败关闭")
	}
	if _, err := zeroEnv.LookupLocalIdentity(); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 LookupLocalIdentity = %v, 期望 ErrInvalidArgument", err)
	}
	var zeroProc sys.SystemProcess
	if _, err := zeroProc.Run(context.Background(), mustHelperSpec(t, "echo", algebraic.None[uint64]()), nil); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 SystemProcess.Run = %v, 期望 ErrInvalidArgument", err)
	}
	var zeroTerm sys.Terminal
	if zeroTerm.IsInteractive() {
		t.Fatal("零值 Terminal.IsInteractive 必须为 false")
	}
	if v, err := zeroTerm.CanSuspendProcessGroup(); v != security.VerdictDeny || !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("零值 CanSuspendProcessGroup = (%v, %v), 期望 (VerdictDeny, ErrInvalidArgument)", v, err)
	}
}
