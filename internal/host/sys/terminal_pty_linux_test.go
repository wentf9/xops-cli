//go:build linux

package sys_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/host/sys"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

func openLinuxPTYPair(t *testing.T) (master, slave *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("当前容器环境无法打开 /dev/ptmx，跳过真实 PTY 测试: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = ptmx.Close()
		t.Fatalf("解锁 Linux PTY 从端失败: %v", err)
	}
	ptsNum, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = ptmx.Close()
		t.Fatalf("查询 Linux PTY 编号失败: %v", err)
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptsNum)
	pts, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = ptmx.Close()
		t.Fatalf("打开 %s 失败: %v", slavePath, err)
	}
	t.Cleanup(func() {
		_ = pts.Close()
		_ = ptmx.Close()
	})
	return ptmx, pts
}

// TestLinuxRealPTYRawModeRestoreAndCancelableRelay 验证 Linux 真实 PTY 原始模式切换/无条件恢复、窗口尺寸查询与远端先 EOF 零泄漏退出。
func TestLinuxRealPTYRawModeRestoreAndCancelableRelay(t *testing.T) {
	defer goleak.VerifyNone(t)
	master, slave := openLinuxPTYPair(t)

	wantWS := &unix.Winsize{Col: 112, Row: 38}
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, wantWS); err != nil {
		t.Fatalf("设置 PTY 窗口尺寸失败: %v", err)
	}
	origTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("读取 PTY 初始 termios 失败: %v", err)
	}

	term, err := sys.NewFileTerminal(slave, slave)
	if err != nil {
		t.Fatalf("NewFileTerminal(slave) 失败: %v", err)
	}
	if !term.IsInteractive() {
		t.Fatal("真实 Linux PTY 从端必须被识别为交互式终端")
	}
	sz, err := term.Size()
	if err != nil || sz.Cols() != 112 || sz.Rows() != 38 {
		t.Fatalf("Size() = (%v, %v), 期望 112x38", sz, err)
	}

	var remoteIn bytes.Buffer
	err = term.WithRawTerminal(context.Background(), func(h ports.TerminalHandle) error {
		inRaw, rErr := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if rErr != nil {
			return rErr
		}
		if inRaw.Lflag&(unix.ECHO|unix.ICANON) != 0 {
			t.Fatalf("WithRawTerminal 内未进入原始模式: lflag=%#x", inRaw.Lflag)
		}
		// 远端立即 EOF 时，阻塞在真实 PTY slave poll 上的本地读协程必须被 self-pipe 立即唤醒且零泄漏。
		return h.Relay(context.Background(), &remoteIn, strings.NewReader("pty-remote-eof"), nil)
	})
	if err != nil {
		t.Fatalf("WithRawTerminal / Relay(PTY) 失败: %v", err)
	}

	afterTermios, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatalf("读取恢复后 termios 失败: %v", err)
	}
	if afterTermios.Iflag != origTermios.Iflag || afterTermios.Oflag != origTermios.Oflag || afterTermios.Lflag != origTermios.Lflag {
		t.Fatalf("WithRawTerminal 退出后未完整恢复 termios 状态: before=%+v after=%+v", origTermios, afterTermios)
	}
}
