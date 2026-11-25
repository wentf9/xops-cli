package sys

import (
	"context"
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
)

// SystemClock 实现 ports.Clock，封装真实系统墙钟、单调耗时计算与可取消睡眠等待；零值恒无效。
//
//xops:opaque
//xops:failclosed
type SystemClock struct {
	valid bool
}

// NewSystemClock 构造可用的真实系统时钟实例。
func NewSystemClock() *SystemClock { return &SystemClock{valid: true} }

// Now 返回当前真实时间；零值或 nil 接收者失败关闭返回零时刻。
func (c *SystemClock) Now() time.Time {
	if c == nil || !c.valid {
		return time.Time{}
	}
	return time.Now()
}

// Since 计算自 t 以来的单调耗时；零值或 nil 接收者失败关闭返回 0。
func (c *SystemClock) Since(t time.Time) time.Duration {
	if c == nil || !c.valid {
		return 0
	}
	return time.Since(t)
}

// NewTimer 创建绑定至标准库 time.Timer 的单次定时器；零值或 nil 接收者返回已停止的失败关闭定时器。
func (c *SystemClock) NewTimer(d time.Duration) ports.Timer {
	if c == nil || !c.valid {
		return &systemTimer{}
	}
	return &systemTimer{timer: time.NewTimer(max(d, 0))}
}

// Sleep 在 ctx 取消控制下阻塞等待时长 d，期间 ctx 取消立即停止定时器并返回 ctx.Err()。
func (c *SystemClock) Sleep(ctx context.Context, d time.Duration) error {
	if c == nil || !c.valid {
		return fmt.Errorf("%w: SystemClock 未初始化", ports.ErrInvalidArgument)
	}
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C:
		return nil
	}
}

type systemTimer struct {
	timer *time.Timer
}

func (t *systemTimer) C() <-chan time.Time {
	if t == nil || t.timer == nil {
		return nil
	}
	return t.timer.C
}

func (t *systemTimer) Stop() bool {
	if t == nil || t.timer == nil {
		return false
	}
	return t.timer.Stop()
}

func (t *systemTimer) Reset(d time.Duration) bool {
	if t == nil || t.timer == nil {
		return false
	}
	return t.timer.Reset(max(d, 0))
}
