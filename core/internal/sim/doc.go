// Package sim 提供 XOps v2 全部出站端口（core/ports）的 100% 确定性内存仿真与故障注入引擎（Plan P2-T6）。
//
// 架构约束：零生产可达（xopsvet/archbound）；零 time.Now/time.Sleep/裸 go/crypto/rand/path/filepath/nolint；
// SimVault 采用 AES-256-GCM 静态密文存储；全部作用域借用句柄均带运行时失效哨兵。
package sim

import (
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
	"slices"
	"sync"
	"time"
)

// 仿真器导出的不可变哨兵错误。
var (
	ErrSimNotInitialized = errors.New("sim: 仿真适配器未初始化")
	ErrFaultInjected     = errors.New("sim: 命中确定性故障注入规则")
	ErrSimulatedENOSPC   = errors.New("sim: 模拟磁盘空间不足 (ENOSPC)")
	ErrSimulatedCrash    = errors.New("sim: 模拟进程 SIGKILL 突发崩溃")
)

// DefaultBaseTime 返回默认确定性 UTC 基准时刻（2026-05-01T12:00:00Z）。
func DefaultBaseTime() time.Time { return time.Date(2026, time.May, 1, 12, 0, 0, 0, time.UTC) }
func checkCtx(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	return ctx.Err()
}
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// FaultInjector 是面向全部仿真端口的并发安全确定性故障注入器（常驻/单次/概率/自定义钩子）。
type FaultInjector = memtree.FaultInjector

// NewFaultInjector 构造确定性故障注入器（rng 仅在使用 SetRate 时需要，可为 nil）。
func NewFaultInjector(rng *SeededRand) *FaultInjector {
	var chance func(int, int) bool
	if rng != nil {
		chance = rng.Chance
	}
	return memtree.NewFaultInjector(chance)
}

// simBase 封装仿真适配器共享的初始化门控、互斥锁与故障注入器（正门控 initialized 满足 failclosed）。
type simBase struct {
	mu          sync.Mutex
	initialized bool
	faults      *FaultInjector
}

func newSimBase(rng *SeededRand) simBase {
	return simBase{initialized: true, faults: NewFaultInjector(rng)}
}
func (b *simBase) ok() bool { return b != nil && b.initialized }
func (b *simBase) Faults() *FaultInjector {
	if b.ok() {
		return b.faults
	}
	return nil
}
func (b *simBase) withLock(fn func()) {
	if b.ok() {
		b.mu.Lock()
		fn()
		b.mu.Unlock()
	}
}
func withLockRet[T any](b *simBase, fallback T, fn func() T) T {
	if !b.ok() {
		return fallback
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return fn()
}
func (b *simBase) check(ctx context.Context, op string, valid ...bool) error {
	return b.checkFn(ctx, true, op, valid...)
}
func (b *simBase) checkFn(ctx context.Context, hasFn bool, op string, valid ...bool) error {
	if !b.ok() {
		return ErrSimNotInitialized
	}
	if err := checkCtx(ctx); err != nil {
		return err
	}
	if !hasFn {
		return ports.ErrNilCallback
	}
	if slices.Contains(valid, false) {
		return ports.ErrInvalidArgument
	}
	if op != "" {
		return b.faults.Check(op)
	}
	return nil
}

// SimClock 提供 100% 确定性并发安全虚拟时钟与定时器调度器（实现 ports.Clock，零 time.Sleep）。
//
//xops:opaque
//xops:failclosed
type SimClock struct {
	simBase
	core *memtree.ClockCore
}

// NewSimClock 构造从 start（零值默认 DefaultBaseTime）起步的虚拟时钟。
func NewSimClock(start time.Time) *SimClock {
	if start.IsZero() {
		start = DefaultBaseTime()
	}
	return &SimClock{simBase: newSimBase(nil), core: memtree.NewClockCore(start)}
}
func (c *SimClock) clockCore() *memtree.ClockCore {
	if c.ok() {
		return c.core
	}
	return nil
}

// Now / Since / PendingTimers / Advance / AdvanceToNext / NewTimer / Sleep / WaitPending 驱动虚拟时钟。
func (c *SimClock) Now() time.Time                       { return c.clockCore().Now() }
func (c *SimClock) Since(t time.Time) time.Duration      { return c.clockCore().Since(t) }
func (c *SimClock) PendingTimers() int                   { return c.clockCore().PendingTimers() }
func (c *SimClock) Advance(d time.Duration)              { c.clockCore().Advance(d) }
func (c *SimClock) AdvanceToNext() (time.Duration, bool) { return c.clockCore().AdvanceToNext() }
func (c *SimClock) NewTimer(d time.Duration) ports.Timer { return c.clockCore().NewTimer(d) }
func (c *SimClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := c.check(ctx, ""); err != nil {
		return err
	}
	return c.core.Sleep(ctx, d)
}
func (c *SimClock) WaitPending(ctx context.Context, n int) error {
	if err := c.check(ctx, ""); err != nil {
		return err
	}
	return c.core.WaitPending(ctx, n)
}
