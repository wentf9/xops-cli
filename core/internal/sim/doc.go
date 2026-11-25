// Package sim 提供 XOps v2 全部出站端口（core/ports）的 100% 确定性内存仿真与故障注入引擎（Plan P2-T6）。
//
// 架构约束：零生产可达（xopsvet/archbound）；零 time.Now/time.Sleep/裸 go/crypto/rand/path/filepath/nolint；
// SimVault 采用 AES-256-GCM 静态密文存储；全部作用域借用句柄均带运行时失效哨兵。
package sim

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/internal/sim/memtree"
	"github.com/wentf9/xops-cli/core/ports"
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
//
//xops:opaque
//xops:failclosed
type FaultInjector struct {
	mu          sync.Mutex
	initialized bool
	rng         *SeededRand
	rules       map[string]func(call uint64) error
	counts      map[string]uint64
}

// NewFaultInjector 构造确定性故障注入器（rng 仅在使用 SetRate 时需要，可为 nil）。
func NewFaultInjector(rng *SeededRand) *FaultInjector {
	return &FaultInjector{initialized: true, rng: rng, rules: make(map[string]func(uint64) error), counts: make(map[string]uint64)}
}
func (f *FaultInjector) lockDo(fn func()) {
	if f != nil && f.initialized {
		f.mu.Lock()
		fn()
		f.mu.Unlock()
	}
}

// SetHook / SetSticky / InjectOnce / SetRate / Clear / ClearAll / Count / Check 管理与评估故障规则。
func (f *FaultInjector) SetHook(op string, fn func(call uint64) error) {
	f.lockDo(func() {
		if fn == nil {
			delete(f.rules, op)
		} else {
			f.rules[op] = fn
		}
	})
}
func (f *FaultInjector) Clear(op string)            { f.SetHook(op, nil) }
func (f *FaultInjector) ClearAll()                  { f.lockDo(func() { clear(f.rules) }) }
func (f *FaultInjector) Count(op string) (n uint64) { f.lockDo(func() { n = f.counts[op] }); return n }
func (f *FaultInjector) SetSticky(op string, err error) {
	if err == nil {
		f.Clear(op)
		return
	}
	f.SetHook(op, func(uint64) error { return err })
}
func (f *FaultInjector) InjectOnce(op string, err error) {
	if err == nil {
		return
	}
	var fired atomic.Bool
	f.SetHook(op, func(uint64) error {
		if fired.CompareAndSwap(false, true) {
			return err
		}
		return nil
	})
}
func (f *FaultInjector) SetRate(op string, num, den int, err error) {
	if num <= 0 || den <= 0 || err == nil {
		return
	}
	f.SetHook(op, func(uint64) error {
		if f.rng != nil && f.rng.Chance(num, den) {
			return err
		}
		return nil
	})
}
func (f *FaultInjector) Check(op string) error {
	var call uint64
	var rule func(uint64) error
	f.lockDo(func() { f.counts[op]++; call, rule = f.counts[op], f.rules[op] })
	if rule != nil {
		return rule(call)
	}
	return nil
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

// Now / Since / PendingTimers / Advance / AdvanceToNext / NewTimer / Sleep / WaitPending 驱动虚拟时钟。
func (c *SimClock) Now() time.Time {
	if !c.ok() {
		return time.Time{}
	}
	return c.core.Now()
}
func (c *SimClock) Since(t time.Time) time.Duration {
	if !c.ok() {
		return 0
	}
	return c.core.Since(t)
}
func (c *SimClock) PendingTimers() int {
	if !c.ok() {
		return 0
	}
	return c.core.PendingTimers()
}
func (c *SimClock) Advance(d time.Duration) {
	if c.ok() {
		c.core.Advance(d)
	}
}
func (c *SimClock) AdvanceToNext() (time.Duration, bool) {
	if !c.ok() {
		return 0, false
	}
	return c.core.AdvanceToNext()
}
func (c *SimClock) NewTimer(d time.Duration) ports.Timer {
	if !c.ok() {
		return &memtree.ClockTimer{}
	}
	return c.core.NewTimer(d)
}
func (c *SimClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := c.check(ctx, ""); err != nil || d <= 0 {
		return err
	}
	tm := c.core.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tm.C():
		return nil
	}
}
func (c *SimClock) WaitPending(ctx context.Context, n int) error {
	if err := c.check(ctx, ""); err != nil {
		return err
	}
	return c.core.WaitPending(ctx, n)
}
