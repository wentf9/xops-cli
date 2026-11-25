// Package sim 提供 XOps v2 全部出站端口（core/ports）的 100% 确定性内存仿真与故障注入引擎（Plan P2-T6）。
//
// 架构约束：零生产可达（xopsvet/archbound）；零 time.Now/time.Sleep/裸 go/crypto/rand/path/filepath/nolint；
// SimVault 采用 AES-256-GCM 静态密文存储；全部作用域借用句柄均带运行时失效哨兵。
package sim

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

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
func growBytes(buf []byte, size int64) []byte {
	if size <= int64(len(buf)) {
		return buf
	}
	out := make([]byte, size)
	copy(out, buf)
	return out
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

type simScopedReader struct {
	r       *bytes.Reader
	expired *atomic.Bool
}

func (sr *simScopedReader) Read(p []byte) (int, error) {
	if sr == nil || sr.expired == nil || sr.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	return sr.r.Read(p)
}
func withScopedReader(data []byte, fn func(io.Reader, int64) error) error {
	var expired atomic.Bool
	defer expired.Store(true)
	return fn(&simScopedReader{r: bytes.NewReader(data), expired: &expired}, int64(len(data)))
}

type simScopedWriter struct {
	buf        *bytes.Buffer
	expired    *atomic.Bool
	checkWrite func() error
}

func (sw *simScopedWriter) Write(p []byte) (int, error) {
	if sw == nil || sw.expired == nil || sw.expired.Load() {
		return 0, ports.ErrHandleExpired
	}
	if sw.checkWrite != nil {
		if err := sw.checkWrite(); err != nil {
			return 0, err
		}
	}
	return sw.buf.Write(p)
}

type simAddr string

func (a simAddr) Network() string { return "sim" }
func (a simAddr) String() string  { return string(a) }

type simMemListener struct {
	addr    simAddr
	expired *atomic.Bool
}

func (l *simMemListener) Addr() net.Addr { return l.addr }
func (l *simMemListener) Close() error {
	if l != nil && l.expired != nil && l.expired.Load() {
		return ports.ErrHandleExpired
	}
	return nil
}
func (l *simMemListener) Accept() (net.Conn, error) {
	return nil, firstErr(l.Close(), ports.ErrClosed)
}

type simEchoConn struct {
	mu     sync.Mutex
	addr   simAddr
	buf    bytes.Buffer
	closed bool
}

func (c *simEchoConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.EOF
	}
	return c.buf.Read(p)
}
func (c *simEchoConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, ports.ErrClosed
	}
	return c.buf.Write(p)
}
func (c *simEchoConn) Close() error                     { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *simEchoConn) LocalAddr() net.Addr              { return c.addr }
func (c *simEchoConn) RemoteAddr() net.Addr             { return c.addr }
func (c *simEchoConn) SetDeadline(time.Time) error      { return nil }
func (c *simEchoConn) SetReadDeadline(time.Time) error  { return nil }
func (c *simEchoConn) SetWriteDeadline(time.Time) error { return nil }

// SimClock 提供 100% 确定性并发安全虚拟时钟与定时器调度器（实现 ports.Clock，零 time.Sleep）。
//
//xops:opaque
//xops:failclosed
type SimClock struct {
	simBase
	now     time.Time
	nextSeq uint64
	timers  []*simTimer
	notify  chan struct{}
}

// NewSimClock 构造从 start（零值默认 DefaultBaseTime）起步的虚拟时钟。
func NewSimClock(start time.Time) *SimClock {
	if start.IsZero() {
		start = DefaultBaseTime()
	}
	return &SimClock{simBase: newSimBase(nil), now: start.UTC().Round(0), notify: make(chan struct{})}
}

// Now / Since / PendingTimers / Advance / AdvanceToNext / NewTimer / Sleep / WaitPending 驱动虚拟时钟。
func (c *SimClock) Now() time.Time {
	return withLockRet(&c.simBase, time.Time{}, func() time.Time { return c.now })
}
func (c *SimClock) Since(t time.Time) time.Duration {
	return withLockRet(&c.simBase, 0, func() time.Duration { return c.now.Sub(t) })
}
func (c *SimClock) PendingTimers() int {
	return withLockRet(&c.simBase, 0, func() int { return len(c.timers) })
}
func (c *SimClock) Advance(d time.Duration) {
	c.withLock(func() { c.now = c.now.Add(max(d, 0)); c.fireDueLocked() })
}
func (c *SimClock) AdvanceToNext() (delta time.Duration, ok bool) {
	c.withLock(func() {
		for _, tm := range c.timers {
			if tm.active && (!ok || tm.fireAt.Before(c.now.Add(delta))) {
				delta, ok = max(tm.fireAt.Sub(c.now), 0), true
			}
		}
		if ok {
			c.now = c.now.Add(delta)
			c.fireDueLocked()
		}
	})
	return delta, ok
}
func (c *SimClock) NewTimer(d time.Duration) ports.Timer {
	tm := &simTimer{clk: c, ch: make(chan time.Time, 1)}
	c.withLock(func() { c.armTimerLocked(tm, d) })
	return tm
}
func (c *SimClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := c.check(ctx, ""); err != nil || d <= 0 {
		return err
	}
	tm := c.NewTimer(d)
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
	for {
		c.mu.Lock()
		done, ch := len(c.timers) >= n, c.notify
		c.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (c *SimClock) armTimerLocked(tm *simTimer, d time.Duration) {
	c.nextSeq++
	tm.seq, tm.fireAt = c.nextSeq, c.now.Add(d)
	if d <= 0 {
		tm.active = false
		c.removeTimerLocked(tm)
		tm.ch <- c.now
	} else if tm.active = true; !slices.Contains(c.timers, tm) {
		c.timers = append(c.timers, tm)
	}
	close(c.notify)
	c.notify = make(chan struct{})
}
func (c *SimClock) fireDueLocked() {
	var due []*simTimer
	kept := c.timers[:0]
	for _, tm := range c.timers {
		if tm.active && !c.now.Before(tm.fireAt) {
			tm.active, due = false, append(due, tm)
		} else if tm.active {
			kept = append(kept, tm)
		}
	}
	clear(c.timers[len(kept):])
	c.timers = kept
	slices.SortFunc(due, func(a, b *simTimer) int {
		return cmp.Or(cmp.Compare(a.fireAt.UnixNano(), b.fireAt.UnixNano()), cmp.Compare(a.seq, b.seq))
	})
	for _, tm := range due {
		select {
		case tm.ch <- c.now:
		default:
		}
	}
}
func (c *SimClock) removeTimerLocked(t *simTimer) {
	if i := slices.Index(c.timers, t); i >= 0 {
		c.timers = slices.Delete(c.timers, i, i+1)
	}
}

type simTimer struct {
	clk    *SimClock
	seq    uint64
	ch     chan time.Time
	fireAt time.Time
	active bool
}

func (t *simTimer) C() <-chan time.Time        { return t.ch }
func (t *simTimer) Stop() bool                 { return t.mutate(false, 0) }
func (t *simTimer) Reset(d time.Duration) bool { return t.mutate(true, d) }
func (t *simTimer) mutate(reset bool, d time.Duration) bool {
	return t != nil && t.clk != nil && withLockRet(&t.clk.simBase, false, func() bool {
		was := t.active
		if !reset {
			t.active = false
			t.clk.removeTimerLocked(t)
			return was
		}
		select {
		case <-t.ch:
		default:
		}
		t.clk.armTimerLocked(t, d)
		return was
	})
}
