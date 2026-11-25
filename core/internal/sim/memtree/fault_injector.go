package memtree

import (
	"sync"
	"sync/atomic"
)

// FaultInjector 是面向全部仿真端口的并发安全确定性故障注入器（常驻/单次/概率/自定义钩子）。
//
//xops:opaque
//xops:failclosed
type FaultInjector struct {
	mu          sync.Mutex
	initialized bool
	chanceFn    func(num, den int) bool
	rules       map[string]func(call uint64) error
	counts      map[string]uint64
}

// NewFaultInjector 构造确定性故障注入器（chanceFn 仅在使用 SetRate 时需要，可为 nil）。
func NewFaultInjector(chanceFn func(num, den int) bool) *FaultInjector {
	return &FaultInjector{
		initialized: true, chanceFn: chanceFn,
		rules: make(map[string]func(uint64) error), counts: make(map[string]uint64),
	}
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
		if f.chanceFn != nil && f.chanceFn(num, den) {
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
