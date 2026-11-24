package conc

import "context"

// CtxMutex 是基于容量为 1 的通道实现的可取消互斥锁。
// 零值实例未初始化，对零值或 nil 调用 Lock/TryLock/WithLock 均会失败关闭，调用 Unlock 会触发 panic。
//
//xops:opaque
//xops:failclosed
type CtxMutex struct {
	ch          chan struct{}
	initialized bool
}

// NewCtxMutex 创建并初始化一个未加锁状态的 CtxMutex。
func NewCtxMutex() *CtxMutex {
	return &CtxMutex{
		ch:          make(chan struct{}, 1),
		initialized: true,
	}
}

// Lock 尝试获取互斥锁，直至加锁成功或 ctx 被取消/超时。
// 若 ctx 在调用前已取消，优先确定性返回 ctx.Err()；若未初始化或 ctx 为 nil 则失败关闭。
func (m *CtxMutex) Lock(ctx context.Context) error {
	if m == nil || !m.initialized || m.ch == nil {
		return ErrMutexNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryLock 尝试以非阻塞方式获取互斥锁；成功返回 true，未初始化或锁已被占用返回 false。
func (m *CtxMutex) TryLock() bool {
	if m == nil || !m.initialized || m.ch == nil {
		return false
	}
	select {
	case m.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Unlock 释放互斥锁。
// 若在未初始化实例或未加锁状态（含重复 Unlock）上调用，会以非阻塞方式立即 panic，避免永久挂起。
func (m *CtxMutex) Unlock() {
	if m == nil || !m.initialized || m.ch == nil {
		panic("conc: unlock of uninitialized CtxMutex")
	}
	select {
	case <-m.ch:
	default:
		panic("conc: unlock of unlocked CtxMutex")
	}
}

// WithLock 在获取互斥锁后同步执行 fn，并保证无论 fn 正常返回、返回错误还是 panic 都会释放锁。
//
//xops:syncclosure
func (m *CtxMutex) WithLock(ctx context.Context, fn func() error) error {
	if m == nil || !m.initialized || m.ch == nil {
		return ErrMutexNotInitialized
	}
	if fn == nil {
		return ErrNilTask
	}
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock()
	return fn()
}
