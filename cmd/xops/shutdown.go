package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

const defaultShutdownGrace = 5 * time.Second

type shutdownEntry struct {
	stage string
	fn    func(context.Context) error
}

// shutdownStack 维护组合根按启动正序登记的资源关闭钩子，
// 并在停机期严格按 LIFO 逆序执行：
// Entry -> Engine/UseCases -> Pool -> Vault (RouterVault.Close) -> Store -> Audit -> Sys/Relay。
// 关闭过程受 sync.Once 幂等保护，使用剥离取消且带有限超时的上下文，并通过 errors.Join 聚合全部失败。
//
//xops:opaque
//xops:failclosed
type shutdownStack struct {
	mu      sync.Mutex
	entries []shutdownEntry
	timeout time.Duration
	onStage func(stage string)

	once     sync.Once
	closeErr error
	valid    bool
}

func newShutdownStack(timeout time.Duration) *shutdownStack {
	if timeout <= 0 {
		timeout = defaultShutdownGrace
	}
	return &shutdownStack{
		timeout: timeout,
		valid:   true,
	}
}

// Add 按资源初始化顺序登记阶段名与关闭闭包；停机时自动以严格逆序调用。
func (s *shutdownStack) Add(stage string, fn func(context.Context) error) {
	if s == nil || !s.valid || fn == nil {
		return
	}
	s.mu.Lock()
	s.entries = append(s.entries, shutdownEntry{stage: stage, fn: fn})
	s.mu.Unlock()
}

// Close 幂等逆序关闭全部已登记阶段；若 ctx 已取消或无截止期限，则以剥离取消的有限超时上下文收尾。
func (s *shutdownStack) Close(ctx context.Context) error {
	if s == nil || !s.valid {
		return nil
	}
	s.once.Do(func() {
		shutCtx, cancel := deriveShutdownContext(ctx, s.timeout)
		defer cancel()

		s.mu.Lock()
		items := slices.Clone(s.entries)
		hook := s.onStage
		s.mu.Unlock()

		var errs []error
		for i := len(items) - 1; i >= 0; i-- {
			item := items[i]
			if hook != nil {
				hook(item.stage)
			}
			if err := item.fn(shutCtx); err != nil {
				errs = append(errs, fmt.Errorf("shutdown %s: %w", item.stage, err))
			}
		}
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func deriveShutdownContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		return context.WithTimeout(context.Background(), timeout)
	}
	base := context.WithoutCancel(parent)
	if dl, ok := parent.Deadline(); ok && parent.Err() == nil {
		return context.WithDeadline(base, dl)
	}
	return context.WithTimeout(base, timeout)
}
