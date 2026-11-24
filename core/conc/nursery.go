package conc

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
)

// errScopeCompleted 是 RunScoped 正常退出时注入给内部上下文的私有取消原因哨兵。
// 该哨兵绝不向调用方泄露，仅用于在 filterExpectedScopeCancel 中区分 RunScoped 正常收尾与真实故障或父上下文取消。
var errScopeCompleted = errors.New("conc: scope completed")

// singleUnwrapper 匹配标准库单值错误包装接口（如 *os.PathError、*AuditPostWriteError、fmt.Errorf("%w", ...)）。
// 嵌入 error 接口以配合 errors.AsType 做类型安全匹配，同时避免直接对 error 做类型断言触发 errorlint 告警。
type singleUnwrapper interface {
	error
	Unwrap() error
}

// multiUnwrapper 匹配标准库多值错误组合接口（如 errors.Join、多 %w 的 fmt.Errorf）。
// 嵌入 error 接口以配合 errors.AsType 做类型安全匹配，同时避免直接对 error 做类型断言触发 errorlint 告警。
type multiUnwrapper interface {
	error
	Unwrap() []error
}

// PanicError 封装受监督协程或作用域闭包中捕获的 panic 值与完整堆栈信息。
// 通过 Unwrap 返回 ErrTaskPanicked，便于上层使用 errors.Is 统一识别 panic 故障。
//
//xops:opaque
type PanicError struct {
	value any
	stack []byte
}

func newPanicError(value any, stack []byte) *PanicError {
	copied := make([]byte, len(stack))
	copy(copied, stack)
	return &PanicError{
		value: value,
		stack: copied,
	}
}

// Error 返回包含 panic 值与堆栈摘要的格式化错误文本。
func (e *PanicError) Error() string {
	if e == nil {
		return ErrTaskPanicked.Error()
	}
	if len(e.stack) == 0 {
		return fmt.Sprintf("%s: %v", ErrTaskPanicked.Error(), e.value)
	}
	return fmt.Sprintf("%s: %v\n%s", ErrTaskPanicked.Error(), e.value, string(e.stack))
}

// Unwrap 返回哨兵错误 ErrTaskPanicked，支持 errors.Is 匹配。
func (e *PanicError) Unwrap() error {
	return ErrTaskPanicked
}

// Value 返回原始 panic 值（若接收者为 nil 则返回 nil）。
func (e *PanicError) Value() any {
	if e == nil {
		return nil
	}
	return e.value
}

// Stack 返回捕获 panic 时的调用栈副本（若接收者为 nil 则返回 nil）。
func (e *PanicError) Stack() []byte {
	if e == nil || len(e.stack) == 0 {
		return nil
	}
	copied := make([]byte, len(e.stack))
	copy(copied, e.stack)
	return copied
}

// Nursery 是结构化并发监督作用域。
// 其零值未初始化且所有方法均对零值与 nil 失败关闭；一旦调用 Wait、Close 或作用域退场收尾，
// closed 标志会在持有互斥锁与 wg.Add(1) 同一临界区内锁定，防止 wg.Add 与 wg.Wait 竞态并阻断新增任务。
//
//xops:opaque
//xops:failclosed
type Nursery struct {
	parentCtx   context.Context
	ctx         context.Context
	cancel      context.CancelCauseFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	initialized bool
	closed      bool
	errs        []error
}

// NewNursery 创建并初始化一个绑定到 parent 上下文的 Nursery。
// 若 parent 为 nil，则直接失败关闭并返回 ErrNilContext。
func NewNursery(parent context.Context) (*Nursery, error) {
	if parent == nil {
		return nil, ErrNilContext
	}
	ctx, cancel := context.WithCancelCause(parent)
	return &Nursery{
		parentCtx:   parent,
		ctx:         ctx,
		cancel:      cancel,
		initialized: true,
	}, nil
}

// RunWait 以 Fork-Join 语义在结构化并发作用域内同步执行 fn：
//   - 当 fn 正常返回 nil 时，锁定 Nursery 并等待所有已派生子协程自然执行完毕，随后释放上下文取消绑定；
//   - 当 fn 返回错误、发生 panic 或任一子协程出错/panic 时，立即取消作用域上下文并等待全部子协程收敛退出，
//     最后聚合返回全部错误。
//
//xops:syncclosure
func RunWait(ctx context.Context, fn func(ctx context.Context, n *Nursery) error) error {
	n, err := NewNursery(ctx)
	if err != nil {
		return err
	}
	if fn == nil {
		n.cancel(ErrNilTask)
		return ErrNilTask
	}
	return n.runWaitScope(fn)
}

// RunScoped 以守护/Watchdog 作用域语义同步执行 fn：
//   - 无论 fn 正常返回 nil、返回错误还是发生 panic，退出前一律先取消作用域上下文再等待全部子协程退出；
//   - 当 fn 正常返回 nil 且父上下文未被取消时，RunScoped 会以私有哨兵取消内部上下文，
//     仅过滤子协程因预期退场而返回的裸取消错误（context.Canceled / context.Cause(ctx) 及其 errors.Join 组合），
//     任何携带操作语义的单值包装故障（如 *os.PathError、fmt.Errorf("flush: %w", ...)）均 100% 保留。
//
//xops:syncclosure
func RunScoped(ctx context.Context, fn func(ctx context.Context, n *Nursery) error) error {
	n, err := NewNursery(ctx)
	if err != nil {
		return err
	}
	if fn == nil {
		n.cancel(ErrNilTask)
		return ErrNilTask
	}
	return n.runScoped(fn)
}

func (n *Nursery) runWaitScope(fn func(ctx context.Context, n *Nursery) error) error {
	fnErr, panicked := n.invokeScope(fn)
	if panicked {
		return n.Close()
	}
	if fnErr != nil {
		n.recordError(fnErr)
		n.Cancel(fnErr)
		return n.Close()
	}
	return n.Wait()
}

func (n *Nursery) runScoped(fn func(ctx context.Context, n *Nursery) error) error {
	fnErr, panicked := n.invokeScope(fn)
	if panicked {
		return n.Close()
	}
	if fnErr != nil {
		n.recordError(fnErr)
		n.Cancel(fnErr)
		return n.Close()
	}
	return n.closeCompleted()
}

func (n *Nursery) invokeScope(fn func(ctx context.Context, n *Nursery) error) (fnErr error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			pErr := newPanicError(r, debug.Stack())
			n.recordError(pErr)
			n.Cancel(pErr)
		}
	}()
	fnErr = fn(n.Context(), n)
	return fnErr, false
}

// Context 返回 Nursery 绑定的上下文。
// 若 Nursery 为 nil 或未初始化，则返回已预先取消的失败关闭上下文。
func (n *Nursery) Context() context.Context {
	if n == nil || !n.initialized || n.ctx == nil {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(ErrNurseryNotInitialized)
		return ctx
	}
	return n.ctx
}

// Go 在 Nursery 监督下异步启动一个子协程执行 fn。
// 任意子任务返回非预期错误或发生 panic 时，都会记录错误并立即取消 Nursery 上下文以通知其余兄弟协程收敛退出。
// 注意：Go 为异步派生入口，故意不以 With 开头且不标注 syncclosure，以便 linearlease 拦截借用资源逃逸。
func (n *Nursery) Go(fn func(ctx context.Context) error) error {
	if n == nil || !n.initialized {
		return ErrNurseryNotInitialized
	}
	if fn == nil {
		return ErrNilTask
	}

	// 在同一把锁下原子校验 closed 并完成 wg.Add(1)，彻底消除与 wg.Wait 的并发竞态。
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return ErrNurseryClosed
	}
	n.wg.Add(1)
	n.mu.Unlock()

	go n.runChild(fn)
	return nil
}

func (n *Nursery) runChild(fn func(ctx context.Context) error) {
	defer n.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			pErr := newPanicError(r, debug.Stack())
			n.recordError(pErr)
			n.cancel(pErr)
		}
	}()

	if err := fn(n.ctx); err != nil {
		if filtered := n.filterExpectedScopeCancel(err); filtered != nil {
			n.recordError(filtered)
			n.cancel(filtered)
		}
	}
}

// filterExpectedScopeCancel 仅在 RunScoped 正常退场（内部上下文取消原因为 errScopeCompleted 且父 ctx 未取消）
// 且子协程返回裸预期取消错误（或其 errors.Join 组合）时返回 nil；
// 任何具名单值包装故障（如 *os.PathError、*AuditPostWriteError、fmt.Errorf("flush: %w", ...)）均 100% 保留。
func (n *Nursery) filterExpectedScopeCancel(err error) error {
	if err == nil {
		return nil
	}
	if !errors.Is(context.Cause(n.ctx), errScopeCompleted) {
		return err
	}
	if n.parentCtx != nil && n.parentCtx.Err() != nil {
		return err
	}
	if nonScopeCancelLeaf(err) == nil {
		return nil
	}
	return err
}

// nonScopeCancelLeaf 递归检查 err 是否完全由 RunScoped 预期退场裸取消叶子构成；
// 若存在任意单值包装错误、空多值包装或非预期故障，则返回非 nil 原错误以禁止吞噬。
func nonScopeCancelLeaf(err error) error {
	if err == nil {
		return nil
	}
	// 先检查单值 Unwrap() error 包装（含嵌套在 errors.Join 内的单值包装）：
	// 一旦命中即视为携带操作语义的真实故障，直接原样保留，绝不递归吞噬。
	if _, ok := errors.AsType[singleUnwrapper](err); ok {
		return err
	}
	if multi, ok := errors.AsType[multiUnwrapper](err); ok {
		return checkMultiScopeCancel(err, multi.Unwrap())
	}
	// 裸叶子错误：使用 errors.Is 满足 errorlint（无需任何静态检查抑制注释），同时覆盖 context.Canceled
	// 与子协程返回 context.Cause(childCtx) 得到的 errScopeCompleted（绝不向外泄露未导出哨兵）。
	if errors.Is(err, context.Canceled) || errors.Is(err, errScopeCompleted) {
		return nil
	}
	return err
}

func checkMultiScopeCancel(orig error, errs []error) error {
	if len(errs) == 0 {
		return orig
	}
	for _, sub := range errs {
		if sub == nil || nonScopeCancelLeaf(sub) != nil {
			return orig
		}
	}
	return nil
}

// Cancel 以指定原因主动取消 Nursery 上下文；若未初始化或 nil 则安全无操作。
func (n *Nursery) Cancel(cause error) {
	if n == nil || !n.initialized || n.cancel == nil {
		return
	}
	n.cancel(cause)
}

// Wait 锁定 Nursery 禁止再调用 Go，等待当前已启动的全部子协程自然退出，
// 随后释放与父上下文的取消绑定并返回全部子任务聚合错误。
func (n *Nursery) Wait() error {
	if n == nil || !n.initialized {
		return ErrNurseryNotInitialized
	}
	n.markClosed()
	n.wg.Wait()
	n.cancel(nil)
	return n.joinedErrors()
}

// Close 立即锁定 Nursery 并取消上下文，等待全部子协程退出后返回聚合错误。
func (n *Nursery) Close() error {
	if n == nil || !n.initialized {
		return ErrNurseryNotInitialized
	}
	n.markClosed()
	n.cancel(nil)
	n.wg.Wait()
	return n.joinedErrors()
}

// closeCompleted 专供 RunScoped 正常退出路径调用：
// 先锁定拒绝新任务，再以私有哨兵 errScopeCompleted 触发退场取消，等待全部后台常驻协程退出并聚合真实错误。
func (n *Nursery) closeCompleted() error {
	n.markClosed()
	n.cancel(errScopeCompleted)
	n.wg.Wait()
	return n.joinedErrors()
}

func (n *Nursery) markClosed() {
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
}

func (n *Nursery) recordError(err error) {
	if err == nil {
		return
	}
	n.mu.Lock()
	n.errs = append(n.errs, err)
	n.mu.Unlock()
}

func (n *Nursery) joinedErrors() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.errs) == 0 {
		return nil
	}
	return errors.Join(n.errs...)
}
