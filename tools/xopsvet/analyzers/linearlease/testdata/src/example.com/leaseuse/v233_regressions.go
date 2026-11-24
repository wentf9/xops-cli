package leaseuse

import (
	"context"
	"iter"
	"slices"

	"example.com/leasedef"
)

// v2.3.3 H4 / L2a / C4 / HIGH-1 专项对抗回归套件。

var (
	leakedSessPtr *leasedef.Session
	leakedChanVal leasedef.Session
)

// 未标注 //xops:syncclosure 的 With* 函数（v2.3.3 L2a 废除名字猜测，必须按非同步拦截）。
func WithOnClose(fn func()) {
	fnStorage = append(fnStorage, fn)
}

func evilIter(n int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for i := range n {
			if !yield(i) {
				return
			}
		}
	}
}

func copyOutBorrowed(dst, src []leasedef.Session) {
	copy(dst, src) // want "禁止通过 copy 将 //xops:borrowed 借用变量逃逸"
}

func badV233Regressions(
	ctx context.Context,
	p leasedef.Pool,
	//xops:borrowed
	hs []leasedef.Session,
	//xops:borrowed
	ch chan leasedef.Session,
) {
	// H4: append(borrowedSlice, ...) 与 comma-ok chan 接收
	leakedSlice = append(hs, nil) // want "禁止将 //xops:borrowed 借用变量逃逸"
	if v, ok := <-ch; ok {
		leakedChanVal = v // want "禁止将 //xops:borrowed 借用变量逃逸"
	}

	// C4: 同包辅助函数调用方非种子形参隔离
	copyOutBorrowed(leakedSlice, hs)

	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		// H4: Go 1.27 new(borrowed) 逃逸
		leakedSessPtr = new(sess) // want "禁止将 //xops:borrowed 借用变量逃逸"

		// L2a: 未标注 //xops:syncclosure 的 WithOnClose 必须拦截
		WithOnClose(func() { // want "禁止在非同步子闭包"
			_ = sess.Close()
		})

		// 显式 //xops:syncclosure 合法放行同步闭包
		leasedef.RunSync(func() {
			_ = sess.Exec(ctx, "sync-do-ok")
		})

		// HIGH-1 陷阱 4: 写后子切片别名反溯
		buf := make([]leasedef.Session, 4)
		leakedSlice = buf // want "禁止将 //xops:borrowed 借用变量逃逸"
		sub := buf[1:]
		sub[0] = sess

		// HIGH-1 陷阱 3: 标准库 slices.Values 放行，自定义 evilIter 拦截
		for s := range slices.Values(hs) {
			_ = s.Exec(ctx, "iter-ok")
		}
		for range evilIter(1) { // want "禁止在非标准库自定义迭代器中捕获"
			_ = sess.Close()
		}
		return nil
	})
}
