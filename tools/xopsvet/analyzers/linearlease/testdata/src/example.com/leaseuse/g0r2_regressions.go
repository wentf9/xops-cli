package leaseuse

import (
	"context"
	"slices"

	"example.com/leasedef"
)

var g0r2Escaped leasedef.Session

// badG0R2SyncClosureEscape 验证同步闭包/IIFE 回写外层变量逃逸必须拦截（LL-1）。
func badG0R2SyncClosureEscape(p leasedef.Pool) {
	_ = p.WithLease(context.Background(), func(ctx context.Context, sess leasedef.Session) error {
		leasedef.RunSync(func() {
			g0r2Escaped = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		})
		func() {
			g0r2Escaped = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		}()
		return nil
	})
}

// badG0R2NamedReturnDeferEscape 验证 defer 闭包向祖先具名返回值逃逸必须拦截（LL-2）。
func badG0R2NamedReturnDeferEscape(p leasedef.Pool) (out leasedef.Session) {
	_ = p.WithLease(context.Background(), func(ctx context.Context, sess leasedef.Session) error {
		defer func() {
			out = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		}()
		return nil
	})
	return out
}

// badG0R2PanicAndGoRecv 验证 panic(sess) 与 go sess.Close() 必须拦截（LL-3 / LL-6）。
func badG0R2PanicAndGoRecv(p leasedef.Pool) {
	_ = p.WithLease(context.Background(), func(ctx context.Context, sess leasedef.Session) error {
		go sess.Close() // want "白名单包 core/conc 之外禁止使用裸 go 语句" "禁止在 go 语句中调用捕获了 //xops:borrowed 变量的闭包"
		panic(sess)     // want "禁止将 //xops:borrowed 借用变量传入 panic"
	})
}

// badG0R2DirectIterSeqAndPhiClosure 验证直接调用 slices.Values 与分支 Phi 闭包逃逸（LL-4 / LL-5）。
func badG0R2DirectIterSeqAndPhiClosure(p leasedef.Pool, cond bool) {
	_ = p.WithSliceLease(context.Background(), func(ctx context.Context, hs []leasedef.Session) error {
		slices.Values(hs)(func(s leasedef.Session) bool {
			g0r2Escaped = s // want "禁止将 //xops:borrowed 借用变量逃逸"
			return false
		})
		var fn func()
		if cond {
			fn = func() {
				g0r2Escaped = hs[0] // want "禁止将 //xops:borrowed 借用变量逃逸"
			}
		} else {
			fn = func() {}
		}
		leasedef.RunSync(fn)
		return nil
	})
}

// badG0R2UnknownCallback 验证向 //xops:borrowed 传入未知外部回调变量必须 fail-closed 拦截（LL-7）。
func badG0R2UnknownCallback(p leasedef.Pool, cb func(context.Context, leasedef.Session) error) error {
	return p.WithLease(context.Background(), cb) // want "禁止将无法静态验证的未知函数或回调传入 //xops:borrowed 高阶函数"
}
