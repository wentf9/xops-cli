package leaseuse

import (
	"context"
	"time"

	"example.com/leasedef"
)

type CapInspect struct{}

type Nursery interface {
	Go(fn func())
	GoErr(fn func() error)
}

type Closer interface {
	Close() error
}

type Holder struct {
	S leasedef.Session
}

type myFunc func()

type mySessions []leasedef.Session

func getOuterSlice() []leasedef.Session {
	return leakedSlice
}

var (
	leakedSess   leasedef.Session
	leakedCloser Closer
	leakedBox    *leasedef.SecretBox
	leakedReader leasedef.Reader
	leakedFn     func() error
	leakedFnZero func()
	leakedAny    any
	leakedSlice  []leasedef.Session
	sessChan     chan leasedef.Session
	fnStorage    []func()
)

func registerAsync(fn func()) {
	fnStorage = append(fnStorage, fn)
}

func helperSync(ctx context.Context, s leasedef.Session) error {
	return s.Exec(ctx, "ok")
}

func okNestedBracketAndShadowing(ctx context.Context, p leasedef.Pool, v leasedef.Vault, fs leasedef.OperatorReadFS) error {
	var totalSize int64
	if err := fs.WithOperatorRead(ctx, "/tmp/a", func(r leasedef.Reader, size int64) error {
		totalSize = size
		buf := make([]byte, 4)
		_, err := r.Read(buf)
		return err
	}); err != nil {
		return err
	}
	_ = totalSize

	return leasedef.WithAuthorized[CapInspect](ctx, func(auth leasedef.Authorized[CapInspect]) error {
		_ = auth
		return p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
			defer sess.Close()
			defer func() {
				_ = sess.Exec(ctx, "defer")
			}()
			if err := func() error {
				return helperSync(ctx, sess)
			}(); err != nil {
				return err
			}
			localFn := func() error {
				return sess.Exec(ctx, "localfn")
			}
			if err := localFn(); err != nil {
				return err
			}
			defer localFn()
			fnOkOrig := func() error {
				return sess.Exec(ctx, "ok-alias")
			}
			fnOkAlias := fnOkOrig
			leasedef.RunSync(func() {
				_ = fnOkAlias()
			})
			func(x leasedef.Session) {
				_ = x.Exec(ctx, "iife-clean")
			}(sess)

			return v.WithSecret(ctx, "k", func(box *leasedef.SecretBox) error {
				// 参数同名遮蔽不应引起误报
				shadow := func(sess *leasedef.SecretBox) { _ = sess }
				shadow(box)
				return box.Use(func(plain []byte) error {
					var sum byte
					for _, b := range plain {
						sum += b
					}
					var err error
					leasedef.RunSync(func() {
						err = sess.Exec(ctx, sum)
					})
					return err
				})
			})
		})
	})
}

func okInlineBorrowedSliceRange( // want okInlineBorrowedSliceRange:"syncclosure,borrowed"
	fn func(
		//xops:borrowed
		plain []byte,
	),
) {
	_ = fn
}

func okNamedCallback(cb leasedef.BorrowedCallback) {
	leasedef.RunWithNamed(cb)
}

func badBareGo() {
	go func() {}() // want "禁止使用裸 go 语句"
}

func badEscapes(ctx context.Context, p leasedef.Pool, v leasedef.Vault, n Nursery, fs leasedef.OperatorReadFS) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"

		var localAlias leasedef.Session
		localAlias = sess
		leakedSess = localAlias // want "禁止将 //xops:borrowed 借用变量逃逸"

		var h Holder
		h.S = sess // want "禁止将 //xops:borrowed 借用变量写入结构体字段"

		_ = Holder{S: sess}                        // want "禁止将 //xops:borrowed 借用变量存入复合字面量"
		_ = []leasedef.Session{sess}               // want "禁止将 //xops:borrowed 借用变量存入复合字面量"
		_ = map[string]leasedef.Session{"k": sess} // want "禁止将 //xops:borrowed 借用变量存入复合字面量"
		leakedSlice = append(leakedSlice, sess)    // want "禁止通过 append 将 //xops:borrowed 借用变量存入切片"

		sessChan <- sess // want "禁止将 //xops:borrowed 借用变量发送至 channel"

		if c, ok := any(sess).(Closer); ok {
			leakedCloser = c // want "禁止将 //xops:borrowed 借用变量逃逸"
		}
		switch tv := any(sess).(type) {
		case Closer:
			leakedCloser = tv // want "禁止将 //xops:borrowed 借用变量逃逸"
		}

		n.Go(func() { // want "禁止在非同步子闭包"
			_ = sess.Close()
		})
		n.GoErr(sess.Close)   // want "禁止将 //xops:borrowed 接收者的未调用方法值转存或逃逸"
		leakedAny = sess.Exec // want "禁止将 //xops:borrowed 接收者的未调用方法值转存或逃逸"

		badClosure := func() error {
			return sess.Exec(ctx, "x")
		}
		n.Go(func() { // want "禁止在非同步子闭包"
			_ = badClosure()
		})
		leakedFn = badClosure  // want "禁止将 //xops:borrowed 借用变量逃逸"
		registerAsync(func() { // want "禁止在非同步子闭包"
			_ = sess
		})

		_ = v.WithSecret(ctx, "k", func(box *leasedef.SecretBox) error {
			leakedBox = box // want "禁止将 //xops:borrowed 借用变量逃逸"
			return nil
		})
		return nil
	})

	_ = fs.WithOperatorRead(ctx, "/tmp/b", func(r leasedef.Reader, size int64) error {
		leakedReader = r // want "禁止将 //xops:borrowed 借用变量逃逸"
		return nil
	})
}

func badOuterAliasInsideInner(ctx context.Context, p leasedef.Pool, v leasedef.Vault) error {
	return p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		var outerAlias leasedef.Session
		var outerBox *leasedef.SecretBox
		_ = v.WithSecret(ctx, "k", func(box *leasedef.SecretBox) error {
			outerAlias = sess
			outerBox = box // want "禁止将 //xops:borrowed 借用变量逃逸"
			return nil
		})
		leakedSess = outerAlias // want "禁止将 //xops:borrowed 借用变量逃逸"
		_ = outerBox
		return nil
	})
}

func badReturnAndNamedResult(ctx context.Context, p leasedef.Pool) {
	_ = func() leasedef.Session {
		var out leasedef.Session
		_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
			out = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
			return nil
		})
		return out
	}()

	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		f := func() (out leasedef.Session) {
			out = sess
			return // want "禁止通过 return 返回 //xops:borrowed 借用变量"
		}
		_ = f()
		_ = func() any {
			return any(sess) // want "禁止通过 return 返回 //xops:borrowed 借用变量"
		}()
		return nil
	})
}

func badStandaloneNestedAndRange(ctx context.Context, p leasedef.Pool, n Nursery) {
	n.Go(func() {
		_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
			return nil
		})
	})

	fn := func(
		//xops:borrowed
		hs []leasedef.Session,
	) {
		for _, h := range hs {
			leakedSess = h // want "禁止将 //xops:borrowed 借用变量逃逸"
		}
	}
	_ = fn
}

func badNamedCallbackBody(ctx context.Context) {
	leasedef.RunWithNamed(func(ctx context.Context, sess leasedef.Session) error {
		leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		return nil
	})
}

func badBypassL1TypeAssertAndWrap(ctx context.Context, p leasedef.Pool, n Nursery) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		var fAny any = func() {
			_ = sess.Exec(ctx, "any")
		}
		n.Go(fAny.(func()))          // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
		leakedFnZero = fAny.(func()) // want "禁止将 //xops:borrowed 借用变量逃逸"
		n.Go(myFunc(func() {         // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
			_ = sess.Close()
		}))
		n.Go(any(sess.Close).(func())) // want "禁止将 //xops:borrowed 接收者的未调用方法值转存或逃逸"
		_ = func() func() {
			return fAny.(func()) // want "禁止通过 return 返回 //xops:borrowed 借用变量"
		}()
		return nil
	})
}

func badBypassL3ClosureAliasChain(ctx context.Context, p leasedef.Pool) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		fnOrig := func() {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		}
		fnAlias := fnOrig
		leasedef.RunSync(fnAlias)

		// 6 跳逆序局部闭包别名链测试（循环确保 SSA 真实可达）
		var a1, a2, a3, a4, a5, a6 func()
		for range 6 {
			a6 = a5
			a5 = a4
			a4 = a3
			a3 = a2
			a2 = a1
			a1 = func() {
				leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
			}
		}
		fnConv := myFunc(a6)
		leasedef.RunSync(fnConv)
		return nil
	})
}

func badBypassL5AndChallenge1IIFE(ctx context.Context, p leasedef.Pool) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		inlineBorrowed := func(
			//xops:borrowed
			s leasedef.Session,
		) {
			leakedSess = s // want "禁止将 //xops:borrowed 借用变量逃逸"
		}
		inlineBorrowed(sess)

		func(
			//xops:borrowed
			s leasedef.Session,
		) {
			leakedSess = s // want "禁止将 //xops:borrowed 借用变量逃逸"
		}(sess)

		func(x leasedef.Session) {
			leakedSess = x // want "禁止将 //xops:borrowed 借用变量逃逸"
		}(sess)
		return nil
	})
}

func badBypassL4SliceRange(ctx context.Context, p leasedef.Pool) {
	_ = p.WithSliceLease(ctx, func(ctx context.Context, hs []leasedef.Session) error {
		for _, h := range hs {
			_ = h
		}
		for _, leakedSess = range hs { // want "禁止将 //xops:borrowed 借用变量逃逸"
		}
		return nil
	})
}

func badBypassL7Copy(
	//xops:borrowed
	src []leasedef.Session,
) {
	copy(leakedSlice, src) // want "禁止通过 copy 将 //xops:borrowed 借用变量逃逸"
	localBuf := make([]leasedef.Session, len(src))
	copy(localBuf[0:], src)
	localEscape := make([]leasedef.Session, len(src))
	copy(localEscape, src)
	leakedSlice = localEscape // want "禁止将 //xops:borrowed 借用变量逃逸"
}

func badVariadicCallbacks() {
	leasedef.WithVariadic(
		func(s leasedef.Session) { _ = s.Close() },
		func(s leasedef.Session) { leakedSess = s }, // want "禁止将 //xops:borrowed 借用变量逃逸"
	)
}

func badBypassNBL1IIFECallbacks(ctx context.Context, p leasedef.Pool, n Nursery) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		func(cb func()) {
			cb()
		}(func() {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		})

		func(cb func()) {
			n.Go(cb) // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
		}(func() {
			_ = sess.Exec(ctx, "bypass-iife-ngo")
		})

		func(cb func()) {
			leakedFnZero = cb // want "禁止将 //xops:borrowed 借用变量逃逸"
		}(func() {
			_ = sess.Exec(ctx, "bypass-iife-leakfn")
		})

		runCB := func(cb func()) { cb() }
		runCB(func() {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
		})

		spawnCB := func(cb func()) {
			n.Go(cb) // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
		}
		spawnCB(func() {
			_ = sess.Exec(ctx, "bypass-localcb-ngo")
		})

		func(cb func()) {
			cb()
		}(func() {
			_ = sess.Exec(ctx, "clean-iife-cb")
		})
		return nil
	})
}

func badBypassNBL3VariadicClosures(ctx context.Context, p leasedef.Pool, n Nursery) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		func(cbs ...func()) {
			n.Go(cbs[0]) // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
		}(func() {
			_ = sess.Exec(ctx, "nb-l3-index")
		})

		func(cbs ...func()) {
			for _, c := range cbs {
				n.Go(c) // want "禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用"
			}
		}(func() {
			_ = sess.Exec(ctx, "nb-l3-range")
		})

		func(cbs ...func()) {
			for _, leakedFnZero = range cbs { // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
			}
		}(func() {
			_ = sess.Exec(ctx, "nb-l3-range-outer")
		})

		func(cbs ...func()) {
			cbs[0]()
		}(func() {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		})

		func(cbs ...func()) {
			for _, c := range cbs {
				c()
			}
		}(func() {
			leakedSess = sess // want "禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值"
		})

		// NB-L3 干净对照：同步索引/遍历变参闭包切片不应误报
		func(cbs ...func()) {
			cbs[0]()
		}(func() {
			_ = sess.Exec(ctx, "nb-l3-clean-index")
		})

		func(cbs ...func()) {
			for _, c := range cbs {
				c()
			}
		}(func() {
			_ = sess.Exec(ctx, "nb-l3-clean-range")
		})
		return nil
	})
}

// v2.3.2 B2/B3 回归用例：移除 defer 同步误放行 + copy 目标 IsFreshLocalSliceAlloc 精准校验。
func badDeferAsyncAndCopyCallTargets(
	ctx context.Context,
	p leasedef.Pool,
	n Nursery,
	//xops:borrowed
	src []leasedef.Session,
	//xops:borrowed
	plain []byte,
) {
	_ = p.WithLease(ctx, func(ctx context.Context, sess leasedef.Session) error {
		defer n.Go(func() { // want "禁止在非同步子闭包"
			_ = sess.Close()
		})
		defer time.AfterFunc(time.Second, func() { // want "禁止在非同步子闭包"
			_ = sess.Close()
		})
		defer registerAsync(func() { // want "禁止在非同步子闭包"
			_ = sess
		})
		// 合法对照：defer IIFE 与 defer 同步方法调用仍放行
		defer func() {
			_ = sess.Exec(ctx, "ok-defer-iife")
		}()
		defer sess.Close()
		return nil
	})

	copy(getOuterSlice(), src)         // want "禁止通过 copy 将 //xops:borrowed 借用变量写入非新建局部切片目标"
	copy(mySessions(leakedSlice), src) // want "禁止通过 copy 将 //xops:borrowed 借用变量写入非新建局部切片目标"
	copy(make([]leasedef.Session, 1), src)
	copy([]byte("xxxx"), plain)
	copy([]byte(nil), plain)
}
