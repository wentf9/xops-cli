package leaseuse

import (
	"context"

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

var (
	leakedSess   leasedef.Session
	leakedCloser Closer
	leakedBox    *leasedef.SecretBox
	leakedReader leasedef.Reader
	leakedFn     func() error
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
			out = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
			return
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
