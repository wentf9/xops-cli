package leasedef

import "context"

type Session interface {
	Exec(ctx context.Context, arg any) error
	Close() error
}

type Reader interface {
	Read(p []byte) (int, error)
}

type SecretBox struct {
	raw []byte
}

//xops:secretuse
func (b *SecretBox) Use(fn func(plain []byte) error) error { // want Use:"syncclosure"
	return fn(b.raw)
}

type Authorized[C any] struct{}

//xops:borrowed
func WithAuthorized[C any](ctx context.Context, run func(auth Authorized[C]) error) error { // want WithAuthorized:"syncclosure,borrowed"
	var a Authorized[C]
	return run(a)
}

type Pool interface {
	//xops:borrowed
	WithLease(ctx context.Context, fn func(ctx context.Context, sess Session) error) error // want WithLease:"syncclosure,borrowed"
	//xops:borrowed
	WithSliceLease(ctx context.Context, fn func(ctx context.Context, hs []Session) error) error // want WithSliceLease:"syncclosure,borrowed"
}

type Vault interface {
	//xops:borrowed
	WithSecret(ctx context.Context, ref string, fn func(box *SecretBox) error) error // want WithSecret:"syncclosure,borrowed"
}

type OperatorReadFS interface {
	//xops:borrowed
	WithOperatorRead(ctx context.Context, p string, fn func(r Reader, size int64) error) error // want WithOperatorRead:"syncclosure,borrowed"
}

//xops:syncclosure
func RunSync(fn func()) { // want RunSync:"syncclosure"
	fn()
}

type BorrowedCallback func( // want BorrowedCallback:"syncclosure,borrowed"
	ctx context.Context,
	//xops:borrowed
	sess Session,
) error

func RunWithNamed(cb BorrowedCallback) {
	_ = cb
}

var leakedFromHelper Session

func HelperDirectBorrowedOk(
	ctx context.Context,
	//xops:borrowed
	sess Session,
) error {
	return sess.Exec(ctx, "ok")
}

func HelperDirectBorrowedBad(
	ctx context.Context,
	//xops:borrowed
	sess Session,
) error {
	leakedFromHelper = sess // want "禁止将 //xops:borrowed 借用变量逃逸"
	return nil
}

//xops:borrowed
func WithVariadic(fns ...func(s Session)) { // want WithVariadic:"syncclosure,borrowed"
	for _, fn := range fns {
		if fn != nil {
			fn(nil)
		}
	}
}

var leakedInt *int

func paramSameLineTrailing(s Session /* //xops:borrowed */, other *int) {
	leakedFromHelper = s // want "禁止将 //xops:borrowed 借用变量逃逸"
	leakedInt = other
}
