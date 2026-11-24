package violations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// 禁止在白名单外使用 //nolint: 注释（普通说明注释不应误报）。

type myStringer struct{}

func (myStringer) String() string { return "ok" }
func (myStringer) init()          {}

var _ fmt.Stringer = (*myStringer)(nil)
var _ fmt.Stringer = &myStringer{}

func sideEffect() fmt.Stringer { return myStringer{} }

var _ = sideEffect()             // want "禁止声明可变包级 var"
var _ fmt.Stringer = sideEffect() // want "禁止声明可变包级 var"
var mutableGlobal = 42           // want "禁止声明可变包级 var"

var ErrBase = errors.New("base")
var ErrWrap = fmt.Errorf("wrap: %w", ErrBase)
var ErrEOF = fmt.Errorf("eof: %w", io.EOF)
var ErrMut = errors.New("mutable")
var ErrDyn = fmt.Errorf("dyn: %d", mutableGlobal) // want "禁止声明可变包级 var"
var badName = errors.New("not err prefix")        // want "禁止声明可变包级 var"

func init() {} // want "禁止定义 func init"

func mutateSentinel() {
	ErrMut = nil // want "禁止在运行期修改哨兵错误 ErrMut"
	p := &ErrMut // want "禁止对哨兵错误 ErrMut 取地址"
	_ = p
	for _, ErrMut = range []error{nil} { // want "禁止在运行期修改哨兵错误 ErrMut"
	}
	for ErrMut = range map[error]int{} { // want "禁止在运行期修改哨兵错误 ErrMut"
	}
}

type myCtx struct{ context.Context }
type myCache struct{}

func (myCache) Value(k string) int { return len(k) }

func checkCtxAndIfaces(ctx context.Context, x any) {
	//nolint:errcheck // want "白名单包外禁止使用行内 //nolint"
	_ = context.WithValue(ctx, "k", "v") // want "禁止使用 context.WithValue"
	_ = ctx.Value("k")                   // want "禁止调用 ctx.Value"
	mc := myCtx{Context: ctx}
	_ = mc.Value("k")                    // want "禁止调用 ctx.Value"
	_ = (myCache{}).Value("ok")

	_ = x.(any)
	_ = x.(fmt.Stringer)
	_ = x.(interface{})                  // want "禁止匿名接口断言"
	_ = x.(interface{ M() })             // want "禁止匿名接口断言"
	_ = x.(*interface{ M() })            // want "禁止匿名接口断言"
	_ = x.([]interface{ M() })           // want "禁止匿名接口断言"
	_ = x.(func(interface{ M() }))       // want "禁止匿名接口断言"
	_ = x.(func() interface{ M() })      // want "禁止匿名接口断言"
	_ = x.(struct{ F interface{ M() } }) // want "禁止匿名接口断言"
	_ = x.(map[string]interface{ M() })  // want "禁止匿名接口断言"
	_ = x.(chan interface{ M() })        // want "禁止匿名接口断言"

	switch x.(type) {
	case interface{ M() }: // want "禁止在 type switch 中使用匿名接口"
	}
}

/* nolint:govet */ // want "白名单包外禁止使用行内 //nolint"
func nolintBlock() {}

type TaggedDTO struct {
	Ok      algebraic.Duration                  `json:"ok"`
	Ignored time.Duration                       `json:"-"`
	Bad     time.Duration                       `json:"bad"`     // want "禁止裸用 time.Duration"
	Nested  algebraic.Option[time.Duration]     `yaml:"nested"`  // want "禁止裸用 time.Duration"
	Slice   []time.Duration                     `json:"slice"`   // want "禁止裸用 time.Duration"
}

//xops:dto
type directiveStruct struct {
	TTL time.Duration // want "禁止裸用 time.Duration"
}
