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
func sideEffectInt() int       { return 1 }

var _ = sideEffect()                        // want "禁止声明可变包级 var"
var _ fmt.Stringer = sideEffect()           // want "禁止声明可变包级 var"
var _ any = new(sideEffect())               // want "禁止声明可变包级 var"
var _ any = map[int]int{sideEffectInt(): 0} // want "禁止声明可变包级 var"
var _ any = new(myStringer)                 // 合法：Go 1.27 new(T) 类型分配
var _ any = new(42)                         // 合法：Go 1.27 new(纯常量表达式)
var mutableGlobal = 42                      // want "禁止声明可变包级 var"

var ErrBase = errors.New("base")
var ErrWrap = fmt.Errorf("wrap: %w", ErrBase)
var ErrEOF = fmt.Errorf("eof: %w", io.EOF)
var ErrCtx = fmt.Errorf("ctx: %w", context.Canceled)
var ErrMut = errors.New("mutable")
var ErrDyn = fmt.Errorf("dyn: %d", mutableGlobal) // want "禁止声明可变包级 var"
var badName = errors.New("not err prefix")        // want "禁止声明可变包级 var"

func init() {} // want "禁止定义 func init"

func mutateSentinel() {
	ErrMut = nil // want "禁止在运行期修改哨兵错误 ErrMut"
	p := &ErrMut // want "禁止对哨兵错误 ErrMut 取地址"
	_ = p
	io.EOF = nil                         // want "禁止在运行期修改哨兵错误 EOF"
	context.Canceled = nil               // want "禁止在运行期修改哨兵错误 Canceled"
	for _, ErrMut = range []error{nil} { // want "禁止在运行期修改哨兵错误 ErrMut"
	}
	for ErrMut = range map[error]int{} { // want "禁止在运行期修改哨兵错误 ErrMut"
	}
}

type myCtx struct{ context.Context }
type myCache struct{}

func (myCache) Value(k string) int { return len(k) }

// HIGH-3: 显式嵌入 context.Context 的扩展接口声明合法；非嵌入暴露 Value(any) any 的窄接口声明禁止。
type SessionContext interface {
	context.Context
	SessionID() string
}

type narrowValuer interface { // want "禁止声明暴露 Value\\(any\\) any 的窄接口"
	Value(any) any
}

type genericGetter[K, V any] interface {
	Value(K) V
}

type genericBox[T any] struct{ V T }

func consumeNarrow(v narrowValuer) any { return v.Value("k") } // want "禁止将 context.Context 擦除或调用 Value\\(any\\) any 窄接口"

func checkCtxAndIfaces(ctx context.Context, x any) {
	//nolint:errcheck // want "白名单包外禁止使用行内 //nolint"
	_ = context.WithValue(ctx, "k", "v") // want "禁止使用 context.WithValue"
	_ = ctx.Value("k")                   // want "禁止调用 ctx.Value"
	mc := myCtx{Context: ctx}
	_ = mc.Value("k") // want "禁止调用 ctx.Value"
	_ = (myCache{}).Value("ok")
	_ = consumeNarrow(ctx)                     // want "禁止将 context.Context 擦除或调用 Value\\(any\\) any 窄接口"
	_ = x.(genericGetter[any, any]).Value("k") // want "禁止将 context.Context 擦除或调用 Value\\(any\\) any 窄接口"

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
	_ = x.(genericBox[interface{ M() }]) // want "禁止匿名接口断言"

	switch x.(type) {
	case interface{ M() }: // want "禁止在 type switch 中使用匿名接口"
	}
}

/* nolint:govet */ // want "白名单包外禁止使用行内 //nolint"
func nolintBlock() {}

// L2b: 纯内存运行期 *Config 结构体不再全局误杀。
type RuntimePoolConfig struct {
	IdleTimeout time.Duration
}

type customJSONOnly struct {
	Wait time.Duration
}

func (customJSONOnly) MarshalJSON() ([]byte, error) { return []byte(`"1s"`), nil }

type ptrTextDur struct {
	Wait time.Duration
}

func (*ptrTextDur) MarshalText() ([]byte, error) { return []byte("1s"), nil }

type TaggedDTO struct {
	Ok            algebraic.Duration `json:"ok"`
	Ignored       time.Duration      `json:"-"`
	privateCached time.Duration
	JSONOnlySafe  customJSONOnly  `json:"json_only"`
	Bad           time.Duration   `json:"bad"`   // want "禁止裸用 time.Duration"
	Slice         []time.Duration `json:"slice"` // want "禁止裸用 time.Duration"
}

type YAMLTaggedDTO struct {
	Nested       algebraic.Option[time.Duration] `yaml:"nested"` // want "禁止裸用 time.Duration"
	JSONIgnored  time.Duration                   `json:"-"`      // want "禁止裸用 time.Duration"
	YAMLIgnored  time.Duration                   `yaml:"-"`
	BadJSONOnly  customJSONOnly                  `yaml:"bad_json_only"` // want "禁止裸用 time.Duration"
	BadMapPtrTxt map[string]ptrTextDur           `yaml:"bad_map_ptr"`   // want "禁止裸用 time.Duration"
}

//xops:dto
type directiveStruct struct {
	TTL time.Duration // want "禁止裸用 time.Duration"
}
