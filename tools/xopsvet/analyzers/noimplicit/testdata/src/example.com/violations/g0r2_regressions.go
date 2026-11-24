package violations

import "context"

type genericValuer[K, V any] interface {
	Value(K) V
}

func stealViaGeneric[K, V any, C genericValuer[K, V]](c C, k K) V {
	return c.Value(k)
}

// BadGenericContextValue 验证泛型接口约束实例化为 context.Context 绕过 Value(any) any 时必须拦截（H1）。
func BadGenericContextValue(ctx context.Context) any {
	return stealViaGeneric[any, any, context.Context](ctx, "k") // want "禁止以 context\\.Context 实例化含 Value\\(any\\) any 约束的泛型"
}
