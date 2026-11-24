package trace

import "context"

type ctxKey struct{}

//nolint:unused // trace 在白名单内允许少量底层标注
func WithTrace(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func ReadTrace(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}
