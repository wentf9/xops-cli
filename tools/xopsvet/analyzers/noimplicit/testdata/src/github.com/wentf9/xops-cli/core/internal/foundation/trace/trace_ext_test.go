package trace_test

import (
	"context"
	"testing"
)

func TestExternalTraceNotWhitelisted(t *testing.T) {
	//nolint:errcheck // want "白名单包外禁止使用行内 //nolint"
	ctx := context.WithValue(context.Background(), "k", "v") // want "禁止使用 context.WithValue"
	_ = ctx.Value("k")                                       // want "禁止调用 ctx.Value"
}
