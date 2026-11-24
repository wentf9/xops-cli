package osfs

import "context"

//nolint:unused // osfs 在 //nolint 白名单内
func OpenRaw(ctx context.Context) {
	_ = context.WithValue(ctx, "k", "v") // want "禁止使用 context.WithValue"
}
