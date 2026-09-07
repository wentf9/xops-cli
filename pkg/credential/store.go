package credential

import "context"

// Source 定义只读凭据源契约。
type Source interface {
	// Get 从底层存储中根据引用检索机密。
	Get(ctx context.Context, ref Ref) (Secret, error)
}

// Store 定义可读写的凭据存储契约。
type Store interface {
	Source
	// Put 向底层存储写入或更新凭据项。
	Put(ctx context.Context, ref Ref, secret Secret) error
	// Delete 从底层存储删除指定的凭据项。
	Delete(ctx context.Context, ref Ref) error
}
