package credential

import (
	"context"
	"fmt"
)

// NoneStore 实现固定 fail-closed 语义的凭据后端。
// 任何读取均报告 ErrCredentialNotFound，任何写入均被拒绝为 ErrCredentialStoreReadOnly。
type NoneStore struct{}

// NewNoneStore 创建一个 NoneStore 实例。
func NewNoneStore() *NoneStore {
	return &NoneStore{}
}

// Get 固定返回 ErrCredentialNotFound，确保调用方在无引用或缺失凭据时安全失败关闭。
func (n *NoneStore) Get(_ context.Context, _ Ref) (Secret, error) {
	return Secret{}, ErrCredentialNotFound
}

// Put 固定返回 ErrCredentialStoreReadOnly，禁止向 none 后端持久化凭据。
func (n *NoneStore) Put(_ context.Context, _ Ref, _ Secret) error {
	return fmt.Errorf("%w: none store does not support persistence", ErrCredentialStoreReadOnly)
}

// Delete 固定返回 ErrCredentialStoreReadOnly，禁止执行删除。
func (n *NoneStore) Delete(_ context.Context, _ Ref) error {
	return fmt.Errorf("%w: none store does not support persistence", ErrCredentialStoreReadOnly)
}
