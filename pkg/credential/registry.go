package credential

import (
	"fmt"
	"sort"
	"sync"
)

// Registry 管理 StoreID 到凭据源（Source / Store）的映射。
// Registry 的读写锁仅用于保护内部映射表的并发安全，严禁跨外部 I/O 持有锁。
type Registry struct {
	mu     sync.RWMutex
	stores map[string]Source
}

// NewRegistry 创建一个空的凭据存储注册表。
func NewRegistry() *Registry {
	return &Registry{
		stores: make(map[string]Source),
	}
}

// Register 注册一个凭据源（Source 或 Store）。如果已存在同名 StoreID，返回 ErrStoreAlreadyRegistered。
func (r *Registry) Register(storeID string, source Source) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}
	if err := validateRefIdentifier("storeID", storeID); err != nil {
		return err
	}
	if source == nil {
		return fmt.Errorf("source cannot be nil for store %q", storeID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.stores[storeID]; exists {
		return fmt.Errorf("%w: store %q", ErrStoreAlreadyRegistered, storeID)
	}
	r.stores[storeID] = source
	return nil
}

// Unregister 注销一个已注册的凭据源，主要用于测试或动态重新加载。
func (r *Registry) Unregister(storeID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.stores, storeID)
}

// Get 根据 StoreID 获取只读凭据源 Source。
// 注意：锁在检索到对象后立即释放，调用方使用返回的 Source 进行外部 I/O 时不持有 Registry 锁。
func (r *Registry) Get(storeID string) (Source, error) {
	if r == nil {
		return nil, fmt.Errorf("registry is nil")
	}
	r.mu.RLock()
	source, exists := r.stores[storeID]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("%w: store %q", ErrStoreNotFound, storeID)
	}
	return source, nil
}

// GetStore 根据 StoreID 获取可读写的凭据存储 Store。
// 如果目标仅实现了只读 Source，返回包装了 ErrCredentialStoreReadOnly 的错误。
func (r *Registry) GetStore(storeID string) (Store, error) {
	source, err := r.Get(storeID)
	if err != nil {
		return nil, err
	}
	store, ok := source.(Store)
	if !ok {
		return nil, fmt.Errorf("%w: store %q does not support write operations", ErrCredentialStoreReadOnly, storeID)
	}
	return store, nil
}

// Has 检查指定的 StoreID 是否已注册。
func (r *Registry) Has(storeID string) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.stores[storeID]
	return exists
}

// List 返回已注册的所有 StoreID 列表，结果按字母字典序排序。
func (r *Registry) List() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.stores))
	for name := range r.stores {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
