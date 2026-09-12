package credential

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

type dummySource struct {
	getFn func(ctx context.Context, ref Ref) (Secret, error)
}

func (d *dummySource) Get(ctx context.Context, ref Ref) (Secret, error) {
	if d.getFn != nil {
		return d.getFn(ctx, ref)
	}
	return Secret{}, nil
}

type dummyStore struct {
	dummySource
	putFn    func(ctx context.Context, ref Ref, secret Secret) error
	deleteFn func(ctx context.Context, ref Ref) error
}

func (d *dummyStore) Put(ctx context.Context, ref Ref, secret Secret) error {
	if d.putFn != nil {
		return d.putFn(ctx, ref, secret)
	}
	return nil
}

func (d *dummyStore) Delete(ctx context.Context, ref Ref) error {
	if d.deleteFn != nil {
		return d.deleteFn(ctx, ref)
	}
	return nil
}

func TestRegistryBasic(t *testing.T) {
	reg := NewRegistry()

	src := &dummySource{}
	str := &dummyStore{}

	if err := reg.Register("sys", src); err != nil {
		t.Fatalf("register sys failed: %v", err)
	}
	if err := reg.Register("vault", str); err != nil {
		t.Fatalf("register vault failed: %v", err)
	}

	// 重复注册应报错
	err := reg.Register("sys", src)
	if !errors.Is(err, ErrStoreAlreadyRegistered) {
		t.Fatalf("expected ErrStoreAlreadyRegistered, got: %v", err)
	}

	// 验证 Has
	if !reg.Has("sys") || !reg.Has("vault") || reg.Has("missing") {
		t.Errorf("unexpected Has result")
	}

	// 验证 List 排序
	list := reg.List()
	if len(list) != 2 || list[0] != "sys" || list[1] != "vault" {
		t.Fatalf("unexpected List result: %v", list)
	}

	// 验证 Get
	gotSrc, err := reg.Get("sys")
	if err != nil || gotSrc != src {
		t.Fatalf("Get sys failed: %v", err)
	}

	_, err = reg.Get("missing")
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("expected ErrStoreNotFound, got: %v", err)
	}

	// 验证 GetStore
	gotStore, err := reg.GetStore("vault")
	if err != nil || gotStore != str {
		t.Fatalf("GetStore vault failed: %v", err)
	}

	// 只读 Source 调用 GetStore 应报错 ErrCredentialStoreReadOnly
	_, err = reg.GetStore("sys")
	if !errors.Is(err, ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly, got: %v", err)
	}

	// Unregister
	reg.Unregister("sys")
	if reg.Has("sys") {
		t.Errorf("expected sys to be unregistered")
	}
}

func TestRegistryConcurrent(t *testing.T) {
	reg := NewRegistry()
	const workers = 20
	var wg sync.WaitGroup

	// 先注册几个基础 store
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("store-%d", i)
		_ = reg.Register(name, &dummyStore{})
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			storeName := fmt.Sprintf("store-%d", workerID%5)
			if _, err := reg.Get(storeName); err != nil {
				t.Errorf("concurrent Get failed: %v", err)
			}
			_ = reg.List()
			_ = reg.Has(storeName)
			_ = reg.Register(fmt.Sprintf("dynamic-%d", workerID), &dummySource{})
		}()
	}

	wg.Wait()
}
