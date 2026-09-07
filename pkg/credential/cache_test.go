package credential

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCacheBasicAndExpiry(t *testing.T) {
	currentTime := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		return currentTime
	}

	// 缓存容量 2，TTL 10 秒
	cache := NewCache(CacheOptions{
		Capacity:   2,
		DefaultTTL: 10 * time.Second,
		NowFunc:    nowFn,
	})

	ref1 := Ref{StoreID: "system", ItemID: "item-1"}
	sec1 := NewSecret([]byte("pass1"))

	cache.Put(ref1, sec1)

	// 命中缓存
	got, found := cache.Get(ref1)
	if !found || string(got.Value) != "pass1" {
		t.Fatalf("expected cache hit with 'pass1', got: %v (found: %v)", string(got.Value), found)
	}

	// 时间推进 5 秒，尚未过期
	currentTime = currentTime.Add(5 * time.Second)
	got, found = cache.Get(ref1)
	if !found || string(got.Value) != "pass1" {
		t.Fatalf("expected cache hit after 5s")
	}

	// 时间推进至 11 秒，已过期
	currentTime = currentTime.Add(6 * time.Second)
	_, found = cache.Get(ref1)
	if found {
		t.Fatalf("expected cache miss due to expiration")
	}
	if cache.Len() != 0 {
		t.Fatalf("expected expired entry to be lazily evicted, len = %d", cache.Len())
	}
}

func TestCacheMinExpiryWithBackend(t *testing.T) {
	currentTime := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		return currentTime
	}

	// DefaultTTL 10m, 但后端在 3s 后就过期
	cache := NewCache(CacheOptions{
		Capacity:   5,
		DefaultTTL: 10 * time.Minute,
		NowFunc:    nowFn,
	})

	ref := Ref{StoreID: "vault", ItemID: "token-1"}
	backendExp := currentTime.Add(3 * time.Second)
	sec := NewSecretWithExpiry([]byte("token-val"), backendExp)

	cache.Put(ref, sec)

	// 2s 后仍有效
	currentTime = currentTime.Add(2 * time.Second)
	_, found := cache.Get(ref)
	if !found {
		t.Fatalf("expected cache hit at 2s")
	}

	// 4s 后应过期（优先遵从后端的 3s）
	currentTime = currentTime.Add(2 * time.Second)
	_, found = cache.Get(ref)
	if found {
		t.Fatalf("expected cache miss at 4s due to backend expiry")
	}
}

func TestCacheLRUEvictionAndZeroing(t *testing.T) {
	cache := NewCache(CacheOptions{
		Capacity:   2,
		DefaultTTL: time.Hour,
	})

	ref1 := Ref{StoreID: "s", ItemID: "1"}
	ref2 := Ref{StoreID: "s", ItemID: "2"}
	ref3 := Ref{StoreID: "s", ItemID: "3"}

	sec1Val := []byte("secret-one")
	cache.Put(ref1, NewSecret(sec1Val))
	cache.Put(ref2, NewSecret([]byte("secret-two")))

	// 访问 ref1，使其成为最近使用
	_, _ = cache.Get(ref1)

	// 插入 ref3，应逐出 ref2
	cache.Put(ref3, NewSecret([]byte("secret-three")))

	if cache.Len() != 2 {
		t.Fatalf("expected cache len 2, got %d", cache.Len())
	}

	_, found2 := cache.Get(ref2)
	if found2 {
		t.Errorf("expected ref2 to be evicted")
	}

	_, found1 := cache.Get(ref1)
	if !found1 {
		t.Errorf("expected ref1 to remain in cache")
	}

	_, found3 := cache.Get(ref3)
	if !found3 {
		t.Errorf("expected ref3 to be in cache")
	}
}

func TestCacheCloneIsolation(t *testing.T) {
	cache := NewCache(CacheOptions{
		Capacity:   2,
		DefaultTTL: time.Hour,
	})

	ref := Ref{StoreID: "s", ItemID: "k"}
	cache.Put(ref, NewSecret([]byte("original")))

	got1, found := cache.Get(ref)
	if !found {
		t.Fatalf("expected hit")
	}

	// 修改调用方拿到的切片
	got1.Value[0] = 'X'

	// 再次获取，缓存中的数据不应受外部修改影响
	got2, _ := cache.Get(ref)
	if string(got2.Value) != "original" {
		t.Fatalf("cache isolation violated: got %s, want %s", string(got2.Value), "original")
	}
}

func TestCachedSourceAndStore(t *testing.T) {
	ctx := context.Background()
	ref := Ref{StoreID: "s", ItemID: "key1"}

	backendData := make(map[string]Secret)
	getCalls := 0
	putCalls := 0
	delCalls := 0

	store := &dummyStore{
		dummySource: dummySource{
			getFn: func(_ context.Context, r Ref) (Secret, error) {
				getCalls++
				sec, ok := backendData[r.String()]
				if !ok {
					return Secret{}, ErrCredentialNotFound
				}
				return sec.Clone(), nil
			},
		},
		putFn: func(_ context.Context, r Ref, secret Secret) error {
			putCalls++
			backendData[r.String()] = secret.Clone()
			return nil
		},
		deleteFn: func(_ context.Context, r Ref) error {
			delCalls++
			delete(backendData, r.String())
			return nil
		},
	}

	cache := NewCache(CacheOptions{
		Capacity:   10,
		DefaultTTL: time.Hour,
	})
	cachedStore := NewCachedStore(store, cache)

	// 第一次 Put
	err := cachedStore.Put(ctx, ref, NewSecret([]byte("val1")))
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if putCalls != 1 {
		t.Errorf("expected 1 put call, got %d", putCalls)
	}

	// 首次 Get 应直接命中 Put 写入的缓存，不穿透到底层
	got, err := cachedStore.Get(ctx, ref)
	if err != nil || string(got.Value) != "val1" {
		t.Fatalf("unexpected get result: %v", string(got.Value))
	}
	if getCalls != 0 {
		t.Errorf("expected 0 getCalls, got %d", getCalls)
	}

	// 主动 Invalidate 后再次 Get，触发底层 Get 并重新填充缓存
	cache.Invalidate(ref)
	got, err = cachedStore.Get(ctx, ref)
	if err != nil || string(got.Value) != "val1" {
		t.Fatalf("unexpected get after invalidate: %v", string(got.Value))
	}
	if getCalls != 1 {
		t.Errorf("expected 1 getCall after invalidate, got %d", getCalls)
	}

	// 再次 Get，应命中缓存，getCalls 仍为 1
	_, err = cachedStore.Get(ctx, ref)
	if err != nil {
		t.Fatalf("cached get failed: %v", err)
	}
	if getCalls != 1 {
		t.Errorf("expected getCalls to remain 1, got %d", getCalls)
	}

	// Delete 后缓存失效，底层也被删除
	err = cachedStore.Delete(ctx, ref)
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if delCalls != 1 {
		t.Errorf("expected 1 delete call, got %d", delCalls)
	}

	_, err = cachedStore.Get(ctx, ref)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound after delete, got %v", err)
	}
}

func TestCacheConcurrency(t *testing.T) {
	cache := NewCache(CacheOptions{
		Capacity:   16,
		DefaultTTL: time.Second,
	})

	const goroutines = 20
	const ops = 100
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < ops; j++ {
				ref := Ref{StoreID: "s", ItemID: fmt.Sprintf("k-%d", (workerID+j)%10)}
				switch j % 3 {
				case 0:
					cache.Put(ref, NewSecret([]byte("val")))
				case 1:
					_, _ = cache.Get(ref)
				default:
					cache.Invalidate(ref)
				}
			}
		}()
	}

	wg.Wait()
}
