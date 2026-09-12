package credential

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

	// Put 后缓存失效，首次 Get 必须穿透到底层进行真实读回校验
	got, err := cachedStore.Get(ctx, ref)
	if err != nil || string(got.Value) != "val1" {
		t.Fatalf("unexpected get result: %v", string(got.Value))
	}
	if getCalls != 1 {
		t.Errorf("expected 1 getCall on readback passthrough, got %d", getCalls)
	}

	// 读回完成后已填充缓存，再次 Get 应命中缓存
	got, err = cachedStore.Get(ctx, ref)
	if err != nil || string(got.Value) != "val1" {
		t.Fatalf("unexpected cached get result: %v", string(got.Value))
	}
	if getCalls != 1 {
		t.Errorf("expected getCalls to remain 1 on hit, got %d", getCalls)
	}

	// 主动 Invalidate 后再次 Get，触发底层读取
	cache.Invalidate(ref)
	got, err = cachedStore.Get(ctx, ref)
	if err != nil || string(got.Value) != "val1" {
		t.Fatalf("unexpected get after invalidate: %v", string(got.Value))
	}
	if getCalls != 2 {
		t.Errorf("expected 2 getCalls after invalidate, got %d", getCalls)
	}

	// 再次 Get，应命中缓存，getCalls 仍为 2
	_, err = cachedStore.Get(ctx, ref)
	if err != nil {
		t.Fatalf("cached get failed: %v", err)
	}
	if getCalls != 2 {
		t.Errorf("expected getCalls to remain 2, got %d", getCalls)
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

func TestWriteReadbackMustReachBackend(t *testing.T) {
	ctx := context.Background()
	backend := &dummyStore{
		dummySource: dummySource{
			getFn: func(_ context.Context, _ Ref) (Secret, error) {
				return Secret{}, ErrCredentialNotFound
			},
		},
		putFn: func(_ context.Context, _ Ref, _ Secret) error {
			return nil
		},
	}
	cs := NewCachedStore(backend, NewCache(CacheOptions{Capacity: 64, DefaultTTL: time.Minute}))
	ref := Ref{StoreID: "s", ItemID: "new"}
	if err := cs.Put(ctx, ref, NewSecret([]byte("synthetic"))); err != nil {
		t.Fatal(err)
	}
	got, err := cs.Get(ctx, ref)
	defer got.Zero()
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("readback hid missing backend item: err=%v", err)
	}
}

func TestDeleteMustFenceInflightGet(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	backend := &dummyStore{
		dummySource: dummySource{
			getFn: func(ctx context.Context, _ Ref) (Secret, error) {
				close(started)
				select {
				case <-release:
					return NewSecret([]byte("deleted-synthetic")), nil
				case <-ctx.Done():
					return Secret{}, ctx.Err()
				}
			},
		},
		deleteFn: func(_ context.Context, _ Ref) error {
			return nil
		},
	}
	cache := NewCache(CacheOptions{Capacity: 64, DefaultTTL: time.Minute})
	cs := NewCachedStore(backend, cache)
	ref := Ref{StoreID: "s", ItemID: "old"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		sec, err := cs.Get(ctx, ref)
		sec.Zero()
		done <- err
	}()

	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	if err := cs.Delete(ctx, ref); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	close(release)

	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sec, found := cache.Get(ref)
	defer sec.Zero()
	if found {
		t.Fatal("inflight Get repopulated cache after Delete completed")
	}
}

func TestZeroTTLDoesNotRetainSecrets(t *testing.T) {
	now := time.Now()
	c := NewCache(CacheOptions{
		Capacity:   64,
		DefaultTTL: 0,
		NowFunc:    func() time.Time { return now },
	})
	ref := Ref{StoreID: "s", ItemID: "zero"}
	c.Put(ref, NewSecret([]byte("synthetic")))
	now = now.Add(365 * 24 * time.Hour)
	sec, found := c.Get(ref)
	defer sec.Zero()
	if found {
		t.Fatal("zero TTL retained secret after one year")
	}
}

func TestClearFencesFirstInflightRead(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	backend := &dummyStore{
		dummySource: dummySource{
			getFn: func(ctx context.Context, _ Ref) (Secret, error) {
				close(started)
				select {
				case <-release:
					return NewSecret([]byte("synthetic")), nil
				case <-ctx.Done():
					return Secret{}, ctx.Err()
				}
			},
		},
	}
	c := NewCache(CacheOptions{Capacity: 1, DefaultTTL: time.Minute})
	cs := NewCachedSource(backend, c)
	ref := Ref{StoreID: "s", ItemID: "first"}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		sec, err := cs.Get(ctx, ref)
		sec.Zero()
		done <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	c.Clear()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sec, found := c.Get(ref)
	defer sec.Zero()
	if found {
		t.Fatal("first inflight read repopulated the cache after Clear")
	}
}

func TestGenerationMetadataIsBounded(t *testing.T) {
	for _, capacity := range []int{1, 0} {
		t.Run(fmt.Sprintf("capacity_%d", capacity), func(t *testing.T) {
			c := NewCache(CacheOptions{Capacity: capacity, DefaultTTL: time.Minute})
			for i := range 10000 {
				c.Invalidate(Ref{StoreID: "s", ItemID: fmt.Sprint(i)})
			}
			c.Clear()
			count := reflect.ValueOf(c).Elem().FieldByName("generations").Len()
			if count > 64 {
				t.Fatalf("capacity=%d, entries=%d, retained generation keys=%d after Clear", capacity, c.Len(), count)
			}
		})
	}
}

type failedPutStoreForTest struct {
	started chan struct{}
	release chan struct{}
}

func (*failedPutStoreForTest) Get(context.Context, Ref) (Secret, error) {
	return NewSecret([]byte("old-synthetic")), nil
}

func (s *failedPutStoreForTest) Put(ctx context.Context, _ Ref, _ Secret) error {
	close(s.started)
	select {
	case <-s.release:
		return ErrCredentialStoreUnavailable
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*failedPutStoreForTest) Delete(context.Context, Ref) error {
	return nil
}

func TestFailedPutStillInvalidatesConcurrentRead(t *testing.T) {
	b := &failedPutStoreForTest{started: make(chan struct{}), release: make(chan struct{})}
	c := NewCache(CacheOptions{Capacity: 1, DefaultTTL: time.Minute})
	cs := NewCachedStore(b, c)
	ref := Ref{StoreID: "s", ItemID: "existing"}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- cs.Put(ctx, ref, NewSecret([]byte("new-synthetic")))
	}()
	select {
	case <-b.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	sec, err := cs.Get(ctx, ref)
	sec.Zero()
	close(b.release)
	putErr := <-done
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(putErr, ErrCredentialStoreUnavailable) {
		t.Fatal(putErr)
	}
	sec, found := c.Get(ref)
	defer sec.Zero()
	if found {
		t.Fatal("failed Put left a concurrent read cached despite unknown write outcome")
	}
}

// TestFetchQueueContinuousSuccessAndFailure 验证连续读取完成/失败后队列与活跃令牌严格同步回收
func TestFetchQueueContinuousSuccessAndFailure(t *testing.T) {
	// 1. 连续失败读取
	cFail := NewCache(CacheOptions{Capacity: 2, DefaultTTL: time.Minute})
	csFail := NewCachedSource(&dummyStore{
		dummySource: dummySource{
			getFn: func(context.Context, Ref) (Secret, error) {
				return Secret{}, ErrCredentialNotFound
			},
		},
	}, cFail)

	for i := range 1000 {
		sec, err := csFail.Get(t.Context(), Ref{StoreID: "s", ItemID: fmt.Sprint(i)})
		sec.Zero()
		if err == nil {
			t.Fatal("expected backend miss")
		}
	}
	queueLen := reflect.ValueOf(cFail).Elem().FieldByName("generationKeys").Len()
	if queueLen != 0 || cFail.ActiveFetchesCount() != 0 {
		t.Fatalf("after 1000 failed reads: active=%d, queueLen=%d, want 0", cFail.ActiveFetchesCount(), queueLen)
	}

	// 2. 连续成功读取
	cSucc := NewCache(CacheOptions{Capacity: 5, DefaultTTL: time.Minute})
	csSucc := NewCachedSource(&dummyStore{
		dummySource: dummySource{
			getFn: func(_ context.Context, r Ref) (Secret, error) {
				return NewSecret([]byte("val-" + r.ItemID)), nil
			},
		},
	}, cSucc)

	for i := range 500 {
		sec, err := csSucc.Get(t.Context(), Ref{StoreID: "s", ItemID: fmt.Sprint(i)})
		if err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
		sec.Zero()
	}
	queueLen = reflect.ValueOf(cSucc).Elem().FieldByName("generationKeys").Len()
	if queueLen != 0 || cSucc.ActiveFetchesCount() != 0 {
		t.Fatalf("after 500 successful reads: active=%d, queueLen=%d, want 0", cSucc.ActiveFetchesCount(), queueLen)
	}
}

// TestFetchQueueDuplicateRefStartFetch 验证同一引用重复读取时队列不重复堆叠，且旧令牌被覆盖
func TestFetchQueueDuplicateRefStartFetch(t *testing.T) {
	c := NewCache(CacheOptions{Capacity: 4, DefaultTTL: time.Minute})
	ref := Ref{StoreID: "s", ItemID: "duplicate-key"}

	// 连续对同一引用启动 5 次读取
	tokens := make([]FetchToken, 5)
	for i := 0; i < 5; i++ {
		tokens[i] = c.StartFetch(ref)
	}

	// 验证队列中该 key 仅出现一次，活跃令牌数量也仅为 1
	queueLen := reflect.ValueOf(c).Elem().FieldByName("generationKeys").Len()
	if queueLen != 1 || c.ActiveFetchesCount() != 1 {
		t.Fatalf("duplicate ref in queue: active=%d, queueLen=%d, want 1", c.ActiveFetchesCount(), queueLen)
	}

	// 前 4 个旧令牌回填均应被拒绝
	for i := 0; i < 4; i++ {
		sec := NewSecret([]byte("stale"))
		c.PutIfMatch(ref, sec, tokens[i])
		sec.Zero()
		if _, found := c.Get(ref); found {
			t.Fatalf("stale token %d successfully backfilled cache", i)
		}
	}
	// 队列与 map 依然保持 1 项
	if c.ActiveFetchesCount() != 1 {
		t.Fatalf("expected active fetch count to remain 1 after rejected puts, got %d", c.ActiveFetchesCount())
	}

	// 第 5 个最新令牌回填成功，并清理活跃项
	finalSec := NewSecret([]byte("latest"))
	c.PutIfMatch(ref, finalSec, tokens[4])
	finalSec.Zero()

	got, found := c.Get(ref)
	defer got.Zero()
	if !found || string(got.Value) != "latest" {
		t.Fatalf("expected latest secret cached, got found=%v, val=%s", found, string(got.Value))
	}
	if c.ActiveFetchesCount() != 0 {
		t.Fatalf("expected 0 active fetches after successful put, got %d", c.ActiveFetchesCount())
	}
	queueLen = reflect.ValueOf(c).Elem().FieldByName("generationKeys").Len()
	if queueLen != 0 {
		t.Fatalf("expected 0 queue items after successful put, got %d", queueLen)
	}
}

// TestFetchQueueEvictionWithStaleHistory 验证历史失效项之后触发淘汰，严格遵守容量上限
func TestFetchQueueEvictionWithStaleHistory(t *testing.T) {
	const capVal = 3
	c := NewCache(CacheOptions{Capacity: capVal, DefaultTTL: time.Minute})

	// 启动 3 次读取，填满活跃容量
	ref1 := Ref{StoreID: "s", ItemID: "k1"}
	ref2 := Ref{StoreID: "s", ItemID: "k2"}
	ref3 := Ref{StoreID: "s", ItemID: "k3"}
	c.StartFetch(ref1)
	c.StartFetch(ref2)
	c.StartFetch(ref3)

	if active := c.ActiveFetchesCount(); active != capVal {
		t.Fatalf("expected %d active fetches, got %d", capVal, active)
	}

	// 主动 Invalidate 其中一项
	c.Invalidate(ref2)
	if active := c.ActiveFetchesCount(); active != 2 {
		t.Fatalf("expected 2 active fetches after invalidate, got %d", active)
	}

	// 连续启动 20 次新读取，验证活跃令牌和队列长度始终不超过容量上限
	for i := 0; i < 20; i++ {
		c.StartFetch(Ref{StoreID: "s", ItemID: fmt.Sprintf("extra-%d", i)})
		active := c.ActiveFetchesCount()
		queueLen := reflect.ValueOf(c).Elem().FieldByName("generationKeys").Len()
		if active > capVal || queueLen > capVal {
			t.Fatalf("step %d exceeded capacity: active=%d, queueLen=%d, capacity=%d", i, active, queueLen, capVal)
		}
		if active != queueLen {
			t.Fatalf("step %d active (%d) != queueLen (%d)", i, active, queueLen)
		}
	}
}
