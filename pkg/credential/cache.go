package credential

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// DefaultCacheCapacity 是默认缓存容量上限。
	DefaultCacheCapacity = 64
)

type cacheEntry struct {
	key       string
	secret    Secret
	expiresAt time.Time
	hasExpiry bool
	prev      *cacheEntry
	next      *cacheEntry
}

// Cache 提供有界的内存凭据缓存，采用 LRU 淘汰与惰性过期（lazy expiration）机制。
// 本缓存不启动任何后台清理 Goroutine，确保零资源泄漏。
type Cache struct {
	mu         sync.Mutex
	capacity   int
	defaultTTL time.Duration
	entries    map[string]*cacheEntry
	head       *cacheEntry // 最近使用的项
	tail       *cacheEntry // 最久未使用的项
	nowFunc    func() time.Time
}

// CacheOptions 包含初始化凭据缓存的可选参数。
type CacheOptions struct {
	Capacity   int
	DefaultTTL time.Duration
	NowFunc    func() time.Time
}

// NewCache 创建一个新的有界凭据缓存。
// capacity <= 0 表示完全禁用缓存。
func NewCache(opts CacheOptions) *Cache {
	capVal := opts.Capacity
	if capVal < 0 {
		capVal = 0
	}
	nowFn := opts.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Cache{
		capacity:   capVal,
		defaultTTL: opts.DefaultTTL,
		entries:    make(map[string]*cacheEntry),
		nowFunc:    nowFn,
	}
}

// Get 从缓存中获取凭据副本。
// 若未命中或已过期，返回 (Secret{}, false)。
// 若命中且未过期，将该项提升至 LRU 头部并返回其深拷贝副本。
func (c *Cache) Get(ref Ref) (Secret, bool) {
	if c == nil || c.capacity <= 0 {
		return Secret{}, false
	}
	key := ref.String()
	if key == "" {
		return Secret{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		return Secret{}, false
	}

	now := c.nowFunc()
	if entry.hasExpiry && now.After(entry.expiresAt) {
		// 惰性删除过期项
		c.removeEntryLocked(entry)
		return Secret{}, false
	}

	c.moveToHeadLocked(entry)
	return entry.secret.Clone(), true
}

// Put 将凭据写入缓存。
// 凭据数据将被深拷贝存入，计算过期时间为 min(cacheTTL, backend_expires_at)。
// 当容量超出时，最久未使用的项将被淘汰并清零内存。
func (c *Cache) Put(ref Ref, secret Secret) {
	if c == nil || c.capacity <= 0 {
		return
	}
	key := ref.String()
	if key == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 如果旧条目存在，先移除并清零
	if existing, exists := c.entries[key]; exists {
		c.removeEntryLocked(existing)
	}

	// 淘汰尾部直到未超出容量限制
	for len(c.entries) >= c.capacity && c.tail != nil {
		c.removeEntryLocked(c.tail)
	}

	now := c.nowFunc()
	expiresAt, hasExpiry := c.calculateExpiry(now, secret.ExpiresAt)

	entry := &cacheEntry{
		key:       key,
		secret:    secret.Clone(),
		expiresAt: expiresAt,
		hasExpiry: hasExpiry,
	}

	c.addToHeadLocked(entry)
	c.entries[key] = entry
}

// Invalidate 使指定引用的缓存条目立即失效，并清零其内存。
func (c *Cache) Invalidate(ref Ref) {
	if c == nil {
		return
	}
	key := ref.String()
	if key == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.entries[key]; exists {
		c.removeEntryLocked(entry)
	}
}

// Clear 清空全部缓存条目并对所有机密字节执行 Zero 清零。
func (c *Cache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	curr := c.head
	for curr != nil {
		next := curr.next
		curr.secret.Zero()
		curr.prev = nil
		curr.next = nil
		curr = next
	}
	c.entries = make(map[string]*cacheEntry)
	c.head = nil
	c.tail = nil
}

// Len 返回当前有效缓存条目数量。
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) calculateExpiry(now time.Time, backendExp *time.Time) (time.Time, bool) {
	hasTTL := c.defaultTTL > 0
	hasBackendExp := backendExp != nil

	if !hasTTL && !hasBackendExp {
		return time.Time{}, false
	}

	if hasTTL && !hasBackendExp {
		return now.Add(c.defaultTTL), true
	}

	if !hasTTL && hasBackendExp {
		return *backendExp, true
	}

	ttlExp := now.Add(c.defaultTTL)
	if backendExp.Before(ttlExp) {
		return *backendExp, true
	}
	return ttlExp, true
}

func (c *Cache) addToHeadLocked(entry *cacheEntry) {
	entry.next = c.head
	entry.prev = nil
	if c.head != nil {
		c.head.prev = entry
	}
	c.head = entry
	if c.tail == nil {
		c.tail = entry
	}
}

func (c *Cache) moveToHeadLocked(entry *cacheEntry) {
	if c.head == entry {
		return
	}
	c.detachLocked(entry)
	c.addToHeadLocked(entry)
}

func (c *Cache) detachLocked(entry *cacheEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		c.head = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		c.tail = entry.prev
	}
	entry.prev = nil
	entry.next = nil
}

func (c *Cache) removeEntryLocked(entry *cacheEntry) {
	delete(c.entries, entry.key)
	c.detachLocked(entry)
	entry.secret.Zero()
}

// CachedSource 将 Source 装饰为带本地有界缓存的只读凭据源。
type CachedSource struct {
	underlying Source
	cache      *Cache
}

// NewCachedSource 创建带缓存的只读凭据源。
func NewCachedSource(source Source, cache *Cache) *CachedSource {
	return &CachedSource{
		underlying: source,
		cache:      cache,
	}
}

// Get 优先从缓存获取凭据；未命中时在锁外调用底层存储，成功后再写入缓存并返回。
func (cs *CachedSource) Get(ctx context.Context, ref Ref) (Secret, error) {
	if cs == nil || cs.underlying == nil {
		return Secret{}, fmt.Errorf("cached source is not initialized")
	}

	if cs.cache != nil {
		if sec, found := cs.cache.Get(ref); found {
			return sec, nil
		}
	}

	// 必须在锁外调用底层存储 I/O
	sec, err := cs.underlying.Get(ctx, ref)
	if err != nil {
		return Secret{}, err
	}

	if cs.cache != nil {
		cs.cache.Put(ref, sec)
	}

	return sec.Clone(), nil
}

// CachedStore 将 Store 装饰为带本地有界缓存的可读写凭据存储。
type CachedStore struct {
	CachedSource
	underlyingStore Store
}

// NewCachedStore 创建带缓存的可读写凭据存储。
func NewCachedStore(store Store, cache *Cache) *CachedStore {
	return &CachedStore{
		CachedSource: CachedSource{
			underlying: store,
			cache:      cache,
		},
		underlyingStore: store,
	}
}

// Put 向底层存储写入凭据。写入前使旧缓存失效，写入成功后将新凭据写入缓存。
func (cs *CachedStore) Put(ctx context.Context, ref Ref, secret Secret) error {
	if cs == nil || cs.underlyingStore == nil {
		return fmt.Errorf("cached store is not initialized")
	}

	if cs.cache != nil {
		cs.cache.Invalidate(ref)
	}

	// 锁外执行底层存储写入
	if err := cs.underlyingStore.Put(ctx, ref, secret); err != nil {
		return err
	}

	if cs.cache != nil {
		cs.cache.Put(ref, secret)
	}
	return nil
}

// Delete 从底层存储删除凭据，并立即使缓存项失效。
func (cs *CachedStore) Delete(ctx context.Context, ref Ref) error {
	if cs == nil || cs.underlyingStore == nil {
		return fmt.Errorf("cached store is not initialized")
	}

	if cs.cache != nil {
		cs.cache.Invalidate(ref)
	}

	// 锁外执行底层存储删除
	err := cs.underlyingStore.Delete(ctx, ref)
	if cs.cache != nil {
		cs.cache.Invalidate(ref)
	}
	return err
}
