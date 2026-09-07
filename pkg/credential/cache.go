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
	mu          sync.Mutex
	capacity    int
	defaultTTL  time.Duration
	entries     map[string]*cacheEntry
	generations map[string]uint64
	head        *cacheEntry // 最近使用的项
	tail        *cacheEntry // 最久未使用的项
	nowFunc     func() time.Time
}

// CacheOptions 包含初始化凭据缓存的可选参数。
type CacheOptions struct {
	Capacity   int
	DefaultTTL time.Duration
	NowFunc    func() time.Time
}

// NewCache 创建一个新的有界凭据缓存。
// capacity <= 0 或 DefaultTTL <= 0 明确表示完全禁用缓存。
func NewCache(opts CacheOptions) *Cache {
	capVal := opts.Capacity
	if capVal < 0 {
		capVal = 0
	}
	ttlVal := opts.DefaultTTL
	if ttlVal < 0 {
		// 拒绝负数 TTL，设为 0
		ttlVal = 0
	}
	nowFn := opts.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Cache{
		capacity:    capVal,
		defaultTTL:  ttlVal,
		entries:     make(map[string]*cacheEntry),
		generations: make(map[string]uint64),
		nowFunc:     nowFn,
	}
}

// Get 从缓存中获取凭据副本。
// 若未命中或已过期，返回 (Secret{}, false)。
// 若命中且未过期，将该项提升至 LRU 头部并返回其深拷贝副本。
func (c *Cache) Get(ref Ref) (Secret, bool) {
	if c == nil || c.capacity <= 0 || c.defaultTTL <= 0 {
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

// StartFetch 获取指定引用的当前版本号（generation），作为在途读取的栅栏令牌。
func (c *Cache) StartFetch(ref Ref) uint64 {
	if c == nil || c.capacity <= 0 || c.defaultTTL <= 0 {
		return 0
	}
	key := ref.String()
	if key == "" {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.generations[key]
}

// Put 将凭据写入缓存。
func (c *Cache) Put(ref Ref, secret Secret) {
	if c == nil || c.capacity <= 0 || c.defaultTTL <= 0 {
		return
	}
	key := ref.String()
	if key == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 主动 Put 会使当前世代递增，废弃在途旧 Get
	c.generations[key]++
	c.putLocked(key, secret)
}

// PutIfMatch 只有当缓存条目的 generation 仍等于 expectedGen 时才写入缓存。
// 若在读取期间发生了 Invalidate/Delete/Clear，将安全放弃回填。
func (c *Cache) PutIfMatch(ref Ref, secret Secret, expectedGen uint64) {
	if c == nil || c.capacity <= 0 || c.defaultTTL <= 0 {
		return
	}
	key := ref.String()
	if key == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.generations[key] != expectedGen {
		return
	}
	c.putLocked(key, secret)
}

func (c *Cache) putLocked(key string, secret Secret) {
	now := c.nowFunc()
	expiresAt, hasExpiry := c.calculateExpiry(now, secret.ExpiresAt)
	if !hasExpiry {
		// 零 TTL 或无有效未来过期时间，不存入缓存
		return
	}

	// 如果旧条目存在，先移除并清零
	if existing, exists := c.entries[key]; exists {
		c.removeEntryLocked(existing)
	}

	// 淘汰尾部直到未超出容量限制
	for len(c.entries) >= c.capacity && c.tail != nil {
		c.removeEntryLocked(c.tail)
	}

	entry := &cacheEntry{
		key:       key,
		secret:    secret.Clone(),
		expiresAt: expiresAt,
		hasExpiry: true,
	}

	c.addToHeadLocked(entry)
	c.entries[key] = entry
}

// Invalidate 使指定引用的缓存条目立即失效，递增其 generation 栅栏，并清零内存。
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

	c.generations[key]++
	if entry, exists := c.entries[key]; exists {
		c.removeEntryLocked(entry)
	}
}

// Clear 清空全部缓存条目，递增所有 generation，并对所有机密字节执行 Zero 清零。
func (c *Cache) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for k := range c.generations {
		c.generations[k]++
	}

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
	// 设计规范：cache_ttl 零值具有明确的禁用语义
	if c.defaultTTL <= 0 {
		return time.Time{}, false
	}

	ttlExp := now.Add(c.defaultTTL)
	if backendExp == nil {
		return ttlExp, true
	}

	if backendExp.Before(ttlExp) {
		if backendExp.Before(now) {
			return time.Time{}, false
		}
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

// Get 优先从缓存获取凭据；未命中时在锁外调用底层存储，使用 generation 栅栏防并发回填。
func (cs *CachedSource) Get(ctx context.Context, ref Ref) (Secret, error) {
	if cs == nil || cs.underlying == nil {
		return Secret{}, fmt.Errorf("cached source is not initialized")
	}

	if cs.cache != nil {
		if sec, found := cs.cache.Get(ref); found {
			return sec, nil
		}
	}

	var fetchToken uint64
	if cs.cache != nil {
		fetchToken = cs.cache.StartFetch(ref)
	}

	// 必须在锁外调用底层存储 I/O
	sec, err := cs.underlying.Get(ctx, ref)
	if err != nil {
		return Secret{}, err
	}

	if cs.cache != nil {
		cs.cache.PutIfMatch(ref, sec, fetchToken)
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

// Put 向底层存储写入凭据。
// 写入前后均使缓存失效，绝不提前缓存输入值，确保后续写后读回校验（Get）能穿透到底层后端。
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

	// 写入完成后再次显式失效，强制随后的写后读回直达后端
	if cs.cache != nil {
		cs.cache.Invalidate(ref)
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
