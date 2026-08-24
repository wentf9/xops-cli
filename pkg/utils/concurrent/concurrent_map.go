package concurrent

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// 默认分片数量
const DEFAULT_SHARD_COUNT = 32

// Option 定义配置函数的类型
type Option[K comparable, V any] func(*Map[K, V])

// WithShardCount 允许用户自定义分片数量
// count: 建议设置为 2 的幂 (如 16, 32, 64, 128)
func WithShardCount[K comparable, V any](count uint32) Option[K, V] {
	return func(m *Map[K, V]) {
		m.shardCount = count
	}
}

// Map 是我们暴露给外部的主结构体
// K: 键的类型 (必须是可比较的)
// V: 值的类型 (任意)
type Map[K comparable, V any] struct {
	shards   []*ConcurrentMapShard[K, V]
	hashFunc func(K) uint32 // 用于计算 Key 的哈希值，决定分片位置
	// 定义分片的数量
	// 通常建议设置为 2 的幂次方，例如 32, 64 等
	// 数量越多，锁的粒度越小，并发性能越好，但内存开销稍大
	shardCount uint32
}

// ConcurrentMapShard 是内部的分片结构
// 每个分片拥有自己的锁和原生 Map
type ConcurrentMapShard[K comparable, V any] struct {
	items        map[K]V
	sync.RWMutex // 读写锁，读写分离提高性能
}

// NewMap 创建一个新的并发 Map
// hashFunc: 需要用户传入一个函数，将 Key 转换为 uint32 整数
func NewMap[K comparable, V any](hashFunc func(K) uint32, opts ...Option[K, V]) *Map[K, V] {
	m := &Map[K, V]{
		shardCount: DEFAULT_SHARD_COUNT,
		hashFunc:   hashFunc,
	}

	// 应用用户传入的配置
	for _, opt := range opts {
		opt(m)
	}

	m.shards = make([]*ConcurrentMapShard[K, V], m.shardCount)
	// 初始化每个分片
	for i := range m.shardCount {
		m.shards[i] = &ConcurrentMapShard[K, V]{
			items: make(map[K]V),
		}
	}
	return m
}

// getShard 根据 Key 获取对应的分片
func (m *Map[K, V]) getShard(key K) *ConcurrentMapShard[K, V] {
	hash := m.hashFunc(key)
	// 使用位运算取模 (前提是 SHARD_COUNT 必须是 2 的幂，这里为了通用使用 %)
	return m.shards[hash%m.shardCount]
}

// Set 写入键值对
func (m *Map[K, V]) Set(key K, value V) {
	shard := m.getShard(key)
	shard.Lock() // 加写锁
	defer shard.Unlock()
	shard.items[key] = value
}

// Get 读取键值对
func (m *Map[K, V]) Get(key K) (V, bool) {
	shard := m.getShard(key)
	shard.RLock() // 加读锁
	defer shard.RUnlock()
	val, ok := shard.items[key]
	return val, ok
}

// Remove 删除键值对
func (m *Map[K, V]) Remove(key K) {
	shard := m.getShard(key)
	shard.Lock()
	defer shard.Unlock()
	delete(shard.items, key)
}

// Count 统计所有元素的数量（大概率是准的，但在极高并发下是近似值）
func (m *Map[K, V]) Count() int {
	count := 0
	for i := range m.shardCount {
		shard := m.shards[i]
		shard.RLock()
		count += len(shard.items)
		shard.RUnlock()
	}
	return count
}

// Keys 获取所有的 Key
func (m *Map[K, V]) Keys() []K {
	keys := make([]K, 0)
	for i := range m.shardCount {
		shard := m.shards[i]
		shard.RLock()
		for k := range shard.items {
			keys = append(keys, k)
		}
		shard.RUnlock()
	}
	return keys
}

// IterCb 接受一个回调函数 fn
// fn 的参数是 key 和 value
// fn 的返回值是一个 bool：如果返回 true，继续遍历；如果返回 false，停止遍历。
func (m *Map[K, V]) IterCb(fn func(key K, v V) bool) {
	// 逐个遍历分片
	for i := range m.shardCount {
		shard := m.shards[i]

		// 加读锁：遍历期间，该分片不允许写入，但允许其他协程读取
		// 注意：我们是一次锁一个分片，而不是锁整个 Map，这样能减少对性能的影响
		shard.RLock()

		for k, v := range shard.items {
			// 执行用户的回调逻辑
			keepGoing := fn(k, v)

			// 如果用户返回 false，表示想提前结束遍历
			if !keepGoing {
				shard.RUnlock()
				return
			}
		}

		// 当前分片遍历完，释放锁，继续下一个分片
		shard.RUnlock()
	}
}

// MarshalJSON 实现 json.Marshaler 接口
// 当你调用 json.Marshal(cMap) 时，会自动调用此方法
func (m *Map[K, V]) MarshalJSON() ([]byte, error) {
	// 1. 创建一个临时的标准 Map
	tmp := make(map[K]V)

	// 2. 遍历所有分片，将数据复制到临时 Map 中
	// 这一步相当于给当前状态做一个“快照”
	for i := range m.shardCount {
		shard := m.shards[i]
		shard.RLock()
		maps.Copy(tmp, shard.items)
		shard.RUnlock()
	}

	// 3. 使用标准库序列化这个临时 Map
	return json.Marshal(tmp)
}

// UnmarshalJSON 实现 json.Unmarshaler 接口
// 当你调用 json.Unmarshal(data, cMap) 时，会自动调用此方法
func (m *Map[K, V]) UnmarshalJSON(b []byte) error {
	// 1. 创建一个临时的标准 Map 用于承接解析的数据
	tmp := make(map[K]V)

	// 2. 解析 JSON 数据到临时 Map
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}

	// 3. 将数据从临时 Map 转移到 ConcurrentMap
	// 注意：这里假设 m 已经被 NewConcurrentMap 初始化过（拥有 shards 和 hashFunc）
	for k, v := range tmp {
		m.Set(k, v)
	}

	return nil
}

// ==========================================
// YAML 序列化支持 (gopkg.in/yaml.v3)
// ==========================================

// MarshalYAML 实现 yaml.Marshaler 接口
// 当调用 yaml.Marshal(cMap) 时会自动触发
func (m *Map[K, V]) MarshalYAML() (interface{}, error) {
	// 1. 创建一个临时的普通 Map
	tmp := make(map[K]V)

	// 2. 遍历分片，将数据快照复制到临时 Map
	for i := uint32(0); i < m.shardCount; i++ {
		shard := m.shards[i]
		shard.RLock()
		maps.Copy(tmp, shard.items)
		shard.RUnlock()
	}

	// 3. 直接返回临时 Map，yaml 库会自动处理它的序列化
	return tmp, nil
}

// UnmarshalYAML 实现 yaml.Unmarshaler 接口
// 当调用 yaml.Unmarshal(data, cMap) 时会自动触发
func (m *Map[K, V]) UnmarshalYAML(value *yaml.Node) error {
	// 1. 创建一个临时的普通 Map 用于承接解析的数据
	tmp := make(map[K]V)

	// 2. 使用 yaml.Node 的 Decode 方法将数据解析到临时 Map 中
	if err := value.Decode(&tmp); err != nil {
		return err
	}

	// 3. 将数据从临时 Map 转移到 ConcurrentMap
	// 注意：这里假设 m 已经被 NewConcurrentMap 初始化过
	for k, v := range tmp {
		m.Set(k, v)
	}

	return nil
}

// Clear 清空 Map 中的所有数据
// 策略：直接用一个新的空 Map 替换旧 Map，而不是逐个删除 Key
func (m *Map[K, V]) Clear() {
	for i := range m.shardCount {
		shard := m.shards[i]
		shard.Lock()
		// 直接重新分配内存，旧的 map 会被 GC 回收
		shard.items = make(map[K]V)
		shard.Unlock()
	}
}

// MSet 批量写入多个键值对
// 策略：预先将数据按分片归类，减少锁的竞争次数
func (m *Map[K, V]) MSet(data map[K]V) {
	// 1. 创建临时存储，用于将输入的数据按“分片索引”归类
	// batchedData[i] 存放属于第 i 个分片的所有数据
	batchedData := make([]map[K]V, m.shardCount)

	// 2. 遍历输入数据，计算哈希，分配到对应的临时组中
	// 这一步是纯内存操作，不涉及锁，速度极快
	for key, value := range data {
		shardIndex := m.hashFunc(key) % m.shardCount

		if batchedData[shardIndex] == nil {
			batchedData[shardIndex] = make(map[K]V)
		}
		batchedData[shardIndex][key] = value
	}

	// 3. 遍历临时组，对每个分片只需加一次锁，然后批量写入
	for i, items := range batchedData {
		if items == nil {
			continue // 如果该分片没有数据需要写入，直接跳过
		}

		shard := m.shards[i]
		shard.Lock() // 获取锁
		maps.Copy(shard.items, items)
		shard.Unlock() // 释放锁
	}
}

// Pop 从 Map 中删除一个 Key，并返回它被删除之前的值
// 如果 Key 不存在，返回零值和 false
func (m *Map[K, V]) Pop(key K) (V, bool) {
	shard := m.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	val, ok := shard.items[key]
	if ok {
		delete(shard.items, key)
	}
	return val, ok
}

// RemoveIfMatch 原子的"比较并删除"：仅当 key 当前对应的值与 expected 相等（== 比较）时才删除。
// 用于防止"读取-比对-删除"三步之间被并发写替换后误删新值的竞态。
// 返回是否实际发生了删除。要求 V 可比较（如指针类型）
func RemoveIfMatch[K comparable, V comparable](m *Map[K, V], key K, expected V) bool {
	shard := m.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	current, ok := shard.items[key]
	if !ok || current != expected {
		return false
	}
	delete(shard.items, key)
	return true
}

// Upsert 提供原子性的“读取-修改-回写”操作
// cb: 回调函数，参数是 (是否存在, 旧值)。返回值将作为新值写入 Map。
// 返回值: 最终写入 Map 的新值
func (m *Map[K, V]) Upsert(key K, cb func(exist bool, valueInMap V) V) V {
	shard := m.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	// 1. 读取当前值
	oldVal, ok := shard.items[key]

	// 2. 调用用户回调，计算新值 (这一步在锁内，绝对安全)
	newVal := cb(ok, oldVal)

	// 3. 写入新值
	shard.items[key] = newVal

	return newVal
}

// SetIfAbsent 如果 Key 不存在，则写入值；如果存在，则什么都不做
// 返回值: (实际存储的值, 是否是新写入的)
// 如果返回 true，说明写入成功；如果返回 false，说明 Key 已存在，返回旧值
func (m *Map[K, V]) SetIfAbsent(key K, value V) (V, bool) {
	shard := m.getShard(key)
	shard.Lock()
	defer shard.Unlock()

	oldVal, ok := shard.items[key]
	if ok {
		return oldVal, false
	}

	shard.items[key] = value
	return value, true
}

// String 实现 fmt.Stringer 接口
// 这允许你直接使用 fmt.Println(cMap)
// 输出格式示例: {key1: val1, key2: val2}
func (m *Map[K, V]) String() string {
	var parts []string

	// 使用我们之前写的 IterCb 安全遍历
	m.IterCb(func(k K, v V) bool {
		// %v 占位符会自动适配各种类型
		parts = append(parts, fmt.Sprintf("%v:%v", k, v))
		return true
	})

	return "{" + strings.Join(parts, ", ") + "}"
}

// Print 逐行打印所有键值对 (适合数据量较大时查看)
// 格式:
// [Key] val
// [Key] val
func (m *Map[K, V]) Print(w io.Writer) {
	_, _ = fmt.Fprintln(w, "--- ConcurrentMap Content ---")
	count := 0
	m.IterCb(func(k K, v V) bool {
		_, _ = fmt.Fprintf(w, "[%v] %v\n", k, v)
		count++
		return true
	})
	_, _ = fmt.Fprintf(w, "--- Total: %d items ---\n", count)
}

// PrettyPrint 以格式化的 JSON 样式打印 (适合调试复杂结构)
// 需要引入 "encoding/json"
func (m *Map[K, V]) PrettyPrint() string {
	// 复用我们之前实现的 MarshalJSON
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}
