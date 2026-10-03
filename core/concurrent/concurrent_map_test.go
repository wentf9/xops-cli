package concurrent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

func newTestMap() *Map[string, int] {
	return NewMap[string, int](HashString)
}

func TestSetGet(t *testing.T) {
	m := newTestMap()
	m.Set("a", 1)
	m.Set("b", 2)

	if v, ok := m.Get("a"); !ok || v != 1 {
		t.Errorf("Get(a) = (%v, %v), want (1, true)", v, ok)
	}
	if v, ok := m.Get("b"); !ok || v != 2 {
		t.Errorf("Get(b) = (%v, %v), want (2, true)", v, ok)
	}
	if _, ok := m.Get("c"); ok {
		t.Error("Get(c) should return false for nonexistent key")
	}
}

func TestRemove(t *testing.T) {
	m := newTestMap()
	m.Set("x", 42)
	m.Remove("x")

	if _, ok := m.Get("x"); ok {
		t.Error("expected key to be removed")
	}
}

func TestCount(t *testing.T) {
	m := newTestMap()
	for i := range 100 {
		m.Set(fmt.Sprintf("key%d", i), i)
	}
	if c := m.Count(); c != 100 {
		t.Errorf("Count() = %d, want 100", c)
	}
}

func TestKeys(t *testing.T) {
	m := newTestMap()
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)

	keys := m.Keys()
	if len(keys) != 3 {
		t.Errorf("len(Keys()) = %d, want 3", len(keys))
	}

	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	for _, expected := range []string{"a", "b", "c"} {
		if !keySet[expected] {
			t.Errorf("Keys() missing %q", expected)
		}
	}
}

func TestMSet(t *testing.T) {
	m := newTestMap()
	data := map[string]int{"x": 10, "y": 20, "z": 30}
	m.MSet(data)

	if c := m.Count(); c != 3 {
		t.Errorf("Count() = %d after MSet, want 3", c)
	}
	if v, _ := m.Get("y"); v != 20 {
		t.Errorf("Get(y) = %d, want 20", v)
	}
}

func TestPop(t *testing.T) {
	m := newTestMap()
	m.Set("key", 99)

	val, ok := m.Pop("key")
	if !ok || val != 99 {
		t.Errorf("Pop(key) = (%d, %v), want (99, true)", val, ok)
	}
	if _, ok = m.Get("key"); ok {
		t.Error("key should be removed after Pop")
	}

	// Pop 不存在的 key
	_, ok = m.Pop("nonexistent")
	if ok {
		t.Error("Pop of nonexistent key should return false")
	}
}

func TestUpsert(t *testing.T) {
	m := newTestMap()

	// 初始插入
	v := m.Upsert("counter", func(exist bool, old int) int {
		if exist {
			return old + 1
		}
		return 1
	})
	if v != 1 {
		t.Errorf("first Upsert = %d, want 1", v)
	}

	// 更新
	v = m.Upsert("counter", func(exist bool, old int) int {
		if exist {
			return old + 1
		}
		return 1
	})
	if v != 2 {
		t.Errorf("second Upsert = %d, want 2", v)
	}
}

func TestSetIfAbsent(t *testing.T) {
	m := newTestMap()
	m.Set("existing", 100)

	// 已存在的 key：不覆盖
	val, inserted := m.SetIfAbsent("existing", 999)
	if inserted {
		t.Error("SetIfAbsent should not overwrite existing key")
	}
	if val != 100 {
		t.Errorf("SetIfAbsent returned %d, want 100 (old value)", val)
	}

	// 不存在的 key：写入
	val, inserted = m.SetIfAbsent("new", 42)
	if !inserted {
		t.Error("SetIfAbsent should insert new key")
	}
	if val != 42 {
		t.Errorf("SetIfAbsent returned %d, want 42", val)
	}
}

func TestClear(t *testing.T) {
	m := newTestMap()
	m.MSet(map[string]int{"a": 1, "b": 2, "c": 3})
	m.Clear()

	if c := m.Count(); c != 0 {
		t.Errorf("Count() = %d after Clear, want 0", c)
	}
}

func TestIterCb_EarlyBreak(t *testing.T) {
	m := NewMap(HashInt, WithShardCount[int, int](1))
	for i := range 10 {
		m.Set(i, i*10)
	}

	count := 0
	m.IterCb(func(k int, v int) bool {
		count++
		return count < 3 // 只遍历 3 个就停
	})

	if count != 3 {
		t.Errorf("IterCb visited %d items, want 3", count)
	}
}

func TestConcurrentAccess(t *testing.T) {
	m := newTestMap()
	const goroutines = 50
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range opsPerGoroutine {
				key := fmt.Sprintf("g%d-k%d", id, i)
				m.Set(key, i)
				m.Get(key)
				if i%3 == 0 {
					m.Remove(key)
				}
			}
		}(g)
	}

	wg.Wait()
	// 只要不 panic / data race 即通过
}

func TestMarshalJSON_UnmarshalJSON(t *testing.T) {
	m := newTestMap()
	m.Set("alpha", 1)
	m.Set("beta", 2)

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}

	m2 := newTestMap()
	if err := json.Unmarshal(data, m2); err != nil {
		t.Fatalf("UnmarshalJSON failed: %v", err)
	}

	if v, ok := m2.Get("alpha"); !ok || v != 1 {
		t.Errorf("after JSON round-trip: Get(alpha) = (%d, %v), want (1, true)", v, ok)
	}
	if v, ok := m2.Get("beta"); !ok || v != 2 {
		t.Errorf("after JSON round-trip: Get(beta) = (%d, %v), want (2, true)", v, ok)
	}
}

func TestMarshalYAML_UnmarshalYAML(t *testing.T) {
	type wrapper struct {
		Data *Map[string, int] `yaml:"data"`
	}

	m := newTestMap()
	m.Set("x", 10)
	m.Set("y", 20)

	w := wrapper{Data: m}
	data, err := yaml.Marshal(w)
	if err != nil {
		t.Fatalf("MarshalYAML failed: %v", err)
	}

	w2 := wrapper{Data: newTestMap()}
	if err := yaml.Unmarshal(data, &w2); err != nil {
		t.Fatalf("UnmarshalYAML failed: %v", err)
	}

	if v, ok := w2.Data.Get("x"); !ok || v != 10 {
		t.Errorf("after YAML round-trip: Get(x) = (%d, %v), want (10, true)", v, ok)
	}
}

func TestWithShardCount(t *testing.T) {
	m := NewMap(HashString, WithShardCount[string, int](4))
	m.Set("test", 1)

	if v, ok := m.Get("test"); !ok || v != 1 {
		t.Errorf("custom shard count: Get(test) = (%d, %v), want (1, true)", v, ok)
	}
}

func TestRemoveIfMatch(t *testing.T) {
	m := newTestMap()
	m.Set("k", 1)

	// 值匹配：删除成功
	if !RemoveIfMatch(m, "k", 1) {
		t.Error("RemoveIfMatch with matching value should return true")
	}
	if _, ok := m.Get("k"); ok {
		t.Error("key should be removed when value matches")
	}

	// 值不匹配：不删除
	m.Set("k", 2)
	if RemoveIfMatch(m, "k", 1) {
		t.Error("RemoveIfMatch with stale value should return false")
	}
	if v, ok := m.Get("k"); !ok || v != 2 {
		t.Errorf("current value must survive stale RemoveIfMatch, got (%d, %v)", v, ok)
	}

	// key 不存在：返回 false
	if RemoveIfMatch(m, "absent", 1) {
		t.Error("RemoveIfMatch on missing key should return false")
	}
}

// TestRemoveIfMatch_ConcurrentReplace 验证条件删除与并发写入竞争时不会误删新值
func TestRemoveIfMatch_ConcurrentReplace(t *testing.T) {
	m := newTestMap()
	const oldValue, newValue = 1, 2
	m.Set("k", oldValue)

	replaced := make(chan struct{})
	removed := make(chan bool, 1)
	go func() {
		<-replaced // 确保并发写入完成后，再用旧值尝试条件删除
		removed <- RemoveIfMatch(m, "k", oldValue)
	}()

	m.Set("k", newValue) // 模拟并发重连替换
	close(replaced)

	if <-removed {
		t.Error("RemoveIfMatch must not delete when value was concurrently replaced")
	}
	if v, ok := m.Get("k"); !ok || v != newValue {
		t.Errorf("expected new value %d to survive, got (%d, %v)", newValue, v, ok)
	}
}

// TestRemoveIfMatch_ConcurrentStress 并发读写同一 key，配合 -race 验证无数据竞争
func TestRemoveIfMatch_ConcurrentStress(t *testing.T) {
	m := newTestMap()
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(2)
		go func(v int) {
			defer wg.Done()
			m.Set("k", v)
		}(i)
		go func(v int) {
			defer wg.Done()
			RemoveIfMatch(m, "k", v)
		}(i)
	}
	wg.Wait()
}

type errWriter struct {
	failAfter int
	written   int
}

func (w *errWriter) Write(p []byte) (n int, err error) {
	if w.written >= w.failAfter {
		return 0, errors.New("simulated write error")
	}
	w.written += len(p)
	return len(p), nil
}

func TestMap_Print(t *testing.T) {
	m := newTestMap()
	m.Set("k1", 100)
	m.Set("k2", 200)

	var buf bytes.Buffer
	if err := m.Print(&buf); err != nil {
		t.Fatalf("expected nil error on valid write, got %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, "--- ConcurrentMap Content ---") {
		t.Errorf("expected header, got %s", output)
	}
	if !strings.Contains(output, "--- Total: 2 items ---") {
		t.Errorf("expected total count, got %s", output)
	}

	// 验证写失败时返回错误
	ew := &errWriter{failAfter: 5}
	if err := m.Print(ew); err == nil {
		t.Error("expected write error from Print with failing writer, got nil")
	}
}
