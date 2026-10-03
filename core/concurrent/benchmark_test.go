package concurrent

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ==============================================================================
// Benchmark — 性能基准测试
// ==============================================================================

// BenchmarkSet 测试纯写入性能
func BenchmarkSet(b *testing.B) {
	m := NewMap[string, int](HashString)
	b.ResetTimer()
	for i := range b.N {
		m.Set(fmt.Sprintf("key-%d", i), i)
	}
}

// BenchmarkGet 测试纯读取性能（预填充数据）
func BenchmarkGet(b *testing.B) {
	m := NewMap[string, int](HashString)
	for i := range 10000 {
		m.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	for i := range b.N {
		m.Get(fmt.Sprintf("key-%d", i%10000))
	}
}

// BenchmarkMixedReadWrite 测试 90% 读 10% 写的混合场景
func BenchmarkMixedReadWrite(b *testing.B) {
	m := NewMap[string, int](HashString)
	for i := range 10000 {
		m.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	for i := range b.N {
		if i%10 == 0 {
			m.Set(fmt.Sprintf("key-%d", i%10000), i)
		} else {
			m.Get(fmt.Sprintf("key-%d", i%10000))
		}
	}
}

// BenchmarkConcurrentSet 测试并发写入性能
func BenchmarkConcurrentSet(b *testing.B) {
	m := NewMap[string, int](HashString)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Set(fmt.Sprintf("key-%d", i), i)
			i++
		}
	})
}

// BenchmarkConcurrentGet 测试并发读取性能
func BenchmarkConcurrentGet(b *testing.B) {
	m := NewMap[string, int](HashString)
	for i := range 10000 {
		m.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			m.Get(fmt.Sprintf("key-%d", i%10000))
			i++
		}
	})
}

// BenchmarkConcurrentMixed 测试并发混合读写
func BenchmarkConcurrentMixed(b *testing.B) {
	m := NewMap[string, int](HashString)
	for i := range 10000 {
		m.Set(fmt.Sprintf("key-%d", i), i)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%10 == 0 {
				m.Set(fmt.Sprintf("key-%d", i%10000), i)
			} else {
				m.Get(fmt.Sprintf("key-%d", i%10000))
			}
			i++
		}
	})
}

// BenchmarkMSet 测试批量写入性能
func BenchmarkMSet(b *testing.B) {
	batch := make(map[string]int, 100)
	for i := range 100 {
		batch[fmt.Sprintf("key-%d", i)] = i
	}
	m := NewMap[string, int](HashString)
	b.ResetTimer()
	for range b.N {
		m.MSet(batch)
	}
}

// BenchmarkShardCount 对比不同分片数量的写入性能
func BenchmarkShardCount(b *testing.B) {
	shardCounts := []uint32{1, 4, 16, 32, 64, 128}
	for _, sc := range shardCounts {
		b.Run(fmt.Sprintf("shards-%d", sc), func(b *testing.B) {
			m := NewMap(HashString, WithShardCount[string, int](sc))
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					m.Set(fmt.Sprintf("key-%d", i), i)
					i++
				}
			})
		})
	}
}

// ==============================================================================
// Stress Test — 压力测试
// ==============================================================================

// TestStress_HighConcurrency 高并发压力测试
// 100 个 goroutine 同时进行混合操作（写/读/删/Upsert），验证数据一致性
func TestStress_HighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	m := NewMap[int, int](HashInt)
	const (
		goroutines = 100
		opsPerG    = 5000
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(uint64(id), uint64(id+1)))
			for i := range opsPerG {
				key := rng.IntN(1000) // 键空间 [0, 1000)，制造竞争
				switch i % 5 {
				case 0: // 20% 写入
					m.Set(key, id*opsPerG+i)
				case 1, 2: // 40% 读取
					m.Get(key)
				case 3: // 20% 删除
					m.Remove(key)
				case 4: // 20% Upsert
					m.Upsert(key, func(exist bool, old int) int {
						if exist {
							return old + 1
						}
						return 1
					})
				}
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	totalOps := goroutines * opsPerG
	opsPerSec := float64(totalOps) / elapsed.Seconds()

	t.Logf("=== 高并发压力测试结果 ===")
	t.Logf("  Goroutines:    %d", goroutines)
	t.Logf("  每 G 操作数:    %d", opsPerG)
	t.Logf("  总操作数:      %d", totalOps)
	t.Logf("  耗时:          %v", elapsed)
	t.Logf("  吞吐量:        %.0f ops/sec", opsPerSec)
	t.Logf("  最终元素数:    %d", m.Count())
}

// TestStress_DataIntegrity 数据完整性压力测试
// 并发写入已知数据，完成后验证所有数据完整存在
func TestStress_DataIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	m := NewMap[string, int](HashString)
	const (
		goroutines = 50
		keysPerG   = 1000
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	// 每个 goroutine 写入独占的 key 空间
	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			for i := range keysPerG {
				key := fmt.Sprintf("g%d-k%d", id, i)
				m.Set(key, id*keysPerG+i)
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// 验证 — 每个 key 必须存在且值正确
	expectedCount := goroutines * keysPerG
	if got := m.Count(); got != expectedCount {
		t.Errorf("Count = %d, want %d", got, expectedCount)
	}

	var missing, incorrect int
	for g := range goroutines {
		for i := range keysPerG {
			key := fmt.Sprintf("g%d-k%d", g, i)
			val, ok := m.Get(key)
			if !ok {
				missing++
			} else if val != g*keysPerG+i {
				incorrect++
			}
		}
	}

	totalOps := goroutines * keysPerG
	opsPerSec := float64(totalOps) / elapsed.Seconds()

	t.Logf("=== 数据完整性压力测试结果 ===")
	t.Logf("  Goroutines:    %d", goroutines)
	t.Logf("  总写入 Key:    %d", totalOps)
	t.Logf("  耗时:          %v", elapsed)
	t.Logf("  写入吞吐量:    %.0f ops/sec", opsPerSec)
	t.Logf("  数据丢失:      %d", missing)
	t.Logf("  数据错误:      %d", incorrect)

	if missing > 0 {
		t.Errorf("data loss: %d keys missing", missing)
	}
	if incorrect > 0 {
		t.Errorf("data corruption: %d keys have incorrect values", incorrect)
	}
}

// TestStress_UpsertCounter 原子计数器压力测试
// 多个 goroutine 对同一个 key 进行 Upsert 累加，验证最终值等于总操作数
func TestStress_UpsertCounter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	m := NewMap[string, int64](HashString)
	const (
		goroutines = 100
		opsPerG    = 10000
	)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	for range goroutines {
		go func() {
			defer wg.Done()
			for range opsPerG {
				m.Upsert("counter", func(exist bool, old int64) int64 {
					if exist {
						return old + 1
					}
					return 1
				})
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	expected := int64(goroutines * opsPerG)
	val, _ := m.Get("counter")

	totalOps := goroutines * opsPerG
	opsPerSec := float64(totalOps) / elapsed.Seconds()

	t.Logf("=== Upsert 原子计数器压力测试 ===")
	t.Logf("  Goroutines:    %d", goroutines)
	t.Logf("  总 Upsert:     %d", totalOps)
	t.Logf("  耗时:          %v", elapsed)
	t.Logf("  吞吐量:        %.0f ops/sec", opsPerSec)
	t.Logf("  最终计数:      %d (期望 %d)", val, expected)

	if val != expected {
		t.Errorf("counter = %d, want %d (data race!)", val, expected)
	}
}

// TestStress_SetIfAbsentRace SetIfAbsent 幂等性压力测试
// 多个 goroutine 竞争写入同一个 key，最终只有一个成功
func TestStress_SetIfAbsentRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	m := NewMap[string, int](HashString)
	const goroutines = 200

	var winCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			if _, inserted := m.SetIfAbsent("winner", id); inserted {
				winCount.Add(1)
			}
		}(g)
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("=== SetIfAbsent 幂等性压力测试 ===")
	t.Logf("  竞争 Goroutines: %d", goroutines)
	t.Logf("  耗时:            %v", elapsed)
	t.Logf("  成功写入者:      %d (期望 1)", winCount.Load())

	if winCount.Load() != 1 {
		t.Errorf("SetIfAbsent succeeded %d times, want exactly 1", winCount.Load())
	}
}
