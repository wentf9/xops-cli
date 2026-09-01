package concurrent

const (
	offset32 = 2166136261
	prime32  = 16777619
)

// HashString 针对 string 类型的标准 FNV-1a 哈希算法
// FNV 算法分布极其均匀，是处理字符串的标准选择
func HashString(s string) uint32 {
	var hash uint32 = offset32
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	return hash
}

// ==========================================
// 整数哈希 (Integer Hashing)
// ==========================================
// 对于整数，我们不使用 FNV（因为它需要转成字节，太慢）。
// 我们使用位运算（Bit Manipulation）或乘法哈希，速度是 FNV 的几十倍。

// HashInt 针对 int 类型的快速哈希
// 使用了 Knuth's Multiplicative Hash 的变种，确保简单的序列数也能均匀打散
func HashInt(key int) uint32 {
	// 将 int 强转为 uint32 (在 64 位系统上会丢失高位，通常没关系，因为分片只看低位)
	// 乘以一个大素数来打散位
	return uint32(key) * 2654435761
}

// HashInt64 针对 int64 类型的哈希
// 混合高 32 位和低 32 位，确保高位变化也能影响分片结果
func HashInt64(key int64) uint32 {
	value := uint64(key)
	// 将高 32 位移下来与低 32 位进行异或运算
	return uint32(value^(value>>32)) * 2654435761
}

// HashUint64 针对 uint64 类型的哈希
func HashUint64(key uint64) uint32 {
	// 同上，异或高低位
	return uint32(key^(key>>32)) * 2654435761
}
