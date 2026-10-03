// Package concurrent preserves the original import path for the shared map.
package concurrent

import core "github.com/wentf9/xops-cli/core/concurrent"

const DEFAULT_SHARD_COUNT = core.DEFAULT_SHARD_COUNT

type Map[K comparable, V any] = core.Map[K, V]
type Option[K comparable, V any] = core.Option[K, V]
type ConcurrentMapShard[K comparable, V any] = core.ConcurrentMapShard[K, V]

func NewMap[K comparable, V any](hash func(K) uint32, opts ...Option[K, V]) *Map[K, V] {
	return core.NewMap(hash, opts...)
}

func WithShardCount[K comparable, V any](count uint32) Option[K, V] {
	return core.WithShardCount[K, V](count)
}

func RemoveIfMatch[K comparable, V comparable](m *Map[K, V], key K, expected V) bool {
	return core.RemoveIfMatch(m, key, expected)
}

func HashString(value string) uint32 { return core.HashString(value) }
func HashInt(value int) uint32       { return core.HashInt(value) }
func HashInt64(value int64) uint32   { return core.HashInt64(value) }
func HashUint64(value uint64) uint32 { return core.HashUint64(value) }
