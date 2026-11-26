// Package yamlcodec 实现 XOps v2 YAML vNext（version: 2）强判别式配置文档的纯内存编解码与不变量校验
// （ADR-006 / RFC §3.6 & §4.2）。
//
// 核心不变量：
//   - 仅接受 schema version: 2（100% 零 v1 迁移、读取或兼容垫片代码），严格开启 KnownFields(true)，
//     拒绝尾随多文档、重复键、未知字段、算法算子/路径状态伪装与零值非法字段；
//   - 所有持久化时长字段强制使用 core/domain/algebraic.Duration（零裸 time.Duration）；
//   - 100% 纯内存编解码，零文件/网络 I/O、零裸 go、零 init()、零可变包级 var、零 nolint 抑制指令。
package yamlcodec

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

// SchemaVersionV2 是 XOps v2 YAML vNext 唯一接受的配置版本号（100% 零 v1 兼容）。
const SchemaVersionV2 = 2

// ErrUnsupportedSchemaVersion 表示配置文件缺失 version 字段或版本不是唯一合法的 version: 2。
var ErrUnsupportedSchemaVersion = errors.New("yamlcodec: 不受支持的配置 schema 版本（仅支持 version: 2）")

func zeroVal[T any]() (z T) { return z }

func ptrOf[T any](v T) *T { return &v }

func optPtr[T any](o algebraic.Option[T]) *T {
	if v, ok := o.Get(); ok {
		return &v
	}
	return nil
}

func optStr[T fmt.Stringer](o algebraic.Option[T]) string {
	if v, ok := o.Get(); ok {
		return v.String()
	}
	return ""
}

func parseOptional[T any](raw string, parse func(string) (T, error)) (algebraic.Option[T], error) {
	if raw == "" {
		return algebraic.None[T](), nil
	}
	v, err := parse(raw)
	if err != nil {
		return algebraic.None[T](), err
	}
	return algebraic.Some(v), nil
}

func encodeMapValues[T, V any](items []T, keyFn func(T) string, encFn func(T) (V, error)) (map[string]V, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make(map[string]V, len(items))
	for _, it := range items {
		v, err := encFn(it)
		if err != nil {
			return nil, err
		}
		out[keyFn(it)] = v
	}
	return out, nil
}

func decodeSortedMap[V, T any](section string, m map[string]V, decFn func(string, V) (T, error)) ([]T, error) {
	keys := slices.Sorted(maps.Keys(m))
	out := make([]T, 0, len(keys))
	for _, k := range keys {
		item, err := decFn(k, m[k])
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", section, k, err)
		}
		out = append(out, item)
	}
	return out, nil
}

func mapSliceErr[S, D any](in []S, fn func(S) (D, error)) ([]D, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]D, len(in))
	for i, s := range in {
		v, err := fn(s)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

func toStrings[T fmt.Stringer](in []T) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = v.String()
	}
	return out
}

func isIn(raw string, allowed ...string) bool {
	return slices.Contains(allowed, strings.ToLower(strings.TrimSpace(raw)))
}

func isEmptyOrIn(raw string, allowed ...string) bool {
	return strings.TrimSpace(raw) == "" || isIn(raw, allowed...)
}

func fieldMask(flags ...bool) uint8 {
	var m uint8
	for i, f := range flags {
		if f {
			m |= 1 << i
		}
	}
	return m
}
