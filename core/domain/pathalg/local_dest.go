package pathalg

import (
	"cmp"
	"encoding"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

var (
	_ encoding.TextAppender    = LocalRootedDest{}
	_ encoding.TextMarshaler   = LocalRootedDest{}
	_ encoding.TextUnmarshaler = (*LocalRootedDest)(nil)
)

// LocalRootedDest 表示面向 ScopedRootFS（Go *os.Root）的严格沙箱相对目标路径。
//
// 核心安全不变量：
//   - 严格为非空相对路径，以 '/' 分隔且至少包含一个分量，100% 兼容 io/fs.ValidPath 与 *os.Root；
//   - 严禁前导/尾随 '/'、双斜杠 '//'、反斜杠 '\'、Windows 盘符/UNC 前缀、"." 或 ".." 段；
//   - 每一路径分量均经 ValidateLocalComponent 强制校验，阻断跨 OS 设备名、ADS、尾随点/空格与控制字符；
//   - 零值恒无效（IsValid() == false），且 Equal 对无效值恒返回 false。
//
//xops:opaque
//xops:failclosed
type LocalRootedDest struct {
	rel string
}

// ParseLocalRootedDest 校验并构造严格位于沙箱根目录内的相对目标路径。
func ParseLocalRootedDest(raw string) (LocalRootedDest, error) {
	if raw == "" {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "local_dest"))
	}
	if len(raw) > MaxRemotePathBytes {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "local_dest"), domi18n.Int("size", len(raw)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	if strings.HasPrefix(raw, "/") || strings.HasSuffix(raw, "/") {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", raw), domi18n.Str("reason", "leading_or_trailing_slash"))
	}
	if strings.ContainsRune(raw, '\\') {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyPathalgForbiddenChar, domi18n.BoundStr("value", raw), domi18n.Str("char", `\`))
	}
	for seg := range strings.SplitSeq(raw, "/") {
		if err := ValidateLocalComponent(seg); err != nil {
			return LocalRootedDest{}, domi18n.WrapSentinel(ErrInvalidLocalDest, err)
		}
	}
	return LocalRootedDest{rel: raw}, nil
}

// LocalRootedDestFromComponents 将一组单个本地分量校验并拼接为 LocalRootedDest。
func LocalRootedDestFromComponents(parts ...string) (LocalRootedDest, error) {
	if len(parts) == 0 {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "components"))
	}
	for _, seg := range parts {
		if err := ValidateLocalComponent(seg); err != nil {
			return LocalRootedDest{}, domi18n.WrapSentinel(ErrInvalidLocalDest, err)
		}
	}
	joined := strings.Join(parts, "/")
	if len(joined) > MaxRemotePathBytes {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "local_dest"), domi18n.Int("size", len(joined)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	return LocalRootedDest{rel: joined}, nil
}

// JoinComponent 在当前沙箱目标路径下追加单个经 ValidateLocalComponent 校验的分量。
func (d LocalRootedDest) JoinComponent(name string) (LocalRootedDest, error) {
	if !d.IsValid() {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_dest"))
	}
	if err := ValidateLocalComponent(name); err != nil {
		return LocalRootedDest{}, domi18n.WrapSentinel(ErrInvalidLocalDest, err)
	}
	joined := d.rel + "/" + name
	if len(joined) > MaxRemotePathBytes {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "local_dest"), domi18n.Int("size", len(joined)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	return LocalRootedDest{rel: joined}, nil
}

// JoinRemoteName 将已校验的远端名称通过跨平台 ValidateLocalComponent 桥接追加到当前沙箱目标路径。
func (d LocalRootedDest) JoinRemoteName(name RemoteName) (LocalRootedDest, error) {
	if !name.IsValid() {
		return LocalRootedDest{}, domi18n.EF(ErrInvalidLocalDest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_name"))
	}
	return d.JoinComponent(name.name)
}

// IsValid 报告 LocalRootedDest 是否有效。
func (d LocalRootedDest) IsValid() bool { return d.rel != "" }

// IsZero 报告 LocalRootedDest 是否为无效零值。
func (d LocalRootedDest) IsZero() bool { return d.rel == "" }

// String 返回规范化沙箱相对路径（以 '/' 分隔）；无效零值返回空串。
func (d LocalRootedDest) String() string { return d.rel }

// Segments 返回路径分量切片的新副本；无效零值返回 nil。
func (d LocalRootedDest) Segments() []string {
	if !d.IsValid() {
		return nil
	}
	return strings.Split(d.rel, "/")
}

// Depth 返回路径分量个数（有效值 >= 1，无效零值返回 0）；所在父目录相对根的深度为 Depth() - 1。
func (d LocalRootedDest) Depth() int {
	if !d.IsValid() {
		return 0
	}
	return strings.Count(d.rel, "/") + 1
}

// Base 返回末段文件名分量；无效零值返回空串。
func (d LocalRootedDest) Base() string {
	if !d.IsValid() {
		return ""
	}
	if idx := strings.LastIndexByte(d.rel, '/'); idx >= 0 {
		return d.rel[idx+1:]
	}
	return d.rel
}

// Parent 返回父级 LocalRootedDest；若当前已处于根直属第一层或无效，则返回 (零值, false)。
func (d LocalRootedDest) Parent() (LocalRootedDest, bool) {
	if !d.IsValid() {
		return LocalRootedDest{}, false
	}
	idx := strings.LastIndexByte(d.rel, '/')
	if idx <= 0 {
		return LocalRootedDest{}, false
	}
	return LocalRootedDest{rel: d.rel[:idx]}, true
}

// Equal 判断两个 LocalRootedDest 是否均有效且完全相等；无效零值永不相等。
func (d LocalRootedDest) Equal(other LocalRootedDest) bool {
	return d.IsValid() && other.IsValid() && d.rel == other.rel
}

// Compare 定义 LocalRootedDest 上的确定性全序关系。
func (d LocalRootedDest) Compare(other LocalRootedDest) int {
	return cmp.Compare(d.rel, other.rel)
}

// AppendText 实现 encoding.TextAppender（值接收者）；无效零值返回 ErrInvalidLocalDest。
func (d LocalRootedDest) AppendText(b []byte) ([]byte, error) {
	if !d.IsValid() {
		return nil, ErrInvalidLocalDest
	}
	return append(b, d.rel...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (d LocalRootedDest) MarshalText() ([]byte, error) { return d.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值。
func (d *LocalRootedDest) UnmarshalText(text []byte) error {
	if d == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseLocalRootedDest(string(text))
	if err != nil {
		*d = LocalRootedDest{}
		return err
	}
	*d = parsed
	return nil
}
