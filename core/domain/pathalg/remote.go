package pathalg

import (
	"cmp"
	"encoding"
	"path"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

var (
	_ encoding.TextAppender    = RemoteName{}
	_ encoding.TextMarshaler   = RemoteName{}
	_ encoding.TextUnmarshaler = (*RemoteName)(nil)
	_ encoding.TextAppender    = RemotePath{}
	_ encoding.TextMarshaler   = RemotePath{}
	_ encoding.TextUnmarshaler = (*RemotePath)(nil)
)

// RemoteName 表示经过严格校验的单个 POSIX 远端目录项名称（不含 '/'、非 "."/".."、无 NUL/控制/Bidi-Cf 字符）。
//
// 本类型仅约束 POSIX 远端单段合法性（不限制远端文件名含 ':' 或 '\'）；
// 若需落盘至本地沙箱，必须经 LocalRootedDest.JoinRemoteName 触发跨平台 ValidateLocalComponent 校验。
// 零值恒无效（IsValid() == false），且 Equal 对无效值恒返回 false。
//
//xops:opaque
//xops:failclosed
type RemoteName struct {
	name string
}

// ParseRemoteName 校验并构造单个远端 POSIX 目录项名称。
func ParseRemoteName(raw string) (RemoteName, error) {
	if raw == "" {
		return RemoteName{}, domi18n.EF(ErrInvalidRemoteName, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "remote_name"))
	}
	if len(raw) > MaxComponentBytes {
		return RemoteName{}, domi18n.EF(ErrInvalidRemoteName, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_name"), domi18n.Int("size", len(raw)), domi18n.Int("limit", MaxComponentBytes))
	}
	if raw == "." || raw == ".." {
		return RemoteName{}, domi18n.EF(ErrInvalidRemoteName, domi18n.KeyPathalgTraversalForbidden, domi18n.BoundStr("segment", raw))
	}
	if strings.ContainsRune(raw, '/') {
		return RemoteName{}, domi18n.EF(ErrInvalidRemoteName, domi18n.KeyPathalgForbiddenChar, domi18n.BoundStr("value", raw), domi18n.Str("char", "/"))
	}
	if hasForbiddenPathText(raw) {
		return RemoteName{}, domi18n.EF(ErrInvalidRemoteName, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "remote_name"))
	}
	return RemoteName{name: raw}, nil
}

// IsValid 报告 RemoteName 是否为有效远端名称。
func (n RemoteName) IsValid() bool { return n.name != "" }

// IsZero 报告 RemoteName 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (n RemoteName) IsZero() bool { return n.name == "" }

// String 返回远端目录项名称；无效零值返回空串。
func (n RemoteName) String() string { return n.name }

// Equal 判断两个 RemoteName 是否均有效且逐字节相等；无效零值永不相等。
func (n RemoteName) Equal(other RemoteName) bool {
	return n.IsValid() && other.IsValid() && n.name == other.name
}

// Compare 定义 RemoteName 上的确定性全序关系（无效零值排在所有有效值之前）。
func (n RemoteName) Compare(other RemoteName) int {
	return cmp.Compare(n.name, other.name)
}

// AppendText 实现 encoding.TextAppender（值接收者）；无效零值失败关闭返回 ErrInvalidRemoteName。
func (n RemoteName) AppendText(b []byte) ([]byte, error) {
	if !n.IsValid() {
		return nil, ErrInvalidRemoteName
	}
	return append(b, n.name...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (n RemoteName) MarshalText() ([]byte, error) { return n.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值并失败关闭。
func (n *RemoteName) UnmarshalText(text []byte) error {
	if n == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseRemoteName(string(text))
	if err != nil {
		*n = RemoteName{}
		return err
	}
	*n = parsed
	return nil
}

// RemotePath 表示经过规范化 POSIX 清洗的不可变远端路径值对象。
//
// 关键不变量与架构边界（ADR-007 / xopsvet/osboundary）：
//   - 全程仅使用标准库 path 执行 POSIX 词法规范化，严禁在任何包内对 RemotePath 调用 path/filepath.*；
//   - 保留合法 UTF-8 原始字节序列（不做隐式 NFC/NFD 重写，避免在字节敏感的 Linux SFTP 服务器上发生 ENOENT）；
//   - 严格拒绝空串、超长路径（> 4096 字节）、单段超长（> 255 字节）、非法 UTF-8、NUL、控制字符与 Bidi/Cf 格式字符；
//   - 零值恒无效（IsValid() == false），且 Equal / HasPrefix 对无效值恒返回 false。
//
//xops:opaque
//xops:failclosed
type RemotePath struct {
	clean string
}

// ParseRemotePath 校验并按 POSIX 语义规范化远端路径字符串。
func ParseRemotePath(raw string) (RemotePath, error) {
	if raw == "" {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "remote_path"))
	}
	if len(raw) > MaxRemotePathBytes {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_path"), domi18n.Int("size", len(raw)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	if hasForbiddenPathText(raw) {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "remote_path"))
	}
	cleaned := path.Clean(raw)
	if err := validateRemotePathSegments(cleaned); err != nil {
		return RemotePath{}, err
	}
	return RemotePath{clean: cleaned}, nil
}

// ParseAbsRemotePath 校验并规范化绝对 POSIX 远端路径（必须以 '/' 开头）。
func ParseAbsRemotePath(raw string) (RemotePath, error) {
	p, err := ParseRemotePath(raw)
	if err != nil {
		return RemotePath{}, err
	}
	if !p.IsAbs() {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", raw), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyPathalgReasonMustBeAbs)))
	}
	return p, nil
}

func validateRemotePathSegments(cleaned string) error {
	if len(cleaned) > MaxRemotePathBytes {
		return domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_path"), domi18n.Int("size", len(cleaned)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	for seg := range strings.SplitSeq(cleaned, "/") {
		if len(seg) > MaxComponentBytes {
			return domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "component"), domi18n.Int("size", len(seg)), domi18n.Int("limit", MaxComponentBytes))
		}
	}
	return nil
}

// IsValid 报告 RemotePath 是否有效。
func (p RemotePath) IsValid() bool { return p.clean != "" }

// IsZero 报告 RemotePath 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (p RemotePath) IsZero() bool { return p.clean == "" }

// IsAbs 报告 RemotePath 是否为以 '/' 开头的绝对 POSIX 路径。
func (p RemotePath) IsAbs() bool { return p.IsValid() && strings.HasPrefix(p.clean, "/") }

// IsRoot 报告 RemotePath 是否为 POSIX 根目录 "/"。
func (p RemotePath) IsRoot() bool { return p.clean == "/" }

// String 返回规范化 POSIX 路径文本；无效零值返回空串。
func (p RemotePath) String() string { return p.clean }

// Canonical 返回规范化后的 RemotePath（对有效值满足幂等律 p.Canonical() == p；无效值返回零值）。
func (p RemotePath) Canonical() RemotePath {
	if !p.IsValid() {
		return RemotePath{}
	}
	return p
}

// Dir 返回当前路径的父目录（POSIX path.Dir 语义）；无效零值返回无效零值。
func (p RemotePath) Dir() RemotePath {
	if !p.IsValid() {
		return RemotePath{}
	}
	return RemotePath{clean: path.Dir(p.clean)}
}

// Base 返回路径末段作为已校验的 RemoteName；当路径无效、为 "/"、"." 或末段为 ".." 时返回 (零值, false)。
func (p RemotePath) Base() (RemoteName, bool) {
	if !p.IsValid() || p.clean == "/" || p.clean == "." || p.clean == ".." {
		return RemoteName{}, false
	}
	base := path.Base(p.clean)
	if base == "" || base == "/" || base == "." || base == ".." {
		return RemoteName{}, false
	}
	return RemoteName{name: base}, true
}

// Join 在当前有效路径下依次拼接一个或多个已校验的 RemoteName，返回规范化后的新 RemotePath。
func (p RemotePath) Join(names ...RemoteName) (RemotePath, error) {
	if !p.IsValid() {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_path"))
	}
	cur := p.clean
	for _, n := range names {
		if !n.IsValid() {
			return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_name"))
		}
		cur = path.Join(cur, n.name)
	}
	if len(cur) > MaxRemotePathBytes {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_path"), domi18n.Int("size", len(cur)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	return RemotePath{clean: cur}, nil
}

// Resolve 以当前路径为基准解析目标路径：若 target 为绝对路径则直接返回 target，否则按 POSIX 词法拼接并清洗。
func (p RemotePath) Resolve(target RemotePath) (RemotePath, error) {
	if !p.IsValid() || !target.IsValid() {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_path"))
	}
	if target.IsAbs() {
		return target, nil
	}
	joined := path.Join(p.clean, target.clean)
	if err := validateRemotePathSegments(joined); err != nil {
		return RemotePath{}, err
	}
	return RemotePath{clean: joined}, nil
}

// Rel 计算从当前基准路径 p 到 target 的 POSIX 词法相对路径，满足 p.Resolve(rel) == target。
//
// 仅当 p 与 target 同为绝对路径或同为相对路径时可计算；若其中任一无效、绝对性不一致，或相对基准路径
// 在消除公共前缀后仍以 ".." 开头导致无法脱离当前工作目录确定上行段时，严格失败关闭返回错误。
func (p RemotePath) Rel(target RemotePath) (RemotePath, error) {
	if !p.IsValid() || !target.IsValid() {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_path"))
	}
	if p.IsAbs() != target.IsAbs() {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", target.clean), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyPathalgReasonAbsRelMismatch)))
	}
	if p.clean == target.clean {
		return RemotePath{clean: "."}, nil
	}
	baseSegs := remotePathSegments(p.clean)
	targSegs := remotePathSegments(target.clean)
	common := commonSegmentPrefix(baseSegs, targSegs)
	remBase := baseSegs[common:]
	remTarg := targSegs[common:]
	if len(remBase) > 0 && remBase[0] == ".." {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonPathForbidden, domi18n.BoundStr("path", p.clean), domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyPathalgReasonUnresolvBase)))
	}
	out := make([]string, 0, len(remBase)+len(remTarg))
	for range remBase {
		out = append(out, "..")
	}
	out = append(out, remTarg...)
	rel := "."
	if len(out) > 0 {
		rel = strings.Join(out, "/")
	}
	if len(rel) > MaxRemotePathBytes {
		return RemotePath{}, domi18n.EF(ErrInvalidRemotePath, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "remote_path"), domi18n.Int("size", len(rel)), domi18n.Int("limit", MaxRemotePathBytes))
	}
	return RemotePath{clean: rel}, nil
}

func remotePathSegments(cleaned string) []string {
	if cleaned == "/" || cleaned == "." {
		return nil
	}
	trimmed := strings.TrimPrefix(cleaned, "/")
	return strings.Split(trimmed, "/")
}

func commonSegmentPrefix(a, b []string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// HasPrefix 按 POSIX 段边界判断当前路径是否等于 prefix 或位于 prefix 子树下；无效路径恒返回 false。
func (p RemotePath) HasPrefix(prefix RemotePath) bool {
	if !p.IsValid() || !prefix.IsValid() || p.IsAbs() != prefix.IsAbs() {
		return false
	}
	if p.clean == prefix.clean {
		return true
	}
	if prefix.clean == "/" {
		return strings.HasPrefix(p.clean, "/")
	}
	if prefix.clean == "." {
		return !p.IsAbs() && p.clean != ".." && !strings.HasPrefix(p.clean, "../")
	}
	rem, ok := strings.CutPrefix(p.clean, prefix.clean+"/")
	return ok && rem != ".." && !strings.HasPrefix(rem, "../")
}

// Equal 判断两个 RemotePath 是否均有效且规范表示完全相等；无效零值永不相等。
func (p RemotePath) Equal(other RemotePath) bool {
	return p.IsValid() && other.IsValid() && p.clean == other.clean
}

// Compare 定义 RemotePath 上的确定性全序关系（无效零值排在所有有效值之前）。
func (p RemotePath) Compare(other RemotePath) int {
	return cmp.Compare(p.clean, other.clean)
}

// AppendText 实现 encoding.TextAppender（值接收者）；无效零值失败关闭返回 ErrInvalidRemotePath。
func (p RemotePath) AppendText(b []byte) ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidRemotePath
	}
	return append(b, p.clean...), nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (p RemotePath) MarshalText() ([]byte, error) { return p.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为零值并失败关闭。
func (p *RemotePath) UnmarshalText(text []byte) error {
	if p == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseRemotePath(string(text))
	if err != nil {
		*p = RemotePath{}
		return err
	}
	*p = parsed
	return nil
}
