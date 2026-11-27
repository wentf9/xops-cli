package secret

import (
	"cmp"
	"encoding"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const maxRefSegmentLen = 128

var (
	_ encoding.TextAppender    = Ref{}
	_ encoding.TextMarshaler   = Ref{}
	_ encoding.TextUnmarshaler = (*Ref)(nil)
)

// Ref 是指向凭据存储（Vault / OS Keychain / External Helper）中某条机密的不可变非敏感引用标识。
//
// Ref 仅携带 (store, item) 逻辑定位信息而不含任何明文机密，可安全进入配置、计划、事件与审计日志；
// 规范文本格式为 "<store>/<item>"（两段均严格禁止 '/'、路径穿越与跨平台非法文件名字符，保证双射无歧义）；
// 零值代表无效未设置状态（IsValid() == false），序列化与 Equal 均严格失败关闭。
//
//xops:opaque
//xops:failclosed
type Ref struct {
	store string
	item  string
}

// NewRef 校验并构造不可变凭据引用 Ref。
// store 与 item 均须为长度 1..128 的安全 ASCII 标识符（首字符 [A-Za-z0-9_]，其余 [A-Za-z0-9._-]，
// 不以 '.' 结尾，且拒绝 Windows DOS 保留设备主干名 CON/PRN/AUX/NUL/COM1–COM9/LPT1–LPT9），
// 确保跨 Linux/macOS/Windows 文件系统与 dirfd 映射无路径穿越或保留设备名碰撞风险。
func NewRef(store, item string) (Ref, error) {
	if !isValidRefSegment(store) {
		return Ref{}, domi18n.EF(ErrInvalidRef, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "store"), domi18n.BoundStr("value", store))
	}
	if !isValidRefSegment(item) {
		return Ref{}, domi18n.EF(ErrInvalidRef, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "item"), domi18n.BoundStr("value", item))
	}
	return Ref{
		store: store,
		item:  item,
	}, nil
}

// ParseRef 解析规范文本格式 "<store>/<item>" 为 Ref；缺失分隔符、含多段斜杠或标识非法均失败关闭。
func ParseRef(raw string) (Ref, error) {
	store, item, ok := strings.Cut(raw, "/")
	if !ok {
		return Ref{}, domi18n.EF(ErrInvalidRef, domi18n.KeySecretRefFormat, domi18n.BoundStr("value", raw))
	}
	return NewRef(store, item)
}

// IsValid 报告 Ref 是否包含合法的非空 store 与 item 标识。
func (r Ref) IsValid() bool {
	return r.store != "" && r.item != ""
}

// IsZero 报告 Ref 是否为无效零值（配合 encoding/json/v2 omitzero）。
func (r Ref) IsZero() bool {
	return !r.IsValid()
}

// Store 返回所属凭据存储标识；零值返回空串。
func (r Ref) Store() string {
	return r.store
}

// Item 返回存储内条目唯一标识；零值返回空串。
func (r Ref) Item() string {
	return r.item
}

// String 返回规范文本 "<store>/<item>"；无效零值返回空串。
func (r Ref) String() string {
	if !r.IsValid() {
		return ""
	}
	return r.store + "/" + r.item
}

// Equal 比较两个 Ref 是否均有效且指向同一 (store, item)；遵循失败关闭原则，无效零值永不相等。
func (r Ref) Equal(other Ref) bool {
	if !r.IsValid() || !other.IsValid() {
		return false
	}
	return r.store == other.store && r.item == other.item
}

// Compare 定义 Ref 上的确定性全序关系（无效零值排在有效值之前，有效值按 store 再按 item 字典序排列）。
func (r Ref) Compare(other Ref) int {
	if !r.IsValid() && !other.IsValid() {
		return 0
	}
	if !r.IsValid() {
		return -1
	}
	if !other.IsValid() {
		return 1
	}
	if c := cmp.Compare(r.store, other.store); c != 0 {
		return c
	}
	return cmp.Compare(r.item, other.item)
}

// AppendText 实现 encoding.TextAppender（值接收者）；对无效零值严格失败关闭。
func (r Ref) AppendText(b []byte) ([]byte, error) {
	if !r.IsValid() {
		return nil, ErrInvalidRef
	}
	b = append(b, r.store...)
	b = append(b, '/')
	b = append(b, r.item...)
	return b, nil
}

// MarshalText 实现 encoding.TextMarshaler（值接收者），语义与 AppendText(nil) 完全一致。
func (r Ref) MarshalText() ([]byte, error) {
	return r.AppendText(nil)
}

// UnmarshalText 实现 encoding.TextUnmarshaler，解析 "<store>/<item>"；失败时重置为零值并失败关闭。
func (r *Ref) UnmarshalText(text []byte) error {
	if r == nil {
		return ErrNilReceiver
	}
	parsed, err := ParseRef(string(text))
	if err != nil {
		*r = Ref{}
		return err
	}
	*r = parsed
	return nil
}

func isValidRefSegment(seg string) bool {
	if len(seg) == 0 || len(seg) > maxRefSegmentLen {
		return false
	}
	if !isRefStartByte(seg[0]) || seg[len(seg)-1] == '.' {
		return false
	}
	for i := 1; i < len(seg); i++ {
		if !isRefBodyByte(seg[i]) {
			return false
		}
	}
	stem, _, _ := strings.Cut(seg, ".")
	return !isWindowsReservedDeviceStem(stem)
}

func isWindowsReservedDeviceStem(stem string) bool {
	switch len(stem) {
	case 3:
		return strings.EqualFold(stem, "CON") ||
			strings.EqualFold(stem, "PRN") ||
			strings.EqualFold(stem, "AUX") ||
			strings.EqualFold(stem, "NUL")
	case 4:
		last := stem[3]
		if last < '1' || last > '9' {
			return false
		}
		prefix := stem[:3]
		return strings.EqualFold(prefix, "COM") || strings.EqualFold(prefix, "LPT")
	default:
		return false
	}
}

func isRefStartByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func isRefBodyByte(b byte) bool {
	return isRefStartByte(b) || b == '-' || b == '.'
}
