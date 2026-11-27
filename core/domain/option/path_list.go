package option

import (
	"slices"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

const allowedPathPercentTokens = "%CdhijLlnpru"

// PathEntryKind 与 PathListState 分别为路径项形态与路径集合状态枚举；零值代表无效或未设置单位元。
//
//xops:failclosed
type PathEntryKind uint8

//xops:failclosed
type PathListState uint8

const (
	PathEntryInvalid  PathEntryKind = iota // 无效路径项（零值失败关闭）
	PathEntryLiteral                       // 字面路径
	PathEntryTemplate                      // 含 OpenSSH % 或 ${VAR} 的模板路径
)
const (
	PathListUnset    PathListState = iota // 未设置（单位元，允许默认路径回退）
	PathListDisabled                      // 显式 "none" 禁用（吸收低优先级右操作数）
	PathListSet                           // 含至少一个有序去重路径项
)

// String 返回 PathEntryKind 与 PathListState 的可读名称。
func (k PathEntryKind) String() string { return enumNameOr(uint8(k), "invalid", "literal", "template") }
func (s PathListState) String() string {
	return enumNameOr(uint8(s)+1, "invalid", "unset", "disabled", "set")
}

// PathEntry 表示经校验的单个 OpenSSH 路径配置项；零值恒无效。
//
//xops:opaque
//xops:failclosed
type PathEntry struct {
	raw  string
	kind PathEntryKind
}

// ParsePathEntry 严格校验并构造 PathEntry；拒绝空串、控制字符、非法占位符与保留字 "none"。
func ParsePathEntry(raw string) (PathEntry, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" || len(t) > maxTokenLen || isNoneKeyword(t) {
		return PathEntry{}, domi18n.EF(ErrInvalidPathList, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "path"), domi18n.BoundStr("value", raw))
	}
	if err := validateTemplateTokens(t, allowedPathPercentTokens, true); err != nil {
		return PathEntry{}, domi18n.WrapS(ErrInvalidPathList, err, domi18n.KeyOptionTemplateInvalid, domi18n.Str("option", "PathEntry"))
	}
	kind := PathEntryLiteral
	if strings.ContainsRune(t, '%') || strings.Contains(t, "${") {
		kind = PathEntryTemplate
	}
	return PathEntry{t, kind}, nil
}

// PathEntry 只读访问器与文本编解码方法。
func (e PathEntry) IsValid() bool       { return e.kind == PathEntryLiteral || e.kind == PathEntryTemplate }
func (e PathEntry) IsZero() bool        { return !e.IsValid() }
func (e PathEntry) Kind() PathEntryKind { return e.kind }
func (e PathEntry) IsTemplate() bool    { return e.kind == PathEntryTemplate }
func (e PathEntry) String() string      { return e.raw }
func (e PathEntry) Equal(o PathEntry) bool {
	return e.IsValid() && o.IsValid() && e.kind == o.kind && e.raw == o.raw
}
func (e PathEntry) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, e.raw, e.IsValid(), ErrInvalidPathList)
}
func (e PathEntry) MarshalText() ([]byte, error) { return e.AppendText(nil) }
func (e *PathEntry) UnmarshalText(text []byte) error {
	return unmarshalTextVia(e, text, ParsePathEntry)
}

func dedupPathEntries(entries []PathEntry) ([]PathEntry, error) {
	items := make([]PathEntry, 0, len(entries))
	for _, e := range entries {
		if !e.IsValid() {
			return nil, domi18n.EF(ErrInvalidPathList, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "path_entry"))
		}
		if !slices.Contains(items, e) {
			items = append(items, e)
		}
	}
	return items, nil
}
func rawPathItems(items []PathEntry) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.raw
	}
	return nilIfEmpty(out)
}
func parsePathTokens(rawItems []string, allowMixedNone bool) (PathListState, []PathEntry, bool, error) {
	var items []PathEntry
	terminated := false
	for _, raw := range rawItems {
		entry, isNone, err := parseOnePathToken(raw, allowMixedNone, len(rawItems))
		if err != nil {
			return PathListUnset, nil, false, err
		}
		if isNone {
			terminated = true
		} else if !terminated && !slices.Contains(items, entry) {
			items = append(items, entry)
		}
	}
	if len(items) > 0 {
		return PathListSet, items, terminated, nil
	}
	if terminated {
		return PathListDisabled, nil, true, nil
	}
	return PathListUnset, nil, false, nil
}
func parseOnePathToken(raw string, allowMixedNone bool, total int) (PathEntry, bool, error) {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" {
		return PathEntry{}, false, domi18n.EF(ErrInvalidPathList, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "path"), domi18n.BoundStr("value", raw))
	}
	if isNoneKeyword(t) {
		if !allowMixedNone && total > 1 {
			return PathEntry{}, false, domi18n.EF(ErrInvalidPathList, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "path"), domi18n.Str("value", "none"))
		}
		return PathEntry{}, true, nil
	}
	entry, err := ParsePathEntry(t)
	return entry, false, err
}
func buildPathState(entries []PathEntry) (PathListState, []PathEntry, error) {
	if len(entries) == 0 {
		return PathListUnset, nil, nil
	}
	items, err := dedupPathEntries(entries)
	if err != nil {
		return PathListUnset, nil, err
	}
	return PathListSet, items, nil
}

// pathSetBase 封装 PathList 与 KnownHostsList 共用的不可变状态与防御性只读访问器。
type pathSetBase struct {
	state PathListState
	items []PathEntry
}

func (b pathSetBase) State() PathListState  { return b.state }
func (b pathSetBase) IsUnset() bool         { return b.state == PathListUnset }
func (b pathSetBase) IsDisabled() bool      { return b.state == PathListDisabled }
func (b pathSetBase) IsSet() bool           { return b.state == PathListSet }
func (b pathSetBase) IsZero() bool          { return b.state == PathListUnset }
func (b pathSetBase) DefaultsAllowed() bool { return b.state == PathListUnset }
func (b pathSetBase) Items() []PathEntry    { return slices.Clone(b.items) }
func (b pathSetBase) RawItems() []string    { return rawPathItems(b.items) }

// PathList 表示专用于 OpenSSH IdentityFile / CertificateFile 的三态累积路径幺半群 (PathList, Compose, Unset)。
// Unset 为单位元，Disabled("none") 作为左零元吸收一切低优先级层，terminated 右封口位严格保证结合律。
//
//xops:opaque
//xops:failclosed
type PathList struct {
	pathSetBase
	terminated bool
}

// UnsetPathList、DisabledPathList、NewPathList 与 ParsePathListEntries 构造 PathList。
func UnsetPathList() PathList    { return PathList{} }
func DisabledPathList() PathList { return PathList{pathSetBase{state: PathListDisabled}, true} }
func NewPathList(entries ...PathEntry) (PathList, error) {
	st, items, err := buildPathState(entries)
	return PathList{pathSetBase{st, items}, false}, err
}
func ParsePathListEntries(rawItems []string) (PathList, error) {
	st, items, term, err := parsePathTokens(rawItems, true)
	return PathList{pathSetBase{st, items}, term}, err
}

// PathList 封口访问器、幺半群复合、折叠与等价判定。
func (p PathList) Terminated() bool { return p.state == PathListDisabled || p.terminated }
func (p PathList) clone() PathList {
	return PathList{pathSetBase{p.state, slices.Clone(p.items)}, p.terminated}
}
func (p PathList) Equal(o PathList) bool {
	return p.state == o.state && p.Terminated() == o.Terminated() && slices.Equal(p.items, o.items)
}
func FoldPathLists(layers ...PathList) PathList {
	return foldMonoid(UnsetPathList(), PathList.Compose, layers)
}
func (p PathList) Compose(lower PathList) PathList {
	if p.state == PathListUnset {
		return lower.clone()
	}
	if p.Terminated() || lower.state == PathListUnset {
		return p.clone()
	}
	if lower.state == PathListDisabled {
		return PathList{pathSetBase{PathListSet, slices.Clone(p.items)}, true}
	}
	merged := slices.Clone(p.items)
	for _, item := range lower.items {
		if !slices.Contains(merged, item) {
			merged = append(merged, item)
		}
	}
	return PathList{pathSetBase{PathListSet, merged}, lower.terminated}
}

// KnownHostsList 表示专用于 OpenSSH UserKnownHostsFile 的独立不透明 FirstWins 幺半群。
// 单条指令支持空白分隔多路径或独立 "none"（禁止混用）；跨指令与跨层严格 FirstWins，杜绝 HostKey 信任锚点跨层污染。
//
//xops:opaque
//xops:failclosed
type KnownHostsList struct{ pathSetBase }

// UnsetKnownHostsList、DisabledKnownHostsList、NewKnownHostsList 与 ParseKnownHostsList 构造 KnownHostsList。
func UnsetKnownHostsList() KnownHostsList { return KnownHostsList{} }
func DisabledKnownHostsList() KnownHostsList {
	return KnownHostsList{pathSetBase{state: PathListDisabled}}
}
func NewKnownHostsList(entries ...PathEntry) (KnownHostsList, error) {
	st, items, err := buildPathState(entries)
	return KnownHostsList{pathSetBase{st, items}}, err
}
func ParseKnownHostsList(rawItems []string) (KnownHostsList, error) {
	st, items, _, err := parsePathTokens(rawItems, false)
	return KnownHostsList{pathSetBase{st, items}}, err
}

// KnownHostsList 复合、折叠与等价判定。
func (k KnownHostsList) clone() KnownHostsList {
	return KnownHostsList{pathSetBase{k.state, slices.Clone(k.items)}}
}
func (k KnownHostsList) Equal(o KnownHostsList) bool {
	return k.state == o.state && slices.Equal(k.items, o.items)
}
func FoldKnownHostsLists(layers ...KnownHostsList) KnownHostsList {
	return foldMonoid(UnsetKnownHostsList(), KnownHostsList.Compose, layers)
}
func (k KnownHostsList) Compose(lower KnownHostsList) KnownHostsList {
	if k.state == PathListUnset {
		return lower.clone()
	}
	return k.clone()
}
