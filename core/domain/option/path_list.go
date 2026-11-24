package option

import (
	"fmt"
	"slices"
	"strings"
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
		return PathEntry{}, fmt.Errorf("%w: 路径 %q 非法或为保留字 none", ErrInvalidPathList, raw)
	}
	if err := validateTemplateTokens(t, allowedPathPercentTokens, true); err != nil {
		return PathEntry{}, fmt.Errorf("%w: 路径占位符非法: %w", ErrInvalidPathList, err)
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
			return nil, fmt.Errorf("%w: 包含无效 PathEntry", ErrInvalidPathList)
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
		if err := appendPathToken(raw, &items, &terminated, allowMixedNone, len(rawItems)); err != nil {
			return PathListUnset, nil, false, err
		}
	}
	if len(items) == 0 && terminated {
		return PathListDisabled, nil, true, nil
	}
	if len(items) == 0 {
		return PathListUnset, nil, false, nil
	}
	return PathListSet, items, terminated, nil
}

func appendPathToken(raw string, items *[]PathEntry, terminated *bool, allowMixedNone bool, total int) error {
	t := strings.TrimSpace(raw)
	if hasForbiddenControlChar(raw) || t == "" {
		return fmt.Errorf("%w: 路径项 %q 非法或为空", ErrInvalidPathList, raw)
	}
	if isNoneKeyword(t) {
		if !allowMixedNone && total > 1 {
			return fmt.Errorf("%w: none 必须单独出现", ErrInvalidPathList)
		}
		*terminated = true
		return nil
	}
	entry, err := ParsePathEntry(t)
	if err != nil {
		return err
	}
	if !*terminated && !slices.Contains(*items, entry) {
		*items = append(*items, entry)
	}
	return nil
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

// PathList 表示专用于 OpenSSH IdentityFile / CertificateFile 的三态累积路径幺半群 (PathList, Compose, Unset)。
// Unset 为单位元，Disabled("none") 作为左零元吸收一切低优先级层，terminated 右封口位严格保证结合律。
//
//xops:opaque
//xops:failclosed
type PathList struct {
	state      PathListState
	items      []PathEntry
	terminated bool
}

// UnsetPathList、DisabledPathList、NewPathList 与 ParsePathListEntries 构造 PathList。
func UnsetPathList() PathList    { return PathList{} }
func DisabledPathList() PathList { return PathList{state: PathListDisabled, terminated: true} }
func NewPathList(entries ...PathEntry) (PathList, error) {
	st, items, err := buildPathState(entries)
	return PathList{state: st, items: items}, err
}
func ParsePathListEntries(rawItems []string) (PathList, error) {
	st, items, term, err := parsePathTokens(rawItems, true)
	return PathList{st, items, term}, err
}

// PathList 只读访问器、幺半群复合、折叠与等价判定（切片均返回防御性副本）。
func (p PathList) State() PathListState  { return p.state }
func (p PathList) IsUnset() bool         { return p.state == PathListUnset }
func (p PathList) IsDisabled() bool      { return p.state == PathListDisabled }
func (p PathList) IsSet() bool           { return p.state == PathListSet }
func (p PathList) IsZero() bool          { return p.state == PathListUnset }
func (p PathList) Terminated() bool      { return p.state == PathListDisabled || p.terminated }
func (p PathList) DefaultsAllowed() bool { return p.state == PathListUnset }
func (p PathList) Items() []PathEntry    { return slices.Clone(p.items) }
func (p PathList) RawItems() []string    { return rawPathItems(p.items) }
func (p PathList) clone() PathList       { return PathList{p.state, slices.Clone(p.items), p.terminated} }
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
		return PathList{PathListSet, slices.Clone(p.items), true}
	}
	merged := slices.Clone(p.items)
	for _, item := range lower.items {
		if !slices.Contains(merged, item) {
			merged = append(merged, item)
		}
	}
	return PathList{PathListSet, merged, lower.terminated}
}

// KnownHostsList 表示专用于 OpenSSH UserKnownHostsFile 的独立不透明 FirstWins 幺半群。
// 单条指令支持空白分隔多路径或独立 "none"（禁止混用）；跨指令与跨层严格 FirstWins，杜绝 HostKey 信任锚点跨层污染。
//
//xops:opaque
//xops:failclosed
type KnownHostsList struct {
	state PathListState
	items []PathEntry
}

// UnsetKnownHostsList、DisabledKnownHostsList、NewKnownHostsList 与 ParseKnownHostsList 构造 KnownHostsList。
func UnsetKnownHostsList() KnownHostsList    { return KnownHostsList{} }
func DisabledKnownHostsList() KnownHostsList { return KnownHostsList{state: PathListDisabled} }
func NewKnownHostsList(entries ...PathEntry) (KnownHostsList, error) {
	st, items, err := buildPathState(entries)
	return KnownHostsList{state: st, items: items}, err
}
func ParseKnownHostsList(rawItems []string) (KnownHostsList, error) {
	st, items, _, err := parsePathTokens(rawItems, false)
	return KnownHostsList{st, items}, err
}

// KnownHostsList 只读访问器、FirstWins 复合、折叠与等价判定（切片均返回防御性副本）。
func (k KnownHostsList) State() PathListState  { return k.state }
func (k KnownHostsList) IsUnset() bool         { return k.state == PathListUnset }
func (k KnownHostsList) IsDisabled() bool      { return k.state == PathListDisabled }
func (k KnownHostsList) IsSet() bool           { return k.state == PathListSet }
func (k KnownHostsList) IsZero() bool          { return k.state == PathListUnset }
func (k KnownHostsList) DefaultsAllowed() bool { return k.state == PathListUnset }
func (k KnownHostsList) Items() []PathEntry    { return slices.Clone(k.items) }
func (k KnownHostsList) RawItems() []string    { return rawPathItems(k.items) }
func (k KnownHostsList) clone() KnownHostsList { return KnownHostsList{k.state, slices.Clone(k.items)} }
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
