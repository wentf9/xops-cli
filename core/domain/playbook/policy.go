package playbook

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
)

const targetSelectorDomainTag = "xops.playbook.target_selector.v2"

// PlaybookID 与 StepID 为不可变强类型标识符；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type PlaybookID struct{ value string }

//xops:opaque
//xops:failclosed
type StepID struct{ value string }

// ParsePlaybookID 与 ParseStepID 校验并构造不可变 PlaybookID / StepID。
func ParsePlaybookID(raw string) (PlaybookID, error) {
	if err := validateIdentToken(raw, ErrInvalidPlaybookID); err != nil {
		return PlaybookID{}, err
	}
	return PlaybookID{raw}, nil
}
func ParseStepID(raw string) (StepID, error) {
	if err := validateIdentToken(raw, ErrInvalidStepID); err != nil {
		return StepID{}, err
	}
	return StepID{raw}, nil
}

func (id PlaybookID) IsValid() bool  { return id.value != "" }
func (id PlaybookID) IsZero() bool   { return id.value == "" }
func (id PlaybookID) String() string { return id.value }
func (id PlaybookID) Equal(o PlaybookID) bool {
	return id.IsValid() && o.IsValid() && id.value == o.value
}
func (id PlaybookID) Compare(o PlaybookID) int { return cmp.Compare(id.value, o.value) }
func (id PlaybookID) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, id.IsValid(), id.value, ErrInvalidPlaybookID)
}
func (id PlaybookID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *PlaybookID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, PlaybookID{}, text, ParsePlaybookID)
}

func (id StepID) IsValid() bool        { return id.value != "" }
func (id StepID) IsZero() bool         { return id.value == "" }
func (id StepID) String() string       { return id.value }
func (id StepID) Equal(o StepID) bool  { return id.IsValid() && o.IsValid() && id.value == o.value }
func (id StepID) Compare(o StepID) int { return cmp.Compare(id.value, o.value) }
func (id StepID) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, id.IsValid(), id.value, ErrInvalidStepID)
}
func (id StepID) MarshalText() ([]byte, error) { return id.AppendText(nil) }
func (id *StepID) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(id, StepID{}, text, ParseStepID)
}

// OnErrorPolicy 定义确定失败时的错误处置策略；零值 OnErrorInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type OnErrorPolicy uint8

const (
	OnErrorInvalid  OnErrorPolicy = iota // 未初始化零值（失败关闭）
	OnErrorFailFast                      // 当前节点首步失败立即停止该节点后续步骤
	OnErrorContinue                      // 记录失败并继续当前节点后续步骤
	OnErrorAbort                         // 任一节点失败中止整批 Playbook 剩余步骤
)

// ParseOnErrorPolicy 严格解析规范小写策略（"fail_fast"、"continue"、"abort"）。
func ParseOnErrorPolicy(raw string) (OnErrorPolicy, error) {
	return parseEnumByName(raw, OnErrorFailFast, OnErrorAbort, OnErrorInvalid, OnErrorPolicy.String, ErrInvalidOnErrorPolicy)
}
func (p OnErrorPolicy) IsValid() bool { return p >= OnErrorFailFast && p <= OnErrorAbort }
func (p OnErrorPolicy) IsZero() bool  { return p == OnErrorInvalid }
func (p OnErrorPolicy) String() string {
	return enumName(uint8(p), "invalid", "invalid", "fail_fast", "continue", "abort")
}
func (p OnErrorPolicy) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, p.IsValid(), p.String(), ErrInvalidOnErrorPolicy)
}
func (p OnErrorPolicy) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *OnErrorPolicy) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(p, OnErrorInvalid, text, ParseOnErrorPolicy)
}

// FileMode 表示经校验的不可变 POSIX 文件权限位（0000..07777）；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type FileMode struct {
	bits  uint32
	valid bool
}

// NewFileMode 与 ParseFileMode 校验并构造不可变 FileMode（ParseFileMode 仅接受 3/4 位八进制串）。
func NewFileMode(bits uint32) (FileMode, error) {
	if bits > maxFileMode {
		return FileMode{}, domi18n.EF(ErrInvalidFileMode, domi18n.KeyCommonPermInvalid, domi18n.Str("perm", fmt.Sprintf("0%o", bits)))
	}
	return FileMode{bits: bits, valid: true}, nil
}
func ParseFileMode(raw string) (FileMode, error) {
	if len(raw) < 3 || len(raw) > 4 || hasForbiddenStrictText(raw) {
		return FileMode{}, domi18n.EF(ErrInvalidFileMode, domi18n.KeyPlaybookOctalModeInvalid, domi18n.BoundStr("value", raw))
	}
	for i := range len(raw) {
		if raw[i] < '0' || raw[i] > '7' {
			return FileMode{}, domi18n.EF(ErrInvalidFileMode, domi18n.KeyPlaybookOctalModeInvalid, domi18n.BoundStr("value", raw))
		}
	}
	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return FileMode{}, domi18n.WrapSentinel(ErrInvalidFileMode, err)
	}
	return NewFileMode(uint32(parsed))
}

func (m FileMode) IsValid() bool         { return m.valid && m.bits <= maxFileMode }
func (m FileMode) IsZero() bool          { return !m.IsValid() }
func (m FileMode) Bits() uint32          { return pickIf(m.IsValid(), m.bits, 0) }
func (m FileMode) String() string        { return pickIf(m.IsValid(), fmt.Sprintf("%04o", m.bits), "") }
func (m FileMode) Equal(o FileMode) bool { return m.IsValid() && o.IsValid() && m.bits == o.bits }
func (m FileMode) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, m.IsValid(), m.String(), ErrInvalidFileMode)
}
func (m FileMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }
func (m *FileMode) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(m, FileMode{}, text, ParseFileMode)
}

// TargetSelectorSpec 与 TargetSelector 表示目标节点筛选表达式（零值失败关闭，经 digestcover 校验）。
type TargetSelectorSpec struct {
	All          bool
	Nodes        []inventory.NodeID
	Tags         []inventory.Tag
	ExcludeNodes []inventory.NodeID
	ExcludeTags  []inventory.Tag
}

//xops:opaque
//xops:failclosed
//xops:canonicalhash
type TargetSelector struct {
	all          bool
	nodes        []inventory.NodeID
	tags         []inventory.Tag
	excludeNodes []inventory.NodeID
	excludeTags  []inventory.Tag
	valid        bool
}

// NewTargetSelector 校验并排序去重目标选择器，要求至少指定一种正向条件且包含/排除集合无重叠。
func NewTargetSelector(spec TargetSelectorSpec) (TargetSelector, error) {
	nodes, err := canonicalizeOrdered(spec.Nodes, maxSelectorItems, inventory.NodeID.IsZero, inventory.NodeID.Compare, inventory.NodeID.Equal, ErrInvalidTargetSelector)
	if err != nil {
		return TargetSelector{}, err
	}
	tags, err := canonicalizeTags(spec.Tags, maxSelectorItems, ErrInvalidTargetSelector)
	if err != nil {
		return TargetSelector{}, err
	}
	exNodes, err := canonicalizeOrdered(spec.ExcludeNodes, maxSelectorItems, inventory.NodeID.IsZero, inventory.NodeID.Compare, inventory.NodeID.Equal, ErrInvalidTargetSelector)
	if err != nil {
		return TargetSelector{}, err
	}
	exTags, err := canonicalizeTags(spec.ExcludeTags, maxSelectorItems, ErrInvalidTargetSelector)
	if err != nil {
		return TargetSelector{}, err
	}
	if !spec.All && len(nodes) == 0 && len(tags) == 0 {
		return TargetSelector{}, domi18n.EF(ErrInvalidTargetSelector, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "all, nodes, tags"))
	}
	if hasSortedOverlap(nodes, exNodes, inventory.NodeID.Compare) || hasSortedOverlap(tags, exTags, inventory.Tag.Compare) {
		return TargetSelector{}, domi18n.EF(ErrInvalidTargetSelector, domi18n.KeyPlaybookSelectorOverlap)
	}
	return TargetSelector{spec.All, nodes, tags, exNodes, exTags, true}, nil
}

func canonicalizeTags(raw []inventory.Tag, limit int, baseErr error) ([]inventory.Tag, error) {
	return canonicalizeOrdered(raw, limit, inventory.Tag.IsZero, inventory.Tag.Compare, inventory.Tag.Equal, baseErr)
}

func canonicalizeOrdered[T any](raw []T, limit int, isZero func(T) bool, cmpFn func(T, T) int, eqFn func(T, T) bool, baseErr error) ([]T, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > limit || slices.ContainsFunc(raw, isZero) {
		return nil, domi18n.EF(baseErr, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "selector"))
	}
	out := slices.Clone(raw)
	slices.SortFunc(out, cmpFn)
	return slices.CompactFunc(out, eqFn), nil
}

func hasSortedOverlap[T any](a, b []T, cmpFn func(T, T) int) bool {
	return slices.ContainsFunc(a, func(x T) bool { _, found := slices.BinarySearchFunc(b, x, cmpFn); return found })
}

func (s TargetSelector) IsValid() bool {
	return s.valid && (s.all || len(s.nodes) > 0 || len(s.tags) > 0)
}
func (s TargetSelector) IsZero() bool                     { return !s.IsValid() }
func (s TargetSelector) All() bool                        { return s.IsValid() && s.all }
func (s TargetSelector) Nodes() []inventory.NodeID        { return slices.Clone(s.nodes) }
func (s TargetSelector) Tags() []inventory.Tag            { return slices.Clone(s.tags) }
func (s TargetSelector) ExcludeNodes() []inventory.NodeID { return slices.Clone(s.excludeNodes) }
func (s TargetSelector) ExcludeTags() []inventory.Tag     { return slices.Clone(s.excludeTags) }

// Matches 判定给定节点与标签集合是否命中选择器；排除条件始终优先于包含条件，零值失败关闭返回 false。
func (s TargetSelector) Matches(id inventory.NodeID, nodeTags []inventory.Tag) bool {
	if !s.IsValid() || !id.IsValid() {
		return false
	}
	if _, excluded := slices.BinarySearchFunc(s.excludeNodes, id, inventory.NodeID.Compare); excluded || anyTagInSorted(nodeTags, s.excludeTags) {
		return false
	}
	if s.all {
		return true
	}
	_, byNode := slices.BinarySearchFunc(s.nodes, id, inventory.NodeID.Compare)
	return byNode || anyTagInSorted(nodeTags, s.tags)
}

func anyTagInSorted(candidates, sorted []inventory.Tag) bool {
	if len(candidates) == 0 || len(sorted) == 0 {
		return false
	}
	for _, t := range candidates {
		if t.IsValid() {
			if _, found := slices.BinarySearchFunc(sorted, t, inventory.Tag.Compare); found {
				return true
			}
		}
	}
	return false
}

func (s TargetSelector) Equal(o TargetSelector) bool {
	return s.IsValid() && o.IsValid() && s.all == o.all &&
		slices.EqualFunc(s.nodes, o.nodes, inventory.NodeID.Equal) &&
		slices.EqualFunc(s.tags, o.tags, inventory.Tag.Equal) &&
		slices.EqualFunc(s.excludeNodes, o.excludeNodes, inventory.NodeID.Equal) &&
		slices.EqualFunc(s.excludeTags, o.excludeTags, inventory.Tag.Equal)
}

// WriteCanonical 以零反射长度前缀方式写入 TargetSelector 全部字段（受 digestcover 校验）。
func (s TargetSelector) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !s.valid || !s.IsValid() {
		return ErrInvalidTargetSelector
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(targetSelectorDomainTag)
	enc.writeBool(s.all)
	writeStringers(enc, s.nodes)
	writeStringers(enc, s.tags)
	writeStringers(enc, s.excludeNodes)
	writeStringers(enc, s.excludeTags)
	return enc.err
}
