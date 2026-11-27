package playbook

import (
	jsonv2 "encoding/json/v2"
	"io"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const (
	stepDomainTag     = "xops.playbook.step.v2"
	playbookDomainTag = "xops.playbook.ast.v2"
)

// StepSpec 与 Step 表示 Playbook 中的单条不可变声明式步骤（零值失败关闭，经 digestcover 校验）。
type StepSpec struct {
	ID       StepID
	Name     string
	Action   StepAction
	OnError  algebraic.Option[OnErrorPolicy]
	WhenTags []inventory.Tag
}

//xops:opaque
//xops:failclosed
//xops:canonicalhash
type Step struct {
	id       StepID
	name     string
	action   StepAction
	onError  algebraic.Option[OnErrorPolicy]
	whenTags []inventory.Tag
	valid    bool
}

// NewStep 校验步骤 ID、名称、封闭动作、可选错误覆盖与条件标签，构造不可变 Step。
func NewStep(spec StepSpec) (Step, error) {
	if !spec.ID.IsValid() {
		return Step{}, domi18n.WrapSentinel(ErrInvalidStep, ErrInvalidStepID)
	}
	if len(spec.Name) > maxNameBytes || hasForbiddenStrictText(spec.Name) {
		return Step{}, domi18n.EF(ErrInvalidStep, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "step.name"))
	}
	if p, ok := spec.OnError.Get(); ok && !p.IsValid() {
		return Step{}, domi18n.WrapSentinel(ErrInvalidStep, ErrInvalidOnErrorPolicy)
	}
	action, err := cloneStepAction(spec.Action)
	if err != nil {
		return Step{}, domi18n.WrapSentinel(ErrInvalidStep, err)
	}
	whenTags, err := canonicalizeTags(spec.WhenTags, maxStepTags, ErrInvalidStep)
	if err != nil {
		return Step{}, err
	}
	return Step{spec.ID, spec.Name, action, spec.OnError, whenTags, true}, nil
}

func (s Step) IsValid() bool {
	return s.valid && s.id.IsValid() && s.action != nil && s.action.IsValid()
}
func (s Step) IsZero() bool                             { return !s.IsValid() }
func (s Step) ID() StepID                               { return s.id }
func (s Step) Name() string                             { return s.name }
func (s Step) Action() StepAction                       { return pickIf(s.IsValid(), mustCloneValidAction(s.action), nil) }
func (s Step) OnError() algebraic.Option[OnErrorPolicy] { return s.onError }
func (s Step) WhenTags() []inventory.Tag                { return slices.Clone(s.whenTags) }
func (s Step) MatchesTags(nodeTags []inventory.Tag) bool {
	return s.IsValid() && (len(s.whenTags) == 0 || anyTagInSorted(nodeTags, s.whenTags))
}
func (s Step) Equal(o Step) bool {
	return s.IsValid() && o.IsValid() && s.id.Equal(o.id) && s.name == o.name &&
		EqualStepAction(s.action, o.action) && algebraic.EqualOption(s.onError, o.onError) &&
		slices.EqualFunc(s.whenTags, o.whenTags, inventory.Tag.Equal)
}

// WriteCanonical 以零反射长度前缀方式写入 Step 全部字段（受 digestcover 校验）。
func (s Step) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !s.valid || !s.IsValid() {
		return ErrInvalidStep
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(stepDomainTag)
	enc.writeString(s.id.String())
	enc.writeString(s.name)
	if enc.err == nil {
		enc.fail(writeStepActionCanonical(w, s.action))
	}
	if p, ok := s.onError.Get(); ok {
		enc.writeUint8(1)
		enc.writeUint8(uint8(p))
	} else {
		enc.writeUint8(0)
	}
	writeStringers(enc, s.whenTags)
	return enc.err
}

// PlaybookSpec 与 Playbook 表示不可变声明式 Playbook vNext AST 快照（仅支持 version=2，零值失败关闭）。
type PlaybookSpec struct {
	Version     uint32
	ID          PlaybookID
	Name        string
	Description string
	OnError     OnErrorPolicy
	Target      TargetSelector
	Vars        map[string]string
	Steps       algebraic.NonEmpty[Step]
}

//xops:opaque
//xops:failclosed
//xops:canonicalhash
type Playbook struct {
	version        uint32
	id             PlaybookID
	name           string
	description    string
	onError        OnErrorPolicy
	target         TargetSelector
	vars           []kvEntry
	steps          algebraic.NonEmpty[Step]
	snapshotDigest security.Digest //xops:hash-exclude:由 Playbook.WriteCanonical 派生的不可变规范快照摘要
	valid          bool
}

// NewPlaybook 校验 version==2、元数据、目标选择器、变量表与非空且 ID 唯一的步骤序列，并计算不可变规范摘要。
func NewPlaybook(spec PlaybookSpec) (Playbook, error) {
	if err := validatePlaybookHeader(spec); err != nil {
		return Playbook{}, err
	}
	vars, err := canonicalizeKVMap(spec.Vars, maxVarsCount, maxVarValBytes, isValidVarKey, true)
	if err != nil {
		return Playbook{}, domi18n.WrapSentinel(ErrInvalidPlaybook, err)
	}
	steps, err := cloneAndValidateSteps(spec.Steps)
	if err != nil {
		return Playbook{}, err
	}
	pb := Playbook{VersionV2, spec.ID, spec.Name, spec.Description, spec.OnError, spec.Target, vars, steps, zeroVal[security.Digest](), true}
	digest, err := digestCanonical(pb.WriteCanonical)
	if err != nil {
		return Playbook{}, domi18n.WrapSentinel(ErrInvalidPlaybook, err)
	}
	pb.snapshotDigest = digest
	return pb, nil
}

func validatePlaybookHeader(spec PlaybookSpec) error {
	switch {
	case spec.Version != VersionV2:
		return domi18n.EF(ErrUnsupportedVersion, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "version"), domi18n.Uint64("value", uint64(spec.Version)))
	case !spec.ID.IsValid():
		return domi18n.WrapSentinel(ErrInvalidPlaybook, ErrInvalidPlaybookID)
	case spec.Name == "" || len(spec.Name) > maxNameBytes || hasForbiddenStrictText(spec.Name) || !hasVisibleText(spec.Name):
		return domi18n.EF(ErrInvalidPlaybook, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "playbook.name"))
	case len(spec.Description) > maxDescriptionBytes || hasForbiddenStrictText(spec.Description):
		return domi18n.EF(ErrInvalidPlaybook, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "playbook.description"))
	case !spec.OnError.IsValid():
		return domi18n.WrapSentinel(ErrInvalidPlaybook, ErrInvalidOnErrorPolicy)
	case !spec.Target.IsValid():
		return domi18n.WrapSentinel(ErrInvalidPlaybook, ErrInvalidTargetSelector)
	}
	return nil
}

func cloneAndValidateSteps(raw algebraic.NonEmpty[Step]) (algebraic.NonEmpty[Step], error) {
	if !raw.IsValid() {
		return zeroVal[algebraic.NonEmpty[Step]](), domi18n.EF(ErrInvalidPlaybook, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "steps"))
	}
	slice := raw.Slice()
	if len(slice) > maxStepsPerPlaybook {
		return zeroVal[algebraic.NonEmpty[Step]](), domi18n.EF(ErrInvalidPlaybook, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "steps"), domi18n.Int("count", len(slice)), domi18n.Int("limit", maxStepsPerPlaybook))
	}
	seen, cloned := make(map[StepID]bool, len(slice)), make([]Step, len(slice))
	for i, st := range slice {
		if !st.IsValid() {
			return zeroVal[algebraic.NonEmpty[Step]](), domi18n.EF(ErrInvalidStep, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "steps"), domi18n.Int("index", i))
		}
		if seen[st.id] {
			return zeroVal[algebraic.NonEmpty[Step]](), domi18n.EF(ErrDuplicateStepID, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "step_id"), domi18n.BoundStr("value", st.id.String()))
		}
		seen[st.id] = true
		cloned[i] = cloneValidStep(st)
	}
	return algebraic.NonEmptyFromSlice(cloned)
}

func cloneValidStep(st Step) Step {
	return Step{st.id, st.name, mustCloneValidAction(st.action), st.onError, slices.Clone(st.whenTags), true}
}

func (p Playbook) IsValid() bool {
	return p.valid && p.version == VersionV2 && p.id.IsValid() && p.name != "" &&
		p.onError.IsValid() && p.target.IsValid() && p.steps.IsValid() && p.snapshotDigest.IsValid()
}
func (p Playbook) IsZero() bool                    { return !p.IsValid() }
func (p Playbook) Version() uint32                 { return p.version }
func (p Playbook) ID() PlaybookID                  { return p.id }
func (p Playbook) Name() string                    { return p.name }
func (p Playbook) Description() string             { return p.description }
func (p Playbook) OnError() OnErrorPolicy          { return p.onError }
func (p Playbook) Target() TargetSelector          { return p.target }
func (p Playbook) Vars() map[string]string         { return kvSliceToMap(p.vars) }
func (p Playbook) Steps() algebraic.NonEmpty[Step] { return p.steps }
func (p Playbook) Digest() security.Digest         { return p.snapshotDigest }

// VarValue 按键二分查找单个 Playbook 变量值。
func (p Playbook) VarValue(key string) (string, bool) { return lookupKV(p.vars, key) }

// StepSlice 返回全部步骤的防御性深拷贝切片。
func (p Playbook) StepSlice() []Step {
	if !p.IsValid() {
		return nil
	}
	src := p.steps.Slice()
	out := make([]Step, len(src))
	for i, st := range src {
		out[i] = cloneValidStep(st)
	}
	return out
}

// StepByID 按 StepID 查找步骤及其声明序号；不存在或无效返回 (零值, -1, false)。
func (p Playbook) StepByID(id StepID) (Step, int, bool) {
	if !p.IsValid() || !id.IsValid() {
		return Step{}, -1, false
	}
	for i, st := range p.steps.Slice() {
		if st.id.Equal(id) {
			return cloneValidStep(st), i, true
		}
	}
	return Step{}, -1, false
}

// EffectiveOnError 计算某步骤在当前 Playbook 下的生效错误策略（步骤级覆盖优先于 Playbook 默认）。
func (p Playbook) EffectiveOnError(step Step) OnErrorPolicy {
	if !p.IsValid() || !step.IsValid() {
		return OnErrorInvalid
	}
	return step.onError.OrElse(p.onError)
}

// CanonicalJSON 使用 Go 1.27 encoding/json/v2 Deterministic(true) 编码确定性 JSON。
func (p Playbook) CanonicalJSON() ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidPlaybook
	}
	return jsonv2.Marshal(p, jsonv2.Deterministic(true))
}

func (p Playbook) Equal(o Playbook) bool {
	return p.IsValid() && o.IsValid() && p.version == o.version && p.id.Equal(o.id) &&
		p.name == o.name && p.description == o.description && p.onError == o.onError &&
		p.target.Equal(o.target) && slices.Equal(p.vars, o.vars) &&
		p.snapshotDigest.Equal(o.snapshotDigest) && slices.EqualFunc(p.steps.Slice(), o.steps.Slice(), Step.Equal)
}

// WriteCanonical 以零反射、长度前缀与域分离方式将 Playbook 全部语义字段写入 w（受 digestcover 校验）。
func (p Playbook) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !p.valid || p.version != VersionV2 || !p.id.IsValid() || p.name == "" || !p.onError.IsValid() || !p.target.IsValid() || !p.steps.IsValid() {
		return ErrInvalidPlaybook
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(playbookDomainTag)
	enc.writeUint32(p.version)
	enc.writeString(p.id.String())
	enc.writeString(p.name)
	enc.writeString(p.description)
	enc.writeUint8(uint8(p.onError))
	if enc.err == nil {
		enc.fail(p.target.WriteCanonical(w))
	}
	enc.writeKVs(p.vars)
	steps := p.steps.Slice()
	enc.writeUint64(uint64(len(steps)))
	for _, st := range steps {
		if enc.err == nil {
			enc.fail(st.WriteCanonical(w))
		}
	}
	return enc.err
}
