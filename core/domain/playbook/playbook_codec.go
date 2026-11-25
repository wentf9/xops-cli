package playbook

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

type optActionWire struct {
	val *stepActionWire
	set bool
}

func (o optActionWire) IsZero() bool { return !o.set || o.val == nil }

func (o optActionWire) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !o.set || o.val == nil {
		return enc.WriteToken(jsontext.Null)
	}
	return jsonv2.MarshalEncode(enc, o.val)
}

func (o *optActionWire) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if dec.PeekKind() == 'n' {
		if _, err := dec.ReadToken(); err != nil {
			return err
		}
		return fmt.Errorf("%w: 嵌套动作不能为 JSON null", ErrInvalidStepAction)
	}
	var w stepActionWire
	if err := jsonv2.UnmarshalDecode(dec, &w, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	o.val, o.set = &w, true
	return nil
}

type (
	targetSelectorWire struct {
		All          bool               `json:"all,omitzero"`
		Nodes        []inventory.NodeID `json:"nodes,omitzero"`
		Tags         []inventory.Tag    `json:"tags,omitzero"`
		ExcludeNodes []inventory.NodeID `json:"exclude_nodes,omitzero"`
		ExcludeTags  []inventory.Tag    `json:"exclude_tags,omitzero"`
	}
	stepActionWire struct {
		Kind          algebraic.Option[StepActionKind]          `json:"kind"`
		Command       string                                    `json:"command,omitzero"`
		Source        algebraic.Option[pathalg.LocalSourcePath] `json:"source,omitzero"`
		SymlinkPolicy algebraic.Option[pathalg.SymlinkPolicy]   `json:"symlink_policy,omitzero"`
		Dest          algebraic.Option[pathalg.RemotePath]      `json:"dest,omitzero"`
		Args          []string                                  `json:"args,omitzero"`
		Profile       algebraic.Option[execution.LaunchProfile] `json:"profile,omitzero"`
		WorkDir       algebraic.Option[pathalg.RemotePath]      `json:"work_dir,omitzero"`
		Env           map[string]string                         `json:"env,omitzero"`
		Timeout       algebraic.Option[algebraic.Duration]      `json:"timeout,omitzero"`
		Vars          map[string]string                         `json:"vars,omitzero"`
		Mode          algebraic.Option[FileMode]                `json:"mode,omitzero"`
		Overwrite     algebraic.Option[bool]                    `json:"overwrite,omitzero"`
		Atomic        algebraic.Option[bool]                    `json:"atomic,omitzero"`
		Check         optActionWire                             `json:"check,omitzero"`
		Action        optActionWire                             `json:"action,omitzero"`
		MaxRetries    algebraic.Option[uint8]                   `json:"max_retries,omitzero"`
	}
	stepWire struct {
		ID       algebraic.Option[StepID]        `json:"id"`
		Name     string                          `json:"name,omitzero"`
		Action   optActionWire                   `json:"action"`
		OnError  algebraic.Option[OnErrorPolicy] `json:"on_error,omitzero"`
		WhenTags []inventory.Tag                 `json:"when_tags,omitzero"`
	}
	playbookWire struct {
		Version     algebraic.Option[uint32]          `json:"version"`
		ID          algebraic.Option[PlaybookID]      `json:"id"`
		Name        algebraic.Option[string]          `json:"name"`
		Description string                            `json:"description,omitzero"`
		OnError     algebraic.Option[OnErrorPolicy]   `json:"on_error"`
		Target      algebraic.Option[TargetSelector]  `json:"target"`
		Vars        map[string]string                 `json:"vars,omitzero"`
		Steps       []Step                            `json:"steps"`
		Digest      algebraic.Option[security.Digest] `json:"digest,omitzero"`
	}
)

// MarshalJSONTo 为 TargetSelector 提供值接收者 json/v2 确定性编码；零值失败关闭。
func (s TargetSelector) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !s.IsValid() {
		return ErrInvalidTargetSelector
	}
	return jsonv2.MarshalEncode(enc, targetSelectorWire{
		All: s.all, Nodes: s.nodes, Tags: s.tags, ExcludeNodes: s.excludeNodes, ExcludeTags: s.excludeTags,
	})
}

// UnmarshalJSONFrom 为 TargetSelector 提供失败关闭 json/v2 解码，拒绝 null、未知字段与非法规则。
func (s *TargetSelector) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(s, dec, ErrInvalidTargetSelector, func(w targetSelectorWire) (TargetSelector, error) {
		return NewTargetSelector(TargetSelectorSpec(w))
	})
}

// MarshalStepActionTo 将任意有效 StepAction 编码至 Go 1.27 JSON/v2 流；nil 或零值失败关闭。
func MarshalStepActionTo(enc *jsontext.Encoder, action StepAction) error {
	if enc == nil {
		return ErrNilWriter
	}
	w, err := encodeStepActionWire(action, 0)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, w)
}

// UnmarshalStepActionFrom 从 Go 1.27 JSON/v2 流严格解码多态 StepAction；
// 拒绝 JSON null、未知字段、缺失必需字段、跨变体字段混用及嵌套 ensure。
func UnmarshalStepActionFrom(dec *jsontext.Decoder) (StepAction, error) {
	if dec == nil {
		return nil, ErrNilReceiver
	}
	var out StepAction
	err := unmarshalJSONStrict(&out, dec, ErrInvalidStepAction, func(w stepActionWire) (StepAction, error) {
		return decodeStepActionWire(w, 0)
	})
	return out, err
}

// MarshalJSONTo 为 5 类封闭 StepAction 变体提供值接收者 json/v2 编码（零值失败关闭）。
func (s StepShell) MarshalJSONTo(enc *jsontext.Encoder) error    { return MarshalStepActionTo(enc, &s) }
func (s StepScript) MarshalJSONTo(enc *jsontext.Encoder) error   { return MarshalStepActionTo(enc, &s) }
func (s StepCopy) MarshalJSONTo(enc *jsontext.Encoder) error     { return MarshalStepActionTo(enc, &s) }
func (s StepTemplate) MarshalJSONTo(enc *jsontext.Encoder) error { return MarshalStepActionTo(enc, &s) }
func (s StepEnsure) MarshalJSONTo(enc *jsontext.Encoder) error   { return MarshalStepActionTo(enc, &s) }

func encodeStepActionWire(a StepAction, depth int) (stepActionWire, error) {
	if a == nil || !a.IsValid() {
		return stepActionWire{}, ErrInvalidStepAction
	}
	if depth > 1 {
		return stepActionWire{}, ErrNestedEnsureForbidden
	}
	switch v := a.(type) {
	case *StepShell:
		return stepActionWire{Kind: algebraic.Some(StepActionKindShell), Command: v.command, Profile: v.profile, WorkDir: v.workDir, Env: kvSliceToMap(v.env), Timeout: v.timeout}, nil
	case *StepScript:
		return stepActionWire{Kind: algebraic.Some(StepActionKindScript), Source: algebraic.Some(v.source), SymlinkPolicy: algebraic.Some(v.symlinkPolicy), Args: v.args, Profile: v.profile, WorkDir: v.workDir, Env: kvSliceToMap(v.env), Timeout: v.timeout}, nil
	case *StepCopy:
		return stepActionWire{Kind: algebraic.Some(StepActionKindCopy), Source: algebraic.Some(v.source), SymlinkPolicy: algebraic.Some(v.symlinkPolicy), Dest: algebraic.Some(v.dest), Mode: v.mode, Overwrite: optTrue(v.overwrite), Atomic: optTrue(v.atomic)}, nil
	case *StepTemplate:
		return stepActionWire{Kind: algebraic.Some(StepActionKindTemplate), Source: algebraic.Some(v.source), SymlinkPolicy: algebraic.Some(v.symlinkPolicy), Dest: algebraic.Some(v.dest), Vars: kvSliceToMap(v.vars), Mode: v.mode, Overwrite: optTrue(v.overwrite), Atomic: optTrue(v.atomic)}, nil
	case *StepEnsure:
		return encodeEnsureWire(v, depth)
	default:
		return stepActionWire{}, ErrInvalidStepAction
	}
}

func encodeEnsureWire(v *StepEnsure, depth int) (stepActionWire, error) {
	if depth > 0 {
		return stepActionWire{}, ErrNestedEnsureForbidden
	}
	cw, err := encodeStepActionWire(v.check, depth+1)
	if err != nil {
		return stepActionWire{}, err
	}
	aw, err := encodeStepActionWire(v.action, depth+1)
	if err != nil {
		return stepActionWire{}, err
	}
	w := stepActionWire{Kind: algebraic.Some(StepActionKindEnsure), Check: optActionWire{val: &cw, set: true}, Action: optActionWire{val: &aw, set: true}}
	if v.maxRetries > 0 {
		w.MaxRetries = algebraic.Some(v.maxRetries)
	}
	return w, nil
}

func decodeStepActionWire(w stepActionWire, depth int) (StepAction, error) {
	kind, ok := w.Kind.Get()
	if !ok {
		return nil, fmt.Errorf("%w: 缺少必需的 action.kind 字段", ErrInvalidStepAction)
	}
	mask := stepActionFieldMask(w)
	switch kind {
	case StepActionKindShell:
		return decodeShellWire(w, mask)
	case StepActionKindScript:
		return decodeScriptWire(w, mask)
	case StepActionKindCopy:
		return decodeCopyWire(w, mask)
	case StepActionKindTemplate:
		return decodeTemplateWire(w, mask)
	case StepActionKindEnsure:
		return decodeEnsureWire(w, mask, depth)
	default:
		return nil, fmt.Errorf("%w: 未知动作类别 %d", ErrInvalidStepAction, uint8(kind))
	}
}

func optTrue(v bool) algebraic.Option[bool] {
	return pickIf(v, algebraic.Some(true), algebraic.None[bool]())
}

// stepActionFieldMask 按语义组编码已填写字段位掩码，精确阻断跨变体串用字段（含显式零值如 false/[]/{}）。
func stepActionFieldMask(w stepActionWire) uint16 {
	return maskFlags(
		w.Command != "", w.Source.IsSome(), w.SymlinkPolicy.IsSome(), w.Dest.IsSome(), w.Args != nil,
		w.Profile.IsSome() || w.WorkDir.IsSome() || w.Env != nil || w.Timeout.IsSome(),
		w.Vars != nil, w.Mode.IsSome() || w.Overwrite.IsSome() || w.Atomic.IsSome(),
		w.Check.set || w.Action.set || w.MaxRetries.IsSome(),
	)
}

func decodeShellWire(w stepActionWire, mask uint16) (StepAction, error) {
	const allowed = (1 << 0) | (1 << 5)
	if mask&^allowed != 0 || w.Command == "" {
		return nil, fmt.Errorf("%w: shell 变体字段组合非法", ErrInvalidStepAction)
	}
	return NewStepShell(StepShellSpec{w.Command, w.Profile, w.WorkDir, w.Env, w.Timeout})
}

func decodeScriptWire(w stepActionWire, mask uint16) (StepAction, error) {
	const allowed = (1 << 1) | (1 << 2) | (1 << 4) | (1 << 5)
	src, hasSrc := w.Source.Get()
	if mask&^allowed != 0 || !hasSrc {
		return nil, fmt.Errorf("%w: script 变体字段组合非法", ErrInvalidStepAction)
	}
	return NewStepScript(StepScriptSpec{src, w.SymlinkPolicy.OrElse(pathalg.SymlinkReject), w.Args, w.Profile, w.WorkDir, w.Env, w.Timeout})
}

func decodeCopyWire(w stepActionWire, mask uint16) (StepAction, error) {
	const allowed = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 7)
	src, hasSrc := w.Source.Get()
	dst, hasDst := w.Dest.Get()
	if mask&^allowed != 0 || !hasSrc || !hasDst {
		return nil, fmt.Errorf("%w: copy 变体字段组合非法", ErrInvalidStepAction)
	}
	return NewStepCopy(StepCopySpec{src, w.SymlinkPolicy.OrElse(pathalg.SymlinkReject), dst, w.Mode, w.Overwrite.OrElse(false), w.Atomic.OrElse(false)})
}

func decodeTemplateWire(w stepActionWire, mask uint16) (StepAction, error) {
	const allowed = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 6) | (1 << 7)
	src, hasSrc := w.Source.Get()
	dst, hasDst := w.Dest.Get()
	if mask&^allowed != 0 || !hasSrc || !hasDst {
		return nil, fmt.Errorf("%w: template 变体字段组合非法", ErrInvalidStepAction)
	}
	return NewStepTemplate(StepTemplateSpec{src, w.SymlinkPolicy.OrElse(pathalg.SymlinkReject), dst, w.Vars, w.Mode, w.Overwrite.OrElse(false), w.Atomic.OrElse(false)})
}

func decodeEnsureWire(w stepActionWire, mask uint16, depth int) (StepAction, error) {
	if depth > 0 {
		return nil, ErrNestedEnsureForbidden
	}
	if mask&^(1<<8) != 0 || !w.Check.set || w.Check.val == nil || !w.Action.set || w.Action.val == nil {
		return nil, fmt.Errorf("%w: ensure 变体必须携带 check 与 action 且不得混用其他字段", ErrInvalidStepAction)
	}
	check, err := decodeStepActionWire(*w.Check.val, depth+1)
	if err != nil {
		return nil, err
	}
	action, err := decodeStepActionWire(*w.Action.val, depth+1)
	if err != nil {
		return nil, err
	}
	return NewStepEnsure(StepEnsureSpec{check, action, w.MaxRetries.OrElse(0)})
}

// MarshalJSONTo 为 Step 提供值接收者 json/v2 确定性编码；零值失败关闭。
func (s Step) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !s.IsValid() {
		return ErrInvalidStep
	}
	aw, err := encodeStepActionWire(s.action, 0)
	if err != nil {
		return err
	}
	return jsonv2.MarshalEncode(enc, stepWire{algebraic.Some(s.id), s.name, optActionWire{val: &aw, set: true}, s.onError, s.whenTags})
}

// UnmarshalJSONFrom 为 Step 提供失败关闭 json/v2 解码。
func (s *Step) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(s, dec, ErrInvalidStep, func(w stepWire) (Step, error) {
		id, okID := w.ID.Get()
		if !okID || !w.Action.set || w.Action.val == nil {
			return Step{}, fmt.Errorf("%w: 缺少必需的 step.id 或 step.action 字段", ErrInvalidStep)
		}
		action, err := decodeStepActionWire(*w.Action.val, 0)
		if err != nil {
			return Step{}, fmt.Errorf("%w: %w", ErrInvalidStep, err)
		}
		return NewStep(StepSpec{id, w.Name, action, w.OnError, w.WhenTags})
	})
}

// MarshalJSONTo 为 Playbook 提供值接收者 json/v2 确定性编码（附带不可变快照摘要）；零值失败关闭。
func (p Playbook) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidPlaybook
	}
	return jsonv2.MarshalEncode(enc, playbookWire{algebraic.Some(p.version), algebraic.Some(p.id), algebraic.Some(p.name), p.description, algebraic.Some(p.onError), algebraic.Some(p.target), p.Vars(), p.steps.Slice(), algebraic.Some(p.snapshotDigest)})
}

// UnmarshalJSONFrom 为 Playbook 提供严格失败关闭解码，拒绝 null、未知字段、非 v2 版本及篡改摘要。
func (p *Playbook) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONStrict(p, dec, ErrInvalidPlaybook, buildPlaybookFromWire)
}

func buildPlaybookFromWire(w playbookWire) (Playbook, error) {
	ver, okV := w.Version.Get()
	id, okID := w.ID.Get()
	name, okN := w.Name.Get()
	onErr, okE := w.OnError.Get()
	target, okT := w.Target.Get()
	if !okV || !okID || !okN || !okE || !okT {
		return Playbook{}, fmt.Errorf("%w: 缺少必需的 version/id/name/on_error/target 字段", ErrInvalidPlaybook)
	}
	steps, err := algebraic.NonEmptyFromSlice(w.Steps)
	if err != nil {
		return Playbook{}, fmt.Errorf("%w: %w", ErrInvalidPlaybook, err)
	}
	pb, err := NewPlaybook(PlaybookSpec{ver, id, name, w.Description, onErr, target, w.Vars, steps})
	if err != nil {
		return Playbook{}, err
	}
	if dig, hasDig := w.Digest.Get(); hasDig && !dig.Equal(pb.snapshotDigest) {
		return Playbook{}, ErrTamperedDigest
	}
	return pb, nil
}
