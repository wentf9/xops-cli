package security

import (
	"cmp"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

const operationBindingDomainTag = "xops.security.operation_binding.v1"

type bindingParam struct{ key, value string }

// OperationBindingSpec 是构造不可变 OperationBinding 的显式入参规格。
type OperationBindingSpec struct {
	Capability     CapabilityKind
	Tool           string
	Action         string
	NodeID         string
	NodeIDs        []string
	Endpoint       algebraic.Option[netaddr.Endpoint]
	CanonicalPaths []string
	RecursivePaths []string
	CommandDigest  algebraic.Option[Digest]
	PlanDigest     algebraic.Option[Digest]
	Parameters     map[string]string
}

// OperationBinding 是不可变的操作规范绑定快照（INV-E4 / INV-E5），锁定能力、工具/动作、目标、
// 规范路径、命令/计划摘要与排序参数，并经 //xops:canonicalhash 由 xopsvet/digestcover 校验全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type OperationBinding struct {
	capability     CapabilityKind
	tool           string
	action         string
	nodeID         string
	nodeIDs        []string
	endpoint       algebraic.Option[netaddr.Endpoint]
	canonicalPaths []string
	recursivePaths []string
	commandDigest  algebraic.Option[Digest]
	planDigest     algebraic.Option[Digest]
	parameters     []bindingParam
	valid          bool
}

// NewOperationBinding 校验并构造规范排序去重后的不可变 OperationBinding。
func NewOperationBinding(spec OperationBindingSpec) (OperationBinding, error) {
	if err := validateBindingSpec(spec); err != nil {
		return OperationBinding{}, err
	}
	nodeIDs, err := canonicalizeUniqueFiltered(spec.NodeIDs, "node_ids", ErrInvalidOperationBinding, isValidNodeID)
	if err != nil {
		return OperationBinding{}, err
	}
	canonicalPaths, err := canonicalizeUniqueStrings(spec.CanonicalPaths, "canonical_paths", ErrInvalidOperationBinding)
	if err != nil {
		return OperationBinding{}, err
	}
	recursivePaths, err := canonicalizeUniqueStrings(spec.RecursivePaths, "recursive_paths", ErrInvalidOperationBinding)
	if err != nil {
		return OperationBinding{}, err
	}
	params, err := canonicalizeBindingParams(spec.Parameters)
	if err != nil {
		return OperationBinding{}, err
	}
	return OperationBinding{
		capability: spec.Capability, tool: spec.Tool, action: spec.Action,
		nodeID: spec.NodeID, nodeIDs: nodeIDs, endpoint: spec.Endpoint,
		canonicalPaths: canonicalPaths, recursivePaths: recursivePaths,
		commandDigest: spec.CommandDigest, planDigest: spec.PlanDigest,
		parameters: params, valid: true,
	}, nil
}

func validateBindingSpec(spec OperationBindingSpec) error {
	switch {
	case !spec.Capability.IsValid():
		return domi18n.WrapSentinel(ErrInvalidOperationBinding, ErrInvalidCapability)
	case !isValidASCIIToken(spec.Tool, maxOperationIDLen) || !isValidASCIIToken(spec.Action, maxOperationIDLen):
		return domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "tool/action"))
	case spec.NodeID != "" && !isValidNodeID(spec.NodeID):
		return domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "node_id"), domi18n.BoundStr("value", spec.NodeID))
	case optInvalid(spec.Endpoint) || optInvalid(spec.CommandDigest) || optInvalid(spec.PlanDigest):
		return domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "endpoint/digest"))
	}
	return nil
}

func canonicalizeUniqueStrings(items []string, field string, baseErr error) ([]string, error) {
	return canonicalizeUniqueFiltered(items, field, baseErr, func(s string) bool {
		return s != "" && !hasInvalidUTF8OrControl(s)
	})
}

func canonicalizeUniqueFiltered(items []string, field string, baseErr error, valid func(string) bool) ([]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		if !valid(item) {
			return nil, domi18n.EF(baseErr, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", field), domi18n.Int("index", i))
		}
		out[i] = item
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func canonicalizeBindingParams(raw map[string]string) ([]bindingParam, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]bindingParam, 0, len(raw))
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		v := raw[k]
		if k == "" || hasInvalidUTF8OrControl(k) {
			return nil, domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "parameter"), domi18n.BoundStr("value", k))
		}
		if !utf8.ValidString(v) || strings.IndexByte(v, 0) >= 0 {
			return nil, domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonInvalidTextChars, domi18n.BoundStr("field", k))
		}
		out = append(out, bindingParam{key: k, value: v})
	}
	return out, nil
}

// IsValid 报告 OperationBinding 是否经构造器有效初始化。
func (b OperationBinding) IsValid() bool {
	return b.valid && b.capability.IsValid() && b.tool != "" && b.action != ""
}

// IsZero 报告 OperationBinding 是否为无效零值。
func (b OperationBinding) IsZero() bool { return !b.IsValid() }

// Capability 返回绑定的能力类别；无效零值返回 CapabilityInvalid。
func (b OperationBinding) Capability() CapabilityKind {
	return pickIf(b.IsValid(), b.capability, CapabilityInvalid)
}

// Tool 返回绑定的工具或用例标识。
func (b OperationBinding) Tool() string { return b.tool }

// Action 返回绑定的具体子动作标识。
func (b OperationBinding) Action() string { return b.action }

// NodeID 返回主目标节点标识（全局操作为空串）。
func (b OperationBinding) NodeID() string { return b.nodeID }

// NodeIDs 返回排序去重后的多目标节点防御性拷贝。
func (b OperationBinding) NodeIDs() []string { return slices.Clone(b.nodeIDs) }

// Endpoint 返回可选强类型目标 SSH 端点。
func (b OperationBinding) Endpoint() algebraic.Option[netaddr.Endpoint] { return b.endpoint }

// CanonicalPaths 返回排序去重后的规范路径防御性拷贝。
func (b OperationBinding) CanonicalPaths() []string { return slices.Clone(b.canonicalPaths) }

// RecursivePaths 返回排序去重后的递归目录路径防御性拷贝。
func (b OperationBinding) RecursivePaths() []string { return slices.Clone(b.recursivePaths) }

// CommandDigest 返回可选命令计划 SHA-256 摘要。
func (b OperationBinding) CommandDigest() algebraic.Option[Digest] { return b.commandDigest }

// PlanDigest 返回可选连接计划 Merkle SHA-256 摘要。
func (b OperationBinding) PlanDigest() algebraic.Option[Digest] { return b.planDigest }

// Parameters 返回规范参数映射的全新拷贝，隔离外部修改。
func (b OperationBinding) Parameters() map[string]string {
	if !b.IsValid() || len(b.parameters) == 0 {
		return nil
	}
	out := make(map[string]string, len(b.parameters))
	for _, kv := range b.parameters {
		out[kv.key] = kv.value
	}
	return out
}

// Param 按键查询单个绑定参数；无效绑定或键不存在返回 ("", false)。
func (b OperationBinding) Param(key string) (string, bool) {
	if !b.IsValid() || len(b.parameters) == 0 {
		return "", false
	}
	idx, found := slices.BinarySearchFunc(b.parameters, key, func(item bindingParam, target string) int {
		return cmp.Compare(item.key, target)
	})
	if !found {
		return "", false
	}
	return b.parameters[idx].value, true
}

// WriteCanonical 以零反射、长度前缀与域分离方式将 OperationBinding 全部字段写入 w（受 digestcover 校验）。
func (b OperationBinding) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !b.valid || !b.IsValid() {
		return ErrInvalidOperationBinding
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(operationBindingDomainTag)
	enc.writeUint8(uint8(b.capability))
	enc.writeString(b.tool)
	enc.writeString(b.action)
	enc.writeString(b.nodeID)
	enc.writeStrings(b.nodeIDs)
	enc.writeOptEndpoint(b.endpoint)
	enc.writeStrings(b.canonicalPaths)
	enc.writeStrings(b.recursivePaths)
	enc.writeOptDigest(b.commandDigest)
	enc.writeOptDigest(b.planDigest)
	enc.writeParams(b.parameters)
	return enc.err
}

// Digest 计算并返回 OperationBinding 的确定性 SHA-256 规范摘要。
func (b OperationBinding) Digest() (Digest, error) { return digestCanonical(b.WriteCanonical) }

// Equal 严格比对两个 OperationBinding 是否均有效且全部字段完全一致（无效零值永不相等）。
func (b OperationBinding) Equal(other OperationBinding) bool {
	return b.IsValid() && other.IsValid() && b.capability == other.capability && b.tool == other.tool &&
		b.action == other.action && b.nodeID == other.nodeID && slices.Equal(b.nodeIDs, other.nodeIDs) &&
		equalOpt(b.endpoint, other.endpoint) && slices.Equal(b.canonicalPaths, other.canonicalPaths) &&
		slices.Equal(b.recursivePaths, other.recursivePaths) && equalOpt(b.commandDigest, other.commandDigest) &&
		equalOpt(b.planDigest, other.planDigest) && slices.Equal(b.parameters, other.parameters)
}

type operationBindingWire struct {
	Capability     algebraic.Option[CapabilityKind]   `json:"capability"`
	Tool           algebraic.Option[string]           `json:"tool"`
	Action         algebraic.Option[string]           `json:"action"`
	NodeID         string                             `json:"node_id,omitzero"`
	NodeIDs        []string                           `json:"node_ids,omitzero"`
	Endpoint       algebraic.Option[netaddr.Endpoint] `json:"endpoint,omitzero"`
	CanonicalPaths []string                           `json:"canonical_paths,omitzero"`
	RecursivePaths []string                           `json:"recursive_paths,omitzero"`
	CommandDigest  algebraic.Option[Digest]           `json:"command_digest,omitzero"`
	PlanDigest     algebraic.Option[Digest]           `json:"plan_digest,omitzero"`
	Parameters     map[string]string                  `json:"parameters,omitzero"`
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；配合 Deterministic(true) 产出确定性 JSON，零值失败关闭。
func (b OperationBinding) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !b.IsValid() {
		return ErrInvalidOperationBinding
	}
	return jsonv2.MarshalEncode(enc, operationBindingWire{
		Capability: algebraic.Some(b.capability), Tool: algebraic.Some(b.tool), Action: algebraic.Some(b.action),
		NodeID: b.nodeID, NodeIDs: b.nodeIDs, Endpoint: b.endpoint, CanonicalPaths: b.canonicalPaths,
		RecursivePaths: b.recursivePaths, CommandDigest: b.commandDigest, PlanDigest: b.planDigest,
		Parameters: b.Parameters(),
	})
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；对 JSON null、缺失必需字段或非法值失败关闭并重置零值。
func (b *OperationBinding) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(b, dec, ErrInvalidOperationBinding, func(w operationBindingWire) (OperationBinding, error) {
		capKind, okC := w.Capability.Get()
		tool, okT := w.Tool.Get()
		action, okA := w.Action.Get()
		if !okC || !okT || !okA {
			return OperationBinding{}, domi18n.EF(ErrInvalidOperationBinding, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "capability/tool/action"))
		}
		return NewOperationBinding(OperationBindingSpec{
			Capability: capKind, Tool: tool, Action: action, NodeID: w.NodeID, NodeIDs: w.NodeIDs,
			Endpoint: w.Endpoint, CanonicalPaths: w.CanonicalPaths, RecursivePaths: w.RecursivePaths,
			CommandDigest: w.CommandDigest, PlanDigest: w.PlanDigest, Parameters: w.Parameters,
		})
	})
}
