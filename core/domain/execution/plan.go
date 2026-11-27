package execution

import (
	"cmp"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const commandPlanDomainTag = "xops.execution.command_plan.v1"

// PlanKind 标识命令执行计划的操作类型（普通命令或脚本）；零值 PlanKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type PlanKind uint8

const (
	PlanKindInvalid PlanKind = iota // 无效计划类型（零值失败关闭）
	PlanKindCommand                 // 单次命令执行（command 字符串或 argv 参数向量）
	PlanKindScript                  // 有界脚本执行（必须绑定非 server 显式解释器）
)

// ParsePlanKind 严格解析规范小写计划类型（"command" 或 "script"）。
func ParsePlanKind(raw string) (PlanKind, error) {
	if !hasForbiddenStrictText(raw) {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "command":
			return PlanKindCommand, nil
		case "script":
			return PlanKindScript, nil
		}
	}
	return PlanKindInvalid, domi18n.EF(ErrInvalidPlanKind, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "plan_kind"), domi18n.BoundStr("value", raw))
}

// IsValid 报告 k 是否为合法计划类型。
func (k PlanKind) IsValid() bool { return k == PlanKindCommand || k == PlanKindScript }

// IsZero 报告 k 是否为无效零值。
func (k PlanKind) IsZero() bool { return k == PlanKindInvalid }

// String 返回计划类型的规范小写文本；非法值返回 "invalid"。
func (k PlanKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "command", "script")
}

// AppendText 实现 encoding.TextAppender（值接收者）；对非法值失败关闭。
func (k PlanKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidPlanKind, uint8(k))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (k PlanKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 PlanKindInvalid 并失败关闭。
func (k *PlanKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, PlanKindInvalid, text, ParsePlanKind)
}

type envEntry struct{ key, value string }

// CommandPlanSpec 是构造不可变 CommandPlan 的显式入参规格。
// PlanKindCommand 要求 Command 与 Argv 二选一且互斥；PlanKindScript 要求非空脚本文本 Command，并允许附带可选位置参数 Argv；
// MaxOutputBytes 未设置时取 DefaultMaxOutputBytes，显式 Some(0) 失败关闭。
type CommandPlanSpec struct {
	Kind           PlanKind
	Profile        LaunchProfile
	Command        string
	Argv           []string
	WorkDir        algebraic.Option[pathalg.RemotePath]
	Env            map[string]string
	Timeout        algebraic.Option[algebraic.Duration]
	MaxOutputBytes algebraic.Option[uint64]
	PTY            bool
}

// CommandPlan 表示经过完整校验与规范排序的不可变远端命令/脚本执行计划；
// 零值恒无效，且经 //xops:canonicalhash 由 xopsvet/digestcover 校验 WriteCanonical 全字段覆盖。
//
//xops:opaque
//xops:failclosed
//xops:canonicalhash
type CommandPlan struct {
	kind           PlanKind
	profile        LaunchProfile
	command        string
	argv           []string
	workDir        algebraic.Option[pathalg.RemotePath]
	env            []envEntry
	timeout        algebraic.Option[algebraic.Duration]
	maxOutputBytes uint64
	pty            bool
	valid          bool
}

// NewCommandPlan 校验执行配置、命令/参数载荷、工作目录、环境变量、超时与输出上限，构造不可变 CommandPlan。
func NewCommandPlan(spec CommandPlanSpec) (CommandPlan, error) {
	if err := validateCommandPlanHeader(spec); err != nil {
		return CommandPlan{}, err
	}
	argv, err := validateCommandPayload(spec.Kind, spec.Command, spec.Argv)
	if err != nil {
		return CommandPlan{}, err
	}
	env, err := canonicalizeEnvMap(spec.Env)
	if err != nil {
		return CommandPlan{}, err
	}
	maxOut, err := resolveMaxOutputBytes(spec.MaxOutputBytes)
	if err != nil {
		return CommandPlan{}, err
	}
	p := CommandPlan{
		kind: spec.Kind, profile: spec.Profile, command: spec.Command, argv: argv,
		workDir: spec.WorkDir, env: env, timeout: spec.Timeout, maxOutputBytes: maxOut,
		pty: spec.PTY, valid: true,
	}
	if _, err := p.RenderCommand(); err != nil {
		return CommandPlan{}, err
	}
	if err := p.validateScriptStdin(); err != nil {
		return CommandPlan{}, err
	}
	return p, nil
}

func validateCommandPlanHeader(spec CommandPlanSpec) error {
	switch {
	case !spec.Kind.IsValid():
		return domi18n.WrapSentinel(ErrInvalidCommandPlan, ErrInvalidPlanKind)
	case !spec.Profile.IsValid():
		return domi18n.WrapSentinel(ErrInvalidCommandPlan, ErrInvalidLaunchProfile)
	case spec.Kind == PlanKindScript && (spec.Profile.Interpreter() == InterpreterServer || spec.Profile.Interpreter() == InterpreterCmd):
		return domi18n.EF(ErrUnsupportedExecutionCombination, domi18n.KeyExecutionScriptInterpreter)
	case spec.Kind == PlanKindScript && spec.PTY:
		return domi18n.EF(ErrUnsupportedExecutionCombination, domi18n.KeyExecutionScriptPTYForbidden)
	}
	if wd, ok := spec.WorkDir.Get(); ok && !wd.IsValid() {
		return domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "work_dir"))
	}
	if d, ok := spec.Timeout.Get(); ok && !d.IsPositive() {
		return domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "timeout"))
	}
	return nil
}

func validateCommandPayload(kind PlanKind, cmd string, rawArgv []string) ([]string, error) {
	if kind == PlanKindScript {
		return validateScriptPayload(cmd, rawArgv)
	}
	hasCmd, hasArgv := cmd != "", len(rawArgv) > 0
	if hasCmd == hasArgv {
		return nil, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonOneOfRequired, domi18n.Str("options", "command, argv"))
	}
	if hasCmd {
		if err := validateCommandText(cmd); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if rawArgv[0] == "" {
		return nil, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "argv[0]"))
	}
	return cloneAndValidateArgv(rawArgv)
}

func validateScriptPayload(script string, rawArgv []string) ([]string, error) {
	if script == "" {
		return nil, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "command"))
	}
	if err := validateCommandText(script); err != nil {
		return nil, err
	}
	if len(rawArgv) == 0 {
		return nil, nil
	}
	return cloneAndValidateArgv(rawArgv)
}

func validateCommandText(cmd string) error {
	if len(cmd) > maxCommandBytes || hasForbiddenCommandText(cmd) {
		return domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonInvalidTextChars, domi18n.Str("field", "command"))
	}
	return nil
}

func cloneAndValidateArgv(rawArgv []string) ([]string, error) {
	if len(rawArgv) > maxArgvCount {
		return nil, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "argv"), domi18n.Int("count", len(rawArgv)), domi18n.Int("limit", maxArgvCount))
	}
	out := make([]string, len(rawArgv))
	for i, arg := range rawArgv {
		if len(arg) > maxArgBytes || hasForbiddenCommandText(arg) {
			return nil, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "argv"), domi18n.Int("index", i))
		}
		out[i] = arg
	}
	return out, nil
}

func canonicalizeEnvMap(raw map[string]string) ([]envEntry, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxEnvCount {
		return nil, domi18n.EF(ErrInvalidEnvVar, domi18n.KeyCommonCountLimit, domi18n.Str("kind", "env"), domi18n.Int("count", len(raw)), domi18n.Int("limit", maxEnvCount))
	}
	out := make([]envEntry, 0, len(raw))
	for _, k := range slices.Sorted(maps.Keys(raw)) {
		v := raw[k]
		if !isValidEnvKey(k) {
			return nil, domi18n.EF(ErrInvalidEnvVar, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "env"), domi18n.BoundStr("value", k))
		}
		if len(v) > maxEnvValBytes || hasForbiddenStrictText(v) {
			return nil, domi18n.EF(ErrInvalidEnvVar, domi18n.KeyCommonInvalidTextChars, domi18n.BoundStr("field", k))
		}
		out = append(out, envEntry{key: k, value: v})
	}
	return out, nil
}

func resolveMaxOutputBytes(opt algebraic.Option[uint64]) (uint64, error) {
	v, ok := opt.Get()
	if !ok {
		return DefaultMaxOutputBytes, nil
	}
	if v == 0 || v > MaxAllowedOutputBytes {
		return 0, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonFieldRange, domi18n.Str("field", "max_output_bytes"), domi18n.Uint64("value", v), domi18n.Int("min", 1), domi18n.Uint64("max", MaxAllowedOutputBytes))
	}
	return v, nil
}

// IsValid 报告 CommandPlan 是否经构造器合法初始化。
func (p CommandPlan) IsValid() bool {
	payloadOK := pickIf(p.kind == PlanKindScript, p.command != "", (p.command != "") != (len(p.argv) > 0))
	return p.valid && p.kind.IsValid() && p.profile.IsValid() && p.maxOutputBytes > 0 && payloadOK
}

// IsZero 报告 CommandPlan 是否为无效零值。
func (p CommandPlan) IsZero() bool { return !p.IsValid() }

// Kind 返回计划操作类型。
func (p CommandPlan) Kind() PlanKind { return pickIf(p.IsValid(), p.kind, PlanKindInvalid) }

// Profile 返回启动配置副本。
func (p CommandPlan) Profile() LaunchProfile { return p.profile }

// Command 返回原始命令或脚本文本（argv 模式下为空串）。
func (p CommandPlan) Command() string { return p.command }

// Argv 返回参数向量的防御性拷贝（纯 command 模式或无位置参数脚本返回 nil）。
func (p CommandPlan) Argv() []string { return slices.Clone(p.argv) }

// WorkDir 返回可选远端 POSIX 工作目录。
func (p CommandPlan) WorkDir() algebraic.Option[pathalg.RemotePath] { return p.workDir }

// Timeout 返回可选执行超时（algebraic.Duration）。
func (p CommandPlan) Timeout() algebraic.Option[algebraic.Duration] { return p.timeout }

// MaxOutputBytes 返回输出字节上限；无效零值返回 0。
func (p CommandPlan) MaxOutputBytes() uint64 { return p.maxOutputBytes }

// PTY 报告是否请求分配伪终端。
func (p CommandPlan) PTY() bool { return p.valid && p.pty }

// Env 返回环境变量映射的全新拷贝，隔离外部修改。
func (p CommandPlan) Env() map[string]string {
	if !p.IsValid() || len(p.env) == 0 {
		return nil
	}
	out := make(map[string]string, len(p.env))
	for _, kv := range p.env {
		out[kv.key] = kv.value
	}
	return out
}

// EnvValue 按键二分查找单个环境变量值；无效计划或键不存在返回 ("", false)。
func (p CommandPlan) EnvValue(key string) (string, bool) {
	if !p.IsValid() || len(p.env) == 0 {
		return "", false
	}
	idx, ok := slices.BinarySearchFunc(p.env, key, func(item envEntry, target string) int {
		return cmp.Compare(item.key, target)
	})
	if !ok {
		return "", false
	}
	return p.env[idx].value, true
}

// RedactedSummary 返回单行脱敏展示摘要（绝不暴露环境变量值与内联凭据）。
func (p CommandPlan) RedactedSummary() string { return redactCommandSummary(p) }

// WriteCanonical 以零反射、长度前缀与域分离方式将 CommandPlan 全字段写入 w（受 digestcover 校验）。
func (p CommandPlan) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !p.valid || !p.IsValid() {
		return ErrInvalidCommandPlan
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(commandPlanDomainTag)
	enc.writeUint8(uint8(p.kind))
	if enc.err == nil {
		enc.fail(p.profile.WriteCanonical(w))
	}
	enc.writeString(p.command)
	enc.writeStrings(p.argv)
	if wd, ok := p.workDir.Get(); ok {
		enc.writeUint8(1)
		enc.writeString(wd.String())
	} else {
		enc.writeUint8(0)
	}
	enc.writeUint64(uint64(len(p.env)))
	for _, kv := range p.env {
		enc.writeString(kv.key)
		enc.writeString(kv.value)
	}
	if d, ok := p.timeout.Get(); ok {
		enc.writeUint8(1)
		enc.writeInt64(int64(d.Std()))
	} else {
		enc.writeUint8(0)
	}
	enc.writeUint64(p.maxOutputBytes)
	enc.writeBool(p.pty)
	return enc.err
}

// Digest 计算并返回 CommandPlan 的确定性 SHA-256 规范摘要（直接兼容 security.OperationBinding）。
func (p CommandPlan) Digest() (security.Digest, error) { return digestCanonical(p.WriteCanonical) }

// CanonicalJSON 使用 Go 1.27 encoding/json/v2 Deterministic(true) 编码确定性 JSON。
func (p CommandPlan) CanonicalJSON() ([]byte, error) {
	if !p.IsValid() {
		return nil, ErrInvalidCommandPlan
	}
	return jsonv2.Marshal(p, jsonv2.Deterministic(true))
}

// Equal 严格比对两个 CommandPlan 是否均有效且全部字段完全一致（无效零值永不相等）。
func (p CommandPlan) Equal(other CommandPlan) bool {
	if !p.IsValid() || !other.IsValid() {
		return false
	}
	wdA, okA := p.workDir.Get()
	wdB, okB := other.workDir.Get()
	toA, tokA := p.timeout.Get()
	toB, tokB := other.timeout.Get()
	return p.kind == other.kind && p.profile.Equal(other.profile) &&
		p.command == other.command && slices.Equal(p.argv, other.argv) &&
		okA == okB && (!okA || wdA.Equal(wdB)) &&
		slices.Equal(p.env, other.env) &&
		tokA == tokB && (!tokA || toA.Equal(toB)) &&
		p.maxOutputBytes == other.maxOutputBytes && p.pty == other.pty
}

type commandPlanWire struct {
	Kind           algebraic.Option[PlanKind]           `json:"kind"`
	Profile        algebraic.Option[LaunchProfile]      `json:"profile"`
	Command        string                               `json:"command,omitzero"`
	Argv           []string                             `json:"argv,omitzero"`
	WorkDir        algebraic.Option[pathalg.RemotePath] `json:"work_dir,omitzero"`
	Env            map[string]string                    `json:"env,omitzero"`
	Timeout        algebraic.Option[algebraic.Duration] `json:"timeout,omitzero"`
	MaxOutputBytes algebraic.Option[uint64]             `json:"max_output_bytes"`
	PTY            bool                                 `json:"pty,omitzero"`
}

// MarshalJSONTo 实现 encoding/json/v2.MarshalerTo（值接收者）；对零值失败关闭。
func (p CommandPlan) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !p.IsValid() {
		return ErrInvalidCommandPlan
	}
	return jsonv2.MarshalEncode(enc, commandPlanWire{
		Kind: algebraic.Some(p.kind), Profile: algebraic.Some(p.profile),
		Command: p.command, Argv: p.argv, WorkDir: p.workDir, Env: p.Env(),
		Timeout: p.timeout, MaxOutputBytes: algebraic.Some(p.maxOutputBytes), PTY: p.pty,
	})
}

// UnmarshalJSONFrom 实现 encoding/json/v2.UnmarshalerFrom；对 JSON null、缺失必需字段或非法值失败关闭。
func (p *CommandPlan) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalJSONWithNullReject(p, dec, ErrInvalidCommandPlan, func(w commandPlanWire) (CommandPlan, error) {
		kind, okK := w.Kind.Get()
		profile, okP := w.Profile.Get()
		if !okK || !okP || w.MaxOutputBytes.IsNone() {
			return CommandPlan{}, domi18n.EF(ErrInvalidCommandPlan, domi18n.KeyCommonJSONMissingField, domi18n.Str("field", "kind/profile/max_output_bytes"))
		}
		return NewCommandPlan(CommandPlanSpec{
			Kind: kind, Profile: profile, Command: w.Command, Argv: w.Argv,
			WorkDir: w.WorkDir, Env: w.Env, Timeout: w.Timeout,
			MaxOutputBytes: w.MaxOutputBytes, PTY: w.PTY,
		})
	})
}
