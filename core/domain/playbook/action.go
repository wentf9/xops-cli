package playbook

import (
	"fmt"
	"io"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

const (
	stepShellDomainTag    = "xops.playbook.step_shell.v2"
	stepScriptDomainTag   = "xops.playbook.step_script.v2"
	stepCopyDomainTag     = "xops.playbook.step_copy.v2"
	stepTemplateDomainTag = "xops.playbook.step_template.v2"
	stepEnsureDomainTag   = "xops.playbook.step_ensure.v2"
)

// NewStepShell 校验命令文本、可选执行配置与环境变量并构造 *StepShell；
// 当显式指定 Profile 时同步委托 execution.NewCommandPlan 验证方言/引用/命令行长度等全部不变量。
func NewStepShell(spec StepShellSpec) (*StepShell, error) {
	if spec.Command == "" || len(spec.Command) > maxCommandBytes || hasForbiddenCommandText(spec.Command) || !hasVisibleText(spec.Command) {
		return nil, fmt.Errorf("%w: shell.command 不能为空、超长或含非法控制/Cf 字符", ErrInvalidStepAction)
	}
	if err := validateExecOptions(spec.Profile, spec.WorkDir, spec.Timeout, false); err != nil {
		return nil, err
	}
	env, err := canonicalizeKVMap(spec.Env, maxEnvCount, maxEnvValBytes, isValidEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStepAction, err)
	}
	if err := validateShellPlan(spec); err != nil {
		return nil, err
	}
	return &StepShell{command: spec.Command, profile: spec.Profile, workDir: spec.WorkDir, env: env, timeout: spec.Timeout, valid: true}, nil
}

// NewStepScript 校验本地源路径、软链策略、参数、可选执行配置与环境变量并构造 *StepScript；
// 当显式指定 Profile 时同步委托 execution.NewCommandPlan 与对应方言参数引用规则校验全量组合合法性。
func NewStepScript(spec StepScriptSpec) (*StepScript, error) {
	if !spec.Source.IsValid() || !spec.SymlinkPolicy.IsValid() {
		return nil, fmt.Errorf("%w: script.source 与 symlink_policy 必须有效", ErrInvalidStepAction)
	}
	if err := validateExecOptions(spec.Profile, spec.WorkDir, spec.Timeout, true); err != nil {
		return nil, err
	}
	args, err := validateArgs(spec.Args)
	if err != nil {
		return nil, err
	}
	env, err := canonicalizeKVMap(spec.Env, maxEnvCount, maxEnvValBytes, isValidEnvKey, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStepAction, err)
	}
	if err := validateScriptPlan(spec, args); err != nil {
		return nil, err
	}
	return &StepScript{source: spec.Source, symlinkPolicy: spec.SymlinkPolicy, args: args, profile: spec.Profile, workDir: spec.WorkDir, env: env, timeout: spec.Timeout, valid: true}, nil
}

// NewStepCopy 校验本地源、软链策略、远端目标与可选权限位并构造 *StepCopy。
func NewStepCopy(spec StepCopySpec) (*StepCopy, error) {
	if err := validateTransferTargets(spec.Source, spec.SymlinkPolicy, spec.Dest, spec.Mode); err != nil {
		return nil, err
	}
	return &StepCopy{source: spec.Source, symlinkPolicy: spec.SymlinkPolicy, dest: spec.Dest, mode: spec.Mode, overwrite: spec.Overwrite, atomic: spec.Atomic, valid: true}, nil
}

// NewStepTemplate 校验模板源、远端目标、模板变量与可选权限位并构造 *StepTemplate。
func NewStepTemplate(spec StepTemplateSpec) (*StepTemplate, error) {
	if err := validateTransferTargets(spec.Source, spec.SymlinkPolicy, spec.Dest, spec.Mode); err != nil {
		return nil, err
	}
	vars, err := canonicalizeKVMap(spec.Vars, maxVarsCount, maxVarValBytes, isValidVarKey, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStepAction, err)
	}
	return &StepTemplate{source: spec.Source, symlinkPolicy: spec.SymlinkPolicy, dest: spec.Dest, vars: vars, mode: spec.Mode, overwrite: spec.Overwrite, atomic: spec.Atomic, valid: true}, nil
}

// NewStepEnsure 校验 Check（仅 shell/script）与 Action（严禁嵌套 *StepEnsure）并构造 *StepEnsure。
func NewStepEnsure(spec StepEnsureSpec) (*StepEnsure, error) {
	if spec.MaxRetries > MaxEnsureRetries {
		return nil, fmt.Errorf("%w: ensure.max_retries=%d 超出上限 %d", ErrInvalidStepAction, spec.MaxRetries, MaxEnsureRetries)
	}
	check, err := validateEnsureBranch(spec.Check, true)
	if err != nil {
		return nil, err
	}
	action, err := validateEnsureBranch(spec.Action, false)
	if err != nil {
		return nil, err
	}
	return &StepEnsure{check: check, action: action, maxRetries: spec.MaxRetries, valid: true}, nil
}

func validateEnsureBranch(a StepAction, checkOnly bool) (StepAction, error) {
	if a == nil || !a.IsValid() {
		return nil, pickIf(checkOnly, ErrInvalidEnsureCheck, ErrInvalidStepAction)
	}
	switch v := a.(type) {
	case *StepShell, *StepScript:
		return mustCloneValidAction(v), nil
	case *StepCopy, *StepTemplate:
		if checkOnly {
			return nil, fmt.Errorf("%w: 不允许使用 %s 作为 ensure.check", ErrInvalidEnsureCheck, v.Kind())
		}
		return mustCloneValidAction(v), nil
	case *StepEnsure:
		return nil, ErrNestedEnsureForbidden
	default:
		return nil, ErrInvalidStepAction
	}
}

// WriteCanonical 为 5 类封闭步骤动作实现零反射长度前缀规范摘要写入（全部受 digestcover 校验）。
func (s *StepShell) WriteCanonical(w io.Writer) error {
	return writeActionWithEnc(w, s != nil && s.valid && s.IsValid(), stepShellDomainTag, func(enc *canonicalEncoder) {
		enc.writeString(s.command)
		writeCanonicalExecOptions(enc, s.profile, s.workDir, s.env, s.timeout)
	})
}
func (s *StepScript) WriteCanonical(w io.Writer) error {
	return writeActionWithEnc(w, s != nil && s.valid && s.IsValid(), stepScriptDomainTag, func(enc *canonicalEncoder) {
		enc.writeString(s.source.String())
		enc.writeUint8(uint8(s.symlinkPolicy))
		enc.writeStrings(s.args)
		writeCanonicalExecOptions(enc, s.profile, s.workDir, s.env, s.timeout)
	})
}
func (s *StepCopy) WriteCanonical(w io.Writer) error {
	return writeActionWithEnc(w, s != nil && s.valid && s.IsValid(), stepCopyDomainTag, func(enc *canonicalEncoder) {
		writeCanonicalTransferFields(enc, s.source, s.symlinkPolicy, s.dest, s.mode, s.overwrite, s.atomic)
	})
}
func (s *StepTemplate) WriteCanonical(w io.Writer) error {
	return writeActionWithEnc(w, s != nil && s.valid && s.IsValid(), stepTemplateDomainTag, func(enc *canonicalEncoder) {
		writeCanonicalTransferFields(enc, s.source, s.symlinkPolicy, s.dest, s.mode, s.overwrite, s.atomic)
		enc.writeKVs(s.vars)
	})
}
func (s *StepEnsure) WriteCanonical(w io.Writer) error {
	return writeActionWithEnc(w, s != nil && s.valid && s.IsValid(), stepEnsureDomainTag, func(enc *canonicalEncoder) {
		if enc.err == nil {
			enc.fail(writeStepActionCanonical(w, s.check))
		}
		if enc.err == nil {
			enc.fail(writeStepActionCanonical(w, s.action))
		}
		enc.writeUint8(s.maxRetries)
	})
}
func writeActionWithEnc(w io.Writer, valid bool, tag string, fn func(*canonicalEncoder)) error {
	if w == nil {
		return ErrNilWriter
	}
	if !valid {
		return ErrInvalidStepAction
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(tag)
	fn(enc)
	return enc.err
}

func writeStepActionCanonical(w io.Writer, a StepAction) error {
	if a == nil || !a.IsValid() {
		return ErrInvalidStepAction
	}
	switch v := a.(type) {
	case *StepShell:
		return v.WriteCanonical(w)
	case *StepScript:
		return v.WriteCanonical(w)
	case *StepCopy:
		return v.WriteCanonical(w)
	case *StepTemplate:
		return v.WriteCanonical(w)
	case *StepEnsure:
		return v.WriteCanonical(w)
	default:
		return ErrInvalidStepAction
	}
}

// EqualStepAction 严格比对两个 StepAction 是否均有效且全字段一致（nil 或零值恒返回 false）。
func EqualStepAction(a, b StepAction) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *StepShell:
		vb, ok := b.(*StepShell)
		return ok && vb.IsValid() && va.command == vb.command && equalExecOpts(va.profile, vb.profile, va.workDir, vb.workDir, va.env, vb.env, va.timeout, vb.timeout)
	case *StepScript:
		vb, ok := b.(*StepScript)
		return ok && vb.IsValid() && va.source.Equal(vb.source) && va.symlinkPolicy == vb.symlinkPolicy &&
			slices.Equal(va.args, vb.args) && equalExecOpts(va.profile, vb.profile, va.workDir, vb.workDir, va.env, vb.env, va.timeout, vb.timeout)
	case *StepCopy:
		vb, ok := b.(*StepCopy)
		return ok && vb.IsValid() && equalTransferOpts(va.source, vb.source, va.symlinkPolicy, vb.symlinkPolicy, va.dest, vb.dest, va.mode, vb.mode, va.overwrite, vb.overwrite, va.atomic, vb.atomic)
	case *StepTemplate:
		vb, ok := b.(*StepTemplate)
		return ok && vb.IsValid() && slices.Equal(va.vars, vb.vars) &&
			equalTransferOpts(va.source, vb.source, va.symlinkPolicy, vb.symlinkPolicy, va.dest, vb.dest, va.mode, vb.mode, va.overwrite, vb.overwrite, va.atomic, vb.atomic)
	case *StepEnsure:
		vb, ok := b.(*StepEnsure)
		return ok && vb.IsValid() && va.maxRetries == vb.maxRetries && EqualStepAction(va.check, vb.check) && EqualStepAction(va.action, vb.action)
	default:
		return false
	}
}

func equalExecOpts(pA, pB algebraic.Option[execution.LaunchProfile], wA, wB algebraic.Option[pathalg.RemotePath], eA, eB []kvEntry, tA, tB algebraic.Option[algebraic.Duration]) bool {
	return equalOptionFunc(pA, pB, execution.LaunchProfile.Equal) && equalOptionFunc(wA, wB, pathalg.RemotePath.Equal) &&
		slices.Equal(eA, eB) && equalOptionFunc(tA, tB, algebraic.Duration.Equal)
}

func equalTransferOpts(sA, sB pathalg.LocalSourcePath, spA, spB pathalg.SymlinkPolicy, dA, dB pathalg.RemotePath, mA, mB algebraic.Option[FileMode], ovA, ovB, atA, atB bool) bool {
	return sA.Equal(sB) && spA == spB && dA.Equal(dB) && equalOptionFunc(mA, mB, FileMode.Equal) && ovA == ovB && atA == atB
}

func cloneStepAction(a StepAction) (StepAction, error) {
	if a == nil || !a.IsValid() {
		return nil, ErrInvalidStepAction
	}
	return mustCloneValidAction(a), nil
}

func mustCloneValidAction(a StepAction) StepAction {
	switch v := a.(type) {
	case *StepShell:
		return &StepShell{command: v.command, profile: v.profile, workDir: v.workDir, env: slices.Clone(v.env), timeout: v.timeout, valid: true}
	case *StepScript:
		return &StepScript{source: v.source, symlinkPolicy: v.symlinkPolicy, args: slices.Clone(v.args), profile: v.profile, workDir: v.workDir, env: slices.Clone(v.env), timeout: v.timeout, valid: true}
	case *StepCopy:
		return &StepCopy{source: v.source, symlinkPolicy: v.symlinkPolicy, dest: v.dest, mode: v.mode, overwrite: v.overwrite, atomic: v.atomic, valid: true}
	case *StepTemplate:
		return &StepTemplate{source: v.source, symlinkPolicy: v.symlinkPolicy, dest: v.dest, vars: slices.Clone(v.vars), mode: v.mode, overwrite: v.overwrite, atomic: v.atomic, valid: true}
	case *StepEnsure:
		return &StepEnsure{check: mustCloneValidAction(v.check), action: mustCloneValidAction(v.action), maxRetries: v.maxRetries, valid: true}
	default:
		return nil
	}
}

func validateExecOptions(prof algebraic.Option[execution.LaunchProfile], wd algebraic.Option[pathalg.RemotePath], to algebraic.Option[algebraic.Duration], isScript bool) error {
	if p, ok := prof.Get(); ok {
		if !p.IsValid() {
			return fmt.Errorf("%w: profile 无效", ErrInvalidStepAction)
		}
		if isScript && (p.Interpreter() == execution.InterpreterServer || p.Interpreter() == execution.InterpreterCmd) {
			return fmt.Errorf("%w: script 步骤仅支持 POSIX 或 PowerShell 显式解释器", ErrInvalidStepAction)
		}
	}
	if w, ok := wd.Get(); ok && !w.IsValid() {
		return fmt.Errorf("%w: work_dir 无效", ErrInvalidStepAction)
	}
	if d, ok := to.Get(); ok && !d.IsPositive() {
		return fmt.Errorf("%w: timeout 必须为正时长", ErrInvalidStepAction)
	}
	return nil
}

func validateShellPlan(spec StepShellSpec) error {
	p, ok := spec.Profile.Get()
	if !ok {
		return nil
	}
	if _, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindCommand, Profile: p, Command: spec.Command, WorkDir: spec.WorkDir, Env: spec.Env, Timeout: spec.Timeout,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStepAction, err)
	}
	return nil
}

func validateScriptPlan(spec StepScriptSpec, args []string) error {
	p, ok := spec.Profile.Get()
	if !ok {
		return nil
	}
	if _, err := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind: execution.PlanKindScript, Profile: p, Command: "true", WorkDir: spec.WorkDir, Env: spec.Env, Timeout: spec.Timeout,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidStepAction, err)
	}
	return validateScriptArgsForProfile(p, args)
}

func validateScriptArgsForProfile(p execution.LaunchProfile, args []string) error {
	var quote func(string) (string, error)
	switch {
	case p.Interpreter().IsPOSIXShell():
		quote = execution.QuotePOSIX
	case p.Interpreter().IsPowerShell():
		quote = execution.QuotePowerShell
	default:
		return fmt.Errorf("%w: script 步骤仅支持 POSIX 或 PowerShell 显式解释器", ErrInvalidStepAction)
	}
	for i, arg := range args {
		if _, err := quote(arg); err != nil {
			return fmt.Errorf("%w: args[%d] 不符合解释器引用不变量: %w", ErrInvalidStepAction, i, err)
		}
	}
	return nil
}

func validateArgs(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxArgsCount {
		return nil, fmt.Errorf("%w: args 数量 %d 超出上限 %d", ErrInvalidStepAction, len(raw), maxArgsCount)
	}
	out := make([]string, len(raw))
	for i, arg := range raw {
		if len(arg) > maxArgBytes || hasForbiddenStrictText(arg) {
			return nil, fmt.Errorf("%w: args[%d] 超长或包含非法字符", ErrInvalidStepAction, i)
		}
		out[i] = arg
	}
	return out, nil
}

func validateTransferTargets(src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, dest pathalg.RemotePath, mode algebraic.Option[FileMode]) error {
	if !src.IsValid() || !policy.IsValid() || !dest.IsValid() {
		return fmt.Errorf("%w: source/symlink_policy/dest 必须均有效", ErrInvalidStepAction)
	}
	if m, ok := mode.Get(); ok && !m.IsValid() {
		return fmt.Errorf("%w: %w", ErrInvalidStepAction, ErrInvalidFileMode)
	}
	return nil
}

func writeCanonicalExecOptions(enc *canonicalEncoder, prof algebraic.Option[execution.LaunchProfile], wd algebraic.Option[pathalg.RemotePath], env []kvEntry, to algebraic.Option[algebraic.Duration]) {
	if p, ok := prof.Get(); ok {
		enc.writeUint8(1)
		if enc.err == nil {
			enc.fail(p.WriteCanonical(enc.w))
		}
	} else {
		enc.writeUint8(0)
	}
	w, hasW := wd.Get()
	enc.writeBool(hasW)
	if hasW {
		enc.writeString(w.String())
	}
	enc.writeKVs(env)
	d, hasD := to.Get()
	enc.writeBool(hasD)
	if hasD {
		enc.writeInt64(int64(d.Std()))
	}
}

func writeCanonicalTransferFields(enc *canonicalEncoder, src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy, dest pathalg.RemotePath, mode algebraic.Option[FileMode], overwrite, atomic bool) {
	enc.writeString(src.String())
	enc.writeUint8(uint8(policy))
	enc.writeString(dest.String())
	m, hasM := mode.Get()
	enc.writeBool(hasM)
	if hasM {
		enc.writeUint32(m.bits)
	}
	enc.writeBool(overwrite)
	enc.writeBool(atomic)
}
