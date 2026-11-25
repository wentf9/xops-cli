package playbook

import (
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
)

// StepActionKind 标识 Playbook 判别式步骤动作类别（RFC §4.2）；零值 StepActionKindInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type StepActionKind uint8

const (
	StepActionKindInvalid  StepActionKind = iota // 无效动作类别（零值失败关闭）
	StepActionKindShell                          // 远端 Shell 命令（*StepShell）
	StepActionKindScript                         // 本地只读脚本投递执行（*StepScript）
	StepActionKindCopy                           // 本地只读文件复制至远端（*StepCopy）
	StepActionKindTemplate                       // 本地只读模板渲染并落盘至远端（*StepTemplate）
	StepActionKindEnsure                         // 幂等探针+收敛动作组合（*StepEnsure，严禁嵌套）
)

// ParseStepActionKind 严格解析规范小写动作类别（shell/script/copy/template/ensure）。
func ParseStepActionKind(raw string) (StepActionKind, error) {
	return parseEnumByName(raw, StepActionKindShell, StepActionKindEnsure, StepActionKindInvalid, StepActionKind.String, ErrInvalidStepAction)
}

func (k StepActionKind) IsValid() bool { return k >= StepActionKindShell && k <= StepActionKindEnsure }
func (k StepActionKind) IsZero() bool  { return k == StepActionKindInvalid }
func (k StepActionKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "shell", "script", "copy", "template", "ensure")
}
func (k StepActionKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidStepAction)
}
func (k StepActionKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *StepActionKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, StepActionKindInvalid, text, ParseStepActionKind)
}

type sealedStepActionMixin struct{}

func (*sealedStepActionMixin) sealedStepAction() {}

// StepAction 是 Playbook 步骤动作的封闭代数和类型（RFC §3.6 / §4.2）：
// 仅含五个具体不可变指针变体 *StepShell、*StepScript、*StepCopy、*StepTemplate 与 *StepEnsure。
//
//xops:failclosed
type StepAction interface {
	sealedStepAction()
	Kind() StepActionKind
	IsValid() bool
}

// 5 类封闭步骤动作的显式入参规格。
type (
	StepShellSpec struct {
		Command string
		Profile algebraic.Option[execution.LaunchProfile]
		WorkDir algebraic.Option[pathalg.RemotePath]
		Env     map[string]string
		Timeout algebraic.Option[algebraic.Duration]
	}
	StepScriptSpec struct {
		Source        pathalg.LocalSourcePath
		SymlinkPolicy pathalg.SymlinkPolicy
		Args          []string
		Profile       algebraic.Option[execution.LaunchProfile]
		WorkDir       algebraic.Option[pathalg.RemotePath]
		Env           map[string]string
		Timeout       algebraic.Option[algebraic.Duration]
	}
	StepCopySpec struct {
		Source        pathalg.LocalSourcePath
		SymlinkPolicy pathalg.SymlinkPolicy
		Dest          pathalg.RemotePath
		Mode          algebraic.Option[FileMode]
		Overwrite     bool
		Atomic        bool
	}
	StepTemplateSpec struct {
		Source        pathalg.LocalSourcePath
		SymlinkPolicy pathalg.SymlinkPolicy
		Dest          pathalg.RemotePath
		Vars          map[string]string
		Mode          algebraic.Option[FileMode]
		Overwrite     bool
		Atomic        bool
	}
	StepEnsureSpec struct {
		Check      StepAction
		Action     StepAction
		MaxRetries uint8
	}
)

// 5 类封闭步骤动作不可变结构体定义（均全私有字段、零值失败关闭并经 //xops:canonicalhash 校验全字段覆盖）。
type (
	// StepShell 表示远端 Shell 命令执行步骤。
	//
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	StepShell struct {
		sealedStepActionMixin //xops:hash-exclude:零字节封闭和类型混入标记
		command               string
		profile               algebraic.Option[execution.LaunchProfile]
		workDir               algebraic.Option[pathalg.RemotePath]
		env                   []kvEntry
		timeout               algebraic.Option[algebraic.Duration]
		valid                 bool
	}
	// StepScript 表示本地只读脚本经 OperatorReadFS 读取后投递至远端执行的步骤。
	//
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	StepScript struct {
		sealedStepActionMixin //xops:hash-exclude:零字节封闭和类型混入标记
		source                pathalg.LocalSourcePath
		symlinkPolicy         pathalg.SymlinkPolicy
		args                  []string
		profile               algebraic.Option[execution.LaunchProfile]
		workDir               algebraic.Option[pathalg.RemotePath]
		env                   []kvEntry
		timeout               algebraic.Option[algebraic.Duration]
		valid                 bool
	}
	// StepCopy 表示本地只读文件上传至远端 POSIX 路径的步骤。
	//
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	StepCopy struct {
		sealedStepActionMixin //xops:hash-exclude:零字节封闭和类型混入标记
		source                pathalg.LocalSourcePath
		symlinkPolicy         pathalg.SymlinkPolicy
		dest                  pathalg.RemotePath
		mode                  algebraic.Option[FileMode]
		overwrite             bool
		atomic                bool
		valid                 bool
	}
	// StepTemplate 表示本地模板经变量渲染并原子落盘至远端 POSIX 路径的步骤。
	//
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	StepTemplate struct {
		sealedStepActionMixin //xops:hash-exclude:零字节封闭和类型混入标记
		source                pathalg.LocalSourcePath
		symlinkPolicy         pathalg.SymlinkPolicy
		dest                  pathalg.RemotePath
		vars                  []kvEntry
		mode                  algebraic.Option[FileMode]
		overwrite             bool
		atomic                bool
		valid                 bool
	}
	// StepEnsure 表示只读探针（Check）与非嵌套收敛动作（Action）组合，严禁嵌套 *StepEnsure。
	//
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	StepEnsure struct {
		sealedStepActionMixin //xops:hash-exclude:零字节封闭和类型混入标记
		check                 StepAction
		action                StepAction
		maxRetries            uint8
		valid                 bool
	}
)

// 5 类封闭步骤动作变体的零值/nil 安全只读访问器（经 val() 值拷贝守卫 typed-nil 指针，切片与映射均返回防御性拷贝）。
func (s *StepShell) IsValid() bool        { return s != nil && s.valid && s.command != "" }
func (s *StepShell) Kind() StepActionKind { return ak(s.IsValid(), StepActionKindShell) }
func (s *StepShell) val() StepShell {
	if !s.IsValid() {
		return StepShell{}
	}
	return *s
}
func (s *StepShell) Command() string                                    { return s.val().command }
func (s *StepShell) Profile() algebraic.Option[execution.LaunchProfile] { return s.val().profile }
func (s *StepShell) WorkDir() algebraic.Option[pathalg.RemotePath]      { return s.val().workDir }
func (s *StepShell) Env() map[string]string                             { return kvSliceToMap(s.val().env) }
func (s *StepShell) Timeout() algebraic.Option[algebraic.Duration]      { return s.val().timeout }

func (s *StepScript) IsValid() bool {
	return s != nil && s.valid && s.source.IsValid() && s.symlinkPolicy.IsValid()
}
func (s *StepScript) Kind() StepActionKind { return ak(s.IsValid(), StepActionKindScript) }
func (s *StepScript) val() StepScript {
	if !s.IsValid() {
		return StepScript{}
	}
	return *s
}
func (s *StepScript) Source() pathalg.LocalSourcePath                    { return s.val().source }
func (s *StepScript) SymlinkPolicy() pathalg.SymlinkPolicy               { return s.val().symlinkPolicy }
func (s *StepScript) Args() []string                                     { return slices.Clone(s.val().args) }
func (s *StepScript) Profile() algebraic.Option[execution.LaunchProfile] { return s.val().profile }
func (s *StepScript) WorkDir() algebraic.Option[pathalg.RemotePath]      { return s.val().workDir }
func (s *StepScript) Env() map[string]string                             { return kvSliceToMap(s.val().env) }
func (s *StepScript) Timeout() algebraic.Option[algebraic.Duration]      { return s.val().timeout }

func (s *StepCopy) IsValid() bool {
	return s != nil && s.valid && s.source.IsValid() && s.symlinkPolicy.IsValid() && s.dest.IsValid()
}
func (s *StepCopy) Kind() StepActionKind { return ak(s.IsValid(), StepActionKindCopy) }
func (s *StepCopy) val() StepCopy {
	if !s.IsValid() {
		return StepCopy{}
	}
	return *s
}
func (s *StepCopy) Source() pathalg.LocalSourcePath      { return s.val().source }
func (s *StepCopy) SymlinkPolicy() pathalg.SymlinkPolicy { return s.val().symlinkPolicy }
func (s *StepCopy) Dest() pathalg.RemotePath             { return s.val().dest }
func (s *StepCopy) Mode() algebraic.Option[FileMode]     { return s.val().mode }
func (s *StepCopy) Overwrite() bool                      { return s.IsValid() && s.overwrite }
func (s *StepCopy) Atomic() bool                         { return s.IsValid() && s.atomic }

func (s *StepTemplate) IsValid() bool {
	return s != nil && s.valid && s.source.IsValid() && s.symlinkPolicy.IsValid() && s.dest.IsValid()
}
func (s *StepTemplate) Kind() StepActionKind { return ak(s.IsValid(), StepActionKindTemplate) }
func (s *StepTemplate) val() StepTemplate {
	if !s.IsValid() {
		return StepTemplate{}
	}
	return *s
}
func (s *StepTemplate) Source() pathalg.LocalSourcePath      { return s.val().source }
func (s *StepTemplate) SymlinkPolicy() pathalg.SymlinkPolicy { return s.val().symlinkPolicy }
func (s *StepTemplate) Dest() pathalg.RemotePath             { return s.val().dest }
func (s *StepTemplate) Vars() map[string]string              { return kvSliceToMap(s.val().vars) }
func (s *StepTemplate) Mode() algebraic.Option[FileMode]     { return s.val().mode }
func (s *StepTemplate) Overwrite() bool                      { return s.IsValid() && s.overwrite }
func (s *StepTemplate) Atomic() bool                         { return s.IsValid() && s.atomic }

func (s *StepEnsure) IsValid() bool {
	return s != nil && s.valid && s.check != nil && s.check.IsValid() && s.action != nil && s.action.IsValid() && s.maxRetries <= MaxEnsureRetries
}
func (s *StepEnsure) Kind() StepActionKind { return ak(s.IsValid(), StepActionKindEnsure) }
func (s *StepEnsure) val() StepEnsure {
	if !s.IsValid() {
		return StepEnsure{}
	}
	return *s
}
func (s *StepEnsure) Check() StepAction  { return mustCloneValidAction(s.val().check) }
func (s *StepEnsure) Action() StepAction { return mustCloneValidAction(s.val().action) }
func (s *StepEnsure) MaxRetries() uint8  { return s.val().maxRetries }

func ak(ok bool, k StepActionKind) StepActionKind { return pickIf(ok, k, StepActionKindInvalid) }
