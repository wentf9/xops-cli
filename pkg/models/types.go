package models

import (
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
)

// OTPConfig 定义身份的显式 OTP 自动化配置（支持托管 TOTP 种子或外部获取命令）。
type OTPConfig struct {
	TOTPSecretRef *credential.Ref `yaml:"totp_secret_ref,omitempty" json:"totp_secret_ref,omitempty"`
	Command       string          `yaml:"command,omitempty" json:"command,omitempty"`
	Args          []string        `yaml:"args,omitempty" json:"args,omitempty"`
	Timeout       time.Duration   `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	PromptPattern string          `yaml:"prompt_pattern,omitempty" json:"prompt_pattern,omitempty"`
}

// Clone returns a deep copy of OTPConfig.
func (c *OTPConfig) Clone() *OTPConfig {
	if c == nil {
		return nil
	}
	cloned := *c
	cloned.TOTPSecretRef = c.TOTPSecretRef.Clone()
	cloned.Args = slices.Clone(c.Args)
	return &cloned
}

// Equal reports whether two OTPConfig values are structurally equal.
func (c *OTPConfig) Equal(other *OTPConfig) bool {
	if c == other {
		return true
	}
	if c == nil || other == nil {
		return false
	}
	if c.Command != other.Command || c.Timeout != other.Timeout || c.PromptPattern != other.PromptPattern {
		return false
	}
	if !slices.Equal(c.Args, other.Args) {
		return false
	}
	if (c.TOTPSecretRef == nil) != (other.TOTPSecretRef == nil) {
		return false
	}
	if c.TOTPSecretRef != nil && *c.TOTPSecretRef != *other.TOTPSecretRef {
		return false
	}
	return true
}

// ChallengeAnswerSource 定义 keyboard-interactive 规则的答案来源类型。
type ChallengeAnswerSource string

const (
	ChallengeSourceOTP           ChallengeAnswerSource = "otp"
	ChallengeSourceLoginPassword ChallengeAnswerSource = "login_password"
	ChallengeSourceSecret        ChallengeAnswerSource = "secret"
	ChallengeSourceCommand       ChallengeAnswerSource = "command"
)

// ChallengeRule 定义单条 keyboard-interactive 问题正则匹配与自动应答规则。
type ChallengeRule struct {
	Name               string                `yaml:"name,omitempty" json:"name,omitempty"`
	PromptPattern      string                `yaml:"prompt_pattern" json:"prompt_pattern"`
	InstructionPattern string                `yaml:"instruction_pattern,omitempty" json:"instruction_pattern,omitempty"`
	Source             ChallengeAnswerSource `yaml:"source" json:"source"`
	SecretRef          *credential.Ref       `yaml:"secret_ref,omitempty" json:"secret_ref,omitempty"`
	Command            string                `yaml:"command,omitempty" json:"command,omitempty"`
	Args               []string              `yaml:"args,omitempty" json:"args,omitempty"`
	Timeout            time.Duration         `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// Clone returns a deep copy of ChallengeRule.
func (r ChallengeRule) Clone() ChallengeRule {
	cloned := r
	cloned.SecretRef = r.SecretRef.Clone()
	cloned.Args = slices.Clone(r.Args)
	return cloned
}

// Equal reports whether two ChallengeRule values are structurally equal.
func (r ChallengeRule) Equal(other ChallengeRule) bool {
	if r.Name != other.Name || r.PromptPattern != other.PromptPattern ||
		r.InstructionPattern != other.InstructionPattern || r.Source != other.Source ||
		r.Command != other.Command || r.Timeout != other.Timeout {
		return false
	}
	if !slices.Equal(r.Args, other.Args) {
		return false
	}
	if (r.SecretRef == nil) != (other.SecretRef == nil) {
		return false
	}
	if r.SecretRef != nil && *r.SecretRef != *other.SecretRef {
		return false
	}
	return true
}

// KeyboardInteractiveConfig 定义 keyboard-interactive 自动应答规则集。
type KeyboardInteractiveConfig struct {
	Rules []ChallengeRule `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// Clone returns a deep copy of KeyboardInteractiveConfig.
func (k *KeyboardInteractiveConfig) Clone() *KeyboardInteractiveConfig {
	if k == nil {
		return nil
	}
	cloned := KeyboardInteractiveConfig{
		Rules: make([]ChallengeRule, len(k.Rules)),
	}
	for i, r := range k.Rules {
		cloned.Rules[i] = r.Clone()
	}
	return &cloned
}

// Equal reports whether two KeyboardInteractiveConfig values are structurally equal.
func (k *KeyboardInteractiveConfig) Equal(other *KeyboardInteractiveConfig) bool {
	if k == other {
		return true
	}
	if k == nil || other == nil {
		return false
	}
	if len(k.Rules) != len(other.Rules) {
		return false
	}
	for i := range k.Rules {
		if !k.Rules[i].Equal(other.Rules[i]) {
			return false
		}
	}
	return true
}

// Identity 定义认证信息
type Identity struct {
	User                string                     `yaml:"user"`
	KeyPath             string                     `yaml:"key_path,omitempty"`
	KeyFingerprint      string                     `yaml:"key_fingerprint,omitempty"`
	Passphrase          string                     `yaml:"passphrase,omitempty"` // 私钥密码（Schema v1）
	Password            string                     `yaml:"password,omitempty"`   // 登录密码（Schema v1）
	AuthType            string                     `yaml:"auth_type"`            // "key", "password", "agent", "auto", "otp", "keyboard-interactive"
	LoginPasswordRef    *credential.Ref            `yaml:"login_password_ref,omitempty"`
	PassphraseRef       *credential.Ref            `yaml:"passphrase_ref,omitempty"`
	OTP                 *OTPConfig                 `yaml:"otp,omitempty"`
	KeyboardInteractive *KeyboardInteractiveConfig `yaml:"keyboard_interactive,omitempty"`
}

// Clone returns a deep copy of Identity.
func (i Identity) Clone() Identity {
	cloned := i
	cloned.LoginPasswordRef = i.LoginPasswordRef.Clone()
	cloned.PassphraseRef = i.PassphraseRef.Clone()
	cloned.OTP = i.OTP.Clone()
	cloned.KeyboardInteractive = i.KeyboardInteractive.Clone()
	return cloned
}

// Equal reports whether two Identity values are structurally equal.
func (i Identity) Equal(other Identity) bool {
	if i.User != other.User || i.KeyPath != other.KeyPath || i.KeyFingerprint != other.KeyFingerprint ||
		i.Passphrase != other.Passphrase || i.Password != other.Password || i.AuthType != other.AuthType {
		return false
	}
	if (i.LoginPasswordRef == nil) != (other.LoginPasswordRef == nil) {
		return false
	}
	if i.LoginPasswordRef != nil && *i.LoginPasswordRef != *other.LoginPasswordRef {
		return false
	}
	if (i.PassphraseRef == nil) != (other.PassphraseRef == nil) {
		return false
	}
	if i.PassphraseRef != nil && *i.PassphraseRef != *other.PassphraseRef {
		return false
	}
	if !i.OTP.Equal(other.OTP) {
		return false
	}
	if !i.KeyboardInteractive.Equal(other.KeyboardInteractive) {
		return false
	}
	return true
}

// Host 定义网络连接信息
type Host struct {
	Alias   []string `yaml:"alias,omitempty"`
	Address string   `yaml:"address"` // IP 或 域名
	Port    uint16   `yaml:"port"`
}

// SudoMode 定义提权模式
type SudoMode string

const (
	SudoModeNone   SudoMode = "none"
	SudoModeSudo   SudoMode = "sudo"
	SudoModeSudoer SudoMode = "sudoer"
	SudoModeSu     SudoMode = "su"
	SudoModeRoot   SudoMode = "root"
	SudoModeAuto   SudoMode = "auto"
)

// Node 是用户操作的最小单元，聚合了 Host 和 Identity
type Node struct {
	Alias []string `yaml:"alias,omitempty"`
	Tags  []string `yaml:"tags,omitempty"` // 用于分组

	// 引用解耦
	HostRef     string `yaml:"host_ref"`
	IdentityRef string `yaml:"identity_ref"`

	// 高级网络配置
	ProxyJump string `yaml:"proxy_jump,omitempty"` // 指向另一个 Node 的 Name

	// 提权配置
	SudoMode             SudoMode        `yaml:"sudo_mode"` // 使用 SudoMode 枚举
	SuPwd                string          `yaml:"su_pwd,omitempty"`
	PrivilegePasswordRef *credential.Ref `yaml:"privilege_password_ref,omitempty"`

	// 交互式拦截配置
	PasswordPromptPattern string `yaml:"password_prompt_pattern,omitempty"` // 节点级自定义密码提示正则

	// 执行环境配置
	Execution *ssh.ExecutionConfig `yaml:"execution,omitempty" json:"execution,omitempty"`

	// OpenSSH 客户端选项配置（支持连接复用、超时、主机密钥策略、算法与认证控制等）
	SSHOptions *ssh.Options `yaml:"ssh_options,omitempty" json:"ssh_options,omitempty"`

	// OpenSSHAlias 记录运行时从 ~/.ssh/config 具体 Host 块派生该节点时的源别名（不序列化落盘）
	OpenSSHAlias string `yaml:"-" json:"-"`
}

// NodeFilter 用于批量操作时筛选节点
type NodeFilter struct {
	Names []string // 精确匹配 Name
	Tags  []string // 包含任意 Tag 即匹配
}
