package playbook

import (
	"fmt"
	"time"
)

// Playbook 是编排文件的顶层结构
type Playbook struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Targets     Targets           `yaml:"targets"`
	Settings    Settings          `yaml:"settings,omitempty"`
	Vars        map[string]string `yaml:"vars,omitempty"`
	Steps       []Step            `yaml:"steps"`
}

// Targets 定义目标主机选择（三种方式任选其一）
type Targets struct {
	Tags  []string `yaml:"tags,omitempty"`
	Nodes []string `yaml:"nodes,omitempty"`
	Hosts []string `yaml:"hosts,omitempty"`
}

// Settings 定义全局执行配置
type Settings struct {
	// Concurrency 控制最大并发主机数，0 表示使用默认值 1
	Concurrency uint     `yaml:"concurrency,omitempty"`
	Sudo        bool     `yaml:"sudo,omitempty"`
	OnError     OnError  `yaml:"on_error,omitempty"`
	Timeout     Duration `yaml:"timeout,omitempty"`
}

// OnError 定义步骤失败时的处理策略
type OnError string

const (
	// OnErrorContinue 忽略当前主机的错误，继续执行该主机的后续步骤
	OnErrorContinue OnError = "continue"
	// OnErrorStop 当前主机停止后续步骤，其他主机不受影响（默认）
	OnErrorStop OnError = "stop"
	// OnErrorAbortAll 立即取消所有主机的执行
	OnErrorAbortAll OnError = "abort_all"
)

// Step 定义单个执行步骤
// 每个 Step 必须恰好指定 shell/script/copy/ensure/template 之一
type Step struct {
	Name     string      `yaml:"name"`
	Shell    string      `yaml:"shell,omitempty"`
	Script   string      `yaml:"script,omitempty"`
	Copy     *CopySpec   `yaml:"copy,omitempty"`
	Ensure   *EnsureSpec `yaml:"ensure,omitempty"`
	Template *CopySpec   `yaml:"template,omitempty"`

	// Sudo 步骤级别的提权覆盖；nil 表示继承全局 Settings.Sudo
	Sudo *bool `yaml:"sudo,omitempty"`

	// Retries 失败重试次数，默认 0（不重试）
	Retries int `yaml:"retries,omitempty"`
	// RetryDelay 重试间隔，默认 1s
	RetryDelay Duration `yaml:"retry_delay,omitempty"`
	// IgnoreError 即使步骤失败也继续，优先级高于 Settings.OnError
	IgnoreError bool `yaml:"ignore_error,omitempty"`
}

// CopySpec 定义文件传输或模板渲染规格
type CopySpec struct {
	Src  string `yaml:"src"`
	Dest string `yaml:"dest"`
	// Mode 文件权限，如 "0644"，为空则保持源文件权限
	Mode string `yaml:"mode,omitempty"`
}

// EnsureSpec 定义幂等性检查规格（状态收敛核心）
type EnsureSpec struct {
	// Check 检查命令，退出码 0 表示已满足期望状态
	Check string `yaml:"check"`
	// Action 当 Check 未通过时执行的修复命令
	Action string `yaml:"action"`
}

// Duration 是 time.Duration 的 YAML 友好包装，支持 "30s", "5m", "1h" 等格式
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if raw == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	if d.Duration == 0 {
		return "", nil
	}
	return d.String(), nil
}
