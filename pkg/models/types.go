package models

// Identity 定义认证信息
type Identity struct {
	User       string `yaml:"user"`
	KeyPath    string `yaml:"key_path,omitempty"`
	Passphrase string `yaml:"passphrase,omitempty"` // 私钥密码
	Password   string `yaml:"password,omitempty"`   // 登录密码
	AuthType   string `yaml:"auth_type"`            // "key", "password", "agent"
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
	SudoMode SudoMode `yaml:"sudo_mode"` // 使用 SudoMode 枚举
	SuPwd    string   `yaml:"su_pwd,omitempty"`

	// 交互式拦截配置
	PasswordPromptPattern string `yaml:"password_prompt_pattern,omitempty"` // 节点级自定义密码提示正则
}

// NodeFilter 用于批量操作时筛选节点
type NodeFilter struct {
	Names []string // 精确匹配 Name
	Tags  []string // 包含任意 Tag 即匹配
}
