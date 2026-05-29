package ssh

// SudoMode 定义了 SSH 连接执行命令时的提权方式
type SudoMode string

const (
	SudoModeRoot   SudoMode = "root"
	SudoModeSudo   SudoMode = "sudo"
	SudoModeSudoer SudoMode = "sudoer"
	SudoModeSu     SudoMode = "su"
	SudoModeNone   SudoMode = "none"
	SudoModeAuto   SudoMode = "auto"
)

// ClientConfig 定义建立 SSH 连接所需的各种参数，代替原有的 models.Node/Host/Identity。
type ClientConfig struct {
	NodeID     string // 逻辑标识
	Address    string
	Port       int
	User       string
	AuthType   string // "password", "key", "agent", "auto"
	Password   string
	KeyPath    string
	Passphrase string
	SudoMode   SudoMode // "root", "sudo", "sudoer", "su", "none", "auto"
	SuPwd      string
	ProxyJump  string // 跳板机的 NodeID
}

// ConfigStore 定义底层如何获取配置以及如何回写探测到的新配置。
type ConfigStore interface {
	// GetConfig 获取指定 nodeID 的连接配置
	GetConfig(nodeID string) (*ClientConfig, error)

	// UpdateAuth 在 "auto" 模式下探测到可用密码或私钥 passphrase 时，写回持久化存储
	UpdateAuth(nodeID string, password, keyPath, passphrase string) error

	// UpdateSudo 在探测到可用提权模式或接收到 su 密码时，写回持久化存储
	UpdateSudo(nodeID string, mode SudoMode, suPwd string) error
}

// InteractionHandler 定义应用层（CLI 或 GUI）所需实现的交互式输入接口。
type InteractionHandler interface {
	// PromptPassword 提示用户输入密码（例如常规密码或 su 密码）
	PromptPassword(prompt string) (string, error)

	// ConfirmHostKey 提示用户确认未知的 HostKey，返回是否同意连接
	ConfirmHostKey(hostname string, fingerprint string) (bool, error)
}
