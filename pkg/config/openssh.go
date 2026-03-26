package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/wentf9/xops-cli/pkg/models"
)

const OpenSSHNodePrefix = "openssh:"

// OpenSSHParser 提供针对 ~/.ssh/config 的解析和模型映射功能
type OpenSSHParser struct {
	cfg *ssh_config.Config
}

// NewOpenSSHParser 尝试加载用户的 SSH 配置文件
func NewOpenSSHParser() *OpenSSHParser {
	parser := &OpenSSHParser{}

	// 按 OpenSSH 标准尝试加载用户配置
	homeDir, err := os.UserHomeDir()
	if err == nil {
		userConfigPath := filepath.Join(homeDir, ".ssh", "config")
		if f, err := os.Open(userConfigPath); err == nil {
			defer func() { _ = f.Close() }()
			cfg, _ := ssh_config.Decode(f)
			parser.cfg = cfg
		}
	}

	// 如果配置加载失败或者不存在，也可以返回空 parser，
	// Get() 方法会使用 fallback default 处理
	return parser
}

// Find 尝试在 ssh_config 中寻找匹配的主机名
// 如果用户输入了未知主机，我们一律返回带前缀的虚拟 NodeID，
// 在连接时利用 ssh_config 的默认回退属性来尝试连接，
// 这样使得 xops 表现得和原生 ssh 命令的体验完全一致。
func (p *OpenSSHParser) Find(alias string) (string, bool) {
	if alias == "" {
		return "", false
	}
	// xops 内部可能传入全名诸如 "user@host:port" 给 provider 检索，
	// 这些复合物并不是原生的 ssh_config Host (除非极罕见被定义成这样)。
	// 为了不妨碍后续拆分逻辑和别名正确分配，我们过滤掉含有 @ 和 : 的别名。
	if strings.Contains(alias, "@") || strings.Contains(alias, ":") {
		return "", false
	}
	return OpenSSHNodePrefix + alias, true
}

// GetVirtualNode 根据 alias 从 ssh_config 生成运行时的内存 Node / Host / Identity
func (p *OpenSSHParser) GetVirtualNode(alias string) (models.Node, models.Host, models.Identity) {
	// 从配置中提取各种字段
	hostName := p.getVal(alias, "HostName", alias)
	user := p.getVal(alias, "User", getCurrentUser())
	portStr := p.getVal(alias, "Port", "22")
	portStr = strings.TrimSpace(portStr)
	var port uint16 = 22
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	identityFile := p.getVal(alias, "IdentityFile", "")
	if identityFile != "" {
		identityFile = expandHomeDir(identityFile)
	}

	proxyJump := p.getVal(alias, "ProxyJump", "")
	if proxyJump != "" {
		proxyJump = OpenSSHNodePrefix + proxyJump
	}

	hostRef := fmt.Sprintf("%s:%d", hostName, port)
	identityRef := fmt.Sprintf("%s@%s", user, hostName)

	node := models.Node{
		HostRef:     hostRef,
		IdentityRef: identityRef,
		ProxyJump:   proxyJump,
		SudoMode:    models.SudoModeAuto, // 对于导入节点，依然支持 auto
		Tags:        []string{"openssh"}, // 打一个虚拟 tag
		Alias:       []string{alias},
	}

	host := models.Host{
		Address: hostName,
		Port:    port,
	}

	identity := models.Identity{
		User:     user,
		AuthType: "auto", // 我们会在 connector 中专门处理 auto 类型的增强 fallback 链
		KeyPath:  identityFile,
	}

	return node, host, identity
}

// getVal 是封装获取的方法
func (p *OpenSSHParser) getVal(alias, key, defaultVal string) string {
	if p.cfg == nil {
		return defaultVal
	}
	val, err := p.cfg.Get(alias, key)
	if err != nil || val == "" {
		return defaultVal
	}
	return val
}

// 辅助函数
func getCurrentUser() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Base(home)
}

func expandHomeDir(path string) string {
	if len(path) == 0 {
		return path
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}
