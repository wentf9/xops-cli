package utils

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"golang.org/x/term"
)

// GetConfigStore 返回配置存储、Provider、配置对象及其可能发生的错误
func GetConfigStore() (config.Store, config.ConfigProvider, *config.Configuration, error) {
	configPath, keyPathCfg := GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPathCfg)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	return configStore, config.NewProvider(cfg), cfg, nil
}

// GetLocalSudoPassword 尝试从配置文件中获取本地 sudo 密码
func GetLocalSudoPassword() string {
	_, provider, _, err := GetConfigStore()
	if err != nil {
		return ""
	}

	nodeID := provider.Find("localhost")
	if nodeID == "" {
		nodeID = provider.Find("local")
	}
	if nodeID == "" {
		nodeID = provider.Find(GetCurrentUser())
	}

	if nodeID != "" {
		if id, ok := provider.GetIdentity(nodeID); ok {
			return id.Password
		}
	}
	return ""
}

// SaveLocalSudoPassword 保存本地 sudo 密码到配置文件
func SaveLocalSudoPassword(password string) error {
	store, provider, cfg, err := GetConfigStore()
	if err != nil {
		return err
	}

	username := GetCurrentUser()
	address := "localhost"

	// 先尝试按 GetLocalSudoPassword 的优先级查找已有的 Node
	nodeID := provider.Find("localhost")
	if nodeID == "" {
		nodeID = provider.Find("local")
	}
	if nodeID == "" {
		nodeID = provider.Find(username)
	}

	if nodeID != "" {
		// 如果找到了已有的 Node，更新其对应的 Identity 密码
		if node, ok := cfg.Nodes.Get(nodeID); ok {
			if identity, ok := cfg.Identities.Get(node.IdentityRef); ok {
				identity.Password = password
				cfg.Identities.Set(node.IdentityRef, identity)
			} else {
				// 有 Node 但 IdentityRef 失效的情况，补充 Identity
				identityID := fmt.Sprintf("%s@local", username)
				provider.AddIdentity(identityID, models.Identity{
					User:     username,
					Password: password,
					AuthType: "password",
				})
				node.IdentityRef = identityID
				cfg.Nodes.Set(nodeID, node)
			}
		}
	} else {
		// 全新创建
		nodeID = fmt.Sprintf("%s@%s", username, address)
		hostID := "localhost"
		identityID := fmt.Sprintf("%s@local", username)

		provider.AddHost(hostID, models.Host{
			Address: "127.0.0.1",
			Port:    22,
			Alias:   []string{"localhost", "local"},
		})

		provider.AddIdentity(identityID, models.Identity{
			User:     username,
			Password: password,
			AuthType: "password",
		})

		provider.AddNode(nodeID, models.Node{
			Alias:       []string{"localhost", "local", username},
			HostRef:     hostID,
			IdentityRef: identityID,
			SudoMode:    models.SudoModeSudo,
		})
	}

	return store.Save(cfg)
}

// ParseAddr 解析 user@host:port 格式的字符串
func ParseAddr(input string) (string, string, uint16) {
	input = strings.TrimSpace(input)
	var user, host string
	var port uint16
	if atIndex := strings.LastIndex(input, ":"); atIndex != -1 {
		p := ParsePort(input[atIndex+1:])
		if p != 0 {
			port = p
			input = strings.TrimSpace(input[:atIndex])
		}
	}
	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = strings.TrimSpace(input[:atIndex])
		input = strings.TrimSpace(input[atIndex+1:])
	}
	host = strings.TrimSpace(input)
	return user, host, port
}

// ParseHost 解析 host:port 格式的字符串
func ParseHost(input string) (string, uint16) {
	var host string
	var port uint16
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	host = input
	return host, port
}

// ParsePort 解析端口字符串
func ParsePort(input string) uint16 {
	if input == "" {
		return 0
	}
	port64, err := strconv.ParseUint(input, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port64)
}

func GetCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		return ""
	}
	return currentUser.Username
}

func GetConfigFilePath() (configPath, keyPath string) {
	user, err := user.Current()
	if err != nil {
		return "", ""
	}
	return filepath.Join(user.HomeDir, ".xops", ConfigFileName), filepath.Join(user.HomeDir, ".xops", ConfigKeyName)
}

func GetPasswordFilePath() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(user.HomeDir, ".xops", PasswordFileName)
}

// AskConfirmation 弹出提示，获取用户确认
func AskConfirmation(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// ReadPasswordFromTerminal 从终端安全地读取密码
func ReadPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// IsValidIP 检查给定的字符串是否是有效的IP地址
func IsValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil
}

// IsValidCIDR 检查给定的字符串是否是有效的CIDR表示法
func IsValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}

// ToAbsolutePath 将路径转换为绝对路径
// 支持 ~ 展开和相对路径转绝对路径
// 如果路径已经是绝对路径，直接返回
func ToAbsolutePath(path string) string {
	if path == "" {
		return path
	}

	// 处理 ~ 开头的路径
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			// 使用 filepath.Join 确保路径分隔符正确
			rest := path[1:]
			if len(rest) > 0 && (rest[0] == '/' || rest[0] == '\\') {
				rest = rest[1:]
			}
			if rest == "" {
				return home
			}
			return filepath.Join(home, rest)
		}
	}

	// 如果已经是绝对路径，直接返回
	if filepath.IsAbs(path) {
		return path
	}

	// 将相对路径转换为绝对路径
	absPath, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return absPath
}
