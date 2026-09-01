package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	pkgfile "github.com/wentf9/xops-cli/pkg/utils/file"
	"golang.org/x/term"
)

// GetConfigStore returns the storage bootstrap handle, the sole durable
// repository, and a defensive configuration snapshot.
func GetConfigStore() (config.Store, *config.Repository, *config.Configuration, error) {
	configPath, keyPathCfg, err := GetConfigFilePath()
	if err != nil {
		return nil, nil, nil, err
	}
	configStore := config.NewDefaultStore(configPath, keyPathCfg)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	repository, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create configuration repository: %w", err)
	}
	return configStore, repository, repository.Snapshot(), nil
}

// GetLocalSudoPassword 尝试从配置文件中获取本地 sudo 密码，返回 (password, found, error)
func GetLocalSudoPassword() (string, bool, error) {
	configPath, keyPathCfg, err := GetConfigFilePath()
	if err != nil {
		return "", false, fmt.Errorf("get config file path failed: %w", err)
	}
	configStore := config.NewDefaultStore(configPath, keyPathCfg)
	cfg, err := configStore.Load()
	if err != nil {
		return "", false, fmt.Errorf("load config failed: %w", err)
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	username, userErr := GetCurrentUser()
	if userErr != nil {
		return "", false, userErr
	}

	nodeID, resolveErr := resolveFirstSelector(provider, "localhost", "local", username)
	if resolveErr != nil {
		return "", false, fmt.Errorf("resolve local sudo node: %w", resolveErr)
	}

	if nodeID != "" {
		if id, ok := provider.GetIdentity(nodeID); ok {
			return id.Password, true, nil
		}
	}
	return "", false, nil
}

// SaveLocalSudoPassword 保存本地 sudo 密码到配置文件
func SaveLocalSudoPassword(password string) error {
	return SaveLocalSudoPasswordContext(context.Background(), password)
}

// SaveLocalSudoPasswordContext persists the local sudo password with caller
// cancellation applied to the configuration transaction.
func SaveLocalSudoPasswordContext(ctx context.Context, password string) error {
	configPath, keyPathCfg, err := GetConfigFilePath()
	if err != nil {
		return fmt.Errorf("get config file path failed: %w", err)
	}
	store := config.NewDefaultStore(configPath, keyPathCfg)
	cfg, err := store.Load()
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}
	repository, repositoryErr := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if repositoryErr != nil {
		return fmt.Errorf("create configuration repository: %w", repositoryErr)
	}

	username, err := GetCurrentUser()
	if err != nil {
		return err
	}
	address := "localhost"

	// 先尝试按 GetLocalSudoPassword 的优先级查找已有的 Node
	view := repository.View()
	nodeID, resolveErr := resolveFirstSelector(repository, "localhost", "local", username)
	if resolveErr != nil {
		return fmt.Errorf("resolve local sudo node: %w", resolveErr)
	}

	if nodeID != "" {
		node, host, identity, resolveErr := repository.Resolve(nodeID)
		if resolveErr != nil {
			return fmt.Errorf("resolve local node %q for update: %w", nodeID, resolveErr)
		}
		identity.Password = password
		identity.AuthType = "password"
		if err := repository.ReplaceNodeAtRefContext(ctx, view.NodeRefs[nodeID], nodeID, node, host, identity); err != nil {
			return fmt.Errorf("update local sudo password failed: %w", err)
		}
	} else {
		// 全新创建
		nodeID = fmt.Sprintf("%s@%s", username, address)
		hostID := "localhost"
		identityID := fmt.Sprintf("%s@local", username)

		if _, err := repository.CreateNodeContext(ctx, nodeID, models.Node{
			Alias:       []string{"localhost", "local", username},
			HostRef:     hostID,
			IdentityRef: identityID,
			SudoMode:    models.SudoModeSudo,
		}, models.Host{
			Address: "127.0.0.1",
			Port:    22,
			Alias:   []string{"localhost", "local"},
		}, models.Identity{
			User:     username,
			Password: password,
			AuthType: "password",
		}); err != nil {
			return fmt.Errorf("create local sudo node failed: %w", err)
		}
	}

	return nil
}

func resolveFirstSelector(provider config.ConfigProvider, selectors ...string) (string, error) {
	for _, selector := range selectors {
		nodeID, err := provider.ResolveSelector(selector)
		if err != nil {
			return "", fmt.Errorf("resolve selector %q: %w", selector, err)
		}
		if nodeID != "" {
			return nodeID, nil
		}
	}
	return "", nil
}

// ParsePort 解析端口字符串
func ParsePort(input string) (uint16, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, fmt.Errorf("port cannot be empty")
	}
	port64, err := strconv.ParseUint(input, 10, 16)
	if err != nil || port64 == 0 {
		return 0, fmt.Errorf("invalid port %q: must be between 1 and 65535", input)
	}
	return uint16(port64), nil
}

// ParseHost 解析 host:port 或 [ipv6]:port 或裸 ipv6 格式的字符串
func ParseHost(input string) (string, uint16, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", 0, fmt.Errorf("host cannot be empty")
	}

	if strings.HasSuffix(input, ":") {
		return "", 0, fmt.Errorf("invalid host-port format %q: missing port after colon", input)
	}

	// 1. 尝试使用标准 net.SplitHostPort 拆分（适用于 host:port, 1.2.3.4:22, [::1]:22 等）
	if h, pStr, err := net.SplitHostPort(input); err == nil {
		port, pErr := ParsePort(pStr)
		if pErr != nil {
			return "", 0, pErr
		}
		h = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h), "]"), "[")
		if h == "" {
			return "", 0, fmt.Errorf("host cannot be empty")
		}
		return h, port, nil
	}

	// 2. 如果是带方括号的 IPv6 地址，如 [::1] 或 [2001:db8::1]
	if strings.HasPrefix(input, "[") && strings.HasSuffix(input, "]") {
		rawIP := input[1 : len(input)-1]
		if ip := net.ParseIP(rawIP); ip != nil {
			return rawIP, 0, nil
		}
		return "", 0, fmt.Errorf("invalid bracketed IPv6 address %q", input)
	}
	if strings.Contains(input, "[") || strings.Contains(input, "]") {
		return "", 0, fmt.Errorf("malformed bracketed address %q", input)
	}

	// 3. 检查是否为不带方括号的裸 IPv6 地址，如 ::1 或 2001:db8::1
	if ip := net.ParseIP(input); ip != nil {
		return input, 0, nil
	}

	// 4. 如果包含冒号且不是有效 IP，说明格式错误
	if strings.Contains(input, ":") {
		return "", 0, fmt.Errorf("invalid address or host-port %q", input)
	}

	// 5. 普通主机名或 IPv4（未带端口）
	return input, 0, nil
}

// ParseAddr 解析 [user@]host[:port] 格式的字符串，支持 IPv6
func ParseAddr(input string) (user, host string, port uint16, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", 0, fmt.Errorf("address cannot be empty")
	}

	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = strings.TrimSpace(input[:atIndex])
		rest := strings.TrimSpace(input[atIndex+1:])
		if user == "" {
			return "", "", 0, fmt.Errorf("invalid address %q: username before '@' cannot be empty", input)
		}
		if rest == "" {
			return "", "", 0, fmt.Errorf("invalid address %q: host after '@' cannot be empty", input)
		}
		host, port, err = ParseHost(rest)
		if err != nil {
			return "", "", 0, err
		}
		return user, host, port, nil
	}

	host, port, err = ParseHost(input)
	if err != nil {
		return "", "", 0, err
	}
	return "", host, port, nil
}

// GetCurrentUser 获取当前用户名
func GetCurrentUser() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %w", err)
	}
	return currentUser.Username, nil
}

// GetConfigFilePath 获取默认配置与密钥路径
func GetConfigFilePath() (configPath, keyPath string, err error) {
	currUser, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("get current user failed: %w", err)
	}
	return filepath.Join(currUser.HomeDir, ".xops", ConfigFileName), filepath.Join(currUser.HomeDir, ".xops", ConfigKeyName), nil
}

// GetPasswordFilePath 获取默认密码本文件路径
func GetPasswordFilePath() (string, error) {
	currUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %w", err)
	}
	return filepath.Join(currUser.HomeDir, ".xops", PasswordFileName), nil
}

// AskConfirmation 弹出提示，获取用户确认
func AskConfirmation(prompt string) (bool, error) {
	if _, err := fmt.Printf("%s [y/N]: ", prompt); err != nil {
		return false, fmt.Errorf("write confirmation prompt failed: %w", err)
	}
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		if err.Error() == "unexpected newline" {
			return false, nil
		}
		return false, fmt.Errorf("read confirmation response failed: %w", err)
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes", nil
}

// ReadPasswordFromTerminal 从终端安全地读取密码
func ReadPasswordFromTerminal(prompt string) (string, error) {
	if _, err := fmt.Print(prompt); err != nil {
		return "", fmt.Errorf("write prompt failed: %w", err)
	}
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if _, werr := fmt.Println(); werr != nil {
		err = errors.Join(err, werr)
	}
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
	return pkgfile.ToAbsolutePath(path)
}
