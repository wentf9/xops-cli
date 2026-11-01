package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
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
	if cfgDir := os.Getenv("XOPS_CONFIG_DIR"); cfgDir != "" {
		return filepath.Join(cfgDir, ConfigFileName), filepath.Join(cfgDir, ConfigKeyName), nil
	}
	currUser, err := user.Current()
	if err != nil {
		return "", "", fmt.Errorf("get current user failed: %w", err)
	}
	return filepath.Join(currUser.HomeDir, ".xops", ConfigFileName), filepath.Join(currUser.HomeDir, ".xops", ConfigKeyName), nil
}

// GetPasswordFilePath 获取默认密码本文件路径
func GetPasswordFilePath() (string, error) {
	if cfgDir := os.Getenv("XOPS_CONFIG_DIR"); cfgDir != "" {
		return filepath.Join(cfgDir, PasswordFileName), nil
	}
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
