package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"
	"github.com/wentf9/xops-cli/pkg/models"
)

const OpenSSHNodePrefix = "openssh:"

// OpenSSHParser 提供针对 ~/.ssh/config 的解析和模型映射功能
type OpenSSHParser struct {
	cfg *ssh_config.Config
}

// NewOpenSSHParser 尝试从标准路径加载用户的 ~/.ssh/config 配置文件。
// 如果文件不存在，返回空的 OpenSSHParser 和 nil 错误；其他错误返回具体包装错误。
func NewOpenSSHParser() (*OpenSSHParser, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home directory failed: %w", err)
	}
	userConfigPath := filepath.Join(homeDir, ".ssh", "config")
	return NewOpenSSHParserFromPath(userConfigPath)
}

// NewOpenSSHParserFromPath 从指定路径加载 SSH 配置文件。如果文件不存在，返回空的 OpenSSHParser 和 nil 错误。
func NewOpenSSHParserFromPath(path string) (parser *OpenSSHParser, retErr error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &OpenSSHParser{cfg: nil}, nil
		}
		return nil, fmt.Errorf("open ssh config %q failed: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close ssh config %q failed: %w", path, closeErr))
		}
	}()

	cfg, decodeErr := ssh_config.Decode(f)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode ssh config %q failed: %w", path, decodeErr)
	}
	return &OpenSSHParser{cfg: cfg}, nil
}

// NewOpenSSHParserFromReader 从任意 io.Reader 加载 SSH 配置
func NewOpenSSHParserFromReader(r io.Reader) (*OpenSSHParser, error) {
	if r == nil {
		return &OpenSSHParser{cfg: nil}, nil
	}
	cfg, err := ssh_config.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("decode ssh config failed: %w", err)
	}
	return &OpenSSHParser{cfg: cfg}, nil
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
func (p *OpenSSHParser) GetVirtualNode(alias string) (models.Node, models.Host, models.Identity, error) {
	lookupAlias, userOverride, portOverride, err := parseOpenSSHHostSpec(alias)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("parse openssh host %q failed: %w", alias, err)
	}
	// 从配置中提取各种字段
	hostName, err := p.getVal(lookupAlias, "HostName", lookupAlias)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}
	defUser, userErr := getCurrentUser()
	if userErr != nil {
		return models.Node{}, models.Host{}, models.Identity{}, userErr
	}
	user, err := p.getVal(lookupAlias, "User", defUser)
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}
	portStr, err := p.getVal(lookupAlias, "Port", "22")
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}
	portStr = strings.TrimSpace(portStr)
	parsedPort, parseErr := strconv.ParseUint(portStr, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return models.Node{}, models.Host{}, models.Identity{}, fmt.Errorf("invalid port %q for %q in ssh config: must be between 1 and 65535", portStr, lookupAlias)
	}
	port := uint16(parsedPort)
	if userOverride != "" {
		user = userOverride
	}
	if portOverride != 0 {
		port = portOverride
	}

	identityFile, err := p.getVal(lookupAlias, "IdentityFile", "")
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}
	if identityFile != "" {
		var expErr error
		identityFile, expErr = expandHomeDir(identityFile)
		if expErr != nil {
			return models.Node{}, models.Host{}, models.Identity{}, expErr
		}
	}

	proxyJump, err := p.getVal(lookupAlias, "ProxyJump", "")
	if err != nil {
		return models.Node{}, models.Host{}, models.Identity{}, err
	}
	if proxyJump != "" {
		if strings.EqualFold(strings.TrimSpace(proxyJump), "none") {
			proxyJump = ""
		} else {
			hops := strings.Split(proxyJump, ",")
			var parsedHops []string
			for _, rawHop := range hops {
				hop := strings.TrimSpace(rawHop)
				if hop == "" || strings.EqualFold(hop, "none") {
					continue
				}
				parsedHops = append(parsedHops, OpenSSHNodePrefix+hop)
			}
			proxyJump = strings.Join(parsedHops, ",")
		}
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

	return node, host, identity, nil
}

func parseOpenSSHHostSpec(spec string) (host, userName string, port uint16, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", 0, fmt.Errorf("host is empty")
	}
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userName = strings.TrimSpace(spec[:at])
		spec = strings.TrimSpace(spec[at+1:])
		if userName == "" || spec == "" {
			return "", "", 0, fmt.Errorf("invalid user or host")
		}
	}

	portText := ""
	portSpecified := false
	switch {
	case strings.HasPrefix(spec, "["):
		end := strings.Index(spec, "]")
		if end < 0 {
			return "", "", 0, fmt.Errorf("invalid bracketed host")
		}
		host = spec[1:end]
		if suffix := spec[end+1:]; suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return "", "", 0, fmt.Errorf("invalid host suffix %q", suffix)
			}
			portSpecified = true
			portText = strings.TrimPrefix(suffix, ":")
		}
	case strings.Count(spec, ":") == 1:
		portSpecified = true
		var splitErr error
		host, portText, splitErr = net.SplitHostPort(spec)
		if splitErr != nil {
			return "", "", 0, fmt.Errorf("parse host and port failed: %w", splitErr)
		}
	default:
		host = spec
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", 0, fmt.Errorf("host is empty")
	}
	if !portSpecified {
		return host, userName, 0, nil
	}
	parsedPort, parseErr := strconv.ParseUint(portText, 10, 16)
	if parseErr != nil || parsedPort == 0 {
		return "", "", 0, fmt.Errorf("invalid port %q", portText)
	}
	return host, userName, uint16(parsedPort), nil
}

// getVal 是封装获取的方法
func (p *OpenSSHParser) getVal(alias, key, defaultVal string) (string, error) {
	if p == nil || p.cfg == nil {
		return defaultVal, nil
	}
	val, err := p.cfg.Get(alias, key)
	if err != nil {
		return "", fmt.Errorf("get %q for %q from ssh config failed: %w", key, alias, err)
	}
	if val == "" {
		return defaultVal, nil
	}
	return val, nil
}

var currentUserFn = func() (string, error) {
	currUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("get current user failed: %w", err)
	}
	return currUser.Username, nil
}

// 辅助函数
func getCurrentUser() (string, error) {
	return currentUserFn()
}

func expandHomeDir(path string) (string, error) {
	if len(path) == 0 {
		return path, nil
	}
	if path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand home dir failed: %w", err)
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}
