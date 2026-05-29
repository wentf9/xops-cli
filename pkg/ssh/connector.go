package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/singleflight"
)

// Connector 负责创建 SSH 连接
type Connector struct {
	store ConfigStore
	ui    InteractionHandler
	// 连接池：缓存 nodeName -> *ssh.Client
	clients *concurrent.Map[string, *ssh.Client]
	// singleflight 组，用来控制并发和去重
	sf singleflight.Group
	// 自动接受新的主机密钥
	AcceptNewHostKey atomic.Bool
}

var hostKeyPromptMutex sync.Mutex

// NewConnector 创建一个新的 Connector
func NewConnector(store ConfigStore, ui InteractionHandler) *Connector {
	return &Connector{
		store:   store,
		ui:      ui,
		clients: concurrent.NewMap[string, *ssh.Client](concurrent.HashString),
	}
}

// Connect 根据节点名称建立 SSH 连接
// 自动处理跳板机逻辑：如果节点配置了 ProxyJump，会递归建立连接
func (c *Connector) Connect(ctx context.Context, nodeName string) (*Client, error) {
	if cachedClient, ok := c.clients.Get(nodeName); ok {
		// 可选：检查连接是否存活（发送一个非阻塞的 KeepAlive 请求）
		// 对于短生命周期的 CLI 工具，通常假设缓存的连接是可用的
		cfg, err := c.store.GetConfig(nodeName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch config for cached node '%s': %w", nodeName, err)
		}
		return newClient(cachedClient, cfg, c.store), nil
	}
	// 缓存未命中，开始建立新连接
	// 【合并请求】使用 singleflight
	// 即使 100 个协程同时调 Connect(host)，Do 里面的函数只会执行一次
	// 其他协程会阻塞在这里等待结果
	result, err, _ := c.sf.Do(nodeName, func() (any, error) {
		return c.initializeConnection(ctx, nodeName)
	})
	if err != nil {
		return nil, err
	}
	// 类型断言返回结果
	return result.(*Client), nil
}

func (c *Connector) initializeConnection(ctx context.Context, nodeName string) (*Client, error) {
	cfg, err := c.store.GetConfig(nodeName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch config for node '%s': %w", nodeName, err)
	}

	// SudoMode 为 su 时若未配置密码，交互式提示并写回 Provider（调用方负责持久化）
	if cfg.SudoMode == SudoModeSu && cfg.SuPwd == "" {
		suPwd, err := c.ui.PromptPassword(fmt.Sprintf("Enter su password for node %s: ", nodeName))
		if err != nil {
			return nil, fmt.Errorf("failed to read su password: %w", err)
		}
		cfg.SuPwd = suPwd
		_ = c.store.UpdateSudo(nodeName, cfg.SudoMode, suPwd)
	}

	dialer, err := c.setupDialer(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to setup dialer: %w", err)
	}

	sshConfig, cleanup, err := c.buildSSHConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	rawClient, err := c.dialAndHandshake(ctx, nodeName, cfg, dialer, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial and handshake: %w", err)
	}

	// 认证并连接成功后，检查我们是否通过 "auto" 下的终端交互获取到了新凭证（密码或密钥密码）。
	if cfg.Password != "" || cfg.Passphrase != "" {
		_ = c.store.UpdateAuth(nodeName, cfg.Password, cfg.KeyPath, cfg.Passphrase)
	}

	c.clients.Set(nodeName, rawClient)
	// 返回封装的 Client
	return newClient(rawClient, cfg, c.store), nil
}

func (c *Connector) setupDialer(ctx context.Context, cfg *ClientConfig) (Dialer, error) {
	var dialer Dialer = &net.Dialer{Timeout: 10 * time.Second} // 默认直连

	if cfg.ProxyJump != "" {
		// 递归：连接跳板机
		jumpNodeClient, err := c.Connect(ctx, cfg.ProxyJump)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to jump host '%s': %w", cfg.ProxyJump, err)
		}
		// 封装：使用跳板机的 SSH 通道作为 Dialer
		dialer = &SSHProxyDialer{Client: jumpNodeClient.sshClient}
	}

	return dialer, nil
}

func (c *Connector) dialAndHandshake(ctx context.Context, nodeName string, cfg *ClientConfig, dialer Dialer, sshConfig *ssh.ClientConfig) (*ssh.Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	targetAddr := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial target '%s' (%s): %w", nodeName, targetAddr, err)
	}

	// 建立 SSH 会话
	// 使用 NewClientConn 接管底层的 conn
	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake failed for '%s': %w", nodeName, err)
	}

	return ssh.NewClient(ncc, chans, reqs), nil
}

// CloseAll 关闭所有缓存的连接 (在程序退出前调用)
func (c *Connector) CloseAll() {
	c.clients.IterCb(func(name string, client *ssh.Client) bool {
		_ = client.Close()
		return true
	})
	c.clients.Clear()
}

// buildSSHConfig 根据 Identity 模型构建 ssh.ClientConfig
func (c *Connector) buildSSHConfig(cfg *ClientConfig) (*ssh.ClientConfig, func(), error) {
	var cleanup func()
	authMethods := []ssh.AuthMethod{}

	// 根据 AuthType 处理不同的认证方式
	switch cfg.AuthType {
	case "auto":
		var autoCleanup func()
		authMethods, autoCleanup = BuildAutoAuthMethods(cfg.User, cfg.Address, c.ui, func(s string) {
			if s != "" {
				cfg.Password = s
				cfg.AuthType = "password"
			}
		}, func(keyPath, passphrase string) {
			if passphrase != "" {
				cfg.KeyPath = keyPath
				cfg.Passphrase = passphrase
				cfg.AuthType = "key"
			}
		})
		cleanup = autoCleanup

	case "password":
		if cfg.Password == "" {
			return nil, nil, fmt.Errorf("auth type is password but password is empty")
		}
		authMethods = append(authMethods, ssh.Password(cfg.Password))

	case "key":
		authMethod, err := buildKeyAuthMethod(cfg)
		if err != nil {
			return nil, nil, err
		}
		authMethods = append(authMethods, authMethod)

	case "agent":
		socket := os.Getenv("SSH_AUTH_SOCK")
		if socket == "" {
			return nil, nil, fmt.Errorf("auth type is agent but SSH_AUTH_SOCK is not set")
		}
		conn, err := net.Dial("unix", socket)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to ssh-agent: %w", err)
		}
		agentClient := agent.NewClient(conn)
		authMethods = append(authMethods, ssh.PublicKeysCallback(agentClient.Signers))
		cleanup = func() { _ = conn.Close() }

	default:
		return nil, nil, fmt.Errorf("unsupported auth type: %s", cfg.AuthType)
	}

	hostKeyCallback, err := c.getHostKeyCallback()
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, fmt.Errorf("get host key callback failed: %w", err)
	}

	return &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}, cleanup, nil
}

func buildKeyAuthMethod(cfg *ClientConfig) (ssh.AuthMethod, error) {
	if cfg.KeyPath == "" {
		return nil, fmt.Errorf("auth type is key but key_path is empty")
	}
	keyBytes, err := os.ReadFile(expandHomeDir(cfg.KeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	var signer ssh.Signer
	if cfg.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(cfg.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

// expandHomeDir 简单的路径处理辅助函数
func expandHomeDir(path string) string {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[1:])
		}
	}
	return path
}

func (c *Connector) getHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get user home dir failed: %w", err)
	}
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")

	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		if mkdirErr := os.MkdirAll(filepath.Dir(knownHostsFile), 0700); mkdirErr != nil {
			return nil, fmt.Errorf("create .ssh directory failed: %w", mkdirErr)
		}
		if writeErr := os.WriteFile(knownHostsFile, []byte(""), 0600); writeErr != nil {
			return nil, fmt.Errorf("create known_hosts file failed: %w", writeErr)
		}
	}

	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("parse known_hosts file failed: %w", err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		if keyErr, ok := errors.AsType[*knownhosts.KeyError](err); ok {
			if len(keyErr.Want) > 0 {
				fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
					"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
					"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
					"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n")
				return err
			}

			if promptErr := c.promptHostKeyVerification(hostname, key); promptErr != nil {
				return promptErr
			}

			return appendKnownHost(knownHostsFile, hostname, key)
		}
		return err
	}, nil
}

func (c *Connector) promptHostKeyVerification(hostname string, key ssh.PublicKey) error {
	if c.AcceptNewHostKey.Load() {
		return nil
	}

	hostKeyPromptMutex.Lock()
	defer hostKeyPromptMutex.Unlock()

	// Double check after acquiring lock
	if c.AcceptNewHostKey.Load() {
		return nil
	}

	fingerprint := ssh.FingerprintSHA256(key)
	agreed, err := c.ui.ConfirmHostKey(hostname, fingerprint)
	if err != nil {
		return fmt.Errorf("read response failed: %w", err)
	}

	if agreed {
		return nil
	}
	return fmt.Errorf("host key verification failed")
}

func appendKnownHost(knownHostsFile, hostname string, key ssh.PublicKey) error {
	hostKeyPromptMutex.Lock()
	defer hostKeyPromptMutex.Unlock()

	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open known_hosts file failed: %w", err)
	}
	defer func() { _ = f.Close() }()

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
	if _, writeErr := f.WriteString(line + "\n"); writeErr != nil {
		return fmt.Errorf("write known_hosts file failed: %w", writeErr)
	}
	return nil
}
