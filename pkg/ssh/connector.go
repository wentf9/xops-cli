package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sync/singleflight"
)

// Connector 负责创建 SSH 连接
type Connector struct {
	Config config.ConfigProvider
	// 连接池：缓存 nodeName -> *ssh.Client
	clients *concurrent.Map[string, *ssh.Client]
	// singleflight 组，用来控制并发和去重
	sf singleflight.Group
}

// NewConnector 创建一个新的 Connector
func NewConnector(cfg config.ConfigProvider) *Connector {
	return &Connector{
		Config:  cfg,
		clients: concurrent.NewMap[string, *ssh.Client](concurrent.HashString),
	}
}

// Connect 根据节点名称建立 SSH 连接
// 自动处理跳板机逻辑：如果节点配置了 ProxyJump，会递归建立连接
func (c *Connector) Connect(ctx context.Context, nodeName string) (*Client, error) {
	if cachedClient, ok := c.clients.Get(nodeName); ok {
		// 可选：检查连接是否存活（发送一个非阻塞的 KeepAlive 请求）
		// 对于短生命周期的 CLI 工具，通常假设缓存的连接是可用的
		node, _ := c.Config.GetNode(nodeName) // 重新获取配置以防更新，或者缓存 wrapper
		host, _ := c.Config.GetHost(node.HostRef)
		identity, _ := c.Config.GetIdentity(node.IdentityRef)
		return newClient(cachedClient, node, host, identity, c.Config, nodeName), nil
	}
	// 缓存未命中，开始建立新连接
	// 【合并请求】使用 singleflight
	// 即使 100 个协程同时调 Connect(host)，Do 里面的函数只会执行一次
	// 其他协程会阻塞在这里等待结果
	result, err, _ := c.sf.Do(nodeName, func() (any, error) {
		// 双重检查：防止在进入 Do 之前那一瞬间，别的协程刚好把连接建立好了
		if cachedClient, ok := c.clients.Get(nodeName); ok {
			node, _ := c.Config.GetNode(nodeName)
			host, _ := c.Config.GetHost(node.HostRef)
			identity, _ := c.Config.GetIdentity(node.IdentityRef)
			return newClient(cachedClient, node, host, identity, c.Config, nodeName), nil
		}

		// 1. 获取节点配置
		node, ok := c.Config.GetNode(nodeName)
		if !ok {
			return nil, fmt.Errorf("node not found '%s'", nodeName)
		}

		// 2. 获取关联的 Host 和 Identity 数据
		host, ok := c.Config.GetHost(nodeName)
		if !ok {
			return nil, fmt.Errorf("host ref '%s' not found for node '%s'", node.HostRef, nodeName)
		}
		identity, ok := c.Config.GetIdentity(nodeName)
		if !ok {
			return nil, fmt.Errorf("identity ref '%s' not found for node '%s'", node.IdentityRef, nodeName)
		}

		// 3. 确定网络拨号器 (Dialer)
		// 如果有 ProxyJump，递归连接跳板机，将其 SSH Client 封装为 Dialer
		var dialer Dialer = &net.Dialer{Timeout: 10 * time.Second} // 默认直连

		if node.ProxyJump != "" {
			jumpHost := c.Config.Find(node.ProxyJump)
			if jumpHost == "" {
				jumpHost = node.ProxyJump
			}
			// 递归：连接跳板机
			jumpNodeClient, err := c.Connect(ctx, jumpHost)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to jump host '%s': %w", node.ProxyJump, err)
			}
			// 封装：使用跳板机的 SSH 通道作为 Dialer
			dialer = &SSHProxyDialer{Client: jumpNodeClient.sshClient}
		}

		// 4. 构建目标 SSH 配置 (认证信息)
		sshConfig, cleanup, err := c.buildSSHConfig(&identity, host.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to build ssh config for '%s': %w", nodeName, err)
		}
		if cleanup != nil {
			defer cleanup()
		}

		// 5. 建立底层 TCP 连接 (通过 Dialer)
		if host.Port == 0 {
			host.Port = 22
		}
		targetAddr := fmt.Sprintf("%s:%d", host.Address, host.Port)
		conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial target '%s' (%s): %w", nodeName, targetAddr, err)
		}

		// 6. 建立 SSH 会话
		// 使用 NewClientConn 接管底层的 conn
		ncc, chans, reqs, err := ssh.NewClientConn(conn, targetAddr, sshConfig)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("ssh handshake failed for '%s': %w", nodeName, err)
		}
		rawClient := ssh.NewClient(ncc, chans, reqs)
		c.clients.Set(nodeName, rawClient)
		// 7. 返回封装的 Client
		return newClient(rawClient, node, host, identity, c.Config, nodeName), nil
	})
	if err != nil {
		return nil, err
	}
	// 类型断言返回结果
	return result.(*Client), nil
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
func (c *Connector) buildSSHConfig(id *models.Identity, hostAddr string) (*ssh.ClientConfig, func(), error) {
	var cleanup func()
	authMethods := []ssh.AuthMethod{}

	// 根据 AuthType 处理不同的认证方式
	switch id.AuthType {
	case "auto":
		var autoCleanup func()
		authMethods, autoCleanup = BuildAutoAuthMethods(id.User, hostAddr, func(s string) {
			if s != "" {
				id.Password = s
				id.AuthType = "password"
			}
		})
		cleanup = autoCleanup

	case "password":
		if id.Password == "" {
			return nil, nil, fmt.Errorf("auth type is password but password is empty")
		}
		authMethods = append(authMethods, ssh.Password(id.Password))

	case "key":
		if id.KeyPath == "" {
			return nil, nil, fmt.Errorf("auth type is key but key_path is empty")
		}
		keyBytes, err := os.ReadFile(expandHomeDir(id.KeyPath))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read key file: %w", err)
		}
		var signer ssh.Signer
		if id.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(id.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))

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
		return nil, nil, fmt.Errorf("unsupported auth type: %s", id.AuthType)
	}

	return &ssh.ClientConfig{
		User:            id.User,
		Auth:            authMethods,
		HostKeyCallback: getHostKeyCallback(),
		Timeout:         15 * time.Second,
	}, cleanup, nil
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

func getHostKeyCallback() ssh.HostKeyCallback {
	home, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey()
	}
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")

	if _, err := os.Stat(knownHostsFile); os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(knownHostsFile), 0700)
		_ = os.WriteFile(knownHostsFile, []byte(""), 0600)
	}

	hostKeyCallback, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return ssh.InsecureIgnoreHostKey()
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := hostKeyCallback(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) > 0 {
				fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
					"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n" +
					"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n" +
					"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n")
				return err
			}

			// Unknown host
			fmt.Printf("The authenticity of host '%s' can't be established.\n", hostname)
			fingerprint := ssh.FingerprintSHA256(key)
			fmt.Printf("%s key fingerprint is %s.\n", key.Type(), fingerprint)
			fmt.Print("Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

			var response string
			_, _ = fmt.Scanln(&response)
			if response != "yes" && response != fingerprint {
				return fmt.Errorf("host key verification failed")
			}

			// Append to known_hosts
			f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0600)
			if err == nil {
				defer func() { _ = f.Close() }()
				line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key)
				_, _ = f.WriteString(line + "\n")
			}
			return nil
		}
		return err
	}
}
