package ssh

import (
	"net"
	"os"

	cmdutil "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AuthMethod 定义获取 SSH 认证方法的接口
type AuthMethod interface {
	GetMethod() (ssh.AuthMethod, error)
}

// PasswordAuth 实现密码认证
type PasswordAuth struct {
	Password string
}

func (p *PasswordAuth) GetMethod() (ssh.AuthMethod, error) {
	return ssh.Password(p.Password), nil
}

// KeyAuth 实现私钥认证
type KeyAuth struct {
	Path       string
	Passphrase string
}

func (k *KeyAuth) GetMethod() (ssh.AuthMethod, error) {
	keyData, err := os.ReadFile(k.Path)
	if err != nil {
		return nil, err
	}
	var signer ssh.Signer
	if k.Passphrase != "" {
		signer, _ = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(k.Passphrase))
	} else {
		signer, _ = ssh.ParsePrivateKey(keyData)
	}
	return ssh.PublicKeys(signer), nil
}

// BuildAutoAuthMethods 生成一个包含多种回退机制的 AuthMethod 链
func BuildAutoAuthMethods(user, host string, passwordCallback func(string)) ([]ssh.AuthMethod, func()) {
	var methods []ssh.AuthMethod
	var cleanup func()

	// SSH Agent
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
			cleanup = func() { _ = conn.Close() }
		}
	}

	// Default Keys
	defaultKeys := []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_dsa"}
	for _, p := range defaultKeys {
		logger.Debugf("Checking default key: %s", expandHomeDir(p))
		if _, err := os.Stat(expandHomeDir(p)); err == nil {
			logger.Debugf("Found default key: %s", expandHomeDir(p))
			keyAuth := &KeyAuth{Path: expandHomeDir(p)}
			if m, err := keyAuth.GetMethod(); err == nil {
				methods = append(methods, m)
			}
		}
	}

	// Password Fallback
	methods = append(methods, ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		password, err := cmdutil.ReadPasswordFromTerminal(i18n.T("prompt_enter_password"))
		if err != nil {
			return "", err
		}
		passwordCallback(password)
		return password, nil
	}), 3))

	return methods, cleanup
}
