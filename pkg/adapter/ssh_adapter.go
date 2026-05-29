package adapter

import (
	"fmt"

	cmdutil "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// SSHAdapter 实现 ssh.ConfigStore 和 ssh.InteractionHandler 接口，作为业务模型与底层 SSH 的防腐层
type SSHAdapter struct {
	cfgProvider config.ConfigProvider
}

// NewSSHAdapter 创建 SSH 适配器
func NewSSHAdapter(cfgProvider config.ConfigProvider) *SSHAdapter {
	return &SSHAdapter{
		cfgProvider: cfgProvider,
	}
}

// NewConnector 是一个辅助方法，快速创建组装好 Adapter 的 ssh.Connector
func NewConnector(cfgProvider config.ConfigProvider) *ssh.Connector {
	adp := NewSSHAdapter(cfgProvider)
	return ssh.NewConnector(adp, adp)
}

// GetConfig 获取底层 SSH 客户端需要的配置
func (a *SSHAdapter) GetConfig(nodeID string) (*ssh.ClientConfig, error) {
	node, ok := a.cfgProvider.GetNode(nodeID)
	if !ok {
		return nil, fmt.Errorf("node not found '%s'", nodeID)
	}

	host, ok := a.cfgProvider.GetHost(nodeID)
	if !ok {
		return nil, fmt.Errorf("host ref '%s' not found for node '%s'", node.HostRef, nodeID)
	}

	identity, ok := a.cfgProvider.GetIdentity(nodeID)
	if !ok {
		return nil, fmt.Errorf("identity ref '%s' not found for node '%s'", node.IdentityRef, nodeID)
	}

	return &ssh.ClientConfig{
		NodeID:     nodeID,
		Address:    host.Address,
		Port:       int(host.Port),
		User:       identity.User,
		AuthType:   identity.AuthType,
		Password:   identity.Password,
		KeyPath:    identity.KeyPath,
		Passphrase: identity.Passphrase,
		SudoMode:   ssh.SudoMode(node.SudoMode),
		SuPwd:      node.SuPwd,
		ProxyJump:  node.ProxyJump,
	}, nil
}

// UpdateAuth 处理密码或私钥密码的回写
func (a *SSHAdapter) UpdateAuth(nodeID string, password, keyPath, passphrase string) error {
	node, ok := a.cfgProvider.GetNode(nodeID)
	if !ok {
		return fmt.Errorf("node not found '%s'", nodeID)
	}
	identity, ok := a.cfgProvider.GetIdentity(nodeID)
	if !ok {
		return fmt.Errorf("identity not found '%s'", nodeID)
	}
	host, ok := a.cfgProvider.GetHost(nodeID)
	if !ok {
		return fmt.Errorf("host not found '%s'", nodeID)
	}

	updated := false
	if password != "" && identity.Password != password {
		identity.Password = password
		identity.AuthType = "password"
		updated = true
	}
	if passphrase != "" && (identity.Passphrase != passphrase || identity.KeyPath != keyPath) {
		identity.Passphrase = passphrase
		identity.KeyPath = keyPath
		identity.AuthType = "key"
		updated = true
	}

	if updated {
		a.cfgProvider.AddIdentity(node.IdentityRef, identity)
		a.cfgProvider.AddNode(nodeID, node)
		a.cfgProvider.AddHost(node.HostRef, host)
	}
	return nil
}

// UpdateSudo 处理提权密码和模式的回写
func (a *SSHAdapter) UpdateSudo(nodeID string, mode ssh.SudoMode, suPwd string) error {
	node, ok := a.cfgProvider.GetNode(nodeID)
	if !ok {
		return fmt.Errorf("node not found '%s'", nodeID)
	}

	updated := false
	if models.SudoMode(mode) != node.SudoMode && mode != "" {
		node.SudoMode = models.SudoMode(mode)
		updated = true
	}
	if suPwd != "" && node.SuPwd != suPwd {
		node.SuPwd = suPwd
		updated = true
	}

	if updated {
		a.cfgProvider.AddNode(nodeID, node)
	}
	return nil
}

// PromptPassword 通过命令行终端获取密码输入
func (a *SSHAdapter) PromptPassword(prompt string) (string, error) {
	return cmdutil.ReadPasswordFromTerminal(prompt)
}

// ConfirmHostKey 通过命令行终端请求确认 HostKey
func (a *SSHAdapter) ConfirmHostKey(hostname string, fingerprint string) (bool, error) {
	fmt.Printf("The authenticity of host '%s' can't be established.\n", hostname)
	fmt.Printf("key fingerprint is %s.\n", fingerprint)
	fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

	var response string
	_, scanErr := fmt.Scanln(&response)
	if scanErr != nil && scanErr.Error() != "unexpected newline" && scanErr.Error() != "EOF" {
		return false, fmt.Errorf("read response failed: %w", scanErr)
	}

	if response == "yes" {
		return true, nil
	}
	return false, nil
}
