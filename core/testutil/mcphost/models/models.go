// Package models contains synthetic inventory data for migrated protocol tests.
// These are fixtures, not public database or CLI configuration entities.
package models

import "github.com/wentf9/xops-cli/core/ssh"

type Host struct {
	Alias   []string
	Address string
	Port    uint16
}
type Identity struct{ User, KeyPath, Passphrase, Password, AuthType string }
type Node struct {
	Alias, Tags                     []string
	HostRef, IdentityRef, ProxyJump string
	SudoMode                        ssh.SudoMode
	SuPwd, PasswordPromptPattern    string
}

const (
	SudoModeRoot = ssh.SudoModeRoot
	SudoModeSu   = ssh.SudoModeSu
)
