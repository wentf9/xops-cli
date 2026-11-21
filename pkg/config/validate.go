package config

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/ssh"
)

// DefaultControlPath specifies the standard OpenSSH multiplexing socket pattern.
const DefaultControlPath = "~/.ssh/cm-%r@%h:%p"

// ValidateSSHOptions validates standalone ssh.Options field syntax and cross-field consistency.
func ValidateSSHOptions(opts *ssh.Options) error {
	if opts == nil {
		return nil
	}
	if err := opts.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
	}
	return nil
}

// ValidateEffectiveSSHOptions verifies the resolved effective OpenSSH options for a node.
func ValidateEffectiveSSHOptions(opts *ssh.Options) error {
	if opts == nil {
		return nil
	}
	if err := opts.ValidateEffective(); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaValidation, err)
	}
	return nil
}

// ValidateControlConfig validates standalone ControlConfig field syntax and cross-field consistency
// by delegating to the canonical core/ssh Options validator.
func ValidateControlConfig(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}
	return ValidateSSHOptions(ssh.OptionsFromControl(ctrl))
}

// ValidateControlPathSyntax verifies raw ControlPath string token syntax without environment dependencies.
func ValidateControlPathSyntax(rawPath string) error {
	return ssh.ValidateControlPathSyntax(rawPath)
}

// ValidateEffectiveControl verifies the resolved effective multiplexing configuration for a node
// by delegating to the canonical core/ssh Options effective validator.
func ValidateEffectiveControl(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}
	return ValidateEffectiveSSHOptions(ssh.OptionsFromControl(ctrl))
}
