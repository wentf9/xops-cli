package config

import (
	"fmt"
	"strings"

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

// ValidateControlConfig validates standalone ControlConfig field syntax and cross-field consistency.
func ValidateControlConfig(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}

	// 1. Validate Master mode
	normMaster := strings.ToLower(strings.TrimSpace(string(ctrl.Master)))
	switch normMaster {
	case "", string(ssh.ControlMasterNo), string(ssh.ControlMasterYes),
		string(ssh.ControlMasterAsk), string(ssh.ControlMasterAuto), string(ssh.ControlMasterAutoAsk):
		// valid
	default:
		return fmt.Errorf("%w: unsupported ControlMaster option %q", ErrSchemaValidation, ctrl.Master)
	}

	// 2. Validate Persist duration format
	if ctrl.Persist != "" {
		if _, _, _, err := ssh.ParseControlPersist(ctrl.Persist); err != nil {
			return fmt.Errorf("%w: invalid ControlPersist %q: %w", ErrSchemaValidation, ctrl.Persist, err)
		}
	}

	// 3. Validate Path syntax & tokens
	if ctrl.Path != "" && ctrl.Path != "none" {
		if err := ValidateControlPathSyntax(ctrl.Path); err != nil {
			return fmt.Errorf("%w: invalid ControlPath %q: %w", ErrSchemaValidation, ctrl.Path, err)
		}
	}

	// 4. Cross-field rules
	// Persist specified while Master is explicitly 'no'
	if normMaster == string(ssh.ControlMasterNo) && ctrl.Persist != "" &&
		!strings.EqualFold(ctrl.Persist, "no") && !strings.EqualFold(ctrl.Persist, "false") {
		return fmt.Errorf("%w: ControlPersist %q cannot be specified when ControlMaster is 'no'", ErrSchemaValidation, ctrl.Persist)
	}

	// Path is 'none' while Master is explicitly active
	if ctrl.Path == "none" && isActiveMasterMode(normMaster) {
		return fmt.Errorf("%w: ControlPath cannot be 'none' when ControlMaster is %q", ErrSchemaValidation, ctrl.Master)
	}

	return nil
}

// ValidateControlPathSyntax verifies raw ControlPath string token syntax without environment dependencies.
func ValidateControlPathSyntax(rawPath string) error {
	return ssh.ValidateControlPathSyntax(rawPath)
}

// ValidateEffectiveControl verifies the resolved effective multiplexing configuration for a node.
func ValidateEffectiveControl(ctrl *ssh.ControlConfig) error {
	if ctrl == nil {
		return nil
	}
	normMaster := strings.ToLower(strings.TrimSpace(string(ctrl.Master)))
	if isActiveMasterMode(normMaster) {
		if ctrl.Path == "" || ctrl.Path == "none" {
			return fmt.Errorf("%w: ControlMaster %q requires non-empty ControlPath", ErrSchemaValidation, ctrl.Master)
		}
	}
	return nil
}

func isActiveMasterMode(mode string) bool {
	return mode == string(ssh.ControlMasterYes) ||
		mode == string(ssh.ControlMasterAsk) ||
		mode == string(ssh.ControlMasterAuto) ||
		mode == string(ssh.ControlMasterAutoAsk)
}
