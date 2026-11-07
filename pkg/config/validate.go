package config

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/core/ssh"
)

// DefaultControlPath specifies the standard OpenSSH multiplexing socket pattern.
const DefaultControlPath = "~/.ssh/cm-%r@%h:%p"

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
	if rawPath == "" || rawPath == "none" {
		return nil
	}

	// Check environment variable format ${VAR}
	if strings.Contains(rawPath, "${") {
		idx := 0
		for {
			start := strings.Index(rawPath[idx:], "${")
			if start == -1 {
				break
			}
			start += idx
			end := strings.Index(rawPath[start:], "}")
			if end == -1 {
				return fmt.Errorf("unclosed environment variable in ControlPath: %q", rawPath[start:])
			}
			end += start
			varName := rawPath[start+2 : end]
			if varName == "" || !isValidEnvVarIdentifier(varName) {
				return fmt.Errorf("invalid environment variable name ${%s} in ControlPath", varName)
			}
			idx = end + 1
		}
	}

	// Check % tokens
	for i := 0; i < len(rawPath); i++ {
		if rawPath[i] == '%' {
			if i+1 >= len(rawPath) {
				return fmt.Errorf("trailing '%%' in ControlPath")
			}
			i++
			switch rawPath[i] {
			case '%', 'h', 'p', 'r', 'n', 'u', 'l', 'L', 'i', 'd', 'j', 'C':
				// Valid OpenSSH tokens
			default:
				return fmt.Errorf("unknown ControlPath token %%%c", rawPath[i])
			}
		}
	}

	return nil
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

func isValidEnvVarIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '_' {
				return false
			}
		} else {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return false
			}
		}
	}
	return true
}
