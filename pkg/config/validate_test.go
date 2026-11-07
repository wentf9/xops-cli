package config

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestValidateControlConfig_Valid(t *testing.T) {
	tests := []struct {
		name string
		ctrl *ssh.ControlConfig
	}{
		{"nil", nil},
		{"empty", &ssh.ControlConfig{}},
		{"master_no", &ssh.ControlConfig{Master: ssh.ControlMasterNo}},
		{"master_yes_with_path", &ssh.ControlConfig{Master: ssh.ControlMasterYes, Path: "~/.ssh/cm-%h"}},
		{"master_auto_with_persist", &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/sock", Persist: "10m"}},
		{"master_ask", &ssh.ControlConfig{Master: ssh.ControlMasterAsk, Path: "/tmp/sock", Persist: "1h30m"}},
		{"master_autoask", &ssh.ControlConfig{Master: ssh.ControlMasterAutoAsk, Path: "/tmp/sock", Persist: "0"}},
		{"path_none_master_no", &ssh.ControlConfig{Master: ssh.ControlMasterNo, Path: "none"}},
		{"path_with_env_var", &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "${XDG_RUNTIME_DIR}/ssh-%C.sock"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateControlConfig(tc.ctrl); err != nil {
				t.Fatalf("expected valid, got: %v", err)
			}
		})
	}
}

func TestValidateControlConfig_InvalidMaster(t *testing.T) {
	invalids := []string{"invalid", "maybe", "123", "none"}
	for _, inv := range invalids {
		ctrl := &ssh.ControlConfig{Master: ssh.ControlMasterMode(inv)}
		err := ValidateControlConfig(ctrl)
		if err == nil {
			t.Fatalf("expected error for master %q, got nil", inv)
		}
		if !errors.Is(err, ErrSchemaValidation) {
			t.Fatalf("expected error wrapping ErrSchemaValidation, got: %v", err)
		}
	}
}

func TestValidateControlConfig_InvalidPersist(t *testing.T) {
	invalids := []string{"10x", "-5m", "invalid", "0m"}
	for _, inv := range invalids {
		ctrl := &ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/sock", Persist: inv}
		err := ValidateControlConfig(ctrl)
		if err == nil {
			t.Fatalf("expected error for persist %q, got nil", inv)
		}
		if !errors.Is(err, ErrSchemaValidation) {
			t.Fatalf("expected error wrapping ErrSchemaValidation, got: %v", err)
		}
	}
}

func TestValidateControlPathSyntax(t *testing.T) {
	// Valid cases
	validPaths := []string{
		"",
		"none",
		"~/.ssh/cm-%r@%h:%p",
		"/tmp/ssh-%u-%h-%p-%n-%l-%L-%i-%d-%j-%C-%%.sock",
		"${HOME}/.ssh/cm-%h",
		"${XDG_RUNTIME_DIR}/ssh-${USER}/sock",
	}
	for _, p := range validPaths {
		if err := ValidateControlPathSyntax(p); err != nil {
			t.Fatalf("path %q should be valid, got: %v", p, err)
		}
	}

	// Invalid trailing percent
	if err := ValidateControlPathSyntax("/tmp/cm-%"); err == nil || !strings.Contains(err.Error(), "trailing '%'") {
		t.Fatalf("expected trailing percent error, got: %v", err)
	}

	// Unknown token
	if err := ValidateControlPathSyntax("/tmp/cm-%z"); err == nil || !strings.Contains(err.Error(), "unknown ControlPath token %z") {
		t.Fatalf("expected unknown token error, got: %v", err)
	}

	// Unclosed env var
	if err := ValidateControlPathSyntax("/tmp/${UNCLOSED/sock"); err == nil || !strings.Contains(err.Error(), "unclosed environment variable") {
		t.Fatalf("expected unclosed env var error, got: %v", err)
	}

	// Invalid env var identifier
	if err := ValidateControlPathSyntax("/tmp/${123BAD}/sock"); err == nil || !strings.Contains(err.Error(), "invalid environment variable name") {
		t.Fatalf("expected invalid env var name error, got: %v", err)
	}
}

func TestValidateControlConfig_CrossFieldRules(t *testing.T) {
	// Rule A: Persist specified when Master is 'no'
	ctrlA := &ssh.ControlConfig{
		Master:  ssh.ControlMasterNo,
		Path:    "/tmp/sock",
		Persist: "10m",
	}
	errA := ValidateControlConfig(ctrlA)
	if errA == nil || !strings.Contains(errA.Error(), "cannot be specified when ControlMaster is 'no'") {
		t.Fatalf("expected persist with master no error, got: %v", errA)
	}

	// Rule B: Path is 'none' when Master is active
	activeModes := []ssh.ControlMasterMode{
		ssh.ControlMasterYes,
		ssh.ControlMasterAsk,
		ssh.ControlMasterAuto,
		ssh.ControlMasterAutoAsk,
	}
	for _, mode := range activeModes {
		ctrlB := &ssh.ControlConfig{
			Master: mode,
			Path:   "none",
		}
		errB := ValidateControlConfig(ctrlB)
		if errB == nil || !strings.Contains(errB.Error(), "ControlPath cannot be 'none' when ControlMaster is") {
			t.Fatalf("expected path none with master %q error, got: %v", mode, errB)
		}
	}
}

func TestValidateEffectiveControl(t *testing.T) {
	// nil is valid
	if err := ValidateEffectiveControl(nil); err != nil {
		t.Fatalf("nil should be valid, got: %v", err)
	}

	// Master no with empty path is valid
	if err := ValidateEffectiveControl(&ssh.ControlConfig{Master: ssh.ControlMasterNo}); err != nil {
		t.Fatalf("master no with empty path should be valid, got: %v", err)
	}

	// Active master with empty path is invalid
	activeModes := []ssh.ControlMasterMode{
		ssh.ControlMasterYes,
		ssh.ControlMasterAsk,
		ssh.ControlMasterAuto,
		ssh.ControlMasterAutoAsk,
	}
	for _, mode := range activeModes {
		ctrlEmpty := &ssh.ControlConfig{Master: mode, Path: ""}
		if err := ValidateEffectiveControl(ctrlEmpty); err == nil || !strings.Contains(err.Error(), "requires non-empty ControlPath") {
			t.Fatalf("mode %q with empty path should fail, got: %v", mode, err)
		}

		ctrlNone := &ssh.ControlConfig{Master: mode, Path: "none"}
		if err := ValidateEffectiveControl(ctrlNone); err == nil || !strings.Contains(err.Error(), "requires non-empty ControlPath") {
			t.Fatalf("mode %q with path none should fail, got: %v", mode, err)
		}

		ctrlValid := &ssh.ControlConfig{Master: mode, Path: "/tmp/valid.sock"}
		if err := ValidateEffectiveControl(ctrlValid); err != nil {
			t.Fatalf("mode %q with valid path should succeed, got: %v", mode, err)
		}
	}
}
