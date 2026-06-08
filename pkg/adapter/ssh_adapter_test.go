package adapter

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestSSHAdapter_NonInteractive(t *testing.T) {
	// 创建一个空配置
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	provider := config.NewProvider(cfg)

	// 创建非交互式 adapter
	adp := NewNonInteractiveSSHAdapter(provider)

	// 验证 PromptPassword
	pwd, err := adp.PromptPassword("Enter password:")
	if err == nil {
		t.Error("expected error from PromptPassword in non-interactive mode, got nil")
	}
	if pwd != "" {
		t.Errorf("expected empty password, got %q", pwd)
	}

	// 验证 ConfirmHostKey
	confirmed, err := adp.ConfirmHostKey("127.0.0.1", "sha256-fingerprint")
	if err == nil {
		t.Error("expected error from ConfirmHostKey in non-interactive mode, got nil")
	}
	if confirmed {
		t.Error("expected confirmed to be false in non-interactive mode")
	}
}
