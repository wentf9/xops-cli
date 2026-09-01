package cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/firewall"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func createTestConfigStore(t *testing.T) (string, string) {
	t.Helper()
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")
	keyPath := filepath.Join(tmpDir, ".key")

	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "192.168.1.1:22",
		IdentityRef: "root@192.168.1.1",
		Tags:        []string{"web"},
		Alias:       []string{"alias-conflict"},
	})
	cfg.Hosts.Set("192.168.1.1:22", models.Host{
		Address: "192.168.1.1",
		Port:    22,
	})
	cfg.Identities.Set("root@192.168.1.1", models.Identity{
		User: "root",
	})

	if err := store.Save(cfg); err != nil {
		t.Fatalf("save test config failed: %v", err)
	}
	return cfgPath, keyPath
}

func TestExec_EmptyTasks_ReturnsErrorAndNoPanic(t *testing.T) {
	cfgPath, keyPath := createTestConfigStore(t)
	t.Setenv("XOPS_CONFIG_PATH", cfgPath)
	t.Setenv("XOPS_KEY_PATH", keyPath)

	opts := &ExecOptions{
		SshOptions: SshOptions{
			Command: "echo hi",
		},
		Tag:         "non-existent-tag",
		Interactive: true,
	}

	err := opts.Run()
	if err == nil {
		t.Fatal("expected error when no targets match, got nil")
	}
	if !strings.Contains(err.Error(), "no target nodes") && !strings.Contains(err.Error(), "no nodes found") && !strings.Contains(err.Error(), "tag") {
		t.Errorf("expected target resolution error message, got: %v", err)
	}
}

func TestExec_BuildTasksFromHosts_PartialErrorsCollected(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "192.168.1.1:22",
		IdentityRef: "root@192.168.1.1",
		Alias:       []string{"existing-alias"},
	})
	cfg.Hosts.Set("192.168.1.1:22", models.Host{Address: "192.168.1.1", Port: 22})
	cfg.Identities.Set("root@192.168.1.1", models.Identity{User: "root"})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "config.key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("initialize test configuration: %v", err)
	}
	provider, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("create test repository: %v", err)
	}

	// 传入包含主机的选项，且设置冲突别名
	opts := &ExecOptions{
		SshOptions: SshOptions{
			Host:  "valid-host.local",
			Alias: "existing-alias", // 会导致该节点解析产生别名冲突错误
		},
	}

	tasks, hostErrs, err := opts.buildTasksFromHosts(context.Background(), provider)
	if err != nil {
		t.Fatalf("buildTasksFromHosts unexpected error: %v", err)
	}
	if len(tasks) != 0 {
		t.Fatalf("expected 0 task generated due to alias conflict, got %d", len(tasks))
	}
	if len(hostErrs) != 1 {
		t.Fatalf("expected 1 host resolution error collected, got %d", len(hostErrs))
	}
}

func TestFirewall_RunRemoteFirewalls_EmptyTargetsReturnsError(t *testing.T) {
	cfgPath, keyPath := createTestConfigStore(t)
	t.Setenv("XOPS_CONFIG_PATH", cfgPath)
	t.Setenv("XOPS_KEY_PATH", keyPath)

	opts := &FirewallOptions{
		SshOptions: SshOptions{
			Tags: []string{"non-existent-tag"},
		},
	}

	err := opts.runRemoteFirewalls(context.Background(), func(fw firewall.Firewall) (string, error) {
		return "ok", nil
	})

	if err == nil {
		t.Fatal("expected error when remote tags match 0 nodes, got nil")
	}
}
