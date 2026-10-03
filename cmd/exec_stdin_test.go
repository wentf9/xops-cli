package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestExecStdinRedirection(t *testing.T) {
	// 创建管道模拟 stdin 输入
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	expectedCmd := "echo 'hello world' && hostname"
	if _, err := w.Write([]byte(expectedCmd)); err != nil {
		t.Fatalf("write pipe failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	o := NewExecOptions()
	cmd := &cobra.Command{}

	// 在没有指定 Command 和 ShellFile，且 args 不包含命令时，
	// 执行 Complete 应该自动从 stdin 读取内容并标记为 stdinScript
	args := []string{"host-01"}
	if err := o.Complete(cmd, args); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if o.Command != expectedCmd {
		t.Errorf("expected Command to be %q, got %q", expectedCmd, o.Command)
	}
	if !o.stdinScript {
		t.Error("expected stdinScript to be true")
	}
}

func TestExecStdinIgnoredWhenCmdProvided(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	os.Stdin = r

	if _, err := w.Write([]byte("stdin command should be ignored")); err != nil {
		t.Fatalf("write pipe failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	o := NewExecOptions()
	cmd := &cobra.Command{}

	// 参数中明确提供了命令 "uname -a"
	args := []string{"host-01", "uname -a"}
	if err := o.Complete(cmd, args); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if o.Command != "uname -a" {
		t.Errorf("expected Command to be %q, got %q", "uname -a", o.Command)
	}
	if o.stdinScript {
		t.Error("expected stdinScript to be false when command is provided in args")
	}
}

func TestExecCommandWithFlagsNotParsedAsXopsFlags(t *testing.T) {
	c := NewCmdExec()
	// 模拟用户在子命令 exec 之后的输入参数：host-01 ss -tlpn
	args := []string{"host-01", "ss", "-tlpn"}
	processed := preprocessSubArgs(args, c)

	// 验证确实在 host 后面插入了 "--"
	expectedProcessed := []string{"host-01", "--", "ss", "-tlpn"}
	if len(processed) != len(expectedProcessed) {
		t.Fatalf("expected processed len %d, got %d", len(expectedProcessed), len(processed))
	}
	for i, v := range expectedProcessed {
		if processed[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, processed[i])
		}
	}

	// 验证经过预处理的参数传递给 Cobra 解析后，能够正常保留所有位置参数
	err := c.Flags().Parse(processed)
	if err != nil {
		t.Fatalf("expected Parse to succeed after preprocessing, got error: %v", err)
	}

	parsedArgs := c.Flags().Args()
	expectedArgs := []string{"host-01", "ss", "-tlpn"}
	if len(parsedArgs) != len(expectedArgs) {
		t.Fatalf("expected %d arguments, got %d (%v)", len(expectedArgs), len(parsedArgs), parsedArgs)
	}
	for i, v := range expectedArgs {
		if parsedArgs[i] != v {
			t.Errorf("at index %d: expected %q, got %q", i, v, parsedArgs[i])
		}
	}
}

func TestExecNonExistingNodeNotPersisted(t *testing.T) {
	// 创建临时的内存 Provider
	cfg := &config.Configuration{
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "config.key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("initialize test configuration: %v", err)
	}
	provider, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("create test repository: %v", err)
	}

	o := NewExecOptions()
	o.Host = "non-existing-host-12345"
	o.Command = "ls"

	// 1. 调用 buildTasksFromHosts，这会在内存中临时注册该节点
	tasks, _, err := o.buildTasksFromHosts(context.Background(), provider)
	if err != nil {
		t.Fatalf("expected buildTasksFromHosts to succeed, got: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	nodeID := tasks[0].nodeID

	// Preparation must be usable for connection but absent from saved assets.
	if _, err := provider.ResolveConnection(nodeID); err != nil {
		t.Fatalf("resolve pending connection: %v", err)
	}
	if _, ok := provider.GetNode(nodeID); ok {
		t.Fatal("pending node was published before authentication")
	}
	disk, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Nodes.Keys()) != 0 || len(disk.Hosts.Keys()) != 0 || len(disk.Identities.Keys()) != 0 {
		t.Fatal("preparation persisted connection entities")
	}
	if err := provider.ConfirmNodeContext(t.Context(), nodeID); err != nil {
		t.Fatalf("confirm authenticated connection: %v", err)
	}
	disk, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := disk.Nodes.Get(nodeID); !ok {
		t.Fatal("authenticated node was not saved")
	}
}

func TestExec_InvalidAddressArgs(t *testing.T) {
	o := NewExecOptions()
	err := o.Complete(nil, []string{"user@host:badport", "echo hello"})
	if err == nil {
		t.Fatal("expected error for invalid host port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid host address") {
		t.Errorf("expected invalid host address error, got: %v", err)
	}
}
