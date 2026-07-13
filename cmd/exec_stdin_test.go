package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
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
	_, _ = w.Write([]byte(expectedCmd))
	_ = w.Close()

	o := NewExecOptions()
	cmd := &cobra.Command{}

	// 在没有指定 Command 和 ShellFile，且 args 不包含命令时，
	// 执行 Complete 应该自动从 stdin 读取内容并标记为 stdinScript
	args := []string{"host-01"}
	o.Complete(cmd, args)

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

	_, _ = w.Write([]byte("stdin command should be ignored"))
	_ = w.Close()

	o := NewExecOptions()
	cmd := &cobra.Command{}

	// 参数中明确提供了命令 "uname -a"
	args := []string{"host-01", "uname -a"}
	o.Complete(cmd, args)

	if o.Command != "uname -a" {
		t.Errorf("expected Command to be %q, got %q", "uname -a", o.Command)
	}
	if o.stdinScript {
		t.Error("expected stdinScript to be false when command is provided in args")
	}
}

func TestExecCommandWithFlagsNotParsedAsXopsFlags(t *testing.T) {
	c := NewCmdExec()
	args := []string{"host-01", "ss", "-tlpn"}
	err := c.Flags().Parse(args)
	if err != nil {
		t.Fatalf("expected Parse to succeed with interspersed false, got error: %v", err)
	}

	parsedArgs := c.Flags().Args()
	expected := []string{"host-01", "ss", "-tlpn"}
	if len(parsedArgs) != len(expected) {
		t.Fatalf("expected %d arguments, got %d (%v)", len(expected), len(parsedArgs), parsedArgs)
	}
	for i, v := range expected {
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
	provider := config.NewProvider(cfg)

	o := NewExecOptions()
	o.Host = "non-existing-host-12345"
	o.Command = "ls"

	// 1. 调用 buildTasksFromHosts，这会在内存中临时注册该节点
	tasks, err := o.buildTasksFromHosts(provider)
	if err != nil {
		t.Fatalf("expected buildTasksFromHosts to succeed, got: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	nodeID := tasks[0].nodeID

	// 验证它目前确实在临时内存注册了
	if _, ok := provider.GetNode(nodeID); !ok {
		t.Fatal("expected temporary node to be registered in provider before cleaning")
	}

	// 2. 调用 cleanUnusedTempNodes，由于它从未连接成功验证，应当被清理删除
	o.cleanUnusedTempNodes(provider)

	// 验证该节点已经被从 provider 中完全清除
	if _, ok := provider.GetNode(nodeID); ok {
		t.Error("expected temporary node to be removed from provider after cleanUnusedTempNodes")
	}

	// 3. 验证如果连接成功了（即从 tempNodes 移除了），它不应该被清理
	tasks, _ = o.buildTasksFromHosts(provider)
	newNodeID := tasks[0].nodeID

	o.verifyTempNode(newNodeID) // 模拟连接成功将其验证并保留
	o.cleanUnusedTempNodes(provider)

	if _, ok := provider.GetNode(newNodeID); !ok {
		t.Error("expected successfully connected temporary node to remain in provider after cleanUnusedTempNodes")
	}
}

func TestExecHasChangesDetection(t *testing.T) {
	// 1. 验证没有任何变更时，hasChanges 应返回 false
	o := NewExecOptions()
	if o.hasChanges() {
		t.Error("expected hasChanges to be false initially")
	}

	// 2. 验证当有已有节点被更新时，hasChanges 返回 true
	o2 := NewExecOptions()
	o2.nodeUpdated = true
	if !o2.hasChanges() {
		t.Error("expected hasChanges to be true when nodeUpdated is true")
	}

	// 3. 验证当有成功连接的临时节点被添加时，hasChanges 返回 true
	o3 := NewExecOptions()
	o3.addTempNode("temp-01")
	o3.verifyTempNode("temp-01") // 模拟连接成功
	if !o3.hasChanges() {
		t.Error("expected hasChanges to be true when savedTempNodes > 0")
	}

	// 4. 验证当有临时节点但全部连接失败被清理后，hasChanges 依然返回 false
	o4 := NewExecOptions()
	o4.addTempNode("temp-02")
	// 模拟清理（不调用 verifyTempNode 而是直接 cleanUnusedTempNodes）
	// 这时 savedTempNodes 为 0，nodeUpdated 为 false
	if o4.hasChanges() {
		t.Error("expected hasChanges to be false when temporary nodes are not verified")
	}
}
