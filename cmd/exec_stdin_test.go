package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
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
