package sftp

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/peterh/liner"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestDispatchCommand(t *testing.T) {
	i18n.Init("zh")

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// liner.NewLiner() 在非 TTY 环境下可能无法正常工作，
	// 但由于 dispatchCommand 及其调用的具体 Handler 并不直接使用 line 成员（Run 和 askConfirmation 除外），
	// 我们可以在测试中使用一个空的 liner 实例或 nil。
	// 为了安全起见，这里创建一个 liner 实例并确保关闭。
	line := liner.NewLiner()
	defer line.Close()

	tempDir := t.TempDir()
	s := &Shell{
		cwd:      "/test/remote/dir",
		localCwd: tempDir,
		line:     line,
		stdout:   &stdout,
		stderr:   &stderr,
	}

	tests := []struct {
		name       string
		cmd        string
		params     []string
		wantExit   bool
		wantErr    bool
		wantOutput string
	}{
		{"exit command", "exit", nil, true, false, ""},
		{"quit command", "quit", nil, true, false, ""},
		{"bye command", "bye", nil, true, false, ""},
		{"pwd command", "pwd", nil, false, false, "/test/remote/dir\n"},
		{"lpwd command", "lpwd", nil, false, false, tempDir},
		{"help command", "help", nil, false, false, "可用命令:"},
		{"lmkdir command", "lmkdir", []string{"test_dir"}, false, false, ""},
		{"lcp command", "lcp", []string{"test_file", "test_file_cp"}, false, false, ""},
		{"lmv command", "lmv", []string{"test_file_cp", "test_file_mv"}, false, false, ""},
		{"lrm command", "lrm", []string{"test_dir"}, false, false, ""},
		{"unknown command", "unknown_cmd", nil, false, false, "未知命令: unknown_cmd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()

			exit, err := s.dispatchCommand(context.Background(), tt.cmd, tt.params)
			if exit != tt.wantExit {
				t.Errorf("dispatchCommand() exit = %v, want %v", exit, tt.wantExit)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("dispatchCommand() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Validate outputs
			out := stdout.String()
			errout := stderr.String()

			if tt.name == "unknown command" {
				if !strings.Contains(errout, tt.wantOutput) {
					t.Errorf("stderr output = %q, want it to contain %q", errout, tt.wantOutput)
				}
			} else if tt.cmd == "pwd" || tt.cmd == "help" || tt.cmd == "lpwd" {
				if !strings.Contains(out, tt.wantOutput) {
					t.Errorf("stdout output = %q, want it to contain %q", out, tt.wantOutput)
				}
			}
		})
	}
}
