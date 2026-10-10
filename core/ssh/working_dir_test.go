package ssh_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestFormatWorkingDirCommand(t *testing.T) {
	tests := []struct {
		name      string
		cwd       string
		command   string
		execution *ssh.ExecutionConfig
		want      string
		wantErr   bool
	}{
		{
			name:      "nil execution defaults to bash cd with quotes and double dash",
			cwd:       "/var/log",
			command:   "ls -la",
			execution: nil,
			want:      "cd -- '/var/log' && ls -la",
		},
		{
			name:      "empty cwd returns command verbatim",
			cwd:       "",
			command:   "ls -la",
			execution: nil,
			want:      "ls -la",
		},
		{
			name:      "cwd with leading dash protected by double dash",
			cwd:       "-strange-dir",
			command:   "echo hi",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash},
			want:      "cd -- '-strange-dir' && echo hi",
		},
		{
			name:      "cwd with single quotes escaped in bash",
			cwd:       "/path/with'quote",
			command:   "pwd",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash},
			want:      "cd -- '/path/with'\\''quote' && pwd",
		},
		{
			name:      "sh interpreter formats posix cd",
			cwd:       "/home/user",
			command:   "whoami",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterSh},
			want:      "cd -- '/home/user' && whoami",
		},
		{
			name:      "server interpreter with root slash succeeds without cd",
			cwd:       "/",
			command:   "uptime",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer},
			want:      "uptime",
		},
		{
			name:      "server interpreter with non-root cwd rejected",
			cwd:       "/var/data",
			command:   "ls",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer},
			wantErr:   true,
		},
		{
			name:      "cmd interpreter formats cd /d",
			cwd:       `C:\Program Files\App`,
			command:   "dir",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterCmd},
			want:      `cd /d "C:\Program Files\App" && dir`,
		},
		{
			name:      "powershell interpreter formats Set-Location with LiteralPath",
			cwd:       `C:\Data[Archive]\Test`,
			command:   "Get-ChildItem",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell},
			want:      "Set-Location -LiteralPath 'C:\\Data[Archive]\\Test' -ErrorAction Stop; Get-ChildItem",
		},
		{
			name:      "pwsh interpreter formats Set-Location with escaped single quotes",
			cwd:       `/opt/dir's/sub`,
			command:   "Get-Date",
			execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPwsh},
			want:      "Set-Location -LiteralPath '/opt/dir''s/sub' -ErrorAction Stop; Get-Date",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ssh.FormatWorkingDirCommand(tc.cwd, tc.command, tc.execution)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (got %q)", got)
				}
				if !errors.Is(err, ssh.ErrExecutionValidation) {
					t.Errorf("expected ErrExecutionValidation, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("FormatWorkingDirCommand = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFormatWorkingDirCommand_ServerRejectionMessage(t *testing.T) {
	cfg := &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}
	_, err := ssh.FormatWorkingDirCommand("/custom/dir", "ls", cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server interpreter does not support inheriting working directory") {
		t.Errorf("error %q does not mention server interpreter inheritance", err.Error())
	}
}
