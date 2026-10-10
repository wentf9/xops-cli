package tui

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestLogSelectModel_RejectsNonPOSIXExecution(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterPowerShell,
			LaunchDialect: ssh.LaunchPowerShell,
		},
	}
	client := ssh.NewTestClient(connCfg)
	model := newLogSelectModel(context.Background(), "node-1", client, tea.WindowSizeMsg{Width: 80, Height: 24})

	cmd := model.scanLogs()
	if cmd == nil {
		t.Fatal("expected non-nil cmd from model.scanLogs()")
	}
	msg := cmd()
	scanMsg, ok := msg.(logScanResultMsg)
	if !ok {
		t.Fatalf("expected logScanResultMsg, got %T", msg)
	}
	if scanMsg.err == nil {
		t.Fatal("expected error for non-POSIX execution config, got nil")
	}
	if !strings.Contains(scanMsg.err.Error(), "Linux/POSIX") {
		t.Errorf("expected Linux/POSIX requirement error, got: %v", scanMsg.err)
	}
}

func TestLogStreamerModel_RejectsNonPOSIXExecution(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterCmd,
			LaunchDialect: ssh.LaunchCmd,
		},
	}
	client := ssh.NewTestClient(connCfg)
	model := newLogStreamerModel(context.Background(), 1, client, "/var/log/syslog", tea.WindowSizeMsg{Width: 80, Height: 24})

	cmd := model.startStream()
	if cmd == nil {
		t.Fatal("expected non-nil cmd from model.startStream()")
	}
	msg := cmd()
	closedMsg, ok := msg.(logStreamClosedMsg)
	if !ok {
		t.Fatalf("expected logStreamClosedMsg, got %T", msg)
	}
	if closedMsg.err == nil {
		t.Fatal("expected error for non-POSIX execution config, got nil")
	}
	if !strings.Contains(closedMsg.err.Error(), "Linux/POSIX") {
		t.Errorf("expected Linux/POSIX requirement error, got: %v", closedMsg.err)
	}
}
