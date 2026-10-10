package sftpshell

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestHandleExec_ServerInterpreterCwdRejection(t *testing.T) {
	connCfg := ssh.ConnectionConfig{
		Execution: &ssh.ExecutionConfig{
			Interpreter:   ssh.InterpreterServer,
			LaunchDialect: ssh.LaunchPOSIX,
		},
	}
	client := ssh.NewTestClient(connCfg)
	var stdout, stderr bytes.Buffer
	s := &Shell{
		batch:     true,
		cwd:       "/remote/dir",
		sshClient: client,
		stdout:    &stdout,
		stderr:    &stderr,
	}

	err := s.handleExec(context.Background(), []string{"ls", "-la"})
	if err == nil {
		t.Fatal("expected handleExec to reject non-root cwd with server interpreter, got nil")
	}
	if !strings.Contains(err.Error(), "server interpreter does not support inheriting working directory") {
		t.Errorf("error %q does not mention server interpreter inheritance", err.Error())
	}
}

func TestHandleExec_EmptyArgsError(t *testing.T) {
	s := &Shell{}
	err := s.handleExec(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on empty args, got nil")
	}
}
