package playbook

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func replyLazyProbe(t *testing.T, command string, ch cryptoSSH.Channel) bool {
	t.Helper()
	output := ""
	if strings.Contains(command, "__XOPS_DIALECT_POSIX__") {
		output = "__XOPS_DIALECT_POSIX__:Linux:/bin/ash\n"
	} else if strings.Contains(command, "__XOPS_INTERP__") {
		output = "__XOPS_INTERP__:sh\n__XOPS_INTERP_END__\n"
	}
	if output == "" {
		return false
	}
	writeLazyResult(t, ch, output, 0)
	return true
}

func writeLazyResult(t *testing.T, ch cryptoSSH.Channel, output string, code uint32) {
	t.Helper()
	if _, err := io.WriteString(ch, output); err != nil {
		t.Error(err)
	}
	if _, err := ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{code})); err != nil {
		t.Error(err)
	}
}

func TestLazyScriptAndEnsureShareProbeWithoutChangingCommands(t *testing.T) {
	var checks atomic.Int32
	var actions atomic.Int32
	client, server := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
		if replyLazyProbe(t, command, ch) {
			return
		}
		if strings.Contains(command, "__XOPS_ENSURE_") {
			if !strings.HasPrefix(command, "sh -c ") {
				t.Error("ensure did not select detected sh adapter")
			}
			marker := regexp.MustCompile(`__XOPS_ENSURE_[a-zA-Z0-9]+__`).FindString(command)
			code := uint32(1)
			if checks.Add(1) > 1 {
				code = 0
			}
			writeLazyResult(t, ch, marker+":"+map[uint32]string{0: "0", 1: "1"}[code]+"\n", code)
			return
		}
		if command == "sh -s" {
			if _, err := io.Copy(io.Discard, ch); err != nil {
				t.Error(err)
			}
		} else if strings.Contains(command, "repair") {
			actions.Add(1)
			if !strings.HasPrefix(command, "sh -c ") {
				t.Error("ensure action lost its controlled adapter")
			}
		} else if command != "echo ordinary" {
			t.Errorf("unexpected command %q", command)
		}
		writeLazyResult(t, ch, "done", 0)
	})
	engine := &Engine{}
	path := filepath.Join(t.TempDir(), "script.sh")
	if err := os.WriteFile(path, []byte("echo script\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := engine.runScript(t.Context(), client, path, nil, false, models.Node{})
	if result.Status != StatusChanged {
		t.Fatalf("lazy script failed: %+v", result)
	}
	result = engine.runEnsure(t.Context(), client, &EnsureSpec{Check: "check", Action: "repair"}, nil, false, models.Node{})
	if result.Status != StatusChanged || actions.Load() != 1 || checks.Load() != 2 {
		t.Fatalf("lazy ensure failed or repeated action: %+v", result)
	}
	result = engine.runShell(t.Context(), client, "echo ordinary", nil, false, models.Node{})
	if result.Status == StatusFailed || server.Executed.Load() != 7 || client.Execution() != nil {
		t.Fatalf("ordinary command defaults or probe cache changed: %+v, requests %d", result, server.Executed.Load())
	}
}

func TestLazyProbeFailureNeverExecutesOrRetriesUserWork(t *testing.T) {
	client, server := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
		if strings.Contains(command, "__XOPS_INTERP__") {
			t.Error("interpreter enumeration started without detecting a dialect")
		}
		writeLazyResult(t, ch, "restricted\n", 0)
	})
	engine := &Engine{}
	for range 2 {
		result := engine.runEnsure(context.Background(), client, &EnsureSpec{Check: "check", Action: "must not run"}, nil, false, models.Node{})
		if result.Status != StatusFailed || result.Outcome != ssh.ExecutionNotStarted || result.Retryable {
			t.Fatalf("failed probe authorized user work: %+v", result)
		}
	}
	if server.Executed.Load() != 3 {
		t.Fatal("failed probe was repeated or user work was sent")
	}
}

func TestLazyScriptHonorsInvalidBodiesAndExplicitServer(t *testing.T) {
	for _, tt := range []struct {
		body      string
		execution *ssh.ExecutionConfig
	}{
		{"#!/bin/bash\necho hi", nil}, // A shebang alone still cannot establish an outer dialect.
		{"#!/usr/bin/python3\nprint(1)", nil},
		{"\xef\xbb\xbfecho hi", nil},
		{"echo hi", &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer}},
	} {
		engine := &Engine{scriptSources: map[string][]byte{"script": []byte(tt.body)}}
		result := engine.runScript(t.Context(), nil, "script", tt.execution, false, models.Node{})
		if result.Outcome != ssh.ExecutionNotStarted || !errors.Is(result.Err, ssh.ErrExecutionValidation) {
			t.Fatalf("invalid or explicit script was probed/executed: %+v", result)
		}
	}
}

func TestLazyWindowsProbeRejectsPOSIXScriptAndEnsure(t *testing.T) {
	client, server := executionTestClient(t, func(command string, ch cryptoSSH.Channel) {
		switch {
		case strings.Contains(command, "__XOPS_DIALECT_POSIX__"):
			writeLazyResult(t, ch, "syntax error\n", 1)
		case strings.HasPrefix(command, "echo __XOPS_DIALECT_CMD__:"):
			writeLazyResult(t, ch, "__XOPS_DIALECT_CMD__:C:\\Windows\\system32\\cmd.exe\n", 0)
		case strings.Contains(command, "__XOPS_INTERP__"):
			writeLazyResult(t, ch, "__XOPS_INTERP__:powershell\n__XOPS_INTERP__:cmd\n__XOPS_INTERP_END__\n", 0)
		default:
			t.Error("POSIX user code was sent to Windows")
			writeLazyResult(t, ch, "", 1)
		}
	})
	engine := &Engine{scriptSources: map[string][]byte{"script": []byte("echo script")}}
	ensure := engine.runEnsure(t.Context(), client, &EnsureSpec{Check: "check", Action: "repair"}, nil, false, models.Node{})
	script := engine.runScript(t.Context(), client, "script", nil, false, models.Node{})
	for _, result := range []StepResult{ensure, script} {
		if result.Outcome != ssh.ExecutionNotStarted || !errors.Is(result.Err, ssh.ErrExecutionValidation) {
			t.Fatalf("Windows probe authorized POSIX operation: %+v", result)
		}
	}
	if server.Executed.Load() != 3 {
		t.Fatal("probe repeated or user work was sent")
	}
}
