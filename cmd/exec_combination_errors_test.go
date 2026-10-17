package cmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestExecExplicitCombinedStreamCancellation(t *testing.T) {
	for _, script := range []bool{false, true} {
		t.Run(map[bool]string{false: "command", true: "sudo script"}[script], func(t *testing.T) {
			fixtureCtx, connector, server := newExecCombinationFixture(t, func(_ string, channel cryptoSSH.Channel) {
				if script {
					_, _ = io.Copy(io.Discard, channel)
				}
				_, _ = io.WriteString(channel, "output awaiting cancellation")
				_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
			})
			o := NewExecOptions()
			command := newCmdExecWithOptions(o)
			flags := []string{"--host", "fixture", "--interpreter", "sh", "--launch-dialect", "posix", "--stream"}
			if script {
				flags = append(flags, "--sudo", "--shell", "synthetic.sh")
			} else {
				flags = append(flags, "-c", "synthetic")
			}
			if err := command.Flags().Parse(flags); err != nil {
				t.Fatal(err)
			}
			if err := o.Complete(command, nil); err != nil {
				t.Fatal(err)
			}
			o.stdout, o.stderr = blockedExecOutput{}, &bytes.Buffer{}
			ctx, cancel := context.WithTimeout(fixtureCtx, 500*time.Millisecond)
			defer cancel()
			var mu sync.Mutex
			err := o.executeTask(ctx, connector, execHostTask{nodeID: "fixture", host: "fixture"}, "synthetic", script, 1, &mu)
			var outputErr *ssh.OutputError
			if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &outputErr) {
				t.Fatalf("stream cancellation lost: %v", err)
			}
			if server.Executed.Load() != 1 {
				t.Fatalf("command replayed/missing: %d", server.Executed.Load())
			}
		})
	}
}

func TestExecExplicitStdinScriptLimit(t *testing.T) {
	input, err := os.CreateTemp(t.TempDir(), "stdin-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	if err := input.Truncate(ssh.MaxCommandInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = old })
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "sh", "--launch-dialect", "posix"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err == nil || !strings.Contains(err.Error(), "script exceeds") {
		t.Fatalf("oversized stdin script accepted: %v", err)
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("borrowed input closed: %v", err)
	}
}
