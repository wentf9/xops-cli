package ssh

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type privilegeBridgeContextKey struct{}

type privilegeInputBridge struct {
	ctx    context.Context
	stdin  *os.File
	closed atomic.Int32
}

func (b *privilegeInputBridge) Start(ctx context.Context, streams InteractiveIO, dst io.Writer) (InputCopy, error) {
	b.ctx, b.stdin = ctx, streams.Stdin
	_, err := io.Copy(dst, streams.Stdin)
	if err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	done <- nil
	return NewInputCopy(ctx, func() error { b.closed.Add(1); return nil }, done)
}

func TestPrivilegeExecutionUsesInjectedInputBridge(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		for _, interactive := range []bool{false, true} {
			name := string(mode)
			if interactive {
				name += "-interactive"
			}
			t.Run(name, func(t *testing.T) {
				setTestHome(t)
				const payload = "first-input"
				addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", inputBytes: len(payload)})
				client := exchangeTestClient(t, addr, mode, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
				inputPath := filepath.Join(t.TempDir(), "input")
				if err := os.WriteFile(inputPath, []byte(payload), 0600); err != nil {
					t.Fatal(err)
				}
				input, err := os.Open(inputPath)
				if err != nil {
					t.Fatal(err)
				}
				defer closePrivilegeTestResource(t, input)
				bridge := &privilegeInputBridge{}
				client.environment.InputBridge = bridge
				var terminal *privilegeTerminal
				if interactive {
					terminal = &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptoSSH.Session) (func() error, error) {
						return func() error { return nil }, nil
					}}
				}
				ctx, cancel := context.WithTimeout(context.WithValue(t.Context(), privilegeBridgeContextKey{}, "operation"), 3*time.Second)
				defer cancel()
				if err := client.runPrivilegeOperation(ctx, mode, "command", input, io.Discard, io.Discard, terminal); err != nil {
					t.Fatal(err)
				}
				if bridge.ctx == nil || bridge.stdin != input {
					t.Fatal("privileged file input bypassed the injected bridge")
				}
				if bridge.ctx.Value(privilegeBridgeContextKey{}) != "operation" {
					t.Fatal("input bridge lost operation context")
				}
				deadline, ok := bridge.ctx.Deadline()
				want, _ := ctx.Deadline()
				if !ok || deadline.After(want) || bridge.ctx.Err() == nil {
					t.Fatal("input bridge did not retain the operation lifetime")
				}
				if bridge.closed.Load() != 1 {
					t.Fatalf("input copy closed %d times", bridge.closed.Load())
				}
				if _, err := input.Stat(); err != nil {
					t.Fatalf("borrowed input was closed: %v", err)
				}
				if got := <-evidence.input; got != payload {
					t.Fatalf("remote input = %q", got)
				}
			})
		}
	}
}
