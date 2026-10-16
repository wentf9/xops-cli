package ssh

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCommandFileInputHonorsInjectedBridge(t *testing.T) {
	for _, mode := range []string{"command", "legacy command", "shell", "legacy shell"} {
		t.Run(mode, func(t *testing.T) {
			const payload = "bridged stdin"
			path := filepath.Join(t.TempDir(), "input")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			input, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close() }()
			scenario := &commandFixture{inputs: make(chan string, 1), inputBytes: len(payload)}
			client := commandTestClient(t, scenario)
			bridge := &privilegeInputBridge{}
			client.environment.InputBridge = bridge
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			plan, err := PlanCommand("command", CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "command":
				err = client.RunCommandPlanWithIO(ctx, plan, input, io.Discard, io.Discard)
			case "legacy command":
				err = client.RunCommandWithIO(ctx, "command", false, input, io.Discard, io.Discard)
			case "shell":
				err = client.RunShellWithoutPTY(ctx, input, io.Discard, io.Discard)
			case "legacy shell":
				err = client.RunShellWithIO(ctx, input, io.Discard, io.Discard)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := <-scenario.inputs; got != payload {
				t.Fatalf("stdin: %q", got)
			}
			if scenario.attempts.Load() != 1 {
				t.Fatal("command was replayed")
			}
			if bridge.stdin != input || bridge.ctx == nil || bridge.closed.Load() != 1 {
				t.Fatal("injected bridge lifecycle was bypassed")
			}
			if deadline, ok := bridge.ctx.Deadline(); !ok || time.Until(deadline) > 3*time.Second {
				t.Fatal("bridge lost operation deadline")
			}
			if _, err := input.Stat(); err != nil {
				t.Fatalf("borrowed stdin closed: %v", err)
			}
		})
	}
}
