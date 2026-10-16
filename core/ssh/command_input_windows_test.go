//go:build windows

package ssh

import (
	"errors"
	"io"
	"os"
	"testing"
)

func TestWindowsCommandFileInputRejectedBeforeStart(t *testing.T) {
	for _, mode := range []string{"command", "legacy command", "shell", "legacy shell", "typed nil bridge"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			scenario := &commandFixture{requestTypes: make(chan string, 10)}
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("command", CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "shell":
				err = client.RunShellWithoutPTY(t.Context(), reader, io.Discard, io.Discard)
			case "legacy shell":
				err = client.RunShellWithIO(t.Context(), reader, io.Discard, io.Discard)
			case "legacy command":
				err = client.RunCommandWithIO(t.Context(), "command", false, reader, io.Discard, io.Discard)
			default:
				if mode == "typed nil bridge" {
					var bridge *privilegeInputBridge
					client.environment.InputBridge = bridge
				}
				err = client.RunCommandPlanWithIO(t.Context(), plan, reader, io.Discard, io.Discard)
			}
			if !errors.Is(err, ErrInteractionRequired) {
				t.Fatalf("input guard lost: %v", err)
			}
			if scenario.attempts.Load() != 0 || len(scenario.requestTypes) != 0 {
				t.Fatal("remote work started before input validation")
			}
		})
	}
}
