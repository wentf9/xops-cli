package cmd

import (
	"log/slog"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func TestSSHVerboseIndependentInternalLogs(t *testing.T) {
	t.Setenv("XOPS_CONFIG_DIR", t.TempDir())
	previous := logger.LogLevel.Level()
	t.Cleanup(func() { logger.LogLevel.Set(previous) })
	for _, tc := range []struct {
		flags []string
		level slog.Level
	}{
		{[]string{"-v"}, slog.Level(100)},
		{[]string{"-qv"}, slog.Level(100)},
		{[]string{"--log-level=error", "-vvv"}, slog.LevelError},
		{[]string{"--debug", "-q"}, slog.LevelDebug},
	} {
		root := newRootCmd()
		initRootFlags(root)
		command := NewCmdSsh()
		called := false
		command.RunE = func(*cobra.Command, []string) error {
			called = true
			if logger.LogLevel.Level() != tc.level {
				t.Fatalf("flags %v changed internal log level", tc.flags)
			}
			return nil
		}
		root.AddCommand(command)
		root.SetArgs(append([]string{"ssh"}, tc.flags...))
		if err := root.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !called {
			t.Fatal("ssh -v was consumed as root version")
		}
	}
}
