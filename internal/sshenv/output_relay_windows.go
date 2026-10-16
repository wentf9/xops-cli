//go:build windows

package sshenv

import (
	"context"
	"os"

	"github.com/wentf9/xops-cli/core/ssh"
)

// OutputContext explicitly selects this CLI's private relay entry point. The
// returned cleanup owns bindings/processes through command completion. Selecting
// the capability starts no process; the first nonempty write starts the relay.
func OutputContext(ctx context.Context) (context.Context, func() error, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	work, cleanup := ssh.WithConsoleOutputRelay(ctx, ssh.ConsoleOutputRelay{
		Executable: executable,
		Args:       []string{consoleOutputRelayArgument},
		Env:        os.Environ(),
	})
	return work, cleanup, nil
}

func platformServeConsoleOutputRelay(spec string) int {
	return ssh.ServeConsoleOutputRelay(spec)
}
