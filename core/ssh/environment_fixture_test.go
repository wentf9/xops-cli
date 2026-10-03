package ssh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Historical SSH fixtures set HOME/USERPROFILE to test-owned directories.
// Resolve those fixture inputs here; production core never discovers them.
func fixtureEnvironment() Environment {
	userDirectory, err := os.UserHomeDir()
	environment := Environment{
		InitializationError: err,
		AgentSocket:         os.Getenv("SSH_AUTH_SOCK"),
		InteractiveIO:       InteractiveIO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
	}
	if err != nil {
		return environment
	}
	environment.KnownHostsFile = filepath.Join(userDirectory, ".ssh", "known_hosts")
	environment.ResolveKeyPath = func(path string) string {
		if strings.HasPrefix(path, "~") {
			return filepath.Join(userDirectory, path[1:])
		}
		return path
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"} {
		environment.DefaultKeyPaths = append(environment.DefaultKeyPaths, filepath.Join(userDirectory, ".ssh", name))
	}
	return environment
}

func newTestConnector(provider ConnectionProvider, opts ...Option) *Connector {
	return NewConnector(provider, append([]Option{WithEnvironment(fixtureEnvironment())}, opts...)...)
}

func buildTestAutoAuthPlan(ctx context.Context, options AutoAuthOptions) autoAuthPlan {
	environment := fixtureEnvironment()
	options.AgentSocket = environment.AgentSocket
	options.DefaultKeyPaths = environment.DefaultKeyPaths
	options.ResolveKeyPath = environment.ResolveKeyPath
	return buildAutoAuthPlan(ctx, options)
}
