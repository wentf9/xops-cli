package ssh

import (
	"os"
	"path/filepath"
	"strings"

	core "github.com/wentf9/xops-cli/core/ssh"
)

// defaultEnvironment preserves CLI discovery at the compatibility boundary.
func defaultEnvironment() core.Environment {
	userDirectory, err := os.UserHomeDir()
	environment := core.Environment{
		InitializationError: err,
		AgentSocket:         os.Getenv("SSH_AUTH_SOCK"),
		InteractiveIO:       core.InteractiveIO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
		InputBridge:         platformInputBridge(),
	}
	if userDirectory != "" {
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
	}
	return environment
}
