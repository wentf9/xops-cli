package sshenv

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	core "github.com/wentf9/xops-cli/core/ssh"
)

// Discover selects the local SSH resources used by the CLI.
// Callers explicitly inject the result into core/ssh with WithEnvironment.
func Discover() core.Environment {
	userDirectory, err := os.UserHomeDir()
	currentUser, _ := user.Current()
	hostname, _ := os.Hostname()

	localUser := ""
	localUID := ""
	if currentUser != nil {
		localUser = currentUser.Username
		localUID = currentUser.Uid
		if userDirectory == "" {
			userDirectory = currentUser.HomeDir
		}
	} else {
		localUser = os.Getenv("USER")
		if localUser == "" {
			localUser = os.Getenv("USERNAME")
		}
	}

	environment := core.Environment{
		InitializationError: err,
		AgentSocket:         os.Getenv("SSH_AUTH_SOCK"),
		InteractiveIO:       core.InteractiveIO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
		InputBridge:         platformInputBridge(),
		HomeDir:             userDirectory,
		LocalUser:           localUser,
		LocalHost:           hostname,
		LocalUID:            localUID,
		LookupEnv:           os.LookupEnv,
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
