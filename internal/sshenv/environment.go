package sshenv

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
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
		AgentSocket:         defaultAgentSocket(),
		InteractiveIO:       core.InteractiveIO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr},
		InputBridge:         platformInputBridge(),
		HomeDir:             userDirectory,
		LocalUser:           localUser,
		LocalHost:           hostname,
		LocalUID:            localUID,
		LookupEnv:           os.LookupEnv,
		Environ:             os.Environ,
		SuspendProcess:      platformSuspendProcess(),
		DialAgent:           platformDialAgent(),
		// Global files are read-only verification sources; missing files are skipped.
		GlobalKnownHostsFiles: defaultGlobalKnownHostsFiles(),
		// Only consulted when VerifyHostKeyDNS=yes|ask.
		LookupSSHFP: newSystemSSHFPLookup(),
	}
	if userDirectory != "" {
		environment.KnownHostsFile = filepath.Join(userDirectory, ".ssh", "known_hosts")
		environment.ResolveKeyPath = func(path string) string {
			if path == "~" {
				return userDirectory
			}
			if strings.HasPrefix(path, "~/") {
				return filepath.Join(userDirectory, path[2:])
			}
			if runtime.GOOS == "windows" && strings.HasPrefix(path, `~\`) {
				return filepath.Join(userDirectory, path[2:])
			}
			return path
		}
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa", "id_dsa"} {
			environment.DefaultKeyPaths = append(environment.DefaultKeyPaths, filepath.Join(userDirectory, ".ssh", name))
		}
	}
	return environment
}
