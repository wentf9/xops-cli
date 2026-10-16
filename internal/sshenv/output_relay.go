package sshenv

const consoleOutputRelayArgument = "--xops-console-output-relay"

// ServeConsoleOutputRelay is called explicitly at the CLI entry point, before
// normal command startup. Environment variables never select this private mode.
func ServeConsoleOutputRelay(args []string) (code int, handled bool) {
	if len(args) == 0 || args[0] != consoleOutputRelayArgument {
		return 0, false
	}
	if len(args) != 2 {
		return 2, true
	}
	return platformServeConsoleOutputRelay(args[1]), true
}
