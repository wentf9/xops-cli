package sshenv

import "testing"

func TestConsoleOutputRelayRequiresExplicitArgument(t *testing.T) {
	t.Setenv("XOPS_WINDOWS_CONSOLE_OUTPUT_RELAY", "invalid")
	for _, args := range [][]string{nil, {"--help"}, {"ssh", "host"}} {
		if _, handled := ServeConsoleOutputRelay(args); handled {
			t.Fatalf("normal arguments dispatched relay: %v", args)
		}
	}
	for _, args := range [][]string{{consoleOutputRelayArgument}, {consoleOutputRelayArgument, "invalid", "extra"}, {consoleOutputRelayArgument, "invalid"}} {
		if code, handled := ServeConsoleOutputRelay(args); !handled || code == 0 {
			t.Fatalf("invalid private invocation accepted: %v: %d %v", args, code, handled)
		}
	}
}
