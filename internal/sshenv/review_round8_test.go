package sshenv

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestRound8_P2_5_ResolveKeyPathDoesNotRewriteOtherUserTilde(t *testing.T) {
	t.Parallel()

	env := Discover()
	if env.HomeDir == "" || env.ResolveKeyPath == nil {
		t.Skip("environment has no home directory")
	}

	// Exact "~" and "~/" expand to current user's HomeDir.
	if got := env.ResolveKeyPath("~"); got != env.HomeDir {
		t.Fatalf("ResolveKeyPath(\"~\") = %q, want %q", got, env.HomeDir)
	}
	wantSub := filepath.Join(env.HomeDir, ".ssh/id_ed25519")
	if got := env.ResolveKeyPath("~/.ssh/id_ed25519"); got != wantSub {
		t.Fatalf("ResolveKeyPath(\"~/.ssh/id_ed25519\") = %q, want %q", got, wantSub)
	}

	// "~alice/sock" and "~bob" MUST NOT be rewritten under current user's HomeDir.
	for _, untouched := range []string{"~alice/.ssh/agent.sock", "~bob", "~alice/id_rsa"} {
		if got := env.ResolveKeyPath(untouched); got != untouched {
			t.Fatalf("ResolveKeyPath(%q) = %q, want untouched %q", untouched, got, untouched)
		}
	}

	// On non-Windows, `~\foo` is a literal filename starting with `~`, not home expansion.
	if runtime.GOOS != "windows" {
		if got := env.ResolveKeyPath(`~\foo`); got != `~\foo` {
			t.Fatalf("ResolveKeyPath(`~\\foo`) on %s = %q, want untouched", runtime.GOOS, got)
		}
	}
}

func TestRound8_P3_3_ValidateExecCommandStringRejectsUnicodeControlsAndInvalidUTF8(t *testing.T) {
	t.Parallel()

	if err := validateExecCommandString("nc\t%h %p"); err != nil {
		t.Fatalf("validateExecCommandString unexpectedly rejected valid tab-separated command: %v", err)
	}
	for _, bad := range []string{
		"nc host 22\u0085evil",
		"nc host 22\u2028evil",
		"nc host 22\u2029evil",
		"nc host 22\x1b[31m",
		"nc host 22\x00",
		"nc host 22\n",
		"nc host 22\r",
		"nc \xff\xfe host 22",
		"   ",
		"NONE",
	} {
		if err := validateExecCommandString(bad); err == nil {
			t.Fatalf("validateExecCommandString(%q) unexpectedly succeeded", bad)
		}
	}
}
