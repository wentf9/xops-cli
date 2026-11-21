package ssh

import (
	"errors"
	"testing"
)

// TestP7Repro_MED12_ExpandRemoteCommand_HomeAllowlistAndIPv6PercentN reproduces MED-12:
//  1. ExpandRemoteCommand validates %d with a denylist (validateSafeRemoteHomeToken) instead of
//     the shared strict allowlist, permitting spaces, '#', backslashes, and shell globs.
//  2. buildRemoteCommandTokenMap does not strip IPv6 brackets from TargetContext.OriginalHost (%n).
func TestP7Repro_MED12_ExpandRemoteCommand_HomeAllowlistAndIPv6PercentN(t *testing.T) {
	t.Run("percent_d_rejects_shell_unsafe_chars", func(t *testing.T) {
		cases := []struct {
			name    string
			homeDir string
		}{
			{name: "space", homeDir: "/home/alice /etc/passwd"},
			{name: "hash_comment", homeDir: "/home/alice#comment"},
			{name: "backslash", homeDir: `/home/alice\escape`},
			{name: "glob_star", homeDir: "/home/alice/*"},
			{name: "glob_question", homeDir: "/home/alice/?"},
			{name: "glob_brackets", homeDir: "/home/alice/[a-z]"},
		}
		target := TargetContext{Host: "example.com", Port: 22, User: "alice"}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				env := Environment{HomeDir: tc.homeDir, LocalHost: "local", LocalUser: "alice"}
				got, err := ExpandRemoteCommand("cd %d && pwd", env, target)
				if err == nil {
					t.Fatalf("MED-12 reproduced: ExpandRemoteCommand accepted unsafe %%d %q -> %q, want ErrUnsafeExecToken", tc.homeDir, got)
				}
				if !errors.Is(err, ErrUnsafeExecToken) {
					t.Fatalf("ExpandRemoteCommand(%q) error = %v, want ErrUnsafeExecToken", tc.homeDir, err)
				}
			})
		}
	})

	t.Run("percent_n_strips_ipv6_brackets", func(t *testing.T) {
		env := Environment{HomeDir: "/home/alice", LocalHost: "local", LocalUser: "alice"}
		target := TargetContext{
			Host:         "[2001:db8::1]",
			OriginalHost: "[2001:db8::1]",
			Port:         2222,
			User:         "ops",
		}
		got, err := ExpandRemoteCommand("echo %h %n", env, target)
		if err != nil {
			t.Fatalf("ExpandRemoteCommand failed: %v", err)
		}
		const want = "echo 2001:db8::1 2001:db8::1"
		if got != want {
			t.Fatalf("MED-12 reproduced: ExpandRemoteCommand(\"echo %%h %%n\") = %q, want %q (%%n kept IPv6 brackets)", got, want)
		}
	})
}

// TestP7Repro_LOW5_ForwardParsing_AsymmetryBracketsAndEscapedSpace reproduces LOW-5 (forward parts):
// 1) ParseRemoteForwardSpec("sockdir/a:b") rejects a relative socket path containing a colon,
// asymmetrically differing from "/tmp/a:b", "./sockdir/a:b", and ParseDynamicForwardEndpoint("sockdir/a:b").
// 2) unwrapForwardHost accepts arbitrary non-IPv6 hostnames inside brackets such as "[foo]:8080".
// 3) splitForwardFields falls back to strings.Fields when no quotes are present, splitting unquoted
// backslash-escaped spaces such as `/tmp/my\ sock 127.0.0.1:80`.
func TestP7Repro_LOW5_ForwardParsing_AsymmetryBracketsAndEscapedSpace(t *testing.T) {
	t.Run("remote_forward_relative_socket_colon_asymmetry", reproLOW5RemoteForwardSocketAsymmetry)
	t.Run("bracketed_non_ipv6_host_rejected", reproLOW5BracketedNonIPv6HostRejected)
	t.Run("unquoted_backslash_escaped_space", reproLOW5UnquotedBackslashEscapedSpace)
}

func reproLOW5RemoteForwardSocketAsymmetry(t *testing.T) {
	// Precondition: explicit-prefix and dynamic parsers accept relative socket paths with colons.
	if _, err := ParseRemoteForwardSpec("./sockdir/a:b"); err != nil {
		t.Fatalf("precondition failed: ParseRemoteForwardSpec(\"./sockdir/a:b\") = %v", err)
	}
	if _, err := ParseDynamicForwardEndpoint("sockdir/a:b"); err != nil {
		t.Fatalf("precondition failed: ParseDynamicForwardEndpoint(\"sockdir/a:b\") = %v", err)
	}

	for _, input := range []string{"sockdir/a:b", "sockdir/a:b:c"} {
		t.Run(input, func(t *testing.T) {
			spec, err := ParseRemoteForwardSpec(input)
			if err != nil {
				t.Fatalf("LOW-5 reproduced: ParseRemoteForwardSpec(%q) rejected relative socket path with colon: %v", input, err)
			}
			if !spec.IsDynamic || spec.Bind.SocketPath != input {
				t.Fatalf("ParseRemoteForwardSpec(%q) = %+v, want IsDynamic=true Bind.SocketPath=%q", input, spec, input)
			}
		})
	}
}

func reproLOW5BracketedNonIPv6HostRejected(t *testing.T) {
	cases := []struct {
		name string
		run  func() (string, error)
	}{
		{
			name: "ParseForwardSpec_bind",
			run: func() (string, error) {
				s, err := ParseForwardSpec("[foo]:8080 127.0.0.1:80")
				return s.String(), err
			},
		},
		{
			name: "ParseForwardSpec_dest_whitespace",
			run: func() (string, error) {
				s, err := ParseForwardSpec("8080 [foo]:80")
				return s.String(), err
			},
		},
		{
			name: "ParseForwardSpec_dest_colon",
			run: func() (string, error) {
				s, err := ParseForwardSpec("8080:[foo]:80")
				return s.String(), err
			},
		},
		{
			name: "ParseRemoteForwardSpec",
			run: func() (string, error) {
				s, err := ParseRemoteForwardSpec("[foo]:8080")
				return s.String(), err
			},
		},
		{
			name: "ParseDynamicForwardEndpoint",
			run: func() (string, error) {
				ep, err := ParseDynamicForwardEndpoint("[foo]:8080")
				return ep.String(), err
			},
		},
		{
			name: "ParseStdioForward",
			run: func() (string, error) {
				host, _, err := ParseStdioForward("[foo]:8080")
				return host, err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.run(); err == nil {
				t.Fatalf("LOW-5 reproduced: %s accepted bracketed non-IPv6 host [foo] -> %q", tc.name, got)
			}
		})
	}
}

func reproLOW5UnquotedBackslashEscapedSpace(t *testing.T) {
	t.Run("ParseForwardSpec", func(t *testing.T) {
		raw := `/tmp/my\ sock 127.0.0.1:80`
		spec, err := ParseForwardSpec(raw)
		if err != nil {
			t.Fatalf("LOW-5 reproduced: ParseForwardSpec(%q) split unquoted backslash-escaped space: %v", raw, err)
		}
		if spec.Bind.SocketPath != "/tmp/my sock" || spec.Dest.Host != "127.0.0.1" || spec.Dest.Port != 80 {
			t.Fatalf("ParseForwardSpec(%q) = %+v, want Bind.SocketPath=/tmp/my sock Dest=127.0.0.1:80", raw, spec)
		}
	})
	t.Run("ParseRemoteForwardSpec", func(t *testing.T) {
		raw := `/tmp/my\ sock`
		spec, err := ParseRemoteForwardSpec(raw)
		if err != nil {
			t.Fatalf("LOW-5 reproduced: ParseRemoteForwardSpec(%q) split unquoted backslash-escaped space: %v", raw, err)
		}
		if !spec.IsDynamic || spec.Bind.SocketPath != "/tmp/my sock" {
			t.Fatalf("ParseRemoteForwardSpec(%q) = %+v, want IsDynamic=true Bind.SocketPath=/tmp/my sock", raw, spec)
		}
	})
	t.Run("ParseDynamicForwardEndpoint", func(t *testing.T) {
		raw := `/tmp/my\ sock`
		ep, err := ParseDynamicForwardEndpoint(raw)
		if err != nil {
			t.Fatalf("LOW-5 reproduced: ParseDynamicForwardEndpoint(%q) split unquoted backslash-escaped space: %v", raw, err)
		}
		if ep.SocketPath != "/tmp/my sock" {
			t.Fatalf("ParseDynamicForwardEndpoint(%q) = %+v, want SocketPath=/tmp/my sock", raw, ep)
		}
	})
}
