package sshenv

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDiscoverEnvironmentContracts(t *testing.T) {
	t.Setenv("XOPS_SSHENV_TEST_MARKER", "present")
	env := Discover()

	if env.Environ == nil {
		t.Fatal("expected Discover() to populate Environ callback")
	}
	snapshot := env.Environ()
	if !slices.Contains(snapshot, "XOPS_SSHENV_TEST_MARKER=present") {
		t.Fatalf("expected Environ() snapshot to include XOPS_SSHENV_TEST_MARKER=present")
	}

	if env.DialAgent == nil {
		t.Fatal("expected Discover() to populate DialAgent callback")
	}
	if env.DialProxyCommand != nil || env.RunLocalCommand != nil {
		t.Fatal("expected local execution hooks to remain nil by default")
	}
	if env.LookupSSHFP == nil {
		t.Fatal("expected Discover() to populate LookupSSHFP (only used when VerifyHostKeyDNS is enabled)")
	}
	if runtime.GOOS != "windows" && len(env.GlobalKnownHostsFiles) == 0 {
		t.Fatal("expected Discover() to populate default GlobalKnownHostsFiles on Unix")
	}
	if runtime.GOOS == "windows" {
		if env.SuspendProcess != nil {
			t.Fatal("expected SuspendProcess to be nil on Windows")
		}
	} else if env.SuspendProcess == nil {
		t.Fatal("expected Discover() to populate SuspendProcess on Unix")
	}

	if runtime.GOOS != "windows" {
		sockDir := t.TempDir()
		sockPath := filepath.Join(sockDir, "agent.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			// Fallback short directory if TempDir exceeds sun_path limit.
			shortDir, mkErr := filepath.EvalSymlinks("/tmp")
			if mkErr != nil {
				t.Skipf("cannot listen unix socket: %v", err)
			}
			sockPath = filepath.Join(shortDir, "xops-sshenv-"+strings.ReplaceAll(t.Name(), "/", "_")+".sock")
			ln, err = net.Listen("unix", sockPath)
			if err != nil {
				t.Skipf("cannot listen unix socket: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })
		} else {
			t.Cleanup(func() { _ = ln.Close() })
		}

		accepted := make(chan struct{})
		go func() {
			defer close(accepted)
			conn, acceptErr := ln.Accept()
			if acceptErr == nil {
				_ = conn.Close()
			}
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		conn, err := env.DialAgent(ctx, sockPath)
		if err != nil {
			t.Fatalf("DialAgent(%q) failed: %v", sockPath, err)
		}
		_ = conn.Close()
		<-accepted
	}
}

func TestNormalizeWindowsAgentPipePath(t *testing.T) {
	for _, invalid := range []string{
		"",
		"   ",
		`\\.\pipe\`,
		`\\.\PIPE\`,
		`\\?\pipe\`,
		`\\.\pipe\\`,
		`//./pipe/`,
		`//?/PIPE/`,
		`/tmp/ssh-agent.sock`,
		`C:\Users\alice\agent.sock`,
	} {
		if got, ok := normalizeWindowsAgentPipePath(invalid); ok {
			t.Fatalf("normalizeWindowsAgentPipePath(%q) = (%q, true), want false", invalid, got)
		}
	}

	cases := []struct {
		in   string
		want string
	}{
		{defaultWindowsOpenSSHAgentPipe, defaultWindowsOpenSSHAgentPipe},
		{`  \\.\PIPE\openssh-ssh-agent  `, `\\.\pipe\openssh-ssh-agent`},
		{`\\?\pipe\openssh-ssh-agent`, `\\.\pipe\openssh-ssh-agent`},
		{`\\?\PIPE\openssh-ssh-agent`, `\\.\pipe\openssh-ssh-agent`},
		{`//./pipe/custom-agent`, `\\.\pipe\custom-agent`},
		{`//./PIPE/custom-agent`, `\\.\pipe\custom-agent`},
		{`//?/pipe/custom-agent`, `\\.\pipe\custom-agent`},
		{`\\.\pipe/sub/mixed-agent`, `\\.\pipe\sub\mixed-agent`},
		{`\\?\PIPE/sub\mixed-agent`, `\\.\pipe\sub\mixed-agent`},
	}
	for _, tc := range cases {
		pipe, ok := normalizeWindowsAgentPipePath(tc.in)
		if !ok || pipe != tc.want {
			t.Fatalf("normalizeWindowsAgentPipePath(%q) = (%q, %v), want (%q, true)", tc.in, pipe, ok, tc.want)
		}
	}
}

func TestDiscoverAgentSocketAndDialAgentCancellation(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/custom/test-agent.sock")
	env := Discover()
	if env.AgentSocket != "/custom/test-agent.sock" {
		t.Fatalf("Discover().AgentSocket = %q, want /custom/test-agent.sock", env.AgentSocket)
	}

	t.Setenv("SSH_AUTH_SOCK", "")
	envUnset := Discover()
	if runtime.GOOS == "windows" {
		if envUnset.AgentSocket != defaultWindowsOpenSSHAgentPipe {
			t.Fatalf("Windows default AgentSocket = %q, want %q", envUnset.AgentSocket, defaultWindowsOpenSSHAgentPipe)
		}
	} else if envUnset.AgentSocket != "" {
		t.Fatalf("Unix unset AgentSocket = %q, want empty", envUnset.AgentSocket)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	conn, err := env.DialAgent(ctx, "/nonexistent/canceled.sock")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("expected DialAgent on canceled context to fail")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DialAgent canceled error = %v, want context.Canceled", err)
	}
}

func TestParseWindowsAgentPipePath_SecurityAndValidation(t *testing.T) {
	invalid := []string{
		`\\.\pipe\`,
		`\\?\pipe\`,
		`//./pipe/`,
		`\\.\pipe\..\C:\Users\victim\.ssh\id_ed25519`,
		`\\?\pipe\..\evil`,
		`\\.\pipe\a\..\b`,
		`//./pipe/a/../b`,
		`\\.\pipe\.\agent`,
		`\\.\pipe\foo:bar`,
		`\\.\pipe\foo.. `,
		`\\.\pipe\.. \bar`,
		`\\.\pipe\...`,
		`\\.\pipe\\foo`,
		`\\.\pipe\foo\`,
		`\\.\pipe\agent` + "\x00",
		"\\\\.\\pipe\\agent\r\n",
		"\n\\\\.\\pipe\\agent",
		"\\\\.\\pipe\\agent\tname",
	}
	for _, in := range invalid {
		pipePath, isPipe, err := parseWindowsAgentPipePath(in)
		if !isPipe || err == nil || pipePath != "" {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (%q, %v, %v), want (\"\", true, error)", in, pipePath, isPipe, err)
		}
		if norm, ok := normalizeWindowsAgentPipePath(in); ok || norm != "" {
			t.Fatalf("normalizeWindowsAgentPipePath(%q) = (%q, %v), want (\"\", false)", in, norm, ok)
		}
	}

	valid := []struct {
		in   string
		want string
	}{
		{`\\.\pipe\sub\agent.sock`, `\\.\pipe\sub\agent.sock`},
		{`\\?\PIPE/sub/agent.sock`, `\\.\pipe\sub\agent.sock`},
	}
	for _, tc := range valid {
		pipePath, isPipe, err := parseWindowsAgentPipePath(tc.in)
		if !isPipe || err != nil || pipePath != tc.want {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (%q, %v, %v), want (%q, true, nil)", tc.in, pipePath, isPipe, err, tc.want)
		}
	}

	for _, nonPipe := range []string{"", `C:\Users\alice\agent.sock`, `/tmp/agent.sock`} {
		if pipePath, isPipe, err := parseWindowsAgentPipePath(nonPipe); isPipe || err != nil || pipePath != "" {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (%q, %v, %v), want (\"\", false, nil)", nonPipe, pipePath, isPipe, err)
		}
	}

	for _, ctrlNonPipe := range []string{"/tmp/agent\x00.sock", "/tmp/agent\r.sock", "\t"} {
		if _, isPipe, err := parseWindowsAgentPipePath(ctrlNonPipe); isPipe || err == nil {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (isPipe=%v, err=%v), want (false, error)", ctrlNonPipe, isPipe, err)
		}
	}
}

func TestRound4_P1_7_P3_5_WindowsAgentPathWhitelistAndLeadingControls(t *testing.T) {
	// Leading/trailing ASCII control chars on pipe paths must be rejected BEFORE TrimSpace.
	for _, raw := range []string{
		"\t\\\\.\\pipe\\openssh-ssh-agent",
		" \v\\\\.\\pipe\\openssh-ssh-agent",
		"\\\\.\\pipe\\agent\x7f",
	} {
		if _, isPipe, err := parseWindowsAgentPipePath(raw); !isPipe || err == nil {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (isPipe=%v, err=%v), want (true, error)", raw, isPipe, err)
		}
	}

	// UNC, device namespace, and NT object manager paths must fail closed rather than falling back to AF_UNIX.
	for _, blocked := range []string{
		`\\attacker\share\agent.sock`,
		`\\attacker\pipe\openssh-ssh-agent`,
		`//attacker/pipe/openssh-ssh-agent`,
		`\\localhost\pipe\openssh-ssh-agent`,
		`\\.\CON`,
		`\\.\NUL`,
		`\\?\GLOBALROOT\Device\NamedPipe\evil`,
		`\\?\UNC\attacker\share\agent`,
		`\??\C:\Users\alice\agent.sock`,
		`/??/C:/Users/alice/agent.sock`,
		`\??`,
	} {
		if pipePath, isPipe, err := parseWindowsAgentPipePath(blocked); isPipe || err == nil || pipePath != "" {
			t.Fatalf("parseWindowsAgentPipePath(%q) = (%q, %v, %v), want (\"\", false, error)", blocked, pipePath, isPipe, err)
		}
	}
}
