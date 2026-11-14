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
