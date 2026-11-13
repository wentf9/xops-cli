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
	if env.DialProxyCommand != nil || env.RunLocalCommand != nil || env.LookupSSHFP != nil {
		t.Fatal("expected local execution and DNS SSHFP hooks to remain nil by default")
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
	if _, ok := normalizeWindowsAgentPipePath(""); ok {
		t.Fatal("expected empty socket not to match named pipe prefix directly")
	}
	if _, ok := normalizeWindowsAgentPipePath(`\\.\pipe\`); ok {
		t.Fatal("expected bare \\\\.\\pipe\\ without name to be rejected")
	}
	pipe, ok := normalizeWindowsAgentPipePath(defaultWindowsOpenSSHAgentPipe)
	if !ok || pipe != defaultWindowsOpenSSHAgentPipe {
		t.Fatalf("default pipe = (%q, %v), want (%q, true)", pipe, ok, defaultWindowsOpenSSHAgentPipe)
	}
	pipe, ok = normalizeWindowsAgentPipePath(`//./pipe/custom-agent`)
	if !ok || pipe != `\\.\pipe\custom-agent` {
		t.Fatalf("slash pipe = (%q, %v), want (\\\\.\\pipe\\custom-agent, true)", pipe, ok)
	}
	if _, ok := normalizeWindowsAgentPipePath(`/tmp/ssh-agent.sock`); ok {
		t.Fatal("expected unix socket path not to match Windows named pipe prefix")
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
