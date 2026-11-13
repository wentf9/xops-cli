package sshenv

import (
	"context"
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
