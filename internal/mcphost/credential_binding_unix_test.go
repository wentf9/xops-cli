//go:build !windows

package mcphost

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestCredentialVersionSkipsFIFOWithoutBlockingResolveOrEnter(t *testing.T) {
	dir := t.TempDir()
	fifoCert := filepath.Join(dir, "fifo-cert.pub")
	if err := syscall.Mkfifo(fifoCert, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifoSidecar := keyPath + "-cert.pub"
	if err := syscall.Mkfifo(fifoSidecar, 0o600); err != nil {
		t.Fatalf("Mkfifo sidecar failed: %v", err)
	}

	cfg := credentialBindingConfig()
	node, _ := cfg.Nodes.Get("node")
	node.SSHOptions = ssh.MustOptions(
		ssh.OptionIdentityFile, keyPath,
		ssh.OptionCertificateFile, fifoCert,
	)
	cfg.Nodes.Set("node", node)

	h := credentialBindingHost(cfg, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		view, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
		if err != nil {
			done <- err
			return
		}
		binding, err := ports.Bind(view, "scope", "test", struct{}{})
		if err != nil {
			done <- err
			return
		}
		permit, err := h.Enter(ctx, ports.Admission{
			OperationID: "fifo-op",
			Phase:       ports.Execute,
			Snapshot:    view,
			Binding:     binding,
		})
		if permit != nil {
			_ = permit.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Resolve/Enter with FIFO CertificateFile failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("MCP Resolve/Enter blocked opening a FIFO CertificateFile")
	}

	// Also test sidecar FIFO when no explicit CertificateFile is configured.
	if b, ok := inspectCertificateBinding(fifoSidecar, false); ok {
		t.Fatalf("non-regular sidecar FIFO must be skipped, got %+v", b)
	}
}
