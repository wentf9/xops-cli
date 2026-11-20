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

func TestCredentialVersionSkipsFIFOAndSymlinkToFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifoCert := filepath.Join(dir, "fifo-cert.pub")
	if err := syscall.Mkfifo(fifoCert, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}
	symlinkToFIFO := filepath.Join(dir, "symlink-fifo-cert.pub")
	if err := os.Symlink(fifoCert, symlinkToFIFO); err != nil {
		t.Fatalf("Symlink to FIFO failed: %v", err)
	}

	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	fifoSidecarTarget := filepath.Join(dir, "raw-sidecar.fifo")
	if err := syscall.Mkfifo(fifoSidecarTarget, 0o600); err != nil {
		t.Fatalf("Mkfifo sidecar target failed: %v", err)
	}
	fifoSidecarLink := keyPath + "-cert.pub"
	if err := os.Symlink(fifoSidecarTarget, fifoSidecarLink); err != nil {
		t.Fatalf("Symlink sidecar to FIFO failed: %v", err)
	}

	for _, certOptPath := range []string{fifoCert, symlinkToFIFO} {
		cfg := credentialBindingConfig()
		node, _ := cfg.Nodes.Get("node")
		node.SSHOptions = ssh.MustOptions(
			ssh.OptionIdentityFile, keyPath,
			ssh.OptionCertificateFile, certOptPath,
		)
		cfg.Nodes.Set("node", node)

		h := credentialBindingHost(cfg, false)
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
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
			cancel()
			if err != nil {
				t.Fatalf("Resolve/Enter with FIFO path %q failed: %v", certOptPath, err)
			}
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("MCP Resolve/Enter blocked opening FIFO path %q", certOptPath)
		}
	}

	// Verify both direct FIFO and symlink-to-FIFO sidecars are classified non-regular without blocking.
	if b, ok := inspectCertificateBinding(fifoCert, false); ok {
		t.Fatalf("direct FIFO sidecar must be skipped, got %+v", b)
	}
	if b, ok := inspectCertificateBinding(fifoSidecarLink, false); ok {
		t.Fatalf("symlink-to-FIFO sidecar must be skipped, got %+v", b)
	}
	if b, ok := inspectCertificateBinding(symlinkToFIFO, true); !ok || !b.NonRegular {
		t.Fatalf("explicit symlink-to-FIFO must record NonRegular=true, got (%+v, %v)", b, ok)
	}
	if b, ok := inspectCertificateBinding("/dev/null", true); !ok || !b.NonRegular {
		t.Fatalf("/dev/null must record NonRegular=true via nonblocking+NOCTTY open, got (%+v, %v)", b, ok)
	}
	if b, ok := inspectCertificateBinding("/dev/null", false); ok {
		t.Fatalf("/dev/null sidecar must be skipped, got %+v", b)
	}
}

func atomicFlipSymlink(t *testing.T, linkPath, newTarget string) {
	t.Helper()
	tmpLink := linkPath + ".tmp"
	_ = os.Remove(tmpLink)
	if err := os.Symlink(newTarget, tmpLink); err != nil {
		t.Fatalf("os.Symlink(%q -> %q): %v", tmpLink, newTarget, err)
	}
	if err := os.Rename(tmpLink, linkPath); err != nil {
		t.Fatalf("os.Rename(%q -> %q): %v", tmpLink, linkPath, err)
	}
}

func TestCredentialVersionBindsSymlinkedUserCertificatesAcrossAtomicRotation(t *testing.T) {
	dir := t.TempDir()
	certV1 := filepath.Join(dir, "cert-v1.pub")
	certV2 := filepath.Join(dir, "cert-v2.pub")
	writeTestUserCertForBinding(t, certV1, 101, 5000)
	writeTestUserCertForBinding(t, certV2, 102, 9000)

	// (a) Symlinked auto-discovered sidecar (<key>-cert.pub -> cert-v1.pub -> cert-v2.pub).
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecarLink := keyPath + "-cert.pub"
	if err := os.Symlink(certV1, sidecarLink); err != nil {
		t.Fatal(err)
	}

	cfgSidecar := credentialBindingConfig()
	nodeSidecar, _ := cfgSidecar.Nodes.Get("node")
	nodeSidecar.SSHOptions = ssh.MustOptions(ssh.OptionIdentityFile, keyPath)
	cfgSidecar.Nodes.Set("node", nodeSidecar)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	hostSidecar := credentialBindingHost(cfgSidecar, false)
	admSidecar := persistedAdmission(t, ctx, hostSidecar)
	assertAdmission(t, ctx, hostSidecar, admSidecar, false)

	atomicFlipSymlink(t, sidecarLink, certV2)
	assertAdmission(t, ctx, hostSidecar, admSidecar, true)

	// (b) Symlinked explicit CertificateFile (explicit-cert.pub -> cert-v1.pub -> cert-v2.pub).
	explicitLink := filepath.Join(dir, "explicit-cert.pub")
	if err := os.Symlink(certV1, explicitLink); err != nil {
		t.Fatal(err)
	}

	cfgExplicit := credentialBindingConfig()
	nodeExplicit, _ := cfgExplicit.Nodes.Get("node")
	nodeExplicit.SSHOptions = ssh.MustOptions(
		ssh.OptionIdentityFile, keyPath,
		ssh.OptionCertificateFile, explicitLink,
	)
	cfgExplicit.Nodes.Set("node", nodeExplicit)

	hostExplicit := credentialBindingHost(cfgExplicit, false)
	admExplicit := persistedAdmission(t, ctx, hostExplicit)
	assertAdmission(t, ctx, hostExplicit, admExplicit, false)

	atomicFlipSymlink(t, explicitLink, certV2)
	assertAdmission(t, ctx, hostExplicit, admExplicit, true)
}
