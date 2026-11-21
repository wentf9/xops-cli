package mcphost

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestP1_CredentialVersionBindsDefaultSSHAuthSock(t *testing.T) {
	cfg := credentialBindingConfig()
	provider := config.NewProviderWithoutOpenSSH(cfg)

	baseHop := ssh.ConnectionConfig{
		NodeID:  "node",
		Address: "192.0.2.1",
		Port:    22,
		User:    "fixture",
	}
	plan := ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}}

	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-default-agent-1.sock")
	v1, err := credentialVersion(provider, plan)
	if err != nil {
		t.Fatalf("credentialVersion #1: %v", err)
	}

	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-default-agent-2.sock")
	v2, err := credentialVersion(provider, plan)
	if err != nil {
		t.Fatalf("credentialVersion #2: %v", err)
	}
	if v1 == v2 {
		t.Fatal("rotating default SSH_AUTH_SOCK with unset IdentityAgent must invalidate credentialVersion")
	}

	t.Setenv("SSH_AUTH_SOCK", "")
	vEmpty, err := credentialVersion(provider, plan)
	if err != nil {
		t.Fatalf("credentialVersion(empty): %v", err)
	}
	if vEmpty == v2 {
		t.Fatal("clearing default SSH_AUTH_SOCK must change credentialVersion")
	}

	// IdentitiesOnly=yes with unset IdentityAgent ignores ambient SSH_AUTH_SOCK rotation.
	hopIDOnly := baseHop.Clone()
	hopIDOnly.Options = ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes")
	planIDOnly := ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hopIDOnly}}

	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-idonly-agent-a.sock")
	vIDOnly1, err := credentialVersion(provider, planIDOnly)
	if err != nil {
		t.Fatalf("credentialVersion(IdentitiesOnly #1): %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-idonly-agent-b.sock")
	vIDOnly2, err := credentialVersion(provider, planIDOnly)
	if err != nil {
		t.Fatalf("credentialVersion(IdentitiesOnly #2): %v", err)
	}
	if vIDOnly1 != vIDOnly2 {
		t.Fatal("IdentitiesOnly=yes with unset IdentityAgent should not change credentialVersion on SSH_AUTH_SOCK rotation")
	}

	// IdentityAgent=none ignores ambient SSH_AUTH_SOCK rotation.
	hopAgentNone := baseHop.Clone()
	hopAgentNone.Options = ssh.MustOptions(ssh.OptionIdentityAgent, "none")
	planAgentNone := ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hopAgentNone}}

	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-none-agent-a.sock")
	vNone1, err := credentialVersion(provider, planAgentNone)
	if err != nil {
		t.Fatalf("credentialVersion(IdentityAgent=none #1): %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", "/tmp/p1-none-agent-b.sock")
	vNone2, err := credentialVersion(provider, planAgentNone)
	if err != nil {
		t.Fatalf("credentialVersion(IdentityAgent=none #2): %v", err)
	}
	if vNone1 != vNone2 {
		t.Fatal("IdentityAgent=none must not change credentialVersion on SSH_AUTH_SOCK rotation")
	}
}

func TestP1_PlanBoundSFTPInspectOpenFilesTransferAndTunnelIsolationAcrossConfigEdit(t *testing.T) {
	ctx, repo, first, second := setupTunnelRepository(t)

	h := newHost(Config{Provider: repo})
	deps := h.dependencies()
	rawBackend, err := deps.NewBackend(ctx)
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer func() {
		if shutErr := rawBackend.Shutdown(ctx); shutErr != nil {
			t.Errorf("backend Shutdown: %v", shutErr)
		}
	}()

	viewFirst, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve(first): %v", err)
	}
	bindingFirst, err := ports.Bind(viewFirst, "p1-scope", "sftp", struct{}{})
	if err != nil {
		t.Fatalf("Bind(first): %v", err)
	}

	admitFirst := func(opID string, phase ports.Phase) ports.Permit {
		t.Helper()
		p, enterErr := h.Enter(ctx, ports.Admission{
			OperationID: opID,
			Phase:       phase,
			Snapshot:    viewFirst,
			Binding:     bindingFirst,
		})
		if enterErr != nil {
			t.Fatalf("Enter(%s, %s): %v", opID, phase, enterErr)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}

	execPermit := admitFirst("op-exec", ports.Execute)
	inspectPermit := admitFirst("op-inspect", ports.Inspect)
	transferStartPermit := admitFirst("op-transfer-start", ports.TransferStart)
	commitPermit := admitFirst("op-commit", ports.Commit)
	dlPermit := admitFirst("op-download", ports.TransferStart)
	tunnelPermit := admitFirst("op-tunnel", ports.Execute)

	// Mutate live repository AFTER admission so "node" now points to second server.
	ref := repo.View().NodeRefs["node"]
	node, _, identity, err := repo.Resolve("node")
	if err != nil {
		t.Fatalf("repo.Resolve(node): %v", err)
	}
	if err := repo.ReplaceNodeAtRefContext(ctx, ref, "node", node, tunnelSnapshotHost(t, second.Address), identity); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext(second): %v", err)
	}

	// 1. OpenFiles & Inspect bound to admitted Plan (first).
	verifyPlanBoundOpenFilesAndInspect(t, ctx, rawBackend, execPermit, inspectPermit, transferStartPermit)

	// 2. OpenTransfer stream, commit, and download against admitted Plan (first).
	verifyPlanBoundTransferRoundTrip(t, ctx, rawBackend, transferStartPermit, commitPermit, dlPermit)

	// 3. Verify second server never received either file (admitted SFTP never drifted to live repo).
	verifySecondServerUntouched(t, ctx, h, rawBackend)

	// 4. RunTunnel dials admitted Plan (first) via ConnectPlan, never second.
	verifyPlanBoundTunnelIsolation(t, ctx, rawBackend.(ports.TunnelBackend), tunnelPermit, first.Forwards.Load, second.Forwards.Load)
}

func verifyPlanBoundOpenFilesAndInspect(
	t *testing.T,
	ctx context.Context,
	rawBackend ports.Backend,
	execPermit, inspectPermit, transferStartPermit ports.Permit,
) {
	t.Helper()
	if _, err := rawBackend.OpenFiles(ctx, inspectPermit, "node"); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("OpenFiles(inspectPermit) = %v, want ports.ErrPurpose", err)
	}
	files, err := rawBackend.OpenFiles(ctx, execPermit, "node")
	if err != nil {
		t.Fatalf("OpenFiles(execPermit): %v", err)
	}
	const fileBody = "bound-to-first-plan"
	_, created, err := files.CreatePrivateExclusive(ctx, "/admitted-file", func(w io.Writer) error {
		_, writeErr := io.WriteString(w, fileBody)
		return writeErr
	})
	if err != nil || !created {
		_ = files.Close()
		t.Fatalf("CreatePrivateExclusive = (created=%v, err=%v)", created, err)
	}
	if err := files.Close(); err != nil {
		t.Fatalf("files.Close(): %v", err)
	}

	meta, err := rawBackend.Inspect(ctx, transferStartPermit, "node", ports.InspectRequest{Path: "/admitted-file"})
	if err != nil {
		t.Fatalf("Inspect(transferStartPermit): %v", err)
	}
	if meta.Size != int64(len(fileBody)) {
		t.Fatalf("Inspect size = %d, want %d", meta.Size, len(fileBody))
	}

	canceledCtx, cancelNow := context.WithCancel(ctx)
	cancelNow()
	if _, err := rawBackend.Inspect(canceledCtx, inspectPermit, "node", ports.InspectRequest{Path: "/admitted-file"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Inspect(canceledCtx) = %v, want context.Canceled", err)
	}
}

func verifyPlanBoundTransferRoundTrip(
	t *testing.T,
	ctx context.Context,
	rawBackend ports.Backend,
	transferStartPermit, commitPermit, dlPermit ports.Permit,
) {
	t.Helper()
	transferSess, err := rawBackend.OpenTransfer(ctx, transferStartPermit, "node")
	if err != nil {
		t.Fatalf("OpenTransfer: %v", err)
	}
	streamRes, err := transferSess.Upload(ctx, "/tmp-transfer", strings.NewReader("transfer-first"), 14, nil, nil)
	if err != nil || !streamRes.Created || streamRes.Bytes != 14 {
		_ = transferSess.Close()
		t.Fatalf("transferSess.Upload = (%+v, %v)", streamRes, err)
	}
	if err := transferSess.ReserveCommit(ctx, commitPermit); err != nil {
		_ = transferSess.Close()
		t.Fatalf("ReserveCommit: %v", err)
	}
	commitRes, err := transferSess.Commit(ctx, "/tmp-transfer", "/committed-transfer", false)
	if err != nil || !commitRes.Committed {
		_ = transferSess.Close()
		t.Fatalf("Commit = (%+v, %v)", commitRes, err)
	}
	if err := transferSess.Close(); err != nil {
		t.Fatalf("transferSess.Close(): %v", err)
	}

	dlSess, err := rawBackend.OpenTransfer(ctx, dlPermit, "node")
	if err != nil {
		t.Fatalf("OpenTransfer(download): %v", err)
	}
	dlMeta, err := dlSess.Inspect(ctx, "/committed-transfer", false, false)
	if err != nil {
		_ = dlSess.Close()
		t.Fatalf("dlSess.Inspect: %v", err)
	}
	var dlBuf bytes.Buffer
	if _, err := dlSess.Download(ctx, dlMeta, &dlBuf, nil); err != nil {
		_ = dlSess.Close()
		t.Fatalf("dlSess.Download: %v", err)
	}
	if err := dlSess.Close(); err != nil {
		t.Fatalf("dlSess.Close(): %v", err)
	}
	if dlBuf.String() != "transfer-first" {
		t.Fatalf("downloaded content = %q, want %q", dlBuf.String(), "transfer-first")
	}
}

func verifySecondServerUntouched(t *testing.T, ctx context.Context, h *host, rawBackend ports.Backend) {
	t.Helper()
	viewSecond, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatalf("Resolve(second): %v", err)
	}
	bindingSecond, err := ports.Bind(viewSecond, "p1-scope", "sftp-check", struct{}{})
	if err != nil {
		t.Fatalf("Bind(second): %v", err)
	}
	inspectSecond, err := h.Enter(ctx, ports.Admission{
		OperationID: "op-inspect-second",
		Phase:       ports.Inspect,
		Snapshot:    viewSecond,
		Binding:     bindingSecond,
	})
	if err != nil {
		t.Fatalf("Enter(second): %v", err)
	}
	defer func() { _ = inspectSecond.Close() }()

	for _, path := range []string{"/admitted-file", "/committed-transfer"} {
		if _, err := rawBackend.Inspect(ctx, inspectSecond, "node", ports.InspectRequest{Path: path}); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("second server unexpectedly saw %s (err=%v): post-admission config edit leaked into SFTP!", path, err)
		}
	}
}

func verifyPlanBoundTunnelIsolation(
	t *testing.T,
	ctx context.Context,
	tunnelBackend ports.TunnelBackend,
	tunnelPermit ports.Permit,
	firstForwards, secondForwards func() int32,
) {
	t.Helper()
	echoAddr := startTunnelEcho(t)
	spec, err := tunnel.Normalize(tunnel.Spec{
		RequestID:  "p1-tunnel",
		NodeID:     "node",
		Mode:       "remote",
		ListenHost: "127.0.0.1",
		ListenPort: 0,
		TargetHost: "127.0.0.1",
		TargetPort: parseAddrPort(t, echoAddr),
		TTLSeconds: 60,
	})
	if err != nil {
		t.Fatalf("tunnel.Normalize: %v", err)
	}

	tunCtx, tunCancel := context.WithCancel(ctx)
	readyAddr := make(chan string, 1)
	tunErrCh := make(chan error, 1)
	go func() {
		tunErrCh <- tunnelBackend.RunTunnel(tunCtx, tunnelPermit, spec, func(addr string) bool {
			readyAddr <- addr
			return true
		}, nil)
	}()

	select {
	case addr := <-readyAddr:
		assertTunnelEcho(t, addr)
	case err := <-tunErrCh:
		t.Fatalf("RunTunnel exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		tunCancel()
		t.Fatal("timed out waiting for RunTunnel ready")
	}

	tunCancel()
	select {
	case err := <-tunErrCh:
		if err != nil {
			t.Fatalf("RunTunnel stop error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for RunTunnel shutdown")
	}

	if firstForwards() != 1 || secondForwards() != 0 {
		t.Fatalf("RunTunnel drifted across post-admission edit: first=%d second=%d, want 1/0",
			firstForwards(), secondForwards())
	}
}

func parseAddrPort(t *testing.T, addr string) int {
	t.Helper()
	host := tunnelSnapshotHost(t, addr)
	return int(host.Port)
}
