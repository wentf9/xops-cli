package sshexec_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type secrets struct{}

func (secrets) ResolveSecret(ctx context.Context, _ ssh.SecretRequest) ([]byte, error) {
	return []byte(sshfixture.Password), ctx.Err()
}

type trust struct{ key cryptoSSH.PublicKey }

func (t trust) Verify(ctx context.Context, _ ssh.HostKeyRequest, key cryptoSSH.PublicKey) error {
	if !bytes.Equal(t.key.Marshal(), key.Marshal()) {
		return errors.New("fixture host key changed")
	}
	return ctx.Err()
}

func setupBackend(t *testing.T) (*sshexec.Backend, ports.OperationSnapshot, *sshfixture.Server, context.Context) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	server, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	host, portText, err := net.SplitHostPort(server.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := sshexec.New(ctx, sshexec.Options{SSH: []ssh.Option{ssh.WithSecretResolver(secrets{}), ssh.WithHostKeyVerifier(trust{server.HostKey})}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := backend.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	view := ports.OperationSnapshot{DomainID: "fixture", Targets: map[string]ports.Target{"node": {Info: ports.NodeInfo{ID: "node"}, Version: "v1", Plan: ssh.ConnectionPlan{Scope: "fixture", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "v1"}}}}}}
	return backend, view, server, ctx
}

func permit(t *testing.T, ctx context.Context, view ports.OperationSnapshot, phase ports.Phase) ports.Permit {
	t.Helper()
	binding, err := ports.Bind(view, "fixture", "fixture-operation", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	permission, err := ports.NewPermit(ctx, ports.Admission{OperationID: "operation", Phase: phase, Snapshot: view, Binding: binding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := permission.Close(); err != nil {
			t.Error(err)
		}
	})
	return permission
}

func TestBackendExecutesOnlyWithBoundPermission(t *testing.T) {
	backend, view, server, ctx := setupBackend(t)
	inspect := permit(t, ctx, view, ports.Inspect)
	if _, err := backend.Run(ctx, inspect, "node", ports.Command{Text: "hostname"}); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("inspection permit executed a command")
	}
	if _, err := backend.OpenFiles(ctx, inspect, "node"); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("inspection permit acquired writable SFTP")
	}
	if server.Executed.Load() != 0 {
		t.Fatal("rejected operation reached SSH")
	}
	execute := permit(t, ctx, view, ports.Execute)
	result, err := backend.Run(ctx, execute, "node", ports.Command{Text: "hostname"})
	if err != nil || result.Output != "fixture-output" {
		t.Fatalf("SSH roundtrip: %+v %v", result, err)
	}
	if err := execute.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Run(context.Background(), execute, "node", ports.Command{Text: "hostname"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed permit executed: %v", err)
	}
	if server.Executed.Load() != 1 {
		t.Fatal("cancelled execution reached SSH")
	}
}

func TestBackendStreamsAndCommitsThroughSeparatePermits(t *testing.T) {
	backend, view, _, ctx := setupBackend(t)
	stream := permit(t, ctx, view, ports.TransferStart)
	upload, err := backend.OpenTransfer(ctx, stream, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := upload.Close(); err != nil {
			t.Error(err)
		}
	}()
	result, err := upload.Upload(ctx, "/temporary", strings.NewReader("payload"), 7, nil, nil)
	if err != nil || !result.Created || result.Bytes != 7 {
		t.Fatalf("upload: %+v %v", result, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Commit(context.Background(), "/temporary", "/destination", false); !errors.Is(err, ports.ErrPurpose) {
		t.Fatalf("stream permission gained commit capability: %v", err)
	}
	commit := permit(t, ctx, view, ports.Commit)
	remote, err := backend.OpenTransfer(ctx, commit, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := remote.Close(); err != nil {
			t.Error(err)
		}
	}()
	outcome, err := remote.Commit(ctx, "/temporary", "/destination", false)
	if err != nil || !outcome.Committed {
		t.Fatalf("commit: %+v %v", outcome, err)
	}
	if _, err := remote.Upload(ctx, "/other", strings.NewReader("x"), 1, nil, nil); !errors.Is(err, ports.ErrPurpose) {
		t.Fatal("commit permit started another upload")
	}
	downloadPermit := permit(t, ctx, view, ports.TransferStart)
	download, err := backend.OpenTransfer(ctx, downloadPermit, "node")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := download.Close(); err != nil {
			t.Error(err)
		}
	}()
	metadata, err := download.Inspect(ctx, "/destination", false, false)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := download.Download(ctx, metadata, &output, nil); err != nil {
		t.Fatal(err)
	}
	if output.String() != "payload" {
		t.Fatalf("download = %q", output.String())
	}
}
