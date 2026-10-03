package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/sshexec"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"go.uber.org/goleak"
)

func TestRuntimeUsesSharedBackendForDeferredTransfers(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	provider := startTransferSSH(t, pkgsftp.InMemHandler())
	dependencies := provider.Dependencies()
	dependencies.NewBackend = func(ctx context.Context) (ports.Backend, error) {
		return sshexec.New(ctx, sshexec.Options{SSH: provider.SSHOptions()})
	}
	server := httptest.NewUnstartedServer(nil)
	options := DefaultHTTPOptions()
	options.Token = httpTestToken
	options.Listen = server.Listener.Addr().String()
	options.PublicURL = "http://" + options.Listen
	options.StateDir = filepath.Join(t.TempDir(), "transfers")
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies), WithHTTP(options))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		server.Close()
	})
	server.Config.Handler, err = r.HTTPHandler()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.ReadHeaderTimeout = time.Second
	server.Start()
	client := connectHTTPTestClient(t, server, nil)
	data := []byte("captured-runtime-transfer\x00\xff")
	digest := sha256.Sum256(data)
	upload := prepareTransferTest(t, client, "xops_prepare_upload", PrepareUploadInput{RequestID: "ports-upload", NodeID: "files", RemotePath: "/ports-file", Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:])})
	response, body := transferTestRequest(t, server, http.MethodPut, upload.URL, upload.Headers, bytes.NewReader(data))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upload HTTP %d: %s", response.StatusCode, body)
	}
	if status := transferTestStatus(t, server, upload); status.State != transfer.Completed {
		t.Fatalf("upload state: %+v", status)
	}
	download := prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: "ports-download", NodeID: "files", RemotePath: "/ports-file"})
	response, body = transferTestRequest(t, server, http.MethodGet, download.URL, download.Headers, nil)
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, data) {
		t.Fatalf("download mismatch: HTTP %d", response.StatusCode)
	}
	if status := transferTestStatus(t, server, download); status.State != transfer.Streamed {
		t.Fatalf("download state: %+v", status)
	}
}

type failedStartupBackend struct {
	ports.Backend
	closed atomic.Int32
}

func (b *failedStartupBackend) Shutdown(context.Context) error { b.closed.Add(1); return nil }

func TestRuntimeOwnsPartiallyCreatedBackend(t *testing.T) {
	marker := errors.New("factory failed after allocation")
	for _, cancelStartup := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		dependencies := runtimeTestProvider("node").Dependencies()
		backend := &failedStartupBackend{}
		dependencies.NewBackend = func(context.Context) (ports.Backend, error) {
			if cancelStartup {
				cancel()
				return backend, nil
			}
			return backend, marker
		}
		r, err := NewRuntime(ctx, WithDependencies(dependencies))
		cancel()
		want := marker
		if cancelStartup {
			want = context.Canceled
		}
		if r != nil || !errors.Is(err, want) || backend.closed.Load() != 1 {
			t.Fatalf("startup resource leak: runtime=%v error=%v closes=%d", r, err, backend.closed.Load())
		}
	}
}

type mismatchedGate struct {
	source   ports.StateSource
	released atomic.Int32
}

func (g *mismatchedGate) DomainID() string { return g.source.DomainID() }
func (g *mismatchedGate) Enter(ctx context.Context, admission ports.Admission) (ports.Permit, error) {
	admission.Binding.Scope = "different-scope"
	return ports.NewPermit(ctx, admission, func() error { g.released.Add(1); return nil })
}
func TestRuntimeRejectsChangedGateGrant(t *testing.T) {
	provider := runtimeTestProvider("node")
	dependencies := provider.Dependencies()
	gate := &mismatchedGate{source: provider}
	dependencies.Gate = gate
	r, err := NewRuntime(t.Context(), WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, r)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	view, err := provider.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "operation", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.enter(ctx, view, binding, ports.Execute, "operation-id"); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("gate changed the authorization: %v", err)
	}
	if gate.released.Load() != 1 {
		t.Fatal("rejected grant leaked its lease")
	}
}
