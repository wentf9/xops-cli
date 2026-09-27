package mcpserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/transfer"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

func closeTransferTestResource(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("close transfer test resource: %v", err)
	}
}

// startTransferSSH serves shared in-memory files over actual loopback SSH/SFTP.
// No path presented to this server can access the host operating system files.
func startTransferSSH(t *testing.T, handlers pkgsftp.Handlers) *config.Provider {
	t.Helper()
	home := isolateMCPTestEnvironment(t)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() { serveTransferTestSSH(t, ctx, conn, serverConfig, handlers, &workers) })
		}
	})
	t.Cleanup(func() {
		cancel()
		closeTransferTestResource(t, listener)
		workers.Wait()
	})
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t, home, host, portText, signer.PublicKey())
	cfg := runtimeTestProvider("files").Snapshot()
	cfg.Hosts.Set("host", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: "fixture-only"})
	return config.NewProviderWithoutOpenSSH(cfg)
}

func serveTransferTestSSH(t *testing.T, ctx context.Context, conn net.Conn, config *cryptossh.ServerConfig, handlers pkgsftp.Handlers, workers *sync.WaitGroup) {
	defer closeTransferTestResource(t, conn)
	stop := context.AfterFunc(ctx, func() { closeTransferTestResource(t, conn) })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		t.Error(err)
		return
	}
	sshConn, channels, requests, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		if ctx.Err() == nil {
			t.Error(err)
		}
		return
	}
	defer closeTransferTestResource(t, sshConn)
	workers.Go(func() { cryptossh.DiscardRequests(requests) })
	for incoming := range channels {
		if incoming.ChannelType() != "session" {
			if err := incoming.Reject(cryptossh.UnknownChannelType, "session required"); err != nil && ctx.Err() == nil {
				t.Error(err)
			}
			continue
		}
		channel, reqs, err := incoming.Accept()
		if err != nil {
			if ctx.Err() == nil {
				t.Error(err)
			}
			continue
		}
		workers.Go(func() { serveTransferSubsystem(t, ctx, channel, reqs, handlers) })
	}
}

func serveTransferSubsystem(t *testing.T, ctx context.Context, channel cryptossh.Channel, requests <-chan *cryptossh.Request, handlers pkgsftp.Handlers) {
	defer closeTransferTestResource(t, channel)
	for request := range requests {
		var subsystem struct{ Name string }
		accepted := request.Type == "subsystem" && cryptossh.Unmarshal(request.Payload, &subsystem) == nil && subsystem.Name == "sftp"
		if request.WantReply {
			if err := request.Reply(accepted, nil); err != nil {
				if ctx.Err() == nil {
					t.Error(err)
				}
				return
			}
		}
		if !accepted {
			continue
		}
		server := pkgsftp.NewRequestServer(channel, handlers)
		err := server.Serve()
		closeTransferTestResource(t, server)
		// Cancellation may truncate an in-flight SFTP packet before channel close.
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.ErrClosedPipe) && ctx.Err() == nil {
			t.Error(err)
		}
		return
	}
}

func startTransferRuntime(t *testing.T, modify func(*HTTPOptions), handlers pkgsftp.Handlers, hooks ...func(*Runtime)) (*Runtime, *httptest.Server, *mcp.ClientSession) {
	t.Helper()
	provider := startTransferSSH(t, handlers)
	server := httptest.NewUnstartedServer(nil)
	options := DefaultHTTPOptions()
	options.Token, options.PublicURL, options.StateDir = httpTestToken, "http://"+server.Listener.Addr().String(), filepath.Join(t.TempDir(), "tasks")
	if modify != nil {
		modify(&options)
	}
	r, err := NewRuntime(t.Context(), WithConfigProvider(provider), WithHTTP(options))
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
	for _, hook := range hooks {
		hook(r)
	}
	server.Config.Handler, err = r.HTTPHandler()
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	return r, server, connectHTTPTestClient(t, server, nil)
}

func prepareTransferTest(t *testing.T, client *mcp.ClientSession, name string, input any) PreparedTransferOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("prepare failed: %+v", result.Content)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out PreparedTransferOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.Task.ID == "" {
		t.Fatalf("missing task: %s", data)
	}
	return out
}

func transferTestRequest(t *testing.T, server *httptest.Server, method, url string, headers map[string]string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, response.Body)
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, data
}

func transferTestStatus(t *testing.T, server *httptest.Server, p PreparedTransferOutput) transfer.Status {
	t.Helper()
	response, data := transferTestRequest(t, server, http.MethodGet, p.StatusURL, p.Headers, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status HTTP %d: %s", response.StatusCode, data)
	}
	var body transferResponse
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	if body.Task == nil {
		t.Fatal("missing status")
	}
	return *body.Task
}

func TestHTTPToSFTPBinaryRoundTrip(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	for _, payload := range [][]byte{nil, []byte("binary\x00\xff\xfe\nwith unicode 文件"), bytes.Repeat([]byte{0, 1, 2, 255}, (5<<20)/4)} {
		name := fmt.Sprintf("/文件 with spaces-%d.bin", len(payload))
		digest := sha256.Sum256(payload)
		input := PrepareUploadInput{RequestID: fmt.Sprintf("upload-%d", len(payload)), NodeID: "files", RemotePath: name, Size: int64(len(payload)), SHA256: hex.EncodeToString(digest[:])}
		upload := prepareTransferTest(t, client, "xops_prepare_upload", input)
		response, data := transferTestRequest(t, server, upload.Method, upload.URL, upload.Headers, bytes.NewReader(payload))
		if response.StatusCode != http.StatusOK {
			t.Fatalf("upload HTTP %d: %s", response.StatusCode, data)
		}
		status := transferTestStatus(t, server, upload)
		if status.State != transfer.Completed || status.SHA256 != input.SHA256 || status.Bytes != int64(len(payload)) {
			t.Fatalf("upload status: %+v", status)
		}
		download := prepareTransferTest(t, client, "xops_prepare_download", PrepareDownloadInput{RequestID: fmt.Sprintf("download-%d", len(payload)), NodeID: "files", RemotePath: name})
		response, got := transferTestRequest(t, server, download.Method, download.URL, download.Headers, nil)
		if response.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
			t.Fatalf("download content mismatch: HTTP %d bytes=%d", response.StatusCode, len(got))
		}
		status = transferTestStatus(t, server, download)
		if status.State != transfer.Streamed || status.SHA256 != input.SHA256 {
			t.Fatalf("download status: %+v", status)
		}
		// Client-side promotion occurs only after digest and server-state checks.
		clientDir := t.TempDir()
		temporary := filepath.Join(clientDir, "download.tmp")
		if err := os.WriteFile(temporary, got, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, filepath.Join(clientDir, "download.bin")); err != nil {
			t.Fatal(err)
		}
		for _, record := range r.transfers.Records() {
			if record.CleanupPending {
				t.Fatalf("unexpected leftover: %+v", record)
			}
		}
	}
}

func TestHTTPUploadDigestMismatchCleansTemporary(t *testing.T) {
	r, server, client := startTransferRuntime(t, nil, pkgsftp.InMemHandler())
	digest := sha256.Sum256([]byte("correct"))
	p := prepareTransferTest(t, client, "xops_prepare_upload", PrepareUploadInput{RequestID: "bad-digest", NodeID: "files", RemotePath: "/destination", Size: 7, SHA256: hex.EncodeToString(digest[:])})
	response, _ := transferTestRequest(t, server, p.Method, p.URL, p.Headers, strings.NewReader("corrupt"))
	if response.StatusCode < 400 {
		t.Fatal("digest mismatch succeeded")
	}
	status := transferTestStatus(t, server, p)
	if status.State != transfer.Failed || status.CleanupPending {
		t.Fatalf("mismatch status: %+v", status)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	remote, err := r.getMCPSFTPClient(ctx, "files")
	if err != nil {
		t.Fatal(err)
	}
	defer closeTransferTestResource(t, remote)
	if err := remote.Do(ctx, func(raw *pkgsftp.Client) error {
		entries, err := raw.ReadDir("/")
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("failed upload left remote files: %v", entries)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
