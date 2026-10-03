package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptossh "golang.org/x/crypto/ssh"
)

type scpTransferFixture struct {
	ctx       context.Context
	repo      *config.Repository
	connector *xssh.Connector
	// Keep native paths for fixture I/O separate from the server's SFTP paths:
	// on Windows these are C:\... and /C:/..., respectively.
	home       string
	remoteHome string
}

func closeSCPTestResource(t *testing.T, resource io.Closer) {
	t.Helper()
	if err := resource.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("close SCP test resource: %v", err)
	}
}

func newSCPTransferFixture(t *testing.T) scpTransferFixture {
	t.Helper()
	localHome := t.TempDir()
	t.Setenv("HOME", localHome)
	t.Setenv("USERPROFILE", localHome)
	remoteHome := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &cryptossh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(signer)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	var workers sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		closeSCPTestResource(t, listener)
		workers.Wait()
	})
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
					t.Errorf("accept SCP test connection: %v", err)
				}
				return
			}
			workers.Go(func() { serveSCPTestConnection(t, ctx, conn, serverConfig, remoteHome) })
		}
	})
	port := listener.Addr().(*net.TCPAddr).Port
	provider, err := config.NewProvider(nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := provider.Snapshot()
	hostID := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	snapshot.Hosts.Set(hostID, models.Host{Address: "127.0.0.1", Port: uint16(port)})
	snapshot.Identities.Set("test", models.Identity{User: "test", AuthType: "password", Password: "test"})
	snapshot.Nodes.Set("test@"+hostID, models.Node{HostRef: hostID, IdentityRef: "test", Alias: []string{"scp-test"}})
	repo, err := config.NewRepositoryWithoutOpenSSH(snapshot, &memoryStore{cfg: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	connector := xssh.NewConnector(tunnelTestProvider{cfg: &xssh.ClientConfig{
		NodeID: "test@" + hostID, Address: "127.0.0.1", Port: port,
		User: "test", AuthType: "password", Password: "test",
	}}, xssh.WithEnvironment(sshenv.Discover()))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close SCP test connector: %v", err)
		}
	})
	_, client, err := NewScpOptions().connectSftpForPath(ctx, PathInfo{Host: "scp-test"}, "", repo, connector)
	if err != nil {
		t.Fatalf("connect SCP fixture SFTP client: %v", err)
	}
	defer closeSCPTestResource(t, client)
	sftpHome, err := client.Cwd(ctx)
	if err != nil {
		t.Fatalf("resolve SCP fixture remote home: %v", err)
	}
	return scpTransferFixture{ctx: ctx, repo: repo, connector: connector, home: remoteHome, remoteHome: sftpHome}
}

func serveSCPTestConnection(t *testing.T, ctx context.Context, conn net.Conn, cfg *cryptossh.ServerConfig, home string) {
	defer closeSCPTestResource(t, conn)
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(closed)
		closeSCPTestResource(t, conn)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Error(err)
		return
	}
	server, channels, requests, err := cryptossh.NewServerConn(conn, cfg)
	if err != nil {
		t.Errorf("handshake SCP test connection: %v", err)
		return
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	defer closeSCPTestResource(t, server)
	workers.Go(func() { cryptossh.DiscardRequests(requests) })
	for pending := range channels {
		channel, requests, err := pending.Accept()
		if err != nil {
			t.Errorf("accept SCP test channel: %v", err)
			return
		}
		workers.Go(func() {
			defer closeSCPTestResource(t, channel)
			for request := range requests {
				accepted := request.Type == "subsystem" && string(request.Payload) == string(cryptossh.Marshal(struct{ Name string }{"sftp"}))
				if err := request.Reply(accepted, nil); err != nil {
					t.Errorf("reply to SCP test subsystem: %v", err)
					return
				}
				if accepted {
					server, err := pkgsftp.NewServer(channel, pkgsftp.WithServerWorkingDirectory(home))
					if err != nil {
						t.Errorf("create SCP test SFTP server: %v", err)
						return
					}
					defer closeSCPTestResource(t, server)
					if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
						t.Errorf("serve SCP test SFTP: %v", err)
					}
					return
				}
			}
		})
	}
}

func writeSCPTestFile(t *testing.T, name, content string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(name, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func assertSCPTestFile(t *testing.T, name, want string) {
	t.Helper()
	content, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != want {
		t.Fatalf("file %q = %q, want %q", name, content, want)
	}
}

func setSCPTestConfirmation(t *testing.T, response string) {
	t.Helper()
	name := filepath.Join(t.TempDir(), "stdin")
	writeSCPTestFile(t, name, response+"\n")
	input, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = input
	t.Cleanup(func() {
		os.Stdin = original
		closeSCPTestResource(t, input)
	})
}

func TestSCPUploadRemoteHome(t *testing.T) {
	for _, target := range []string{"~/code/", "~", "", "~/renamed.txt", "code/"} {
		t.Run(target, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			if err := os.Mkdir(filepath.Join(fixture.home, "code"), 0o700); err != nil {
				t.Fatal(err)
			}
			local := filepath.Join(t.TempDir(), "payload.txt")
			writeSCPTestFile(t, local, "payload")
			options := NewScpOptions()
			if err := options.runUpload(fixture.ctx, local, PathInfo{Host: "scp-test", Path: target}, fixture.repo, fixture.connector); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(fixture.home, "payload.txt")
			switch target {
			case "~/code/", "code/":
				want = filepath.Join(fixture.home, "code", "payload.txt")
			case "~/renamed.txt":
				want = filepath.Join(fixture.home, "renamed.txt")
			}
			assertSCPTestFile(t, want, "payload")
		})
	}
}

func TestSCPDownloadRemoteHome(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	writeSCPTestFile(t, filepath.Join(fixture.home, "payload.txt"), "payload")
	destination := t.TempDir()
	options := NewScpOptions()
	if err := options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: "~/payload.txt"}, destination, fixture.repo, fixture.connector); err != nil {
		t.Fatal(err)
	}
	assertSCPTestFile(t, filepath.Join(destination, "payload.txt"), "payload")
}

func TestSCPBatchAndRelayRemoteHome(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	for _, dir := range []string{"batch", "relay"} {
		if err := os.Mkdir(filepath.Join(fixture.home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	options := NewScpOptions()
	options.Source = filepath.Join(t.TempDir(), "payload.txt")
	options.Dest = "~/batch/"
	writeSCPTestFile(t, options.Source, "payload")
	if err := options.executeTransfer(fixture.ctx, "scp-test", PathInfo{Host: "scp-test"}, "", fixture.repo, fixture.connector); err != nil {
		t.Fatal(err)
	}
	assertSCPTestFile(t, filepath.Join(fixture.home, "batch", "payload.txt"), "payload")
	if err := options.runRemoteToRemote(fixture.ctx,
		PathInfo{Host: "scp-test", Path: "~/batch/payload.txt"},
		PathInfo{Host: "scp-test", Path: "~/relay/"}, fixture.repo, fixture.connector); err != nil {
		t.Fatal(err)
	}
	assertSCPTestFile(t, filepath.Join(fixture.home, "relay", "payload.txt"), "payload")
}

func TestSCPOverwriteMatchingMetadata(t *testing.T) {
	for _, direction := range []string{"upload", "download"} {
		for _, policy := range []string{"confirm", "force", "decline", "no-clobber"} {
			t.Run(direction+"/"+policy, func(t *testing.T) {
				fixture := newSCPTransferFixture(t)
				local := filepath.Join(t.TempDir(), "payload.txt")
				remote := filepath.Join(fixture.home, "payload.txt")
				remotePath := path.Join(fixture.remoteHome, "payload.txt")
				source, destination := local, remote
				if direction == "download" {
					source, destination = remote, local
				}
				writeSCPTestFile(t, source, "new bytes")
				writeSCPTestFile(t, destination, "old bytes")
				options := NewScpOptions()
				options.Force = policy == "force"
				options.NoOverwrite = policy == "no-clobber"
				answer := "n"
				if policy == "confirm" {
					answer = "y"
				}
				setSCPTestConfirmation(t, answer)
				var err error
				if direction == "upload" {
					err = options.runUpload(fixture.ctx, local, PathInfo{Host: "scp-test", Path: remotePath}, fixture.repo, fixture.connector)
				} else {
					err = options.runDownload(fixture.ctx, PathInfo{Host: "scp-test", Path: remotePath}, filepath.Dir(local), fixture.repo, fixture.connector)
				}
				if err != nil {
					t.Fatal(err)
				}
				want := "old bytes"
				if policy == "force" || policy == "confirm" {
					want = "new bytes"
				}
				assertSCPTestFile(t, destination, want)
			})
		}
	}
}

func TestSCPRemoteHomeExpansionBoundaries(t *testing.T) {
	fixture := newSCPTransferFixture(t)
	options := NewScpOptions()
	_, client, err := options.connectSftpForPath(fixture.ctx, PathInfo{Host: "scp-test"}, "", fixture.repo, fixture.connector)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSCPTestResource(t, client)
	for _, remotePath := range []string{"relative/path", "/absolute/path", "./~/literal", "file~name"} {
		got, err := expandSCPRemotePath(fixture.ctx, client, remotePath)
		if err != nil || got != remotePath {
			t.Fatalf("expand %q = %q, %v", remotePath, got, err)
		}
	}
	for _, remotePath := range []string{"~other", "~other/file"} {
		if _, err := expandSCPRemotePath(fixture.ctx, client, remotePath); err == nil || !strings.Contains(err.Error(), "absolute path") {
			t.Fatalf("expand %q error = %v, want unsupported home error", remotePath, err)
		}
	}
	got, err := expandSCPRemotePath(fixture.ctx, client, "~/missing directory/")
	if err != nil || got != path.Join(fixture.remoteHome, "missing directory")+"/" {
		t.Fatalf("expand missing directory = %q, %v", got, err)
	}
	ctx, cancel := context.WithCancel(fixture.ctx)
	cancel()
	if _, err := expandSCPRemotePath(ctx, client, "~/file"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled expansion error = %v", err)
	}
}
