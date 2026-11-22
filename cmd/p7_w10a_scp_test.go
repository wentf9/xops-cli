package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type w10aRealPathRelayHandler struct {
	*p7RelayRecordingHandler
	realPath string
}

func (h *w10aRealPathRelayHandler) RealPath(string) (string, error) {
	return h.realPath, nil
}

func startW10aSCPNodeRepoAndConnector(t *testing.T, ctx context.Context, nodes map[string]int) (*config.Repository, *xssh.Connector) {
	t.Helper()
	prov, err := config.NewProvider(nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	snap := prov.Snapshot()
	snap.Identities.Set("test", models.Identity{User: "test", AuthType: "password", Password: "test"})
	cfgs := make(map[string]*xssh.ClientConfig, len(nodes))
	for alias, port := range nodes {
		hostID := net.JoinHostPort(alias+".fixture.invalid", strconv.Itoa(port))
		snap.Hosts.Set(hostID, models.Host{Address: alias + ".fixture.invalid", Port: uint16(port)})
		nodeID := "test@" + hostID
		snap.Nodes.Set(nodeID, models.Node{HostRef: hostID, IdentityRef: "test", Alias: []string{alias}})
		cfgs[nodeID] = &xssh.ClientConfig{
			NodeID:   nodeID,
			Address:  "127.0.0.1",
			Port:     port,
			User:     "test",
			AuthType: "password",
			Password: "test",
		}
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(snap, &memoryStore{cfg: snap})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	connector := xssh.NewConnector(p7MultiNodeTestProvider{configs: cfgs}, xssh.WithEnvironment(sshenv.Discover()))
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("close connector: %v", closeErr)
		}
	})
	_ = ctx
	return repo, connector
}

// TestP7W10a_AB10M1_SCPRejectsNegativeRemoteFileSize verifies AB10-M1 in
// cmd/scp.go: negative remote regular-file sizes (-1, -50) fail closed in both
// download and remote-to-remote relay flows before overwriting destinations.
func TestP7W10a_AB10M1_SCPRejectsNegativeRemoteFileSize(t *testing.T) {
	t.Run("download_negative_size_fails_closed_preserves_local", func(t *testing.T) {
		for _, negSize := range []int64{-1, -50} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			srcHandler := &p7RelayRecordingHandler{
				stats: map[string]os.FileInfo{
					"/remote/neg.bin": p7RelayFileInfo{name: "neg.bin", size: negSize, mode: 0o644},
				},
				files: map[string][]byte{
					"/remote/neg.bin": []byte("payload"),
				},
			}
			port := startP7RelaySFTPServer(t, ctx, srcHandler)
			repo, connector := startW10aSCPNodeRepoAndConnector(t, ctx, map[string]int{"neg-src": port})

			localPath := filepath.Join(t.TempDir(), "neg.bin")
			const sentinel = "keep-local-intact"
			if err := os.WriteFile(localPath, []byte(sentinel), 0o600); err != nil {
				t.Fatal(err)
			}

			opts := NewScpOptions()
			opts.Source = "neg-src:/remote/neg.bin"
			opts.Dest = localPath
			opts.Force = true
			opts.Quiet = true

			err := opts.runTransfer(ctx, repo, connector)
			if !errors.Is(err, sftp.ErrInvalidRemoteSize) {
				t.Fatalf("scp download (size=%d) err = %v, want ErrInvalidRemoteSize", negSize, err)
			}
			got, readErr := os.ReadFile(localPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != sentinel {
				t.Fatalf("scp download (size=%d) overwrote local file: got %q, want %q", negSize, got, sentinel)
			}
		}
	})

	t.Run("remote_to_remote_negative_size_fails_closed_preserves_dst", func(t *testing.T) {
		for _, negSize := range []int64{-1, -50} {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			srcHandler := &p7RelayRecordingHandler{
				stats: map[string]os.FileInfo{
					"/remote/neg.bin": p7RelayFileInfo{name: "neg.bin", size: negSize, mode: 0o644},
				},
				files: map[string][]byte{
					"/remote/neg.bin": []byte("payload"),
				},
			}
			dstHandler := &p7RelayRecordingHandler{
				stats: map[string]os.FileInfo{
					"/dst/target.bin": p7RelayFileInfo{name: "target.bin", size: 12, mode: 0o644},
				},
			}
			srcPort := startP7RelaySFTPServer(t, ctx, srcHandler)
			dstPort := startP7RelaySFTPServer(t, ctx, dstHandler)
			repo, connector := startW10aSCPNodeRepoAndConnector(t, ctx, map[string]int{
				"neg-relay-src": srcPort,
				"neg-relay-dst": dstPort,
			})

			opts := NewScpOptions()
			opts.Source = "neg-relay-src:/remote/neg.bin"
			opts.Dest = "neg-relay-dst:/dst/target.bin"
			opts.Force = true
			opts.Quiet = true

			err := opts.runTransfer(ctx, repo, connector)
			if !errors.Is(err, sftp.ErrInvalidRemoteSize) {
				t.Fatalf("scp relay (size=%d) err = %v, want ErrInvalidRemoteSize", negSize, err)
			}
			if writes := dstHandler.recordedWrites(); len(writes) != 0 {
				t.Fatalf("scp relay (size=%d) wrote destination despite negative source size: %v", negSize, writes)
			}
		}
	})
}

// TestP7W10a_AB10L1_ExpandSCPRemotePathRejectsEmptyAndNonAbsoluteCwd verifies
// AB10-L1: expandSCPRemotePath fails closed if client.Cwd returns an empty,
// control-char, or non-absolute path instead of rewriting "~/foo" to "/foo".
func TestP7W10a_AB10L1_ExpandSCPRemotePathRejectsEmptyAndNonAbsoluteCwd(t *testing.T) {
	startWithRealPath := func(t *testing.T, realPath string) *sftp.Client {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)

		handler := &w10aRealPathRelayHandler{
			p7RelayRecordingHandler: &p7RelayRecordingHandler{
				stats: make(map[string]os.FileInfo),
				files: make(map[string][]byte),
			},
			realPath: realPath,
		}
		port := startW10aCustomSFTPServer(t, ctx, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})
		repo, connector := startW10aSCPNodeRepoAndConnector(t, ctx, map[string]int{"rp-host": port})
		opts := NewScpOptions()
		_, client, err := opts.connectSftpForPath(ctx, PathInfo{Host: "rp-host"}, "", repo, connector)
		if err != nil {
			t.Fatalf("connectSftpForPath: %v", err)
		}
		t.Cleanup(func() { _ = client.Close() })
		return client
	}

	for _, tc := range []struct {
		name     string
		realPath string
	}{
		{"empty_cwd", ""},
		{"relative_cwd", "relative/home"},
		{"dot_cwd", "."},
		{"control_escape_cwd", "/home/alice\x1b[31m"},
	} {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			client := startWithRealPath(t, tc.realPath)
			for _, in := range []string{"~", "~/file.txt"} {
				got, err := expandSCPRemotePath(t.Context(), client, in)
				if err == nil {
					t.Fatalf("expandSCPRemotePath(cwd=%q, %q) = %q, nil; want error", tc.realPath, in, got)
				}
			}
		})
	}

	for _, tc := range []struct {
		name     string
		realPath string
		input    string
		want     string
	}{
		{"abs_home_tilde", "/home/alice/", "~", "/home/alice"},
		{"abs_home_subpath", "/home/alice/", "~/sub/dir/", "/home/alice/sub/dir/"},
		{"root_home_tilde", "/", "~", "/"},
		{"root_home_subpath", "/", "~/file.txt", "/file.txt"},
	} {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			client := startWithRealPath(t, tc.realPath)
			got, err := expandSCPRemotePath(t.Context(), client, tc.input)
			if err != nil || got != tc.want {
				t.Fatalf("expandSCPRemotePath(cwd=%q, %q) = (%q, %v), want (%q, nil)", tc.realPath, tc.input, got, err, tc.want)
			}
		})
	}
}

func startW10aCustomSFTPServer(t *testing.T, ctx context.Context, handlers pkgsftp.Handlers) int {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	serverCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go serveW10aSSHConn(ctx, conn, serverCfg, handlers, &wg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveW10aSSHConn(ctx context.Context, conn net.Conn, serverCfg *cryptoSSH.ServerConfig, handlers pkgsftp.Handlers, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	sConn, chans, reqs, srvErr := cryptoSSH.NewServerConn(conn, serverCfg)
	if srvErr != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	for pending := range chans {
		ch, chReqs, chErr := pending.Accept()
		if chErr != nil {
			return
		}
		wg.Add(1)
		go func(channel cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
			defer wg.Done()
			defer func() { _ = channel.Close() }()
			for req := range requests {
				if req.Type == "subsystem" && string(req.Payload) == string(cryptoSSH.Marshal(struct{ Name string }{"sftp"})) {
					_ = req.Reply(true, nil)
					srv := pkgsftp.NewRequestServer(channel, handlers)
					_ = srv.Serve()
					_ = srv.Close()
					return
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}(ch, chReqs)
	}
}

// TestP7W10a_AB10L2_DeterminateFailedProgressBarDoesNotJumpTo100Percent verifies
// AB10-L2: finishing an incomplete determinate progress bar (size > 0) after
// partial progress does NOT call bar.Close() (so it never jumps to 100%), ends
// with a clean newline, and leaves no leaked spinner goroutine; indeterminate
// directory bars (size < 0) still close cleanly and stop their spinner goroutine.
func TestP7W10a_AB10L2_DeterminateFailedProgressBarDoesNotJumpTo100Percent(t *testing.T) {
	sinkPath := filepath.Join(t.TempDir(), "determinate-progress.log")
	sink, err := os.Create(sinkPath)
	if err != nil {
		t.Fatalf("create progress sink: %v", err)
	}

	output, err := newSCPDiagnostics(t.Context(), sink, "stderr", false, 0)
	if err != nil {
		_ = sink.Close()
		t.Fatalf("newSCPDiagnostics: %v", err)
	}

	beforeSpinners := countProgressBarSpinnerGoroutines()
	bar, progress, finish := newTransferProgressBar(1000, "Downloading partial.bin", output, 0)
	progress(250)

	if err := finish(); err != nil {
		_ = sink.Close()
		t.Fatalf("finish() returned error: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	if bar.IsFinished() {
		t.Fatal("failed/canceled determinate bar unexpectedly marked IsFinished()==true")
	}
	if after := countProgressBarSpinnerGoroutines(); after > beforeSpinners {
		t.Fatalf("determinate bar leaked spinner goroutine: before=%d after=%d", beforeSpinners, after)
	}

	renderedBytes, err := os.ReadFile(sinkPath)
	if err != nil {
		t.Fatalf("read progress sink: %v", err)
	}
	rendered := string(renderedBytes)
	if strings.Contains(rendered, "100%") {
		t.Fatalf("failed determinate progress bar jumped to 100%%:\n%q", rendered)
	}
	if !strings.HasSuffix(rendered, "\n") {
		t.Fatalf("failed determinate progress bar missing trailing newline:\n%q", rendered)
	}
}
