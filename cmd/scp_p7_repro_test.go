//go:build p7repro

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestP7Repro_MED15_WindowsReservedSuperscriptDeviceNames reproduces MED-15 (part 1):
// cmd/scp's duplicate isWindowsReservedLocalDeviceName checks len(stem)==4, missing
// 2-byte UTF-8 superscripts COM¹/COM²/COM³/LPT¹/LPT²/LPT³ (len==5).
func TestP7Repro_MED15_WindowsReservedSuperscriptDeviceNames(t *testing.T) {
	stems := []string{
		"COM\u00b9", "COM\u00b2", "COM\u00b3",
		"LPT\u00b9", "LPT\u00b2", "LPT\u00b3",
		"com\u00b9", "lpt\u00b3",
	}
	for _, stem := range stems {
		t.Run("stem_"+stem, func(t *testing.T) {
			if !isWindowsReservedLocalDeviceName(stem) {
				t.Errorf("isWindowsReservedLocalDeviceName(%q) = false, want true", stem)
			}
			filename := stem + ".txt"
			if isSafeLocalPathComponent(filename) {
				t.Errorf("isSafeLocalPathComponent(%q) = true, want false", filename)
			}
		})
	}
}

// TestP7Repro_MED15_RunDownloadDirectDownloadFileBypass reproduces MED-15 (part 2):
// ScpOptions.runDownload single-file path validates with cmd/scp's incomplete
// isSafeLocalPathComponent and calls DownloadFile directly instead of core/sftp's
// Download facade, allowing COM¹.txt and LPT³.log to be downloaded into a local dir.
func TestP7Repro_MED15_RunDownloadDirectDownloadFileBypass(t *testing.T) {
	cases := []struct {
		name     string
		filename string
	}{
		{name: "COM_superscript_1", filename: "COM\u00b9.txt"},
		{name: "LPT_superscript_3", filename: "LPT\u00b3.log"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSCPTransferFixture(t)
			writeSCPTestFile(t, filepath.Join(fixture.home, tc.filename), "superscript-device-payload")

			localDir := t.TempDir()
			opts := NewScpOptions()
			opts.Source = "scp-test:./" + tc.filename
			opts.Dest = localDir
			opts.Force = true
			opts.Quiet = true

			err := opts.runTransfer(fixture.ctx, fixture.repo, fixture.connector)
			if err == nil {
				t.Fatalf("runTransfer(%q -> %q) succeeded via direct DownloadFile bypass, want fail-closed error", opts.Source, localDir)
			}
			entries, readErr := os.ReadDir(localDir)
			if readErr != nil {
				t.Fatalf("ReadDir(%q): %v", localDir, readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("localDir must remain empty after rejected download, got %d entries", len(entries))
			}
		})
	}
}

type p7RelayFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f p7RelayFileInfo) Name() string       { return f.name }
func (f p7RelayFileInfo) Size() int64        { return f.size }
func (f p7RelayFileInfo) Mode() os.FileMode  { return f.mode }
func (f p7RelayFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (f p7RelayFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f p7RelayFileInfo) Sys() any           { return nil }

type p7RelayListerAt []os.FileInfo

func (l p7RelayListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

type p7RelayDiscardWriterAt struct{}

func (p7RelayDiscardWriterAt) WriteAt(p []byte, _ int64) (int, error) {
	return len(p), nil
}

type p7RelayRecordingHandler struct {
	mu           sync.Mutex
	stats        map[string]os.FileInfo
	files        map[string][]byte
	writtenPaths []string
	cmdPaths     []string
}

func (h *p7RelayRecordingHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if data, ok := h.files[r.Filepath]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, os.ErrNotExist
}

func (h *p7RelayRecordingHandler) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	h.mu.Lock()
	h.writtenPaths = append(h.writtenPaths, r.Filepath)
	h.mu.Unlock()
	return p7RelayDiscardWriterAt{}, nil
}

func (h *p7RelayRecordingHandler) Filecmd(r *pkgsftp.Request) error {
	h.mu.Lock()
	h.cmdPaths = append(h.cmdPaths, r.Method+":"+r.Filepath+"->"+r.Target)
	h.mu.Unlock()
	return nil
}

func (h *p7RelayRecordingHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method == "Stat" || r.Method == "Lstat" {
		if fi, ok := h.stats[r.Filepath]; ok {
			return p7RelayListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	}
	return nil, os.ErrInvalid
}

func (h *p7RelayRecordingHandler) recordedWrites() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.writtenPaths))
	copy(out, h.writtenPaths)
	return out
}

func startP7RelaySFTPServer(t *testing.T, ctx context.Context, handler *p7RelayRecordingHandler) int {
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
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = c.Close() })
				defer stop()
				sConn, chans, reqs, srvErr := cryptoSSH.NewServerConn(c, serverCfg)
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
								srv := pkgsftp.NewRequestServer(channel, pkgsftp.Handlers{
									FileGet:  handler,
									FilePut:  handler,
									FileCmd:  handler,
									FileList: handler,
								})
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
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

type p7MultiNodeTestProvider struct {
	configs map[string]*xssh.ClientConfig
}

func (p p7MultiNodeTestProvider) GetConfig(nodeID string) (*xssh.ClientConfig, error) {
	cfg, ok := p.configs[nodeID]
	if !ok {
		return nil, config.ErrNodeNotFound
	}
	return cfg, nil
}

// TestP7Repro_MED15_RunRemoteToRemoteDotDotEscapeAndFilepathBase reproduces MED-15 (part 3):
// ScpOptions.runRemoteToRemote derives the destination filename via filepath.Base(src.Path)
// on a POSIX remote path and joins it with dstSftp.JoinPath without validating the component,
// allowing a dirty/hostile remote source path like "/remote/sub/.." to escape dstDir.
func TestP7Repro_MED15_RunRemoteToRemoteDotDotEscapeAndFilepathBase(t *testing.T) {
	t.Run("dotdot_escape_writes_outside_dst_dir", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		payload := []byte("escaped-relay-payload")
		srcHandler := &p7RelayRecordingHandler{
			stats: map[string]os.FileInfo{
				"/remote/sub/..": p7RelayFileInfo{name: "..", size: int64(len(payload)), mode: 0o644},
				"/remote":        p7RelayFileInfo{name: "..", size: int64(len(payload)), mode: 0o644},
			},
			files: map[string][]byte{
				"/remote/sub/..": payload,
				"/remote":        payload,
			},
		}
		dstHandler := &p7RelayRecordingHandler{
			stats: map[string]os.FileInfo{
				"/dst/parent/target": p7RelayFileInfo{name: "target", mode: os.ModeDir | 0o755},
				"/dst/parent":        p7RelayFileInfo{name: "parent", mode: os.ModeDir | 0o755},
			},
		}

		srcPort := startP7RelaySFTPServer(t, ctx, srcHandler)
		dstPort := startP7RelaySFTPServer(t, ctx, dstHandler)

		prov, err := config.NewProvider(nil)
		if err != nil {
			t.Fatalf("NewProvider: %v", err)
		}
		snap := prov.Snapshot()
		srcHostID := net.JoinHostPort("src.fixture.invalid", strconv.Itoa(srcPort))
		dstHostID := net.JoinHostPort("dst.fixture.invalid", strconv.Itoa(dstPort))
		snap.Hosts.Set(srcHostID, models.Host{Address: "src.fixture.invalid", Port: uint16(srcPort)})
		snap.Hosts.Set(dstHostID, models.Host{Address: "dst.fixture.invalid", Port: uint16(dstPort)})
		snap.Identities.Set("test", models.Identity{User: "test", AuthType: "password", Password: "test"})
		srcNodeID := "test@" + srcHostID
		dstNodeID := "test@" + dstHostID
		snap.Nodes.Set(srcNodeID, models.Node{HostRef: srcHostID, IdentityRef: "test", Alias: []string{"relay-src"}})
		snap.Nodes.Set(dstNodeID, models.Node{HostRef: dstHostID, IdentityRef: "test", Alias: []string{"relay-dst"}})

		repo, err := config.NewRepositoryWithoutOpenSSH(snap, &memoryStore{cfg: snap})
		if err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
		}
		connector := xssh.NewConnector(p7MultiNodeTestProvider{
			configs: map[string]*xssh.ClientConfig{
				srcNodeID: {NodeID: srcNodeID, Address: "127.0.0.1", Port: srcPort, User: "test", AuthType: "password", Password: "test"},
				dstNodeID: {NodeID: dstNodeID, Address: "127.0.0.1", Port: dstPort, User: "test", AuthType: "password", Password: "test"},
			},
		}, xssh.WithEnvironment(sshenv.Discover()))
		connector.AcceptNewHostKey.Store(true)
		t.Cleanup(func() {
			if closeErr := connector.CloseAll(); closeErr != nil {
				t.Errorf("close connector: %v", closeErr)
			}
		})

		opts := NewScpOptions()
		opts.Source = "relay-src:/remote/sub/.."
		opts.Dest = "relay-dst:/dst/parent/target"
		opts.Force = true
		opts.Quiet = true

		err = opts.runTransfer(ctx, repo, connector)
		writes := dstHandler.recordedWrites()
		if err == nil {
			t.Fatalf("runRemoteToRemote(%q -> %q) succeeded (writes=%v), want fail-closed error rejecting '..' escape", opts.Source, opts.Dest, writes)
		}
		for _, w := range writes {
			if !strings.HasPrefix(w, "/dst/parent/target/") {
				t.Fatalf("runRemoteToRemote wrote outside destination directory /dst/parent/target: %q (all writes=%v)", w, writes)
			}
		}
	})

	t.Run("runRemoteToRemote_must_not_use_filepath_Base_on_remote_paths", func(t *testing.T) {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("failed to locate test file path")
		}
		scpGoPath := filepath.Join(filepath.Dir(thisFile), "scp.go")
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, scpGoPath, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", scpGoPath, err)
		}

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "runRemoteToRemote" || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkgIdent, ok := sel.X.(*ast.Ident)
				if ok && pkgIdent.Name == "filepath" && sel.Sel.Name == "Base" {
					pos := fset.Position(call.Pos())
					t.Errorf("%s:%d: runRemoteToRemote uses OS-dependent filepath.Base on a POSIX remote path",
						filepath.Base(pos.Filename), pos.Line)
				}
				return true
			})
		}
	})
}
