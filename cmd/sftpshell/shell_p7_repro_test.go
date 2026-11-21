//go:build p7repro

package sftpshell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type p7ReproFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f p7ReproFileInfo) Name() string       { return f.name }
func (f p7ReproFileInfo) Size() int64        { return f.size }
func (f p7ReproFileInfo) Mode() os.FileMode  { return f.mode }
func (f p7ReproFileInfo) ModTime() time.Time { return time.Unix(1700000000, 0) }
func (f p7ReproFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f p7ReproFileInfo) Sys() any           { return nil }

type p7ReproListerAt []os.FileInfo

func (l p7ReproListerAt) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

type p7ReproSFTPHandler struct {
	stats    map[string]os.FileInfo
	dirLists map[string][]os.FileInfo
	files    map[string][]byte
}

func (h *p7ReproSFTPHandler) Fileread(r *pkgsftp.Request) (io.ReaderAt, error) {
	if data, ok := h.files[r.Filepath]; ok {
		return bytes.NewReader(data), nil
	}
	return nil, os.ErrNotExist
}

func (h *p7ReproSFTPHandler) Filewrite(*pkgsftp.Request) (io.WriterAt, error) {
	return nil, os.ErrPermission
}

func (h *p7ReproSFTPHandler) Filecmd(*pkgsftp.Request) error {
	return os.ErrPermission
}

func (h *p7ReproSFTPHandler) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	switch r.Method {
	case "Stat", "Lstat":
		if fi, ok := h.stats[r.Filepath]; ok {
			return p7ReproListerAt{fi}, nil
		}
		return nil, os.ErrNotExist
	case "List":
		if entries, ok := h.dirLists[r.Filepath]; ok {
			return p7ReproListerAt(entries), nil
		}
		return nil, os.ErrNotExist
	default:
		return nil, os.ErrInvalid
	}
}

func newP7ReproSFTPShell(t *testing.T, handler *p7ReproSFTPHandler, remoteCwd, localCwd string) *Shell {
	t.Helper()
	initTestI18n(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(privKey)
	if err != nil {
		t.Fatalf("create SSH signer: %v", err)
	}
	serverCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback for in-process SFTP server: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(serverConn net.Conn) {
				defer wg.Done()
				defer func() { _ = serverConn.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = serverConn.Close() })
				defer stop()
				sConn, chans, reqs, srvErr := cryptoSSH.NewServerConn(serverConn, serverCfg)
				if srvErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
				go cryptoSSH.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, acceptChErr := newCh.Accept()
					if acceptChErr != nil {
						return
					}
					wg.Add(1)
					go func(c cryptoSSH.Channel, requests <-chan *cryptoSSH.Request) {
						defer wg.Done()
						defer func() { _ = c.Close() }()
						for req := range requests {
							if req.Type == "subsystem" && string(req.Payload) == string(cryptoSSH.Marshal(struct{ Name string }{"sftp"})) {
								_ = req.Reply(true, nil)
								srv := pkgsftp.NewRequestServer(c, pkgsftp.Handlers{
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

	rawSSH, err := cryptoSSH.Dial("tcp", ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptoSSH.FixedHostKey(signer.PublicKey()),
		Timeout:         3 * time.Second,
	})
	if err != nil {
		cancel()
		_ = ln.Close()
		wg.Wait()
		t.Fatalf("SSH client handshake: %v", err)
	}
	wrappedSSH := ssh.NewTestClientWithRaw(rawSSH, ssh.ConnectionConfig{})

	sftpCli, err := sftp.NewClient(ctx, wrappedSSH, sftp.WithForce(true))
	if err != nil {
		cancel()
		_ = wrappedSSH.Close()
		_ = ln.Close()
		wg.Wait()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = sftpCli.Close()
		_ = wrappedSSH.Close()
		_ = ln.Close()
		wg.Wait()
	})

	return &Shell{
		client:         sftpCli,
		sshClient:      wrappedSSH,
		cwd:            remoteCwd,
		localCwd:       localCwd,
		stdin:          bytes.NewBuffer(nil),
		stdout:         &bytes.Buffer{},
		stderr:         &bytes.Buffer{},
		batch:          true,
		transferConfig: sftpCli.Config(),
	}
}

// TestP7Repro_H2_HostileRemoteNamesReachDownloadFileAndDirectory reproduces H2 (part 1):
// handleGet / getSingle / resolveLocalDownloadDestination compute localDest with
// filepath.Base and call DownloadFile/DownloadDirectory directly, bypassing
// core/sftp download validation for hostile remote names and ".." via dirty paths.
func TestP7Repro_H2_HostileRemoteNamesReachDownloadFileAndDirectory(t *testing.T) {
	fileCases := []struct {
		name       string
		remotePath string
		baseName   string
	}{
		{name: "windows_reserved_CON_txt", remotePath: "/remote/CON.txt", baseName: "CON.txt"},
		{name: "ntfs_ads_colon", remotePath: "/remote/foo:bar", baseName: "foo:bar"},
		{name: "backslash_traversal_component", remotePath: `/remote/a\..\x`, baseName: `a\..\x`},
		{name: "trailing_dot", remotePath: "/remote/report.", baseName: "report."},
	}

	for _, tc := range fileCases {
		t.Run("file_"+tc.name, func(t *testing.T) {
			payload := []byte("hostile-file")
			handler := &p7ReproSFTPHandler{
				stats: map[string]os.FileInfo{
					tc.remotePath: p7ReproFileInfo{name: tc.baseName, size: int64(len(payload)), mode: 0o644},
				},
				files: map[string][]byte{
					tc.remotePath: payload,
				},
			}
			parent := t.TempDir()
			localDir := filepath.Join(parent, "downloads")
			if err := os.MkdirAll(localDir, 0o755); err != nil {
				t.Fatalf("mkdir localDir: %v", err)
			}

			shell := newP7ReproSFTPShell(t, handler, "/remote", localDir)
			err := shell.handleGet(t.Context(), []string{tc.remotePath, localDir})
			if err == nil {
				t.Fatalf("handleGet(%q, %q) succeeded (bypassed core/sftp validation and wrote hostile target), want error", tc.remotePath, localDir)
			}

			entries, readErr := os.ReadDir(localDir)
			if readErr != nil {
				t.Fatalf("ReadDir(%q): %v", localDir, readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("localDir must remain empty after rejected hostile download, got %d entries", len(entries))
			}
		})
	}

	t.Run("dirty_path_dotdot_escapes_local_dir_via_DownloadDirectory", func(t *testing.T) {
		payload := []byte("escaped-via-dotdot")
		handler := &p7ReproSFTPHandler{
			stats: map[string]os.FileInfo{
				"/remote":             p7ReproFileInfo{name: "remote", mode: os.ModeDir | 0o755},
				"/remote/sub/..":      p7ReproFileInfo{name: "..", mode: os.ModeDir | 0o755},
				"/remote/escaped.txt": p7ReproFileInfo{name: "escaped.txt", size: int64(len(payload)), mode: 0o644},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote": {
					p7ReproFileInfo{name: "escaped.txt", size: int64(len(payload)), mode: 0o644},
				},
				"/remote/sub/..": {
					p7ReproFileInfo{name: "escaped.txt", size: int64(len(payload)), mode: 0o644},
				},
			},
			files: map[string][]byte{
				"/remote/escaped.txt":        payload,
				"/remote/sub/../escaped.txt": payload,
			},
		}

		parent := t.TempDir()
		localDir := filepath.Join(parent, "downloads")
		if err := os.MkdirAll(localDir, 0o755); err != nil {
			t.Fatalf("mkdir localDir: %v", err)
		}

		// Direct check: resolveLocalDownloadDestination must not escape localDir via filepath.Base("/remote/sub/..") == "..".
		dest, _, resErr := resolveLocalDownloadDestination(localDir, "/remote/sub/..")
		if resErr == nil && filepath.Clean(dest) == filepath.Clean(parent) {
			t.Errorf("resolveLocalDownloadDestination(%q, \"/remote/sub/..\") escaped into parent dir %q", localDir, dest)
		}

		shell := newP7ReproSFTPShell(t, handler, "/remote", localDir)
		err := shell.handleGet(t.Context(), []string{"/remote/sub/..", localDir})
		if err == nil {
			t.Fatalf("handleGet(\"/remote/sub/..\", %q) succeeded, want error rejecting '..' traversal", localDir)
		}
		if _, statErr := os.Lstat(filepath.Join(parent, "escaped.txt")); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("dirty path '..' wrote escaped file %q outside localDir", filepath.Join(parent, "escaped.txt"))
		}
	})

	t.Run("hostile_dir_CON_txt_reaches_DownloadDirectory", func(t *testing.T) {
		payload := []byte("inside-con-dir")
		handler := &p7ReproSFTPHandler{
			stats: map[string]os.FileInfo{
				"/remote/CON.txt":        p7ReproFileInfo{name: "CON.txt", mode: os.ModeDir | 0o755},
				"/remote/CON.txt/ok.txt": p7ReproFileInfo{name: "ok.txt", size: int64(len(payload)), mode: 0o644},
			},
			dirLists: map[string][]os.FileInfo{
				"/remote/CON.txt": {
					p7ReproFileInfo{name: "ok.txt", size: int64(len(payload)), mode: 0o644},
				},
			},
			files: map[string][]byte{
				"/remote/CON.txt/ok.txt": payload,
			},
		}

		parent := t.TempDir()
		localDir := filepath.Join(parent, "downloads")
		if err := os.MkdirAll(localDir, 0o755); err != nil {
			t.Fatalf("mkdir localDir: %v", err)
		}

		shell := newP7ReproSFTPShell(t, handler, "/remote", localDir)
		err := shell.handleGet(t.Context(), []string{"/remote/CON.txt", localDir})
		if err == nil {
			t.Fatalf("handleGet(\"/remote/CON.txt\", %q) succeeded (hostile directory reached DownloadDirectory), want error", localDir)
		}
	})
}

// TestP7Repro_H2_SingleArgGetIgnoresLocalCwd reproduces H2 (part 2):
// single-argument `get <remote>` initializes local = filepath.Base(remote)
// without resolving against s.localCwd, writing into the process CWD instead.
func TestP7Repro_H2_SingleArgGetIgnoresLocalCwd(t *testing.T) {
	procDir := t.TempDir()
	localCwdDir := t.TempDir()
	t.Chdir(procDir)

	payload := []byte("single-arg-payload")
	handler := &p7ReproSFTPHandler{
		stats: map[string]os.FileInfo{
			"/remote/hello.txt": p7ReproFileInfo{name: "hello.txt", size: int64(len(payload)), mode: 0o644},
		},
		files: map[string][]byte{
			"/remote/hello.txt": payload,
		},
	}

	shell := newP7ReproSFTPShell(t, handler, "/remote", localCwdDir)
	if err := shell.handleGet(t.Context(), []string{"/remote/hello.txt"}); err != nil {
		t.Fatalf("handleGet single-arg failed: %v", err)
	}

	wantPath := filepath.Join(localCwdDir, "hello.txt")
	got, err := os.ReadFile(wantPath)
	if err != nil {
		wrongPath := filepath.Join(procDir, "hello.txt")
		_, wroteToProcCwd := os.Stat(wrongPath)
		t.Fatalf("single-arg get ignored shell.localCwd=%q (read %q: %v; file landed in process CWD %q: %v)",
			localCwdDir, wantPath, err, wrongPath, wroteToProcCwd == nil)
	}
	if string(got) != string(payload) {
		t.Fatalf("downloaded content = %q, want %q", string(got), string(payload))
	}
	if _, statErr := os.Stat(filepath.Join(procDir, "hello.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("single-arg get unexpectedly wrote to process CWD %q instead of localCwd %q", procDir, localCwdDir)
	}
}
