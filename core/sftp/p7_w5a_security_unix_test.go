//go:build unix

package sftp

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

func newRealFSSFTPClient(t *testing.T, rootDir string) *Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	server, err := pkgsftp.NewServer(serverConn, pkgsftp.WithServerWorkingDirectory(rootDir))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve()
	}()
	rawClient, err := pkgsftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatalf("NewClientPipe: %v", err)
	}
	t.Cleanup(func() {
		_ = rawClient.Close()
		_ = server.Close()
		if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("serve real-fs SFTP server: %v", err)
		}
	})
	return &Client{state: &clientState{sftpClient: rawClient}, config: DefaultConfig()}
}

func TestP7W5a_AB5M1_UnixReadOnlyDirAndFIFORejected(t *testing.T) {
	t.Run("readonly_dir_escaping_ondisk_symlink_rejected_leaves_no_live_escape", func(t *testing.T) {
		outsideDir := t.TempDir()
		localDst := t.TempDir()
		roDir := filepath.Join(localDst, "ro")
		if err := os.MkdirAll(roDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(roDir, "ext")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(roDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/roattack":    syntheticFileInfo{name: "roattack", mode: os.ModeDir | 0o755},
					"/roattack/ro": syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/roattack": {
						syntheticFileInfo{name: "a_escape", mode: os.ModeSymlink | 0o777},
						syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
					},
					"/roattack/ro": {
						syntheticFileInfo{name: "ext", mode: os.ModeSymlink | 0o777},
					},
				},
			},
			readLinks: map[string][]string{
				"/roattack/a_escape": {"ro/ext/secret"},
				"/roattack/ro/ext":   {"safe"},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})

		remoteRoot, _ := ParseRemotePath("/roattack")
		dest, _ := LocalDestPath(localDst)
		err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
		if !errors.Is(err, ErrUnsafeDownloadSymlink) {
			t.Fatalf("Download against 0555 dir escaping symlink = %v, want ErrUnsafeDownloadSymlink", err)
		}
		if _, lstatErr := os.Lstat(filepath.Join(localDst, "a_escape")); !errors.Is(lstatErr, os.ErrNotExist) {
			t.Fatalf("a_escape must not exist on disk: %v", lstatErr)
		}
	})

	t.Run("readonly_dir_safe_ondisk_symlink_replace_attempted_before_new_symlink", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses 0555 directory permission checks")
		}
		localDst := t.TempDir()
		roDir := filepath.Join(localDst, "ro")
		if err := os.MkdirAll(roDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("safe_old", filepath.Join(roDir, "ext")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(roDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

		handler := &customReadLinkHandler{
			maliciousSFTPHandler: maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					"/roorder":    syntheticFileInfo{name: "roorder", mode: os.ModeDir | 0o755},
					"/roorder/ro": syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					"/roorder": {
						syntheticFileInfo{name: "a_new", mode: os.ModeSymlink | 0o777},
						syntheticFileInfo{name: "ro", mode: os.ModeDir | 0o755},
					},
					"/roorder/ro": {
						syntheticFileInfo{name: "ext", mode: os.ModeSymlink | 0o777},
					},
				},
			},
			readLinks: map[string][]string{
				"/roorder/a_new":  {"ro/ext/file"},
				"/roorder/ro/ext": {"safe_new"},
			},
		}
		client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
			FileGet:  handler,
			FilePut:  handler,
			FileCmd:  handler,
			FileList: handler,
		})

		remoteRoot, _ := ParseRemotePath("/roorder")
		dest, _ := LocalDestPath(localDst)
		err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
		if err == nil {
			t.Fatal("expected EACCES error when replacing symlink inside 0555 directory")
		}
		if _, lstatErr := os.Lstat(filepath.Join(localDst, "a_new")); !errors.Is(lstatErr, os.ErrNotExist) {
			t.Fatalf("a_new must not be created before pre-existing ro/ext replacement succeeds: %v", lstatErr)
		}
	})

	t.Run("real_fifo_on_disk_rejected_by_symlink_validation", func(t *testing.T) {
		localDst := t.TempDir()
		fifoPath := filepath.Join(localDst, "pipe")
		if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatalf("Mkfifo: %v", err)
		}

		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		if err := client.state.sftpClient.MkdirAll("/fifo_tree"); err != nil {
			t.Fatal(err)
		}
		if err := client.state.sftpClient.Symlink("pipe/child", "/fifo_tree/link"); err != nil {
			t.Fatal(err)
		}

		remoteRoot, _ := ParseRemotePath("/fifo_tree")
		dest, _ := LocalDestPath(localDst)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); !errors.Is(err, ErrUnsafeDownloadSymlink) {
			t.Fatalf("Download through real on-disk FIFO = %v, want ErrUnsafeDownloadSymlink", err)
		}
	})
}

func TestP7W5a_AB5M2_RelayFileFromPreserves0600AndRefusesTempSymlinkOnRealFS(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcFile := filepath.Join(srcDir, "id_ed25519")
	if err := os.WriteFile(srcFile, []byte("private-ssh-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(srcFile, 0o600); err != nil {
		t.Fatal(err)
	}

	srcClient := newRealFSSFTPClient(t, srcDir)
	dstClient := newRealFSSFTPClient(t, dstDir)

	srcRemote, _ := ParseRemotePath(srcFile)
	dstFile := filepath.Join(dstDir, "id_ed25519")
	dstRemote, _ := ParseRemotePath(dstFile)

	if err := dstClient.RelayFileFrom(t.Context(), srcClient, srcRemote, dstRemote, nil, nil); err != nil {
		t.Fatalf("RelayFileFrom real FS failed: %v", err)
	}
	info, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("Stat(%q): %v", dstFile, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("relayed file mode = %04o, want 0600", got)
	}

	// Pre-existing symlink at .xops-tmp must fail closed without truncating target.
	victim := filepath.Join(dstDir, "victim.txt")
	if err := os.WriteFile(victim, []byte("intact-victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstFile2 := filepath.Join(dstDir, "id_ed25519_2")
	if err := os.Symlink(victim, dstFile2+dstClient.config.TempSuffix); err != nil {
		t.Fatal(err)
	}
	dstRemote2, _ := ParseRemotePath(dstFile2)
	err = dstClient.RelayFileFrom(t.Context(), srcClient, srcRemote, dstRemote2, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("RelayFileFrom with symlink temp file = %v, want not a regular file error", err)
	}
	after, err := os.ReadFile(victim)
	if err != nil || string(after) != "intact-victim" {
		t.Fatalf("victim corrupted = (%q, %v), want \"intact-victim\"", string(after), err)
	}
}
