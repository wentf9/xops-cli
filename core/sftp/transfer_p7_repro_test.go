package sftp

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

func newP7ReproDirSFTPClient(t *testing.T, remoteRoot string) *Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	server, err := pkgsftp.NewServer(serverConn, pkgsftp.WithServerWorkingDirectory(remoteRoot))
	if err != nil {
		_ = serverConn.Close()
		_ = clientConn.Close()
		t.Fatalf("create in-process SFTP server: %v", err)
	}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve()
	}()

	sftpClient, err := pkgsftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		_ = server.Close()
		_ = clientConn.Close()
		<-serverErr
		t.Fatalf("create in-process SFTP client: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := sftpClient.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) && !errors.Is(closeErr, io.ErrClosedPipe) {
			t.Errorf("close SFTP client: %v", closeErr)
		}
		if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) && !errors.Is(closeErr, io.ErrClosedPipe) {
			t.Errorf("close SFTP server: %v", closeErr)
		}
		if serveErr := <-serverErr; serveErr != nil && !errors.Is(serveErr, io.EOF) && !errors.Is(serveErr, io.ErrClosedPipe) {
			t.Errorf("serve SFTP server: %v", serveErr)
		}
	})

	return &Client{
		state:  &clientState{sftpClient: sftpClient},
		config: DefaultConfig(),
	}
}

// TestP7Repro_H1_DownloadDirectoryDotRoot verifies H1 (part 1):
// RemotePath.RelativeTo and Client.Download handle remote root "." and "./"
// cleanly, including direct and nested children.
func TestP7Repro_H1_DownloadDirectoryDotRoot(t *testing.T) {
	t.Run("RelativeTo_dot_root", func(t *testing.T) {
		cases := []struct {
			name     string
			base     string
			target   string
			wantSegs []string
		}{
			{name: "dot_direct_child", base: ".", target: "file.txt", wantSegs: []string{"file.txt"}},
			{name: "dot_nested_child", base: ".", target: "sub/nested.txt", wantSegs: []string{"sub", "nested.txt"}},
			{name: "dot_slash_direct_child", base: "./", target: "file.txt", wantSegs: []string{"file.txt"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				root, err := ParseRemotePath(tc.base)
				if err != nil {
					t.Fatalf("ParseRemotePath(%q): %v", tc.base, err)
				}
				target, err := ParseRemotePath(tc.target)
				if err != nil {
					t.Fatalf("ParseRemotePath(%q): %v", tc.target, err)
				}
				segs, err := target.RelativeTo(root)
				if err != nil {
					t.Fatalf("RelativeTo(%q, %q) failed: %v", target, root, err)
				}
				got := make([]string, len(segs))
				for i, s := range segs {
					got[i] = s.String()
				}
				if !slices.Equal(got, tc.wantSegs) {
					t.Fatalf("RelativeTo(%q, %q) = %v, want %v", target, root, got, tc.wantSegs)
				}
			})
		}
	})

	t.Run("Download_dot_root", func(t *testing.T) {
		remoteRoot := t.TempDir()
		if err := os.WriteFile(filepath.Join(remoteRoot, "file.txt"), []byte("root-payload"), 0o644); err != nil {
			t.Fatalf("write remote file.txt: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(remoteRoot, "zsub"), 0o755); err != nil {
			t.Fatalf("mkdir remote zsub: %v", err)
		}
		if err := os.WriteFile(filepath.Join(remoteRoot, "zsub", "nested.txt"), []byte("nested-payload"), 0o644); err != nil {
			t.Fatalf("write remote zsub/nested.txt: %v", err)
		}

		client := newP7ReproDirSFTPClient(t, remoteRoot)
		localDir := t.TempDir()
		dotRoot, err := ParseRemotePath(".")
		if err != nil {
			t.Fatalf("ParseRemotePath(\".\"): %v", err)
		}
		dest, err := LocalDestPath(localDir)
		if err != nil {
			t.Fatalf("LocalDestPath: %v", err)
		}
		if err := client.Download(t.Context(), dotRoot, dest, DownloadOptions{}); err != nil {
			t.Fatalf("Download(\".\", %q) failed: %v", localDir, err)
		}

		for rel, want := range map[string]string{
			"file.txt":                          "root-payload",
			filepath.Join("zsub", "nested.txt"): "nested-payload",
		} {
			got, err := os.ReadFile(filepath.Join(localDir, rel))
			if err != nil {
				t.Fatalf("read downloaded %q: %v", rel, err)
			}
			if string(got) != want {
				t.Fatalf("downloaded %q = %q, want %q", rel, string(got), want)
			}
		}
	})
}

// TestP7Repro_H1_NonCanonicalBaseRejectsDotDotEntries verifies H1 (part 2):
// non-canonical bases ("/a//b", "/a/./b", "/tmp/x/../data") are normalized by
// ParseRemotePath and every directory entry from the server is validated as a
// RemoteName, rejecting raw ".." traversal entries without skipping validation.
func TestP7Repro_H1_NonCanonicalBaseRejectsDotDotEntries(t *testing.T) {
	cases := []struct {
		name      string
		rawBase   string
		cleanBase string
		entryName string
	}{
		{
			name:      "double_slash_base_with_dotdot_child",
			rawBase:   "/a//b",
			cleanBase: "/a/b",
			entryName: "../escape.txt",
		},
		{
			name:      "dot_segment_base_with_dotdot_child",
			rawBase:   "/a/./b",
			cleanBase: "/a/b",
			entryName: "sub/../escape.txt",
		},
		{
			name:      "dirty_base_with_cleaned_prefix_and_dotdot_child",
			rawBase:   "/tmp/x/../data",
			cleanBase: "/tmp/data",
			entryName: "../escape.txt",
		},
		{
			name:      "double_slash_base_collapsing_to_root",
			rawBase:   "/a//b",
			cleanBase: "/a/b",
			entryName: "./..",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &maliciousSFTPHandler{
				statInfos: map[string]os.FileInfo{
					tc.cleanBase:          syntheticFileInfo{name: "root", mode: os.ModeDir | 0o755},
					tc.cleanBase + "/sub": syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
				},
				dirLists: map[string][]os.FileInfo{
					tc.cleanBase: {
						syntheticFileInfo{name: "sub", mode: os.ModeDir | 0o755},
					},
					tc.cleanBase + "/sub": {
						syntheticFileInfo{name: tc.entryName, size: 7, mode: 0o644},
					},
				},
				files: map[string][]byte{},
			}
			client := newTestSFTPClientWithHandlers(t, pkgsftp.Handlers{
				FileGet:  handler,
				FilePut:  handler,
				FileCmd:  handler,
				FileList: handler,
			})

			remoteRoot, err := ParseRemotePath(tc.rawBase)
			if err != nil {
				t.Fatalf("ParseRemotePath(%q): %v", tc.rawBase, err)
			}
			parent := t.TempDir()
			localDir := filepath.Join(parent, "dst")
			dest, err := LocalDestPath(localDir)
			if err != nil {
				t.Fatalf("LocalDestPath: %v", err)
			}

			if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err == nil {
				t.Fatalf("Download(%q) with malicious entry %q succeeded, want fail-closed error", tc.rawBase, tc.entryName)
			}
			if _, statErr := os.Lstat(filepath.Join(parent, "escape.txt")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("unexpected escaped file in parent dir: %v", statErr)
			}
		})
	}
}

// TestP7Repro_LOW5_DownloadSymlinkPolicyB verifies download symlink policy (b):
// only relative symlink targets whose step-by-step traversal stays inside the
// download root are preserved; absolute, escaping, bounce-escaping, backslash,
// drive-prefixed, and reserved-device targets fail closed with ErrUnsafeDownloadSymlink.
func TestP7Repro_LOW5_DownloadSymlinkPolicyB(t *testing.T) {
	t.Run("reject_unsafe_targets", func(t *testing.T) {
		rejectCases := []struct {
			name    string
			relDir  string
			target  string
			linkDir string
		}{
			{name: "absolute_etc_passwd", relDir: "", target: "/etc/passwd"},
			{name: "absolute_inside_remote_root", relDir: "", target: "/remote_sym/ok.txt"},
			{name: "escape_from_root", relDir: "", target: "../outside.txt"},
			{name: "escape_from_subdir", relDir: "sub", target: "../../outside.txt"},
			{name: "intermediate_bounce_escape", relDir: "sub", target: "../../remote_sym/ok.txt"},
			{name: "backslash_escape", relDir: "sub", target: `..\..\outside.txt`},
			{name: "windows_drive_absolute", relDir: "", target: `C:\Windows\win.ini`},
			{name: "reserved_device_target", relDir: "", target: "CON.txt"},
			{name: "reserved_superscript_target", relDir: "", target: "COM\u00b9.txt"},
		}
		for _, tc := range rejectCases {
			t.Run(tc.name, func(t *testing.T) {
				client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
				remoteDir := "/remote_sym"
				if tc.relDir != "" {
					remoteDir += "/" + tc.relDir
				}
				if err := client.state.sftpClient.MkdirAll(remoteDir); err != nil {
					t.Fatalf("MkdirAll(%q): %v", remoteDir, err)
				}
				linkPath := remoteDir + "/evil_link"
				if err := client.state.sftpClient.Symlink(tc.target, linkPath); err != nil {
					t.Fatalf("Symlink(%q, %q): %v", tc.target, linkPath, err)
				}

				localDst := t.TempDir()
				remoteRoot, _ := ParseRemotePath("/remote_sym")
				dest, _ := LocalDestPath(localDst)
				err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{})
				if err == nil {
					t.Fatalf("Download symlink %q -> %q succeeded, want ErrUnsafeDownloadSymlink", linkPath, tc.target)
				}
				if !errors.Is(err, ErrUnsafeDownloadSymlink) {
					t.Fatalf("Download symlink %q -> %q error = %v, want ErrUnsafeDownloadSymlink", linkPath, tc.target, err)
				}

				localLink := filepath.Join(localDst, tc.relDir, "evil_link")
				if _, lstatErr := os.Lstat(localLink); !errors.Is(lstatErr, os.ErrNotExist) {
					t.Fatalf("rejected symlink %q must not exist locally: %v", localLink, lstatErr)
				}
			})
		}
	})

	t.Run("preserve_safe_relative_in_root_symlinks", func(t *testing.T) {
		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		if err := client.state.sftpClient.MkdirAll("/remote_safe/a/b"); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		f, err := client.state.sftpClient.Create("/remote_safe/target.txt")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		_, _ = f.Write([]byte("ok"))
		_ = f.Close()

		if err := client.state.sftpClient.Symlink("../../target.txt", "/remote_safe/a/b/link_to_root_file"); err != nil {
			t.Fatalf("Symlink in-root: %v", err)
		}
		if err := client.state.sftpClient.Symlink("missing_sibling.txt", "/remote_safe/dangling_inside"); err != nil {
			t.Fatalf("Symlink dangling inside: %v", err)
		}

		localDst := t.TempDir()
		remoteRoot, _ := ParseRemotePath("/remote_safe")
		dest, _ := LocalDestPath(localDst)
		if err := client.Download(t.Context(), remoteRoot, dest, DownloadOptions{}); err != nil {
			if runtime.GOOS == "windows" {
				t.Skip("skipping local symlink creation check on Windows")
			}
			t.Fatalf("Download safe relative symlinks failed: %v", err)
		}

		got1, err := os.Readlink(filepath.Join(localDst, "a", "b", "link_to_root_file"))
		if err != nil || filepath.ToSlash(got1) != "../../target.txt" {
			t.Fatalf("readlink link_to_root_file = (%q, %v), want ../../target.txt", got1, err)
		}
		got2, err := os.Readlink(filepath.Join(localDst, "dangling_inside"))
		if err != nil || filepath.ToSlash(got2) != "missing_sibling.txt" {
			t.Fatalf("readlink dangling_inside = (%q, %v), want missing_sibling.txt", got2, err)
		}
	})
}

func TestClient_Download_GlobSupport(t *testing.T) {
	remoteRoot := t.TempDir()
	for name, body := range map[string]string{
		"a.log": "alpha",
		"b.log": "beta",
		"c.txt": "gamma",
	} {
		if err := os.WriteFile(filepath.Join(remoteRoot, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %q: %v", name, err)
		}
	}
	client := newP7ReproDirSFTPClient(t, remoteRoot)

	t.Run("multi_match_into_dir", func(t *testing.T) {
		localDir := t.TempDir()
		pattern, _ := ParseRemotePath("*.log")
		dest, _ := LocalDestInto(localDir)
		if err := client.Download(t.Context(), pattern, dest, DownloadOptions{ExpandGlob: true}); err != nil {
			t.Fatalf("Download glob *.log failed: %v", err)
		}
		for name, want := range map[string]string{"a.log": "alpha", "b.log": "beta"} {
			got, err := os.ReadFile(filepath.Join(localDir, name))
			if err != nil || string(got) != want {
				t.Fatalf("read %q = (%q, %v), want %q", name, string(got), err, want)
			}
		}
		if _, err := os.Stat(filepath.Join(localDir, "c.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unmatched c.txt unexpectedly downloaded: %v", err)
		}
	})

	t.Run("multi_match_into_non_dir_rejected", func(t *testing.T) {
		localFile := filepath.Join(t.TempDir(), "not-a-dir.txt")
		pattern, _ := ParseRemotePath("*.log")
		dest, _ := LocalDestInto(localFile)
		err := client.Download(t.Context(), pattern, dest, DownloadOptions{ExpandGlob: true})
		if !errors.Is(err, ErrLocalDestNotDir) {
			t.Fatalf("Download multi-glob into non-dir err = %v, want ErrLocalDestNotDir", err)
		}
	})

	t.Run("no_match_returns_ErrGlobNoMatch", func(t *testing.T) {
		pattern, _ := ParseRemotePath("*.nope")
		dest, _ := LocalDestInto(t.TempDir())
		err := client.Download(t.Context(), pattern, dest, DownloadOptions{ExpandGlob: true})
		if !errors.Is(err, ErrGlobNoMatch) {
			t.Fatalf("Download unmatched glob err = %v, want ErrGlobNoMatch", err)
		}
	})
}
