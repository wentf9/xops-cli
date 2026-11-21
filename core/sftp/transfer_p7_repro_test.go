//go:build p7repro

package sftp

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
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

// TestP7Repro_H1_DownloadDirectoryDotRoot reproduces H1 (part 1):
// remoteRelativePath fails when the remote download root is "." because
// prefix becomes "./", which does not match Walk's child paths ("file.txt").
func TestP7Repro_H1_DownloadDirectoryDotRoot(t *testing.T) {
	t.Run("remoteRelativePath_dot_root", func(t *testing.T) {
		cases := []struct {
			name   string
			base   string
			target string
			want   string
		}{
			{name: "dot_direct_child", base: ".", target: "file.txt", want: "file.txt"},
			{name: "dot_nested_child", base: ".", target: "sub/nested.txt", want: "sub/nested.txt"},
			{name: "dot_slash_direct_child", base: "./", target: "file.txt", want: "file.txt"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := remoteRelativePath(tc.base, tc.target)
				if err != nil {
					t.Fatalf("remoteRelativePath(%q, %q) failed: %v (want %q)", tc.base, tc.target, err, tc.want)
				}
				if got != tc.want {
					t.Fatalf("remoteRelativePath(%q, %q) = %q, want %q", tc.base, tc.target, got, tc.want)
				}
			})
		}
	})

	t.Run("DownloadDirectory_dot_root", func(t *testing.T) {
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
		if err := client.DownloadDirectory(t.Context(), ".", localDir, nil); err != nil {
			t.Fatalf("DownloadDirectory(\".\", %q) failed: %v", localDir, err)
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

// TestP7Repro_H1_RemoteRelativePathNonCanonicalBaseSkipsDotDotScan reproduces H1 (part 2):
// when base is non-canonical (e.g. "/a//b", "/a/./b", "/tmp/x/../data"),
// strings.HasPrefix(target, rawBase+"/") is false, so remoteRelativePath skips
// scanning target for raw ".." traversal segments before path.Clean collapses them.
func TestP7Repro_H1_RemoteRelativePathNonCanonicalBaseSkipsDotDotScan(t *testing.T) {
	cases := []struct {
		name   string
		base   string
		target string
	}{
		{
			name:   "double_slash_base_with_dotdot_child",
			base:   "/a//b",
			target: "/a/b/sub/../escape.txt",
		},
		{
			name:   "dot_segment_base_with_dotdot_child",
			base:   "/a/./b",
			target: "/a/b/sub/../escape.txt",
		},
		{
			name:   "dirty_base_with_cleaned_prefix_and_dotdot_child",
			base:   "/tmp/x/../data",
			target: "/tmp/data/sub/../escape.txt",
		},
		{
			name:   "double_slash_base_collapsing_to_root",
			base:   "/a//b",
			target: "/a/b/sub/..",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := remoteRelativePath(tc.base, tc.target)
			if err == nil {
				t.Fatalf("remoteRelativePath(%q, %q) = %q, nil; want error rejecting raw '..' traversal", tc.base, tc.target, got)
			}
		})
	}
}
