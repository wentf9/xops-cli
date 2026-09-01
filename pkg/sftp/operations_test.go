package sftp

import (
	"errors"
	"os"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

func TestClient_RemoveAllAndRename(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	if err := client.state.sftpClient.MkdirAll("/tree/sub"); err != nil {
		t.Fatalf("create remote directory: %v", err)
	}
	file, err := client.state.sftpClient.Create("/tree/sub/file.txt")
	if err != nil {
		t.Fatalf("create remote file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close remote file: %v", err)
	}
	if err := client.state.sftpClient.Symlink("../outside", "/tree/link"); err != nil {
		t.Fatalf("create remote symlink: %v", err)
	}

	if err := client.Rename(t.Context(), "/tree/sub/file.txt", "/tree/sub/renamed.txt"); err != nil {
		t.Fatalf("rename remote file: %v", err)
	}
	if _, err := client.state.sftpClient.Lstat("/tree/sub/renamed.txt"); err != nil {
		t.Fatalf("lstat renamed file: %v", err)
	}

	if err := client.RemoveAll(t.Context(), "/tree"); err != nil {
		t.Fatalf("remove remote tree: %v", err)
	}
	if _, err := client.state.sftpClient.Lstat("/tree"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lstat removed tree got %v, want os.ErrNotExist", err)
	}
	if err := client.RemoveAll(t.Context(), "/missing"); err != nil {
		t.Fatalf("remove missing remote path: %v", err)
	}
}
