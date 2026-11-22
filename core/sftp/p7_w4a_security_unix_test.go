//go:build unix

package sftp

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/wentf9/xops-cli/core/fsx"
	"golang.org/x/sys/unix"
)

func TestP7W4a_M1_UploadAndDownloadRejectFIFOWithoutBlocking(t *testing.T) {
	t.Run("upload_and_uploadFile_reject_fifo_immediately", func(t *testing.T) {
		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		dir := t.TempDir()
		fifoPath := filepath.Join(dir, "stall.fifo")
		if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
			t.Fatalf("Mkfifo failed: %v", err)
		}

		for name, fn := range map[string]func() error{
			"Upload": func() error {
				return client.Upload(t.Context(), fifoPath, "/stall.fifo", nil)
			},
			"UploadFile": func() error {
				return client.UploadFile(t.Context(), fifoPath, "/stall.fifo", 0, 0o600, nil)
			},
		} {
			t.Run(name, func(t *testing.T) {
				done := make(chan error, 1)
				go func() { done <- fn() }()
				select {
				case err := <-done:
					if !errors.Is(err, fsx.ErrNonRegular) {
						t.Fatalf("%s(fifo) = %v, want fsx.ErrNonRegular", name, err)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("%s blocked on local FIFO", name)
				}
			})
		}
	})

	t.Run("download_staging_fifo_rejected_immediately", func(t *testing.T) {
		client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
		f, err := client.state.sftpClient.Create("/remote.txt")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("hello"))
		_ = f.Close()

		dir := t.TempDir()
		dst := filepath.Join(dir, "remote.txt")
		stagingFIFO := dst + client.config.TempSuffix
		if err := unix.Mkfifo(stagingFIFO, 0o600); err != nil {
			t.Fatalf("Mkfifo failed: %v", err)
		}

		remotePath, _ := ParseRemotePath("/remote.txt")
		dest, _ := LocalDestPath(dst)
		done := make(chan error, 1)
		go func() {
			done <- client.Download(t.Context(), remotePath, dest, DownloadOptions{})
		}()
		select {
		case dlErr := <-done:
			if !errors.Is(dlErr, fsx.ErrNonRegular) {
				t.Fatalf("Download with FIFO staging file = %v, want fsx.ErrNonRegular", dlErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Download blocked on FIFO staging file")
		}
	})
}
