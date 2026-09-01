package sftp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pkgsftp "github.com/pkg/sftp"
	"golang.org/x/sync/errgroup"
)

type failingFileCmder struct {
	delegate pkgsftp.FileCmder
	err      error
}

func (c failingFileCmder) Filecmd(request *pkgsftp.Request) error {
	if request.Method == "Setstat" {
		return c.err
	}
	return c.delegate.Filecmd(request)
}

func newTestSFTPClient(t *testing.T, commandErr error) *Client {
	t.Helper()
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = failingFileCmder{delegate: handlers.FileCmd, err: commandErr}
	return newTestSFTPClientWithHandlers(t, handlers)
}

func newTestSFTPClientWithHandlers(t *testing.T, handlers pkgsftp.Handlers) *Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	server := pkgsftp.NewRequestServer(serverConn, handlers)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve()
	}()

	client, err := pkgsftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatalf("create in-memory SFTP client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close in-memory SFTP client: %v", err)
		}
		if err := server.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("close in-memory SFTP server: %v", err)
		}
		if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("serve in-memory SFTP server: %v", err)
		}
	})

	return &Client{state: &clientState{sftpClient: client}, config: DefaultConfig()}
}

type failingPosixRenameFileCmder struct {
	delegate pkgsftp.FileCmder
	err      error
}

func (c failingPosixRenameFileCmder) Filecmd(request *pkgsftp.Request) error {
	return c.delegate.Filecmd(request)
}

func (c failingPosixRenameFileCmder) PosixRename(*pkgsftp.Request) error {
	return c.err
}

func TestClient_UploadFileReturnsMetadataError(t *testing.T) {
	wantErr := errors.New("setstat failed")
	client := newTestSFTPClient(t, wantErr)
	localPath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(localPath, []byte("payload"), 0o640); err != nil {
		t.Fatalf("write local fixture: %v", err)
	}

	err := client.UploadFile(t.Context(), localPath, "/payload.txt", 7, 0o640, nil)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("UploadFile error = %v, want wrapped metadata error", err)
	}
}

func TestClient_UploadFilePreservesDestinationWhenAtomicRenameFails(t *testing.T) {
	wantErr := errors.New("rename failed")
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = failingPosixRenameFileCmder{delegate: handlers.FileCmd, err: wantErr}
	client := newTestSFTPClientWithHandlers(t, handlers)

	remote, err := client.state.sftpClient.Create("/payload.txt")
	if err != nil {
		t.Fatalf("create remote fixture: %v", err)
	}
	if _, err := remote.Write([]byte("original")); err != nil {
		t.Fatalf("write remote fixture: %v", err)
	}
	if err := remote.Close(); err != nil {
		t.Fatalf("close remote fixture: %v", err)
	}

	localPath := filepath.Join(t.TempDir(), "payload.txt")
	if err := os.WriteFile(localPath, []byte("replacement"), 0o640); err != nil {
		t.Fatalf("write local fixture: %v", err)
	}
	err = client.UploadFile(t.Context(), localPath, "/payload.txt", int64(len("replacement")), 0o640, nil)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("UploadFile() error = %v, want atomic rename error", err)
	}

	preserved, err := client.state.sftpClient.Open("/payload.txt")
	if err != nil {
		t.Fatalf("open preserved destination: %v", err)
	}
	content, err := io.ReadAll(preserved)
	if err != nil {
		t.Fatalf("read preserved destination: %v", err)
	}
	if err := preserved.Close(); err != nil {
		t.Fatalf("close preserved destination: %v", err)
	}
	if string(content) != "original" {
		t.Fatalf("destination content = %q, want original content", content)
	}
}

func TestFinishTransferGroupCancelsAndWaitsForWorkers(t *testing.T) {
	operationErr := errors.New("walk failed")
	ctx, cancel := context.WithCancel(t.Context())
	group, groupCtx := errgroup.WithContext(ctx)
	workerDone := make(chan struct{})
	group.Go(func() error {
		<-groupCtx.Done()
		close(workerDone)
		return nil
	})

	err := finishTransferGroup(cancel, group, operationErr)
	if !errors.Is(err, operationErr) {
		t.Fatalf("finishTransferGroup() error = %v, want operation error", err)
	}
	select {
	case <-workerDone:
	default:
		t.Fatal("finishTransferGroup() returned before worker exit")
	}
}

func TestRemoteRelativePath(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		target  string
		want    string
		wantErr bool
	}{
		{name: "root", base: "/data", target: "/data", want: "."},
		{name: "child", base: "/data", target: "/data/log/app.log", want: "log/app.log"},
		{name: "filesystem root", base: "/", target: "/var/log/app.log", want: "var/log/app.log"},
		{name: "similar prefix outside root", base: "/data", target: "/database/file", wantErr: true},
		{name: "parent outside root", base: "/data/log", target: "/data/secret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := remoteRelativePath(tt.base, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("remoteRelativePath(%q, %q) error = nil, want error", tt.base, tt.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("remoteRelativePath(%q, %q) error = %v", tt.base, tt.target, err)
			}
			if got != tt.want {
				t.Fatalf("remoteRelativePath(%q, %q) = %q, want %q", tt.base, tt.target, got, tt.want)
			}
		})
	}
}
