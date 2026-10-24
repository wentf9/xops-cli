package sftp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

type directorySetstatFileCmder struct {
	delegate pkgsftp.FileCmder
	lister   pkgsftp.FileLister
}

func (c directorySetstatFileCmder) Filecmd(r *pkgsftp.Request) error {
	err := c.delegate.Filecmd(r)
	if errors.Is(err, os.ErrInvalid) && r.Method == "Setstat" && c.lister != nil {
		statReq := pkgsftp.NewRequest("Stat", r.Filepath)
		if _, statErr := c.lister.Filelist(statReq); statErr == nil {
			return nil
		}
	}
	return err
}

func (c directorySetstatFileCmder) PosixRename(r *pkgsftp.Request) error {
	if pr, ok := c.delegate.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return errors.New("posix rename not supported")
}

func (c directorySetstatFileCmder) StatVFS(r *pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	if svfs, ok := c.delegate.(pkgsftp.StatVFSFileCmder); ok {
		return svfs.StatVFS(r)
	}
	return nil, errors.New("statvfs not supported")
}

func newTestSFTPClientWithHandlers(t *testing.T, handlers pkgsftp.Handlers) *Client {
	t.Helper()
	if handlers.FileCmd != nil && handlers.FileList != nil {
		handlers.FileCmd = directorySetstatFileCmder{
			delegate: handlers.FileCmd,
			lister:   handlers.FileList,
		}
	}
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
		if err := server.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("close in-memory SFTP server: %v", err)
		}
		if err := <-serverErr; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
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

	err := finishTransferGroup(ctx, cancel, group, operationErr)
	if !errors.Is(err, operationErr) {
		t.Fatalf("finishTransferGroup() error = %v, want operation error", err)
	}
	select {
	case <-workerDone:
	default:
		t.Fatal("finishTransferGroup() returned before worker exit")
	}
}

func TestFinishTransferGroupFiltersInternalContextCanceled(t *testing.T) {
	parentCtx := t.Context()
	transferCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	group, groupCtx := errgroup.WithContext(transferCtx)

	wantWorkerErr := errors.New("upload specific file failed")
	group.Go(func() error {
		return wantWorkerErr
	})

	_ = group.Wait()
	operationErr := groupCtx.Err() // context.Canceled

	err := finishTransferGroup(parentCtx, cancel, group, operationErr)
	if !errors.Is(err, wantWorkerErr) {
		t.Fatalf("finishTransferGroup() error = %v, want worker error", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatalf("finishTransferGroup() error = %v, did not want context.Canceled", err)
	}
}

func TestFinishTransferGroupPreservesParentContextCanceled(t *testing.T) {
	parentCtx, parentCancel := context.WithCancel(t.Context())
	parentCancel()

	transferCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	group, groupCtx := errgroup.WithContext(transferCtx)

	wantWorkerErr := errors.New("upload specific file failed")
	group.Go(func() error {
		return wantWorkerErr
	})

	_ = group.Wait()
	operationErr := groupCtx.Err()

	err := finishTransferGroup(parentCtx, cancel, group, operationErr)
	if !errors.Is(err, wantWorkerErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("finishTransferGroup() error = %v, want both worker error and context.Canceled", err)
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

type vfsStatCmder struct {
	pkgsftp.FileCmder
	vfs *pkgsftp.StatVFS
}

func (c vfsStatCmder) StatVFS(r *pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	if c.vfs != nil {
		return c.vfs, nil
	}
	return nil, errors.New("unsupported")
}

func (c vfsStatCmder) PosixRename(r *pkgsftp.Request) error {
	if pr, ok := c.FileCmder.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return errors.New("posix rename not supported")
}

type failingFileWriteTransfer struct {
	delegate pkgsftp.FileWriter
	writeErr error
}

func (f failingFileWriteTransfer) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	return f.delegate.Filewrite(r)
}

func TestClient_UploadFile_InsufficientStorageDetected(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = vfsStatCmder{
		FileCmder: handlers.FileCmd,
		vfs: &pkgsftp.StatVFS{
			Bsize:  4096,
			Frsize: 4096,
			Blocks: 10 * 1024 * 1024, // 40 GB
			Bfree:  0,                // 0 free
			Bavail: 0,
		},
	}
	sftpFailureErr := errors.New("sftp: \"Failure\" (SSH_FX_FAILURE)")
	handlers.FilePut = failingFileWriteTransfer{
		delegate: handlers.FilePut,
		writeErr: sftpFailureErr,
	}

	client := newTestSFTPClientWithHandlers(t, handlers)
	localPath := filepath.Join(t.TempDir(), "songque.png")
	if err := os.WriteFile(localPath, []byte("data"), 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	err := client.UploadFile(t.Context(), localPath, "/songque.png", 4, 0o644, nil)
	if err == nil {
		t.Fatal("expected UploadFile to fail")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "insufficient remote storage space") {
		t.Errorf("expected error to mention 'insufficient remote storage space', got: %v", errMsg)
	}
	if !strings.Contains(errMsg, "0 B free of 40.0 GB") {
		t.Errorf("expected error to contain '0 B free of 40.0 GB', got: %v", errMsg)
	}
}

type chunkFailingFileWriter struct {
	io.WriterAt
	writeErr error
}

func (w *chunkFailingFileWriter) WriteAt(p []byte, off int64) (n int, err error) {
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return w.WriterAt.WriteAt(p, off)
}

func (w *chunkFailingFileWriter) Close() error {
	if c, ok := w.WriterAt.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

type chunkFailingFilePut struct {
	delegate pkgsftp.FileWriter
	writeErr error
}

func (f *chunkFailingFilePut) Filewrite(r *pkgsftp.Request) (io.WriterAt, error) {
	w, err := f.delegate.Filewrite(r)
	if err != nil {
		return nil, err
	}
	return &chunkFailingFileWriter{WriterAt: w, writeErr: f.writeErr}, nil
}

func TestClient_UploadFile_ContentWriteInsufficientStorageDetected(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = vfsStatCmder{
		FileCmder: handlers.FileCmd,
		vfs: &pkgsftp.StatVFS{
			Bsize:  4096,
			Frsize: 4096,
			Blocks: 10 * 1024 * 1024, // 40 GB
			Bfree:  6,                // 6 * 4096 = 24576 bytes (24.0 KB)
			Bavail: 6,
		},
	}
	sftpFailureErr := errors.New("sftp: \"Failure\" (SSH_FX_FAILURE)")
	handlers.FilePut = &chunkFailingFilePut{
		delegate: handlers.FilePut,
		writeErr: sftpFailureErr,
	}

	client := newTestSFTPClientWithHandlers(t, handlers)
	localPath := filepath.Join(t.TempDir(), "songque.png")
	content := make([]byte, 50*1024)
	if err := os.WriteFile(localPath, content, 0o644); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	err := client.UploadFile(t.Context(), localPath, "/songque.png", int64(len(content)), 0o644, nil)
	if err == nil {
		t.Fatal("expected UploadFile to fail")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "insufficient remote storage space") {
		t.Errorf("expected error to mention 'insufficient remote storage space', got: %v", errMsg)
	}
	if !strings.Contains(errMsg, "24.0 KB free of 40.0 GB") {
		t.Errorf("expected error to contain '24.0 KB free of 40.0 GB', got: %v", errMsg)
	}
}

func TestStorageSpaceCalculations(t *testing.T) {
	vfs := &pkgsftp.StatVFS{
		Frsize: 4096,
		Blocks: 10 * 1024 * 1024,
		Bfree:  1000,
		Bavail: 500,
	}
	avail := AvailableStorageSpace(vfs)
	total := TotalStorageSpace(vfs)
	if avail != 500*4096 {
		t.Errorf("expected avail %d, got %d", 500*4096, avail)
	}
	if total != 10*1024*1024*4096 {
		t.Errorf("expected total %d, got %d", uint64(10*1024*1024*4096), total)
	}
	if got := FormatByteSize(avail); got != "2.0 MB" {
		t.Errorf("expected '2.0 MB', got %q", got)
	}
	if got := FormatByteSize(total); got != "40.0 GB" {
		t.Errorf("expected '40.0 GB', got %q", got)
	}

	// Test non-root user when user quota/disk is full (Bavail == 0, Bfree > 0)
	vfsZeroAvail := &pkgsftp.StatVFS{
		Frsize: 4096,
		Blocks: 10 * 1024 * 1024,
		Bfree:  1000,
		Bavail: 0,
	}
	if got := AvailableStorageSpace(vfsZeroAvail); got != 0 {
		t.Errorf("expected avail 0 when Bavail is 0, got %d", got)
	}
}

func TestClient_WithFileProgress_UploadDirectory(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = directorySetstatFileCmder{delegate: handlers.FileCmd, lister: handlers.FileList}
	client := newTestSFTPClientWithHandlers(t, handlers)

	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("hello world 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	file2 := filepath.Join(tempDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("hello world 22"), 0o644); err != nil {
		t.Fatal(err)
	}

	var progressEvents []FileTransferProgress
	var mu sync.Mutex
	callback := func(p FileTransferProgress) {
		mu.Lock()
		defer mu.Unlock()
		progressEvents = append(progressEvents, p)
	}

	clientWithProgress := client.WithFileProgress(callback)
	if err := clientWithProgress.UploadDirectory(t.Context(), tempDir, "/remotedir", nil); err != nil {
		t.Fatalf("UploadDirectory failed: %v", err)
	}

	mu.Lock()
	eventsCopy := append([]FileTransferProgress(nil), progressEvents...)
	mu.Unlock()

	if len(eventsCopy) == 0 {
		t.Fatal("expected file progress events, got none")
	}

	var file1Completed, file2Completed bool
	for _, ev := range eventsCopy {
		if strings.Contains(ev.Path, "file1.txt") && ev.Transferred == ev.Size && ev.Size == int64(len("hello world 1")) {
			file1Completed = true
		}
		if strings.Contains(ev.Path, "file2.txt") && ev.Transferred == ev.Size && ev.Size == int64(len("hello world 22")) {
			file2Completed = true
		}
	}
	if !file1Completed || !file2Completed {
		t.Errorf("expected both file1 and file2 to complete: file1=%v, file2=%v", file1Completed, file2Completed)
	}
}

func TestClient_WithFileProgress_DownloadDirectory(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = directorySetstatFileCmder{delegate: handlers.FileCmd, lister: handlers.FileList}
	client := newTestSFTPClientWithHandlers(t, handlers)

	tempDir := t.TempDir()
	file1 := filepath.Join(tempDir, "file1.txt")
	if err := os.WriteFile(file1, []byte("hello world 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	file2 := filepath.Join(tempDir, "file2.txt")
	if err := os.WriteFile(file2, []byte("hello world 22"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := client.UploadDirectory(t.Context(), tempDir, "/remotedir", nil); err != nil {
		t.Fatalf("setup UploadDirectory failed: %v", err)
	}

	localDownDir := filepath.Join(t.TempDir(), "down")
	var downEvents []FileTransferProgress
	var mu sync.Mutex
	downCallback := func(p FileTransferProgress) {
		mu.Lock()
		defer mu.Unlock()
		downEvents = append(downEvents, p)
	}

	clientDown := client.WithFileProgress(downCallback)
	if err := clientDown.DownloadDirectory(t.Context(), "/remotedir", localDownDir, nil); err != nil {
		t.Fatalf("DownloadDirectory failed: %v", err)
	}

	mu.Lock()
	downEventsCopy := append([]FileTransferProgress(nil), downEvents...)
	mu.Unlock()

	if len(downEventsCopy) == 0 {
		t.Fatal("expected download file progress events, got none")
	}

	var down1Completed, down2Completed bool
	for _, ev := range downEventsCopy {
		if strings.Contains(ev.Path, "file1.txt") && ev.Transferred == ev.Size {
			down1Completed = true
		}
		if strings.Contains(ev.Path, "file2.txt") && ev.Transferred == ev.Size {
			down2Completed = true
		}
	}
	if !down1Completed || !down2Completed {
		t.Errorf("expected both downloaded files to complete: down1=%v, down2=%v", down1Completed, down2Completed)
	}
}

func TestClient_WithFileProgress_ZeroByteFile(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	handlers.FileCmd = directorySetstatFileCmder{delegate: handlers.FileCmd, lister: handlers.FileList}
	client := newTestSFTPClientWithHandlers(t, handlers)

	tempDir := t.TempDir()
	emptyFile := filepath.Join(tempDir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	var progressEvents []FileTransferProgress
	var mu sync.Mutex
	callback := func(p FileTransferProgress) {
		mu.Lock()
		defer mu.Unlock()
		progressEvents = append(progressEvents, p)
	}

	clientWithProgress := client.WithFileProgress(callback)
	if err := clientWithProgress.UploadFile(t.Context(), emptyFile, "/empty.txt", 0, 0o644, nil); err != nil {
		t.Fatalf("UploadFile empty file failed: %v", err)
	}

	mu.Lock()
	eventsCopy := append([]FileTransferProgress(nil), progressEvents...)
	mu.Unlock()

	if len(eventsCopy) != 1 {
		t.Fatalf("expected exactly 1 progress event for empty file, got %d: %+v", len(eventsCopy), eventsCopy)
	}
	if eventsCopy[0].Size != 0 || eventsCopy[0].Transferred != 0 {
		t.Errorf("unexpected event content: %+v", eventsCopy[0])
	}
}

type countingStatVFSFileCmder struct {
	pkgsftp.FileCmder
	statCalls []string
	vfsErr    error
}

func (c *countingStatVFSFileCmder) StatVFS(r *pkgsftp.Request) (*pkgsftp.StatVFS, error) {
	c.statCalls = append(c.statCalls, r.Filepath)
	if c.vfsErr != nil {
		return nil, c.vfsErr
	}
	return &pkgsftp.StatVFS{Bavail: 100, Bfree: 100, Bsize: 4096}, nil
}

func TestCheckRemoteFreeSpace_UnsupportedStatVFS(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	cmder := &countingStatVFSFileCmder{
		FileCmder: handlers.FileCmd,
		vfsErr:    pkgsftp.ErrSSHFxOpUnsupported,
	}
	handlers.FileCmd = cmder
	client := newTestSFTPClientWithHandlers(t, handlers)

	_, err := client.checkRemoteFreeSpace("/a/b/c/file.txt")
	if !isOpUnsupported(err) {
		t.Fatalf("expected isOpUnsupported(err) = true, got %v", err)
	}
	// 遇到 ErrSSHFxOpUnsupported 时必须立即短路，仅调用 1 次
	if len(cmder.statCalls) != 1 {
		t.Errorf("expected exactly 1 StatVFS call on unsupported, got %d: %v", len(cmder.statCalls), cmder.statCalls)
	}
}

func TestCheckRemoteFreeSpace_RelativePathFallbackToDot(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	cmder := &countingStatVFSFileCmder{
		FileCmder: handlers.FileCmd,
		vfsErr:    pkgsftp.ErrSSHFxNoSuchFile,
	}
	handlers.FileCmd = cmder
	client := newTestSFTPClientWithHandlers(t, handlers)

	_, err := client.checkRemoteFreeSpace("songque.png")
	if err == nil {
		t.Fatal("expected error")
	}
	// 相对路径无上层目录时，原实现遇 dir == "." 直接退出（仅 1 次调用）；
	// 现实现回退探测到 "."（通过 pkg/sftp cleanPath 表现为对当前工作根目录 "/" 的调用），共 2 次调用
	if len(cmder.statCalls) != 2 {
		t.Errorf("expected 2 StatVFS calls falling back to dot, got %d: %v", len(cmder.statCalls), cmder.statCalls)
	}
}
