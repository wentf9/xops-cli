package sftp

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

type customListerAt []os.FileInfo

func (c customListerAt) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(c)) {
		return 0, io.EOF
	}
	n := copy(ls, c[offset:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

type customModeFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (c customModeFileInfo) Mode() os.FileMode {
	return c.mode
}

type customModeFileLister struct {
	delegate      pkgsftp.FileLister
	modeOverrides map[string]os.FileMode
}

func (l *customModeFileLister) Filelist(r *pkgsftp.Request) (pkgsftp.ListerAt, error) {
	list, err := l.delegate.Filelist(r)
	if err != nil {
		return nil, err
	}
	buf := make([]os.FileInfo, 100)
	n, readErr := list.ListAt(buf, 0)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	entries := make([]os.FileInfo, n)
	copy(entries, buf[:n])

	for i, entry := range entries {
		var fullPath string
		if r.Method == "Stat" || r.Method == "Lstat" {
			fullPath = r.Filepath
		} else {
			fullPath = r.Filepath + "/" + entry.Name()
		}
		if override, ok := l.modeOverrides[fullPath]; ok {
			entries[i] = customModeFileInfo{FileInfo: entry, mode: override}
		}
	}
	return customListerAt(entries), nil
}

type recordedSetstat struct {
	path string
	mode os.FileMode
}

type setstatRecordingFileCmder struct {
	delegate pkgsftp.FileCmder
	mu       sync.Mutex
	calls    []recordedSetstat
}

func (c *setstatRecordingFileCmder) Filecmd(r *pkgsftp.Request) error {
	if r.Method == "Setstat" && r.AttrFlags().Permissions {
		c.mu.Lock()
		c.calls = append(c.calls, recordedSetstat{
			path: r.Filepath,
			mode: r.Attributes().FileMode(),
		})
		c.mu.Unlock()
	}
	return c.delegate.Filecmd(r)
}

func (c *setstatRecordingFileCmder) PosixRename(r *pkgsftp.Request) error {
	if pr, ok := c.delegate.(pkgsftp.PosixRenameFileCmder); ok {
		return pr.PosixRename(r)
	}
	return errors.New("posix rename not supported")
}

func (c *setstatRecordingFileCmder) getCallsForPath(targetPath string) []os.FileMode {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []os.FileMode
	for _, call := range c.calls {
		if call.path == targetPath {
			result = append(result, call.mode)
		}
	}
	return result
}

func TestClient_RemoteCopy_PreservesRestrictiveDirectoryPermissions(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	recordingCmder := &setstatRecordingFileCmder{delegate: handlers.FileCmd}
	modeOverrides := map[string]os.FileMode{
		"/src":     os.ModeDir | 0700,
		"/src/sub": os.ModeDir | 0750,
	}
	customLister := &customModeFileLister{delegate: handlers.FileList, modeOverrides: modeOverrides}
	handlers.FileCmd = recordingCmder
	handlers.FileList = customLister

	client := newTestSFTPClientWithHandlers(t, handlers)

	// Create /src and /src/sub
	if err := client.state.sftpClient.MkdirAll("/src/sub"); err != nil {
		t.Fatalf("mkdir /src/sub failed: %v", err)
	}
	f1, err := client.state.sftpClient.Create("/src/file.txt")
	if err != nil {
		t.Fatalf("create /src/file.txt failed: %v", err)
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("close /src/file.txt failed: %v", err)
	}
	f2, err := client.state.sftpClient.Create("/src/sub/secret.txt")
	if err != nil {
		t.Fatalf("create /src/sub/secret.txt failed: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close /src/sub/secret.txt failed: %v", err)
	}

	if err := client.RemoteCopy(t.Context(), "/src", "/dst"); err != nil {
		t.Fatalf("RemoteCopy failed: %v", err)
	}

	// Verify /dst directory modes: initial should be 0700 | 0700 = 0700, final should be 0700
	dstCalls := recordingCmder.getCallsForPath("/dst")
	if len(dstCalls) != 2 {
		t.Fatalf("expected 2 Setstat calls for /dst, got %d: %v", len(dstCalls), dstCalls)
	}
	if dstCalls[0].Perm() != 0700 {
		t.Errorf("expected /dst initial mode 0700, got %v", dstCalls[0].Perm())
	}
	if dstCalls[1].Perm() != 0700 {
		t.Errorf("expected /dst final mode 0700, got %v", dstCalls[1].Perm())
	}

	// Verify /dst/sub directory modes: initial should be 0750 | 0700 = 0750, final should be 0750
	subCalls := recordingCmder.getCallsForPath("/dst/sub")
	if len(subCalls) != 2 {
		t.Fatalf("expected 2 Setstat calls for /dst/sub, got %d: %v", len(subCalls), subCalls)
	}
	if subCalls[0].Perm() != 0750 {
		t.Errorf("expected /dst/sub initial mode 0750, got %v", subCalls[0].Perm())
	}
	if subCalls[1].Perm() != 0750 {
		t.Errorf("expected /dst/sub final mode 0750, got %v", subCalls[1].Perm())
	}
}

func TestClient_RemoteCopy_PreservesReadOnlyDirectoryPermissions(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	recordingCmder := &setstatRecordingFileCmder{delegate: handlers.FileCmd}
	modeOverrides := map[string]os.FileMode{
		"/ro_src": os.ModeDir | 0500,
	}
	customLister := &customModeFileLister{delegate: handlers.FileList, modeOverrides: modeOverrides}
	handlers.FileCmd = recordingCmder
	handlers.FileList = customLister

	client := newTestSFTPClientWithHandlers(t, handlers)

	if err := client.state.sftpClient.MkdirAll("/ro_src"); err != nil {
		t.Fatalf("mkdir /ro_src failed: %v", err)
	}
	f, err := client.state.sftpClient.Create("/ro_src/data.txt")
	if err != nil {
		t.Fatalf("create /ro_src/data.txt failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close /ro_src/data.txt failed: %v", err)
	}

	if err := client.RemoteCopy(t.Context(), "/ro_src", "/ro_dst"); err != nil {
		t.Fatalf("RemoteCopy failed: %v", err)
	}

	// Verify /ro_dst directory modes: initial should be 0500 | 0700 = 0700 (to allow writing), final should be 0500
	roCalls := recordingCmder.getCallsForPath("/ro_dst")
	if len(roCalls) != 2 {
		t.Fatalf("expected 2 Setstat calls for /ro_dst, got %d: %v", len(roCalls), roCalls)
	}
	if roCalls[0].Perm() != 0700 {
		t.Errorf("expected /ro_dst initial mode 0700, got %v", roCalls[0].Perm())
	}
	if roCalls[1].Perm() != 0500 {
		t.Errorf("expected /ro_dst final mode 0500, got %v", roCalls[1].Perm())
	}
}

func TestClient_RemoteCopy_ExistingDestinationDirectoryNotChmoded(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	recordingCmder := &setstatRecordingFileCmder{delegate: handlers.FileCmd}
	modeOverrides := map[string]os.FileMode{
		"/src": os.ModeDir | 0700,
	}
	customLister := &customModeFileLister{delegate: handlers.FileList, modeOverrides: modeOverrides}
	handlers.FileCmd = recordingCmder
	handlers.FileList = customLister

	client := newTestSFTPClientWithHandlers(t, handlers)

	if err := client.state.sftpClient.MkdirAll("/src"); err != nil {
		t.Fatalf("mkdir /src failed: %v", err)
	}
	f, err := client.state.sftpClient.Create("/src/file.txt")
	if err != nil {
		t.Fatalf("create /src/file.txt failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close /src/file.txt failed: %v", err)
	}

	// Pre-create /existing_dst
	if err := client.state.sftpClient.MkdirAll("/existing_dst"); err != nil {
		t.Fatalf("mkdir /existing_dst failed: %v", err)
	}

	if err := client.RemoteCopy(t.Context(), "/src", "/existing_dst"); err != nil {
		t.Fatalf("RemoteCopy failed: %v", err)
	}

	// Verify /existing_dst itself was NOT modified
	existingCalls := recordingCmder.getCallsForPath("/existing_dst")
	if len(existingCalls) != 0 {
		t.Fatalf("expected 0 Setstat calls on pre-existing /existing_dst, got %d: %v", len(existingCalls), existingCalls)
	}
}

func TestClient_RemoteCopy_PreservesExistingDestinationFileMode(t *testing.T) {
	handlers := pkgsftp.InMemHandler()
	recordingCmder := &setstatRecordingFileCmder{delegate: handlers.FileCmd}
	handlers.FileCmd = recordingCmder
	handlers.FileList = &customModeFileLister{
		delegate:      handlers.FileList,
		modeOverrides: map[string]os.FileMode{"/dst/file.txt": 0600},
	}
	client := newTestSFTPClientWithHandlers(t, handlers)

	for _, dir := range []string{"/src", "/dst"} {
		if err := client.state.sftpClient.MkdirAll(dir); err != nil {
			t.Fatalf("mkdir %s failed: %v", dir, err)
		}
	}
	for _, name := range []string{"/src/file.txt", "/dst/file.txt"} {
		f, err := client.state.sftpClient.Create(name)
		if err != nil {
			t.Fatalf("create %s failed: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %s failed: %v", name, err)
		}
	}

	if err := client.RemoteCopy(t.Context(), "/src/file.txt", "/dst/file.txt"); err != nil {
		t.Fatalf("RemoteCopy failed: %v", err)
	}

	calls := recordingCmder.getCallsForPath("/dst/file.txt" + client.config.TempSuffix)
	if len(calls) == 0 {
		t.Fatal("expected a mode to be applied to the temporary destination")
	}
	if got := calls[len(calls)-1].Perm(); got != 0600 {
		t.Fatalf("expected existing destination mode 0600 to be preserved, got %v", got)
	}
}

func TestClient_RemoteCopy_RecursiveFollowsDestinationFileSymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	for _, dir := range []string{"/src", "/dst"} {
		if err := client.state.sftpClient.MkdirAll(dir); err != nil {
			t.Fatalf("mkdir %s failed: %v", dir, err)
		}
	}
	write := func(name, content string) {
		f, err := client.state.sftpClient.Create(name)
		if err != nil {
			t.Fatalf("create %s failed: %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write %s failed: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %s failed: %v", name, err)
		}
	}
	write("/src/file", "new")
	write("/dst/target", "old")
	if err := client.state.sftpClient.Symlink("/dst/target", "/dst/file"); err != nil {
		t.Fatalf("symlink failed: %v", err)
	}

	if err := client.RemoteCopy(t.Context(), "/src", "/dst"); err != nil {
		t.Fatalf("RemoteCopy failed: %v", err)
	}

	info, err := client.state.sftpClient.Lstat("/dst/file")
	if err != nil {
		t.Fatalf("lstat /dst/file failed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected /dst/file to remain a symbolic link, got mode %v", info.Mode())
	}
	f, err := client.state.sftpClient.Open("/dst/target")
	if err != nil {
		t.Fatalf("open /dst/target failed: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close /dst/target failed: %v", err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read /dst/target failed: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("expected link target to receive copied content, got %q", data)
	}
}
