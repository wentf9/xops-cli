package sftp

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

func newP7W18bRealFSSFTPClient(t *testing.T, rootDir string) *Client {
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

func createP7W18bSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlinks unavailable on Windows without privilege: %v", err)
		}
		t.Fatalf("os.Symlink(%q, %q): %v", target, link, err)
	}
}

func TestP7W18b_AB18M3_UploadExactAndContainerExpansion(t *testing.T) {
	t.Run("upload_exact_rejects_existing_directory_and_preserves_nested_entries", testP7W18bUploadExactRejectsDir)
	t.Run("upload_exact_rejects_directory_symlink_and_preserves_target_contents", testP7W18bUploadExactRejectsDirSymlink)
	t.Run("upload_exact_replaces_dangling_symlink_when_confirmed_and_merges_dirs_without_double_nesting", testP7W18bUploadExactDanglingAndDirMerge)
	t.Run("upload_auto_mode_preserved_for_single_step_callers_and_fails_on_nested_dir", testP7W18bUploadAutoMode)
	t.Run("relay_file_from_rejects_directory_and_dir_symlink_before_staging", testP7W18bRelayFileFromRejectsDir)
}

func testP7W18bUploadExactRejectsDir(t *testing.T) {
	remoteRoot := t.TempDir()
	localRoot := t.TempDir()
	cli := newP7W18bRealFSSFTPClient(t, remoteRoot)

	localApp := filepath.Join(localRoot, "app")
	if err := os.WriteFile(localApp, []byte("new-payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	remoteDir := filepath.Join(remoteRoot, "work", "app")
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(remoteDir, "app")
	if err := os.WriteFile(nestedFile, []byte("preserve-me"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := cli.WithForce(true).UploadExact(t.Context(), localApp, "./work/app", nil)
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("UploadExact over directory err = %v, want directory overwrite error", err)
	}
	got, readErr := os.ReadFile(nestedFile)
	if readErr != nil || string(got) != "preserve-me" {
		t.Fatalf("nested file = (%q, %v), want untouched %q", string(got), readErr, "preserve-me")
	}
	if _, tmpErr := os.Lstat(filepath.Join(remoteRoot, "work", "app"+cli.Config().TempSuffix)); !errors.Is(tmpErr, os.ErrNotExist) {
		t.Fatalf("UploadExact left staging file behind: err=%v", tmpErr)
	}
}

func testP7W18bUploadExactRejectsDirSymlink(t *testing.T) {
	remoteRoot := t.TempDir()
	localRoot := t.TempDir()
	cli := newP7W18bRealFSSFTPClient(t, remoteRoot)

	localApp := filepath.Join(localRoot, "app")
	if err := os.WriteFile(localApp, []byte("new-payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	targetDir := filepath.Join(remoteRoot, "target_dir")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	danglingNested := filepath.Join(targetDir, "app")
	missingTarget := filepath.Join(remoteRoot, "missing_nested_target")
	createP7W18bSymlink(t, missingTarget, danglingNested)

	workDir := filepath.Join(remoteRoot, "work")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(workDir, "app")
	createP7W18bSymlink(t, targetDir, dirLink)

	err := cli.WithForce(true).UploadExact(t.Context(), localApp, "./work/app", nil)
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory symbolic link") {
		t.Fatalf("UploadExact over directory symlink err = %v, want directory symlink error", err)
	}
	if info, lstatErr := os.Lstat(dirLink); lstatErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("directory symlink was altered: info=%v err=%v", info, lstatErr)
	}
	if info, lstatErr := os.Lstat(danglingNested); lstatErr != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("nested dangling symlink was clobbered: info=%v err=%v", info, lstatErr)
	}
	if _, statErr := os.Lstat(missingTarget); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing dangling symlink target was created: err=%v", statErr)
	}
}

func testP7W18bUploadExactDanglingAndDirMerge(t *testing.T) {
	remoteRoot := t.TempDir()
	localRoot := t.TempDir()
	cli := newP7W18bRealFSSFTPClient(t, remoteRoot)

	// 1. Dangling symlink at exact path can be atomically replaced when caller explicitly invokes UploadExact.
	localFile := filepath.Join(localRoot, "file.txt")
	if err := os.WriteFile(localFile, []byte("replaced"), 0o600); err != nil {
		t.Fatal(err)
	}
	missingTarget := filepath.Join(remoteRoot, "missing_target.txt")
	danglingPath := filepath.Join(remoteRoot, "dangling.txt")
	createP7W18bSymlink(t, missingTarget, danglingPath)

	if err := cli.WithForce(true).UploadExact(t.Context(), localFile, "./dangling.txt", nil); err != nil {
		t.Fatalf("UploadExact over dangling symlink failed: %v", err)
	}
	if info, err := os.Lstat(danglingPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("danglingPath after UploadExact = (%v, %v), want regular file", info, err)
	}
	if _, err := os.Lstat(missingTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("UploadExact followed dangling symlink target: err=%v", err)
	}

	// 2. Directory UploadExact onto existing directory merges directly without double-nesting.
	localDir := filepath.Join(localRoot, "mydir")
	if err := os.MkdirAll(localDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "hello.txt"), []byte("dir-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	remoteDir := filepath.Join(remoteRoot, "mydir")
	if err := os.MkdirAll(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cli.WithForce(true).UploadExact(t.Context(), localDir, "./mydir", nil); err != nil {
		t.Fatalf("UploadExact directory failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(remoteDir, "hello.txt"))
	if err != nil || string(got) != "dir-body" {
		t.Fatalf("uploaded dir file = (%q, %v), want %q", string(got), err, "dir-body")
	}
	if _, err := os.Lstat(filepath.Join(remoteDir, "mydir")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("UploadExact double-nested directory into mydir/mydir: err=%v", err)
	}
}

func testP7W18bUploadAutoMode(t *testing.T) {
	remoteRoot := t.TempDir()
	localRoot := t.TempDir()
	cli := newP7W18bRealFSSFTPClient(t, remoteRoot)

	localApp := filepath.Join(localRoot, "app")
	if err := os.WriteFile(localApp, []byte("auto-payload"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Single container directory expansion still works in Upload().
	autoDir := filepath.Join(remoteRoot, "auto_dir")
	if err := os.MkdirAll(autoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cli.Upload(t.Context(), localApp, "./auto_dir", nil); err != nil {
		t.Fatalf("Upload(auto) into directory failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(autoDir, "app"))
	if err != nil || string(got) != "auto-payload" {
		t.Fatalf("Upload(auto) target = (%q, %v), want %q", string(got), err, "auto-payload")
	}

	// If the expanded child itself is a directory, Upload() fails closed before staging instead of expanding again.
	nestedDir := filepath.Join(remoteRoot, "nested_parent", "app")
	if err := os.MkdirAll(nestedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cli.Upload(t.Context(), localApp, "./nested_parent", nil); err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("Upload(auto) onto nested same-named dir err = %v, want directory overwrite error", err)
	}
	if _, err := os.Lstat(filepath.Join(nestedDir, "app")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Upload(auto) wrote double-nested file: err=%v", err)
	}
}

func testP7W18bRelayFileFromRejectsDir(t *testing.T) {
	remoteRoot := t.TempDir()
	srcCli := newP7W18bRealFSSFTPClient(t, remoteRoot)
	dstCli := newP7W18bRealFSSFTPClient(t, remoteRoot)

	if err := os.WriteFile(filepath.Join(remoteRoot, "src.txt"), []byte("relay-body"), 0o600); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(remoteRoot, "dst_dir")
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		t.Fatal(err)
	}
	srcPath, _ := ParseRemotePath("./src.txt")
	dstDirPath, _ := ParseRemotePath("./dst_dir")
	if err := dstCli.RelayFileFrom(t.Context(), srcCli, srcPath, dstDirPath, nil, nil); err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory") {
		t.Fatalf("RelayFileFrom onto directory err = %v, want directory overwrite error", err)
	}

	dstDirLink := filepath.Join(remoteRoot, "dst_dir_link")
	createP7W18bSymlink(t, dstDir, dstDirLink)
	dstLinkPath, _ := ParseRemotePath("./dst_dir_link")
	if err := dstCli.RelayFileFrom(t.Context(), srcCli, srcPath, dstLinkPath, nil, nil); err == nil || !strings.Contains(err.Error(), "cannot overwrite remote directory symbolic link") {
		t.Fatalf("RelayFileFrom onto directory symlink err = %v, want directory symlink error", err)
	}
}
