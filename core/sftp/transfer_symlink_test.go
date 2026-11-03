package sftp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	pkgsftp "github.com/pkg/sftp"
)

func TestClient_RemoteCopy_Symlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	// 1. 创建源文件与符号链接
	targetPath := "/target.txt"
	f, err := client.state.sftpClient.Create(targetPath)
	if err != nil {
		t.Fatalf("create target file failed: %v", err)
	}
	if _, err := f.Write([]byte("target content")); err != nil {
		t.Fatalf("write target file failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close target file failed: %v", err)
	}

	srcLink := "/src_link.txt"
	if err := client.state.sftpClient.Symlink(targetPath, srcLink); err != nil {
		t.Fatalf("create src symlink failed: %v", err)
	}

	// 2. 执行远端符号链接复制
	dstLink := "/dst_link.txt"
	if err := client.RemoteCopy(t.Context(), srcLink, dstLink); err != nil {
		t.Fatalf("RemoteCopy symlink failed: %v", err)
	}

	// 3. 断言 dstLink 是符号链接且指向原始目标
	fi, err := client.state.sftpClient.Lstat(dstLink)
	if err != nil {
		t.Fatalf("lstat dst link failed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected destination %q to be symlink, got mode %v", dstLink, fi.Mode())
	}

	target, err := client.state.sftpClient.ReadLink(dstLink)
	if err != nil {
		t.Fatalf("readlink dst link failed: %v", err)
	}
	if target != targetPath {
		t.Errorf("expected symlink target %q, got %q", targetPath, target)
	}
}

func TestClient_RemoteCopy_DirectoryWithSymlinkOutside(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	// 1. 构造目录结构：/outside/secret.txt, /src/inside.txt, /src/link_outside -> /outside
	if err := client.state.sftpClient.MkdirAll("/outside"); err != nil {
		t.Fatalf("mkdir outside failed: %v", err)
	}
	f1, err := client.state.sftpClient.Create("/outside/secret.txt")
	if err != nil {
		t.Fatalf("create secret failed: %v", err)
	}
	if _, err := f1.Write([]byte("secret")); err != nil {
		t.Fatalf("write secret failed: %v", err)
	}
	if err := f1.Close(); err != nil {
		t.Fatalf("close secret failed: %v", err)
	}

	if err := client.state.sftpClient.MkdirAll("/src"); err != nil {
		t.Fatalf("mkdir src failed: %v", err)
	}
	f2, err := client.state.sftpClient.Create("/src/inside.txt")
	if err != nil {
		t.Fatalf("create inside failed: %v", err)
	}
	if _, err := f2.Write([]byte("inside")); err != nil {
		t.Fatalf("write inside failed: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close inside failed: %v", err)
	}

	if err := client.state.sftpClient.Symlink("/outside", "/src/link_outside"); err != nil {
		t.Fatalf("create directory symlink failed: %v", err)
	}

	// 2. 复制整个 /src 目录到 /dst
	if err := client.RemoteCopy(t.Context(), "/src", "/dst"); err != nil {
		t.Fatalf("RemoteCopy directory failed: %v", err)
	}

	// 3. 断言 /dst/inside.txt 存在为普通文件
	fiInside, err := client.state.sftpClient.Lstat("/dst/inside.txt")
	if err != nil {
		t.Fatalf("lstat /dst/inside.txt failed: %v", err)
	}
	if fiInside.IsDir() || fiInside.Mode()&os.ModeSymlink != 0 {
		t.Errorf("expected /dst/inside.txt to be regular file, got mode %v", fiInside.Mode())
	}

	// 4. 断言 /dst/link_outside 是符号链接且指向 /outside
	fiLink, err := client.state.sftpClient.Lstat("/dst/link_outside")
	if err != nil {
		t.Fatalf("lstat /dst/link_outside failed: %v", err)
	}
	if fiLink.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected /dst/link_outside to be symlink, got mode %v", fiLink.Mode())
	}
	target, err := client.state.sftpClient.ReadLink("/dst/link_outside")
	if err != nil {
		t.Fatalf("readlink /dst/link_outside failed: %v", err)
	}
	if target != "/outside" {
		t.Errorf("expected target '/outside', got %q", target)
	}
}

func TestClient_RemoteCopy_DanglingAndRelativeSymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	// 1. 创建悬空相对符号链接
	relativeTarget := "../nonexistent/file.txt"
	if err := client.state.sftpClient.Symlink(relativeTarget, "/dangling_link"); err != nil {
		t.Fatalf("create dangling symlink failed: %v", err)
	}

	// 2. 复制该符号链接
	if err := client.RemoteCopy(t.Context(), "/dangling_link", "/copied_dangling"); err != nil {
		t.Fatalf("RemoteCopy dangling symlink failed: %v", err)
	}

	// 3. 断言目标仍为符号链接且 target 字符串完全一致
	fi, err := client.state.sftpClient.Lstat("/copied_dangling")
	if err != nil {
		t.Fatalf("lstat copied dangling failed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("expected symlink mode, got %v", fi.Mode())
	}

	target, err := client.state.sftpClient.ReadLink("/copied_dangling")
	if err != nil {
		t.Fatalf("readlink copied dangling failed: %v", err)
	}
	if target != relativeTarget {
		t.Errorf("expected target %q, got %q", relativeTarget, target)
	}
}

func TestClient_RemoteCopy_OverwriteExistingDestination(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())
	client.config.Force = true

	// 1. 创建 /link1 -> /target1, /link2 -> /target2
	if err := client.state.sftpClient.Symlink("/target1", "/link1"); err != nil {
		t.Fatalf("create link1 failed: %v", err)
	}
	if err := client.state.sftpClient.Symlink("/target2", "/link2"); err != nil {
		t.Fatalf("create link2 failed: %v", err)
	}

	// 2. 将 /link1 覆盖复制到 /link2
	if err := client.RemoteCopy(t.Context(), "/link1", "/link2"); err != nil {
		t.Fatalf("RemoteCopy overwrite failed: %v", err)
	}

	// 3. 断言 /link2 现在指向 /target1
	target, err := client.state.sftpClient.ReadLink("/link2")
	if err != nil {
		t.Fatalf("readlink link2 failed: %v", err)
	}
	if target != "/target1" {
		t.Errorf("expected target '/target1', got %q", target)
	}
}

func TestClient_RemoveAll_TrailingSlashSymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/outside"); err != nil {
		t.Fatalf("mkdir outside failed: %v", err)
	}
	f, err := client.state.sftpClient.Create("/outside/secret.txt")
	if err != nil {
		t.Fatalf("create secret failed: %v", err)
	}
	if _, err := f.Write([]byte("secret")); err != nil {
		t.Fatalf("write secret failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close secret failed: %v", err)
	}

	if err := client.state.sftpClient.Symlink("/outside", "/link_dir"); err != nil {
		t.Fatalf("create link failed: %v", err)
	}

	if err := client.RemoveAll(t.Context(), "/link_dir/"); err != nil {
		t.Fatalf("RemoveAll trailing slash symlink failed: %v", err)
	}

	if _, err := client.state.sftpClient.Lstat("/link_dir"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected /link_dir to be removed, got: %v", err)
	}
	if _, err := client.state.sftpClient.Lstat("/outside/secret.txt"); err != nil {
		t.Fatalf("expected /outside/secret.txt to remain intact, got: %v", err)
	}
}

func TestClient_RemoveAll_PreservesWhitespaceAndBackslash(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/data"); err != nil {
		t.Fatalf("mkdir /data failed: %v", err)
	}

	createFile := func(path string, content string) {
		f, err := client.state.sftpClient.Create(path)
		if err != nil {
			t.Fatalf("create %q failed: %v", path, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write %q failed: %v", path, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("close %q failed: %v", path, err)
		}
	}

	createFile("/data/report", "report")
	createFile("/data/report  ", "report-spaces")
	if runtime.GOOS != "windows" {
		createFile("/data/report\\", "report-backslash")
	}

	// 1. Remove "/data/report  " (trailing whitespace). Must not remove "/data/report".
	if err := client.RemoveAll(t.Context(), "/data/report  "); err != nil {
		t.Fatalf("RemoveAll /data/report   failed: %v", err)
	}
	if _, err := client.state.sftpClient.Lstat("/data/report  "); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected /data/report   to be removed, got: %v", err)
	}
	if _, err := client.state.sftpClient.Lstat("/data/report"); err != nil {
		t.Fatalf("expected /data/report to remain intact, got: %v", err)
	}

	// 2. Remove "/data/report\\" (trailing backslash). Must not remove "/data/report".
	if runtime.GOOS != "windows" {
		if err := client.RemoveAll(t.Context(), "/data/report\\"); err != nil {
			t.Fatalf("RemoveAll /data/report\\ failed: %v", err)
		}
		if _, err := client.state.sftpClient.Lstat("/data/report\\"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected /data/report\\ to be removed, got: %v", err)
		}
		if _, err := client.state.sftpClient.Lstat("/data/report"); err != nil {
			t.Fatalf("expected /data/report to remain intact, got: %v", err)
		}
	}
}

func TestClient_RemoteCopy_RejectsDestinationDirectorySymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	// 1. Setup /outside directory, /src directory with a file, /dst directory with symlink /dst/sub -> /outside
	if err := client.state.sftpClient.MkdirAll("/outside"); err != nil {
		t.Fatalf("mkdir /outside failed: %v", err)
	}
	if err := client.state.sftpClient.MkdirAll("/src"); err != nil {
		t.Fatalf("mkdir /src failed: %v", err)
	}
	srcFile, err := client.state.sftpClient.Create("/src/file.txt")
	if err != nil {
		t.Fatalf("create /src/file.txt failed: %v", err)
	}
	_ = srcFile.Close()

	if err := client.state.sftpClient.MkdirAll("/dst"); err != nil {
		t.Fatalf("mkdir /dst failed: %v", err)
	}
	if err := client.state.sftpClient.Symlink("/outside", "/dst/sub"); err != nil {
		t.Fatalf("symlink /dst/sub -> /outside failed: %v", err)
	}

	// Direct copy of directory /src onto destination symlink /dst/sub must fail
	if err := client.RemoteCopy(t.Context(), "/src", "/dst/sub"); err == nil {
		t.Fatal("expected RemoteCopy /src to /dst/sub to fail, but succeeded")
	}

	// Recursive copy of directory containing 'sub' into /dst where /dst/sub is a symlink
	if err := client.state.sftpClient.MkdirAll("/parent/sub"); err != nil {
		t.Fatalf("mkdir /parent/sub failed: %v", err)
	}
	subFile, err := client.state.sftpClient.Create("/parent/sub/nested.txt")
	if err != nil {
		t.Fatalf("create /parent/sub/nested.txt failed: %v", err)
	}
	_ = subFile.Close()

	if err := client.RemoteCopy(t.Context(), "/parent", "/dst"); err == nil {
		t.Fatal("expected RemoteCopy /parent to /dst to fail due to /dst/sub symlink, but succeeded")
	}

	// Verify /outside remains intact without nested.txt
	if _, err := client.state.sftpClient.Lstat("/outside/nested.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected /outside/nested.txt to not exist, got: %v", err)
	}
}

func TestClient_UploadDirectory_Symlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	tempDir := t.TempDir()
	baseDir := filepath.Join(tempDir, "legal", "java.base")
	compilerDir := filepath.Join(tempDir, "legal", "java.compiler")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("mkdir baseDir failed: %v", err)
	}
	if err := os.MkdirAll(compilerDir, 0755); err != nil {
		t.Fatalf("mkdir compilerDir failed: %v", err)
	}

	targetContent := []byte("this is license content with many bytes for testing size mismatch")
	targetFilePath := filepath.Join(baseDir, "ADDITIONAL_LICENSE_INFO")
	if err := os.WriteFile(targetFilePath, targetContent, 0644); err != nil {
		t.Fatalf("write target file failed: %v", err)
	}

	symlinkPath := filepath.Join(compilerDir, "ADDITIONAL_LICENSE_INFO")
	relativeTarget := "../java.base/ADDITIONAL_LICENSE_INFO"
	if err := os.Symlink(relativeTarget, symlinkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("create local symlink failed: %v", err)
	}

	// Upload directory
	if err := client.UploadDirectory(t.Context(), tempDir, "/remote_jdk", nil); err != nil {
		t.Fatalf("UploadDirectory with symlink failed: %v", err)
	}

	// Verify target file on remote
	remoteTarget := "/remote_jdk/legal/java.base/ADDITIONAL_LICENSE_INFO"
	fiTarget, err := client.state.sftpClient.Lstat(remoteTarget)
	if err != nil {
		t.Fatalf("lstat remote target file failed: %v", err)
	}
	if fiTarget.IsDir() || fiTarget.Mode()&os.ModeSymlink != 0 {
		t.Errorf("expected regular file for %s, got mode %v", remoteTarget, fiTarget.Mode())
	}
	if fiTarget.Size() != int64(len(targetContent)) {
		t.Errorf("expected size %d, got %d", len(targetContent), fiTarget.Size())
	}

	// Verify symlink on remote
	remoteLink := "/remote_jdk/legal/java.compiler/ADDITIONAL_LICENSE_INFO"
	fiLink, err := client.state.sftpClient.Lstat(remoteLink)
	if err != nil {
		t.Fatalf("lstat remote symlink failed: %v", err)
	}
	if fiLink.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink mode for %s, got %v", remoteLink, fiLink.Mode())
	}

	gotTarget, err := client.state.sftpClient.ReadLink(remoteLink)
	if err != nil {
		t.Fatalf("readlink remote symlink failed: %v", err)
	}
	if gotTarget != relativeTarget {
		t.Errorf("expected symlink target %q, got %q", relativeTarget, gotTarget)
	}
}

func TestClient_DownloadDirectory_Symlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/remote_src/legal/java.base"); err != nil {
		t.Fatalf("mkdir remote base failed: %v", err)
	}
	if err := client.state.sftpClient.MkdirAll("/remote_src/legal/java.compiler"); err != nil {
		t.Fatalf("mkdir remote compiler failed: %v", err)
	}

	f, err := client.state.sftpClient.Create("/remote_src/legal/java.base/ADDITIONAL_LICENSE_INFO")
	if err != nil {
		t.Fatalf("create remote file failed: %v", err)
	}
	content := []byte("some license information that is longer than link path")
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write remote file failed: %v", err)
	}
	_ = f.Close()

	relativeTarget := "../java.base/ADDITIONAL_LICENSE_INFO"
	if err := client.state.sftpClient.Symlink(relativeTarget, "/remote_src/legal/java.compiler/ADDITIONAL_LICENSE_INFO"); err != nil {
		t.Fatalf("create remote symlink failed: %v", err)
	}

	localDst := t.TempDir()
	if err := client.DownloadDirectory(t.Context(), "/remote_src", localDst, nil); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping download symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("DownloadDirectory with symlink failed: %v", err)
	}

	// Verify regular file locally
	localFile := filepath.Join(localDst, "legal", "java.base", "ADDITIONAL_LICENSE_INFO")
	fi, err := os.Lstat(localFile)
	if err != nil {
		t.Fatalf("lstat local file failed: %v", err)
	}
	if fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("expected regular file, got mode %v", fi.Mode())
	}
	if fi.Size() != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), fi.Size())
	}

	// Verify local symlink
	localLink := filepath.Join(localDst, "legal", "java.compiler", "ADDITIONAL_LICENSE_INFO")
	fiLink, err := os.Lstat(localLink)
	if err != nil {
		t.Fatalf("lstat local symlink failed: %v", err)
	}
	if fiLink.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink mode, got %v", fiLink.Mode())
	}

	gotTarget, err := os.Readlink(localLink)
	if err != nil {
		t.Fatalf("readlink local symlink failed: %v", err)
	}
	if gotTarget != relativeTarget {
		t.Errorf("expected symlink target %q, got %q", relativeTarget, gotTarget)
	}
}

func TestClient_UploadDirectory_DanglingSymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	tempDir := t.TempDir()
	danglingLink := filepath.Join(tempDir, "dangling.txt")
	danglingTarget := "nonexistent/file.txt"
	if err := os.Symlink(danglingTarget, danglingLink); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("create dangling symlink failed: %v", err)
	}

	if err := client.UploadDirectory(t.Context(), tempDir, "/remote_dangling", nil); err != nil {
		t.Fatalf("UploadDirectory with dangling symlink failed: %v", err)
	}

	fi, err := client.state.sftpClient.Lstat("/remote_dangling/dangling.txt")
	if err != nil {
		t.Fatalf("lstat remote dangling symlink failed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink mode, got %v", fi.Mode())
	}
	target, err := client.state.sftpClient.ReadLink("/remote_dangling/dangling.txt")
	if err != nil {
		t.Fatalf("readlink remote dangling symlink failed: %v", err)
	}
	if target != danglingTarget {
		t.Errorf("expected target %q, got %q", danglingTarget, target)
	}
}

func TestClient_DownloadDirectory_DanglingSymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/remote_dangling"); err != nil {
		t.Fatalf("mkdir remote_dangling failed: %v", err)
	}
	danglingTarget := "../nonexistent/missing.txt"
	if err := client.state.sftpClient.Symlink(danglingTarget, "/remote_dangling/dangling.txt"); err != nil {
		t.Fatalf("create remote dangling symlink failed: %v", err)
	}

	localDst := t.TempDir()
	if err := client.DownloadDirectory(t.Context(), "/remote_dangling", localDst, nil); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping download symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("DownloadDirectory with dangling symlink failed: %v", err)
	}

	localLink := filepath.Join(localDst, "dangling.txt")
	fi, err := os.Lstat(localLink)
	if err != nil {
		t.Fatalf("lstat local dangling symlink failed: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink mode, got %v", fi.Mode())
	}
	gotTarget, err := os.Readlink(localLink)
	if err != nil {
		t.Fatalf("readlink local dangling symlink failed: %v", err)
	}
	if gotTarget != danglingTarget {
		t.Errorf("expected target %q, got %q", danglingTarget, gotTarget)
	}
}

func TestClient_UploadDirectory_SymlinkOverwriteAndProgress(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	tempDir := t.TempDir()
	linkPath := filepath.Join(tempDir, "link.txt")
	target := "new_target.txt"
	if err := os.Symlink(target, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("create local symlink failed: %v", err)
	}

	// Pre-populate remote destination with a symlink pointing to a different target
	if err := client.state.sftpClient.MkdirAll("/remote_overwrite"); err != nil {
		t.Fatalf("mkdir remote_overwrite failed: %v", err)
	}
	if err := client.state.sftpClient.Symlink("old_target.txt", "/remote_overwrite/link.txt"); err != nil {
		t.Fatalf("create old remote symlink failed: %v", err)
	}

	var totalProgress atomic.Int64
	if err := client.UploadDirectory(t.Context(), tempDir, "/remote_overwrite", func(n int64) {
		totalProgress.Add(n)
	}); err != nil {
		t.Fatalf("UploadDirectory overwrite symlink failed: %v", err)
	}
	if totalProgress.Load() != int64(len(target)) {
		t.Errorf("expected progress %d, got %d", len(target), totalProgress.Load())
	}
	gotTarget, err := client.state.sftpClient.ReadLink("/remote_overwrite/link.txt")
	if err != nil {
		t.Fatalf("readlink failed: %v", err)
	}
	if gotTarget != target {
		t.Errorf("expected target %q, got %q", target, gotTarget)
	}

	// Second upload with Force=false and identical target should skip and still report progress
	totalProgress.Store(0)
	if err := client.UploadDirectory(t.Context(), tempDir, "/remote_overwrite", func(n int64) {
		totalProgress.Add(n)
	}); err != nil {
		t.Fatalf("UploadDirectory skip symlink failed: %v", err)
	}
	if totalProgress.Load() != int64(len(target)) {
		t.Errorf("expected progress %d on skip, got %d", len(target), totalProgress.Load())
	}

	// Upload with Force=true when a stale temporary symlink exists should clean it up and succeed
	staleTemp := "/remote_overwrite/link.txt" + client.config.TempSuffix
	if err := client.state.sftpClient.Symlink("stale", staleTemp); err != nil {
		t.Fatalf("create stale temp symlink failed: %v", err)
	}
	if err := client.WithForce(true).UploadDirectory(t.Context(), tempDir, "/remote_overwrite", nil); err != nil {
		t.Fatalf("UploadDirectory with Force=true and stale temp link failed: %v", err)
	}
}

func TestClient_DownloadDirectory_SymlinkOverwriteAndProgress(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	if err := client.state.sftpClient.MkdirAll("/remote_dl_overwrite"); err != nil {
		t.Fatalf("mkdir remote_dl_overwrite failed: %v", err)
	}
	target := "remote_target.txt"
	if err := client.state.sftpClient.Symlink(target, "/remote_dl_overwrite/link.txt"); err != nil {
		t.Fatalf("create remote symlink failed: %v", err)
	}

	localDst := t.TempDir()
	localLink := filepath.Join(localDst, "link.txt")
	// Pre-populate local destination with a regular file to be overwritten atomically
	if err := os.WriteFile(localLink, []byte("existing regular file"), 0o600); err != nil {
		t.Fatalf("write local file failed: %v", err)
	}

	var totalProgress atomic.Int64
	if err := client.DownloadDirectory(t.Context(), "/remote_dl_overwrite", localDst, func(n int64) {
		totalProgress.Add(n)
	}); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping download symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("DownloadDirectory overwrite failed: %v", err)
	}
	if totalProgress.Load() != int64(len(target)) {
		t.Errorf("expected progress %d, got %d", len(target), totalProgress.Load())
	}
	gotTarget, err := os.Readlink(localLink)
	if err != nil {
		t.Fatalf("readlink local symlink failed: %v", err)
	}
	if gotTarget != target {
		t.Errorf("expected target %q, got %q", target, gotTarget)
	}

	// Second download with Force=false and identical target should skip and report progress
	totalProgress.Store(0)
	if err := client.DownloadDirectory(t.Context(), "/remote_dl_overwrite", localDst, func(n int64) {
		totalProgress.Add(n)
	}); err != nil {
		t.Fatalf("DownloadDirectory skip symlink failed: %v", err)
	}
	if totalProgress.Load() != int64(len(target)) {
		t.Errorf("expected progress %d on skip, got %d", len(target), totalProgress.Load())
	}
}

func TestClient_UploadAndDownloadLink_RejectOverwriteDirectory(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	localDir := t.TempDir()
	localLink := filepath.Join(localDir, "entry")
	if err := os.Symlink("target", localLink); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("create local symlink failed: %v", err)
	}

	// 1. Remote destination is an existing directory -> UploadDirectory must reject
	if err := client.state.sftpClient.MkdirAll("/remote_dir_conflict/entry"); err != nil {
		t.Fatalf("mkdir remote directory failed: %v", err)
	}
	err := client.UploadDirectory(t.Context(), localDir, "/remote_dir_conflict", nil)
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite remote destination directory") {
		t.Fatalf("expected cannot overwrite remote destination directory error, got: %v", err)
	}

	// 2. Remote temporary path is an existing directory -> UploadLink with Force=true must reject
	tempDirConflict := "/remote_temp_dir/entry" + client.config.TempSuffix
	if err := client.state.sftpClient.MkdirAll(tempDirConflict); err != nil {
		t.Fatalf("mkdir remote temp dir conflict failed: %v", err)
	}
	err = client.WithForce(true).UploadLink(t.Context(), localLink, "/remote_temp_dir/entry", nil)
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("expected temporary path is a directory error, got: %v", err)
	}

	// 3. Local destination is an existing directory -> DownloadDirectory must reject
	if err := client.state.sftpClient.MkdirAll("/remote_src_link"); err != nil {
		t.Fatalf("mkdir remote_src_link failed: %v", err)
	}
	if err := client.state.sftpClient.Symlink("target", "/remote_src_link/entry"); err != nil {
		t.Fatalf("create remote symlink failed: %v", err)
	}
	localConflictDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localConflictDir, "entry"), 0o755); err != nil {
		t.Fatalf("mkdir local conflict dir failed: %v", err)
	}
	err = client.DownloadDirectory(t.Context(), "/remote_src_link", localConflictDir, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot overwrite local destination directory") {
		t.Fatalf("expected cannot overwrite local destination directory error, got: %v", err)
	}
}

func TestClient_UploadAndDownloadDirectory_RejectDestinationDirectorySymlink(t *testing.T) {
	client := newTestSFTPClientWithHandlers(t, pkgsftp.InMemHandler())

	// 1. UploadDirectory: remote /dst/sub is a symlink to /outside, local has sub/nested.txt
	if err := client.state.sftpClient.MkdirAll("/outside"); err != nil {
		t.Fatalf("mkdir /outside failed: %v", err)
	}
	if err := client.state.sftpClient.MkdirAll("/dst"); err != nil {
		t.Fatalf("mkdir /dst failed: %v", err)
	}
	if err := client.state.sftpClient.Symlink("/outside", "/dst/sub"); err != nil {
		t.Fatalf("create remote symlink /dst/sub -> /outside failed: %v", err)
	}

	localSrc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(localSrc, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir local sub failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localSrc, "sub", "nested.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write local nested.txt failed: %v", err)
	}

	if err := client.UploadDirectory(t.Context(), localSrc, "/dst", nil); err == nil {
		t.Fatal("expected UploadDirectory to fail when remote subdirectory is a symlink, but succeeded")
	}
	// Top-level remote destination symlink with trailing slash must also be rejected
	if err := client.UploadDirectory(t.Context(), filepath.Join(localSrc, "sub"), "/dst/sub/", nil); err == nil {
		t.Fatal("expected UploadDirectory to fail when top-level remote destination is a symlink with trailing slash, but succeeded")
	}
	if _, err := client.state.sftpClient.Lstat("/outside/nested.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected /outside/nested.txt to not exist, got: %v", err)
	}

	// 2. DownloadDirectory: local dst/sub is a symlink to localOutside, remote has /rsrc/sub/nested.txt
	localOutside := t.TempDir()
	localDst := t.TempDir()
	if err := os.Symlink(localOutside, filepath.Join(localDst, "sub")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("skipping symlink test on Windows due to privilege requirements")
		}
		t.Fatalf("create local symlink sub -> outside failed: %v", err)
	}
	if err := client.state.sftpClient.MkdirAll("/rsrc/sub"); err != nil {
		t.Fatalf("mkdir /rsrc/sub failed: %v", err)
	}
	f, err := client.state.sftpClient.Create("/rsrc/sub/nested.txt")
	if err != nil {
		t.Fatalf("create /rsrc/sub/nested.txt failed: %v", err)
	}
	_ = f.Close()

	if err := client.DownloadDirectory(t.Context(), "/rsrc", localDst, nil); err == nil {
		t.Fatal("expected DownloadDirectory to fail when local subdirectory is a symlink, but succeeded")
	}
	// Top-level local destination symlink with trailing path separator must also be rejected
	if err := client.DownloadDirectory(t.Context(), "/rsrc/sub", filepath.Join(localDst, "sub")+string(os.PathSeparator), nil); err == nil {
		t.Fatal("expected DownloadDirectory to fail when top-level local destination is a symlink with trailing slash, but succeeded")
	}
	if _, err := os.Lstat(filepath.Join(localOutside, "nested.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected local outside/nested.txt to not exist, got: %v", err)
	}
}
