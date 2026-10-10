package sftp

import (
	"errors"
	"os"
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
	createFile("/data/report\\", "report-backslash")

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
