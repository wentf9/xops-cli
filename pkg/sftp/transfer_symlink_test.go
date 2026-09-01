package sftp

import (
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
