//go:build unix

package osfs_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"go.uber.org/goleak"
)

func ensureTestSocketDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建 Unix 套接字测试目录失败: %v", err)
	}
}

func dialAndAssertUnixUID(t *testing.T, ctx context.Context, sockPath osfs.ControlSocketPath) error {
	t.Helper()
	cli, cred, err := osfs.DialUnixVerified(ctx, sockPath)
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()
	if uid, ok := cred.UID(); !ok || uid != uint32(os.Geteuid()) {
		t.Errorf("客户端查询对端 UID = (%d, %v), 期望 %d", uid, ok, os.Geteuid())
	}
	return nil
}

func acceptAndAssertUnixUID(t *testing.T, slot *osfs.SocketSlot) error {
	t.Helper()
	c, cred, err := slot.AcceptVerified()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if uid, ok := cred.UID(); !ok || uid != uint32(os.Geteuid()) {
		t.Errorf("对端 UID = (%d, %v), 期望 %d", uid, ok, os.Geteuid())
	}
	return nil
}

// TestUnixSocketSlotAllowsOpenSSHColonFilename 验证 Unix 平台支持用户显式配置的含 ':' ControlPath，
// 且套接字权限锁定 0600 并通过内核对端 UID 校验。
func TestUnixSocketSlotAllowsOpenSSHColonFilename(t *testing.T) {
	defer goleak.VerifyNone(t)
	dir := shortSocketTempDir(t)
	sockPath, err := osfs.ValidateControlSocketPath(filepath.Join(dir, "cm-alice@prod:22"))
	if err != nil {
		t.Fatalf("Unix ValidateControlSocketPath(含冒号) 失败: %v", err)
	}
	ctx := context.Background()
	err = osfs.WithSocketSlot(ctx, sockPath, osfs.SocketSlotOptions{}, func(slot *osfs.SocketSlot) error {
		fi, lErr := os.Lstat(sockPath.NativePath())
		if lErr != nil {
			return lErr
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("Unix 套接字权限 = %o, 期望 0600", fi.Mode().Perm())
		}
		return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
			if err := n.Go(func(c context.Context) error { return dialAndAssertUnixUID(t, c, sockPath) }); err != nil {
				return err
			}
			return acceptAndAssertUnixUID(t, slot)
		})
	})
	if err != nil {
		t.Fatalf("Unix 含冒号 ControlPath 绑定与验证失败: %v", err)
	}
}

// TestUnixDanglingSymlinkNeverCreatesTarget 验证 Unix openat+O_NOFOLLOW 下，
// 对根内悬空软链调用 AppendLine 与 WithLockedFile(create=true) 均返回 ErrSymlinkRejected 且绝不创建目标文件。
func TestUnixDanglingSymlinkNeverCreatesTarget(t *testing.T) {
	fsPort := osfs.NewScopedRootFS()
	rootDir := mustLocalDir(t, t.TempDir())
	linkDest := mustLocalDest(t, "dangling.link")
	victimDest := mustLocalDest(t, "victim.txt")

	err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		if err := root.CreateSymlink(linkDest, "victim.txt"); err != nil {
			return err
		}
		if aErr := root.AppendLine(linkDest, 0o600, []byte("evil")); !errors.Is(aErr, ports.ErrSymlinkRejected) {
			t.Fatalf("AppendLine(dangling symlink) = %v, 期望 ErrSymlinkRejected", aErr)
		}
		if lErr := root.WithLockedFile(context.Background(), linkDest, ports.LockExclusive, true, 0o600, func(ports.LockedFile) error {
			return nil
		}); !errors.Is(lErr, ports.ErrSymlinkRejected) {
			t.Fatalf("WithLockedFile(dangling symlink, create=true) = %v, 期望 ErrSymlinkRejected", lErr)
		}
		if _, stErr := root.Lstat(victimDest); !errors.Is(stErr, ports.ErrNotFound) {
			t.Fatalf("悬空软链指向目标不应被创建: Lstat = %v", stErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("悬空软链防创建测试失败: %v", err)
	}
}

// TestUnixScopedFSRootPinnedAfterDirRename 验证 Unix 上 *os.Root 在打开期间根目录被重命名后，
// 所有 openat 锚定操作仍严格落在新目录内核对象内，绝不按旧字符串路径逃逸或重建旧目录。
func TestUnixScopedFSRootPinnedAfterDirRename(t *testing.T) {
	base := t.TempDir()
	origDir := filepath.Join(base, "root-orig")
	movedDir := filepath.Join(base, "root-moved")
	if err := os.Mkdir(origDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fsPort := osfs.NewScopedRootFS()
	subDir := mustLocalDest(t, "nested/sub")
	fileDest := mustLocalDest(t, "nested/sub/data.txt")
	logDest := mustLocalDest(t, "nested/sub/audit.jsonl")

	err := fsPort.WithRoot(mustLocalDir(t, origDir), func(root ports.RootHandle) error {
		if rnErr := os.Rename(origDir, movedDir); rnErr != nil {
			return rnErr
		}
		return verifyScopedRootFullOps(context.Background(), root, subDir, fileDest, logDest)
	})
	if err != nil {
		t.Fatalf("Unix 根目录改名后锚定操作失败: %v", err)
	}
	if _, stErr := os.Stat(origDir); !errors.Is(stErr, os.ErrNotExist) {
		t.Fatalf("旧根目录路径不应再存在或被重新创建: %v", stErr)
	}
	if data, rErr := os.ReadFile(filepath.Join(movedDir, "nested", "sub", "data.txt")); rErr != nil || string(data) != "replaced" {
		t.Fatalf("迁移后目录内文件校验失败: (%q, %v)", string(data), rErr)
	}
}
