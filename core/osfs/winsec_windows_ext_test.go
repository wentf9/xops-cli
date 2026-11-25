//go:build windows

package osfs_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/osfs"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
)

// 编译期 Win32 常量恒等断言，确保跨平台纯数学常量与 golang.org/x/sys/windows 零漂移。
const (
	_ = uint(osfs.WinAttrDirectory - windows.FILE_ATTRIBUTE_DIRECTORY)
	_ = uint(windows.FILE_ATTRIBUTE_DIRECTORY - osfs.WinAttrDirectory)
	_ = uint(osfs.WinAttrDevice - windows.FILE_ATTRIBUTE_DEVICE)
	_ = uint(windows.FILE_ATTRIBUTE_DEVICE - osfs.WinAttrDevice)
	_ = uint(osfs.WinAttrReparsePoint - windows.FILE_ATTRIBUTE_REPARSE_POINT)
	_ = uint(windows.FILE_ATTRIBUTE_REPARSE_POINT - osfs.WinAttrReparsePoint)
	_ = uint(osfs.WinACEFlagInheritOnly - windows.INHERIT_ONLY_ACE)
	_ = uint(windows.INHERIT_ONLY_ACE - osfs.WinACEFlagInheritOnly)
	_ = uint(osfs.WinACETypeAllow - windows.ACCESS_ALLOWED_ACE_TYPE)
	_ = uint(windows.ACCESS_ALLOWED_ACE_TYPE - osfs.WinACETypeAllow)
	_ = uint(osfs.WinACETypeDeny - windows.ACCESS_DENIED_ACE_TYPE)
	_ = uint(windows.ACCESS_DENIED_ACE_TYPE - osfs.WinACETypeDeny)
	_ = uint(osfs.WinAccessWriteData - windows.FILE_WRITE_DATA)
	_ = uint(windows.FILE_WRITE_DATA - osfs.WinAccessWriteData)
	_ = uint(osfs.WinAccessDelete - windows.DELETE)
	_ = uint(windows.DELETE - osfs.WinAccessDelete)
	_ = uint(osfs.WinAccessWriteDAC - windows.WRITE_DAC)
	_ = uint(windows.WRITE_DAC - osfs.WinAccessWriteDAC)
	_ = uint(osfs.WinAccessWriteOwner - windows.WRITE_OWNER)
	_ = uint(windows.WRITE_OWNER - osfs.WinAccessWriteOwner)
	_ = uint(osfs.WinAccessGenericAll - windows.GENERIC_ALL)
	_ = uint(windows.GENERIC_ALL - osfs.WinAccessGenericAll)
	_ = uint(osfs.WinAccessGenericWrite - windows.GENERIC_WRITE)
	_ = uint(windows.GENERIC_WRITE - osfs.WinAccessGenericWrite)
	_ = uint(osfs.WinAccessDeleteChild - 0x00000040)
	_ = uint(0x00000040 - osfs.WinAccessDeleteChild)
	_ = uint(uint32(windows.IOC_OUT|windows.IOC_VENDOR|256) - 0x58000100)
	_ = uint(0x58000100 - uint32(windows.IOC_OUT|windows.IOC_VENDOR|256))
)

// shortSocketTempParent 在 Windows 上沿用系统默认临时目录。
func shortSocketTempParent() string { return "" }

// deterministicShortMuxDir 返回 Windows 纯路径构造测试使用的确定性短目录。
func deterministicShortMuxDir() string { return `C:\xops` }

func ensureTestSocketDir(t *testing.T, dir string) {
	t.Helper()
	if err := osfs.EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatalf("创建 Windows Owner-Only 套接字测试目录失败: %v", err)
	}
}

func TestWindowsOwnerOnlyDirectoryAndLongPath(t *testing.T) {
	base := t.TempDir()
	secDir := filepath.Join(base, "secure", "sub")
	if err := osfs.EnsureOwnerOnlyDirectory(secDir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory 失败: %v", err)
	}
	currSID, err := osfs.CurrentProcessUserSID()
	if err != nil {
		t.Fatalf("CurrentProcessUserSID 失败: %v", err)
	}
	if err := osfs.VerifyOwnerOnlyDirectoryByHandle(secDir, currSID); err != nil {
		t.Fatalf("VerifyOwnerOnlyDirectoryByHandle 失败: %v", err)
	}

	// 验证超过 248 UTF-16 码元的超长路径通过 \\?\ 正常读写与操作员只读。
	deep := filepath.Join(base, strings.Repeat("d", 90), strings.Repeat("e", 90), strings.Repeat("f", 90))
	if err := os.MkdirAll(osfs.NormalizeWin32LongPath(deep), 0o700); err != nil {
		t.Fatalf("创建超长测试目录失败: %v", err)
	}
	rootDir := mustLocalDir(t, deep)
	target := mustLocalDest(t, "long.dat")
	fsPort := osfs.NewScopedRootFS()
	if err := fsPort.WithRoot(rootDir, func(root ports.RootHandle) error {
		return root.CreateExclusive(target, 0o600, func(w io.Writer) error {
			_, wErr := w.Write([]byte("win-long-path-ok"))
			return wErr
		})
	}); err != nil {
		t.Fatalf("Windows 超长路径 CreateExclusive 失败: %v", err)
	}
	opFS := osfs.NewOperatorReadFS()
	src := mustLocalSource(t, filepath.Join(deep, "long.dat"))
	var got []byte
	if err := opFS.WithOperatorRead(context.Background(), src, pathalg.SymlinkReject, func(r ports.BoundedReadHandle, _ int64) error {
		var rErr error
		got, rErr = io.ReadAll(r)
		return rErr
	}); err != nil || string(got) != "win-long-path-ok" {
		t.Fatalf("Windows 超长路径 OperatorRead = (%q, %v)", string(got), err)
	}

	// 验证超长目录传入 BuildManagedMuxSocketPath 时返回 ErrControlPathTooLong（而非因 \\?\ 误报 ErrInvalidControlPath）。
	percentC, err := option.ComputePercentC("win", "prod.example.com", 22, "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := osfs.BuildManagedMuxSocketPath(rootDir, percentC); !errors.Is(err, osfs.ErrControlPathTooLong) {
		t.Fatalf("超长目录 BuildManagedMuxSocketPath = %v, 期望 ErrControlPathTooLong", err)
	}

	// 验证 *os.Root 内 NtCreateFile 锚定的 MkdirAll(0700) / CreateExclusive(0600) / AppendLine(0600) 均具备 Owner-Only DACL。
	verifyScopedRootOwnerOnlyDACL(t, currSID)
}

func verifyScopedRootOwnerOnlyDACL(t *testing.T, currSID *windows.SID) {
	t.Helper()
	base := t.TempDir()
	fsPort := osfs.NewScopedRootFS()
	subDir := mustLocalDest(t, "vault/sub")
	fileDest := mustLocalDest(t, "vault/sub/secret.dat")
	logDest := mustLocalDest(t, "vault/sub/audit.jsonl")
	if err := fsPort.WithRoot(mustLocalDir(t, base), func(root ports.RootHandle) error {
		if err := root.MkdirAll(subDir, 0o700); err != nil {
			return err
		}
		if err := root.CreateExclusive(fileDest, 0o600, func(w io.Writer) error {
			_, wErr := w.Write([]byte("owner-only"))
			return wErr
		}); err != nil {
			return err
		}
		return root.AppendLine(logDest, 0o600, []byte("+op-win-1"))
	}); err != nil {
		t.Fatalf("ScopedRootFS 创建 Owner-Only 对象失败: %v", err)
	}
	if err := osfs.VerifyOwnerOnlyDirectoryByHandle(filepath.Join(base, "vault", "sub"), currSID); err != nil {
		t.Fatalf("MkdirAll(0700) 目录未通过 Owner-Only DACL 校验: %v", err)
	}
	for _, rel := range []string{"secret.dat", "audit.jsonl"} {
		if err := osfs.VerifyOwnerOnlyFileByHandle(filepath.Join(base, "vault", "sub", rel), currSID); err != nil {
			t.Fatalf("%s 未通过 Owner-Only DACL 校验: %v", rel, err)
		}
	}
}

// TestWindowsScopedFSRootPinnedBlocksLiveRename 验证 Windows 上 *os.Root 内核级锁定打开中的根目录
// （外部 os.Rename 被内核以 ERROR_SHARING_VIOLATION / ERROR_ACCESS_DENIED 拒绝），
// 且根内 NtCreateFile 锚定的全套创建/追加/旁路锁/原子替换均保持受保护 Owner-Only DACL。
func TestWindowsScopedFSRootPinnedBlocksLiveRename(t *testing.T) {
	base := t.TempDir()
	origDir := filepath.Join(base, "root-orig")
	movedDir := filepath.Join(base, "root-moved")
	if err := os.Mkdir(origDir, 0o700); err != nil {
		t.Fatal(err)
	}
	currSID, err := osfs.CurrentProcessUserSID()
	if err != nil {
		t.Fatalf("CurrentProcessUserSID 失败: %v", err)
	}
	fsPort := osfs.NewScopedRootFS()
	subDir := mustLocalDest(t, "nested/sub")
	fileDest := mustLocalDest(t, "nested/sub/data.txt")
	logDest := mustLocalDest(t, "nested/sub/audit.jsonl")

	err = fsPort.WithRoot(mustLocalDir(t, origDir), func(root ports.RootHandle) error {
		rnErr := os.Rename(origDir, movedDir)
		if !errors.Is(rnErr, windows.ERROR_SHARING_VIOLATION) && !errors.Is(rnErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("Windows 打开中根目录 os.Rename = %v, 期望 ERROR_SHARING_VIOLATION 或 ERROR_ACCESS_DENIED", rnErr)
		}
		return verifyScopedRootFullOps(context.Background(), root, subDir, fileDest, logDest)
	})
	if err != nil {
		t.Fatalf("Windows 根内锚定全套操作失败: %v", err)
	}
	if data, rErr := os.ReadFile(filepath.Join(origDir, "nested", "sub", "data.txt")); rErr != nil || string(data) != "replaced" {
		t.Fatalf("Windows 根内替换文件校验失败: (%q, %v)", string(data), rErr)
	}
	if err := osfs.VerifyOwnerOnlyDirectoryByHandle(filepath.Join(origDir, "nested", "sub"), currSID); err != nil {
		t.Fatalf("Windows 根内目录未通过 Owner-Only DACL 校验: %v", err)
	}
	for _, rel := range []string{"data.txt", "data.txt.lock", "audit.jsonl"} {
		if err := osfs.VerifyOwnerOnlyFileByHandle(filepath.Join(origDir, "nested", "sub", rel), currSID); err != nil {
			t.Fatalf("Windows 根内文件 %s 未通过 Owner-Only DACL 校验: %v", rel, err)
		}
	}
}
