package credentialhelper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestNewSystemStoreDefaultID(t *testing.T) {
	cfg := SystemStoreConfig{
		Command:  "dummy-cmd",
		ReadOnly: false,
	}

	s, err := NewSystemStore("", cfg)
	if err != nil {
		t.Fatalf("NewSystemStore failed: %v", err)
	}
	if s.StoreID() != "system" {
		t.Fatalf("expected storeID 'system', got %q", s.StoreID())
	}

	s2, err := NewSystemStore("custom-sys", cfg)
	if err != nil {
		t.Fatalf("NewSystemStore with custom ID failed: %v", err)
	}
	if s2.StoreID() != "custom-sys" {
		t.Fatalf("expected storeID 'custom-sys', got %q", s2.StoreID())
	}
}

func TestCheckSystemAvailability_HeadlessDetection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux headless detection test on non-Linux platform")
	}

	// 暂存原有环境变量
	origDBus := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	origDisp := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")

	defer func() {
		_ = os.Setenv("DBUS_SESSION_BUS_ADDRESS", origDBus)
		_ = os.Setenv("DISPLAY", origDisp)
		_ = os.Setenv("WAYLAND_DISPLAY", origWayland)
	}()

	// 模拟纯 headless 环境（无 D-Bus，无 Display）
	_ = os.Unsetenv("DBUS_SESSION_BUS_ADDRESS")
	_ = os.Unsetenv("DISPLAY")
	_ = os.Unsetenv("WAYLAND_DISPLAY")

	err := CheckSystemAvailability()
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("expected ErrCredentialStoreUnavailable in headless env, got: %v", err)
	}

	// 恢复 D-Bus 环境变量
	_ = os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/fake-bus")
	err = CheckSystemAvailability()
	if err != nil {
		t.Fatalf("expected nil error when DBus session present, got: %v", err)
	}
}

func TestSystemStoreOperationsWithHelper(t *testing.T) {
	ctx := context.Background()
	storageFile := filepath.Join(t.TempDir(), "sys_store.json")
	opts := FakeHelperOptions("storage_file", "HELPER_STORAGE_FILE="+storageFile)

	cfg := SystemStoreConfig{
		Command:  opts.Command,
		Args:     opts.Args,
		Env:      opts.Env,
		Timeout:  opts.Timeout,
		ReadOnly: false,
	}

	store, err := NewSystemStore("system", cfg)
	if err != nil {
		t.Fatalf("NewSystemStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "system", ItemID: "sys-key"}
	secVal := []byte("secret-sys-payload")

	// 1. Put
	if err := store.Put(ctx, ref, credential.NewSecret(secVal)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 2. Get
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got.Value) != "secret-sys-payload" {
		t.Fatalf("got %s, want secret-sys-payload", string(got.Value))
	}
	got.Zero()

	// 3. Delete
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 4. Get after Delete
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound after delete, got: %v", err)
	}
}

func TestSystemStoreReadOnlyEnforcement(t *testing.T) {
	ctx := context.Background()
	opts := FakeHelperOptions("echo_success")
	cfg := SystemStoreConfig{
		Command:  opts.Command,
		Args:     opts.Args,
		Env:      opts.Env,
		Timeout:  opts.Timeout,
		ReadOnly: true,
	}

	store, err := NewSystemStore("system", cfg)
	if err != nil {
		t.Fatalf("NewSystemStore failed: %v", err)
	}
	if !store.IsReadOnly() {
		t.Fatal("expected store to be read-only")
	}

	ref := credential.Ref{StoreID: "system", ItemID: "k"}
	sec := credential.NewSecret([]byte("val"))
	defer sec.Zero()

	if err := store.Put(ctx, ref, sec); !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly on Put, got: %v", err)
	}
	if err := store.Delete(ctx, ref); !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("expected ErrCredentialStoreReadOnly on Delete, got: %v", err)
	}
}

func TestSystemStoreNativeStoreUnavailableInHeadless(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux headless test on non-Linux")
	}

	origDBus := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	origDisp := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")

	defer func() {
		_ = os.Setenv("DBUS_SESSION_BUS_ADDRESS", origDBus)
		_ = os.Setenv("DISPLAY", origDisp)
		_ = os.Setenv("WAYLAND_DISPLAY", origWayland)
	}()

	_ = os.Unsetenv("DBUS_SESSION_BUS_ADDRESS")
	_ = os.Unsetenv("DISPLAY")
	_ = os.Unsetenv("WAYLAND_DISPLAY")

	// 在无桌面环境且未配置外部 command 时，初始化原生 system store 必须报错 ErrCredentialStoreUnavailable
	_, err := NewSystemStore("system", SystemStoreConfig{})
	if !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("expected ErrCredentialStoreUnavailable, got: %v", err)
	}
}

func TestControlledSystemHelperResolution(t *testing.T) {
	cmdPath, args, env, err := resolveControlledSystemHelper()
	if err != nil {
		t.Fatalf("resolveControlledSystemHelper failed: %v", err)
	}
	if cmdPath == "" {
		t.Fatal("expected non-empty helper command path")
	}
	_ = args
	_ = env
}
