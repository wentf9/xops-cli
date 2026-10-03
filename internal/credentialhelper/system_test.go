package credentialhelper

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	coreauth "github.com/wentf9/xops-cli/core/auth"
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
	if !errors.Is(err, coreauth.ErrCredentialStoreUnavailable) {
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
	if !errors.Is(err, coreauth.ErrCredentialNotFound) {
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
	if !errors.Is(err, coreauth.ErrCredentialStoreUnavailable) {
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

func TestSystemStoreLinuxDBusFailureNotReportedAsNotFound(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping linux-specific test on non-linux")
	}

	fakeScript := filepath.Join(t.TempDir(), "secret-tool")
	scriptContent := "#!/bin/sh\nprintf 'Cannot connect to D-Bus session bus' >&2\nexit 1\n"
	if err := os.WriteFile(fakeScript, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", filepath.Dir(fakeScript)+":"+origPath)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/fake-bus")

	store, err := newNativeSystemStore("system", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	_, err = store.Get(context.Background(), credential.Ref{StoreID: "system", ItemID: "k"})
	if errors.Is(err, coreauth.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialStoreUnavailable on DBus failure, but got ErrCredentialNotFound: %v", err)
	}
	if !errors.Is(err, coreauth.ErrCredentialStoreUnavailable) {
		t.Fatalf("expected ErrCredentialStoreUnavailable, got: %v", err)
	}
}

func TestSystemStoreLinuxDeleteUnlocksMatchingItem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping linux-specific test on non-linux")
	}

	tempDir := t.TempDir()
	fakeScript := filepath.Join(tempDir, "secret-tool")
	callLog := filepath.Join(tempDir, "calls")
	unlocked := filepath.Join(tempDir, "unlocked")
	scriptContent := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_SECRET_TOOL_CALLS"
case "$1" in
search)
    if [ "$2" != "--all" ] || [ "$3" != "--unlock" ]; then
        exit 2
    fi
    : > "$TEST_SECRET_TOOL_UNLOCKED"
    printf 'secret = must-not-leak\n'
    printf 'attribute.xops-item = locked-item\nattribute.xops-store = system\n' >&2
    ;;
clear)
    test -f "$TEST_SECRET_TOOL_UNLOCKED"
    ;;
*)
    exit 2
    ;;
esac
`
	if err := os.WriteFile(fakeScript, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", tempDir+":"+os.Getenv("PATH"))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/fake-bus")
	t.Setenv("TEST_SECRET_TOOL_CALLS", callLog)
	t.Setenv("TEST_SECRET_TOOL_UNLOCKED", unlocked)

	store, err := newNativeSystemStore("system", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "system", ItemID: "locked-item"}
	if err := store.Delete(t.Context(), ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	want := "search --all --unlock xops-store system xops-item locked-item\n" +
		"clear xops-store system xops-item locked-item\n"
	if string(calls) != want {
		t.Fatalf("unexpected secret-tool calls:\n%s\nwant:\n%s", calls, want)
	}
	if strings.Contains(string(calls), "must-not-leak") {
		t.Fatal("secret-tool output leaked into diagnostics")
	}
}

func TestSystemStoreLinuxDeleteStopsWhenUnlockFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping linux-specific test on non-linux")
	}
	for _, testCase := range []struct {
		name     string
		action   string
		exitCode string
		stderr   string
		want     error
	}{
		{"nonzero exit", "search", "1", "", coreauth.ErrCredentialStoreLocked},
		{"partial unlock", "search", "0", "secret-tool: Cannot get secret of a locked object", coreauth.ErrCredentialStoreLocked},
		{"error after metadata", "search", "0", strings.Repeat("attribute.xops-store = system\n", 20) + "secret-tool: Cannot get secret of a locked object", coreauth.ErrCredentialStoreLocked},
		{"truncated diagnostics", "search", "0", strings.Repeat("attribute.xops-store = system\n", 160) + "secret-tool: Cannot get secret of a locked object", coreauth.ErrCredentialStoreUnavailable},
		{"localized failure", "search", "0", "secret-tool: 无法读取锁定条目", coreauth.ErrCredentialStoreUnavailable},
		{"partial clear", "clear", "0", "secret-tool: Cannot delete a locked object", coreauth.ErrCredentialStoreLocked},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("TEST_SECRET_TOOL_FAIL_ACTION", testCase.action)
			t.Setenv("TEST_SECRET_TOOL_EXIT", testCase.exitCode)
			t.Setenv("TEST_SECRET_TOOL_STDERR", testCase.stderr)
			testSystemStoreLinuxDeleteUnlockFailure(t, testCase.want)
		})
	}
}

func testSystemStoreLinuxDeleteUnlockFailure(t *testing.T, wantErr error) {
	t.Helper()

	tempDir := t.TempDir()
	fakeScript := filepath.Join(tempDir, "secret-tool")
	callLog := filepath.Join(tempDir, "calls")
	scriptContent := `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_SECRET_TOOL_CALLS"
if [ "$1" = "search" ]; then
    printf 'secret = must-not-leak\n'
    printf 'attribute.xops-item = locked-item\nattribute.xops-store = system\n' >&2
fi
if [ "$1" = "$TEST_SECRET_TOOL_FAIL_ACTION" ]; then
    printf '%s' "$TEST_SECRET_TOOL_STDERR" >&2
    exit "$TEST_SECRET_TOOL_EXIT"
fi
exit 0
`
	if err := os.WriteFile(fakeScript, []byte(scriptContent), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", tempDir+":"+os.Getenv("PATH"))
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/fake-bus")
	t.Setenv("TEST_SECRET_TOOL_CALLS", callLog)

	store, err := newNativeSystemStore("system", SystemStoreConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "system", ItemID: "locked-item"}
	if err := store.Delete(t.Context(), ref); !errors.Is(err, wantErr) {
		t.Fatalf("Delete error = %v, want %v", err, wantErr)
	}

	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	want := "search --all --unlock xops-store system xops-item locked-item\n"
	if os.Getenv("TEST_SECRET_TOOL_FAIL_ACTION") == "clear" {
		want += "clear xops-store system xops-item locked-item\n"
	}
	if string(calls) != want {
		t.Fatalf("delete continued after failed unlock:\n%s\nwant:\n%s", calls, want)
	}
	assertSystemStoreCleanupRecovery(t, store, ref, wantErr)
}

func assertSystemStoreCleanupRecovery(t *testing.T, store credential.Store, ref credential.Ref, wantErr error) {
	t.Helper()
	registry := credential.NewRegistry()
	if err := registry.Register("system", store); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := credential.NewService(registry, journal, deletedAssetConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := service.DeleteAssets(t.Context(), []credential.Ref{ref}, func(context.Context) (credential.MutationOutcome, error) {
		return credential.MutationOutcome{Applied: true, Durable: true}, nil
	})
	var cleanup *credential.CleanupError
	if !outcome.Durable || !errors.As(err, &cleanup) || !errors.Is(err, wantErr) {
		t.Fatalf("asset deletion lost cleanup failure: %+v, %v", outcome, err)
	}
	if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatal("cleanup error exposed search output")
	}
	service, err = credential.NewService(registry, journal, deletedAssetConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	results, err := service.GC(t.Context())
	if err != nil || len(results) != 1 || !errors.Is(results[0].Err, wantErr) || results[0].Action != credential.RecoveryActionScheduledForGC {
		t.Fatalf("GC lost partial cleanup failure: %+v, %v", results, err)
	}
	assertSystemStorePendingCleanup(t, journal, 1)
	t.Setenv("TEST_SECRET_TOOL_STDERR", "")
	t.Setenv("TEST_SECRET_TOOL_EXIT", "0")
	results, err = service.GC(t.Context())
	if err != nil || len(results) != 1 || results[0].Err != nil || results[0].Action != credential.RecoveryActionCommittedCleaned {
		t.Fatalf("GC did not complete after unlocking: %+v, %v", results, err)
	}
	assertSystemStorePendingCleanup(t, journal, 0)
}

func assertSystemStorePendingCleanup(t *testing.T, journal *credential.JournalStore, want int) {
	t.Helper()
	pending, err := journal.ListPending()
	if err != nil || len(pending) != want {
		t.Fatalf("pending journals = %+v, %v; want %d", pending, err, want)
	}
	for _, entry := range pending {
		if entry.Stage != credential.StageCleanup {
			t.Fatalf("journal stage = %s, want cleanup", entry.Stage)
		}
	}
}

type deletedAssetConfig struct{}

func (deletedAssetConfig) CheckRefUnreferenced(context.Context, credential.Ref) (bool, error) {
	return true, nil
}

func (deletedAssetConfig) ApplyCredentialRefAtVersion(context.Context, credential.Target, string, *credential.Ref) (credential.MutationOutcome, string, error) {
	return credential.MutationOutcome{}, "", errors.New("unexpected credential mutation during asset cleanup")
}

func (deletedAssetConfig) ConfirmRefDurable(context.Context, credential.Target, *credential.Ref) (bool, error) {
	return false, errors.New("unexpected target durability check during asset cleanup")
}

func TestInternalSystemHelperProtocolValidation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		action     string
		input      string
		wantSubstr string
	}{
		{
			name:       "invalid protocol version",
			action:     "get",
			input:      `{"protocolVersion": 99, "storeID": "s", "itemID": "k"}`,
			wantSubstr: "unsupported protocol version",
		},
		{
			name:       "multiple JSON responses",
			action:     "get",
			input:      `{"protocolVersion": 1, "storeID": "s", "itemID": "k"}{"protocolVersion": 1}`,
			wantSubstr: "unexpected multiple JSON objects",
		},
		{
			name:       "empty ref store ID",
			action:     "get",
			input:      `{"protocolVersion": 1, "storeID": "", "itemID": "k"}`,
			wantSubstr: "storeID and itemID cannot be empty",
		},
		{
			name:       "invalid store action empty secret",
			action:     "store",
			input:      `{"protocolVersion": 1, "storeID": "s", "itemID": "k", "secret": ""}`,
			wantSubstr: "secret is empty",
		},
		{
			name:       "invalid store action invalid base64",
			action:     "store",
			input:      `{"protocolVersion": 1, "storeID": "s", "itemID": "k", "secret": "not-valid-base64!@#"}`,
			wantSubstr: "invalid base64 secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(exe, tc.action)
			cmd.Env = append(os.Environ(), internalHelperEnvVar+"=1")
			cmd.Stdin = strings.NewReader(tc.input)
			out, runErr := cmd.Output()
			if runErr == nil {
				t.Fatalf("expected helper process to exit non-zero on validation failure")
			}
			var resp Response
			if err := json.Unmarshal(out, &resp); err != nil {
				t.Fatalf("failed to parse helper json response: %v (raw: %s)", err, string(out))
			}
			if resp.Code != "unavailable" {
				t.Fatalf("expected code 'unavailable', got %q", resp.Code)
			}
			if !strings.Contains(resp.Message, tc.wantSubstr) {
				t.Fatalf("expected message to contain %q, got %q", tc.wantSubstr, resp.Message)
			}
		})
	}
}
