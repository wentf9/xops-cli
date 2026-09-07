package credentialhelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestFakePassCLIProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PASS_CLI_PROCESS") != "1" {
		return
	}

	for _, arg := range os.Args {
		if strings.Contains(strings.ToLower(arg), "passphrase123") {
			_, _ = fmt.Fprintf(os.Stderr, "SECURITY VIOLATION: secret leaked into argv: %s\n", arg)
			os.Exit(99)
		}
	}

	mode := os.Getenv("PASS_TEST_MODE")
	subcmd := ""
	for _, arg := range os.Args {
		switch arg {
		case "show", "insert", "rm":
			subcmd = arg
		}
	}

	switch mode {
	case "storage_file":
		filePath := os.Getenv("PASS_STORAGE_FILE")
		dataMap := make(map[string]string)
		if raw, err := os.ReadFile(filePath); err == nil && len(raw) > 0 {
			for _, line := range strings.Split(string(raw), "\n") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					dataMap[parts[0]] = parts[1]
				}
			}
		}

		itemPath := os.Args[len(os.Args)-1]

		switch subcmd {
		case "show":
			val, ok := dataMap[itemPath]
			if !ok {
				_, _ = fmt.Fprintf(os.Stderr, "Error: %s is not in the password store.\n", itemPath)
				os.Exit(1)
			}
			_, _ = io.WriteString(os.Stdout, val)
			os.Exit(0)
		case "insert":
			stdinBytes, _ := io.ReadAll(os.Stdin)
			dataMap[itemPath] = string(stdinBytes)
			var sb strings.Builder
			for k, v := range dataMap {
				sb.WriteString(k + "=" + v + "\n")
			}
			_ = os.WriteFile(filePath, []byte(sb.String()), 0600)
			os.Exit(0)
		case "rm":
			delete(dataMap, itemPath)
			var sb strings.Builder
			for k, v := range dataMap {
				sb.WriteString(k + "=" + v + "\n")
			}
			_ = os.WriteFile(filePath, []byte(sb.String()), 0600)
			os.Exit(0)
		}

	case "locked":
		_, _ = fmt.Fprintf(os.Stderr, "gpg: decryption failed: pinentry error\n")
		os.Exit(2)

	default:
		os.Exit(0)
	}
}

func fakePassOptions(mode string, env ...string) PassStoreConfig {
	allEnv := append([]string{
		"GO_WANT_PASS_CLI_PROCESS=1",
		"PASS_TEST_MODE=" + mode,
	}, env...)
	return PassStoreConfig{
		Prefix:  "myops",
		Command: os.Args[0],
		Args:    []string{"-test.run=^TestFakePassCLIProcess$", "--"},
		Env:     allEnv,
		Timeout: 2 * time.Second,
	}
}

func TestNewPassStoreValidation(t *testing.T) {
	if _, err := NewPassStore("", PassStoreConfig{}); err == nil {
		t.Fatal("expected error on empty storeID")
	}

	ps, err := NewPassStore("pass-1", PassStoreConfig{})
	if err != nil {
		t.Fatalf("NewPassStore failed: %v", err)
	}
	if ps.StoreID() != "pass-1" || ps.prefix != DefaultPassPrefix || ps.command != DefaultPassCommand {
		t.Fatalf("unexpected defaults: id=%s, prefix=%s, cmd=%s", ps.StoreID(), ps.prefix, ps.command)
	}
}

func TestPassStoreDirectCLI(t *testing.T) {
	ctx := context.Background()
	storageFile := filepath.Join(t.TempDir(), "pass_data.txt")
	cfg := fakePassOptions("storage_file", "PASS_STORAGE_FILE="+storageFile)

	store, err := NewPassStore("pass-store", cfg)
	if err != nil {
		t.Fatalf("NewPassStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "pass-store", ItemID: "srv-pass"}

	// 1. Get 不存在时返回 ErrCredentialNotFound
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound before put, got: %v", err)
	}

	// 2. Put
	secVal := []byte("passphrase123")
	if err := store.Put(ctx, ref, credential.NewSecret(secVal)); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// 3. Get
	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got.Value) != "passphrase123" {
		t.Fatalf("got %s, want passphrase123", string(got.Value))
	}
	got.Zero()

	// 4. Delete
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// 5. Delete 之后再次 Get
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialNotFound) {
		t.Fatalf("expected ErrCredentialNotFound after delete, got: %v", err)
	}
}

func TestPassStoreLockedMapping(t *testing.T) {
	ctx := context.Background()
	cfg := fakePassOptions("locked")

	store, err := NewPassStore("pass-store", cfg)
	if err != nil {
		t.Fatalf("NewPassStore failed: %v", err)
	}

	ref := credential.Ref{StoreID: "pass-store", ItemID: "locked-item"}
	_, err = store.Get(ctx, ref)
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("expected ErrCredentialStoreLocked, got: %v", err)
	}
}

func TestPassStoreHelperProtocolDelegation(t *testing.T) {
	ctx := context.Background()
	storageFile := filepath.Join(t.TempDir(), "pass_helper.json")
	opts := FakeHelperOptions("storage_file", "HELPER_STORAGE_FILE="+storageFile)

	cfg := PassStoreConfig{
		Command:          opts.Command,
		Args:             opts.Args,
		Env:              opts.Env,
		Timeout:          opts.Timeout,
		IsHelperProtocol: true,
	}

	store, err := NewPassStore("pass-helper", cfg)
	if err != nil {
		t.Fatalf("NewPassStore helper mode failed: %v", err)
	}

	ref := credential.Ref{StoreID: "pass-helper", ItemID: "k1"}
	if err := store.Put(ctx, ref, credential.NewSecret([]byte("pass-data"))); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	got, err := store.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(got.Value) != "pass-data" {
		t.Fatalf("got %s, want pass-data", string(got.Value))
	}
	got.Zero()
}
