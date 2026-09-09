package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestLocalSudoNewInstallDoesNotPersist(t *testing.T) {
	dir := setupTestEnvironment(t)
	if err := utils.RememberLocalSudoPassword(t.Context(), "session-secret"); err != nil {
		t.Fatal(err)
	}
	if err := utils.SaveLocalSudoPasswordContext(t.Context(), "session-secret"); !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("explicit none write must fail before metadata creation: %v", err)
	}
	for _, name := range []string{"xops_config.yaml", "secret.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("session-only sudo created %s: %v", name, err)
		}
	}
}

func TestLocalSudoFirstSaveFailurePreservesConfiguration(t *testing.T) {
	for _, code := range []string{"locked", "unavailable"} {
		t.Run(code, func(t *testing.T) {
			dir := setupTestEnvironment(t)
			t.Setenv("TEST_IDENTITY_HELPER", "1")
			t.Setenv("TEST_HELPER_DATA_FILE", filepath.Join(dir, "helper-data"))
			t.Setenv("TEST_HELPER_ERROR_CODE", code)
			path := filepath.Join(dir, "xops_config.yaml")
			store := config.NewDefaultStore(path, filepath.Join(dir, "secret.key"))
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Credential.DefaultStore = "test"
			cfg.Credential.Stores["test"] = config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]}
			if err := store.Save(cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := credential.ErrCredentialStoreLocked
			if code == "unavailable" {
				want = credential.ErrCredentialStoreUnavailable
			}
			if err := utils.SaveLocalSudoPasswordContext(t.Context(), "rejected-secret"); !errors.Is(err, want) {
				t.Fatalf("first save returned %v, want %v", err, want)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(before) {
				t.Fatalf("first failed save modified configuration: %v", err)
			}
			// The same operation must remain retryable after unlocking the store.
			t.Setenv("TEST_HELPER_ERROR_CODE", "")
			if err := utils.SaveLocalSudoPasswordContext(t.Context(), "retry-secret"); err != nil {
				t.Fatal(err)
			}
			got, found, err := utils.GetLocalSudoPasswordContext(t.Context())
			if err != nil || !found || got != "retry-secret" {
				t.Fatalf("retry failed: found=%v err=%v", found, err)
			}
		})
	}
}

func TestLocalSudoV2CredentialLifecycle(t *testing.T) {
	dir := setupTestEnvironment(t)
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", filepath.Join(dir, "helper-data"))
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewDefaultStore(path, key)
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credential.DefaultStore = "test"
	cfg.Credential.RememberPrompted = "always"
	cfg.Credential.Stores["test"] = config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0], NonInteractive: true}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"first-local-secret", "rotated-local-secret"} {
		if err := utils.RememberLocalSudoPassword(t.Context(), password); err != nil {
			t.Fatal(err)
		}
		got, found, err := utils.GetLocalSudoPasswordContext(t.Context())
		if err != nil || !found || got != password {
			t.Fatalf("local credential roundtrip failed: found=%v err=%v", found, err)
		}
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "local-secret") || strings.Contains(string(before), "password:") {
		t.Fatal("local sudo wrote a password into YAML")
	}
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	if err := utils.SaveLocalSudoPasswordContext(t.Context(), "rejected-secret"); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("locked write: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("failed write changed configuration: %v", err)
	}
	if _, _, err := utils.GetLocalSudoPasswordContext(t.Context()); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("locked reference did not fail closed: %v", err)
	}
	// The command must propagate backend failure before prompting or executing sudo.
	if err := executePhase6(t, newCmdSudo(), "true"); !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("sudo swallowed resolver failure: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := utils.GetLocalSudoPasswordContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("resolver lost caller cancellation: %v", err)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local sudo created legacy key: %v", err)
	}
}
