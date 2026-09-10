//go:build integration && linux && amd64

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

func TestOfflineStoreCommands(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{41}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	phase6Config(t, config.StoreConfig{Type: config.StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "key-file", KeyFile: key})
	run := func(op string, args ...string) (storeCommandResult, error) { return executeOfflineJSON(t, op, args...) }
	result, err := run("init")
	if errors.Is(err, credentialfile.ErrUnsupported) {
		t.Skip(err)
	}
	if err != nil || !result.Outcome.Durable {
		t.Fatalf("init: %+v %v", result, err)
	}
	result, err = run("inspect")
	if err != nil || result.Inspection.Authenticated {
		t.Fatalf("inspect: %+v %v", result, err)
	}
	result, err = run("inspect", "--verify")
	if err != nil || !result.Inspection.Authenticated {
		t.Fatalf("verify: %+v %v", result, err)
	}
	if _, err = run("reencrypt"); err != nil {
		t.Fatal(err)
	}
	if _, err = run("resume", "--operation", "00000000000000000000000000000001"); !errors.Is(err, credentialfile.ErrConflict) {
		t.Fatal("wrong operation accepted", err)
	}
	if _, err = run("resume"); err != nil {
		t.Fatal(err)
	}
	result, err = run("prune")
	if err != nil || len(result.Revisions) != 1 {
		t.Fatalf("plan: %+v %v", result, err)
	}
	if _, err = run("prune", "--apply"); err != nil {
		t.Fatal(err)
	}
	if _, err = run("rewrap", "--unlock", "prompt", "--key-file", key); err == nil {
		t.Fatal("conflicting target accepted")
	}
	if _, err = run("reencrypt", "--maintenance-timeout", "0s"); err == nil {
		t.Fatal("zero timeout accepted")
	}
	items := checkConfiguredStores(context.Background())
	for _, item := range items {
		if item.Name == "Store: test" && item.Status != "WARN" {
			t.Fatalf("doctor: %+v", item)
		}
	}
}

func executeOfflineJSON(t *testing.T, op string, args ...string) (storeCommandResult, error) {
	t.Helper()
	cmd := newOfflineStoreCommand(op)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetContext(credential.WithoutInteraction(t.Context()))
	cmd.SetArgs(append([]string{"test", "--json"}, args...))
	err := cmd.Execute()
	if bytes.Contains(output.Bytes(), bytes.Repeat([]byte{41}, 32)) {
		t.Fatal("key leaked")
	}
	var result storeCommandResult
	if e := json.Unmarshal(output.Bytes(), &result); e != nil {
		t.Fatalf("JSON: %s %v", output.String(), e)
	}
	return result, err
}

func TestOfflineStoreCloneRestore(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{17}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "original")
	fileCfg := config.StoreConfig{Type: config.StoreTypeEncryptedFile, Path: original, Unlock: "key-file", KeyFile: key}
	disk := phase6Config(t, fileCfg)
	if _, err := executeOfflineJSON(t, "init"); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	owner := config.NewEncryptedRuntime(t.Context(), "", nil)
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	source, err := owner.Store(t.Context(), "test", fileCfg)
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "test", ItemID: "backup-reference"}
	secret := credential.NewSecret([]byte("public-backup-secret"))
	defer secret.Zero()
	if err := source.Put(t.Context(), ref, secret); err != nil {
		t.Fatal(err)
	}
	cfg, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := cfg.Identities.Get("admin")
	identity.LoginPasswordRef = &ref
	cfg.Identities.Set("admin", identity)
	target := fileCfg
	target.Path = filepath.Join(dir, "copy")
	cfg.Credential.Stores["copy"] = target
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := executeOfflineJSON(t, "clone", "--to", "copy"); err != nil {
		t.Fatal(err)
	}
	clone, err := owner.Store(t.Context(), "copy", target)
	if err != nil {
		t.Fatal(err)
	}
	assertOfflineSecret(t, clone, credential.Ref{StoreID: "copy", ItemID: ref.ItemID}, secret.Value)
	backup := filepath.Join(dir, "backup.yaml")
	v2, err := cfg.ToV2()
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, data, 0600); err != nil {
		t.Fatal(err)
	}
	restored := fileCfg
	restored.Path = filepath.Join(dir, "restored")
	cfg.Credential.Stores["test"] = restored
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := executeOfflineJSON(t, "restore", "--from", original, "--source-unlock", "key-file", "--source-key-file", key, "--backup-config", backup); err != nil {
		t.Fatal(err)
	}
	dest, err := owner.Store(t.Context(), "test", restored)
	if err != nil {
		t.Fatal(err)
	}
	assertOfflineSecret(t, dest, ref, secret.Value)
}

func assertOfflineSecret(t *testing.T, s *credentialfile.Store, ref credential.Ref, want []byte) {
	t.Helper()
	got, err := s.Get(t.Context(), ref)
	equal := bytes.Equal(got.Value, want)
	got.Zero()
	if err != nil || !equal {
		t.Fatalf("offline content mismatch: %v", err)
	}
}

func TestOfflineRegistryComposition(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{35}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	fileCfg := config.StoreConfig{Type: config.StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "key-file", KeyFile: key}
	disk := phase6Config(t, fileCfg)
	if _, err := executeOfflineJSON(t, "init"); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	cfg, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "test", ItemID: "composed"}
	identity, _ := cfg.Identities.Get("admin")
	identity.LoginPasswordRef = &ref
	cfg.Identities.Set("admin", identity)
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, disk)
	if err != nil {
		t.Fatal(err)
	}
	owner := config.NewEncryptedRuntime(t.Context(), "", nil)
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	detach, err := utils.InstallCredentialRuntime(owner)
	if err != nil {
		t.Fatal(err)
	}
	defer detach()
	registry, err := utils.GetCredentialRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.GetStore("test")
	if err != nil {
		t.Fatal(err)
	}
	secret := credential.NewSecret([]byte("public-composition-secret"))
	defer secret.Zero()
	if err := store.Put(t.Context(), ref, secret); err != nil {
		t.Fatal(err)
	}
	resolver := adapter.NewNonInteractiveSSHAdapter(repository, adapter.WithCredentialSource(registry))
	value, err := resolver.ResolveSecret(t.Context(), ssh.SecretRequest{Kind: ssh.SecretKindLoginPassword, NodeID: "node"})
	equal := bytes.Equal(value, secret.Value)
	clear(value)
	if err != nil || !equal {
		t.Fatal("noninteractive adapter failed", err)
	}
	if err := owner.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	value, err = resolver.ResolveSecret(t.Context(), ssh.SecretRequest{Kind: ssh.SecretKindLoginPassword, NodeID: "node"})
	clear(value)
	if err == nil {
		t.Fatal("resolver fell back after key removal")
	}
}
