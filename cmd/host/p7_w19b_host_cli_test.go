package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP7W19b_L4_19_L1_RejectEmptyOrWhitespaceIdentityFlag(t *testing.T) {
	store, wantIdent := seedW18cIdentityIsolationConfig(t)
	assertW19bAddRejectEmptyIdentity(t, store, wantIdent)
	assertW19bEditRejectEmptyIdentity(t, store, wantIdent)
	assertW19bTrimValidIdentityAlias(t, store, wantIdent)
}

func assertW19bAddRejectEmptyIdentity(t *testing.T, store config.Store, wantIdent models.Identity) {
	t.Helper()
	addBadCases := []struct {
		name string
		args []string
	}{
		{name: "long_empty", args: []string{"10.19.0.2", "--identity="}},
		{name: "short_empty", args: []string{"10.19.0.2", "-I", ""}},
		{name: "short_whitespace", args: []string{"10.19.0.2", "-I", "   \t  "}},
		{name: "empty_without_target_fails_before_prompt", args: []string{"--identity="}},
	}
	for _, tc := range addBadCases {
		t.Run("add_reject_"+tc.name, func(t *testing.T) {
			verifyCalled := false
			verifier := func(_ context.Context, _ *config.Repository, _ string, _ *inventoryVerification) error {
				verifyCalled = true
				return nil
			}
			cmd := newCmdInventoryAdd(verifier)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--identity") {
				t.Fatalf("host add %v error = %v, want clear --identity error", tc.args, err)
			}
			if verifyCalled {
				t.Fatalf("host add %v invoked verifier before rejecting empty --identity", tc.args)
			}
			assertW18cSharedIdentityUnchanged(t, store, wantIdent)
			loaded, loadErr := store.Load()
			if loadErr != nil {
				t.Fatalf("store.Load: %v", loadErr)
			}
			if len(loaded.Nodes.Keys()) != 1 {
				t.Fatalf("host add %v mutated node count: got %d, want 1", tc.args, len(loaded.Nodes.Keys()))
			}
		})
	}
}

func assertW19bEditRejectEmptyIdentity(t *testing.T, store config.Store, wantIdent models.Identity) {
	t.Helper()
	editBadCases := []struct {
		name string
		args []string
	}{
		{name: "long_empty", args: []string{"orig@10.18.0.1:22", "--identity="}},
		{name: "short_empty", args: []string{"orig@10.18.0.1:22", "-I", ""}},
		{name: "short_whitespace", args: []string{"orig@10.18.0.1:22", "-I", "  \t "}},
	}
	for _, tc := range editBadCases {
		t.Run("edit_reject_"+tc.name, func(t *testing.T) {
			cmd := NewCmdInventoryEdit()
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			if err == nil || !strings.Contains(err.Error(), "--identity") {
				t.Fatalf("host edit %v error = %v, want clear --identity error", tc.args, err)
			}
			assertW18cSharedIdentityUnchanged(t, store, wantIdent)
			loaded, loadErr := store.Load()
			if loadErr != nil {
				t.Fatalf("store.Load: %v", loadErr)
			}
			node, ok := loaded.Nodes.Get("orig@10.18.0.1:22")
			if !ok || node.IdentityRef != "orig@10.18.0.1" {
				t.Fatalf("host edit %v mutated existing node: (%+v, %v)", tc.args, node, ok)
			}
		})
	}
}

func assertW19bTrimValidIdentityAlias(t *testing.T, store config.Store, wantIdent models.Identity) {
	t.Helper()
	t.Run("add_and_edit_trim_valid_identity_alias", func(t *testing.T) {
		noopVerifier := func(_ context.Context, _ *config.Repository, _ string, _ *inventoryVerification) error {
			return nil
		}
		cmdAdd := newCmdInventoryAdd(noopVerifier)
		cmdAdd.SetArgs([]string{"10.19.0.5:2222", "-I", "  shared-id  ", "--skip-verify"})
		if err := cmdAdd.Execute(); err != nil {
			t.Fatalf("host add with padded valid -I failed: %v", err)
		}
		loaded, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load after add: %v", err)
		}
		added, ok := loaded.Nodes.Get("ops@10.19.0.5:2222")
		if !ok || added.IdentityRef != "shared-id" {
			t.Fatalf("added node = (%+v, %v), want IdentityRef=shared-id", added, ok)
		}

		cmdEdit := NewCmdInventoryEdit()
		cmdEdit.SetArgs([]string{"orig@10.18.0.1:22", "-I", "  shared-id  "})
		if err := cmdEdit.Execute(); err != nil {
			t.Fatalf("host edit with padded valid -I failed: %v", err)
		}
		loaded, err = store.Load()
		if err != nil {
			t.Fatalf("store.Load after edit: %v", err)
		}
		edited, ok := loaded.Nodes.Get("ops@10.18.0.1:22")
		if !ok || edited.IdentityRef != "shared-id" {
			t.Fatalf("edited node = (%+v, %v), want ops@10.18.0.1:22 with IdentityRef=shared-id", edited, ok)
		}
		assertW18cSharedIdentityUnchanged(t, store, wantIdent)
	})
}

func writeW19bEncryptedKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	block, err := cryptoSSH.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519_enc")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", keyPath, err)
	}
	return keyPath
}

func TestP7W19b_L4_19_L2_ImportVerificationPreservesHybridAuthType(t *testing.T) {
	hybridTypes := []string{"otp", "keyboard-interactive", "auto"}
	encKeyPath := writeW19bEncryptedKey(t, "new-key-pass")

	for _, authType := range hybridTypes {
		t.Run("hybrid_"+authType+"_password_and_key_import_verification", func(t *testing.T) {
			repo, store := verificationRepository(t)
			const nodeID = "ops@10.19.1.1:22"
			if _, err := repo.CreateNodeContext(t.Context(), nodeID,
				models.Node{HostRef: "h-hyb", IdentityRef: "id-hyb", SudoMode: models.SudoModeAuto},
				models.Host{Address: "10.19.1.1", Port: 22},
				models.Identity{User: "ops", AuthType: authType, KeyPath: "/tmp/orig_hybrid_key"},
			); err != nil {
				t.Fatalf("CreateNodeContext(%s): %v", authType, err)
			}

			// 1. Verified CSV import updating password must preserve hybrid AuthType during verification & save.
			var seenAuthTypes []string
			verifier := func(_ context.Context, _ *config.Repository, _ string, check *inventoryVerification) error {
				seenAuthTypes = append(seenAuthTypes, check.Identity.AuthType)
				return nil
			}
			var out bytes.Buffer
			if err := executeImport(t.Context(), repo, []utils.HostInfo{
				{Host: "10.19.1.1", Port: 22, User: "ops", Password: "new-password"},
			}, ImportOptions{Output: &out, NoProbe: true}, verifier); err != nil {
				t.Fatalf("executeImport(password on %s): %v\n%s", authType, err, out.String())
			}
			if len(seenAuthTypes) != 1 || seenAuthTypes[0] != authType {
				t.Fatalf("verificationBundle(password) AuthType = %v, want [%q]", seenAuthTypes, authType)
			}
			loaded, err := store.Load()
			if err != nil {
				t.Fatalf("store.Load after password import: %v", err)
			}
			node, _ := loaded.Nodes.Get(nodeID)
			ident, _ := loaded.Identities.Get(node.IdentityRef)
			if ident.AuthType != authType {
				t.Fatalf("saved AuthType after password import = %q, want %q", ident.AuthType, authType)
			}

			// 2. Verified CSV import updating key+passphrase must also preserve hybrid AuthType during verification & save.
			seenAuthTypes = nil
			out.Reset()
			if err := executeImport(t.Context(), repo, []utils.HostInfo{
				{Host: "10.19.1.1", Port: 22, User: "ops", KeyPath: encKeyPath, Passphrase: "new-key-pass"},
			}, ImportOptions{Output: &out, NoProbe: true}, verifier); err != nil {
				t.Fatalf("executeImport(key on %s): %v\n%s", authType, err, out.String())
			}
			if len(seenAuthTypes) != 1 || seenAuthTypes[0] != authType {
				t.Fatalf("verificationBundle(key) AuthType = %v, want [%q]", seenAuthTypes, authType)
			}
			loaded, err = store.Load()
			if err != nil {
				t.Fatalf("store.Load after key import: %v", err)
			}
			node, _ = loaded.Nodes.Get(nodeID)
			ident, _ = loaded.Identities.Get(node.IdentityRef)
			if ident.AuthType != authType {
				t.Fatalf("saved AuthType after key import = %q, want %q", ident.AuthType, authType)
			}
		})
	}

	t.Run("non_hybrid_auth_type_still_updates_during_verification", func(t *testing.T) {
		repo, _ := verificationRepository(t)
		const nodeID = "ops@10.19.1.2:22"
		if _, err := repo.CreateNodeContext(t.Context(), nodeID,
			models.Node{HostRef: "h-plain", IdentityRef: "id-plain", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.19.1.2", Port: 22},
			models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/orig_key"},
		); err != nil {
			t.Fatalf("CreateNodeContext: %v", err)
		}
		draftPW, err := prepareImport(repo, utils.HostInfo{Host: "10.19.1.2", Port: 22, User: "ops", Password: "pw"}, "")
		if err != nil {
			t.Fatalf("prepareImport(pw): %v", err)
		}
		if got := draftPW.verificationBundle().Identity.AuthType; got != "password" {
			t.Fatalf("non-hybrid key->password verificationBundle AuthType = %q, want password", got)
		}

		const pwNodeID = "ops@10.19.1.3:22"
		if _, err := repo.CreateNodeContext(t.Context(), pwNodeID,
			models.Node{HostRef: "h-pw", IdentityRef: "id-pw", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.19.1.3", Port: 22},
			models.Identity{User: "ops", AuthType: "password"},
		); err != nil {
			t.Fatalf("CreateNodeContext(pwNode): %v", err)
		}
		draftKey, err := prepareImport(repo, utils.HostInfo{Host: "10.19.1.3", Port: 22, User: "ops", KeyPath: "/tmp/new_key"}, "")
		if err != nil {
			t.Fatalf("prepareImport(key): %v", err)
		}
		if got := draftKey.verificationBundle().Identity.AuthType; got != "key" {
			t.Fatalf("non-hybrid password->key verificationBundle AuthType = %q, want key", got)
		}
	})
}
