package tui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

func TestP7W15c_L4_15_H1_EditPreservesNamedIdentityRefAndDoesNotClobberCrossPortPeer(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	peerRef := &credential.Ref{StoreID: "mem", ItemID: "peer-2222-pw"}
	prodRef := &credential.Ref{StoreID: "mem", ItemID: "prod-ops-pw"}

	cfg.Hosts.Set("10.0.0.1:22", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("10.0.0.1:2222", models.Host{Address: "10.0.0.1", Port: 2222})
	cfg.Identities.Set("prod-ops", models.Identity{
		User:             "ops",
		AuthType:         "password",
		LoginPasswordRef: prodRef.Clone(),
	})
	cfg.Identities.Set("ops@10.0.0.1", models.Identity{
		User:             "ops",
		AuthType:         "key",
		KeyPath:          "/keys/port-2222",
		LoginPasswordRef: peerRef.Clone(),
	})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "prod-ops",
		SudoMode:    models.SudoModeAuto,
		Tags:        []string{"old"},
	})
	cfg.Nodes.Set("ops@10.0.0.1:2222", models.Node{
		HostRef:     "10.0.0.1:2222",
		IdentityRef: "ops@10.0.0.1",
		SudoMode:    models.SudoModeAuto,
	})

	repo := newTestRepository(t, cfg)
	m := &Model{repository: repo}
	state, err := m.newNodeFormState("ops@10.0.0.1:22")
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.tags = "prod,updated"
	m.formState = state

	completeConfigurationMutation(t, m, m.saveFormCmd())

	snap := repo.Snapshot()
	editedNode, ok := snap.Nodes.Get("ops@10.0.0.1:22")
	if !ok {
		t.Fatal("edited node ops@10.0.0.1:22 disappeared")
	}
	if editedNode.IdentityRef != "prod-ops" {
		t.Fatalf("edited node IdentityRef = %q, want preserved named ref %q", editedNode.IdentityRef, "prod-ops")
	}
	prodIdent, ok := snap.Identities.Get("prod-ops")
	if !ok || prodIdent.LoginPasswordRef == nil || *prodIdent.LoginPasswordRef != *prodRef {
		t.Fatalf("named identity prod-ops lost or corrupted: (%+v, %v)", prodIdent, ok)
	}
	peerIdent, ok := snap.Identities.Get("ops@10.0.0.1")
	if !ok || peerIdent.AuthType != "key" || peerIdent.KeyPath != "/keys/port-2222" {
		t.Fatalf("cross-port peer identity ops@10.0.0.1 was clobbered: (%+v, %v)", peerIdent, ok)
	}
}

func TestP7W15c_L4_15_H1_EditPreservesImportedNodeIDAndHostAliasAcrossPortChange(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("openssh-host:bastion", models.Host{
		Address: "10.0.0.5",
		Port:    22,
		Alias:   []string{"bastion-host"},
	})
	cfg.Identities.Set("openssh-identity:bastion", models.Identity{
		User:     "ops",
		AuthType: "auto",
		KeyPath:  "/keys/bastion_ed25519",
	})
	cfg.Nodes.Set("bastion", models.Node{
		HostRef:     "openssh-host:bastion",
		IdentityRef: "openssh-identity:bastion",
		Alias:       []string{"bastion"},
		Tags:        []string{"openssh"},
		SudoMode:    models.SudoModeAuto,
	})

	repo := newTestRepository(t, cfg)
	m := &Model{repository: repo}
	state, err := m.newNodeFormState("bastion")
	if err != nil {
		t.Fatalf("newNodeFormState(bastion): %v", err)
	}
	if state.authType != "auto" {
		t.Fatalf("newNodeFormState authType = %q, want auto", state.authType)
	}
	state.port = "2222"
	state.tags = "openssh,edge"
	m.formState = state

	completeConfigurationMutation(t, m, m.saveFormCmd())

	snap := repo.Snapshot()
	if _, renamed := snap.Nodes.Get("ops@10.0.0.5:2222"); renamed {
		t.Fatal("custom/imported node bastion was unexpectedly renamed to canonical ID")
	}
	node, ok := snap.Nodes.Get("bastion")
	if !ok {
		t.Fatal("imported node bastion disappeared after edit")
	}
	if node.HostRef != "openssh-host:bastion" {
		t.Fatalf("node.HostRef = %q, want preserved %q", node.HostRef, "openssh-host:bastion")
	}
	if node.IdentityRef != "openssh-identity:bastion" {
		t.Fatalf("node.IdentityRef = %q, want preserved %q", node.IdentityRef, "openssh-identity:bastion")
	}
	host, ok := snap.Hosts.Get(node.HostRef)
	if !ok || host.Port != 2222 || len(host.Alias) != 1 || host.Alias[0] != "bastion-host" {
		t.Fatalf("host after port edit = (%+v, %v), want Port=2222 and preserved Alias=[bastion-host]", host, ok)
	}
	ident, ok := snap.Identities.Get(node.IdentityRef)
	if !ok || ident.AuthType != "auto" || ident.KeyPath != "/keys/bastion_ed25519" {
		t.Fatalf("auto identity after edit = (%+v, %v), want AuthType=auto and preserved KeyPath", ident, ok)
	}
}

func TestP7W15c_L4_15_H1_CreateAvoidsAliasedHostCollisionAndCrossPortIdentityOverwrite(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("10.0.0.1:22", models.Host{
		Address: "10.0.0.1",
		Port:    22,
		Alias:   []string{"db-primary"},
	})
	cfg.Identities.Set("ops@10.0.0.1", models.Identity{
		User:     "ops",
		AuthType: "key",
		KeyPath:  "/keys/existing-ops",
	})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "ops@10.0.0.1",
		SudoMode:    models.SudoModeAuto,
	})

	repo := newTestRepository(t, cfg)

	// 1. Create bob@10.0.0.1:22 on same host:port -> must NOT attach to aliased Hosts["10.0.0.1:22"].
	m1 := &Model{
		repository: repo,
		formState: &nodeFormState{
			isEdit:     false,
			skipVerify: true,
			user:       "bob",
			address:    "10.0.0.1",
			port:       "22",
			authType:   "password",
			sudoMode:   string(models.SudoModeAuto),
		},
	}
	completeConfigurationMutation(t, m1, m1.saveFormCmd())

	bobNode, ok := repo.GetNode("bob@10.0.0.1:22")
	if !ok {
		t.Fatal("bob@10.0.0.1:22 was not created")
	}
	if bobNode.HostRef == "10.0.0.1:22" {
		t.Fatalf("bob@10.0.0.1:22 attached to aliased host ref %q, breaking db-primary alias uniqueness", bobNode.HostRef)
	}
	resolved, err := repo.ResolveSelector("db-primary")
	if err != nil {
		t.Fatalf("ResolveSelector(db-primary) failed with ambiguity after creating bob: %v", err)
	}
	if resolved != "ops@10.0.0.1:22" {
		t.Fatalf("ResolveSelector(db-primary) = %q, want ops@10.0.0.1:22", resolved)
	}

	// 2. Create ops@10.0.0.1:2222 (same user+addr, different port) -> must NOT overwrite or conflict with Identities["ops@10.0.0.1"].
	m2 := &Model{
		repository: repo,
		formState: &nodeFormState{
			isEdit:     false,
			skipVerify: true,
			user:       "ops",
			address:    "10.0.0.1",
			port:       "2222",
			authType:   "password",
			sudoMode:   string(models.SudoModeAuto),
		},
	}
	completeConfigurationMutation(t, m2, m2.saveFormCmd())

	port2222Node, ok := repo.GetNode("ops@10.0.0.1:2222")
	if !ok {
		t.Fatalf("ops@10.0.0.1:2222 was not created (status=%q)", m2.status)
	}
	if port2222Node.IdentityRef == "ops@10.0.0.1" {
		t.Fatalf("ops@10.0.0.1:2222 reused existing IdentityRef %q", port2222Node.IdentityRef)
	}
	origIdent, ok := repo.Snapshot().Identities.Get("ops@10.0.0.1")
	if !ok || origIdent.AuthType != "key" || origIdent.KeyPath != "/keys/existing-ops" {
		t.Fatalf("original ops@10.0.0.1 identity was mutated: (%+v, %v)", origIdent, ok)
	}
}

func TestP7W15c_L4_15_H1_HybridMFAPreservesKeyPathAndPassphraseAndClearsOnPasswordSwitch(t *testing.T) {
	keyFile := writeW15cEncryptedTestKey(t, "hybrid-pass")
	for _, authType := range []string{"otp", "keyboard-interactive", "auto"} {
		t.Run(authType, func(t *testing.T) {
			assertW15cHybridMFALifecycle(t, authType, keyFile)
		})
	}
}

func writeW15cEncryptedTestKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(privKey, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "hybrid_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile
}

func newW15cHybridMFAFixture(t *testing.T, authType, keyFile string) (*Model, *config.Repository, *memoryCredentialStore, credential.Ref, credential.Ref) {
	t.Helper()
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{DefaultStore: "mem"},
	}
	loginRef := credential.Ref{StoreID: "mem", ItemID: "login-" + authType}
	passRef := credential.Ref{StoreID: "mem", ItemID: "pass-" + authType}
	totpRef := credential.Ref{StoreID: "mem", ItemID: "totp-" + authType}

	ident := models.Identity{
		User:             "mfa",
		AuthType:         authType,
		KeyPath:          keyFile,
		KeyFingerprint:   "SHA256:existing-fp",
		LoginPasswordRef: loginRef.Clone(),
		PassphraseRef:    passRef.Clone(),
	}
	if authType == "otp" {
		ident.OTP = &models.OTPConfig{TOTPSecretRef: totpRef.Clone()}
	}
	cfg.Hosts.Set("10.0.9.1:22", models.Host{Address: "10.0.9.1", Port: 22})
	cfg.Identities.Set("mfa-id", ident)
	cfg.Nodes.Set("mfa@10.0.9.1:22", models.Node{
		HostRef:     "10.0.9.1:22",
		IdentityRef: "mfa-id",
		SudoMode:    models.SudoModeAuto,
	})

	repo := newTestRepository(t, cfg)
	memStore := newMemoryCredentialStore()
	_ = memStore.Put(t.Context(), loginRef, credential.NewSecret([]byte("old-login")))
	_ = memStore.Put(t.Context(), passRef, credential.NewSecret([]byte("old-pass")))
	svc := newFormCredentialTestService(t, repo, memStore)
	return &Model{repository: repo, credentialService: svc}, repo, memStore, passRef, totpRef
}

func assertW15cHybridMFALifecycle(t *testing.T, authType, keyFile string) {
	t.Helper()
	const nodeID = "mfa@10.0.9.1:22"
	m, repo, memStore, passRef, totpRef := newW15cHybridMFAFixture(t, authType, keyFile)

	// 1. Edit tags + rotate login password -> KeyPath, PassphraseRef, KeyFingerprint, OTP preserved.
	state, err := m.newNodeFormState(nodeID)
	if err != nil {
		t.Fatalf("newNodeFormState: %v", err)
	}
	state.tags = "mfa-keep"
	state.password = "new-login-pw"
	state.passwordAction = "replace"
	m.formState = state
	completeConfigurationMutation(t, m, m.saveFormCmd())

	snap, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection after hybrid edit: %v", err)
	}
	assertW15cHybridKeyPreserved(t, snap.Identity, authType, keyFile, passRef, totpRef)

	// 2. Rotate passphrase on hybrid node -> KeyPath + PassphraseRef + KeyFingerprint updated while LoginPasswordRef preserved.
	rotatedLoginRef := snap.Identity.LoginPasswordRef.Clone()
	m.formState = nil
	state2, err := m.newNodeFormState(nodeID)
	if err != nil {
		t.Fatalf("newNodeFormState(passphrase replace): %v", err)
	}
	state2.passphrase = "hybrid-pass"
	state2.passphraseAction = "replace"
	m.formState = state2
	completeConfigurationMutation(t, m, m.saveFormCmd())

	snap2, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection after passphrase replace: %v", err)
	}
	assertW15cHybridPassphraseRotated(t, snap2.Identity, authType, keyFile, passRef, rotatedLoginRef)

	// 3. Switching explicitly to "password" clears KeyPath & deletes PassphraseRef while keeping LoginPasswordRef.
	oldRotatedPassRef := snap2.Identity.PassphraseRef.Clone()
	m.formState = nil
	state3, err := m.newNodeFormState(nodeID)
	if err != nil {
		t.Fatalf("newNodeFormState(switch to password): %v", err)
	}
	state3.authType = "password"
	m.formState = state3
	completeConfigurationMutation(t, m, m.saveFormCmd())

	snap3, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection after switch to password: %v", err)
	}
	assertW15cHybridSwitchedToPassword(t, snap3.Identity, memStore, rotatedLoginRef, oldRotatedPassRef)
}

func assertW15cHybridKeyPreserved(t *testing.T, ident models.Identity, authType, keyFile string, passRef, totpRef credential.Ref) {
	t.Helper()
	if ident.AuthType != authType || ident.KeyPath != keyFile {
		t.Fatalf("identity authType/keyPath = (%q, %q), want (%q, %q)", ident.AuthType, ident.KeyPath, authType, keyFile)
	}
	if ident.PassphraseRef == nil || *ident.PassphraseRef != passRef {
		t.Fatalf("PassphraseRef = %v, want preserved %v", ident.PassphraseRef, passRef)
	}
	if ident.KeyFingerprint != "SHA256:existing-fp" {
		t.Fatalf("KeyFingerprint = %q, want preserved", ident.KeyFingerprint)
	}
	if authType == "otp" && (ident.OTP == nil || ident.OTP.TOTPSecretRef == nil || *ident.OTP.TOTPSecretRef != totpRef) {
		t.Fatalf("OTP config was lost: %+v", ident.OTP)
	}
}

func assertW15cHybridPassphraseRotated(t *testing.T, ident models.Identity, authType, keyFile string, oldPassRef credential.Ref, wantLoginRef *credential.Ref) {
	t.Helper()
	if ident.AuthType != authType || ident.KeyPath != keyFile {
		t.Fatalf("hybrid passphrase replace lost authType/keyPath: %+v", ident)
	}
	if ident.PassphraseRef == nil || ident.PassphraseRef.ItemID == oldPassRef.ItemID {
		t.Fatalf("PassphraseRef was not rotated: %+v", ident.PassphraseRef)
	}
	if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != *wantLoginRef {
		t.Fatalf("LoginPasswordRef lost on passphrase replace: got %v want %v", ident.LoginPasswordRef, wantLoginRef)
	}
}

func assertW15cHybridSwitchedToPassword(t *testing.T, ident models.Identity, memStore *memoryCredentialStore, wantLoginRef, deletedPassRef *credential.Ref) {
	t.Helper()
	if ident.AuthType != "password" {
		t.Fatalf("AuthType after switch = %q, want password", ident.AuthType)
	}
	if ident.KeyPath != "" || ident.PassphraseRef != nil || ident.KeyFingerprint != "" {
		t.Fatalf("key material not cleared after switching to password: %+v", ident)
	}
	if ident.LoginPasswordRef == nil || *ident.LoginPasswordRef != *wantLoginRef {
		t.Fatalf("LoginPasswordRef lost when switching hybrid -> password: %+v", ident)
	}
	if _, err := memStore.Get(t.Context(), *deletedPassRef); err == nil {
		t.Fatalf("old passphrase secret was not deleted from store")
	}
}

func TestP7W15c_L4_15_H1_CreateVerifyPreviewIncludesHybridMFAKeyAndPassword(t *testing.T) {
	repo := newTestRepository(t, nil)
	var seenIdentity models.Identity
	m := &Model{
		repository: repo,
		ctx:        t.Context(),
		state:      viewForm,
		formState: &nodeFormState{
			isEdit:     false,
			skipVerify: false,
			user:       "mfa",
			address:    "192.0.2.88",
			port:       "22",
			authType:   "otp",
			password:   "mfa-pw",
			keyPath:    "%d/.ssh/id_mfa",
			passphrase: "mfa-key-pass",
			sudoMode:   string(models.SudoModeAuto),
		},
	}
	m.connectionConfig.verifyConnection = func(_ context.Context, preview *config.Provider, id string, _ adapter.CredentialResolver) error {
		_, _, ident, err := preview.Resolve(id)
		if err != nil {
			return err
		}
		seenIdentity = ident
		return nil
	}

	cmd := m.saveFormCmd()
	if cmd == nil {
		t.Fatal("saveFormCmd() returned nil")
	}
	_, next := m.Update(cmd())
	if next == nil {
		t.Fatalf("verification did not advance to save (status=%q)", m.status)
	}
	m.Update(next())

	if seenIdentity.AuthType != "otp" || seenIdentity.Password != "mfa-pw" || seenIdentity.KeyPath != "%d/.ssh/id_mfa" || seenIdentity.Passphrase != "mfa-key-pass" {
		t.Fatalf("preview checkIdentity lost hybrid MFA fields: %+v", seenIdentity)
	}
	snap, err := repo.ResolveConnection("mfa@192.0.2.88:22")
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if snap.Identity.AuthType != "otp" || snap.Identity.KeyPath != "%d/.ssh/id_mfa" {
		t.Fatalf("saved hybrid MFA node lost KeyPath: %+v", snap.Identity)
	}
}
