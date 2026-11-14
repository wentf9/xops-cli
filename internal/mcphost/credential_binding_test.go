package mcphost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func credentialBindingConfig() *config.Configuration {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	cfg.Credential = &config.CredentialConfig{
		Stores: map[string]config.StoreConfig{
			"fixture":         {Type: config.StoreTypeHelper, Command: "original-helper"},
			"totp-store":      {Type: config.StoreTypeHelper, Command: "totp-helper"},
			"challenge-store": {Type: config.StoreTypeHelper, Command: "challenge-helper"},
			"unused":          {Type: config.StoreTypeNone},
		},
	}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{
		User:             "fixture",
		AuthType:         "password",
		LoginPasswordRef: &credential.Ref{StoreID: "fixture", ItemID: "login-1"},
		PassphraseRef:    &credential.Ref{StoreID: "fixture", ItemID: "passphrase-1"},
		KeyFingerprint:   "fingerprint-1",
		OTP: &models.OTPConfig{
			TOTPSecretRef: &credential.Ref{StoreID: "totp-store", ItemID: "totp-1"},
		},
		KeyboardInteractive: &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "rule-1",
					PromptPattern: "^Verification code:",
					Source:        models.ChallengeSourceSecret,
					SecretRef:     &credential.Ref{StoreID: "challenge-store", ItemID: "answer-1"},
				},
			},
		},
	})
	cfg.Nodes.Set("node", models.Node{
		HostRef:              "host",
		IdentityRef:          "identity",
		SudoMode:             models.SudoModeSu,
		PrivilegePasswordRef: &credential.Ref{StoreID: "fixture", ItemID: "privilege-1"},
		SSHOptions:           ssh.MustOptions(ssh.OptionIdentityFile, "/keys/id_a", ssh.OptionIdentityFile, "/keys/id_b"),
	})
	return cfg
}

func credentialBindingHost(cfg *config.Configuration, frozen bool) *host {
	provider := config.NewProviderWithoutOpenSSH(cfg)
	var source config.ConfigProvider = provider
	if frozen {
		source = provider.Frozen()
	}
	return newHost(Config{Provider: source, HTTP: &mcpruntime.HTTPOptions{}})
}

func persistedAdmission(t *testing.T, ctx context.Context, host *host) ports.Admission {
	t.Helper()
	view, err := host.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "test", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(transfer.Authorization{Snapshot: view, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	var restored transfer.Authorization
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatal(err)
	}
	return ports.Admission{OperationID: "recovery", Phase: ports.Recovery, Snapshot: restored.Snapshot, Binding: restored.Binding}
}

func TestCLIRecoveryBindsCredentialDependenciesWithoutUpdateRef(t *testing.T) {
	for _, frozen := range []bool{false, true} {
		for _, edit := range []string{
			"login-ref", "passphrase-ref", "privilege-ref", "fingerprint",
			"password", "passphrase", "su-password", "identity-ref", "store",
			"jump-login-ref", "display-only", "unused-store",
			"totp-ref", "totp-command", "totp-store",
			"challenge-ref", "challenge-command", "challenge-rule-added", "challenge-store",
			"jump-totp-ref", "jump-challenge-ref",
			"identity-file-added", "identity-file-reordered", "jump-identity-file-added",
		} {
			t.Run(edit+map[bool]string{false: "-provider", true: "-frozen"}[frozen], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				cfg := credentialBindingConfig()
				jumpIdentity, _ := cfg.Identities.Get("identity")
				jumpIdentity.LoginPasswordRef = &credential.Ref{StoreID: "fixture", ItemID: "jump-login-1"}
				jumpIdentity.OTP = &models.OTPConfig{
					TOTPSecretRef: &credential.Ref{StoreID: "totp-store", ItemID: "jump-totp-1"},
				}
				jumpIdentity.KeyboardInteractive = &models.KeyboardInteractiveConfig{
					Rules: []models.ChallengeRule{
						{
							Name:          "jump-rule-1",
							PromptPattern: "^Jump code:",
							Source:        models.ChallengeSourceSecret,
							SecretRef:     &credential.Ref{StoreID: "challenge-store", ItemID: "jump-answer-1"},
						},
					},
				}
				cfg.Identities.Set("jump-identity", jumpIdentity)
				cfg.Nodes.Set("jump", models.Node{HostRef: "host", IdentityRef: "jump-identity"})
				node, _ := cfg.Nodes.Get("node")
				node.ProxyJump = "jump"
				cfg.Nodes.Set("node", node)
				original := credentialBindingHost(cfg, frozen)
				snapshot, err := original.provider().ResolveConnection("node")
				if err != nil || snapshot.UpdateRef != nil {
					t.Fatalf("fixture must exercise a read-only provider: %v", err)
				}
				admission := persistedAdmission(t, ctx, original)
				// Recreating an unchanged host must keep recovery possible.
				assertAdmission(t, ctx, credentialBindingHost(cfg, frozen), admission, false)
				editCredentialBinding(cfg, edit)
				stale := edit != "display-only" && edit != "unused-store"
				assertAdmission(t, ctx, credentialBindingHost(cfg, frozen), admission, stale)
			})
		}
	}
}

func assertAdmission(t *testing.T, ctx context.Context, host *host, admission ports.Admission, stale bool) {
	t.Helper()
	permit, err := host.Enter(ctx, admission)
	if permit != nil {
		if err := permit.Close(); err != nil {
			t.Error(err)
		}
	}
	if stale && !errors.Is(err, ports.ErrStaleBinding) || !stale && err != nil {
		t.Fatalf("stale=%v admission error=%v", stale, err)
	}
}

//nolint:gocyclo // Test helper managing mutation scenarios for connection dependency binding
func editCredentialBinding(cfg *config.Configuration, edit string) {
	node, _ := cfg.Nodes.Get("node")
	identity, _ := cfg.Identities.Get("identity")
	switch edit {
	case "login-ref":
		identity.LoginPasswordRef = &credential.Ref{StoreID: "fixture", ItemID: "login-2"}
	case "passphrase-ref":
		identity.PassphraseRef = &credential.Ref{StoreID: "fixture", ItemID: "passphrase-2"}
	case "privilege-ref":
		node.PrivilegePasswordRef = &credential.Ref{StoreID: "fixture", ItemID: "privilege-2"}
	case "fingerprint":
		identity.KeyFingerprint = "fingerprint-2"
	case "password":
		identity.Password = "changed-legacy-password"
	case "passphrase":
		identity.Passphrase = "changed-legacy-passphrase"
	case "su-password":
		node.SuPwd = "changed-legacy-su-password"
	case "identity-ref":
		cfg.Identities.Set("replacement", identity)
		node.IdentityRef = "replacement"
	case "store":
		store := cfg.Credential.Stores["fixture"]
		store.Command = "replacement-helper"
		cfg.Credential.Stores["fixture"] = store
	case "jump-login-ref":
		jump, _ := cfg.Identities.Get("jump-identity")
		jump.LoginPasswordRef = &credential.Ref{StoreID: "fixture", ItemID: "jump-login-2"}
		cfg.Identities.Set("jump-identity", jump)
	case "display-only":
		node.Alias = []string{"display-alias"}
		node.Tags = []string{"display-tag"}
	case "unused-store":
		cfg.Credential.Stores["unused"] = config.StoreConfig{Type: config.StoreTypeHelper, Command: "unused-helper"}
	case "totp-ref":
		identity.OTP.TOTPSecretRef = &credential.Ref{StoreID: "totp-store", ItemID: "totp-2"}
	case "totp-command":
		identity.OTP.Command = "/usr/bin/get-totp"
	case "totp-store":
		store := cfg.Credential.Stores["totp-store"]
		store.Command = "replacement-totp-helper"
		cfg.Credential.Stores["totp-store"] = store
	case "challenge-ref":
		identity.KeyboardInteractive.Rules[0].SecretRef = &credential.Ref{StoreID: "challenge-store", ItemID: "answer-2"}
	case "challenge-command":
		identity.KeyboardInteractive.Rules[0].Command = "/usr/bin/get-answer"
	case "challenge-rule-added":
		identity.KeyboardInteractive.Rules = append(identity.KeyboardInteractive.Rules, models.ChallengeRule{
			Name:          "rule-2",
			PromptPattern: "^Second factor:",
			Source:        models.ChallengeSourceOTP,
		})
	case "challenge-store":
		store := cfg.Credential.Stores["challenge-store"]
		store.Command = "replacement-challenge-helper"
		cfg.Credential.Stores["challenge-store"] = store
	case "jump-totp-ref":
		jump, _ := cfg.Identities.Get("jump-identity")
		jump.OTP = &models.OTPConfig{
			TOTPSecretRef: &credential.Ref{StoreID: "totp-store", ItemID: "jump-totp-2"},
		}
		cfg.Identities.Set("jump-identity", jump)
	case "jump-challenge-ref":
		jump, _ := cfg.Identities.Get("jump-identity")
		jump.KeyboardInteractive = &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "jump-rule-1",
					PromptPattern: "^Jump code:",
					Source:        models.ChallengeSourceSecret,
					SecretRef:     &credential.Ref{StoreID: "challenge-store", ItemID: "jump-answer-2"},
				},
			},
		}
		cfg.Identities.Set("jump-identity", jump)
	case "identity-file-added":
		node.SSHOptions = ssh.MustOptions(ssh.OptionIdentityFile, "/keys/id_a", ssh.OptionIdentityFile, "/keys/id_b", ssh.OptionIdentityFile, "/keys/id_c")
	case "identity-file-reordered":
		node.SSHOptions = ssh.MustOptions(ssh.OptionIdentityFile, "/keys/id_b", ssh.OptionIdentityFile, "/keys/id_a")
	case "jump-identity-file-added":
		jumpNode, _ := cfg.Nodes.Get("jump")
		jumpNode.SSHOptions = ssh.MustOptions(ssh.OptionIdentityFile, "/keys/jump_extra")
		cfg.Nodes.Set("jump", jumpNode)
	}
	cfg.Nodes.Set("node", node)
	cfg.Identities.Set("identity", identity)
}

func TestCLICredentialBindingDoesNotPersistSecretsOrInventWriteAuthority(t *testing.T) {
	cfg := credentialBindingConfig()
	identity, _ := cfg.Identities.Get("identity")
	identity.Password, identity.Passphrase = "private-login-fixture", "private-passphrase-fixture"
	cfg.Identities.Set("identity", identity)
	node, _ := cfg.Nodes.Get("node")
	node.SuPwd = "private-privilege-fixture"
	cfg.Nodes.Set("node", node)
	admission := persistedAdmission(t, t.Context(), credentialBindingHost(cfg, true))
	data, err := json.Marshal(admission.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{identity.Password, identity.Passphrase, node.SuPwd} {
		if strings.Contains(string(data), secret) {
			t.Fatal("credential material leaked into persistent snapshot")
		}
	}
	target := admission.Snapshot.Targets["node"]
	if target.Version == "" {
		t.Fatal("credential dependency version missing")
	}
	for _, hop := range target.Plan.Hops {
		if hop.AuthUpdateToken != "" || hop.SudoUpdateToken != "" {
			t.Fatal("read-only dependency hash became a credential-write token")
		}
	}
}

func TestCredentialVersionBindsHopKeyPathsAndOrder(t *testing.T) {
	cfg := credentialBindingConfig()
	provider := config.NewProviderWithoutOpenSSH(cfg)
	baseHop := ssh.ConnectionConfig{
		NodeID:   "node",
		Address:  "192.0.2.1",
		Port:     22,
		User:     "fixture",
		KeyPaths: []string{"/keys/first", "/keys/second"},
	}
	vBase, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}

	reorderedHop := baseHop.Clone()
	reorderedHop.KeyPaths = []string{"/keys/second", "/keys/first"}
	vReordered, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{reorderedHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vBase == vReordered {
		t.Fatal("reordering hop.KeyPaths must change credentialVersion")
	}

	extendedHop := baseHop.Clone()
	extendedHop.KeyPaths = []string{"/keys/first", "/keys/second", "/keys/third"}
	vExtended, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{extendedHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vBase == vExtended || vReordered == vExtended {
		t.Fatal("adding to hop.KeyPaths must change credentialVersion")
	}
}

func writeTestUserCertForBinding(t *testing.T, path string, serial uint64, validBefore uint64) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshUserPub, err := cryptoSSH.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}
	_ = caPub
	cert := &cryptoSSH.Certificate{
		Key:             sshUserPub,
		Serial:          serial,
		CertType:        cryptoSSH.UserCert,
		KeyId:           "mcp-binding-test",
		ValidPrincipals: []string{"fixture"},
		ValidAfter:      100,
		ValidBefore:     validBefore,
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, cryptoSSH.MarshalAuthorizedKey(cert), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialVersionBindsCertificatesAndIdentityAgent(t *testing.T) {
	cfg := credentialBindingConfig()
	provider := config.NewProviderWithoutOpenSSH(cfg)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("placeholder-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseHop := ssh.ConnectionConfig{
		NodeID:   "node",
		Address:  "192.0.2.1",
		Port:     22,
		User:     "fixture",
		KeyPaths: []string{keyPath},
	}

	vPlain, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Auto-discovered <key>-cert.pub sidecar creation and rotation must change credentialVersion.
	sidecarCert := keyPath + "-cert.pub"
	writeTestUserCertForBinding(t, sidecarCert, 1, 2000)
	vSidecar1, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vSidecar1 == vPlain {
		t.Fatal("creating sidecar user certificate must change credentialVersion")
	}

	writeTestUserCertForBinding(t, sidecarCert, 2, 4000)
	vSidecar2, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vSidecar2 == vSidecar1 {
		t.Fatal("rotating sidecar user certificate serial/validity must change credentialVersion")
	}

	// 2. Explicit CertificateFile and IdentityAgent options must bind and track in-place cert rotation.
	explicitCert := filepath.Join(dir, "explicit-cert.pub")
	writeTestUserCertForBinding(t, explicitCert, 10, 5000)
	hopWithOpts := baseHop.Clone()
	opts := &ssh.Options{}
	if err := opts.Set(ssh.OptionCertificateFile, explicitCert); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(ssh.OptionIdentityAgent, "/run/agent-a.sock"); err != nil {
		t.Fatal(err)
	}
	hopWithOpts.Options = opts

	vExplicit1, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hopWithOpts}})
	if err != nil {
		t.Fatal(err)
	}
	if vExplicit1 == vSidecar2 {
		t.Fatal("explicit CertificateFile + IdentityAgent must change credentialVersion")
	}

	writeTestUserCertForBinding(t, explicitCert, 11, 9000)
	vExplicit2, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hopWithOpts}})
	if err != nil {
		t.Fatal(err)
	}
	if vExplicit2 == vExplicit1 {
		t.Fatal("rotating explicit CertificateFile must change credentialVersion")
	}

	hopAgentChanged := hopWithOpts.Clone()
	if err := hopAgentChanged.Options.Set(ssh.OptionIdentityAgent, "none"); err != nil {
		t.Fatal(err)
	}
	vAgentNone, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hopAgentChanged}})
	if err != nil {
		t.Fatal(err)
	}
	if vAgentNone == vExplicit2 {
		t.Fatal("changing IdentityAgent must change credentialVersion")
	}
}

func TestCredentialVersionBindsDefaultIdentitySidecarCert(t *testing.T) {
	homeDir := t.TempDir()
	sshDir := filepath.Join(homeDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", homeDir)
	t.Setenv("USERPROFILE", homeDir)

	defaultKey := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(defaultKey, []byte("placeholder-default-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	defaultSidecar := defaultKey + "-cert.pub"

	cfg := credentialBindingConfig()
	node, _ := cfg.Nodes.Get("node")
	node.SSHOptions = nil
	cfg.Nodes.Set("node", node)
	provider := config.NewProviderWithoutOpenSSH(cfg)

	baseHop := ssh.ConnectionConfig{
		NodeID:  "node",
		Address: "192.0.2.1",
		Port:    22,
		User:    "fixture",
	}

	vNoCert, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}

	writeTestUserCertForBinding(t, defaultSidecar, 50, 5000)
	vCert1, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vCert1 == vNoCert {
		t.Fatal("creating ~/.ssh/id_ed25519-cert.pub must change credentialVersion")
	}

	writeTestUserCertForBinding(t, defaultSidecar, 51, 9000)
	vCert2, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{baseHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vCert2 == vCert1 {
		t.Fatal("rotating ~/.ssh/id_ed25519-cert.pub must change credentialVersion")
	}

	// With IdentitiesOnly=yes and an explicit key, default sidecar rotation is ignored;
	// with IdentitiesOnly=yes and NO explicit key, default sidecar rotation is still bound.
	explicitKey := filepath.Join(homeDir, "explicit_id")
	if err := os.WriteFile(explicitKey, []byte("explicit"), 0o600); err != nil {
		t.Fatal(err)
	}
	idOnlyHop := baseHop.Clone()
	idOnlyHop.KeyPaths = []string{explicitKey}
	idOnlyHop.Options = ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes")
	vExplicitIDOnly1, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{idOnlyHop}})
	if err != nil {
		t.Fatal(err)
	}
	writeTestUserCertForBinding(t, defaultSidecar, 52, 12000)
	vExplicitIDOnly2, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{idOnlyHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vExplicitIDOnly1 != vExplicitIDOnly2 {
		t.Fatal("IdentitiesOnly=yes with explicit key must ignore default sidecar cert rotation")
	}

	noExplicitIDOnlyHop := baseHop.Clone()
	noExplicitIDOnlyHop.Options = ssh.MustOptions(ssh.OptionIdentitiesOnly, "yes")
	vNoExplicit1, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{noExplicitIDOnlyHop}})
	if err != nil {
		t.Fatal(err)
	}
	writeTestUserCertForBinding(t, defaultSidecar, 53, 15000)
	vNoExplicit2, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{noExplicitIDOnlyHop}})
	if err != nil {
		t.Fatal(err)
	}
	if vNoExplicit1 == vNoExplicit2 {
		t.Fatal("IdentitiesOnly=yes without explicit key must bind default sidecar cert rotation")
	}
}

func TestCredentialVersionExpandsPercentNWithoutOpenSSHPrefixAndCapsOversizedCert(t *testing.T) {
	dir := t.TempDir()
	openSSHText := "Host web\n" +
		" HostName 192.0.2.10\n" +
		" Port 22\n" +
		" User fixture\n" +
		" CertificateFile " + filepath.ToSlash(filepath.Join(dir, "%n-cert.pub")) + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(openSSHText))
	if err != nil {
		t.Fatal(err)
	}
	cfg := credentialBindingConfig()
	provider := config.NewProviderWithOpenSSHParser(cfg, parser)

	// Pass NodeID="openssh:web" with empty OriginalHost to verify OpenSSHOriginalHost stripping on %n.
	hop := ssh.ConnectionConfig{
		NodeID:  "openssh:web",
		Address: "192.0.2.10",
		Port:    22,
		User:    "fixture",
		Options: ssh.MustOptions(ssh.OptionCertificateFile, filepath.Join(dir, "%n-cert.pub")),
	}
	vMissing, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hop}})
	if err != nil {
		t.Fatal(err)
	}

	// Write cert at <dir>/web-cert.pub (NOT <dir>/openssh:web-cert.pub!).
	webCert := filepath.Join(dir, "web-cert.pub")
	writeTestUserCertForBinding(t, webCert, 77, 8000)
	vPresent, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hop}})
	if err != nil {
		t.Fatal(err)
	}
	if vPresent == vMissing {
		t.Fatal("CertificateFile %n expansion on openssh:web must bind <dir>/web-cert.pub")
	}

	writeTestUserCertForBinding(t, webCert, 78, 9000)
	vRotated, err := credentialVersion(provider, ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{hop}})
	if err != nil {
		t.Fatal(err)
	}
	if vRotated == vPresent {
		t.Fatal("rotating <dir>/web-cert.pub must change credentialVersion")
	}

	// Oversized regular file (> 256 KiB) is bounded via LimitReader without failing or reading unboundedly.
	hugePath := filepath.Join(dir, "huge-cert.pub")
	hugePayload := make([]byte, maxMCPCertBindingBytes+64*1024)
	for i := range hugePayload {
		hugePayload[i] = byte('a' + (i % 26))
	}
	if err := os.WriteFile(hugePath, hugePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	binding, ok := inspectCertificateBinding(hugePath, true)
	if !ok || !binding.Truncated || binding.RawSHA256 == "" || binding.NonRegular || binding.Missing {
		t.Fatalf("unexpected oversized cert binding: %+v ok=%v", binding, ok)
	}
}
