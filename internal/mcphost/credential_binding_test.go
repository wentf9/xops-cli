package mcphost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func credentialBindingConfig() *config.Configuration {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	cfg.Credential = &config.CredentialConfig{Stores: map[string]config.StoreConfig{"fixture": {Type: config.StoreTypeHelper, Command: "original-helper"}, "unused": {Type: config.StoreTypeNone}}}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", LoginPasswordRef: &credential.Ref{StoreID: "fixture", ItemID: "login-1"}, PassphraseRef: &credential.Ref{StoreID: "fixture", ItemID: "passphrase-1"}, KeyFingerprint: "fingerprint-1"})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity", SudoMode: models.SudoModeSu, PrivilegePasswordRef: &credential.Ref{StoreID: "fixture", ItemID: "privilege-1"}})
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
		for _, edit := range []string{"login-ref", "passphrase-ref", "privilege-ref", "fingerprint", "password", "passphrase", "su-password", "identity-ref", "store", "jump-login-ref", "display-only", "unused-store"} {
			t.Run(edit+map[bool]string{false: "-provider", true: "-frozen"}[frozen], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				cfg := credentialBindingConfig()
				jumpIdentity, _ := cfg.Identities.Get("identity")
				jumpIdentity.LoginPasswordRef = &credential.Ref{StoreID: "fixture", ItemID: "jump-login-1"}
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
