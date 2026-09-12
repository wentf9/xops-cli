package adapter

import (
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestRememberExistingReferencesDoesNotConfirm(t *testing.T) {
	for _, tc := range []struct {
		name, password, key, passphrase, privilege string
		wantCalls                                  int
	}{
		{name: "login", password: "stored"},
		{name: "passphrase", key: "key", passphrase: "stored"},
		{name: "privilege", privilege: "stored"},
		{name: "changed login", password: "changed", wantCalls: 1},
		{name: "changed key", key: "other-key", passphrase: "stored", wantCalls: 1},
		{name: "changed privilege", privilege: "changed", wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := &credential.Ref{StoreID: "memory", ItemID: "existing"}
			cfg := &config.Configuration{Nodes: concurrent.NewMap[string, models.Node](concurrent.HashString), Hosts: concurrent.NewMap[string, models.Host](concurrent.HashString), Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString)}
			cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "id", PrivilegePasswordRef: ref, SudoMode: models.SudoModeSu})
			cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
			cfg.Identities.Set("id", models.Identity{User: "ops", KeyPath: "key", AuthType: "auto", LoginPasswordRef: ref, PassphraseRef: ref})
			repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
			if err != nil {
				t.Fatal(err)
			}
			registry := credential.NewRegistry()
			if err := registry.Register("memory", &adapterCredentialStore{data: map[string]credential.Secret{"existing": credential.NewSecret([]byte("stored"))}}); err != nil {
				t.Fatal(err)
			}
			journal, err := credential.NewJournalStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			service, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			a := NewSSHAdapter(repo, WithCredentialSource(registry), WithCredentialService(service), WithRememberConfirmation(func(context.Context, string) (bool, error) { calls++; return false, nil }))
			snapshot, err := repo.ResolveConnection("node")
			if err != nil {
				t.Fatal(err)
			}
			if tc.privilege != "" {
				_, err = a.UpdateSudo(t.Context(), "node", string(snapshot.UpdateRef.SudoVersion[:]), ssh.SudoModeSu, tc.privilege)
			} else {
				_, err = a.UpdateAuth(t.Context(), "node", string(snapshot.UpdateRef.AuthVersion[:]), tc.password, tc.key, tc.passphrase)
			}
			if err != nil || calls != tc.wantCalls {
				t.Fatalf("confirmation calls=%d err=%v", calls, err)
			}
			// An unreadable reference must not be interpreted as a new secret.
			registry.Unregister("memory")
			_, err = a.UpdateAuth(t.Context(), "node", string(snapshot.UpdateRef.AuthVersion[:]), "stored", "", "")
			if !errors.Is(err, credential.ErrStoreNotFound) || calls != tc.wantCalls {
				t.Fatalf("reference error triggered confirmation: calls=%d err=%v", calls, err)
			}
		})
	}
}
