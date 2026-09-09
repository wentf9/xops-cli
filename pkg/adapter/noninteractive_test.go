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

type nonInteractiveProbe struct {
	t     *testing.T
	calls int
}

func (p *nonInteractiveProbe) Resolve(ctx context.Context, _ credential.Ref) (credential.Secret, error) {
	p.calls++
	if !credential.InteractionDisabled(ctx) {
		p.t.Error("backend received an interactive request")
	}
	return credential.Secret{}, credential.ErrCredentialStoreLocked
}

func TestNonInteractiveAdapterPropagatesPolicyForEverySecretKind(t *testing.T) {
	ref := &credential.Ref{StoreID: "store", ItemID: "item"}
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity", PrivilegePasswordRef: ref})
	cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "user", LoginPasswordRef: ref, PassphraseRef: ref})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatal(err)
	}
	probe := &nonInteractiveProbe{t: t}
	adp := NewNonInteractiveSSHAdapter(repo, WithCredentialSource(probe))
	for _, kind := range []ssh.SecretKind{ssh.SecretKindLoginPassword, ssh.SecretKindPrivateKeyPassphrase, ssh.SecretKindSuPassword} {
		_, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{NodeID: "node", Kind: kind})
		if !errors.Is(err, credential.ErrCredentialStoreLocked) {
			t.Fatalf("kind %v lost error classification: %v", kind, err)
		}
	}
	if probe.calls != 3 {
		t.Fatalf("resolver calls = %d", probe.calls)
	}
}
