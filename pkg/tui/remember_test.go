package tui

import (
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/adapter"
)

func TestTUIRememberPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, policy                string
		confirm, answer, wantStored bool
		wantCalls                   int
		confirmErr                  error
	}{
		{name: "never", policy: "never", confirm: true},
		{name: "always", policy: "always", wantStored: true},
		{name: "ask accepted", policy: "ask", confirm: true, answer: true, wantStored: true, wantCalls: 1},
		{name: "ask declined", policy: "ask", confirm: true, wantCalls: 1},
		{name: "ask unavailable", policy: "ask"},
		{name: "ask canceled", policy: "ask", confirm: true, wantCalls: 1, confirmErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newFormCredentialTestConfiguration("")
			cfg.Credential.RememberPrompted = tc.policy
			repo := newTestRepository(t, cfg)
			service := newFormCredentialTestService(t, repo, newMemoryCredentialStore())
			mc := modelConfig{credentialService: service}
			calls := 0
			if tc.confirm {
				mc.rememberConfirmation = func(context.Context, string) (bool, error) { calls++; return tc.answer, tc.confirmErr }
			}
			adp := adapter.NewSSHAdapter(repo, credentialAdapterOptions(repo, mc)...)
			snapshot, err := repo.ResolveConnection(formCredentialTestNodeID)
			if err != nil {
				t.Fatal(err)
			}
			_, err = adp.UpdateAuth(t.Context(), formCredentialTestNodeID, string(snapshot.UpdateRef.AuthVersion[:]), "fixture-secret", "", "")
			if !errors.Is(err, tc.confirmErr) {
				t.Fatalf("record authentication = %v", err)
			}
			got, err := repo.ResolveConnection(formCredentialTestNodeID)
			if err != nil {
				t.Fatal(err)
			}
			if (got.Identity.LoginPasswordRef != nil) != tc.wantStored || got.Identity.Password != "" || calls != tc.wantCalls {
				t.Fatalf("stored=%v, confirmation calls=%d", got.Identity.LoginPasswordRef != nil, calls)
			}
		})
	}
}
