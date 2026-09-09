package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestConnectionAskOnlyForNewCredential(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SchemaVersion = 2
	cfg.Credential.RememberPrompted = "ask"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "stored-secret"); err != nil {
		t.Fatal(err)
	}
	// Each iteration builds a fresh adapter, as with separate CLI invocations.
	for _, tc := range []struct {
		value   string
		prompts int
	}{
		{"stored-secret", 0}, {"new-secret", 1}, {"new-secret", 0},
	} {
		_, repo, cfg, err := utils.GetConfigStore()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		o := NewSshOptions()
		o.interaction = newCLIInteractionHandlerWithStreams(io.NopCloser(strings.NewReader("y\n")), &out)
		opts, err := o.buildAdapterOptions("node", cfg, repo)
		if err != nil {
			t.Fatal(err)
		}
		if out.Len() != 0 {
			t.Fatal("asked before authentication")
		}
		before, err := repo.ResolveConnection("node")
		if err != nil {
			t.Fatal(err)
		}
		adp := adapter.NewSSHAdapter(repo, opts...)
		if _, err := adp.UpdateAuth(t.Context(), "node", string(before.UpdateRef.AuthVersion[:]), tc.value, "", ""); err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(out.String(), "Save credential"); got != tc.prompts {
			t.Fatalf("prompts=%d, want %d", got, tc.prompts)
		}
		after, err := repo.ResolveConnection("node")
		if err != nil {
			t.Fatal(err)
		}
		if tc.prompts == 0 && *before.Identity.LoginPasswordRef != *after.Identity.LoginPasswordRef {
			t.Fatal("unchanged credential was rotated")
		}
	}
}

func TestConnectionAskDetectsReplacedKeyAtSamePath(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SchemaVersion = 2
	cfg.Credential.RememberPrompted = "ask"
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	key := inventoryTestPrivateKey(t, true)
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--key", key, "--key-pass", "key-password"); err != nil {
		t.Fatal(err)
	}
	for _, replaced := range []bool{false, true} {
		if replaced {
			data, err := os.ReadFile(inventoryTestPrivateKey(t, true))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, data, 0600); err != nil {
				t.Fatal(err)
			}
			clear(data)
		}
		_, repo, cfg, err := utils.GetConfigStore()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		o := NewSshOptions()
		o.interaction = newCLIInteractionHandlerWithStreams(io.NopCloser(strings.NewReader("no\n")), &out)
		opts, err := o.buildAdapterOptions("node", cfg, repo)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := repo.ResolveConnection("node")
		if err != nil {
			t.Fatal(err)
		}
		a := adapter.NewSSHAdapter(repo, opts...)
		if _, err := a.UpdateAuth(t.Context(), "node", string(snapshot.UpdateRef.AuthVersion[:]), "", key, "key-password"); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "Save credential") != replaced {
			t.Fatalf("unexpected confirmation for replaced=%v", replaced)
		}
	}
}
