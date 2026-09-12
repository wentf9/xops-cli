package cmd

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestV2PassphraseCLIIncludesKeyFingerprint(t *testing.T) {
	for _, name := range []string{"identity add", "identity edit", "identity credential set", "host edit", "recorder"} {
		t.Run(name, func(t *testing.T) {
			store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
			cfg, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.SchemaVersion = 2
			path := inventoryTestPrivateKey(t, true)
			link := filepath.Join(filepath.Dir(path), "linked-key")
			if err := os.Symlink(path, link); err == nil {
				path = link
			} else if runtime.GOOS != "windows" {
				t.Fatal(err)
			} else {
				t.Logf("symlinks unavailable; testing regular key: %v", err)
			}

			identity, _ := cfg.Identities.Get("admin")
			identity.KeyPath = path
			cfg.Identities.Set("admin", identity)
			if err := store.Save(cfg); err != nil {
				t.Fatal(err)
			}
			var cmd *cobra.Command
			var args []string
			targetIdentity := "admin"
			switch name {
			case "identity add":
				cmd = NewCmdIdentity()
				args = []string{"add", "--name", "new", "--user", "user", "--key", path, "--key-pass", "key-password"}
				targetIdentity = "new"
			case "identity edit":
				cmd = NewCmdIdentity()
				args = []string{"edit", "admin", "--key", path, "--key-pass", "key-password"}
			case "identity credential set":
				cmd = NewCmdIdentity()
				cmd.SetIn(strings.NewReader("key-password\n"))
				args = []string{"credential", "set", "admin", "--kind", "passphrase", "--password-stdin"}
			case "host edit":
				cmd = hostcmd.NewCmdInventoryEdit()
				args = []string{"node", "--key", path, "--key-pass", "key-password"}
			case "recorder":
				recordV2Passphrase(t, cfg, store, path)
			}
			if cmd != nil {
				if err := executePhase6(t, cmd, args...); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err = store.Load()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := cfg.Identities.Get(targetIdentity)
			fingerprint, err := config.PrivateKeyFingerprint(path, []byte("key-password"))
			if err != nil {
				t.Fatal(err)
			}
			if id.PassphraseRef == nil || id.Passphrase != "" || id.KeyFingerprint != fingerprint {
				t.Fatal("v2 reference was not committed with its key fingerprint")
			}
			if _, err := cfg.Snapshot().ToV2(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func recordV2Passphrase(t *testing.T, cfg *config.Configuration, store config.Store, path string) {
	t.Helper()
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	service, err := utils.GetCredentialService(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	adp := adapter.NewSSHAdapter(repo, adapter.WithCredentialService(service))
	snapshot, err := repo.ResolveConnection("node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adp.UpdateAuth(t.Context(), "node", string(snapshot.UpdateRef.AuthVersion[:]), "", path, "key-password"); err != nil {
		t.Fatal(err)
	}
}
