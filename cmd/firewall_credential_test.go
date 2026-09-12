package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/firewall"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type firewallProbeDialer struct{ err error }

func (d firewallProbeDialer) Dial(string, string) (net.Conn, error) { return nil, d.err }
func (d firewallProbeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func setupFirewallCredential(t *testing.T) {
	t.Helper()
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0], NonInteractive: true})
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SchemaVersion = 2
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := executePhase6(t, NewCmdIdentity(), "edit", "admin", "--password", "firewall-secret"); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallConnectorResolvesStoredPassword(t *testing.T) {
	setupFirewallCredential(t)
	_, repo, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"node", "node,other"} {
		o := NewFirewallOptions()
		o.Host = host
		reachedDial := errors.New("credential resolved; stop before network I/O")
		connector, err := o.credentialConnector(repo, cfg, ssh.WithDialer(firewallProbeDialer{err: reachedDial}))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := connector.CloseAll(); err != nil {
				t.Errorf("close connector: %v", err)
			}
		})
		if _, err := connector.Connect(t.Context(), "node"); !errors.Is(err, reachedDial) {
			t.Fatalf("firewall failed before resolving stored credential: %v", err)
		}
	}
}

func TestRemoteFirewallPropagatesStoreLocked(t *testing.T) {
	setupFirewallCredential(t)
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	o := NewFirewallOptions()
	o.Host = "node"
	err := o.runRemoteFirewalls(t.Context(), func(firewall.Firewall) (string, error) {
		t.Error("firewall action ran after credential failure")
		return "", nil
	})
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("firewall did not propagate backend error: %v", err)
	}
}

func TestFirewallBatchRequiresNonInteractiveStore(t *testing.T) {
	setupFirewallCredential(t)
	_, repo, cfg, err := utils.GetConfigStore()
	if err != nil {
		t.Fatal(err)
	}
	store := cfg.Credential.Stores["test"]
	store.NonInteractive = false
	cfg.Credential.Stores["test"] = store
	o := NewFirewallOptions()
	o.Host = "node,other"
	connector, err := o.credentialConnector(repo, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close connector: %v", err)
		}
	}()
	if _, err := connector.Connect(t.Context(), "node"); !errors.Is(err, credential.ErrCredentialStoreUnavailable) {
		t.Fatalf("batch accepted an interactive-only backend: %v", err)
	}
}
