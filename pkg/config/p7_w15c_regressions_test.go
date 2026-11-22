package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W15c_L4_15_M1_ImportOpenSSHHostsEnforcesOpenSSHJumpCyclesAndDuplicateHops(t *testing.T) {
	t.Parallel()

	t.Run("wildcard_stanza_cycle_rejected_fail_closed", func(t *testing.T) {
		t.Parallel()
		const sshCfg = `
Host *.jump.corp
    HostName 10.242.0.200
    User ops
    ProxyJump app

Host app
    HostName 10.242.0.10
    User ops
    ProxyJump gw.jump.corp
`
		repo, store := newW14cOpenSSHRepoFixture(t, sshCfg)
		hosts, err := ParseOpenSSHHosts(strings.NewReader(sshCfg), "ops")
		if err != nil {
			t.Fatalf("ParseOpenSSHHosts: %v", err)
		}
		var cycleErr *ssh.ProxyCycleError
		if _, err := repo.ImportOpenSSHHostsContext(t.Context(), hosts); !errors.As(err, &cycleErr) {
			t.Fatalf("ImportOpenSSHHostsContext(wildcard cycle) = %v, want *ssh.ProxyCycleError", err)
		}
		disk, err := store.Load()
		if err != nil {
			t.Fatalf("store.Load: %v", err)
		}
		if _, exists := disk.Nodes.Get("app"); exists {
			t.Fatal("cyclic imported node app leaked to disk")
		}
	})

	t.Run("reverse_forward_ref_cycle_and_alias_duplicate_hop_rejected", func(t *testing.T) {
		t.Parallel()
		const sshCfg = `
Host ssh-saved-app
    HostName 10.242.1.1
    Port 22
    User ops

Host ssh-gw-99
    HostName 10.242.1.99
    Port 22
    User ops
`
		repo, _ := newW14cOpenSSHRepoFixture(t, sshCfg)
		if _, err := repo.CreateNodeContext(t.Context(), "saved-app",
			models.Node{HostRef: "h-saved", IdentityRef: "id-ops", ProxyJump: "future-jump"},
			models.Host{Address: "10.242.1.1", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(saved-app): %v", err)
		}

		var cycleErr *ssh.ProxyCycleError
		if _, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
			Name:     "future-jump",
			Host:     models.Host{Address: "10.242.1.50", Port: 22},
			Identity: models.Identity{User: "ops", AuthType: "auto"},
			Node:     models.Node{Alias: []string{"future-jump"}, ProxyJump: "openssh:ssh-saved-app", SudoMode: models.SudoModeAuto},
		}}); !errors.As(err, &cycleErr) {
			t.Fatalf("ImportOpenSSHHostsContext(reverse cycle) = %v, want *ssh.ProxyCycleError", err)
		}
		if _, exists := repo.GetNode("future-jump"); exists {
			t.Fatal("cyclic imported node future-jump leaked into repository")
		}

		if _, err := repo.CreateNodeContext(t.Context(), "dup-watcher",
			models.Node{HostRef: "h-watch", IdentityRef: "id-ops", ProxyJump: "dup-gw.corp,openssh:ssh-gw-99"},
			models.Host{Address: "10.242.1.2", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(dup-watcher): %v", err)
		}
		if _, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
			Name:     "imported-gw",
			Host:     models.Host{Address: "10.242.1.99", Port: 22},
			Identity: models.Identity{User: "ops", AuthType: "auto"},
			Node:     models.Node{Alias: []string{"dup-gw.corp"}, SudoMode: models.SudoModeAuto},
		}}); !errors.As(err, &cycleErr) {
			t.Fatalf("ImportOpenSSHHostsContext(duplicate hop via alias) = %v, want *ssh.ProxyCycleError", err)
		}
	})
}

func TestP7W15c_L4_15_M2_ConfigurationReferencesCredentialStoreChecksAllFiveRefLocations(t *testing.T) {
	t.Parallel()

	if !ConfigurationReferencesCredentialStore(nil, "file") {
		t.Fatal("nil config must fail closed as referenced")
	}
	empty := cloneConfiguration(nil)
	if ConfigurationReferencesCredentialStore(empty, "file") {
		t.Fatal("empty config unexpectedly reported referenced store")
	}

	cases := []struct {
		name  string
		setup func(*Configuration)
	}{
		{
			name: "login_password_ref",
			setup: func(cfg *Configuration) {
				cfg.Identities.Set("id1", models.Identity{LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "i1"}})
			},
		},
		{
			name: "passphrase_ref",
			setup: func(cfg *Configuration) {
				cfg.Identities.Set("id1", models.Identity{PassphraseRef: &credential.Ref{StoreID: "file", ItemID: "i2"}})
			},
		},
		{
			name: "otp_totp_secret_ref",
			setup: func(cfg *Configuration) {
				cfg.Identities.Set("id1", models.Identity{
					AuthType: "otp",
					OTP:      &models.OTPConfig{TOTPSecretRef: &credential.Ref{StoreID: "file", ItemID: "i3"}},
				})
			},
		},
		{
			name: "keyboard_interactive_rule_secret_ref",
			setup: func(cfg *Configuration) {
				cfg.Identities.Set("id1", models.Identity{
					AuthType: "keyboard-interactive",
					KeyboardInteractive: &models.KeyboardInteractiveConfig{
						Rules: []models.ChallengeRule{
							{Name: "pin", PromptPattern: "PIN:", Source: models.ChallengeSourceSecret, SecretRef: &credential.Ref{StoreID: "file", ItemID: "i4"}},
						},
					},
				})
			},
		},
		{
			name: "node_privilege_password_ref",
			setup: func(cfg *Configuration) {
				cfg.Nodes.Set("n1", models.Node{PrivilegePasswordRef: &credential.Ref{StoreID: "file", ItemID: "i5"}})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := cloneConfiguration(nil)
			tc.setup(cfg)
			if !ConfigurationReferencesCredentialStore(cfg, "file") {
				t.Fatalf("ConfigurationReferencesCredentialStore(%s, file) = false, want true", tc.name)
			}
			if ConfigurationReferencesCredentialStore(cfg, "other") {
				t.Fatalf("ConfigurationReferencesCredentialStore(%s, other) = true, want false", tc.name)
			}
		})
	}
}

func TestP7W15c_L4_15_L1_ConfirmPendingEntryValidatesOpenSSHOriginCycleBeforePublishing(t *testing.T) {
	t.Parallel()

	// ssh-origin-app resolves to 10.243.0.10, while another alias/target points to
	// a different host IP but jumps back via openssh:ssh-origin-app. When a pending
	// create/update carries OpenSSHAlias="ssh-origin-app" and a concurrent edit makes
	// its jump hop route back to openssh:ssh-origin-app, confirmPendingEntry must
	// validate against merged OpenSSHOrigin before committing or publishing origin.
	const sshCfg = `
Host ssh-origin-app
    HostName 10.243.0.10
    Port 22
    User ops

Host ssh-origin-alias-only
    HostName 10.243.0.99
    Port 22
    User ops
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	baseCfg := cloneConfiguration(nil)
	baseCfg.SchemaVersion = 2
	baseCfg.Credential = &CredentialConfig{
		DefaultStore: "none",
		Stores:       map[string]StoreConfig{"none": {Type: StoreTypeNone}},
	}
	if err := store.Save(baseCfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(baseCfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	if _, err := repo.CreateNodeContext(t.Context(), "mid-bastion",
		models.Node{HostRef: "h-mid", IdentityRef: "id-ops"},
		models.Host{Address: "10.243.0.50", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(mid-bastion): %v", err)
	}

	t.Run("pending_create_origin_cycle_rejected", func(t *testing.T) {
		var cycleErr *ssh.ProxyCycleError
		err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{
				Selector:     "ops@10.243.0.10:22",
				ProxyJump:    "mid-bastion",
				HasProxyJump: true,
			},
		}, func(lease PendingLease) error {
			if lease.NodeID() != "ops@10.243.0.10:22" {
				t.Fatalf("unexpected pending create NodeID = %q", lease.NodeID())
			}
			// Simulate an origin-matched alias cycle introduced concurrently before Confirm:
			// mid-bastion now jumps to openssh:ssh-origin-alias-only, and pending origin
			// is updated to ssh-origin-alias-only so endpoint alone (10.243.0.10 vs 10.243.0.99)
			// differs and ONLY OpenSSHOrigin catches the cycle.
			repo.SetNodeOpenSSHOrigin(lease.NodeID(), OpenSSHOrigin{
				Alias:         "ssh-origin-alias-only",
				CanonicalHost: "ssh-origin-alias-only",
			})
			view := repo.View()
			midNode, _ := view.Configuration.Nodes.Get("mid-bastion")
			midHost, _ := view.Configuration.Hosts.Get(midNode.HostRef)
			midIdent, _ := view.Configuration.Identities.Get(midNode.IdentityRef)
			midNode.ProxyJump = "openssh:ssh-origin-alias-only"
			if editErr := repo.ReplaceNodeAtRefContext(t.Context(), view.NodeRefs["mid-bastion"], "mid-bastion", midNode, midHost, midIdent); editErr != nil {
				t.Fatalf("concurrent ReplaceNodeAtRefContext(mid-bastion): %v", editErr)
			}
			return lease.Confirm(t.Context())
		})
		if !errors.As(err, &cycleErr) {
			t.Fatalf("lease.Confirm(create) with OpenSSHOrigin cycle = %v, want *ssh.ProxyCycleError", err)
		}
		if _, exists := repo.GetNode("ops@10.243.0.10:22"); exists {
			t.Fatal("cyclic pending node leaked into repository after failed confirm")
		}
		if got := repo.NodeOpenSSHAlias("ops@10.243.0.10:22"); got != "" {
			t.Fatalf("failed confirm published OpenSSHAlias %q", got)
		}
	})

	t.Run("pending_update_origin_cycle_rejected", func(t *testing.T) {
		if _, err := repo.CreateNodeContext(t.Context(), "saved-origin-app",
			models.Node{HostRef: "h-saved-origin", IdentityRef: "id-ops"},
			models.Host{Address: "10.243.0.11", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		); err != nil {
			t.Fatalf("CreateNodeContext(saved-origin-app): %v", err)
		}
		// Reset mid-bastion jump before staging pending update.
		view := repo.View()
		midNode, _ := view.Configuration.Nodes.Get("mid-bastion")
		midHost, _ := view.Configuration.Hosts.Get(midNode.HostRef)
		midIdent, _ := view.Configuration.Identities.Get(midNode.IdentityRef)
		midNode.ProxyJump = ""
		if err := repo.ReplaceNodeAtRefContext(t.Context(), view.NodeRefs["mid-bastion"], "mid-bastion", midNode, midHost, midIdent); err != nil {
			t.Fatalf("reset mid-bastion ProxyJump: %v", err)
		}

		var cycleErr *ssh.ProxyCycleError
		err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "saved-origin-app"},
			ExistingUpdate: PendingNodeUpdate{
				Enabled:  true,
				JumpHost: "mid-bastion",
			},
		}, func(lease PendingLease) error {
			repo.SetNodeOpenSSHOrigin(lease.NodeID(), OpenSSHOrigin{
				Alias:         "ssh-origin-alias-only",
				CanonicalHost: "ssh-origin-alias-only",
			})
			v := repo.View()
			mNode, _ := v.Configuration.Nodes.Get("mid-bastion")
			mHost, _ := v.Configuration.Hosts.Get(mNode.HostRef)
			mIdent, _ := v.Configuration.Identities.Get(mNode.IdentityRef)
			mNode.ProxyJump = "openssh:ssh-origin-alias-only"
			if editErr := repo.ReplaceNodeAtRefContext(t.Context(), v.NodeRefs["mid-bastion"], "mid-bastion", mNode, mHost, mIdent); editErr != nil {
				t.Fatalf("concurrent ReplaceNodeAtRefContext(mid-bastion): %v", editErr)
			}
			return lease.Confirm(t.Context())
		})
		if !errors.As(err, &cycleErr) {
			t.Fatalf("lease.Confirm(update) with OpenSSHOrigin cycle = %v, want *ssh.ProxyCycleError", err)
		}
		if saved, _ := repo.GetNode("saved-origin-app"); saved.ProxyJump != "" {
			t.Fatalf("cyclic pending update leaked ProxyJump %q", saved.ProxyJump)
		}
		if got := repo.NodeOpenSSHAlias("saved-origin-app"); got != "" {
			t.Fatalf("failed pending update published OpenSSHAlias %q", got)
		}
	})
}
