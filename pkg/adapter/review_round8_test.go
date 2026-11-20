package adapter

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound8_P2_9_StatelessBaseHostAllowsAdapterReuseAndDetectsConcurrentMutation(t *testing.T) {
	t.Parallel()

	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	creds := round7StubCredentialResolver{secrets: map[string]string{"file/ov": "pw-ov"}}
	_, err = repo.CreateNodeContext(t.Context(), "app",
		models.Node{HostRef: "h1", IdentityRef: "id1"},
		models.Host{Address: "10.88.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "password", LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "ov"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	adp := NewSSHAdapter(repo,
		WithCredentialSource(creds),
		WithSessionAuthOverride("app", SessionAuth{HostName: "override.internal"}),
	)

	// Connection 1 captures BaseHost = 10.88.0.1.
	cfg1, err := adp.GetConfig("app")
	if err != nil {
		t.Fatalf("GetConfig #1: %v", err)
	}
	if cfg1.BaseHost != "10.88.0.1" {
		t.Fatalf("cfg1.BaseHost = %q, want 10.88.0.1", cfg1.BaseHost)
	}

	// Legitimately update saved node address on disk to 10.88.0.2.
	snapCfg := repo.Snapshot()
	ref := repo.View().NodeRefs["app"]
	n, _ := snapCfg.Nodes.Get("app")
	id, _ := snapCfg.Identities.Get(n.IdentityRef)
	if err := repo.ReplaceNodeAtRefContext(t.Context(), ref, "app", n, models.Host{Address: "10.88.0.2", Port: 22}, id); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}

	// Stale Connection 1 request (BaseHost=10.88.0.1) MUST still fail with ErrSnapshotMismatch.
	if _, err := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
		NodeID:       "app",
		Host:         cfg1.Address,
		BaseHost:     cfg1.BaseHost,
		Port:         cfg1.Port,
		User:         cfg1.User,
		Kind:         ssh.SecretKindLoginPassword,
		VersionToken: cfg1.AuthUpdateToken,
	}); !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("stale conn #1 ResolveSecret = %v, want ErrSnapshotMismatch", err)
	}

	// Fresh Connection 2 on the SAME reused adapter captures BaseHost=10.88.0.2 and succeeds!
	cfg2, err := adp.GetConfig("app")
	if err != nil {
		t.Fatalf("GetConfig #2: %v", err)
	}
	if cfg2.BaseHost != "10.88.0.2" {
		t.Fatalf("cfg2.BaseHost = %q, want 10.88.0.2", cfg2.BaseHost)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sec, rErr := adp.ResolveSecret(t.Context(), ssh.SecretRequest{
				NodeID:       "app",
				Host:         cfg2.Address,
				BaseHost:     cfg2.BaseHost,
				Port:         cfg2.Port,
				User:         cfg2.User,
				Kind:         ssh.SecretKindLoginPassword,
				VersionToken: cfg2.AuthUpdateToken,
			})
			if rErr != nil || string(sec) != "pw-ov" {
				t.Errorf("reused adapter ResolveSecret = (%q, %v), want (pw-ov, nil)", string(sec), rErr)
			}
		}()
	}
	wg.Wait()
}

func TestRound8_P2_10_P2_11_P3_4_LiteralControlValidationStrictIsolationAndCollisionPort(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.89.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("srv", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		SSHOptions:  ssh.MustOptions(ssh.OptionRemoteCommand, "echo hi", ssh.OptionForwardAgent, "yes", ssh.OptionControlMaster, "auto", ssh.OptionControlPath, "/tmp/c-%C"),
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	// P2-10: Invalid literal ControlPath (whitespace or control char) fails closed in ResolveControl & ResolveSSHOptions.
	adp := NewSSHAdapter(prov)
	for _, badLit := range []string{"   ", "/tmp/bad\rpath", "/tmp/bad\u2028path"} {
		var sc SessionControlOptions
		sc.SetLiteralPath(badLit)
		if _, err := adp.ResolveControl("srv", sc); err == nil {
			t.Fatalf("ResolveControl accepted invalid literal ControlPath %q", badLit)
		}
		if _, err := adp.ResolveSSHOptions("srv", sc); err == nil {
			t.Fatalf("ResolveSSHOptions accepted invalid literal ControlPath %q", badLit)
		}
	}
	// P2-10: Case-insensitive "NONE" disables multiplexing consistently.
	var scNone SessionControlOptions
	scNone.SetLiteralPath("NONE")
	ctrl, err := adp.ResolveControl("srv", scNone)
	if err != nil {
		t.Fatalf("ResolveControl(NONE): %v", err)
	}
	if ctrl == nil || ctrl.Path != "none" || ctrl.Master != ssh.ControlMasterNo || ctrl.LiteralPath {
		t.Fatalf("ResolveControl(NONE) = %+v, want disabled none", ctrl)
	}

	// P2-11: WithStrictIsolation strips Mux, Trust, Session, Forward, and disables LocalExec.
	isoAdp := NewSSHAdapter(prov, WithStrictIsolation())
	isoOpts, err := isoAdp.ResolveSSHOptions("srv", SessionControlOptions{})
	if err != nil {
		t.Fatalf("WithStrictIsolation ResolveSSHOptions: %v", err)
	}
	if isoOpts != nil && (isoOpts.Get(ssh.OptionRemoteCommand) != "" || isoOpts.Get(ssh.OptionForwardAgent) != "" || isoOpts.Get(ssh.OptionControlMaster) != "") {
		t.Fatalf("WithStrictIsolation leaked isolated options: %v", isoOpts.Map())
	}
	if isoCtrl, err := isoAdp.ResolveControl("srv", SessionControlOptions{}); err != nil || isoCtrl != nil {
		t.Fatalf("WithStrictIsolation ResolveControl = (%+v, %v), want (nil, nil)", isoCtrl, err)
	}

	// P3-4: parseFallbackNodeIDAddressPort strips collision suffix "-<digits>".
	host, port, ok := parseFallbackNodeIDAddressPort("ops@10.70.0.2:22-2")
	if !ok || host != "10.70.0.2" || port != 22 {
		t.Fatalf("parseFallbackNodeIDAddressPort(ops@10.70.0.2:22-2) = (%q, %d, %v), want (10.70.0.2, 22, true)", host, port, ok)
	}
	if _, _, ok := parseFallbackNodeIDAddressPort("ops@10.70.0.2:22-abc"); ok {
		t.Fatal("parseFallbackNodeIDAddressPort accepted non-digit suffix")
	}
}
