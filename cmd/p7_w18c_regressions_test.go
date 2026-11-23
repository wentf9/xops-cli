package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func setupW18cCLISavedCanonicalFixture(t *testing.T, setRuntimeOrigin bool) (*config.Provider, *config.Repository) {
	t.Helper()
	sshCfg := strings.Join([]string{
		"Host app",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains example.com",
		"",
		"Host app.example.com",
		"  HostName 192.0.2.99",
		"  Port 9999",
		"  ProxyCommand /bin/evil-proxy",
		"  SendEnv LEAK_ENV",
		"  ConnectTimeout 77",
		"  ControlMaster auto",
		"  ControlPath /tmp/leaked-cli-w18c-%C",
		"",
		"Host app-real-endpoint",
		"  HostName 10.10.0.1",
		"  Port 2222",
		"  ProxyCommand /bin/evil-real-ep",
		"  SendEnv LEAK_REAL_EP",
		"  ConnectTimeout 41",
		"  ControlMaster auto",
		"  ControlPath /tmp/scoped-cli-w18c-%C",
	}, "\n") + "\n"

	makePair := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-app", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-app", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("app.example.com", models.Node{
			HostRef:     "h-app",
			IdentityRef: "id-app",
			Alias:       []string{"app-saved"},
		})
		return cfg, parser
	}

	roCfg, roParser := makePair()
	roProv := config.NewProviderWithOpenSSHParser(roCfg, roParser)
	repoCfg, repoParser := makePair()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "xops_config.yaml"), filepath.Join(t.TempDir(), "xops.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(repoCfg, store, repoParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	if setRuntimeOrigin {
		origin := config.OpenSSHOrigin{Alias: "app", CanonicalHost: "app.example.com"}
		roProv.SetNodeOpenSSHOrigin("app.example.com", origin)
		repo.SetNodeOpenSSHOrigin("app.example.com", origin)
	}
	return roProv, repo
}

func assertW18cCLIOptionsClean(t *testing.T, opts *ssh.Options, desc string) {
	t.Helper()
	if opts == nil {
		return
	}
	if got := opts.ActiveProxyCommand(); got != "" {
		t.Fatalf("%s: leaked Tier-4 ProxyCommand=%q", desc, got)
	}
	if envVal := opts.Get(ssh.OptionSendEnv); envVal != "" {
		t.Fatalf("%s: leaked Tier-4 SendEnv=%q", desc, envVal)
	}
	if got := opts.Get(ssh.OptionConnectTimeout); got == "77" {
		t.Fatalf("%s: leaked mismatched Host app.example.com ConnectTimeout=77", desc)
	}
	if got := opts.ControlPath(); strings.Contains(got, "leaked-cli-w18c") {
		t.Fatalf("%s: leaked mismatched Host app.example.com ControlPath=%q", desc, got)
	}
}

func TestP7W18c_L3_18_H1_CLIDialAndControlCheckProxySavedNodeDerivedIsolation(t *testing.T) {
	t.Parallel()
	t.Run("dial_canonicalized_saved_node_with_l_and_p_stays_adhoc_pending_and_filtered", assertW18cCLIDialSavedCanonical)
	t.Run("control_check_and_proxy_canonicalized_and_runtime_origin_saved_node_overrides", assertW18cCLIControlSavedOverrides)
}

func assertW18cCLIDialSavedCanonical(t *testing.T) {
	t.Parallel()
	_, repo := setupW18cCLISavedCanonicalFixture(t, false)
	dialOpts := NewSshOptions()
	dialOpts.User = "altuser"
	dialOpts.Host = "app.example.com"
	dialOpts.originalHost = "app"
	dialOpts.canonicalized = true
	dialOpts.Target = config.ConnectionTarget{
		Selector:     "app.example.com",
		OriginalHost: "app",
		User:         "altuser",
		HasUser:      true,
	}
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{Target: dialOpts.Target}, func(lease config.PendingLease) error {
		snap, err := repo.ResolveConnection(lease.NodeID())
		if err != nil {
			t.Fatalf("ResolveConnection: %v", err)
		}
		if snap.Provenance != config.ProvenanceAdHocPending {
			t.Fatalf("dial pending Provenance = %s, want adhoc_pending", snap.Provenance)
		}
		adpOpts, err := dialOpts.buildAdapterOptions(lease.NodeID(), repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("buildAdapterOptions: %v", err)
		}
		pol, err := adapter.NewSSHAdapter(repo, adpOpts...).Resolve(t.Context(), adapter.ResolveRequest{
			NodeID:       lease.NodeID(),
			ResolveProxy: true,
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		assertW18cCLIOptionsClean(t, pol.Options(), "CLI dial -l altuser canonicalized saved node")
		if pol.Options() == nil || pol.Options().Get(ssh.OptionConnectTimeout) != "41" {
			t.Fatalf("expected endpoint-matched safe ConnectTimeout=41, got %v", pol.Options())
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func assertW18cCLIControlSavedOverrides(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		setRuntimeOrigin bool
		configure        func(*SshOptions)
		wantLookup       string
		wantScopedSock   bool
	}{
		{
			name: "canonicalized_user_override",
			configure: func(o *SshOptions) {
				o.User = "altuser"
				o.Host = "app.example.com"
				o.originalHost = "app"
				o.canonicalized = true
				o.args = []string{"app.example.com"}
				o.Target = config.ConnectionTarget{
					Selector:     "app.example.com",
					OriginalHost: "app",
					User:         "altuser",
					HasUser:      true,
				}
				o.parsedArgs = true
			},
			wantLookup:     "altuser@10.10.0.1:2222",
			wantScopedSock: true,
		},
		{
			name: "canonicalized_port_2223_override",
			configure: func(o *SshOptions) {
				o.Port = 2223
				o.Host = "app.example.com"
				o.originalHost = "app"
				o.canonicalized = true
				o.args = []string{"app.example.com"}
				o.Target = config.ConnectionTarget{
					Selector:     "app.example.com",
					OriginalHost: "app",
					Port:         2223,
					HasPort:      true,
				}
				o.parsedArgs = true
			},
			wantLookup:     "ops@10.10.0.1:2223",
			wantScopedSock: false,
		},
		{
			name:             "runtime_origin_user_override",
			setRuntimeOrigin: true,
			configure: func(o *SshOptions) {
				o.User = "altuser"
				o.args = []string{"app-saved"}
			},
			wantLookup:     "altuser@10.10.0.1:2222",
			wantScopedSock: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			roProv, _ := setupW18cCLISavedCanonicalFixture(t, tc.setRuntimeOrigin)
			assertW18cCLIControlCheckAndProxyCase(t, roProv, tc.name, tc.configure, tc.wantLookup, tc.wantScopedSock)
		})
	}
}

func assertW18cCLIControlCheckAndProxyCase(
	t *testing.T,
	roProv *config.Provider,
	name string,
	configure func(*SshOptions),
	wantLookup string,
	wantScopedSock bool,
) {
	t.Helper()
	checkOpts := NewSshOptions()
	checkOpts.control.CtlCmd = "check"
	configure(checkOpts)
	if err := checkOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("ensureArgsParsed(check): %v", err)
	}
	nodeID, err := resolveControlNodeID(roProv, effectiveConnectionTarget(checkOpts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID: %v", err)
	}
	if nodeID != "" {
		t.Fatalf("expected empty matched nodeID for overridden saved node, got %q", nodeID)
	}
	target, err := controlTarget(checkOpts, roProv, nodeID)
	if err != nil {
		t.Fatalf("controlTarget: %v", err)
	}
	lookupKey, _ := resolveControlSessionLookup(checkOpts, roProv, nodeID, effectiveConnectionTarget(checkOpts, nodeID), target)
	if lookupKey != wantLookup || config.IsOpenSSHNodeID(lookupKey) {
		t.Fatalf("check lookupKey = %q, want non-OpenSSH %q", lookupKey, wantLookup)
	}
	sockPath, err := controlSocketPath(checkOpts, roProv, nodeID)
	if err != nil {
		t.Fatalf("controlSocketPath: %v", err)
	}
	if strings.Contains(sockPath, "leaked-cli-w18c") {
		t.Fatalf("-O check leaked mismatched Host app.example.com ControlPath: %q", sockPath)
	}
	if wantScopedSock && !strings.Contains(sockPath, "scoped-cli-w18c") {
		t.Fatalf("-O check sockPath = %q, want scoped-cli-w18c", sockPath)
	}
	if !wantScopedSock && sockPath != "" {
		t.Fatalf("-O check sockPath = %q, want empty for non-matching port 2223", sockPath)
	}

	proxyOpts := NewSshOptions()
	proxyOpts.control.CtlCmd = "proxy"
	configure(proxyOpts)
	if err := proxyOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("ensureArgsParsed(proxy): %v", err)
	}
	fallbackLookup := resolveControlProxyFallbackLookup(target, roProv, proxyOpts)
	if fallbackLookup != wantLookup || config.IsOpenSSHNodeID(fallbackLookup) {
		t.Fatalf("proxy fallbackLookup = %q, want non-OpenSSH %q", fallbackLookup, wantLookup)
	}
	clientCfg, _ := buildControlProxyClientConfig(target, roProv, nodeID, proxyOpts)
	if clientCfg == nil {
		t.Fatal("buildControlProxyClientConfig returned nil")
	}
	assertW18cCLIOptionsClean(t, clientCfg.Options, "-O proxy "+name)
}

func TestP7W18c_L3_18_M1_BackgroundPreForkAndHandoffPropagateFullSessionAuth(t *testing.T) {
	t.Parallel()

	t.Run("prefork_and_handoff_detect_proxy_cycle_introduced_by_HostName_User_Port_override", func(t *testing.T) {
		t.Parallel()
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-hop", models.Host{Address: "10.20.0.99", Port: 2222})
		cfg.Identities.Set("id-hop", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("hop-1", models.Node{HostRef: "h-hop", IdentityRef: "id-hop"})

		cfg.Hosts.Set("h-dest", models.Host{Address: "10.20.0.1", Port: 22})
		cfg.Identities.Set("id-dest", models.Identity{User: "dest", AuthType: "auto"})
		cfg.Nodes.Set("dest-node", models.Node{
			HostRef:     "h-dest",
			IdentityRef: "id-dest",
			ProxyJump:   "hop-1",
		})
		prov := config.NewProviderWithoutOpenSSH(cfg)

		// Overriding HostName/Port/User to match hop-1 (ops@10.20.0.99:2222) creates a ProxyJump cycle!
		bgOpts := NewSshOptions()
		bgOpts.BgRun = true
		bgOpts.NoCmd = true
		bgOpts.Host = "dest-node"
		bgOpts.HostName = "10.20.0.99"
		bgOpts.Port = 2222
		bgOpts.User = "ops"
		bgOpts.Target = config.ConnectionTarget{Selector: "dest-node", User: "ops", HasUser: true, Port: 2222, HasPort: true}
		bgOpts.targetNodeIDs = []string{"dest-node"}

		err := bgOpts.validateBackgroundProxyCommand(prov, "dest-node")
		var cycleErr *ssh.ProxyCycleError
		if err == nil || !errors.As(err, &cycleErr) {
			t.Fatalf("validateBackgroundProxyCommand(-f -o HostName=10.20.0.99 -p 2222 -l ops) err = %v, want *ssh.ProxyCycleError", err)
		}

		// ControlPersist master handoff path (shouldSkipMasterHandoff) must also detect the cycle.
		handoffOpts := NewSshOptions()
		handoffOpts.Host = "dest-node"
		handoffOpts.HostName = "10.20.0.99"
		handoffOpts.Port = 2222
		handoffOpts.User = "ops"
		handoffOpts.Target = config.ConnectionTarget{Selector: "dest-node", User: "ops", HasUser: true, Port: 2222, HasPort: true}
		handoffOpts.targetNodeIDs = []string{"dest-node"}

		skip, handoffErr := handoffOpts.shouldSkipMasterHandoff(context.Background(), nil, prov, "dest-node")
		if !skip || handoffErr == nil || !errors.As(handoffErr, &cycleErr) {
			t.Fatalf("shouldSkipMasterHandoff(-o HostName=10.20.0.99) = (%v, %v), want (true, *ssh.ProxyCycleError)", skip, handoffErr)
		}
	})

	t.Run("prefork_and_handoff_evaluate_overridden_HostName_for_ProxyCommand_detection", func(t *testing.T) {
		t.Parallel()
		sshCfg := strings.Join([]string{
			"Host 10.20.0.1",
			"  Port 22",
			"  ProxyCommand /bin/old-host-proxy",
			"",
			"Host jump-with-proxy",
			"  HostName 10.20.0.77",
			"  Port 2222",
			"  ProxyCommand /bin/override-proxy",
		}, "\n") + "\n"
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h-clean", models.Host{Address: "10.20.0.1", Port: 22})
		cfg.Identities.Set("id-clean", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("clean-node", models.Node{HostRef: "h-clean", IdentityRef: "id-clean"})
		prov := config.NewProviderWithOpenSSHParser(cfg, parser)

		// Overriding HostName via -o HostName=10.20.0.50 (no cycle, no ProxyCommand) must pass pre-fork & handoff cleanly.
		opts := NewSshOptions()
		opts.BgRun = true
		opts.NoCmd = true
		opts.Host = "clean-node"
		opts.HostName = "10.20.0.50"
		opts.Target = config.ConnectionTarget{Selector: "clean-node"}
		opts.targetNodeIDs = []string{"clean-node"}
		if err := opts.validateBackgroundProxyCommand(prov, "clean-node"); err != nil {
			t.Fatalf("validateBackgroundProxyCommand(clean HostName override) failed: %v", err)
		}

		// Invalid HostName % token must fail closed in buildProxyCommandPathChecker.
		badOpts := NewSshOptions()
		badOpts.BgRun = true
		badOpts.NoCmd = true
		badOpts.Host = "clean-node"
		badOpts.cliHostName = "%z.invalid"
		badOpts.Target = config.ConnectionTarget{Selector: "clean-node"}
		badOpts.targetNodeIDs = []string{"clean-node"}
		if err := badOpts.validateBackgroundProxyCommand(prov, "clean-node"); err == nil {
			t.Fatal("validateBackgroundProxyCommand(invalid cliHostName token) succeeded, want fail-closed error")
		}
	})
}

func execW18cRoot(args ...string) error {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)
	root.PersistentPreRunE = nil
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	return root.Execute()
}

func TestP7W18c_L4_18_M1_CLIRootHostAddReusableIdentityVaultPreserved(t *testing.T) {
	store, vaultFile := setupW16cHelperStore(t)
	encKey := inventoryTestPrivateKey(t, true)
	unencKey := inventoryTestPrivateKey(t, false)

	mustExecRoot(t, "key-password\n", "identity", "add", "shared-vault", "ops", "--key", encKey, "--passphrase-stdin")
	cfgBefore, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	identBefore, ok := cfgBefore.Identities.Get("shared-vault")
	if !ok || identBefore.PassphraseRef == nil {
		t.Fatalf("shared-vault identity missing PassphraseRef: %+v", identBefore)
	}
	passItemID := identBefore.PassphraseRef.ItemID

	// Reject combining -I with --key, --user, or positional user@host without touching vault.
	for _, badArgs := range [][]string{
		{"host", "add", "10.90.0.1:22", "-I", "shared-vault", "-k", unencKey, "--skip-verify"},
		{"host", "add", "10.90.0.1:22", "-I", "shared-vault", "-u", "bob", "--skip-verify"},
		{"host", "add", "bob@10.90.0.1:22", "-I", "shared-vault", "--skip-verify"},
	} {
		if err := execW18cRoot(badArgs...); err == nil {
			t.Fatalf("expected error for %v, got nil", badArgs)
		}
		vault := readW16cHelperVault(t, vaultFile)
		if vault[passItemID] != "key-password" {
			t.Fatalf("rejected %v corrupted/deleted shared-vault secret: %v", badArgs, vault)
		}
	}

	// Valid host add with -I preserves reusable identity and its vault secret.
	mustExecRoot(t, "", "host", "add", "10.90.0.1:22", "-I", "shared-vault", "--skip-verify")
	vaultAfterAdd := readW16cHelperVault(t, vaultFile)
	if vaultAfterAdd[passItemID] != "key-password" {
		t.Fatalf("host add -I shared-vault deleted vault secret: %v", vaultAfterAdd)
	}
	cfgAfterAdd, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load after add: %v", err)
	}
	identAfterAdd, _ := cfgAfterAdd.Identities.Get("shared-vault")
	if identAfterAdd.PassphraseRef == nil || identAfterAdd.PassphraseRef.ItemID != passItemID || identAfterAdd.KeyPath != encKey {
		t.Fatalf("shared-vault mutated after host add -I: %+v", identAfterAdd)
	}

	// Reject host edit -I with positional user@host.
	if err := execW18cRoot("host", "edit", "ops@10.90.0.1:22", "bob@10.90.0.2:22", "-I", "shared-vault"); err == nil {
		t.Fatal("host edit with positional user@host and -I succeeded, want error")
	}
}
