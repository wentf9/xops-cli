package adapter

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func runLiveSSHGProxy(t *testing.T, sshBin, cfgPath, target string, extraArgs ...string) (proxyJump, proxyCommand string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	args := make([]string, 0, 4+len(extraArgs))
	args = append(args, "-F", cfgPath, "-G")
	args = append(args, extraArgs...)
	args = append(args, target)
	out, err := exec.CommandContext(ctx, sshBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -F %s -G %v %q failed (%v):\n%s", cfgPath, extraArgs, target, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "proxyjump":
			if proxyJump == "" {
				proxyJump = strings.TrimSpace(v)
			}
		case "proxycommand":
			if proxyCommand == "" {
				proxyCommand = strings.TrimSpace(v)
			}
		}
	}
	if strings.EqualFold(proxyCommand, "none") {
		proxyCommand = ""
	}
	return proxyJump, proxyCommand
}

func TestP7W4c_D1_ShadowedTier4ProxyCommand_DifferentialAndLocalExecEnforcement(t *testing.T) {
	t.Parallel()

	rawCfg := strings.Join([]string{
		"Host app",
		"  HostName 10.77.0.1",
		"  User ops",
		"  ProxyJump bastion",
		"",
		"Host app-shadow-none",
		"  HostName 10.77.0.2",
		"  User ops",
		"  ProxyJump bastion",
		"  ProxyCommand none",
		"",
		"Host short",
		"  User ops",
		"  ProxyJump bastion",
		"",
		"Host short.corp.example.com",
		"  HostName 10.77.0.3",
		"  ProxyCommand ssh -W %h:%p canon-proxy",
		"",
		"Host *",
		"  ProxyCommand nc %h %p",
	}, "\n") + "\n"

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "ssh_config")
	if err := os.WriteFile(cfgPath, []byte(rawCfg), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	parser, err := config.NewOpenSSHParserFromPath(cfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}
	store := config.NewDefaultStore(filepath.Join(tmpDir, "xops.yaml"), filepath.Join(tmpDir, "xops.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// Saved managed node pointing to the same endpoint as Host app must still block
	// Tier-4 OptionClassLocalExec/ProxyCommand per Tier-4 trust policy.
	if _, err := repo.CreateNodeContext(
		t.Context(),
		"saved-app",
		models.Node{HostRef: "h-app", IdentityRef: "id-app", ProxyJump: "saved-bastion"},
		models.Host{Address: "10.77.0.1", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext(saved-app): %v", err)
	}

	sshBin, _ := exec.LookPath("ssh")

	t.Run("virtual_node_J_none_and_dash_o_ProxyJump_none_reveal_shadowed_ProxyCommand_matching_ssh_G", func(t *testing.T) {
		testP7W4cD1VirtualNode(t, repo, sshBin, cfgPath)
	})

	t.Run("openssh_derived_and_canonicalized_two_pass_preserve_shadowed_ProxyCommand", func(t *testing.T) {
		testP7W4cD1DerivedAndCanonicalized(t, repo, tmpDir)
	})

	t.Run("saved_managed_node_still_blocks_Tier4_ProxyCommand_under_J_none", func(t *testing.T) {
		testP7W4cD1SavedManagedIsolation(t, repo)
	})
}

func testP7W4cD1VirtualNode(t *testing.T, repo *config.Repository, sshBin, cfgPath string) {
	t.Helper()
	nodeID := config.OpenSSHNodePrefix + "app"

	if sshBin != "" {
		assertP7W4cD1LiveSSHG(t, sshBin, cfgPath)
	}

	// 1. Without -J none: ProxyJump masks shadowed ProxyCommand; WithLocalExecution(false) succeeds.
	adpNoExec := NewSSHAdapter(repo, WithLocalExecution(false))
	cfgDefault, err := adpNoExec.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(%q) without -J none failed under WithLocalExecution(false): %v", nodeID, err)
	}
	if cfgDefault.ProxyJump != "openssh:bastion" || cfgDefault.Options.ActiveProxyCommand() != "" {
		t.Fatalf("default proxy = (jump=%q cmd=%q), want (openssh:bastion, \"\")", cfgDefault.ProxyJump, cfgDefault.Options.ActiveProxyCommand())
	}

	// 2. With -J none and -o ProxyJump=none: reveal shadowed ProxyCommand and enforce WithLocalExecution(false).
	pjNoneCtrl, err := ParseSessionOptions([]string{"ProxyJump=none"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(ProxyJump=none): %v", err)
	}
	modes := []struct {
		name string
		opts []Option
	}{
		{"dash_J_none_SessionAuth", []Option{WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: "none"})}},
		{"dash_o_ProxyJump_none_SessionControlOnly", []Option{WithSessionControlOverride(nodeID, pjNoneCtrl)}},
		{"both_SessionAuth_and_SessionControl", []Option{
			WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: "none"}),
			WithSessionControlOverride(nodeID, pjNoneCtrl),
		}},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			assertP7W4cD1ShadowedProxyCommandMode(t, repo, nodeID, mode.opts)
		})
	}

	// 3. -o ProxyCommand=none disables both ProxyJump and shadowed ProxyCommand; WithLocalExecution(false) succeeds.
	pcNoneCtrl, err := ParseSessionOptions([]string{"ProxyCommand=none"}, "")
	if err != nil {
		t.Fatal(err)
	}
	adpCmdNone := NewSSHAdapter(repo, WithLocalExecution(false), WithSessionControlOverride(nodeID, pcNoneCtrl))
	cfgCmdNone, err := adpCmdNone.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(ProxyCommand=none, WithLocalExecution=false): %v", err)
	}
	if cfgCmdNone.ProxyJump != "" || (cfgCmdNone.Options != nil && cfgCmdNone.Options.ActiveProxyCommand() != "") {
		t.Fatalf("ProxyCommand=none left active proxy: jump=%q cmd=%q", cfgCmdNone.ProxyJump, cfgCmdNone.Options.ActiveProxyCommand())
	}

	// 4. Shadowed ProxyCommand=none beneath ProxyJump remains disabled under -J none (does not expose Host * ProxyCommand).
	shadowNoneID := config.OpenSSHNodePrefix + "app-shadow-none"
	adpShadowNone := NewSSHAdapter(repo, WithLocalExecution(false), WithSessionAuthOverride(shadowNoneID, SessionAuth{ProxyJump: "none"}))
	cfgShadowNone, err := adpShadowNone.GetConfig(shadowNoneID)
	if err != nil {
		t.Fatalf("GetConfig(app-shadow-none, -J none): %v", err)
	}
	if cfgShadowNone.ProxyJump != "" || (cfgShadowNone.Options != nil && cfgShadowNone.Options.ActiveProxyCommand() != "") {
		t.Fatalf("app-shadow-none leaked Host * ProxyCommand: jump=%q cmd=%q", cfgShadowNone.ProxyJump, cfgShadowNone.Options.ActiveProxyCommand())
	}
}

func assertP7W4cD1LiveSSHG(t *testing.T, sshBin, cfgPath string) {
	t.Helper()
	pjNone, pcNone := runLiveSSHGProxy(t, sshBin, cfgPath, "app", "-J", "none")
	if pjNone != "" || pcNone != "nc %h %p" {
		t.Fatalf("ssh -G -J none app = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")", pjNone, pcNone)
	}
	pjOpt, pcOpt := runLiveSSHGProxy(t, sshBin, cfgPath, "app", "-o", "ProxyJump=none")
	if pjOpt != "" || pcOpt != "nc %h %p" {
		t.Fatalf("ssh -G -o ProxyJump=none app = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")", pjOpt, pcOpt)
	}
	pjCmdNone, pcCmdNone := runLiveSSHGProxy(t, sshBin, cfgPath, "app", "-o", "ProxyCommand=none")
	if pjCmdNone != "" || pcCmdNone != "" {
		t.Fatalf("ssh -G -o ProxyCommand=none app = (jump=%q cmd=%q), want both empty", pjCmdNone, pcCmdNone)
	}
}

func assertP7W4cD1ShadowedProxyCommandMode(t *testing.T, repo *config.Repository, nodeID string, modeOpts []Option) {
	t.Helper()
	adpExec := NewSSHAdapter(repo, append([]Option{WithLocalExecution(true)}, modeOpts...)...)
	pol, err := adpExec.Resolve(t.Context(), ResolveRequest{NodeID: nodeID, RequireSnapshot: true})
	if err != nil {
		t.Fatalf("Resolve(WithLocalExecution=true): %v", err)
	}
	if gotCmd, ok := pol.Proxy().Command(); !ok || gotCmd != "nc %h %p" {
		t.Fatalf("pol.Proxy().Command() = (%q, %v), want (\"nc %%h %%p\", true)", gotCmd, ok)
	}
	if pol.Options() == nil || pol.Options().ActiveProxyCommand() != "nc %h %p" {
		t.Fatalf("pol.Options().ActiveProxyCommand() = %q, want \"nc %%h %%p\"", pol.Options().ActiveProxyCommand())
	}
	cfg, err := adpExec.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(WithLocalExecution=true): %v", err)
	}
	if cfg.ProxyJump != "" || cfg.Options == nil || cfg.Options.ActiveProxyCommand() != "nc %h %p" {
		t.Fatalf("GetConfig = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")", cfg.ProxyJump, cfg.Options.ActiveProxyCommand())
	}

	adpDeny := NewSSHAdapter(repo, append([]Option{WithLocalExecution(false)}, modeOpts...)...)
	if _, err := adpDeny.Resolve(t.Context(), ResolveRequest{NodeID: nodeID, RequireSnapshot: true}); !errors.Is(err, ErrLocalExecutionDisabled) {
		t.Fatalf("Resolve(WithLocalExecution=false) err = %v, want ErrLocalExecutionDisabled", err)
	}
	if _, err := adpDeny.GetConfig(nodeID); !errors.Is(err, ErrLocalExecutionDisabled) {
		t.Fatalf("GetConfig(WithLocalExecution=false) err = %v, want ErrLocalExecutionDisabled", err)
	}
}

func testP7W4cD1DerivedAndCanonicalized(t *testing.T, repo *config.Repository, tmpDir string) {
	t.Helper()
	// ProvenanceOpenSSHDerived for admin@app with -J none.
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "app", User: "admin", HasUser: true, ProxyJump: "none", HasProxyJump: true},
	}, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		adpExec := NewSSHAdapter(repo, WithLocalExecution(true), WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: "none"}))
		cfg, err := adpExec.GetConfig(nodeID)
		if err != nil {
			t.Fatalf("GetConfig(derived, WithLocalExecution=true): %v", err)
		}
		if cfg.ProxyJump != "" || cfg.Options == nil || cfg.Options.ActiveProxyCommand() != "nc %h %p" {
			t.Fatalf("derived GetConfig = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")", cfg.ProxyJump, cfg.Options.ActiveProxyCommand())
		}
		adpDeny := NewSSHAdapter(repo, WithLocalExecution(false), WithSessionAuthOverride(nodeID, SessionAuth{ProxyJump: "none"}))
		if _, err := adpDeny.GetConfig(nodeID); !errors.Is(err, ErrLocalExecutionDisabled) {
			t.Fatalf("derived GetConfig(WithLocalExecution=false) err = %v, want ErrLocalExecutionDisabled", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(admin@app): %v", err)
	}

	// Two-pass canonicalized virtual node with Host * ProxyCommand:
	// Pass 1 (short) matches Host * before Pass 2 (short.corp.example.com), matching live `ssh -G -J none short`.
	canonNodeID := config.OpenSSHNodePrefix + "short.corp.example.com"
	adpCanonPass1 := NewSSHAdapter(repo, WithLocalExecution(true), WithSessionAuthOverride(canonNodeID, SessionAuth{
		OriginalHost: "short",
		ProxyJump:    "none",
	}))
	cfgCanonPass1, err := adpCanonPass1.GetConfig(canonNodeID)
	if err != nil {
		t.Fatalf("GetConfig(canonicalized pass1 Host *, -J none): %v", err)
	}
	if cfgCanonPass1.ProxyJump != "" || cfgCanonPass1.Options == nil || cfgCanonPass1.Options.ActiveProxyCommand() != "nc %h %p" {
		t.Fatalf("canonicalized pass1 GetConfig = (jump=%q cmd=%q), want (\"\", \"nc %%h %%p\")",
			cfgCanonPass1.ProxyJump, cfgCanonPass1.Options.ActiveProxyCommand())
	}

	// Dedicated two-pass config without Host * ProxyCommand:
	// Pass 1 (short) sets ProxyJump bastion; Pass 2 (short.corp.example.com) sets shadowed ProxyCommand.
	canonOnlyCfg := strings.Join([]string{
		"Host short",
		"  User ops",
		"  ProxyJump bastion",
		"",
		"Host short.corp.example.com",
		"  HostName 10.77.0.3",
		"  ProxyCommand ssh -W %h:%p canon-proxy",
	}, "\n") + "\n"
	canonParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(canonOnlyCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(canonOnlyCfg): %v", err)
	}
	canonStore := config.NewDefaultStore(filepath.Join(tmpDir, "canon.yaml"), filepath.Join(tmpDir, "canon.key"))
	canonRepo, err := config.NewRepositoryWithOpenSSHParser(nil, canonStore, canonParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser(canonOnlyCfg): %v", err)
	}
	adpCanonPass2 := NewSSHAdapter(canonRepo, WithLocalExecution(true), WithSessionAuthOverride(canonNodeID, SessionAuth{
		OriginalHost: "short",
		ProxyJump:    "none",
	}))
	cfgCanonPass2, err := adpCanonPass2.GetConfig(canonNodeID)
	if err != nil {
		t.Fatalf("GetConfig(canonicalized pass2, -J none): %v", err)
	}
	if cfgCanonPass2.ProxyJump != "" || cfgCanonPass2.Options == nil || cfgCanonPass2.Options.ActiveProxyCommand() != "ssh -W %h:%p canon-proxy" {
		t.Fatalf("canonicalized pass2 GetConfig = (jump=%q cmd=%q), want (\"\", \"ssh -W %%h:%%p canon-proxy\")",
			cfgCanonPass2.ProxyJump, cfgCanonPass2.Options.ActiveProxyCommand())
	}
	adpCanonDeny := NewSSHAdapter(canonRepo, WithLocalExecution(false), WithSessionAuthOverride(canonNodeID, SessionAuth{
		OriginalHost: "short",
		ProxyJump:    "none",
	}))
	if _, err := adpCanonDeny.GetConfig(canonNodeID); !errors.Is(err, ErrLocalExecutionDisabled) {
		t.Fatalf("canonicalized pass2 GetConfig(WithLocalExecution=false) err = %v, want ErrLocalExecutionDisabled", err)
	}
}

func testP7W4cD1SavedManagedIsolation(t *testing.T, repo *config.Repository) {
	t.Helper()
	adpSaved := NewSSHAdapter(repo, WithLocalExecution(false), WithSessionAuthOverride("saved-app", SessionAuth{ProxyJump: "none"}))
	cfgSaved, err := adpSaved.GetConfig("saved-app")
	if err != nil {
		t.Fatalf("saved-app GetConfig(-J none, WithLocalExecution=false) unexpectedly failed: %v", err)
	}
	if cfgSaved.ProxyJump != "" || (cfgSaved.Options != nil && cfgSaved.Options.ActiveProxyCommand() != "") {
		t.Fatalf("saved-app leaked Tier-4 ProxyCommand: jump=%q cmd=%q", cfgSaved.ProxyJump, cfgSaved.Options.ActiveProxyCommand())
	}
}

func TestP7W4c_D4_InvalidProxyJumpFailsClosedInResolve(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"bad\x00hop", "bastion\n", "none\x00", "\x00", "a,,b", "a,", ",b"} {
		if ps, err := proxySettingFromJumpString(bad); err == nil {
			t.Errorf("proxySettingFromJumpString(%q) = %q, want error", bad, ps)
		}
	}

	cfg := newP7TestConfig()
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("clean", models.Node{HostRef: "h1", IdentityRef: "id1"})
	cfg.Nodes.Set("bad-node", models.Node{HostRef: "h1", IdentityRef: "id1", ProxyJump: "bad\x00hop"})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	for _, bad := range []string{"bad\x00hop", "bastion\n", "a,,b"} {
		adp := NewSSHAdapter(prov, WithSessionAuthOverride("clean", SessionAuth{ProxyJump: bad}))
		if _, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "clean", RequireSnapshot: true}); err == nil {
			t.Errorf("Resolve(SessionAuth.ProxyJump=%q) succeeded, want error", bad)
		}
		if _, err := adp.GetConfig("clean"); err == nil {
			t.Errorf("GetConfig(SessionAuth.ProxyJump=%q) succeeded, want error", bad)
		}
	}

	adpBadNode := NewSSHAdapter(prov)
	if _, err := adpBadNode.Resolve(t.Context(), ResolveRequest{NodeID: "bad-node", RequireSnapshot: true}); err == nil {
		t.Fatal("Resolve(bad-node with NUL in Node.ProxyJump) succeeded, want error")
	}
}

func TestP7W4c_D5_SessionControlIdentityFileDerivesAutoAuthType(t *testing.T) {
	t.Parallel()

	cfg := newP7TestConfig()
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("pwd-node", models.Node{HostRef: "h1", IdentityRef: "id1"})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	t.Run("programmatic WithSessionControlOverride IdentityFile=/path flips password to auto", func(t *testing.T) {
		t.Parallel()
		sc := SessionControlOptions{Options: ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/custom_id_ed25519")}
		adp := NewSSHAdapter(prov, WithSessionControlOverride("pwd-node", sc))
		clientCfg, err := adp.GetConfig("pwd-node")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if clientCfg.AuthType != "auto" {
			t.Fatalf("AuthType = %q, want \"auto\"", clientCfg.AuthType)
		}
		if clientCfg.KeyPath != "/tmp/custom_id_ed25519" || !slices.Equal(clientCfg.KeyPaths, []string{"/tmp/custom_id_ed25519"}) {
			t.Fatalf("keys = (KeyPath=%q KeyPaths=%v), want /tmp/custom_id_ed25519", clientCfg.KeyPath, clientCfg.KeyPaths)
		}
	})

	t.Run("programmatic WithSessionControlOverride IdentityFile=none preserves password", func(t *testing.T) {
		t.Parallel()
		sc := SessionControlOptions{Options: ssh.MustOptions(ssh.OptionIdentityFile, "none")}
		adp := NewSSHAdapter(prov, WithSessionControlOverride("pwd-node", sc))
		clientCfg, err := adp.GetConfig("pwd-node")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if clientCfg.AuthType != "password" {
			t.Fatalf("AuthType = %q, want \"password\"", clientCfg.AuthType)
		}
		if clientCfg.KeyPath != "" || !slices.Equal(clientCfg.KeyPaths, []string{"none"}) {
			t.Fatalf("keys = (KeyPath=%q KeyPaths=%v), want disabled", clientCfg.KeyPath, clientCfg.KeyPaths)
		}
	})

	t.Run("SessionAuth KeyPaths=none terminates SessionControl IdentityFile=/path and preserves password", func(t *testing.T) {
		t.Parallel()
		sc := SessionControlOptions{Options: ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/lower_id")}
		adp := NewSSHAdapter(
			prov,
			WithSessionAuthOverride("pwd-node", SessionAuth{KeyPaths: []string{"none"}}),
			WithSessionControlOverride("pwd-node", sc),
		)
		clientCfg, err := adp.GetConfig("pwd-node")
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if clientCfg.AuthType != "password" {
			t.Fatalf("AuthType = %q, want \"password\" when SessionAuth disabled keys", clientCfg.AuthType)
		}
	})
}

func TestP7W4c_D6_MultiLayerTier4DefaultAlgoPolicyShadowsLowerLayer(t *testing.T) {
	t.Parallel()

	rawCfg := strings.Join([]string{
		"Host alias1",
		"  HostName 10.88.0.1",
		"  MACs +umac-64@openssh.com",
		"  Ciphers ^unsupported-cipher@example.com",
		"",
		"Host alias2",
		"  HostName 10.88.0.1",
		"  MACs hmac-sha2-256",
		"  Ciphers aes128-ctr",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(rawCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := newP7TestConfig()
	cfg.Hosts.Set("h1", models.Host{Address: "10.88.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("multi-alias", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"alias1", "alias2"},
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	adp := NewSSHAdapter(prov)
	pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "multi-alias", RequireSnapshot: true})
	if err != nil {
		t.Fatalf("Resolve(multi-alias): %v", err)
	}
	opts := pol.Options()
	if opts == nil {
		t.Fatal("expected non-nil effective options preserving DefaultAlgoPolicy")
	}
	if got := opts.MACs(); got != "" {
		t.Fatalf("alias1 MACs +umac-64@openssh.com failed to shadow alias2 MACs hmac-sha2-256: got %q", got)
	}
	if got := opts.Ciphers(); got != "" {
		t.Fatalf("alias1 Ciphers ^unsupported-cipher@example.com failed to shadow alias2 Ciphers aes128-ctr: got %q", got)
	}
	if macPol, ok := opts.AlgoPolicy(ssh.OptionMACs); !ok || !macPol.IsDefault() {
		t.Fatalf("AlgoPolicy(MACs) = (%+v, %v), want DefaultAlgoPolicy", macPol, ok)
	}
	if cipPol, ok := opts.AlgoPolicy(ssh.OptionCiphers); !ok || !cipPol.IsDefault() {
		t.Fatalf("AlgoPolicy(Ciphers) = (%+v, %v), want DefaultAlgoPolicy", cipPol, ok)
	}

	// Higher Tier-1 CLI override still beats Tier-4 DefaultAlgoPolicy.
	cliOpts, err := ParseSessionOptions([]string{"MACs=hmac-sha2-512"}, "")
	if err != nil {
		t.Fatal(err)
	}
	adpCLI := NewSSHAdapter(prov, WithSessionControlOverride("multi-alias", cliOpts))
	clientCfg, err := adpCLI.GetConfig("multi-alias")
	if err != nil {
		t.Fatalf("GetConfig(CLI MACs override): %v", err)
	}
	if clientCfg.Options == nil || clientCfg.Options.MACs() != "hmac-sha2-512" {
		t.Fatalf("CLI MACs override = %q, want hmac-sha2-512", clientCfg.Options.MACs())
	}
}
