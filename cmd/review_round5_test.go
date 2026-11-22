package cmd

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	xssh "github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestRound5_P2_12_And_P3_11_SnakeCaseGeneralAndDaemonOptions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	k1 := filepath.Join(tmpDir, "id_snake")
	k2 := filepath.Join(tmpDir, "id_camel")

	opts := NewSshOptions()
	cmd := newCmdSshWithOptions(opts)
	if err := cmd.Flags().Parse([]string{
		"-i", k2,
		"-o", "identity_file=" + k1,
		"-o", "proxy_jump=jump-snake",
		"10.0.0.1",
	}); err != nil {
		t.Fatalf("Parse flags: %v", err)
	}
	if err := opts.Complete(cmd, cmd.Flags().Args()); err != nil {
		t.Fatalf("Complete failed: %v", err)
	}
	if opts.JumpHost != "jump-snake" || opts.effectiveCLIJumpHost() != "jump-snake" {
		t.Fatalf("proxy_jump not applied to JumpHost: got %q / %q", opts.JumpHost, opts.effectiveCLIJumpHost())
	}
	if !slices.Contains(opts.IdentityFiles, k1) || !slices.Contains(opts.IdentityFiles, k2) {
		t.Fatalf("identity_file + -i not preserved: %v", opts.IdentityFiles)
	}

	for _, opt := range []string{
		"identity_file=" + k1,
		"proxy_jump=jump-snake",
		"proxy_command=nc %h %p",
	} {
		if targetOnly, err := isTargetOnlyMuxDaemonOption(opt); err != nil || !targetOnly {
			t.Fatalf("isTargetOnlyMuxDaemonOption(%q) = (%v, %v), want (true, nil)", opt, targetOnly, err)
		}
	}
	if !isProxyCommandOptionKey("proxy_command") || !isProxyCommandOptionKey("ProxyCommand") {
		t.Fatal("isProxyCommandOptionKey must match both ProxyCommand and proxy_command")
	}
}

func TestRound5_P2_13_ReadPathControlLookupZeroProviderMutationAndFrozenParity(t *testing.T) {
	sshCfg := strings.Join([]string{
		"Host short",
		"  User ops",
		"  ConnectTimeout 17",
		"",
		"Host *.corp.example.com",
		"  ControlPath /tmp/r5-ctrl-%n-%h",
		"  ServerAliveInterval 29",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(repo.Snapshot(), parser)
	frozen := repo.Frozen()

	nodeID := config.OpenSSHNodePrefix + "short.corp.example.com"
	for _, tc := range []struct {
		name string
		p    config.ConfigProvider
	}{
		{"repository", repo},
		{"provider", prov},
		{"frozen", frozen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := NewSshOptions()
			o.Host = "short.corp.example.com"
			o.canonicalized = true
			o.originalHost = "short"
			o.expandHost = "short"
			o.Target = config.ConnectionTarget{Selector: "short.corp.example.com", OriginalHost: "short"}

			sock, err := controlSocketPath(o, tc.p, nodeID)
			if err != nil {
				t.Fatalf("controlSocketPath(%s) failed: %v", tc.name, err)
			}
			if sock != "/tmp/r5-ctrl-short-short.corp.example.com" {
				t.Fatalf("controlSocketPath(%s) = %q, want /tmp/r5-ctrl-short-short.corp.example.com", tc.name, sock)
			}

			eff, err := o.resolveAndCacheSessionOptions(tc.p, nodeID)
			if err != nil {
				t.Fatalf("resolveAndCacheSessionOptions(%s) failed: %v", tc.name, err)
			}
			if eff == nil || eff.Get(xssh.OptionConnectTimeout) != "17" || eff.ServerAliveInterval() != 29*time.Second {
				t.Fatalf("resolveAndCacheSessionOptions(%s) = %v, want ConnectTimeout=17 & ServerAliveInterval=29s", tc.name, eff)
			}

			if aliasSrc, ok := tc.p.(interface{ NodeOpenSSHAlias(string) string }); ok {
				if alias := aliasSrc.NodeOpenSSHAlias(nodeID); alias != "" {
					t.Fatalf("%s NodeOpenSSHAlias(%q) mutated to %q on read path", tc.name, nodeID, alias)
				}
				if alias := aliasSrc.NodeOpenSSHAlias("short"); alias != "" {
					t.Fatalf("%s NodeOpenSSHAlias(\"short\") mutated to %q on read path", tc.name, alias)
				}
			}
			if canonSrc, ok := tc.p.(interface{ NodeCanonicalHost(string) string }); ok {
				if canon := canonSrc.NodeCanonicalHost(nodeID); canon != "" {
					t.Fatalf("%s NodeCanonicalHost(%q) mutated to %q on read path", tc.name, nodeID, canon)
				}
			}
		})
	}
}

func TestRound5_P3_12_PresetJumpAndRepeatedCompleteNoDrift(t *testing.T) {
	t.Parallel()

	o := NewSshOptions()
	o.Host = "10.0.0.5"
	o.JumpHost = "preset-jump"
	cmd := NewCmdSsh()
	if err := o.Complete(cmd, []string{}); err != nil {
		t.Fatalf("first Complete failed: %v", err)
	}
	if err := o.Complete(cmd, []string{}); err != nil {
		t.Fatalf("second Complete failed: %v", err)
	}
	if got := o.effectiveCLIJumpHost(); got != "preset-jump" {
		t.Fatalf("effectiveCLIJumpHost after repeated Complete = %q, want preset-jump", got)
	}

	// Updating programmatic JumpHost after ApplyGeneralOptions no longer drifts from a stale mirror field.
	o.JumpHost = "updated-jump"
	if got := o.effectiveCLIJumpHost(); got != "updated-jump" {
		t.Fatalf("effectiveCLIJumpHost after update = %q, want updated-jump", got)
	}
}

func TestRound5_P3_13_ResolveMasterNodeIDMatchesSavedNodeAndHostAliases(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, err := net.SplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	cfg := newEmptyTestConfig()
	cfg.Hosts.Set("h1", models.Host{
		Address: host,
		Port:    uint16(portNum),
		Alias:   []string{"host-alias"},
	})
	cfg.Identities.Set("id1", models.Identity{User: "fixture", AuthType: "password", Password: "fixture-pass"})
	nodeID := config.FormatNodeID("fixture", host, uint16(portNum))
	cfg.Nodes.Set(nodeID, models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"node-alias"},
	})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key")))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	rawClient, err := cryptoSSH.Dial("tcp", fix.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("cryptoSSH.Dial: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	tmpDir := shortControlTempDir(t)
	for _, alias := range []string{"node-alias", "host-alias"} {
		m, mErr := xssh.StartMuxServer(ctx, rawClient, xssh.MuxMasterOptions{
			Path: filepath.Join(tmpDir, alias+".sock"),
			Target: xssh.TargetContext{
				Host:          host,
				Port:          portNum,
				User:          "fixture",
				OriginalHost:  alias,
				CanonicalHost: alias + ".corp.example.com",
				Control:       &xssh.ControlConfig{Master: xssh.ControlMasterAuto, Path: filepath.Join(tmpDir, alias+".sock"), Persist: "1m"},
			},
		})
		if mErr != nil {
			t.Fatalf("StartMuxServer(%s): %v", alias, mErr)
		}
		got := resolveMasterNodeID(repo, m)
		_ = m.Shutdown()
		if got != nodeID {
			t.Fatalf("resolveMasterNodeID(%s) = %q, want saved node %q", alias, got, nodeID)
		}
	}
}

func TestRound5_P3_14_ScpMissingHostFileAndCanonicalizePathAutoAppliesGeneralOpts(t *testing.T) {
	t.Parallel()

	// 1. Missing --ifile must surface the file read error rather than failing on --exclude.
	scpMissing := NewScpOptions()
	scpMissing.HostFile = filepath.Join(t.TempDir(), "does-not-exist.hosts")
	scpMissing.Exclude = []string{"web"}
	scpMissing.Source = "/tmp/src"
	scpMissing.Dest = "/tmp/dst"

	prov := config.NewProviderWithoutOpenSSH(newEmptyTestConfig())
	if _, err := scpMissing.resolveExcludes(prov); err == nil || !strings.Contains(err.Error(), "does-not-exist.hosts") {
		t.Fatalf("resolveExcludes with missing --ifile = %v, want file read error", err)
	}
	if err := scpMissing.canonicalizeEndpoints(t.Context(), prov); err == nil || !strings.Contains(err.Error(), "does-not-exist.hosts") {
		t.Fatalf("canonicalizeEndpoints with missing --ifile = %v, want file read error", err)
	}

	// 2. canonicalizePathInfo must auto-apply -o general options (e.g. ProxyJump=none keeps
	// canonicalization enabled and populates JumpHost="none" from -o).
	sshCfg := strings.Join([]string{
		"Host short",
		"  User ops",
		"Host *.corp.example.com",
		"  User ops",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	scpOpt := NewScpOptions()
	scpOpt.control.Options = []string{"ProxyJump=none"}
	scpOpt.canonicalResolver = &round4FakeCanonicalResolver{
		hosts: map[string][]string{"short.corp.example.com": {"10.10.0.10"}},
	}
	canonProv := config.NewProviderWithOpenSSHParser(nil, parser)
	_, cErr := scpOpt.canonicalizePathInfo(t.Context(), canonProv, PathInfo{Host: "short", IsRemote: true})
	if cErr != nil {
		t.Fatalf("canonicalizePathInfo failed: %v", cErr)
	}
	if !scpOpt.appliedGeneralOpts || scpOpt.JumpHost != "none" {
		t.Fatalf("canonicalizePathInfo did not auto-apply general options: applied=%v JumpHost=%q", scpOpt.appliedGeneralOpts, scpOpt.JumpHost)
	}
}
