//go:build p7repro

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newP7MemoryRepo(t *testing.T, initial *Configuration) *Repository {
	t.Helper()
	store := NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := NewRepositoryWithOpenSSHParser(initial, store, &OpenSSHParser{})
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo
}

// TestP7Repro_MED5_CyclicAndSelfProxyJump_RejectedAtWriteBoundaries reproduces MED-5:
// cyclic and self-referential ProxyJump graphs pass ValidateV2, Repository commit
// (CreateNodeContext / NewRepository), and ImportOpenSSHHostsContext.
func TestP7Repro_MED5_CyclicAndSelfProxyJump_RejectedAtWriteBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("ValidateV2_rejects_self_ProxyJump", func(t *testing.T) {
		t.Parallel()
		cfg := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts:         map[string]models.Host{"h-a": {Address: "10.0.0.1", Port: 22}},
			Identities:    map[string]IdentityV2{"id-a": {User: "ops", AuthType: "auto"}},
			Nodes: map[string]NodeV2{
				"node-a": {HostRef: "h-a", IdentityRef: "id-a", ProxyJump: "node-a", SudoMode: models.SudoModeAuto},
			},
		}
		if err := ValidateV2(cfg); err == nil {
			t.Fatal("MED-5: ValidateV2 accepted self-referential ProxyJump (node-a -> node-a)")
		}
	})

	t.Run("ValidateV2_rejects_two_node_ProxyJump_cycle", func(t *testing.T) {
		t.Parallel()
		cfg := &ConfigurationV2{
			SchemaVersion: 2,
			Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
			Hosts: map[string]models.Host{
				"h-a": {Address: "10.0.0.1", Port: 22},
				"h-b": {Address: "10.0.0.2", Port: 22},
			},
			Identities: map[string]IdentityV2{"id": {User: "ops", AuthType: "auto"}},
			Nodes: map[string]NodeV2{
				"node-a": {HostRef: "h-a", IdentityRef: "id", ProxyJump: "node-b", SudoMode: models.SudoModeAuto},
				"node-b": {HostRef: "h-b", IdentityRef: "id", ProxyJump: "node-a", SudoMode: models.SudoModeAuto},
			},
		}
		if err := ValidateV2(cfg); err == nil {
			t.Fatal("MED-5: ValidateV2 accepted cyclic ProxyJump (node-a -> node-b -> node-a)")
		}
	})

	t.Run("Repository_CreateNodeContext_rejects_self_and_cycle", func(t *testing.T) {
		t.Parallel()
		repo := newP7MemoryRepo(t, nil)

		_, err := repo.CreateNodeContext(
			t.Context(),
			"self-node",
			models.Node{HostRef: "h-self", IdentityRef: "id-self", ProxyJump: "self-node", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.1", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		if err == nil {
			t.Errorf("MED-5: Repository.CreateNodeContext committed self-referential ProxyJump (self-node -> self-node)")
		}

		_, errA := repo.CreateNodeContext(
			t.Context(),
			"cycle-a",
			models.Node{HostRef: "h-ca", IdentityRef: "id-ca", ProxyJump: "cycle-b", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.2", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		_, errB := repo.CreateNodeContext(
			t.Context(),
			"cycle-b",
			models.Node{HostRef: "h-cb", IdentityRef: "id-cb", ProxyJump: "cycle-a", SudoMode: models.SudoModeAuto},
			models.Host{Address: "10.0.1.3", Port: 22},
			models.Identity{User: "ops", AuthType: "auto"},
		)
		if errA == nil && errB == nil {
			t.Errorf("MED-5: Repository.CreateNodeContext committed 2-node ProxyJump cycle (cycle-a <-> cycle-b)")
		}
	})

	t.Run("ImportOpenSSHHostsContext_rejects_self_and_cycle", func(t *testing.T) {
		t.Parallel()
		repo := newP7MemoryRepo(t, nil)

		hosts := []OpenSSHHost{
			{
				Name:     "imp-self",
				Host:     models.Host{Address: "10.0.2.1", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-self"}, ProxyJump: "imp-self", SudoMode: models.SudoModeAuto},
			},
			{
				Name:     "imp-a",
				Host:     models.Host{Address: "10.0.2.2", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-a"}, ProxyJump: "imp-b", SudoMode: models.SudoModeAuto},
			},
			{
				Name:     "imp-b",
				Host:     models.Host{Address: "10.0.2.3", Port: 22},
				Identity: models.Identity{User: "ops", AuthType: "auto"},
				Node:     models.Node{Alias: []string{"imp-b"}, ProxyJump: "imp-a", SudoMode: models.SudoModeAuto},
			},
		}

		res, err := repo.ImportOpenSSHHostsContext(t.Context(), hosts)
		if err == nil {
			snap := repo.Snapshot()
			if _, ok := snap.Nodes.Get("imp-self"); ok {
				t.Errorf("MED-5: ImportOpenSSHHostsContext persisted self-loop node imp-self (res=%+v)", res)
			}
			_, hasA := snap.Nodes.Get("imp-a")
			_, hasB := snap.Nodes.Get("imp-b")
			if hasA && hasB {
				t.Errorf("MED-5: ImportOpenSSHHostsContext persisted cyclic nodes imp-a <-> imp-b (res=%+v)", res)
			}
		}
	})
}

// TestP7Repro_MED6_OpenSSHAllowList_BareModifiersAndInvalidTokensError reproduces MED-6:
// filterOpenSSHAllowListOption silently ignores bare algorithm modifiers (`Ciphers -`,
// `Ciphers +`, `KexAlgorithms ^`) and malformed negated tokens (`MACs -bad!mac`) instead
// of returning an error.
func TestP7Repro_MED6_OpenSSHAllowList_BareModifiersAndInvalidTokensError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		directive string
	}{
		{name: "Ciphers_bare_minus", directive: "Ciphers -"},
		{name: "Ciphers_bare_plus", directive: "Ciphers +"},
		{name: "KexAlgorithms_bare_caret", directive: "KexAlgorithms ^"},
		{name: "MACs_invalid_negated_token", directive: "MACs -bad!mac"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfgText := fmt.Sprintf("Host app\n    HostName 10.0.0.1\n    %s\n", tc.directive)
			parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
			if err != nil {
				// Failing at parse time also satisfies fail-closed rejection.
				return
			}
			opts, optErr := parser.GetSSHOptions("app")
			if optErr == nil {
				t.Fatalf("MED-6: GetSSHOptions(%q) silently ignored %q (opts=%+v), want error", "app", tc.directive, opts)
			}
		})
	}
}

// TestP7Repro_MED8_Canonicalize_ProxyJumpNoneOverTier4ProxyJumpAndLowerProxyCommand
// reproduces the first half of MED-8: when Tier-4 defines both ProxyJump and a lower
// ProxyCommand, CLI `-o ProxyJump=none` cancels Tier-4 ProxyJump, exposing the active
// lower ProxyCommand which must suppress CanonicalizeHostname=yes DNS canonicalization.
func TestP7Repro_MED8_Canonicalize_ProxyJumpNoneOverTier4ProxyJumpAndLowerProxyCommand(t *testing.T) {
	t.Parallel()

	configs := []struct {
		name   string
		sshCfg string
	}{
		{
			name: "tier4_proxyjump_with_wildcard_proxycommand",
			sshCfg: `
Host app
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    ProxyJump bastion

Host *
    ProxyCommand ssh -W %h:%p lower-proxy
`,
		},
		{
			name: "tier4_same_block_proxyjump_and_proxycommand",
			sshCfg: `
Host app
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    ProxyJump bastion
    ProxyCommand ssh -W %h:%p lower-proxy
`,
		},
	}

	cliOverrides := []struct {
		name         string
		rawCLI       []string
		cliProxyJump string
	}{
		{name: "dash_o_ProxyJump_none", rawCLI: []string{"ProxyJump=none"}},
		{name: "dash_J_none", cliProxyJump: "none"},
	}

	for _, cfgCase := range configs {
		for _, cliCase := range cliOverrides {
			t.Run(cfgCase.name+"/"+cliCase.name, func(t *testing.T) {
				t.Parallel()
				parser, err := NewOpenSSHParserFromReader(strings.NewReader(cfgCase.sshCfg))
				if err != nil {
					t.Fatalf("NewOpenSSHParserFromReader: %v", err)
				}
				provider := NewProviderWithOpenSSHParser(nil, parser)
				res := &fakeCanonicalResolver{
					hosts: map[string][]string{
						"app.corp.example.com": {"10.20.30.40"},
					},
				}

				if cands := CanonicalDomainCandidatesWithOptions(provider, "app", cliCase.rawCLI, cliCase.cliProxyJump); len(cands) != 0 {
					t.Errorf("MED-8: CanonicalDomainCandidatesWithOptions returned %v despite exposed lower ProxyCommand", cands)
				}

				out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
					Provider:      provider,
					Host:          "app",
					RawCLIOptions: cliCase.rawCLI,
					CLIProxyJump:  cliCase.cliProxyJump,
					Resolver:      res,
				})
				if err != nil {
					t.Fatalf("CanonicalizeHost err: %v", err)
				}
				if out.Canonicalized || len(res.queried) != 0 {
					t.Fatalf("MED-8: -o ProxyJump=none over Tier-4 ProxyJump + lower ProxyCommand triggered DNS canonicalization: out=%+v queried=%v",
						out, res.queried)
				}
			})
		}
	}
}

type p7DeadlineCaptureResolver struct {
	remaining time.Duration
	hasDL     bool
}

func (r *p7DeadlineCaptureResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if dl, ok := ctx.Deadline(); ok {
		r.hasDL = true
		r.remaining = time.Until(dl)
	}
	if host == "app.corp.example.com" {
		return []string{"10.20.30.40"}, nil
	}
	return nil, errors.New("no such host")
}

func (r *p7DeadlineCaptureResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}

// TestP7Repro_MED8_ConnectTimeoutParity_0m_00 reproduces the second half of MED-8:
// parseCanonicalConnectTimeout accepts "0m" and "00" (mapping them to maxCanonicalProbeTimeout),
// whereas core/ssh OptionConnectTimeout rejects both.
func TestP7Repro_MED8_ConnectTimeoutParity_0m_00(t *testing.T) {
	t.Parallel()

	invalidValues := []string{"0m", "00"}

	// Precondition: OptionConnectTimeout rejects "0m" and "00".
	for _, raw := range invalidValues {
		var o ssh.Options
		if err := o.Set(ssh.OptionConnectTimeout, raw); err == nil {
			t.Fatalf("precondition failed: OptionConnectTimeout unexpectedly accepted %q", raw)
		}
	}

	t.Run("parseCanonicalConnectTimeout_rejects_0m_and_00", func(t *testing.T) {
		t.Parallel()
		for _, raw := range invalidValues {
			if d, ok := parseCanonicalConnectTimeout(raw); ok {
				t.Errorf("MED-8: parseCanonicalConnectTimeout(%q) = (%v, true), want (_, false) matching OptionConnectTimeout", raw, d)
			}
		}
	})

	t.Run("CanonicalizeHost_does_not_accept_0m_or_00_over_valid_timeout", func(t *testing.T) {
		t.Parallel()
		const sshCfg = `
Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    ConnectTimeout 1
`
		parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		provider := NewProviderWithOpenSSHParser(nil, parser)

		for _, raw := range invalidValues {
			res := &p7DeadlineCaptureResolver{}
			_, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
				Provider:      provider,
				Host:          "app",
				RawCLIOptions: []string{"ConnectTimeout=" + raw},
				Resolver:      res,
			})
			if err == nil && res.hasDL && res.remaining > 2*time.Second {
				t.Errorf("MED-8: CanonicalizeHost accepted invalid ConnectTimeout=%q and overrode 1s timeout to ~%v", raw, res.remaining.Round(time.Millisecond))
			}
		}
	})
}

// TestP7Repro_MED13_IncludeBudget_CountsGlobFanOutDirsAndDanglingSymlinks reproduces MED-13:
// Include glob fan-out over directories, dangling symlinks, and active-cycle symlinks
// performs unbounded Stat / EvalSymlinks probes without charging includeBudget.
func TestP7Repro_MED13_IncludeBudget_CountsGlobFanOutDirsAndDanglingSymlinks(t *testing.T) {
	t.Parallel()

	const fanOutCount = 2100

	t.Run("directory_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "dirs")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		for i := range fanOutCount {
			if err := os.Mkdir(filepath.Join(incDir, fmt.Sprintf("d-%04d", i)), 0o700); err != nil {
				t.Fatalf("Mkdir %d: %v", i, err)
			}
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d directories succeeded without tripping include budget", fanOutCount)
		}
	})

	t.Run("dangling_symlink_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "dangling")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		missingTarget := filepath.Join(baseDir, "does-not-exist")
		for i := range fanOutCount {
			linkPath := filepath.Join(incDir, fmt.Sprintf("l-%04d", i))
			if err := os.Symlink(missingTarget, linkPath); err != nil {
				t.Skipf("os.Symlink unsupported: %v", err)
			}
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d dangling symlinks succeeded without tripping include budget", fanOutCount)
		}
	})

	t.Run("active_cycle_symlink_glob_fanout_counts_against_budget", func(t *testing.T) {
		t.Parallel()
		baseDir := t.TempDir()
		incDir := filepath.Join(baseDir, "cycles")
		if err := os.MkdirAll(incDir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		cfgPath := filepath.Join(baseDir, "ssh_config")
		cfgText := fmt.Sprintf("Include %s/*\nHost app\n    HostName 10.0.0.1\n", incDir)
		if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		for i := range fanOutCount {
			linkPath := filepath.Join(incDir, fmt.Sprintf("c-%04d", i))
			if err := os.Symlink(cfgPath, linkPath); err != nil {
				t.Skipf("os.Symlink unsupported: %v", err)
			}
		}

		if _, err := NewOpenSSHParserFromPath(cfgPath); err == nil {
			t.Fatalf("MED-13: Include glob over %d cycle symlinks succeeded without tripping include budget", fanOutCount)
		}
	})
}

// TestP7Repro_MED14_ProxyJumpAndTargetRef_DoublePrefixAndCaseDrift reproduces MED-14:
// ResolveProxyJumpChain accepts and emits double-prefixed `openssh:openssh:22`, and
// `OPENSSH:` prefix handling drifts in case sensitivity across ResolveProxyJumpChain,
// ParseTargetRef, and IsOpenSSHNodeID.
func TestP7Repro_MED14_ProxyJumpAndTargetRef_DoublePrefixAndCaseDrift(t *testing.T) {
	t.Parallel()

	emptyCfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	emptyParser := &OpenSSHParser{}

	t.Run("ResolveProxyJumpChain_rejects_openssh_openssh_22", func(t *testing.T) {
		t.Parallel()
		got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "openssh:openssh:22")
		if err == nil {
			t.Fatalf("MED-14: ResolveProxyJumpChain(\"openssh:openssh:22\") accepted and emitted %q, want error", got)
		}
	})

	t.Run("ResolveProxyJumpChain_fallback_does_not_emit_double_prefix", func(t *testing.T) {
		t.Parallel()
		cfg := &Configuration{
			Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
			Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
			Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		}
		cfg.Hosts.Set("h-ossh", models.Host{Address: "openssh", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("box", models.Node{HostRef: "h-ossh", IdentityRef: "id1"})

		got, err := ResolveProxyJumpChainWithConfig(cfg, emptyParser, "box:2222")
		if err == nil && strings.HasPrefix(strings.ToLower(got), "openssh:openssh:") {
			t.Fatalf("MED-14: ResolveProxyJumpChain(\"box:2222\") emitted double-prefixed %q", got)
		}
	})

	t.Run("OPENSSH_uppercase_case_drift_in_ProxyJump_and_TargetRef", func(t *testing.T) {
		t.Parallel()

		if got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "openssh:OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ResolveProxyJumpChain(\"openssh:OPENSSH:22\") accepted and emitted %q, want error", got)
		}
		if got, err := ResolveProxyJumpChainWithConfig(emptyCfg, emptyParser, "OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ResolveProxyJumpChain(\"OPENSSH:22\") accepted and emitted %q instead of treating OPENSSH: as reserved prefix", got)
		}
		if ref, err := ParseTargetRef("OPENSSH:bastion"); err != nil || !ref.OpenSSH || ref.Host != "bastion" {
			t.Errorf("MED-14: ParseTargetRef(\"OPENSSH:bastion\") = (%+v, %v), want OpenSSH=true Host=\"bastion\" (case-insensitive prefix)", ref, err)
		}
		if ref, err := ParseTargetRef("openssh:OPENSSH:22"); err == nil {
			t.Errorf("MED-14: ParseTargetRef(\"openssh:OPENSSH:22\") accepted double prefix as %+v, want error", ref)
		}
		if !IsOpenSSHNodeID("OPENSSH:bastion") {
			t.Errorf("MED-14: IsOpenSSHNodeID(\"OPENSSH:bastion\") = false, want true (case-insensitive parity with ValidateNodeAlias)")
		}
	})
}

// TestP7Repro_LOW2_ValidateNodeAlias_RejectsAtColonAndControlChars reproduces LOW-2:
// ValidateNodeAlias accepts '@', ':', and ASCII control characters that CLI alias
// validation (and safe persistence boundaries) must reject.
func TestP7Repro_LOW2_ValidateNodeAlias_RejectsAtColonAndControlChars(t *testing.T) {
	t.Parallel()

	badAliases := []string{
		"ops@web",
		"web:2222",
		"web\nprod",
		"web\rprod",
		"web\x00prod",
		"web\tprod",
	}

	t.Run("ValidateNodeAlias_direct", func(t *testing.T) {
		t.Parallel()
		for _, alias := range badAliases {
			if err := ValidateNodeAlias(alias); err == nil {
				t.Errorf("LOW-2: ValidateNodeAlias(%q) = nil, want error", alias)
			}
		}
	})

	t.Run("ValidateV2_and_Repository_reject_invalid_Node_Alias", func(t *testing.T) {
		t.Parallel()
		for _, alias := range badAliases {
			cfgV2 := &ConfigurationV2{
				SchemaVersion: 2,
				Credential:    CredentialConfig{Stores: map[string]StoreConfig{}},
				Hosts:         map[string]models.Host{"h1": {Address: "10.0.0.1", Port: 22}},
				Identities:    map[string]IdentityV2{"id1": {User: "ops", AuthType: "auto"}},
				Nodes: map[string]NodeV2{
					"web-node": {
						HostRef:     "h1",
						IdentityRef: "id1",
						Alias:       []string{alias},
						SudoMode:    models.SudoModeAuto,
					},
				},
			}
			if err := ValidateV2(cfgV2); err == nil {
				t.Errorf("LOW-2: ValidateV2 accepted invalid Node.Alias %q", alias)
			}

			repo := newP7MemoryRepo(t, nil)
			if _, err := repo.CreateNodeContext(
				t.Context(),
				"web-node",
				models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{alias}, SudoMode: models.SudoModeAuto},
				models.Host{Address: "10.0.0.1", Port: 22},
				models.Identity{User: "ops", AuthType: "auto"},
			); err == nil {
				t.Errorf("LOW-2: Repository.CreateNodeContext accepted invalid Node.Alias %q", alias)
			}
		}
	})
}

// TestP7Repro_LOW3_SendEnvNegativeWildcard_DifferentialAgainstOpenSSH reproduces LOW-3:
// OpenSSH `SendEnv -PATTERN` removes previously added patterns matching PATTERN at config
// parse/merge time (pattern-against-pattern), whereas xops evaluates `-PATTERN` as a
// runtime negative rule against environment variable names.
func TestP7Repro_LOW3_SendEnvNegativeWildcard_DifferentialAgainstOpenSSH(t *testing.T) {
	sshBin := requireOpenSSHBinary(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "sendenv_diff.conf")
	writeCfgFile(t, cfgPath, `
Host neg-literal-vs-wild
    HostName 10.10.0.1
    User ops
    SendEnv FOO_*
    SendEnv -FOO_SECRET

Host neg-narrow-vs-broad
    HostName 10.10.0.2
    User ops
    SendEnv APP_*
    SendEnv -APP_DEV_*
`)

	parser, err := NewOpenSSHParserFromPath(cfgPath)
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromPath: %v", err)
	}

	cases := []struct {
		host    string
		envKeys []string
	}{
		{
			host:    "neg-literal-vs-wild",
			envKeys: []string{"FOO_PUBLIC", "FOO_SECRET", "OTHER"},
		},
		{
			host:    "neg-narrow-vs-broad",
			envKeys: []string{"APP_PROD_KEY", "APP_DEV_KEY", "OTHER"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			dump := runSSHConfigDump(t, sshBin, cfgPath, tc.host)
			opts, err := parser.GetSSHOptions(tc.host)
			if err != nil {
				t.Fatalf("GetSSHOptions(%q): %v", tc.host, err)
			}

			gotVars, err := ssh.ResolveSessionEnv(opts, func() []string {
				out := make([]string, 0, len(tc.envKeys))
				for _, k := range tc.envKeys {
					out = append(out, k+"=1")
				}
				return out
			})
			if err != nil {
				t.Fatalf("ResolveSessionEnv(%q): %v", tc.host, err)
			}
			var gotNames []string
			for _, ev := range gotVars {
				gotNames = append(gotNames, ev.Name)
			}

			wantSend := dump["sendenv"]
			var wantNames []string
			for _, k := range tc.envKeys {
				for _, pat := range wantSend {
					if ok, _ := filepath.Match(pat, k); ok {
						wantNames = append(wantNames, k)
						break
					}
				}
			}
			slices.Sort(gotNames)
			slices.Sort(wantNames)

			if !slices.Equal(gotNames, wantNames) {
				t.Fatalf("LOW-3: SendEnv -PATTERN semantics diverged from `ssh -G` for %q: xops resolved=%v (patterns=%v), ssh -G resolved=%v (sendenv=%v)",
					tc.host, gotNames, opts.SendEnvPatterns(), wantNames, wantSend)
			}
		})
	}
}
