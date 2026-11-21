package adapter

import (
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func newP7TestConfig() *config.Configuration {
	return &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
}

// TestP7Repro_H3_IdentityFileNone_PreservesSavedPasswordAuthType verifies the
// pkg/adapter half of H3: supplying -o IdentityFile=none (which sets SessionAuth.KeyPaths
// to ["none"] or KeyPath to "none") must NOT flip a saved password-auth node's AuthType
// from "password" to "auto".
func TestP7Repro_H3_IdentityFileNone_PreservesSavedPasswordAuthType(t *testing.T) {
	t.Parallel()

	cfg := newP7TestConfig()
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("pwd-node", models.Node{HostRef: "h1", IdentityRef: "id1"})

	cases := []struct {
		name        string
		auth        SessionAuth
		rawOptFlags []string
	}{
		{
			name:        "SessionAuth_KeyPaths_none_with_option",
			auth:        SessionAuth{KeyPaths: []string{"none"}},
			rawOptFlags: []string{"IdentityFile=none"},
		},
		{
			name:        "SessionAuth_KeyPath_none_case_insensitive",
			auth:        SessionAuth{KeyPath: "NONE"},
			rawOptFlags: []string{"IdentityFile=NONE"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessionCtrl, err := ParseSessionOptions(tc.rawOptFlags, "")
			if err != nil {
				t.Fatalf("ParseSessionOptions(%v): %v", tc.rawOptFlags, err)
			}
			adp := NewSSHAdapter(
				config.NewProviderWithoutOpenSSH(cfg),
				WithSessionAuthOverride("pwd-node", tc.auth),
				WithSessionControlOverride("pwd-node", sessionCtrl),
			)
			clientCfg, err := adp.GetConfig("pwd-node")
			if err != nil {
				t.Fatalf("GetConfig(pwd-node): %v", err)
			}
			if clientCfg.AuthType != "password" {
				t.Fatalf("H3: -o IdentityFile=none flipped saved password node AuthType to %q, want %q", clientCfg.AuthType, "password")
			}
		})
	}
}

// TestP7Repro_H4_Tier4SavedManagedScope_EnforcesPort verifies H4:
// Tier-4 ProvenanceSavedManaged scoping (resolveScopedSavedOpenSSHAlias and
// savedNodeAllowsTier4Key) enforces full ssh.Endpoint equality (address + Port),
// preventing a :22 OpenSSH Host stanza from leaking onto a saved managed node at :2222.
func TestP7Repro_H4_Tier4SavedManagedScope_EnforcesPort(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host app
    HostName 10.0.0.1
    Port 22
    ControlMaster auto
    ControlPath /tmp/leaked-port22-%C
    ConnectTimeout 99

Host app-implicit22
    HostName 10.0.0.2
    ControlMaster auto
    ControlPath /tmp/leaked-implicit22-%C
    ConnectTimeout 88

Host 10.0.0.3
    Port 22
    ControlMaster auto
    ControlPath /tmp/leaked-ip22-%C
    ConnectTimeout 77

Host short.corp.example
    HostName 10.0.0.1
    Port 22
    ControlMaster auto
    ControlPath /tmp/leaked-canon22-%C
    ConnectTimeout 66
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := newP7TestConfig()
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})

	cfg.Hosts.Set("h1-2222", models.Host{Address: "10.0.0.1", Port: 2222})
	cfg.Nodes.Set("app", models.Node{HostRef: "h1-2222", IdentityRef: "id1"})
	cfg.Nodes.Set("saved-orig-2222", models.Node{HostRef: "h1-2222", IdentityRef: "id1"})
	cfg.Nodes.Set("saved-alias-2222", models.Node{
		HostRef:     "h1-2222",
		IdentityRef: "id1",
		Alias:       []string{"app"},
	})

	cfg.Hosts.Set("h2-2222", models.Host{Address: "10.0.0.2", Port: 2222})
	cfg.Nodes.Set("saved-implicit-2222", models.Node{
		HostRef:     "h2-2222",
		IdentityRef: "id1",
		Alias:       []string{"app-implicit22"},
	})

	cfg.Hosts.Set("h3-2222", models.Host{Address: "10.0.0.3", Port: 2222})
	cfg.Nodes.Set("saved-ip-2222", models.Node{
		HostRef:     "h3-2222",
		IdentityRef: "id1",
	})

	assertNoTier4Leak := func(t *testing.T, adp *SSHAdapter, nodeID, desc string) {
		t.Helper()
		pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: nodeID})
		if err != nil {
			t.Fatalf("%s: Resolve(%q) err: %v", desc, nodeID, err)
		}
		if ctrl := pol.Control(); ctrl != nil {
			t.Fatalf("H4 (%s): :22 Host stanza leaked ControlConfig onto :2222 saved node %q: %+v", desc, nodeID, ctrl)
		}
		if opts := pol.Options(); opts != nil && (opts.ControlPath() != "" || opts.Get(ssh.OptionConnectTimeout) != "") {
			t.Fatalf("H4 (%s): :22 Host stanza leaked SSHOptions onto :2222 saved node %q: ControlPath=%q ConnectTimeout=%q",
				desc, nodeID, opts.ControlPath(), opts.Get(ssh.OptionConnectTimeout))
		}
	}

	t.Run("resolveScopedSavedOpenSSHAlias_matching_nodeID_port_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))
		assertNoTier4Leak(t, adp, "app", "resolveScopedSavedOpenSSHAlias via nodeID")
	})

	t.Run("resolveScopedSavedOpenSSHAlias_session_OriginalHost_port_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(
			config.NewProviderWithOpenSSHParser(cfg, parser),
			WithSessionAuthOverride("saved-orig-2222", SessionAuth{OriginalHost: "app"}),
		)
		assertNoTier4Leak(t, adp, "saved-orig-2222", "resolveScopedSavedOpenSSHAlias via OriginalHost")
	})

	t.Run("resolveScopedSavedOpenSSHAlias_canonical_port_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(
			config.NewProviderWithOpenSSHParser(cfg, parser),
			WithSessionAuthOverride("saved-orig-2222", SessionAuth{
				OriginalHost:  "short",
				CanonicalHost: "short.corp.example",
			}),
		)
		assertNoTier4Leak(t, adp, "saved-orig-2222", "resolveScopedSavedOpenSSHAlias via CanonicalHost")
	})

	t.Run("savedNodeAllowsTier4Key_node_alias_explicit_port_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))
		assertNoTier4Leak(t, adp, "saved-alias-2222", "savedNodeAllowsTier4Key via Node.Alias")
	})

	t.Run("savedNodeAllowsTier4Key_implicit_default_port22_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))
		assertNoTier4Leak(t, adp, "saved-implicit-2222", "savedNodeAllowsTier4Key implicit Port 22")
	})

	t.Run("savedNodeAllowsTier4Key_bare_ip_port_mismatch", func(t *testing.T) {
		t.Parallel()
		adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))
		assertNoTier4Leak(t, adp, "saved-ip-2222", "savedNodeAllowsTier4Key bare IP Host stanza")
	})
}

func formatP7MasterPtr(m *ssh.ControlMasterMode) string {
	if m == nil {
		return "<nil>"
	}
	return string(*m)
}

// TestP7Repro_MED4_ParseSessionOptions_RejectsEmptyAndControlChars verifies MED-4:
// the single option parser (ParseSessionOptions / core/ssh.ParseOption) rejects
// empty `ControlMaster=` and control-character-tainted `ControlMaster=yes\n`.
func TestP7Repro_MED4_ParseSessionOptions_RejectsEmptyAndControlChars(t *testing.T) {
	t.Parallel()

	t.Run("ParseSessionOptions_rejects_empty_ControlMaster", func(t *testing.T) {
		t.Parallel()
		got, err := ParseSessionOptions([]string{"ControlMaster="}, "")
		if err == nil {
			t.Fatalf("MED-4: ParseSessionOptions(\"ControlMaster=\") succeeded with Master=%q, want error", formatP7MasterPtr(got.Master))
		}
	})

	t.Run("ParseSessionOptions_rejects_ControlMaster_with_newline", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{"ControlMaster=yes\n", "ControlMaster=\nyes", "ControlMaster=auto\r"} {
			got, err := ParseSessionOptions([]string{raw}, "")
			if err == nil {
				t.Errorf("MED-4: ParseSessionOptions(%q) succeeded with Master=%q, want error", raw, formatP7MasterPtr(got.Master))
			}
		}
	})

	t.Run("ParseOption_rejects_empty_and_newline_ControlMaster_values", func(t *testing.T) {
		t.Parallel()
		for _, val := range []string{"", "yes\n", "auto\r\n"} {
			parsed, err := ssh.ParseOption(ssh.OptionControlMaster, val, ssh.OptionSourceCLI)
			if err == nil {
				t.Errorf("MED-4: ssh.ParseOption(ControlMaster, %q) succeeded with %+v, want error", val, parsed)
			}
		}
	})
}

// TestP7Repro_MED7_MergeOptions_IdentityFileNone_Associative verifies the first
// half of MED-7: multi-stage MergeOptions is associative for IdentityFile=none
// and CertificateFile=none so lower-tier keys cannot leak after a none sentinel.
func TestP7Repro_MED7_MergeOptions_IdentityFileNone_Associative(t *testing.T) {
	t.Parallel()

	t.Run("IdentityFile_none_associativity", func(t *testing.T) {
		t.Parallel()
		a := ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/key-a")
		b := ssh.MustOptions(ssh.OptionIdentityFile, "none")
		c := ssh.MustOptions(ssh.OptionIdentityFile, "/tmp/key-c")

		left := ssh.MergeOptions(ssh.MergeOptions(a, b), c)
		right := ssh.MergeOptions(a, ssh.MergeOptions(b, c))
		flat := ssh.MergeOptions(a, b, c)

		gotLeft := left.IdentityFiles()
		gotRight := right.IdentityFiles()
		gotFlat := flat.IdentityFiles()

		if !slices.Equal(gotLeft, gotRight) || !slices.Equal(gotLeft, gotFlat) {
			t.Fatalf("MED-7: MergeOptions non-associative for IdentityFile none: ((A+B)+C)=%v, (A+(B+C))=%v, (A+B+C)=%v",
				gotLeft, gotRight, gotFlat)
		}
	})

	t.Run("CertificateFile_none_associativity", func(t *testing.T) {
		t.Parallel()
		a := ssh.MustOptions(ssh.OptionCertificateFile, "/tmp/cert-a.pub")
		b := ssh.MustOptions(ssh.OptionCertificateFile, "none")
		c := ssh.MustOptions(ssh.OptionCertificateFile, "/tmp/cert-c.pub")

		left := ssh.MergeOptions(ssh.MergeOptions(a, b), c)
		right := ssh.MergeOptions(a, ssh.MergeOptions(b, c))
		flat := ssh.MergeOptions(a, b, c)

		gotLeft := left.CertificateFiles()
		gotRight := right.CertificateFiles()
		gotFlat := flat.CertificateFiles()

		if !slices.Equal(gotLeft, gotRight) || !slices.Equal(gotLeft, gotFlat) {
			t.Fatalf("MED-7: MergeOptions non-associative for CertificateFile none: ((A+B)+C)=%v, (A+(B+C))=%v, (A+B+C)=%v",
				gotLeft, gotRight, gotFlat)
		}
	})
}

// TestP7Repro_MED7_ResolveAndGetConfig_RejectInvalidControlCombos verifies the
// second half of MED-7: the single Resolve entry point, GetControlConfig, and
// GetConfig all reject invalid control option combinations consistently.
func TestP7Repro_MED7_ResolveAndGetConfig_RejectInvalidControlCombos(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		nodeOpts *ssh.Options
		cliOpts  []string
	}{
		{
			name:    "ControlMaster_yes_without_ControlPath",
			cliOpts: []string{"ControlMaster=yes"},
		},
		{
			name:    "ControlPersist_10m_without_ControlPath",
			cliOpts: []string{"ControlPersist=10m"},
		},
		{
			name: "CrossLayer_ControlMaster_no_over_node_ControlPersist_10m",
			nodeOpts: ssh.MustOptions(
				ssh.OptionControlMaster, "auto",
				ssh.OptionControlPath, "/tmp/cm-%C",
				ssh.OptionControlPersist, "10m",
			),
			cliOpts: []string{"ControlMaster=no"},
		},
		{
			name:    "IntraLayer_ControlMaster_yes_with_ControlPath_none",
			cliOpts: []string{"ControlMaster=yes", "ControlPath=none"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := newP7TestConfig()
			cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.20", Port: 22})
			cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
			cfg.Nodes.Set("app", models.Node{
				HostRef:     "h1",
				IdentityRef: "id1",
				SSHOptions:  tc.nodeOpts.Clone(),
			})

			sc, err := ParseSessionOptions(tc.cliOpts, "")
			if err != nil {
				t.Fatalf("ParseSessionOptions(%v): %v", tc.cliOpts, err)
			}

			adp := NewSSHAdapter(
				config.NewProviderWithoutOpenSSH(cfg),
				WithSessionControlOverride("app", sc),
			)

			if ctrl, ctrlErr := adp.GetControlConfig("app"); ctrlErr == nil {
				t.Errorf("MED-7: GetControlConfig accepted invalid control combo %q (ctrl=%+v)", tc.name, ctrl)
			}
			if pol, resErr := adp.Resolve(t.Context(), ResolveRequest{NodeID: "app", SessionControl: &sc}); resErr == nil {
				t.Errorf("MED-7: Resolve accepted invalid control combo %q (opts=%+v)", tc.name, pol.Options())
			}
			if clientCfg, cfgErr := adp.GetConfig("app"); cfgErr == nil {
				t.Errorf("MED-7: GetConfig accepted invalid control combo %q (options=%+v)", tc.name, clientCfg.Options)
			}
		})
	}
}
