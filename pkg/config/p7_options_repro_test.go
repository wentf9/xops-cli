package config

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

// TestP7Repro_MED6_OpenSSHAllowList_BareModifiersAndInvalidTokensError verifies MED-6:
// bare algorithm modifiers (`Ciphers -`, `Ciphers +`, `KexAlgorithms ^`) and malformed
// negated tokens (`MACs -bad!mac`) return errors from OpenSSH config parsing.
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
// verifies the first half of MED-8: when Tier-4 defines both ProxyJump and a lower
// ProxyCommand, CLI `-o ProxyJump=none` / `-J none` cancels Tier-4 ProxyJump, exposing
// the active lower ProxyCommand which suppresses CanonicalizeHostname=yes DNS canonicalization.
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

// TestP7Repro_MED8_ConnectTimeoutParity_0m_00 verifies the second half of MED-8:
// canonicalize shares the single core/ssh.ParseOption parser and rejects "0m" and "00"
// consistently with core/ssh OptionConnectTimeout instead of overriding valid lower timeouts.
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

	t.Run("ParseOption_and_resolveCanonicalizePolicy_reject_0m_and_00", func(t *testing.T) {
		t.Parallel()
		t3 := ssh.MustOptions(ssh.OptionConnectTimeout, "1")
		for _, raw := range invalidValues {
			if _, err := ssh.ParseOption(ssh.OptionConnectTimeout, raw, ssh.OptionSourceCLI); err == nil {
				t.Errorf("MED-8: ParseOption(ConnectTimeout, %q) = nil, want error", raw)
			}
			pol, err := resolveCanonicalizePolicy(nil, t3, "app", []string{"ConnectTimeout=" + raw}, "")
			if err != nil || pol.timeout != time.Second {
				t.Errorf("MED-8: resolveCanonicalizePolicy(ConnectTimeout=%q).timeout = (%v, %v), want 1s", raw, pol.timeout, err)
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

// TestP7Repro_LOW3_SendEnvNegativeWildcard_DifferentialAgainstOpenSSH verifies LOW-3:
// OpenSSH `SendEnv -PATTERN` removes previously added patterns matching PATTERN at config
// parse/merge time (pattern-against-pattern), matching `ssh -G` differential output.
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
