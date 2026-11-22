package config

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

type fakeCanonicalResolver struct {
	hosts   map[string][]string
	cnames  map[string]string
	queried []string
}

func (f *fakeCanonicalResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.queried = append(f.queried, host)
	if addrs, ok := f.hosts[host]; ok && len(addrs) > 0 {
		return addrs, nil
	}
	return nil, errors.New("no such host")
}

func (f *fakeCanonicalResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if cname, ok := f.cnames[host]; ok {
		return cname, nil
	}
	return host + ".", nil
}

func TestCanonicalizeHost_TwoPassAndFilters(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *.corp.example.com
    User corp-user
    ConnectTimeout 15
    StrictHostKeyChecking no
    HashKnownHosts yes

Host *
    CanonicalizeHostname yes
    CanonicalDomains dev.example.com corp.example.com
    CanonicalizeMaxDots 1
    CanonicalizeFallbackLocal yes
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("probes domains in order and runs bounded Pass 2 with Gate 1 intact", func(t *testing.T) {
		res := &fakeCanonicalResolver{
			hosts: map[string][]string{
				"web.corp.example.com": {"10.20.30.40"},
			},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "web",
			Resolver: res,
		})
		if err != nil {
			t.Fatalf("CanonicalizeHost() error = %v", err)
		}
		if !out.Canonicalized || out.OriginalHost != "web" || out.CanonicalHost != "web.corp.example.com" {
			t.Fatalf("unexpected canonicalize result: %+v", out)
		}
		wantQueried := []string{"web.dev.example.com", "web.corp.example.com"}
		if !slices.Equal(res.queried, wantQueried) {
			t.Fatalf("queried = %v, want %v", res.queried, wantQueried)
		}
		if out.Pass2Options == nil || out.Pass2Options.Get(ssh.OptionConnectTimeout) != "15" {
			t.Fatalf("expected Pass2Options ConnectTimeout=15, got %+v", out.Pass2Options)
		}
		if out.Pass2Options.Get("strict_host_key_checking") != "" {
			t.Fatalf("Gate 1 violation: StrictHostKeyChecking leaked into Pass2Options")
		}
		if out.Pass2Options.Get(ssh.OptionHashKnownHosts) != "yes" {
			t.Fatalf("expected HashKnownHosts=yes in Pass2Options, got %q", out.Pass2Options.Get(ssh.OptionHashKnownHosts))
		}
	})

	t.Run("skips IP literal, localhost, matched saved node, and max dots", func(t *testing.T) {
		for _, tc := range []struct {
			name             string
			host             string
			matchedSavedNode bool
		}{
			{name: "IPv4", host: "192.168.1.10"},
			{name: "IPv6", host: "2001:db8::1"},
			{name: "localhost", host: "localhost"},
			{name: "saved node", host: "web", matchedSavedNode: true},
			{name: "exceeds max dots", host: "a.b.c"},
		} {
			res := &fakeCanonicalResolver{hosts: map[string][]string{"a.b.c.corp.example.com": {"1.2.3.4"}}}
			out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
				Provider:         provider,
				Host:             tc.host,
				MatchedSavedNode: tc.matchedSavedNode,
				Resolver:         res,
			})
			if err != nil {
				t.Fatalf("%s: unexpected error = %v", tc.name, err)
			}
			if out.Canonicalized || len(res.queried) != 0 {
				t.Fatalf("%s: expected no canonicalization or DNS queries, got out=%+v queried=%v", tc.name, out, res.queried)
			}
		}
	})
}

func TestCanonicalizeHost_ProxySkipsUnlessAlways(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *
    CanonicalizeHostname yes
    CanonicalDomains dev.example.com corp.example.com
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("ProxyJump, CLI -J, and ProxyCommand skip when yes but run when always", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			in   CanonicalizeInput
		}{
			{
				name: "-o ProxyJump",
				in:   CanonicalizeInput{Provider: provider, Host: "web", RawCLIOptions: []string{"ProxyJump=bastion"}},
			},
			{
				name: "CLI -J",
				in:   CanonicalizeInput{Provider: provider, Host: "web", CLIProxyJump: "bastion"},
			},
			{
				name: "-o ProxyCommand",
				in:   CanonicalizeInput{Provider: provider, Host: "web", RawCLIOptions: []string{"ProxyCommand=ssh -W %h:%p bastion"}},
			},
		} {
			res := &fakeCanonicalResolver{hosts: map[string][]string{"web.corp.example.com": {"10.20.30.40"}}}
			tc.in.Resolver = res
			out, err := CanonicalizeHost(t.Context(), tc.in)
			if err != nil || out.Canonicalized || len(res.queried) != 0 {
				t.Fatalf("%s: expected skip, got out=%+v err=%v queried=%v", tc.name, out, err, res.queried)
			}
		}

		resAlways := &fakeCanonicalResolver{hosts: map[string][]string{"web.corp.example.com": {"10.20.30.40"}}}
		outAlways, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "web",
			CLIProxyJump:  "bastion",
			RawCLIOptions: []string{"CanonicalizeHostname=always"},
			Resolver:      resAlways,
		})
		if err != nil || !outAlways.Canonicalized || outAlways.CanonicalHost != "web.corp.example.com" {
			t.Fatalf("expected CanonicalizeHostname=always to canonicalize despite -J, got %+v err=%v", outAlways, err)
		}
	})
}

func TestCanonicalizeHost_CNAMEFallbackAndTimeout(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *.internal.corp.example.com
    ConnectTimeout 7

Host *
    CanonicalizeHostname yes
    CanonicalDomains dev.example.com corp.example.com
    CanonicalizeMaxDots 1
    CanonicalizeFallbackLocal yes
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("CanonicalizePermittedCNAMEs adopts permitted CNAME and keeps fqdn otherwise", func(t *testing.T) {
		resPermitted := &fakeCanonicalResolver{
			hosts: map[string][]string{"web.corp.example.com": {"10.2.2.2"}},
			cnames: map[string]string{
				"web.corp.example.com": "web-lb.internal.corp.example.com.",
			},
		}
		outPermitted, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "web",
			RawCLIOptions: []string{"CanonicalizePermittedCNAMEs=*.corp.example.com:*.internal.corp.example.com"},
			Resolver:      resPermitted,
		})
		if err != nil || !outPermitted.Canonicalized || outPermitted.CanonicalHost != "web-lb.internal.corp.example.com" {
			t.Fatalf("expected permitted CNAME adopted, got %+v err=%v", outPermitted, err)
		}
		if outPermitted.Pass2Options == nil || outPermitted.Pass2Options.Get(ssh.OptionConnectTimeout) != "7" {
			t.Fatalf("expected Pass2Options matched on CNAME target, got %+v", outPermitted.Pass2Options)
		}

		resDenied := &fakeCanonicalResolver{
			hosts: map[string][]string{"web.dev.example.com": {"10.1.1.1"}},
			cnames: map[string]string{
				"web.dev.example.com": "evil.external.net.",
			},
		}
		outDenied, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "web",
			RawCLIOptions: []string{"CanonicalizePermittedCNAMEs=*.corp.example.com:*.internal.corp.example.com"},
			Resolver:      resDenied,
		})
		if err != nil || !outDenied.Canonicalized || outDenied.CanonicalHost != "web.dev.example.com" {
			t.Fatalf("expected non-permitted CNAME to keep fqdn (not skip), got %+v err=%v", outDenied, err)
		}
	})

	t.Run("CanonicalizeFallbackLocal=no returns ErrCanonicalizeFailed when no domain resolves", func(t *testing.T) {
		res := &fakeCanonicalResolver{}
		_, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "missing",
			RawCLIOptions: []string{"CanonicalizeFallbackLocal=no"},
			Resolver:      res,
		})
		if !errors.Is(err, ErrCanonicalizeFailed) {
			t.Fatalf("expected ErrCanonicalizeFailed, got %v", err)
		}
		wantQueried := []string{"missing.dev.example.com", "missing.corp.example.com"}
		if !slices.Equal(res.queried, wantQueried) {
			t.Fatalf("queried = %v, want %v", res.queried, wantQueried)
		}
	})

	t.Run("Tier 3 Snapshot().SSHOptions and ConnectTimeout cap", func(t *testing.T) {
		tier3Opts, _ := ssh.NewOptions()
		_ = tier3Opts.Set(ssh.OptionCanonicalizeHostname, "yes")
		_ = tier3Opts.Set(ssh.OptionCanonicalDomains, "tier3.example.com")
		_ = tier3Opts.Set(ssh.OptionConnectTimeout, "2")
		policy, err := resolveCanonicalizePolicy(nil, tier3Opts, "web", nil, "")
		if err != nil || policy.mode != "yes" || !slices.Equal(policy.domains, []string{"tier3.example.com"}) || policy.timeout != 2*time.Second {
			t.Fatalf("unexpected Tier 3 policy: (%+v, %v)", policy, err)
		}
		policyLarge, err := resolveCanonicalizePolicy(parser, nil, "web", []string{"ConnectTimeout=30"}, "")
		if err != nil || policyLarge.timeout != maxCanonicalProbeTimeout {
			t.Fatalf("expected timeout capped at %v, got (%v, %v)", maxCanonicalProbeTimeout, policyLarge.timeout, err)
		}
	})
}

func TestCanonicalizeHost_ProxyNoneAndEdgeCases(t *testing.T) {
	t.Parallel()

	const proxyCfg = `
Host cmd-host
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    ProxyCommand nc %h %p

Host jump-host
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    ProxyJump bastion
`
	proxyParser, err := NewOpenSSHParserFromReader(strings.NewReader(proxyCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	proxyProv := NewProviderWithOpenSSHParser(nil, proxyParser)

	assertCanon := func(t *testing.T, prov ConfigProvider, host string, cliOpts []string, cliJump string, wantCanon bool, wantHost string, wantQueries bool) {
		t.Helper()
		res := &fakeCanonicalResolver{hosts: map[string][]string{host + ".corp.example.com": {"10.0.0.1"}}}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      prov,
			Host:          host,
			RawCLIOptions: cliOpts,
			CLIProxyJump:  cliJump,
			Resolver:      res,
		})
		if err != nil || out.Canonicalized != wantCanon || (wantHost != "" && out.CanonicalHost != wantHost) || (!wantQueries && len(res.queried) != 0) {
			t.Fatalf("CanonicalizeHost(%q, opts=%v, jump=%q) = %+v queried=%v err=%v", host, cliOpts, cliJump, out, res.queried, err)
		}
	}

	t.Run("M10 proxy-none CLI precedence matches OpenSSH ProxySetting monoid", func(t *testing.T) {
		testCanonicalizeProxyNoneCLIPrecedence(t, proxyParser, proxyProv, assertCanon)
	})

	t.Run("M10 proxy-none tier-3 global interaction", func(t *testing.T) {
		testCanonicalizeProxyNoneTier3(t, proxyParser, assertCanon)
	})
}

func testCanonicalizeProxyNoneCLIPrecedence(
	t *testing.T,
	proxyParser *OpenSSHParser,
	proxyProv ConfigProvider,
	assertCanon func(*testing.T, ConfigProvider, string, []string, string, bool, string, bool),
) {
	t.Helper()
	assertCanon(t, proxyProv, "cmd-host", []string{"ProxyCommand=none"}, "", true, "cmd-host.corp.example.com", true)
	assertCanon(t, proxyProv, "cmd-host", nil, "none", false, "", false)
	// OpenSSH ProxyCommand=none disables both ProxyCommand and lower ProxyJump.
	assertCanon(t, proxyProv, "jump-host", []string{"ProxyCommand=none"}, "", true, "jump-host.corp.example.com", true)

	p, err := resolveCanonicalizePolicy(proxyParser, nil, "cmd-host", nil, "bastion")
	if err != nil || !p.hasProxyJump || p.hasProxyCommand {
		t.Fatalf("expected CLI ProxyJump to override lower-tier ProxyCommand, got (%+v, %v)", p, err)
	}
}

func testCanonicalizeProxyNoneTier3(
	t *testing.T,
	proxyParser *OpenSSHParser,
	assertCanon func(*testing.T, ConfigProvider, string, []string, string, bool, string, bool),
) {
	t.Helper()
	t3CmdOpts, _ := ssh.NewOptions()
	if err := t3CmdOpts.Set(ssh.OptionProxyCommand, "nc %h %p"); err != nil {
		t.Fatalf("t3CmdOpts.Set(ProxyCommand) error = %v", err)
	}
	pT3, err := resolveCanonicalizePolicy(proxyParser, t3CmdOpts, "jump-host", nil, "none")
	if err != nil || pT3.hasProxyJump || !pT3.hasProxyCommand {
		t.Fatalf("expected Tier 3 ProxyCommand to remain active when CLI -J none cancels Tier 4 ProxyJump, got (%+v, %v)", pT3, err)
	}
	assertCanon(t, NewProviderWithOpenSSHParser(&Configuration{SSHOptions: t3CmdOpts}, proxyParser), "jump-host", nil, "none", false, "", false)

	t3NoneOpts, _ := ssh.NewOptions()
	if err := t3NoneOpts.Set(ssh.OptionProxyCommand, "none"); err != nil {
		t.Fatalf("t3NoneOpts.Set(ProxyCommand=none) error = %v", err)
	}
	if p, err := resolveCanonicalizePolicy(proxyParser, t3NoneOpts, "cmd-host", nil, ""); err != nil || p.hasProxyCommand {
		t.Fatalf("expected Tier 3 ProxyCommand=none to clear Tier 4 ProxyCommand, got (%+v, %v)", p, err)
	}
	// Under ProxySetting monoid (matching OpenSSH), ProxyCommand=none absorbs lower ProxyJump.
	if p, err := resolveCanonicalizePolicy(proxyParser, t3NoneOpts, "jump-host", nil, ""); err != nil || p.hasProxyJump || p.hasProxyCommand {
		t.Fatalf("expected Tier 3 ProxyCommand=none to disable Tier 4 ProxyJump, got (%+v, %v)", p, err)
	}
}

func TestCanonicalizeHost_EdgeCases(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host *
    CanonicalizeHostname yes
    CanonicalDomains dev.example.com corp.example.com
    CanonicalizeMaxDots 1
    CanonicalizeFallbackLocal yes
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("M11 zoned IPv6, trailing-dot FQDN, and empty CanonicalDomains CNAME", func(t *testing.T) {
		resZone := &fakeCanonicalResolver{hosts: map[string][]string{"fe80::1%eth0.corp.example.com": {"fe80::1"}}}
		outZone, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "fe80::1%eth0",
			Resolver: resZone,
		})
		if err != nil || outZone.Canonicalized || len(resZone.queried) != 0 {
			t.Fatalf("expected zoned IPv6 to skip canonicalization, got %+v queried=%v err=%v", outZone, resZone.queried, err)
		}

		resDot := &fakeCanonicalResolver{
			hosts: map[string][]string{"web..corp.example.com": {"10.0.0.1"}},
		}
		outDot, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "web.",
			RawCLIOptions: []string{"CanonicalizeFallbackLocal=no"},
			Resolver:      resDot,
		})
		if err != nil || outDot.Canonicalized {
			t.Fatalf("expected trailing-dot FQDN not to append domain or fail, got %+v err=%v", outDot, err)
		}
		for _, q := range resDot.queried {
			if strings.Contains(q, "..") {
				t.Fatalf("unexpected double-dot query %q", q)
			}
		}

		const cnameOnlyCfg = `
Host *
    CanonicalizeHostname yes
    CanonicalizeMaxDots 2
    CanonicalizePermittedCNAMEs *.example.com:*.internal.example.com
`
		cnameParser, err := NewOpenSSHParserFromReader(strings.NewReader(cnameOnlyCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
		}
		cnameProv := NewProviderWithOpenSSHParser(nil, cnameParser)
		resCNAME := &fakeCanonicalResolver{
			hosts:  map[string][]string{"app.example.com": {"10.0.0.5"}},
			cnames: map[string]string{"app.example.com": "app-real.internal.example.com."},
		}
		outCNAME, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: cnameProv,
			Host:     "app.example.com",
			Resolver: resCNAME,
		})
		if err != nil || !outCNAME.Canonicalized || outCNAME.CanonicalHost != "app-real.internal.example.com" {
			t.Fatalf("expected direct CNAME canonicalization with empty CanonicalDomains, got %+v err=%v", outCNAME, err)
		}
	})
}

func TestCanonicalizeHost_FailClosedAndTwoPassEdgeCases(t *testing.T) {
	t.Parallel()
	t.Run("P1-2 P1-4 P1-8 P2-2.5 broken parser, CNAME negation, Pass-1 HostName, and = syntax", func(t *testing.T) {
		brokenProv := NewProviderWithOpenSSHParser(nil, NewBrokenOpenSSHParser(errors.New("broken ssh config")))
		if _, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: brokenProv,
			Host:     "web",
		}); err == nil {
			t.Fatal("expected broken parser to fail closed when !MatchedSavedNode")
		}
		if outSaved, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:         brokenProv,
			Host:             "web",
			MatchedSavedNode: true,
		}); err != nil || outSaved.Canonicalized {
			t.Fatalf("expected MatchedSavedNode to skip broken parser, got out=%+v err=%v", outSaved, err)
		}

		const cfgText = `
Host ipalias
    HostName 10.20.30.40

Host prod
    HostName web

Host *
    CanonicalizeHostname yes
    CanonicalDomains corp.example.com
    CanonicalizeMaxDots 2
    CanonicalizeFallbackLocal yes
    CanonicalizePermittedCNAMEs *.corp.example.com:!blocked.cdn.net,*.cdn.net
`
		p2, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov2 := NewProviderWithOpenSSHParser(nil, p2)

		// Pass-1 HostName resolving to an IP skips canonicalization.
		resIP := &fakeCanonicalResolver{hosts: map[string][]string{"ipalias.corp.example.com": {"1.2.3.4"}}}
		outIP, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: prov2,
			Host:     "ipalias",
			Resolver: resIP,
		})
		if err != nil || outIP.Canonicalized || len(resIP.queried) != 0 {
			t.Fatalf("expected HostName IP to skip canonicalization, got out=%+v queried=%v err=%v", outIP, resIP.queried, err)
		}

		// Pass-1 HostName "web" is probed for Host "prod", preserving OriginalHost "prod".
		resHN := &fakeCanonicalResolver{hosts: map[string][]string{"web.corp.example.com": {"10.5.5.5"}}}
		outHN, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: prov2,
			Host:     "prod",
			Resolver: resHN,
		})
		if err != nil || !outHN.Canonicalized || outHN.OriginalHost != "prod" || outHN.CanonicalHost != "web.corp.example.com" {
			t.Fatalf("CanonicalizeHost(prod -> web) = %+v, err=%v", outHN, err)
		}

		// !negated pattern in CanonicalizePermittedCNAMEs blocks blocked.cdn.net while allowing ok.cdn.net.
		resBlocked := &fakeCanonicalResolver{
			hosts:  map[string][]string{"web.corp.example.com": {"10.5.5.5"}},
			cnames: map[string]string{"web.corp.example.com": "blocked.cdn.net."},
		}
		outBlocked, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: prov2,
			Host:     "web",
			Resolver: resBlocked,
		})
		if err != nil || outBlocked.CanonicalHost != "web.corp.example.com" {
			t.Fatalf("expected negated CNAME blocked.cdn.net to be rejected, got %+v err=%v", outBlocked, err)
		}
		resAllowed := &fakeCanonicalResolver{
			hosts:  map[string][]string{"web.corp.example.com": {"10.5.5.5"}},
			cnames: map[string]string{"web.corp.example.com": "edge.cdn.net."},
		}
		outAllowed, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: prov2,
			Host:     "web",
			Resolver: resAllowed,
		})
		if err != nil || outAllowed.CanonicalHost != "edge.cdn.net" {
			t.Fatalf("expected positive CNAME edge.cdn.net to be permitted, got %+v err=%v", outAllowed, err)
		}

		// Space around '=' in RawCLIOptions and duration-aware ConnectTimeout.
		polCLI, err := resolveCanonicalizePolicy(p2, nil, "ipalias", []string{
			"CanonicalizeHostname = no",
			"ConnectTimeout = 2s",
		}, "")
		if err != nil || polCLI.mode != "no" || polCLI.timeout != 2*time.Second {
			t.Fatalf("unexpected space-around-'=' / duration policy: mode=%q timeout=%v err=%v", polCLI.mode, polCLI.timeout, err)
		}
	})
}

func TestCanonicalizeHost_Round2PolicyAndFallbackFixes(t *testing.T) {
	t.Run("local fallback without CNAME retains Canonicalized=false even when Pass1 HostName differs", testCanonicalizeRound2LocalFallback)
	t.Run("tier3 none clears tier4 domains and permitted CNAMEs", testCanonicalizeRound2Tier3None)
	t.Run("ProxyCommand=none allows ProxyJump=none to clear tier4 jump while blocking ProxyJump=bastion", testCanonicalizeRound2ProxyCommandNone)
	t.Run("ConnectTimeout none/0/0s resets and large valid duration clamps without overflow", testCanonicalizeRound2ConnectTimeout)
}

func testCanonicalizeRound2LocalFallback(t *testing.T) {
	cfg := strings.Join([]string{
		"Host prod",
		"  HostName web.internal",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
		"  CanonicalizeFallbackLocal yes",
	}, "\n") + "\n"
	p, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	prov := NewProviderWithOpenSSHParser(nil, p)
	res := &fakeCanonicalResolver{hosts: map[string][]string{"web.internal": {"10.1.2.3"}}}
	out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider: prov,
		Host:     "prod",
		Resolver: res,
	})
	if err != nil {
		t.Fatalf("CanonicalizeHost: %v", err)
	}
	if out.Canonicalized || out.CanonicalHost != "prod" {
		t.Fatalf("local fallback without CNAME mutated Canonicalized: %+v", out)
	}
}

func testCanonicalizeRound2Tier3None(t *testing.T) {
	cfg := strings.Join([]string{
		"Host web",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
		"  CanonicalizePermittedCNAMEs *:*.cdn.net",
	}, "\n") + "\n"
	p, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := ssh.NewOptions()
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(ssh.OptionCanonicalDomains, "none"); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(ssh.OptionCanonicalizePermittedCNAMEs, "none"); err != nil {
		t.Fatal(err)
	}
	pol, err := resolveCanonicalizePolicy(p, opts, "web", nil, "")
	if err != nil || len(pol.domains) != 0 || len(pol.permittedCNAMEs) != 0 {
		t.Fatalf("Tier-3 none did not clear Tier-4 policy: domains=%v cnames=%v err=%v", pol.domains, pol.permittedCNAMEs, err)
	}
}

func testCanonicalizeRound2ProxyCommandNone(t *testing.T) {
	cfg := strings.Join([]string{
		"Host web",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
		"  ProxyJump tier4-bastion",
	}, "\n") + "\n"
	p, err := NewOpenSSHParserFromReader(strings.NewReader(cfg))
	if err != nil {
		t.Fatal(err)
	}

	polCleared, err := resolveCanonicalizePolicy(p, nil, "web", []string{"ProxyCommand=none", "ProxyJump=none"}, "")
	if err != nil || polCleared.hasProxyJump || polCleared.hasProxyCommand {
		t.Fatalf("-o ProxyCommand=none -o ProxyJump=none must clear Tier-4 ProxyJump: (%+v, %v)", polCleared, err)
	}
	polBlocked, err := resolveCanonicalizePolicy(p, nil, "web", []string{"ProxyCommand=none", "ProxyJump=bastion"}, "")
	if err != nil || polBlocked.hasProxyJump || polBlocked.hasProxyCommand {
		t.Fatalf("same-tier -o ProxyCommand=none -o ProxyJump=bastion must disable proxying (OpenSSH ProxyCommand=none absorbs ProxyJump): (%+v, %v)", polBlocked, err)
	}
}

func testCanonicalizeRound2ConnectTimeout(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  time.Duration
	}{
		{input: "2", want: 2 * time.Second},
		{input: "0", want: maxCanonicalProbeTimeout},
		{input: "0s", want: maxCanonicalProbeTimeout},
		{input: "none", want: maxCanonicalProbeTimeout},
		{input: "3600s", want: maxCanonicalProbeTimeout},
	} {
		pol, err := resolveCanonicalizePolicy(nil, nil, "web", []string{"ConnectTimeout=" + tc.input}, "")
		if err != nil || pol.timeout != tc.want {
			t.Fatalf("resolveCanonicalizePolicy(ConnectTimeout=%q).timeout = (%v, %v), want %v", tc.input, pol.timeout, err, tc.want)
		}
	}
	t3 := ssh.MustOptions(ssh.OptionConnectTimeout, "2")
	for _, invalid := range []string{"-99999999999999999999", "100000000000000000000", "0m", "00"} {
		pol, err := resolveCanonicalizePolicy(nil, t3, "web", []string{"ConnectTimeout=" + invalid}, "")
		if err != nil || pol.timeout != 2*time.Second {
			t.Fatalf("invalid ConnectTimeout %q altered lower valid timeout: got (%v, %v), want 2s", invalid, pol.timeout, err)
		}
	}
}
