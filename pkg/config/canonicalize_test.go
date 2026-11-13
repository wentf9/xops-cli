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
		policy := resolveCanonicalizePolicy(nil, tier3Opts, "web", nil, "")
		if policy.mode != "yes" || !slices.Equal(policy.domains, []string{"tier3.example.com"}) || policy.timeout != 2*time.Second {
			t.Fatalf("unexpected Tier 3 policy: %+v", policy)
		}
		policyLarge := resolveCanonicalizePolicy(parser, nil, "web", []string{"ConnectTimeout=30"}, "")
		if policyLarge.timeout != maxCanonicalProbeTimeout {
			t.Fatalf("expected timeout capped at %v, got %v", maxCanonicalProbeTimeout, policyLarge.timeout)
		}
	})
}
