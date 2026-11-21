package config

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func FuzzTargetRefRoundTrip(f *testing.F) {
	seeds := []string{
		"",
		"web",
		"Prod Web 01",
		"alice@web",
		"alice@web:2222",
		"alice@corp.local@web:2202",
		"web:0022",
		"10.0.0.5:22",
		"[::1]",
		"[::1]:2222",
		"ops@[::1]:2222",
		"2001:db8::1",
		"fe80::1%eth0",
		"[fe80::1%eth0]:2222",
		"ops@[fe80::1%eth0]:2222",
		"openssh:web",
		"openssh:alice@web:2201",
		"openssh:[::1]:22",
		"openssh:fe80::1%eth0",
		"openssh:22",
		"user@openssh:22",
		"openssh:",
		"openssh: web",
		"openssh:openssh:web",
		"[invalid]",
		"host:0",
		"host:65536",
		"a:b:c",
		"web\n",
		"web\u2028",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 512 {
			return
		}
		ref, err := ParseTargetRef(raw)
		if err != nil {
			return
		}
		if err := ref.Validate(); err != nil {
			t.Fatalf("ParseTargetRef(%q) -> %+v failed Validate(): %v", raw, ref, err)
		}
		norm := ref.NormalizedString()
		if norm == "" {
			t.Fatalf("ParseTargetRef(%q) -> %+v produced empty NormalizedString()", raw, ref)
		}
		reparsed, err := ParseTargetRef(norm)
		if err != nil {
			t.Fatalf("ParseTargetRef(%q) -> %+v -> NormalizedString()=%q failed re-parse: %v", raw, ref, norm, err)
		}
		if reparsed != ref {
			t.Fatalf("TargetRef round-trip mismatch for %q (norm=%q): got %+v, want %+v", raw, norm, reparsed, ref)
		}
		if renorm := reparsed.NormalizedString(); renorm != norm {
			t.Fatalf("NormalizedString not idempotent for %q: first=%q second=%q", raw, norm, renorm)
		}
	})
}

func TestP1_CanonicalizeSkipsWastedLookupAndTrailingDotForNetResolver(t *testing.T) {
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
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	t.Run("skips fallback LookupHost when CanonicalizePermittedCNAMEs is empty", func(t *testing.T) {
		res := &fakeCanonicalResolver{
			hosts: map[string][]string{
				"web": {"10.0.0.1"},
			},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider: provider,
			Host:     "web",
			Resolver: res,
		})
		if err != nil {
			t.Fatalf("CanonicalizeHost: %v", err)
		}
		if out.Canonicalized || out.CanonicalHost != "web" {
			t.Fatalf("unexpected canonicalize result: %+v", out)
		}
		wantQueried := []string{"web.dev.example.com", "web.corp.example.com"}
		if !slices.Equal(res.queried, wantQueried) {
			t.Fatalf("queried = %v, want %v (must skip wasted fallback LookupHost for bare probeTarget)", res.queried, wantQueried)
		}
	})

	t.Run("still probes fallback when CanonicalizePermittedCNAMEs is configured", func(t *testing.T) {
		res := &fakeCanonicalResolver{
			hosts: map[string][]string{
				"web": {"10.0.0.1"},
			},
			cnames: map[string]string{
				"web": "web-real.corp.example.com.",
			},
		}
		out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
			Provider:      provider,
			Host:          "web",
			RawCLIOptions: []string{"CanonicalizePermittedCNAMEs=web:*.corp.example.com"},
			Resolver:      res,
		})
		if err != nil {
			t.Fatalf("CanonicalizeHost: %v", err)
		}
		if !out.Canonicalized || out.CanonicalHost != "web-real.corp.example.com" {
			t.Fatalf("expected fallback CNAME adoption, got %+v", out)
		}
		wantQueried := []string{"web.dev.example.com", "web.corp.example.com", "web"}
		if !slices.Equal(res.queried, wantQueried) {
			t.Fatalf("queried = %v, want %v", res.queried, wantQueried)
		}
	})

	t.Run("trailing dot applied only for real net resolvers", func(t *testing.T) {
		if got := canonicalDomainProbeName(netCanonicalResolver{}, "web.corp.example.com"); got != "web.corp.example.com." {
			t.Fatalf("netCanonicalResolver probe name = %q, want trailing dot", got)
		}
		if got := canonicalDomainProbeName(&netCanonicalResolver{}, "web.corp.example.com."); got != "web.corp.example.com." {
			t.Fatalf("already-dotted probe name = %q, want single trailing dot", got)
		}
		if got := canonicalDomainProbeName(&net.Resolver{}, "web.corp.example.com"); got != "web.corp.example.com." {
			t.Fatalf("*net.Resolver probe name = %q, want trailing dot", got)
		}
		if got := canonicalDomainProbeName(&fakeCanonicalResolver{}, "web.corp.example.com"); got != "web.corp.example.com" {
			t.Fatalf("mock resolver probe name = %q, want unchanged without trailing dot", got)
		}
	})
}

func TestP1_WildcardOpenSSHProxyJumpResolution(t *testing.T) {
	t.Parallel()

	const sshCfg = `
Host !bastion-blocked bastion-*
    HostName %h.corp.example.com
    User jumpops
    Port 2222

Host jump-ip-*
    HostName 10.90.0.10
    User ipjump

Host jump-internal-*
    HostName internal-gateway
    User intjump

Host *
    User fallback
    ServerAliveInterval 30
`
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	for _, tc := range []struct {
		hop      string
		wantID   string
		wantAddr string
		wantPort uint16
		wantUser string
	}{
		{
			hop:      "bastion-prod",
			wantID:   OpenSSHNodePrefix + "bastion-prod",
			wantAddr: "bastion-prod.corp.example.com",
			wantPort: 2222,
			wantUser: "jumpops",
		},
		{
			hop:      "openssh:bastion-prod",
			wantID:   OpenSSHNodePrefix + "bastion-prod",
			wantAddr: "bastion-prod.corp.example.com",
			wantPort: 2222,
			wantUser: "jumpops",
		},
		{
			hop:      "alice@bastion-prod:2200",
			wantID:   OpenSSHNodePrefix + "alice@bastion-prod:2200",
			wantAddr: "bastion-prod.corp.example.com",
			wantPort: 2200,
			wantUser: "alice",
		},
		{
			hop:      "jump-ip-01",
			wantID:   OpenSSHNodePrefix + "jump-ip-01",
			wantAddr: "10.90.0.10",
			wantPort: 22,
			wantUser: "ipjump",
		},
		{
			hop:      "jump-internal-01",
			wantID:   OpenSSHNodePrefix + "jump-internal-01",
			wantAddr: "internal-gateway",
			wantPort: 22,
			wantUser: "intjump",
		},
	} {
		t.Run("accept_"+tc.hop, func(t *testing.T) {
			got, err := prov.ResolveProxyJumpChain(tc.hop)
			if err != nil {
				t.Fatalf("ResolveProxyJumpChain(%q) unexpected error: %v", tc.hop, err)
			}
			if got != tc.wantID {
				t.Fatalf("ResolveProxyJumpChain(%q) = %q, want %q", tc.hop, got, tc.wantID)
			}
			_, host, ident, err := prov.Resolve(got)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", got, err)
			}
			if host.Address != tc.wantAddr || host.Port != tc.wantPort || ident.User != tc.wantUser {
				t.Fatalf("Resolve(%q) = host=%+v ident=%+v, want %s:%d user=%s",
					got, host, ident, tc.wantAddr, tc.wantPort, tc.wantUser)
			}
		})
	}

	for _, badHop := range []string{"unknown-typo", "openssh:unknown-typo", "bastion-blocked", "openssh:bastion-blocked"} {
		t.Run("reject_"+badHop, func(t *testing.T) {
			if got, err := prov.ResolveProxyJumpChain(badHop); err == nil {
				t.Fatalf("ResolveProxyJumpChain(%q) = %q, want fail-closed error", badHop, got)
			}
		})
	}

	t.Run("rejects catch-all Host * with identity HostName %h", func(t *testing.T) {
		noopParser, err := NewOpenSSHParserFromReader(strings.NewReader("Host *\n  HostName %h\n"))
		if err != nil {
			t.Fatal(err)
		}
		noopProv := NewProviderWithOpenSSHParser(nil, noopParser)
		if got, err := noopProv.ResolveProxyJumpChain("unknown-typo"); err == nil {
			t.Fatalf("ResolveProxyJumpChain(unknown-typo) with Host * HostName %%h = %q, want error", got)
		}
	})
}

func TestP1_ValidateV2AndNewRepositoryParity(t *testing.T) {
	t.Parallel()

	baseValid := func() *ConfigurationV2 {
		return &ConfigurationV2{
			SchemaVersion: 2,
			Credential: CredentialConfig{
				DefaultStore: "sys",
				Stores:       map[string]StoreConfig{"sys": {Type: StoreTypeSystem}},
			},
			Hosts: map[string]models.Host{
				"h1": {Address: "10.0.0.1", Port: 22},
			},
			Identities: map[string]IdentityV2{
				"id1": {User: "ops", AuthType: "auto"},
			},
			Nodes: map[string]NodeV2{
				"n1": {HostRef: "h1", IdentityRef: "id1"},
			},
		}
	}

	rejectCases := []struct {
		name   string
		mutate func(*ConfigurationV2)
	}{
		{
			name: "empty host_ref",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n1"] = NodeV2{HostRef: "", IdentityRef: "id1"}
			},
		},
		{
			name: "whitespace host_ref",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n1"] = NodeV2{HostRef: "   ", IdentityRef: "id1"}
			},
		},
		{
			name: "empty identity_ref",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: ""}
			},
		},
		{
			name: "whitespace identity_ref",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: " \t "}
			},
		},
		{
			name: "distinct hosts with duplicate host alias",
			mutate: func(c *ConfigurationV2) {
				c.Hosts["h1"] = models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"dup-host"}}
				c.Hosts["h2"] = models.Host{Address: "10.0.0.2", Port: 22, Alias: []string{"dup-host"}}
				c.Nodes["n2"] = NodeV2{HostRef: "h2", IdentityRef: "id1"}
			},
		},
		{
			name: "duplicate node alias across nodes",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: "id1", Alias: []string{"web"}}
				c.Nodes["n2"] = NodeV2{HostRef: "h1", IdentityRef: "id1", Alias: []string{"web"}}
			},
		},
		{
			name: "node alias collides with other node host alias",
			mutate: func(c *ConfigurationV2) {
				c.Hosts["h2"] = models.Host{Address: "10.0.0.2", Port: 22, Alias: []string{"edge"}}
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: "id1", Alias: []string{"edge"}}
				c.Nodes["n2"] = NodeV2{HostRef: "h2", IdentityRef: "id1"}
			},
		},
	}

	for _, tc := range rejectCases {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			v2 := baseValid()
			tc.mutate(v2)
			v2Err := ValidateV2(v2)
			if !errors.Is(v2Err, ErrSchemaValidation) {
				t.Fatalf("ValidateV2(%s) = %v, want ErrSchemaValidation", tc.name, v2Err)
			}
			// Build equivalent raw Configuration and verify NewRepositoryWithoutOpenSSH also rejects.
			raw := cloneConfiguration(nil)
			for k, h := range v2.Hosts {
				raw.Hosts.Set(k, h)
			}
			for k, id := range v2.Identities {
				raw.Identities.Set(k, models.Identity{User: id.User, AuthType: id.AuthType})
			}
			for k, n := range v2.Nodes {
				raw.Nodes.Set(k, models.Node{HostRef: n.HostRef, IdentityRef: n.IdentityRef, Alias: n.Alias})
			}
			if _, repoErr := NewRepositoryWithoutOpenSSH(raw, &repositoryTestStore{}); repoErr == nil {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) succeeded, breaking parity with ValidateV2 (%v)", tc.name, v2Err)
			}
		})
	}

	acceptCases := []struct {
		name   string
		mutate func(*ConfigurationV2)
	}{
		{
			name: "shared host_ref without host alias",
			mutate: func(c *ConfigurationV2) {
				c.Nodes["n2"] = NodeV2{HostRef: "h1", IdentityRef: "id1"}
			},
		},
		{
			name: "shared host_ref with host alias and explicit node disambiguation",
			mutate: func(c *ConfigurationV2) {
				c.Hosts["h1"] = models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"web1", "frontend-1"}}
				c.Identities["id2"] = IdentityV2{User: "root", AuthType: "auto"}
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: "id1", Alias: []string{"frontend-1"}}
				c.Nodes["n2"] = NodeV2{HostRef: "h1", IdentityRef: "id2"}
			},
		},
		{
			name: "single node repeating its own host alias",
			mutate: func(c *ConfigurationV2) {
				c.Hosts["h1"] = models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"bastion"}}
				c.Nodes["n1"] = NodeV2{HostRef: "h1", IdentityRef: "id1", Alias: []string{"bastion"}}
			},
		},
	}

	for _, tc := range acceptCases {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			v2 := baseValid()
			tc.mutate(v2)
			cfg, err := FromV2(v2)
			if err != nil {
				t.Fatalf("FromV2(%s) unexpected error: %v", tc.name, err)
			}
			repo, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{})
			if err != nil {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) unexpected error: %v", tc.name, err)
			}
			if tc.name == "shared host_ref with host alias and explicit node disambiguation" {
				if got, err := repo.ResolveSelector("frontend-1"); err != nil || got != "n1" {
					t.Fatalf("ResolveSelector(frontend-1) = (%q, %v), want n1", got, err)
				}
				var ambig *AmbiguousNodeError
				if _, err := repo.ResolveSelector("web1"); !errors.As(err, &ambig) {
					t.Fatalf("ResolveSelector(web1) = %v, want AmbiguousNodeError", err)
				}
				if got, err := repo.ResolveSelector("root@web1"); err != nil || got != "n2" {
					t.Fatalf("ResolveSelector(root@web1) = (%q, %v), want n2", got, err)
				}
			}
		})
	}

	t.Run("example config loads cleanly into NewRepositoryWithoutOpenSSH", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "..", "xops_config.example.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		v2, err := UnmarshalV2(data)
		if err != nil {
			t.Fatalf("UnmarshalV2(example): %v", err)
		}
		cfg, err := FromV2(v2)
		if err != nil {
			t.Fatalf("FromV2(example): %v", err)
		}
		if _, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{}); err != nil {
			t.Fatalf("NewRepositoryWithoutOpenSSH(example): %v", err)
		}
	})
}

func TestP1_WithOpenSSHConfigOverrideOriginsIsolation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baseParser, err := NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.1\n  User ops\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{HostRef: "h1", IdentityRef: "id1"})

	repo, err := NewRepositoryWithOpenSSHParser(cfg, &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}, baseParser)
	if err != nil {
		t.Fatal(err)
	}
	repo.SetNodeOpenSSHOrigin("ops@10.0.0.1:22", OpenSSHOrigin{
		Alias:         "edge",
		CanonicalHost: "edge.corp.example.com",
	})

	t.Run("-F none does not copy stale openSSHOrigins", func(t *testing.T) {
		noneProv, err := WithOpenSSHConfigOverride(repo, "none")
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride(none): %v", err)
		}
		n, ok := noneProv.GetNode("ops@10.0.0.1:22")
		if !ok {
			t.Fatal("saved node missing in override provider")
		}
		if n.OpenSSHAlias != "" || n.CanonicalHost != "" {
			t.Fatalf("-F none leaked stale OpenSSH origin metadata: alias=%q canon=%q", n.OpenSSHAlias, n.CanonicalHost)
		}
	})

	t.Run("-F unrelated config does not copy stale openSSHOrigins", func(t *testing.T) {
		otherCfg := filepath.Join(dir, "other_ssh_config")
		if err := os.WriteFile(otherCfg, []byte("Host other\n  HostName 10.0.0.2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		otherProv, err := WithOpenSSHConfigOverride(repo, otherCfg)
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride(other): %v", err)
		}
		n, ok := otherProv.GetNode("ops@10.0.0.1:22")
		if !ok {
			t.Fatal("saved node missing in override provider")
		}
		if n.OpenSSHAlias != "" || n.CanonicalHost != "" {
			t.Fatalf("-F unrelated config leaked stale OpenSSH origin: alias=%q canon=%q", n.OpenSSHAlias, n.CanonicalHost)
		}
	})

	t.Run("-F conflicting HostName for same alias does not copy stale origin", func(t *testing.T) {
		conflictCfg := filepath.Join(dir, "conflict_ssh_config")
		if err := os.WriteFile(conflictCfg, []byte("Host edge\n  HostName 10.99.99.99\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		conflictProv, err := WithOpenSSHConfigOverride(repo, conflictCfg)
		if err != nil {
			t.Fatalf("WithOpenSSHConfigOverride(conflict): %v", err)
		}
		n, ok := conflictProv.GetNode("ops@10.0.0.1:22")
		if !ok {
			t.Fatal("saved node missing in override provider")
		}
		if n.OpenSSHAlias != "" || n.CanonicalHost != "" {
			t.Fatalf("-F conflicting HostName leaked stale origin: alias=%q canon=%q", n.OpenSSHAlias, n.CanonicalHost)
		}
	})

	// Base repository retains its own session origin untouched.
	if got := repo.NodeOpenSSHOrigin("ops@10.0.0.1:22"); got != (OpenSSHOrigin{Alias: "edge", CanonicalHost: "edge.corp.example.com"}) {
		t.Fatalf("base repo origin mutated: %+v", got)
	}
}

func TestP1_RepositoryRefChecksRespectContextWhileCommitLocked(t *testing.T) {
	t.Parallel()

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id1"})
	repo, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
	if err != nil {
		t.Fatal(err)
	}

	repo.commitMu.Lock()
	defer repo.commitMu.Unlock()

	ref := credential.Ref{StoreID: "sys", ItemID: "item-1"}
	ctx1, cancel1 := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel1()
	if _, err := repo.CheckRefUnreferenced(ctx1, ref); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CheckRefUnreferenced under locked commitMu = %v, want context.DeadlineExceeded", err)
	}

	ctx2, cancel2 := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel2()
	if _, err := repo.ConfirmRefDurable(ctx2, credential.Target{NodeID: "n1", Kind: credential.KindLoginPassword}, &ref); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ConfirmRefDurable under locked commitMu = %v, want context.DeadlineExceeded", err)
	}
}

func TestP1_IsPersistableIdentityPath_DelegatesCanonicalRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty", "", false},
		{"spaces_only", "   ", false},
		{"none_lower", "none", false},
		{"none_upper_padded", "  NONE  ", false},
		{"percent_token", "%d/.ssh/id_%r", false},
		{"invalid_percent_token", "~/.ssh/id_%k", false},
		{"env_placeholder", "${SSH_KEY_PATH}", false},
		{"invalid_env_placeholder", "${BAD-NAME}/id", false},
		{"control_newline", "/tmp/id_ed25519\n", false},
		{"control_nul", "/tmp/id\x00key", false},
		{"unicode_line_sep", "/tmp/id\u2028key", false},
		{"unresolved_tilde_user", "~nonexistent_xops_user_999/id_ed25519", false},
		{"home_tilde", "~/.ssh/id_ed25519", true},
		{"home_tilde_padded", "  ~/.ssh/id_ed25519  ", true},
		{"concrete_abs", "/tmp/id_ed25519", true},
		{"concrete_rel", "rel_id_ed25519", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPersistableIdentityPath(tc.raw); got != tc.want {
				t.Errorf("IsPersistableIdentityPath(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
