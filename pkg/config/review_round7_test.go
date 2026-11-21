package config

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound7_P1_4_SemanticEndpointMatchingAndNodeIDCollisionAllocation(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host reused-alias",
		"  HostName 10.70.0.1",
		"  User ops",
		"",
		"Host collision-alias",
		"  HostName 10.70.0.2",
		"  User root",
		"",
		"Host collision-alias-same",
		"  HostName 10.70.0.2",
		"  User ops",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := cloneConfiguration(nil)
	// Node 1 has custom ID "custom-app" at (ops, 10.70.0.1, 22).
	cfg.Hosts.Set("h1", models.Host{Address: "10.70.0.1", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("custom-app", models.Node{HostRef: "h1", IdentityRef: "id-ops"})

	// Node 2 has ID "ops@10.70.0.2:22" that was edited in-place to 10.70.0.99.
	cfg.Hosts.Set("h2-edited", models.Host{Address: "10.70.0.99", Port: 22})
	cfg.Nodes.Set("ops@10.70.0.2:22", models.Node{HostRef: "h2-edited", IdentityRef: "id-ops"})

	repo, err := NewRepositoryWithOpenSSHParser(cfg, &memoryPersistStore{cfg: cfg}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	verifyRound7AliasEndpointReuse(t, repo)
	verifyRound7EditedNodeCollisionAllocation(t, repo)
}

func verifyRound7AliasEndpointReuse(t *testing.T, repo *Repository) {
	t.Helper()
	// 1. OpenSSH alias pointing to 10.70.0.1 with explicit port
	// must reuse custom-app rather than creating a duplicate node.
	reuseTarget := ConnectionTarget{Selector: "reused-alias", Port: 22, HasPort: true}
	resReuse, err := ResolveTarget(repo, reuseTarget)
	if err != nil {
		t.Fatalf("ResolveTarget(reused-alias): %v", err)
	}
	if resReuse.MatchedNodeID != "custom-app" || resReuse.NodeID != "custom-app" || resReuse.Created {
		t.Fatalf("reused-alias missed custom-app: %+v", resReuse)
	}
	prepReuse, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: reuseTarget,
	})
	if err != nil || prepReuse.Created || prepReuse.NodeID != "custom-app" {
		t.Fatalf("PrepareNodeContext(reused-alias) = (%+v, %v), want custom-app Created=false", prepReuse, err)
	}
}

func verifyRound7EditedNodeCollisionAllocation(t *testing.T, repo *Repository) {
	t.Helper()
	// 2. Edited-node key collision: ops@10.70.0.2:22 now points to 10.70.0.99!
	// Unpersisted matching alias resolves to virtual without hijacking ops@10.70.0.2:22.
	resSame, err := ResolveTarget(repo, ConnectionTarget{Selector: "collision-alias-same"})
	if err != nil || resSame.MatchedNodeID != "openssh:collision-alias-same" || resSame.NodeID != "openssh:collision-alias-same" || resSame.Provenance != ProvenanceOpenSSHVirtual || resSame.Created {
		t.Fatalf("ResolveTarget(collision-alias-same) = (%+v, %v), want openssh:collision-alias-same virtual", resSame, err)
	}
	// Requests for 10.70.0.2 (explicit address or overridden OpenSSH alias) must NOT hijack ops@10.70.0.2:22
	// and must deterministically allocate ops@10.70.0.2:22-2.
	for _, target := range []ConnectionTarget{
		{Selector: "collision-alias", User: "ops", HasUser: true, Port: 22, HasPort: true},
		{Selector: "10.70.0.2", User: "ops", HasUser: true, Port: 22, HasPort: true},
	} {
		resCol, rErr := ResolveTarget(repo, target)
		if rErr != nil {
			t.Fatalf("ResolveTarget(%+v): %v", target, rErr)
		}
		if resCol.Host != "10.70.0.2" || resCol.MatchedNodeID != "" || !resCol.Created {
			t.Fatalf("target %+v hijacked edited node: %+v", target, resCol)
		}
		if resCol.NodeID != "ops@10.70.0.2:22-2" {
			t.Fatalf("target %+v NodeID = %q, want ops@10.70.0.2:22-2", target, resCol.NodeID)
		}
	}

	verifyRound7CollisionPrepareConfirm(t, repo)
}

func verifyRound7CollisionPrepareConfirm(t *testing.T, repo *Repository) {
	t.Helper()
	// Ensure PrepareNodeContext + ConfirmNodeContext allocate and persist "ops@10.70.0.2:22-2" cleanly.
	prepCol, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "10.70.0.2", User: "ops", HasUser: true, Port: 22, HasPort: true},
	})
	if err != nil || !prepCol.Created || prepCol.NodeID != "ops@10.70.0.2:22-2" {
		t.Fatalf("PrepareNodeContext(10.70.0.2) = (%+v, %v), want ops@10.70.0.2:22-2 Created=true", prepCol, err)
	}
	if err := repo.ConfirmNodeContext(t.Context(), prepCol.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(%q): %v", prepCol.NodeID, err)
	}
	prepCol2, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "collision-alias-same", Port: 22, HasPort: true},
	})
	if err != nil || prepCol2.Created || prepCol2.NodeID != "ops@10.70.0.2:22-2" {
		t.Fatalf("second PrepareNodeContext(collision-alias-same) = (%+v, %v), want reuse ops@10.70.0.2:22-2", prepCol2, err)
	}
	// Original edited node must remain intact on 10.70.0.99.
	_, editedHost, _, err := repo.Resolve("ops@10.70.0.2:22")
	if err != nil || editedHost.Address != "10.70.0.99" {
		t.Fatalf("edited node ops@10.70.0.2:22 corrupted: host=%+v err=%v", editedHost, err)
	}
}

func TestRound7_P1_5_And_P3_6_EquivalenceBracketsLookupAndJumpNormalization(t *testing.T) {
	t.Parallel()

	// Equivalence axiom: Endpoint.Equal(a, b) <=> Norm(a) != "" && Norm(a) == Norm(b)
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"Web.Example.COM", "web.example.com", true},
		{"[2001:0DB8::1]", "2001:db8::1", true},
		{"[::1", "::1", false},
		{"::1]", "::1", false},
		{"[10.0.0.1]", "10.0.0.1", false},
	} {
		epA, errA := ssh.NewEndpoint(tc.a, 22)
		epB, errB := ssh.NewEndpoint(tc.b, 22)
		got := errA == nil && errB == nil && epA.Equal(epB)
		if got != tc.want {
			t.Errorf("Endpoint.Equal(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if tc.want && NormalizeHostAddress(tc.a) != NormalizeHostAddress(tc.b) {
			t.Errorf("NormalizeHostAddress split equivalence class for %q vs %q: %q != %q",
				tc.a, tc.b, NormalizeHostAddress(tc.a), NormalizeHostAddress(tc.b))
		}
	}

	if got := StripHostBrackets("[fe80::1%eth0]"); got != "fe80::1%eth0" {
		t.Fatalf("StripHostBrackets([fe80::1%%eth0]) = %q", got)
	}
	if got := StripHostBrackets("[::1"); got != "[::1" {
		t.Fatalf("StripHostBrackets unbalanced = %q", got)
	}
	if got := StripHostBrackets("[10.0.0.1]"); got != "[10.0.0.1]" {
		t.Fatalf("StripHostBrackets non-IPv6 = %q", got)
	}

	verifyRound7SelectorLookupAndJump(t)
}

func verifyRound7SelectorLookupAndJump(t *testing.T) {
	t.Helper()
	// Whitespace, leading-zero port, uppercase DNS, and case-sensitive NodeID protection.
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-dns", models.Host{Address: "Web.Example.COM", Port: 22, Alias: []string{"APP-ALIAS"}})
	cfg.Hosts.Set("h-custom", models.Host{Address: "10.71.0.8", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg.Nodes.Set("web-node", models.Node{HostRef: "h-dns", IdentityRef: "id-ops"})
	cfg.Nodes.Set("app-alias", models.Node{HostRef: "h-custom", IdentityRef: "id-ops"})

	prov := NewProviderWithoutOpenSSH(cfg)
	for _, sel := range []string{"web.example.com", "WEB.EXAMPLE.COM", " ops@Web.Example.COM:0022 "} {
		got, err := prov.ResolveSelector(sel)
		if err != nil || got != "web-node" {
			t.Errorf("ResolveSelector(%q) = (%q, %v), want web-node", sel, got, err)
		}
	}
	// Lowercase custom NodeID "app-alias" vs Host.Alias "APP-ALIAS" on web-node must stay exact!
	if got, err := prov.ResolveSelector("app-alias"); err != nil || got != "app-alias" {
		t.Fatalf("ResolveSelector(\"app-alias\") = (%q, %v), want exact app-alias", got, err)
	}
	if got, err := prov.ResolveSelector("APP-ALIAS"); err != nil || got != "web-node" {
		t.Fatalf("ResolveSelector(\"APP-ALIAS\") = (%q, %v), want web-node via Host.Alias", got, err)
	}

	// isDNSHostname trailing dot & resolveJumpForNode mixed "" / "none".
	if !isDNSHostname("bastion.example.com.") {
		t.Fatal("isDNSHostname rejected valid trailing-dot FQDN")
	}
	if isDNSHostname("bastion.") || isDNSHostname("bastion.example.com..") {
		t.Fatal("isDNSHostname accepted invalid single-label or double-dot hostname")
	}
	if got, err := ResolveProxyJumpChainWithConfig(cfg, nil, "bastion.example.com."); err != nil || got != "openssh:bastion.example.com." {
		t.Fatalf("ResolveProxyJumpChainWithConfig(trailing dot) = (%q, %v)", got, err)
	}

	jumpCfg := cloneConfiguration(nil)
	jumpCfg.Hosts.Set("hj", models.Host{Address: "10.72.0.5", Port: 22})
	jumpCfg.Identities.Set("id1", models.Identity{User: "alice"})
	jumpCfg.Identities.Set("id2", models.Identity{User: "bob"})
	jumpCfg.Nodes.Set("alice@10.72.0.5:22", models.Node{HostRef: "hj", IdentityRef: "id1", ProxyJump: ""})
	jumpCfg.Nodes.Set("bob@10.72.0.5:22", models.Node{HostRef: "hj", IdentityRef: "id2", ProxyJump: "none"})
	repo, _ := NewRepositoryWithoutOpenSSH(jumpCfg, &abortSaveStore{})
	j, err := repo.resolveJumpForNode(jumpCfg, EnsureNodeOptions{}, canonicalTargetInfo{}, "10.72.0.5", 22)
	if err != nil || j != "" {
		t.Fatalf("resolveJumpForNode('' + 'none') = (%q, %v), want ('', nil)", j, err)
	}
}

type blockingCancelResolver struct {
	cancelFn context.CancelFunc
	queried  []string
}

func (r *blockingCancelResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	r.queried = append(r.queried, host)
	if r.cancelFn != nil {
		r.cancelFn()
	}
	return nil, ctx.Err()
}

func (r *blockingCancelResolver) LookupCNAME(ctx context.Context, _ string) (string, error) {
	return "", ctx.Err()
}

func TestRound7_P2_5_And_P3_5_CanonicalizeBooleansCaseNonLatchingAndParentCancel(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
		"  CanonicalizeMaxDots 1",
		"  CanonicalizeFallbackLocal yes",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	// 1. CanonicalizeHostname=true + uppercase CanonicalDomains + invalid CLI directives must NOT latch.
	pol := resolveCanonicalizePolicy(parser, nil, "web", []string{
		"CanonicalizeHostname=bogus",
		"CanonicalizeHostname=true",
		"CanonicalDomains= . , .. ",
		"CanonicalDomains=CORP.EXAMPLE.COM corp.example.com",
		"CanonicalizeMaxDots=notanint",
		"CanonicalizeFallbackLocal=maybe",
		"CanonicalizePermittedCNAMEs=malformed_no_colon",
		"ConnectTimeout=notaduration",
	}, "")
	if pol.mode != "yes" || len(pol.domains) != 1 || pol.domains[0] != "corp.example.com" || pol.maxDots != 1 || !pol.fallbackLocal {
		t.Fatalf("unexpected canonicalize policy after invalid/bool/case directives: %+v", pol)
	}

	// 2. Parent context cancellation propagates even when CanonicalizeFallbackLocal=yes.
	ctx, cancel := context.WithCancel(t.Context())
	res := &blockingCancelResolver{cancelFn: cancel}
	_, cErr := CanonicalizeHost(ctx, CanonicalizeInput{
		Provider: prov,
		Host:     "web",
		Resolver: res,
	})
	if !errors.Is(cErr, context.Canceled) {
		t.Fatalf("CanonicalizeHost under parent cancel = %v, want context.Canceled", cErr)
	}
}

func TestRound7_P2_9_And_P3_1_ConcreteHostValidationAndOpenSSHControlChars(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"", "  ", "openssh:web", "OPENSSH:web", "OpenSSH:bob@web:22"} {
		if err := ValidateConcreteHostAddress(bad); err == nil {
			t.Errorf("ValidateConcreteHostAddress(%q) = nil, want error", bad)
		}
	}
	repo, err := NewRepositoryWithoutOpenSSH(nil, &abortSaveStore{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateNodeContext(t.Context(), "valid-id", models.Node{HostRef: "h1", IdentityRef: "id1"}, models.Host{
		Address: "OPENSSH:web",
		Port:    22,
	}, models.Identity{User: "ops"}); err == nil {
		t.Fatal("CreateNodeContext accepted OPENSSH: host address")
	}

	p, err := NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sep := range []string{"\u0085", "\u2028", "\u2029"} {
		if _, _, _, err := p.GetVirtualNode("bad" + sep + "host"); err == nil {
			t.Errorf("GetVirtualNode accepted Unicode control/line sep %q", sep)
		}
		if _, _, _, err := p.GetVirtualNodeWithCanonical("edge", "bad"+sep+"canon"); err == nil {
			t.Errorf("GetVirtualNodeWithCanonical accepted %q", sep)
		}
	}
}
