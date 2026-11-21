package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound8_P1_6_ResolveDirectOrAliasDoesNotHijackLowercaseNodeID(t *testing.T) {
	t.Parallel()

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h-lower", models.Host{Address: "10.80.0.1", Port: 22})
	cfg.Hosts.Set("h-upper", models.Host{Address: "10.80.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	// Node "prod" is an unrelated lowercase custom NodeID.
	cfg.Nodes.Set("prod", models.Node{HostRef: "h-lower", IdentityRef: "id-ops"})
	// Node "upper-box" has Host.Alias "PROD".
	cfg.Nodes.Set("upper-box", models.Node{HostRef: "h-upper", IdentityRef: "id-ops", Alias: []string{"PROD"}})

	repo, err := NewRepositoryWithoutOpenSSH(cfg, &memoryPersistStore{cfg: cfg})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	res, err := ResolveTarget(repo, ConnectionTarget{Selector: "PROD"})
	if err != nil {
		t.Fatalf("ResolveTarget(PROD): %v", err)
	}
	if res.NodeID != "upper-box" || res.Host != "10.80.0.2" {
		t.Fatalf("ResolveTarget(PROD) hijacked lowercase NodeID: %+v, want upper-box / 10.80.0.2", res)
	}
	// Also test when "PROD" is NOT a saved alias (so it must not hijack saved NodeID "prod").
	cfg2 := cloneConfiguration(nil)
	cfg2.Hosts.Set("h-lower", models.Host{Address: "10.80.0.1", Port: 22})
	cfg2.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg2.Nodes.Set("prod", models.Node{HostRef: "h-lower", IdentityRef: "id-ops"})
	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host PROD\n  HostName 10.80.0.9\n  User ops\n"))
	if err != nil {
		t.Fatal(err)
	}
	repo2, err := NewRepositoryWithOpenSSHParser(cfg2, &memoryPersistStore{cfg: cfg2}, parser)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ResolveTarget(repo2, ConnectionTarget{Selector: "PROD"})
	if err != nil {
		t.Fatalf("ResolveTarget(PROD vs lowercase saved prod): %v", err)
	}
	if res2.NodeID != "openssh:PROD" || res2.Host != "10.80.0.9" {
		t.Fatalf("ResolveTarget(PROD) hijacked saved node prod: %+v, want openssh:PROD / 10.80.0.9", res2)
	}
}

func TestRound8_P1_7_ConcreteHostAddressAndHostAliasValidationAcrossAllPersistenceBoundaries(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{
		"",
		"   ",
		"openssh:victim",
		"OPENSSH:victim",
		"10.0.0.1\nevil",
		"10.0.0.1\u2028",
		"10.0.0.1 10.0.0.2",
		"[badhost]",
		"[10.0.0.1]",
		"[::1",
		"::1]",
	} {
		if err := ValidateConcreteHostAddress(bad); err == nil {
			t.Errorf("ValidateConcreteHostAddress(%q) unexpectedly succeeded", bad)
		}
	}
	for _, good := range []string{"10.0.0.1", "web.example.com", "2001:db8::1", "[2001:db8::1]", "[fe80::1%eth0]"} {
		if err := ValidateConcreteHostAddress(good); err != nil {
			t.Errorf("ValidateConcreteHostAddress(%q) failed: %v", good, err)
		}
	}

	store := NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}

	// 1. CreateNodeContext rejects reserved Host.Alias.
	if _, err := repo.CreateNodeContext(t.Context(), "good-node",
		models.Node{HostRef: "h1", IdentityRef: "id1"},
		models.Host{Address: "10.81.0.1", Port: 22, Alias: []string{"OPENSSH:hijack"}},
		models.Identity{User: "ops"},
	); err == nil {
		t.Fatal("CreateNodeContext accepted Host.Alias with reserved openssh: prefix")
	}

	// 2. ImportOpenSSHHostsContext skips invalid address or Host.Alias and records ImportIssue.
	imp, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{
		{
			Name:     "bad-addr",
			Host:     models.Host{Address: "OPENSSH:victim", Port: 22},
			Identity: models.Identity{User: "ops"},
		},
		{
			Name:     "bad-host-alias",
			Host:     models.Host{Address: "10.81.0.2", Port: 22, Alias: []string{"openssh:alias"}},
			Identity: models.Identity{User: "ops"},
		},
		{
			Name:     "good-import",
			Host:     models.Host{Address: "10.81.0.3", Port: 22},
			Identity: models.Identity{User: "ops"},
		},
	})
	if err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	if imp.Imported != 1 || imp.Skipped != 2 || len(imp.Issues) != 2 {
		t.Fatalf("ImportOpenSSHHostsContext = %+v, want Imported=1 Skipped=2 Issues=2", imp)
	}

	// 3. OPENSSH:victim is handled case-insensitively as a read-only OpenSSH virtual
	// selector (never persisted as a concrete host), while double-prefixed selectors
	// and concrete Host.Address values with OPENSSH: are rejected fail-closed.
	prepVirt, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "OPENSSH:victim", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(OPENSSH:victim) unexpected error: %v", err)
	}
	if prepVirt.Created || !IsOpenSSHNodeID(prepVirt.NodeID) {
		t.Fatalf("PrepareNodeContext(OPENSSH:victim) = %+v, want read-only OpenSSH virtual node (Created=false)", prepVirt)
	}
	if _, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "openssh:OPENSSH:victim", User: "ops", HasUser: true},
	}); err == nil {
		t.Fatal("PrepareNodeContext accepted double-prefixed openssh:OPENSSH:victim")
	}
	if _, err := repo.CreateNodeContext(t.Context(), "bad-concrete-host",
		models.Node{HostRef: "h-bad", IdentityRef: "id-bad"},
		models.Host{Address: "OPENSSH:victim", Port: 22},
		models.Identity{User: "ops"},
	); err == nil {
		t.Fatal("CreateNodeContext accepted OPENSSH:victim as concrete host address")
	}

	// 4. ValidateV2 rejects bad Host.Address, Host.Alias, Node name, and Node.Alias.
	badV2 := &ConfigurationV2{
		SchemaVersion: 2,
		Hosts:         map[string]models.Host{"h1": {Address: "[badhost]", Port: 22}},
		Identities:    map[string]IdentityV2{"id1": {User: "ops"}},
		Nodes:         map[string]NodeV2{"n1": {HostRef: "h1", IdentityRef: "id1"}},
	}
	if err := ValidateV2(badV2); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("ValidateV2([badhost]) = %v, want ErrSchemaValidation", err)
	}
	badAliasV2 := &ConfigurationV2{
		SchemaVersion: 2,
		Hosts:         map[string]models.Host{"h1": {Address: "10.0.0.1", Port: 22, Alias: []string{"openssh:x"}}},
		Identities:    map[string]IdentityV2{"id1": {User: "ops"}},
		Nodes:         map[string]NodeV2{"n1": {HostRef: "h1", IdentityRef: "id1"}},
	}
	if err := ValidateV2(badAliasV2); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("ValidateV2(openssh host alias) = %v, want ErrSchemaValidation", err)
	}
}

func TestRound8_P2_7_P2_8_ResolveSelectorConsistencyAndNormalizedSavedCandidateAddress(t *testing.T) {
	t.Parallel()

	// P2-7: ResolveSelector checks aliasIndex before lookupIndex, handles port-normalized
	// mixed-case host alias, and passes trimmed selector to openSSH.Find.
	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host ssh-box\n  HostName 10.82.0.50\n  User ops\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.82.0.1", Port: 22, Alias: []string{"DUP-ALIAS"}})
	cfg.Hosts.Set("h2", models.Host{Address: "10.82.0.2", Port: 22, Alias: []string{"dup-alias"}})
	cfg.Hosts.Set("h3", models.Host{Address: "10.82.0.3", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfg.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id-ops"})
	cfg.Nodes.Set("n2", models.Node{HostRef: "h2", IdentityRef: "id-ops"})
	cfg.Nodes.Set("n3", models.Node{HostRef: "h3", IdentityRef: "id-ops", Alias: []string{"MyBox"}})
	prov := NewProviderWithOpenSSHParser(cfg, parser)

	if got, err := prov.ResolveSelector("dup-alias"); err != nil || got != "n2" {
		t.Fatalf("ResolveSelector(\"dup-alias\") = (%q, %v), want exact alias n2", got, err)
	}
	if got, err := prov.ResolveSelector(" ops@MyBox:0022 "); err != nil || got != "n3" {
		t.Fatalf("ResolveSelector(\" ops@MyBox:0022 \") = (%q, %v), want n3", got, err)
	}
	if got, err := prov.ResolveSelector("  ssh-box  "); err != nil || got != "openssh:ssh-box" {
		t.Fatalf("ResolveSelector(\"  ssh-box  \") = (%q, %v), want openssh:ssh-box", got, err)
	}

	// P2-8: Saved node with unnormalized IPv6 "[2001:0DB8::1]" produces normalized NodeID
	// when preparing a new user on the same saved node, matching raw "2001:db8::1".
	cfgV6 := cloneConfiguration(nil)
	cfgV6.Hosts.Set("hv6", models.Host{Address: "[2001:0DB8::1]", Port: 22})
	cfgV6.Identities.Set("id-ops", models.Identity{User: "ops"})
	cfgV6.Nodes.Set("v6-saved", models.Node{HostRef: "hv6", IdentityRef: "id-ops"})
	repoV6, err := NewRepositoryWithoutOpenSSH(cfgV6, &memoryPersistStore{cfg: cfgV6})
	if err != nil {
		t.Fatal(err)
	}
	resA, err := ResolveTarget(repoV6, ConnectionTarget{Selector: "v6-saved", User: "admin", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(admin@v6-saved): %v", err)
	}
	resB, err := ResolveTarget(repoV6, ConnectionTarget{Selector: "2001:db8::1", User: "admin", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(admin@2001:db8::1): %v", err)
	}
	if resA.NodeID != resB.NodeID || resA.Host != "2001:db8::1" {
		t.Fatalf("normalized candidate mismatch: via saved=%+v vs via IP=%+v", resA, resB)
	}
}

func TestRound8_P2_11_P2_12_P3_4_OpenSSHTrustTrueCanonicalizeBoundsAndControlAlias(t *testing.T) {
	t.Parallel()

	// P2-11: HashKnownHosts=true in ~/.ssh/config must be accepted as OptionClassTrust.
	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host box\n  HostName 10.83.0.1\n  HashKnownHosts true\n"))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parser.GetSSHOptions("box")
	if err != nil {
		t.Fatalf("GetSSHOptions: %v", err)
	}
	if opts == nil || opts.Get(ssh.OptionHashKnownHosts) != "yes" {
		t.Fatalf("HashKnownHosts true was not accepted: opts=%v", opts)
	}

	// P3-4: getVirtualNodeWithCanonical rejects control chars in lookupAlias before TrimSpace.
	if _, _, _, err := parser.getVirtualNodeWithCanonical("\rbox", "", "", 0, "box"); err == nil {
		t.Fatal("getVirtualNodeWithCanonical accepted leading CR in lookupAlias")
	}

	// P2-12: setMaxDots enforces <= 64 and setDomains rejects invalid domains & "none,corp.com".
	pol := resolveCanonicalizePolicy(nil, nil, "web", []string{
		"CanonicalizeHostname=yes",
		"CanonicalizeMaxDots=999", // out of range (>64): must NOT latch!
		"CanonicalizeMaxDots=3",
		"CanonicalDomains=none,corp.com",     // invalid: must NOT latch!
		"CanonicalDomains=-bad.example.com",  // invalid: must NOT latch!
		"CanonicalDomains=good.example.com.", // valid single trailing dot
	}, "")
	if pol.maxDots != 3 {
		t.Fatalf("pol.maxDots = %d, want 3 (999 must not latch)", pol.maxDots)
	}
	if len(pol.domains) != 1 || pol.domains[0] != "good.example.com" {
		t.Fatalf("pol.domains = %v, want [good.example.com]", pol.domains)
	}

	// P2-12: resolveCanonicalEffectiveInputHost unwraps %h-expanded bracketed IPv6 via unwrapExpandedHostName.
	if got := resolveCanonicalEffectiveInputHost(nil, []string{"HostName=[2001:db8::1]"}, "short"); got != "2001:db8::1" {
		t.Fatalf("resolveCanonicalEffectiveInputHost([2001:db8::1]) = %q, want 2001:db8::1", got)
	}
}
