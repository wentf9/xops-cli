package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP6_CanonicalizeDelegatesToCoreSSHOptionSpec(t *testing.T) {
	t.Parallel()

	t.Run("CanonicalDomains rejects comma-separated lists and matches OptionSpec.Normalize", testP6CanonicalDomainsParity)
	t.Run("CanonicalizePermittedCNAMEs rejects mixed invalid rules without silent dropping", testP6CanonicalPermittedCNAMEsParity)
	t.Run("control characters and bounds match core/ssh OptionSpec across all 5 directives", testP6CanonicalControlCharsAndBounds)
}

func testP6CanonicalDomainsParity(t *testing.T) {
	pol := resolveCanonicalizePolicy(nil, nil, "web", []string{
		"CanonicalizeHostname=yes",
		"CanonicalDomains=dev.example.com,corp.example.com",
		"CanonicalDomains=none,corp.example.com",
		"CanonicalDomains=corp.example.com\n",
		"CanonicalDomains=DEV.EXAMPLE.COM.\tcorp.example.com dev.example.com",
	}, "")
	if want := []string{"dev.example.com", "corp.example.com"}; !slices.Equal(pol.domains, want) {
		t.Fatalf("pol.domains = %v, want %v (comma list and newline must not latch)", pol.domains, want)
	}

	polCommaOnly := resolveCanonicalizePolicy(nil, nil, "web", []string{
		"CanonicalizeHostname=yes",
		"CanonicalDomains=a.example.com,b.example.com",
	}, "")
	if len(polCommaOnly.domains) != 0 {
		t.Fatalf("comma-separated CanonicalDomains unexpectedly accepted: %v", polCommaOnly.domains)
	}

	p, err := NewOpenSSHParserFromReader(strings.NewReader("Host *\n  CanonicalizeHostname yes\n  CanonicalDomains corp.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	polCleared := resolveCanonicalizePolicy(p, nil, "web", []string{"CanonicalDomains=NONE"}, "")
	if len(polCleared.domains) != 0 {
		t.Fatalf("CanonicalDomains=NONE did not clear Tier-4 domains: %v", polCleared.domains)
	}
}

func testP6CanonicalPermittedCNAMEsParity(t *testing.T) {
	invalidCNAMEs := []string{
		"*.a.example.com:*.b.example.com malformed_no_colon",
		"none *.a.example.com:*.b.example.com",
		"*.a.example.com:*.b.example.com:*.c.example.com",
		"*.a.example.com:,*.b.example.com",
		"*.a.example.com:bad/char.example.com",
		"*.a.example.com:*.b.example.com\r",
	}
	for _, bad := range invalidCNAMEs {
		pol := resolveCanonicalizePolicy(nil, nil, "web", []string{
			"CanonicalizeHostname=yes",
			"CanonicalizePermittedCNAMEs=" + bad,
		}, "")
		if len(pol.permittedCNAMEs) != 0 {
			t.Errorf("CanonicalizePermittedCNAMEs=%q silently accepted rules %+v, want rejection", bad, pol.permittedCNAMEs)
		}
	}

	pol := resolveCanonicalizePolicy(nil, nil, "web", []string{
		"CanonicalizeHostname=yes",
		"CanonicalizePermittedCNAMEs=*.a.example.com:*.b.example.com malformed_no_colon",
		"CanonicalizePermittedCNAMEs=*.corp.example.com.:!blocked.cdn.net.,*.cdn.net.",
	}, "")
	if len(pol.permittedCNAMEs) != 1 ||
		pol.permittedCNAMEs[0].sourcePatternList != "*.corp.example.com" ||
		pol.permittedCNAMEs[0].targetPatternList != "!blocked.cdn.net,*.cdn.net" {
		t.Fatalf("pol.permittedCNAMEs = %+v, want single normalized rule", pol.permittedCNAMEs)
	}

	p, err := NewOpenSSHParserFromReader(strings.NewReader("Host *\n  CanonicalizeHostname yes\n  CanonicalDomains corp.example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	prov := NewProviderWithOpenSSHParser(nil, p)
	res := &fakeCanonicalResolver{
		hosts:  map[string][]string{"web.corp.example.com": {"10.1.2.3"}},
		cnames: map[string]string{"web.corp.example.com": "edge.cdn.net."},
	}
	out, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider:      prov,
		Host:          "web",
		RawCLIOptions: []string{"CanonicalizePermittedCNAMEs=*.corp.example.com.:!blocked.cdn.net.,*.cdn.net."},
		Resolver:      res,
	})
	if err != nil || !out.Canonicalized || out.CanonicalHost != "edge.cdn.net" {
		t.Fatalf("CanonicalizeHost permitted CNAME = (%+v, %v), want edge.cdn.net", out, err)
	}
}

func testP6CanonicalControlCharsAndBounds(t *testing.T) {
	pol := resolveCanonicalizePolicy(nil, nil, "web", []string{
		"CanonicalizeHostname=yes\n",
		"CanonicalizeHostname=always",
		"CanonicalizeFallbackLocal=no\r",
		"CanonicalizeFallbackLocal=false",
		"CanonicalizeMaxDots=1\u2028",
		"CanonicalizeMaxDots=-1",
		"CanonicalizeMaxDots=65",
		"CanonicalizeMaxDots=64",
	}, "")
	if pol.mode != "always" || pol.fallbackLocal || pol.maxDots != 64 {
		t.Fatalf("unexpected policy after control-char/bound rejection: %+v", pol)
	}

	p, err := NewOpenSSHParserFromReader(strings.NewReader(strings.Join([]string{
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains bad..domain!",
		"  CanonicalizePermittedCNAMEs *.a:*.b broken_token",
	}, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	polSSH := resolveCanonicalizePolicy(p, nil, "web", nil, "")
	if polSSH.mode != "yes" || len(polSSH.domains) != 0 || len(polSSH.permittedCNAMEs) != 0 {
		t.Fatalf("invalid ssh_config directives should be leniently ignored, got %+v", polSSH)
	}
}

func TestP6_OpenSSHPreferredAuthenticationsFailClosedDelegation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		val     string
		want    string
		wantErr string
	}{
		{
			name: "fail-closed unimplemented methods retained deduplicated and lowercased",
			val:  "GSSAPI-WITH-MIC,hostbased,gssapi-with-mic",
			want: "gssapi-with-mic,hostbased",
		},
		{
			name: "implemented method takes precedence over unimplemented methods",
			val:  "gssapi-with-mic,publickey,hostbased",
			want: "publickey",
		},
		{
			name:    "unknown auth methods fail closed",
			val:     "totally-unknown-auth",
			wantErr: "no supported PreferredAuthentications",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgText := fmt.Sprintf("Host app\n  HostName 10.1.0.1\n  PreferredAuthentications %s\n", tc.val)
			p, err := NewOpenSSHParserFromReader(strings.NewReader(cfgText))
			if err != nil {
				t.Fatalf("NewOpenSSHParserFromReader: %v", err)
			}
			opts, err := p.GetSSHOptions("app")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("GetSSHOptions() err = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetSSHOptions() unexpected err = %v", err)
			}
			if got := opts.Get(ssh.OptionPreferredAuthentications); got != tc.want {
				t.Fatalf("PreferredAuthentications = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestP6_PendingConnectionOverrideCleanupRefcountAndOriginIsolation(t *testing.T) {
	t.Parallel()

	t.Run("override provider cleans up all pending entries on confirm", testP6OverridePendingCleanup)
	t.Run("override confirmed snapshot cache stays bounded", testP6OverrideConfirmedCacheBound)
	t.Run("repository refcount and DiscardPendingNode isolate concurrent callers", testP6RepositoryPendingRefcountBasic)
	t.Run("repository refcount preserves upgrade and disambiguated openssh entries", testP6RepositoryPendingRefcountUpgradeAndAlt)
	t.Run("pending origin setters stay isolated to pending.provider until confirmed", testP6PendingOriginIsolation)
	t.Run("concurrent Prepare Discard SetOrigin and Confirm stay race-free", testP6PendingConcurrencyRace)
}

func newP6OverrideProvider(t *testing.T) *openSSHOverrideProvider {
	t.Helper()
	sshCfgPath := filepath.Join(t.TempDir(), "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.61.0.1",
		"  User reader",
		"  IdentityFile /tmp/id_role_a",
		"Host role-b",
		"  HostName 10.61.0.1",
		"  User writer",
		"  IdentityFile /tmp/id_role_b",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	baseRepo, _ := pendingDiskRepository(t)
	ov, err := WithOpenSSHConfigOverride(baseRepo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	return ov.(*openSSHOverrideProvider)
}

func pendingCount(repo *Repository) int {
	repo.pendingMu.RLock()
	defer repo.pendingMu.RUnlock()
	return len(repo.pending)
}

func testP6OverridePendingCleanup(t *testing.T) {
	ovProv := newP6OverrideProvider(t)

	resA, err := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	})
	if err != nil || IsOpenSSHNodeID(resA.NodeID) {
		t.Fatalf("PrepareNodeContext(role-a) = (%+v, %v), want non-openssh ad-hoc ID", resA, err)
	}
	resB, err := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil || !IsOpenSSHNodeID(resB.NodeID) {
		t.Fatalf("PrepareNodeContext(role-b) = (%+v, %v), want openssh disambiguated ID", resB, err)
	}

	if err := ovProv.ConfirmNodeContext(t.Context(), resA.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext(resA): %v", err)
	}
	if err := ovProv.ConfirmNodeWithExecutionContext(t.Context(), resB.NodeID, nil); err != nil {
		t.Fatalf("ConfirmNodeWithExecutionContext(resB): %v", err)
	}
	if n := pendingCount(ovProv.repo); n != 0 {
		t.Fatalf("override provider leaked %d pending entries after confirm (want 0)", n)
	}

	if snap, err := ovProv.ResolveConnection(resA.NodeID); err != nil || snap.Identity.KeyPath != "/tmp/id_role_a" || snap.Node.OpenSSHAlias != "role-a" {
		t.Fatalf("post-confirm ResolveConnection(resA) = (%+v, %v), want role-a snapshot", snap, err)
	}
	if len(ovProv.Snapshot().Nodes.Keys()) != 0 {
		t.Fatalf("override Snapshot() polluted with ephemeral nodes: %v", ovProv.Snapshot().Nodes.Keys())
	}

	resB2, err := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-b) after role-a confirm failed: %v", err)
	}
	if _, _, identB2, err := ovProv.Resolve(resB2.NodeID); err != nil || identB2.KeyPath != "/tmp/id_role_b" {
		t.Fatalf("Resolve(role-b after confirm) = (%q, %v), want /tmp/id_role_b", identB2.KeyPath, err)
	}
	ovProv.DiscardPendingNode(resB2.NodeID)
	if n := pendingCount(ovProv.repo); n != 0 {
		t.Fatalf("override DiscardPendingNode left %d entries", n)
	}
}

func testP6OverrideConfirmedCacheBound(t *testing.T) {
	ovProv := newP6OverrideProvider(t)
	for i := range maxOverrideConfirmedSnapshots + 10 {
		prep, prepErr := ovProv.PrepareNodeContext(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: fmt.Sprintf("10.62.0.%d", i+1), User: "ops", HasUser: true, Port: 22, HasPort: true},
		})
		if prepErr != nil {
			t.Fatalf("PrepareNodeContext(%d): %v", i, prepErr)
		}
		if err := ovProv.ConfirmNodeContext(t.Context(), prep.NodeID); err != nil {
			t.Fatalf("ConfirmNodeContext(%d): %v", i, err)
		}
	}
	ovProv.confirmedMu.RLock()
	cacheLen := len(ovProv.confirmed)
	ovProv.confirmedMu.RUnlock()
	if cacheLen > maxOverrideConfirmedSnapshots {
		t.Fatalf("override confirmed cache exceeded bound: %d > %d", cacheLen, maxOverrideConfirmedSnapshots)
	}
	if n := pendingCount(ovProv.repo); n != 0 {
		t.Fatalf("expected 0 pending entries after bounded confirms, got %d", n)
	}
}

func newP6PendingRoleRepo(t *testing.T) *Repository {
	t.Helper()
	sshCfg := strings.Join([]string{
		"Host app-a",
		"  HostName 10.63.0.10",
		"  User ops",
		"  Port 2200",
		"Host app-b",
		"  HostName 10.63.0.10",
		"  User ops",
		"  Port 2200",
		"  IdentityFile /tmp/id_app_b",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatal(err)
	}
	store := NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "cfg.key"))
	repo, err := NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func testP6RepositoryPendingRefcountBasic(t *testing.T) {
	repo := newP6PendingRoleRepo(t)
	opts := EnsureNodeOptions{Target: ConnectionTarget{Selector: "10.63.0.10", User: "ops", HasUser: true, Port: 2222, HasPort: true}}

	p1, err := repo.PrepareNodeContext(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := repo.PrepareNodeContext(t.Context(), opts)
	if err != nil || p2.NodeID != p1.NodeID {
		t.Fatalf("reuse PrepareNodeContext = (%+v, %v), want %q", p2, err, p1.NodeID)
	}
	repo.DiscardPendingNode(p1.NodeID)
	if _, err := repo.ResolveConnection(p1.NodeID); err != nil {
		t.Fatalf("first DiscardPendingNode clobbered concurrent caller: %v", err)
	}
	repo.DiscardPendingNode(p1.NodeID)
	if _, err := repo.ResolveConnection(p1.NodeID); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("second DiscardPendingNode did not delete entry: %v", err)
	}
	repo.DiscardPendingNode(p1.NodeID)
	repo.DiscardPendingNode("")
	repo.DiscardPendingNode("nonexistent")

	failA, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-a", Port: 2222, HasPort: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	repo.DiscardPendingNode(failA.NodeID)
	okB, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b", Port: 2222, HasPort: true},
	})
	if err != nil || IsOpenSSHNodeID(okB.NodeID) {
		t.Fatalf("PrepareNodeContext(app-b) after discarding app-a = (%+v, %v), want primary ID", okB, err)
	}
	repo.DiscardPendingNode(okB.NodeID)
	if n := pendingCount(repo); n != 0 {
		t.Fatalf("expected 0 pending entries, got %d", n)
	}
}

func testP6RepositoryPendingRefcountUpgradeAndAlt(t *testing.T) {
	repo := newP6PendingRoleRepo(t)
	rawOpts := EnsureNodeOptions{Target: ConnectionTarget{Selector: "10.63.0.10", User: "ops", HasUser: true, Port: 2222, HasPort: true}}

	u1, err := repo.PrepareNodeContext(t.Context(), rawOpts)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-a", Port: 2222, HasPort: true},
	})
	if err != nil || u2.NodeID != u1.NodeID {
		t.Fatalf("upgrade PrepareNodeContext = (%+v, %v), want %q", u2, err, u1.NodeID)
	}
	repo.DiscardPendingNode(u1.NodeID)
	if gotAlias := repo.NodeOpenSSHAlias(u1.NodeID); gotAlias != "app-a" {
		t.Fatalf("after one discard of upgraded pending entry, alias = %q, want app-a", gotAlias)
	}
	repo.DiscardPendingNode(u2.NodeID)
	if _, err := repo.ResolveConnection(u1.NodeID); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("upgraded pending entry leaked after final discard: %v", err)
	}

	holdA, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-a", Port: 2222, HasPort: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	alt1, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b", Port: 2222, HasPort: true},
	})
	if err != nil || !IsOpenSSHNodeID(alt1.NodeID) {
		t.Fatalf("alt1 = (%+v, %v), want openssh: ID", alt1, err)
	}
	alt2, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "app-b", Port: 2222, HasPort: true},
	})
	if err != nil || alt2.NodeID != alt1.NodeID {
		t.Fatalf("alt2 = (%+v, %v), want reuse %q", alt2, err, alt1.NodeID)
	}
	if err := repo.ConfirmNodeContext(t.Context(), alt1.NodeID); err != nil {
		t.Fatal(err)
	}
	repo.pendingMu.RLock()
	_, altStillPending := repo.pending[alt1.NodeID]
	repo.pendingMu.RUnlock()
	if !altStillPending {
		t.Fatal("first ConfirmNodeContext on shared disambiguated openssh pending entry deleted it before second caller finished")
	}
	repo.DiscardPendingNode(alt2.NodeID)
	repo.DiscardPendingNode(holdA.NodeID)
	if n := pendingCount(repo); n != 0 {
		t.Fatalf("expected 0 pending entries after all discards, got %d", n)
	}
}

func testP6PendingOriginIsolation(t *testing.T) {
	repo, _ := pendingDiskRepository(t)
	prep, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2222))
	if err != nil {
		t.Fatal(err)
	}

	repo.SetNodeOpenSSHOrigin(prep.NodeID, OpenSSHOrigin{Alias: "pending-alias", CanonicalHost: "pending.corp.example.com"})
	if got := repo.NodeOpenSSHOrigin(prep.NodeID); got != (OpenSSHOrigin{Alias: "pending-alias", CanonicalHost: "pending.corp.example.com"}) {
		t.Fatalf("pending NodeOpenSSHOrigin = %+v", got)
	}
	if leaked := repo.provider.NodeOpenSSHOrigin(prep.NodeID); !leaked.IsZero() {
		t.Fatalf("SetNodeOpenSSHOrigin leaked pending metadata into r.provider: %+v", leaked)
	}

	repo.SetNodeCanonicalHost(prep.NodeID, "canon2.corp.example.com")
	if leaked := repo.provider.NodeOpenSSHOrigin(prep.NodeID); !leaked.IsZero() {
		t.Fatalf("SetNodeCanonicalHost leaked pending metadata into r.provider: %+v", leaked)
	}

	repo.SetNodeOpenSSHAlias(prep.NodeID, "alias2")
	if leaked := repo.provider.NodeOpenSSHOrigin(prep.NodeID); !leaked.IsZero() {
		t.Fatalf("SetNodeOpenSSHAlias leaked pending metadata into r.provider: %+v", leaked)
	}

	frozenOrigin := repo.Frozen().(interface{ NodeOpenSSHOrigin(string) OpenSSHOrigin }).NodeOpenSSHOrigin(prep.NodeID)
	if !frozenOrigin.IsZero() {
		t.Fatalf("Frozen() observed unsaved pending metadata: %+v", frozenOrigin)
	}

	repo.DiscardPendingNode(prep.NodeID)
	if got := repo.NodeOpenSSHOrigin(prep.NodeID); !got.IsZero() {
		t.Fatalf("after DiscardPendingNode, NodeOpenSSHOrigin = %+v, want zero", got)
	}

	prep2, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2223))
	if err != nil {
		t.Fatal(err)
	}
	wantOrigin := OpenSSHOrigin{Alias: "confirmed-alias", CanonicalHost: "confirmed.corp.example.com"}
	repo.SetNodeOpenSSHOrigin(prep2.NodeID, wantOrigin)
	if err := repo.ConfirmNodeContext(t.Context(), prep2.NodeID); err != nil {
		t.Fatalf("ConfirmNodeContext: %v", err)
	}
	if got := repo.provider.NodeOpenSSHOrigin(prep2.NodeID); got != wantOrigin {
		t.Fatalf("r.provider origin after ConfirmNodeContext = %+v, want %+v", got, wantOrigin)
	}
}

func testP6PendingConcurrencyRace(t *testing.T) {
	store := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			opts := pendingTestOptions(2200 + uint16(idx%2))
			prep, prepErr := repo.PrepareNodeContext(t.Context(), opts)
			if prepErr != nil {
				t.Errorf("PrepareNodeContext: %v", prepErr)
				return
			}
			_, _ = repo.ResolveConnection(prep.NodeID)
			if idx%2 == 0 {
				repo.DiscardPendingNode(prep.NodeID)
			} else if cErr := repo.ConfirmNodeContext(t.Context(), prep.NodeID); cErr != nil {
				t.Errorf("ConfirmNodeContext: %v", cErr)
			}
		}(i)
	}
	// Separate pending node exercises concurrent origin setters/readers alongside confirmation.
	originPrep, err := repo.PrepareNodeContext(t.Context(), pendingTestOptions(2299))
	if err != nil {
		t.Fatal(err)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 20 {
			repo.SetNodeOpenSSHOrigin(originPrep.NodeID, OpenSSHOrigin{Alias: "race-alias", CanonicalHost: "race.example.com"})
			_ = repo.NodeOpenSSHOrigin(originPrep.NodeID)
		}
	}()
	go func() {
		defer wg.Done()
		for range 20 {
			repo.SetNodeCanonicalHost(originPrep.NodeID, "race2.example.com")
			_, _ = repo.ResolveConnection(originPrep.NodeID)
		}
	}()
	wg.Wait()
	repo.DiscardPendingNode(originPrep.NodeID)
	if leaked := repo.provider.NodeOpenSSHOrigin(originPrep.NodeID); !leaked.IsZero() {
		t.Fatalf("r.provider leaked pending origin under concurrent updates: %+v", leaked)
	}
}

func TestP6_NewRepositoryAndPrepareConfigurationValidateV2Parity(t *testing.T) {
	t.Parallel()

	baseValidCfg := func() *Configuration {
		cfg := cloneConfiguration(nil)
		cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id1"})
		return cfg
	}

	rejectCases := []struct {
		name    string
		mutate  func(*Configuration)
		wantErr error
	}{
		{
			name:   "invalid host address with openssh prefix",
			mutate: func(c *Configuration) { c.Hosts.Set("h1", models.Host{Address: "OPENSSH:victim", Port: 22}) },
		},
		{
			name:   "invalid host address with whitespace",
			mutate: func(c *Configuration) { c.Hosts.Set("h1", models.Host{Address: "bad host", Port: 22}) },
		},
		{
			name: "reserved host alias",
			mutate: func(c *Configuration) {
				c.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22, Alias: []string{"openssh"}})
			},
		},
		{
			name: "reserved node name",
			mutate: func(c *Configuration) {
				c.Nodes.Set("openssh:bad", models.Node{HostRef: "h1", IdentityRef: "id1"})
			},
		},
		{
			name: "reserved node alias",
			mutate: func(c *Configuration) {
				c.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id1", Alias: []string{"OPENSSH:web"}})
			},
		},
		{
			name: "empty host_ref even when empty host key exists",
			mutate: func(c *Configuration) {
				c.Hosts.Set("", models.Host{Address: "10.0.0.2", Port: 22})
				c.Nodes.Set("n1", models.Node{HostRef: "", IdentityRef: "id1"})
			},
			wantErr: ErrHostNotFound,
		},
		{
			name: "missing identity_ref wraps ErrIdentityNotFound",
			mutate: func(c *Configuration) {
				c.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "missing-id"})
			},
			wantErr: ErrIdentityNotFound,
		},
		{
			name: "invalid global execution",
			mutate: func(c *Configuration) {
				c.Execution = &ssh.ExecutionConfig{Interpreter: "bogus-shell"}
			},
		},
		{
			name: "incompatible effective node and global execution",
			mutate: func(c *Configuration) {
				c.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
				c.Nodes.Set("n1", models.Node{
					HostRef:     "h1",
					IdentityRef: "id1",
					Execution:   &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell},
				})
			},
		},
		{
			name: "invalid global ssh_options",
			mutate: func(c *Configuration) {
				c.SSHOptions = ssh.OptionsFromControl(&ssh.ControlConfig{Master: ssh.ControlMasterAuto, Path: "/tmp/bad-%z"})
			},
		},
		{
			name: "incompatible effective node and global ssh_options",
			mutate: func(c *Configuration) {
				c.SSHOptions = ssh.MustOptions(
					ssh.OptionControlMaster, "auto",
					ssh.OptionControlPath, "~/.ssh/cm-%C",
					ssh.OptionControlPersist, "10m",
				)
				c.Nodes.Set("n1", models.Node{
					HostRef:     "h1",
					IdentityRef: "id1",
					SSHOptions:  ssh.MustOptions(ssh.OptionControlMaster, "no"),
				})
			},
		},
		{
			name: "invalid schema v2 credential default_store",
			mutate: func(c *Configuration) {
				c.Credential.DefaultStore = "nonexistent-store"
			},
		},
		{
			name: "invalid credential remember_prompted",
			mutate: func(c *Configuration) {
				c.Credential.RememberPrompted = "sometimes"
			},
		},
		{
			name: "helper store with forbidden shell characters",
			mutate: func(c *Configuration) {
				c.Credential.Stores["bad-helper"] = StoreConfig{Type: StoreTypeHelper, Command: "echo; rm -rf /"}
			},
		},
		{
			name: "incomplete privilege_password_ref",
			mutate: func(c *Configuration) {
				c.Nodes.Set("n1", models.Node{
					HostRef:              "h1",
					IdentityRef:          "id1",
					PrivilegePasswordRef: &credential.Ref{StoreID: "file"},
				})
			},
		},
		{
			name: "empty non-nil login_password_ref",
			mutate: func(c *Configuration) {
				c.Identities.Set("id1", models.Identity{User: "ops", LoginPasswordRef: &credential.Ref{StoreID: "file"}})
			},
		},
		{
			name: "invalid OTP command shell metacharacters",
			mutate: func(c *Configuration) {
				c.Identities.Set("id1", models.Identity{User: "ops", OTP: &models.OTPConfig{Command: "oathtool;id"}})
			},
		},
		{
			name: "invalid KeyboardInteractive duplicate rule names",
			mutate: func(c *Configuration) {
				c.Identities.Set("id1", models.Identity{
					User: "ops",
					KeyboardInteractive: &models.KeyboardInteractiveConfig{
						Rules: []models.ChallengeRule{
							{Name: "dup", PromptPattern: "Code:", Source: models.ChallengeSourceOTP},
							{Name: "dup", PromptPattern: "PIN:", Source: models.ChallengeSourceOTP},
						},
					},
				})
			},
		},
	}

	for _, tc := range rejectCases {
		t.Run("NewRepository_reject_"+tc.name, func(t *testing.T) {
			cfg := baseValidCfg()
			tc.mutate(cfg)
			_, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{})
			if !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) = %v, want ErrSchemaValidation", tc.name, err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewRepositoryWithoutOpenSSH(%s) = %v, want %v", tc.name, err, tc.wantErr)
			}
		})
	}

	t.Run("prepareConfiguration enforces parity on mutations", func(t *testing.T) {
		cfg := baseValidCfg()
		_, _, _, err := prepareConfiguration(cfg, func(mut *Configuration) error {
			mut.Hosts.Set("h1", models.Host{Address: "openssh:bad", Port: 22})
			return nil
		})
		if !errors.Is(err, ErrSchemaValidation) {
			t.Fatalf("prepareConfiguration(invalid host) = %v, want ErrSchemaValidation", err)
		}
	})

	t.Run("NewProviderWithoutOpenSSH remains read-only safe for minimal unit fixtures", func(t *testing.T) {
		minimal := cloneConfiguration(nil)
		minimal.Nodes.Set("dangling", models.Node{HostRef: "missing-h", IdentityRef: "missing-id"})
		prov := NewProviderWithoutOpenSSH(minimal)
		if _, _, _, err := prov.Resolve("dangling"); !errors.Is(err, ErrHostNotFound) {
			t.Fatalf("minimal Provider.Resolve = %v, want ErrHostNotFound", err)
		}
	})

	t.Run("PreviewConnection allows pre-probe partial execution while enforcing standalone checks", func(t *testing.T) {
		cfg := baseValidCfg()
		cfg.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}
		repo, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.PreviewConnection("draft-win",
			models.Node{Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterPowerShell}},
			models.Host{Address: "10.0.0.9", Port: 22},
			models.Identity{User: "admin"},
		); err != nil {
			t.Fatalf("PreviewConnection rejected valid pre-probe draft: %v", err)
		}
		if _, err := repo.PreviewConnection("draft-bad",
			models.Node{},
			models.Host{Address: "openssh:bad", Port: 22},
			models.Identity{User: "admin"},
		); !errors.Is(err, ErrSchemaValidation) {
			t.Fatalf("PreviewConnection(bad host) = %v, want ErrSchemaValidation", err)
		}
	})
}

func TestP6_TargetRefReservedOpenSSHPrefixAndRoundTripHygiene(t *testing.T) {
	t.Parallel()

	roundTripCases := []struct {
		raw  string
		want TargetRef
	}{
		{
			raw:  "openssh:22",
			want: TargetRef{OpenSSH: true, Host: "22"},
		},
		{
			raw:  "user@openssh:22",
			want: TargetRef{OpenSSH: false, User: "user", Host: "openssh", Port: 22, HasPort: true},
		},
		{
			raw:  "openssh",
			want: TargetRef{OpenSSH: false, Host: "openssh"},
		},
		{
			raw:  "openssh:openssh",
			want: TargetRef{OpenSSH: true, Host: "openssh"},
		},
		{
			raw:  "openssh:user@openssh:22",
			want: TargetRef{OpenSSH: true, User: "user", Host: "openssh", Port: 22, HasPort: true},
		},
	}

	for _, tc := range roundTripCases {
		t.Run("roundtrip_"+tc.raw, func(t *testing.T) {
			got, err := ParseTargetRef(tc.raw)
			if err != nil {
				t.Fatalf("ParseTargetRef(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("ParseTargetRef(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Validate(%+v) error = %v", got, err)
			}
			norm := got.NormalizedString()
			if norm != tc.raw {
				t.Fatalf("NormalizedString() = %q, want %q", norm, tc.raw)
			}
			reparsed, err := ParseTargetRef(norm)
			if err != nil || reparsed != got {
				t.Fatalf("reparse(%q) = (%+v, %v), want %+v", norm, reparsed, err, got)
			}
		})
	}

	invalidRefs := []struct {
		name         string
		ref          TargetRef
		wantEmptyStr bool
		wantErrSub   string
	}{
		{
			name:         "ambiguous non-OpenSSH openssh:22 without user",
			ref:          TargetRef{OpenSSH: false, Host: "openssh", Port: 22, HasPort: true},
			wantEmptyStr: true,
			wantErrSub:   "reserved for OpenSSH virtual selectors",
		},
		{
			name:         "duplicate OpenSSH openssh:openssh:22 without user",
			ref:          TargetRef{OpenSSH: true, Host: "openssh", Port: 22, HasPort: true},
			wantEmptyStr: true,
			wantErrSub:   "duplicate",
		},
		{
			name:         "non-OpenSSH user starting with openssh:",
			ref:          TargetRef{OpenSSH: false, User: "openssh:alice", Host: "web"},
			wantEmptyStr: true,
			wantErrSub:   "reserved for OpenSSH virtual selectors",
		},
		{
			name:         "OpenSSH user starting with openssh:",
			ref:          TargetRef{OpenSSH: true, User: "openssh:alice", Host: "web"},
			wantEmptyStr: true,
			wantErrSub:   "duplicate",
		},
		{
			name:         "empty host",
			ref:          TargetRef{},
			wantEmptyStr: true,
			wantErrSub:   "empty",
		},
		{
			name:         "HasPort true with port 0",
			ref:          TargetRef{Host: "web", HasPort: true, Port: 0},
			wantEmptyStr: true,
			wantErrSub:   "invalid port 0",
		},
		{
			name:         "HasPort false with nonzero port",
			ref:          TargetRef{Host: "web", HasPort: false, Port: 22},
			wantEmptyStr: true,
			wantErrSub:   "HasPort=false",
		},
		{
			name:       "non-canonical bracketed IPv6 host without port",
			ref:        TargetRef{Host: "[::1]"},
			wantErrSub: "canonical",
		},
	}

	for _, tc := range invalidRefs {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("Validate(%+v) = %v, want substring %q", tc.ref, err, tc.wantErrSub)
			}
			if tc.wantEmptyStr {
				if norm := tc.ref.NormalizedString(); norm != "" {
					t.Fatalf("NormalizedString(%+v) = %q, want empty string", tc.ref, norm)
				}
			}
		})
	}
}
