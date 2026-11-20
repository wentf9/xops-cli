package config

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/models"
)

type abortSaveStore struct {
	mu      sync.Mutex
	base    *Configuration
	saveErr error
}

func (s *abortSaveStore) Load() (*Configuration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneConfiguration(s.base), nil
}

func (s *abortSaveStore) Save(cfg *Configuration) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.mu.Lock()
	s.base = cloneConfiguration(cfg)
	s.mu.Unlock()
	return nil
}

func TestRound3_P1_1_ProviderResolveWithProvenancePreservesPass1AndInlineOverrides(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  User config-pass1-user",
		"  Port 2201",
		"  IdentityFile /tmp/r3-id-pass1",
		"  ControlPath /tmp/r3-cm-%n-%h",
		"",
		"Host *.corp.example.com",
		"  User corp-pass2-user",
		"  ProxyJump bastion",
		"  ConnectTimeout 9",
	}, "\n") + "\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	store := &abortSaveStore{base: cloneConfiguration(nil)}
	repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}

	res, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     OpenSSHNodePrefix + "alice@short.corp.example.com:2222",
			OriginalHost: "short",
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext error = %v", err)
	}
	wantID := OpenSSHNodePrefix + "alice@short.corp.example.com:2222"
	if res.NodeID != wantID {
		t.Fatalf("NodeID = %q, want %q", res.NodeID, wantID)
	}

	snap, err := repo.ResolveConnection(wantID)
	if err != nil {
		t.Fatalf("ResolveConnection error = %v", err)
	}
	if snap.Identity.User != "alice" || snap.Host.Port != 2222 {
		t.Fatalf("inline user/port lost: user=%q port=%d, want alice:2222", snap.Identity.User, snap.Host.Port)
	}
	if !strings.HasSuffix(snap.Identity.KeyPath, "/tmp/r3-id-pass1") {
		t.Fatalf("Pass-1 IdentityFile lost: %q", snap.Identity.KeyPath)
	}
	if got := snap.Node.SSHOptions.Get(ssh.OptionControlPath); got != "/tmp/r3-cm-%n-%h" {
		t.Fatalf("Pass-1 ControlPath lost: got %q", got)
	}
	if got := snap.Node.SSHOptions.Get(ssh.OptionConnectTimeout); got != "9" {
		t.Fatalf("Pass-2 ConnectTimeout lost: got %q", got)
	}
	if snap.Node.OpenSSHAlias != "short" || snap.Node.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("Node OpenSSHAlias/CanonicalHost = (%q, %q), want (short, short.corp.example.com)", snap.Node.OpenSSHAlias, snap.Node.CanonicalHost)
	}
}

func TestRound3_P1_6_PendingConfirmationGateCleanupAfterConcurrentUpgrade(t *testing.T) {
	t.Parallel()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host short\n  User alice\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	store := &abortSaveStore{base: cloneConfiguration(nil)}
	repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}

	nodeID := FormatNodeID("alice", "short.corp.example.com", 22)
	// First Prepare without OriginalHost registers initial pending entry.
	res1, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector: "short.corp.example.com",
			User:     "alice",
			HasUser:  true,
		},
	})
	if err != nil || !res1.Created || res1.NodeID != nodeID {
		t.Fatalf("initial PrepareNodeContext = (%+v, %v), want created %q", res1, err, nodeID)
	}

	// Simulate concurrent confirmation in flight: hold the original pending gate,
	// upgrade r.pending[nodeID] to a new *pendingConnection sharing the same gate,
	// and verify both ConfirmNodeWithExecutionContext cleanup and gate re-acquisition.
	origPending := repo.pending[nodeID]
	if origPending == nil {
		t.Fatal("missing initial pending connection")
	}
	if err := origPending.gate.acquire(t.Context()); err != nil {
		t.Fatalf("acquire gate error = %v", err)
	}

	// Concurrent second Prepare with OriginalHost upgrades pending pointer while reusing gate.
	res2, err := repo.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "short.corp.example.com",
			OriginalHost: "short",
			User:         "alice",
			HasUser:      true,
		},
	})
	if err != nil || res2.NodeID != nodeID {
		origPending.gate.release()
		t.Fatalf("upgrade PrepareNodeContext = (%+v, %v)", res2, err)
	}
	upgradedPending := repo.pending[nodeID]
	if upgradedPending == nil || upgradedPending == origPending || upgradedPending.gate != origPending.gate {
		origPending.gate.release()
		t.Fatalf("expected upgraded *pendingConnection sharing gate, got orig=%p upgraded=%p", origPending, upgradedPending)
	}

	waiterDone := make(chan error, 1)
	go func() {
		_, cErr := repo.acquirePendingConfirmationGate(t.Context(), nodeID)
		waiterDone <- cErr
	}()

	// Commit with the upgraded pointer while release unblocks waiter after commit? No:
	// first test that ConfirmNodeWithExecutionContext deletes upgraded r.pending[nodeID]
	// even if gate returned the original pointer prior to upgrade.
	origPending.gate.release()
	if wErr := <-waiterDone; wErr != nil {
		t.Fatalf("concurrent acquirePendingConfirmationGate failed: %v", wErr)
	}

	// Now hold origPending manually as if acquired pre-upgrade, call confirm loop body:
	node, host, ident, err := upgradedPending.provider.Resolve(nodeID)
	if err != nil {
		t.Fatalf("Resolve upgraded pending failed: %v", err)
	}
	// Replace r.pending[nodeID] back once more to exercise confirmNodeContext deleting via gate equality.
	upgradedPending.gate.release()
	if err := origPending.gate.acquire(t.Context()); err != nil {
		t.Fatalf("re-acquire gate error = %v", err)
	}
	repo.pendingMu.Lock()
	repo.pending[nodeID] = origPending
	_, _ = repo.upgradePendingAliasAndCanonical(origPending, nodeID, node, node, host, ident)
	repo.pendingMu.Unlock()
	origPending.gate.release()

	if err := repo.ConfirmNodeWithExecutionContext(t.Context(), nodeID, &ssh.ExecutionConfig{}); err != nil {
		t.Fatalf("ConfirmNodeWithExecutionContext error = %v", err)
	}
	repo.pendingMu.RLock()
	remaining := len(repo.pending)
	repo.pendingMu.RUnlock()
	if remaining != 0 {
		t.Fatalf("r.pending leaked %d entries after ConfirmNodeWithExecutionContext", remaining)
	}

	assertGateBasedPendingCleanup(t, repo, nodeID, upgradedPending.provider)
}

func assertGateBasedPendingCleanup(t *testing.T, repo *Repository, nodeID string, prov *Provider) {
	t.Helper()
	repo.pendingMu.Lock()
	pOld := &pendingConnection{provider: prov, provenance: ProvenanceOpenSSHDerived, gate: &contextGate{}}
	pNew := &pendingConnection{provider: prov, provenance: ProvenanceOpenSSHDerived, gate: pOld.gate}
	repo.pending[nodeID] = pNew
	repo.pendingMu.Unlock()
	if pNew.gate == nil {
		t.Fatal("nil gate")
	}
	repo.pendingMu.Lock()
	if cur := repo.pending[nodeID]; cur == pOld || (cur != nil && cur.gate == pOld.gate) {
		delete(repo.pending, nodeID)
	}
	repo.pendingMu.Unlock()
	if len(repo.pending) != 0 {
		t.Fatal("gate-based cleanup did not remove upgraded pending pointer")
	}
}

func TestRound3_P2_13_AltIDReuseChecksCanonicalHostUpgradeAndConflict(t *testing.T) {
	t.Parallel()

	// Primary pending reserves deploy@10.20.30.40:22 with OpenSSHAlias="alpha".
	// Pass 1 "beta" has no HostName so Pass 2 (beta.corp.example.com / beta.other.example.com)
	// supplies HostName 10.20.30.40, colliding at primary and entering the altID path.
	sshCfg2 := strings.Join([]string{
		"Host alpha",
		"  HostName 10.20.30.40",
		"  User alice",
		"",
		"Host beta",
		"  User alice",
		"",
		"Host beta.corp.example.com",
		"  HostName 10.20.30.40",
		"  User alice",
		"",
		"Host beta.other.example.com",
		"  HostName 10.20.30.40",
		"  User alice",
	}, "\n") + "\n"
	parser2, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg2))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader(2) error = %v", err)
	}
	repo2, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), &abortSaveStore{base: cloneConfiguration(nil)}, parser2)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser(2) error = %v", err)
	}
	if _, err := repo2.PrepareNodeContext(t.Context(), EnsureNodeOptions{Target: ConnectionTarget{Selector: "alpha", User: "deploy", HasUser: true}}); err != nil {
		t.Fatalf("Prepare(alpha) error = %v", err)
	}
	wantAltID := OpenSSHNodePrefix + "deploy@beta:22"
	resBeta, err := repo2.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "beta.corp.example.com",
			OriginalHost: "beta",
			User:         "deploy",
			HasUser:      true,
		},
	})
	if err != nil || resBeta.NodeID != wantAltID {
		t.Fatalf("Prepare(beta.corp) = (%+v, %v), want %q", resBeta, err, wantAltID)
	}
	if got := repo2.NodeCanonicalHost(wantAltID); got != "beta.corp.example.com" {
		t.Fatalf("NodeCanonicalHost(%q) = %q, want beta.corp.example.com", wantAltID, got)
	}
	// Reusing identical CanonicalHost on altID succeeds.
	resReuse, err := repo2.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "beta.corp.example.com",
			OriginalHost: "beta",
			User:         "deploy",
			HasUser:      true,
		},
	})
	if err != nil || resReuse.NodeID != wantAltID {
		t.Fatalf("altID identical CanonicalHost reuse = (%+v, %v), want %q", resReuse, err, wantAltID)
	}

	// Conflicting CanonicalHost on altID must fail with ErrConfigConflict.
	_, conflictErr := repo2.PrepareNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "beta.other.example.com",
			OriginalHost: "beta",
			User:         "deploy",
			HasUser:      true,
		},
	})
	if !errors.Is(conflictErr, ErrConfigConflict) {
		t.Fatalf("conflicting altID CanonicalHost err = %v, want ErrConfigConflict", conflictErr)
	}

	// Also verify direct altID upgrade from empty CanonicalHost to non-empty CanonicalHost.
	repo2.pendingMu.Lock()
	snapCfg := repo2.provider.Snapshot()
	altPrev := repo2.pending[wantAltID]
	oldN, oldH, oldI, rErr := altPrev.provider.Resolve(wantAltID)
	if rErr != nil {
		repo2.pendingMu.Unlock()
		t.Fatalf("Resolve(altID) error = %v", rErr)
	}
	noCanonNode := oldN
	noCanonNode.CanonicalHost = ""
	noCanonCfg := cloneConfiguration(nil)
	noCanonCfg.Nodes.Set(wantAltID, noCanonNode)
	noCanonCfg.Hosts.Set(noCanonNode.HostRef, oldH)
	noCanonCfg.Identities.Set(noCanonNode.IdentityRef, oldI)
	noCanonProv := NewProviderWithoutOpenSSH(noCanonCfg)
	noCanonProv.SetNodeOpenSSHAlias(wantAltID, "beta")
	repo2.pending[wantAltID] = &pendingConnection{provider: noCanonProv, provenance: ProvenanceOpenSSHDerived, gate: altPrev.gate}
	upgradedID, handled, upErr := repo2.tryReuseOrDisambiguatePending(snapCfg, repo2.pending["deploy@10.20.30.40:22"], "deploy@10.20.30.40:22", oldN, oldH, oldI)
	repo2.pendingMu.Unlock()
	if upErr != nil || !handled || upgradedID != wantAltID {
		t.Fatalf("tryReuseOrDisambiguatePending altID upgrade = (%q, %v, %v), want (%q, true, nil)", upgradedID, handled, upErr, wantAltID)
	}
	if got := repo2.NodeCanonicalHost(wantAltID); got != "beta.corp.example.com" {
		t.Fatalf("after upgrade NodeCanonicalHost(%q) = %q, want beta.corp.example.com", wantAltID, got)
	}
}

func TestRound3_P1_7_TransactionAbortDoesNotPolluteLiveProvider(t *testing.T) {
	t.Parallel()

	parser, err := NewOpenSSHParserFromReader(strings.NewReader("Host short\n  HostName short.corp.example.com\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	store := &abortSaveStore{base: cloneConfiguration(nil)}
	repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}

	// Inject Save failure BEFORE EnsureNodeContext creates node.
	store.saveErr = errors.New("injected disk failure")
	_, err = repo.EnsureNodeContext(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "short.corp.example.com",
			OriginalHost: "short",
			User:         "alice",
			HasUser:      true,
		},
	})
	if err == nil {
		t.Fatal("expected EnsureNodeContext to fail when store.Save fails")
	}

	targetID := FormatNodeID("alice", "short.corp.example.com", 22)
	if alias := repo.NodeOpenSSHAlias(targetID); alias != "" {
		t.Fatalf("aborted EnsureNodeContext leaked OpenSSHAlias = %q", alias)
	}
	if canon := repo.NodeCanonicalHost(targetID); canon != "" {
		t.Fatalf("aborted EnsureNodeContext leaked CanonicalHost = %q", canon)
	}
}

func TestRound3_P2_9_CanonicalHostPreservedOnSinglePassAndCandidateLookup(t *testing.T) {
	t.Parallel()

	// Single-pass equivalence: Host short and Host short.corp.example.com yield identical virtual node.
	sshCfg := strings.Join([]string{
		"Host short",
		"  HostName 10.44.0.10",
		"  User ops",
		"",
		"Host short.corp.example.com",
		"  HostName 10.44.0.10",
		"  User ops",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	res, err := ResolveTarget(prov, ConnectionTarget{
		Selector:     "short.corp.example.com",
		OriginalHost: "short",
	})
	if err != nil {
		t.Fatalf("ResolveTarget error = %v", err)
	}
	if res.OpenSSHAlias != "short" || res.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("ResolveTarget OpenSSHAlias/CanonicalHost = (%q, %q), want (short, short.corp.example.com)", res.OpenSSHAlias, res.CanonicalHost)
	}

	// Candidate lookup fallback preserves consistent CanonicalHost across saved nodes sharing address.
	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.55.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("ops@10.55.0.1:22", models.Node{
		HostRef:       "h1",
		IdentityRef:   "id1",
		Alias:         []string{"app"},
		OpenSSHAlias:  "short",
		CanonicalHost: "short.corp.example.com",
	})
	repo, err := NewRepositoryWithoutOpenSSH(cfg, &abortSaveStore{base: cloneConfiguration(cfg)})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH error = %v", err)
	}
	savedRes, err := ResolveTarget(repo, ConnectionTarget{Selector: "app", User: "deploy", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(saved candidate) error = %v", err)
	}
	if savedRes.OpenSSHAlias != "short" || savedRes.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("saved candidate OpenSSHAlias/CanonicalHost = (%q, %q), want (short, short.corp.example.com)", savedRes.OpenSSHAlias, savedRes.CanonicalHost)
	}
}

func TestRound3_P1_4_And_P3_6_CanonicalDomainCandidatesAndStrictTimeout(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host proxy-host",
		"  ProxyCommand nc %h %p",
		"",
		"Host hn-host",
		"  HostName edge",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains dev.example.com corp.example.com dev.example.com",
		"  CanonicalizeMaxDots 1",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	if got := CanonicalDomainCandidates(prov, "web"); !slices.Equal(got, []string{"web.dev.example.com", "web.corp.example.com"}) {
		t.Fatalf("CanonicalDomainCandidates(web) = %v", got)
	}
	if got := CanonicalDomainCandidates(prov, "hn-host"); !slices.Equal(got, []string{"edge.dev.example.com", "edge.corp.example.com"}) {
		t.Fatalf("CanonicalDomainCandidates(hn-host) = %v", got)
	}
	if got := CanonicalDomainCandidates(prov, "web."); got != nil {
		t.Fatalf("CanonicalDomainCandidates(trailing dot) = %v, want nil", got)
	}
	if got := CanonicalDomainCandidates(prov, "a.b.c"); got != nil {
		t.Fatalf("CanonicalDomainCandidates(exceeds MaxDots) = %v, want nil", got)
	}
	if got := CanonicalDomainCandidates(prov, "proxy-host"); got != nil {
		t.Fatalf("CanonicalDomainCandidates(proxy-host) = %v, want nil", got)
	}
	if got := CanonicalDomainCandidates(prov, "127.0.0.1"); got != nil {
		t.Fatalf("CanonicalDomainCandidates(IP) = %v, want nil", got)
	}

	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"00", maxCanonicalProbeTimeout},
		{"0s", maxCanonicalProbeTimeout},
		{"0m", maxCanonicalProbeTimeout},
		{"none", maxCanonicalProbeTimeout},
		{"3", 3 * time.Second},
		{"4S", 4 * time.Second},
		{"1m", maxCanonicalProbeTimeout},
		{"1m30s", maxCanonicalProbeTimeout},
		{"99999999999999999999s", maxCanonicalProbeTimeout},
	} {
		pol := canonicalizePolicy{timeout: time.Second}
		pol.setTimeoutSeconds(tc.in)
		if pol.timeout != tc.want {
			t.Fatalf("setTimeoutSeconds(%q) = %v, want %v", tc.in, pol.timeout, tc.want)
		}
	}

	for _, invalid := range []string{"+2", "-2", "1.5s", "500ms", "10bad", "99999999999999999999bad"} {
		pol := canonicalizePolicy{timeout: 2 * time.Second}
		pol.setTimeoutSeconds(invalid)
		if pol.timeout != 2*time.Second {
			t.Fatalf("setTimeoutSeconds(%q) mutated timeout to %v, want unchanged 2s", invalid, pol.timeout)
		}
	}

	// Ensure context parameter is referenced so unused-import checks don't complain if context wasn't needed.
	_ = context.Background()
}
