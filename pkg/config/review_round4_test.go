package config

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound4_P1_8_ResolveTargetExplicitVirtualAppliesUserPortAndJump(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host app-virt",
		"  HostName 10.10.0.5",
		"  User cfguser",
		"  Port 2201",
		"  ProxyJump bastion",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(nil, &abortSaveStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// Simulate dirty shared side maps on r.provider to confirm ResolveTarget never reads them.
	repo.SetNodeOpenSSHAlias(OpenSSHNodePrefix+"app-virt", "hijacked-alias")
	repo.SetNodeCanonicalHost(OpenSSHNodePrefix+"app-virt", "hijacked.example.com")

	resolved, err := ResolveTarget(repo, ConnectionTarget{
		Selector:     OpenSSHNodePrefix + "app-virt",
		User:         "carol",
		HasUser:      true,
		Port:         2222,
		HasPort:      true,
		ProxyJump:    "none,none",
		HasProxyJump: true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if resolved.User != "carol" || resolved.Port != 2222 {
		t.Fatalf("ResolveTarget user/port = (%q, %d), want (\"carol\", 2222)", resolved.User, resolved.Port)
	}
	if resolved.ProxyJump != "" {
		t.Fatalf("ResolveTarget ProxyJump = %q, want empty on none,none", resolved.ProxyJump)
	}
	if resolved.OpenSSHAlias != "app-virt" || resolved.CanonicalHost != "" {
		t.Fatalf("ResolveTarget metadata = (alias=%q, canon=%q), want (\"app-virt\", \"\") without hijack", resolved.OpenSSHAlias, resolved.CanonicalHost)
	}

	inlineRes, err := ResolveTarget(repo, ConnectionTarget{
		Selector: OpenSSHNodePrefix + "bob@app-virt:2323",
	})
	if err != nil {
		t.Fatalf("ResolveTarget inline: %v", err)
	}
	if inlineRes.User != "bob" || inlineRes.Port != 2323 {
		t.Fatalf("ResolveTarget inline user/port = (%q, %d), want (\"bob\", 2323)", inlineRes.User, inlineRes.Port)
	}
}

func TestRound4_P1_9a_VirtualOpenSSHIsolatedFromSideMapsAndResolveWithOrigin(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short-a",
		"  User user-a",
		"  IdentityFile /tmp/id_a",
		"",
		"Host short-b",
		"  User user-b",
		"  IdentityFile /tmp/id_b",
		"",
		"Host shared.corp.example.com",
		"  User direct-user",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(nil, &abortSaveStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	var prepAID string
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     OpenSSHNodePrefix + "shared.corp.example.com",
			OriginalHost: "short-a",
		},
	}, func(lease PendingLease) error {
		prepAID = lease.NodeID()
		// Decision 1.A: ProvenanceOpenSSHVirtual must neither leak into r.pending nor mutate r.provider.
		repo.pendingMu.RLock()
		_, hasPendingVirtual := repo.pending[prepAID]
		repo.pendingMu.RUnlock()
		if hasPendingVirtual {
			t.Fatalf("r.pending leaked virtual OpenSSH entry %q", prepAID)
		}
		if got := repo.NodeOpenSSHAlias(prepAID); got != "" {
			t.Fatalf("NodeOpenSSHAlias = %q, want empty (stateless virtual resolution)", got)
		}
		if got := repo.provider.NodeOpenSSHAlias(prepAID); got != "" {
			t.Fatalf("committed r.provider polluted with virtual alias %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(short-a): %v", err)
	}

	// ResolveConnectionWithOrigin isolates concurrent sessions for short-a, short-b, and direct.
	assertResolveOriginState(t, repo, prepAID, "short-a", "user-a", "short-a", "shared.corp.example.com")
	assertResolveOriginState(t, repo, prepAID, "openssh:short-b", "user-b", "short-b", "shared.corp.example.com")
	assertResolveOriginState(t, repo, prepAID, "", "direct-user", "shared.corp.example.com", "")

	// Unqualified ResolveConnection stays direct without cross-session hijack.
	snapUnqualified, err := repo.ResolveConnection(prepAID)
	if err != nil {
		t.Fatalf("ResolveConnection(unqualified): %v", err)
	}
	if snapUnqualified.Identity.User != "direct-user" || snapUnqualified.Node.CanonicalHost != "" {
		t.Fatalf("ResolveConnection(unqualified) = user:%q canon:%q, want direct-user / empty", snapUnqualified.Identity.User, snapUnqualified.Node.CanonicalHost)
	}
}

func assertResolveOriginState(
	t *testing.T,
	repo *Repository,
	nodeID, origin, wantUser, wantAlias, wantCanon string,
) {
	t.Helper()
	snap, err := repo.ResolveConnectionWithOrigin(nodeID, origin)
	if err != nil {
		t.Fatalf("ResolveConnectionWithOrigin(%q): %v", origin, err)
	}
	if snap.Identity.User != wantUser || snap.Node.OpenSSHAlias != wantAlias || snap.Node.CanonicalHost != wantCanon {
		t.Fatalf("ResolveConnectionWithOrigin(%q) = user:%q alias:%q canon:%q, want user:%q alias:%q canon:%q",
			origin, snap.Identity.User, snap.Node.OpenSSHAlias, snap.Node.CanonicalHost, wantUser, wantAlias, wantCanon)
	}
}

func TestRound4_P1_9b_PendingMetadataIsolatedFromLiveProviderAndFrozen(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host edge-short",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  ConnectTimeout 9",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(nil, &abortSaveStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "edge-short.corp.example.com",
			OriginalHost: "edge-short",
		},
	}, func(lease PendingLease) error {
		id := lease.NodeID()
		if got := repo.NodeOpenSSHAlias(id); got != "edge-short" {
			t.Fatalf("Repository.NodeOpenSSHAlias = %q, want edge-short", got)
		}
		if got := repo.provider.NodeOpenSSHAlias(id); got != "" {
			t.Fatalf("committed r.provider polluted with pending alias %q", got)
		}
		frozen := repo.Frozen().(*frozenRepository)
		if got := frozen.NodeOpenSSHAlias(id); got != "" {
			t.Fatalf("Frozen().NodeOpenSSHAlias leaked pending alias %q", got)
		}
		snap, err := repo.ResolveConnection(id)
		if err != nil || snap.Node.OpenSSHAlias != "edge-short" || snap.Node.CanonicalHost != "edge-short.corp.example.com" {
			t.Fatalf("Repository.ResolveConnection = (%+v, %v)", snap.Node, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func TestRound4_P1_9c_PruneStaleMetadataOnHostChangeAndDeletePreserveOnTagEdit(t *testing.T) {
	t.Parallel()

	repo, err := NewRepositoryWithoutOpenSSH(nil, &abortSaveStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	nodeID := "ops@10.20.0.5:22"
	node := models.Node{HostRef: "h1", IdentityRef: "id1"}
	host := models.Host{Address: "10.20.0.5", Port: 22}
	ident := models.Identity{User: "ops", AuthType: "password", Password: "pw"}
	if _, err := repo.CreateNodeContext(t.Context(), nodeID, node, host, ident); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	repo.SetNodeOpenSSHAlias(nodeID, "short-host")
	repo.SetNodeCanonicalHost(nodeID, "short-host.corp")

	// Updating tags alone must preserve session OpenSSH metadata.
	if _, err := repo.UpdateNodeTagsContext(t.Context(), []string{nodeID}, []string{"prod"}, true); err != nil {
		t.Fatalf("UpdateNodeTagsContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(nodeID) != "short-host" || repo.NodeCanonicalHost(nodeID) != "short-host.corp" {
		t.Fatalf("tag edit wrongly cleared metadata: (%q, %q)", repo.NodeOpenSSHAlias(nodeID), repo.NodeCanonicalHost(nodeID))
	}

	// Updating Host.Address must prune stale metadata inside publishWithAction.
	snapCfg := repo.Snapshot()
	ver, err := nodeEntityVersion(snapCfg, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	updatedNode := node
	updatedNode.Tags = []string{"prod"}
	newHost := models.Host{Address: "10.20.0.99", Port: 22}
	if err := repo.ReplaceNodeAtRefContext(t.Context(), NodeRef{ID: nodeID, Version: ver}, nodeID, updatedNode, newHost, ident); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(nodeID) != "" || repo.NodeCanonicalHost(nodeID) != "" {
		t.Fatalf("address change did not prune stale metadata: (%q, %q)", repo.NodeOpenSSHAlias(nodeID), repo.NodeCanonicalHost(nodeID))
	}

	// Deleting node must also prune metadata.
	repo.SetNodeOpenSSHAlias(nodeID, "readded-alias")
	snapCfg2 := repo.Snapshot()
	ver2, err := nodeEntityVersion(snapCfg2, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DeleteNodeAtRefContext(t.Context(), NodeRef{ID: nodeID, Version: ver2}); err != nil {
		t.Fatalf("DeleteNodeAtRefContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(nodeID) != "" || repo.NodeCanonicalHost(nodeID) != "" {
		t.Fatalf("node deletion did not prune stale metadata")
	}
}

func TestRound4_P1_10_ConfirmAtomicallyMergesConcurrentPendingUpgrade(t *testing.T) {
	t.Parallel()

	inner := &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}}
	store := &blockingUpgradeStore{
		inner:         inner,
		saveStarted:   make(chan struct{}),
		releaseSave:   make(chan struct{}),
		firstSaveDone: &atomic.Bool{},
		concurrent:    &atomic.Int32{},
	}
	sshCfg := strings.Join([]string{
		"Host edge",
		"  User ops",
		"",
		"Host edge.corp.example.com",
		"  HostName 10.30.0.8",
		"  Port 2222",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(cloneConfiguration(nil), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	var nodeID string
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector: "10.30.0.8",
			User:     "ops",
			HasUser:  true,
			Port:     2222,
			HasPort:  true,
		},
	}, func(lease PendingLease) error {
		nodeID = lease.NodeID()
		confirmErr := make(chan error, 1)
		go func() {
			confirmErr <- lease.Confirm(t.Context())
		}()

		select {
		case <-store.saveStarted:
		case err := <-confirmErr:
			t.Fatalf("Confirm returned before saveStarted: %v", err)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for store.saveStarted")
		}
		// Concurrent WithPendingNode upgrades r.pending[nodeID] while store.save is blocked.
		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{
				Selector:     "edge.corp.example.com",
				OriginalHost: "edge",
				Port:         2222,
				HasPort:      true,
			},
		}, func(upgraded PendingLease) error {
			if upgraded.NodeID() != nodeID {
				close(store.releaseSave)
				t.Fatalf("upgraded NodeID = %q, want %q", upgraded.NodeID(), nodeID)
			}
			close(store.releaseSave)
			select {
			case err := <-confirmErr:
				if err != nil {
					t.Fatalf("Confirm: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Confirm timed out")
			}
			return nil
		}); err != nil {
			t.Fatalf("WithPendingNode(upgrade): %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(initial): %v", err)
	}

	if gotAlias, gotCanon := repo.NodeOpenSSHAlias(nodeID), repo.NodeCanonicalHost(nodeID); gotAlias != "edge" || gotCanon != "edge.corp.example.com" {
		t.Fatalf("atomically committed metadata = (%q, %q), want (\"edge\", \"edge.corp.example.com\")", gotAlias, gotCanon)
	}
	repo.pendingMu.RLock()
	_, stillPending := repo.pending[nodeID]
	repo.pendingMu.RUnlock()
	if stillPending {
		t.Fatalf("pending entry %q was not cleaned up after atomic confirmation", nodeID)
	}
}

func TestRound4_P2_16_P3_7_BackfillMetadataAndUnwrapContract(t *testing.T) {
	t.Parallel()

	if got := UnwrapOpenSSHSelector("openssh:bob@short:22"); got != "short" {
		t.Fatalf("UnwrapOpenSSHSelector contract broken: got %q, want \"short\"", got)
	}

	cfg := cloneConfiguration(nil)
	cfg.Hosts.Set("h1", models.Host{Address: "10.40.0.5", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("ops@10.40.0.5:22", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"app.corp.example.com"},
	})
	provider := NewProviderWithoutOpenSSH(cfg)

	res, err := ResolveTarget(provider, ConnectionTarget{
		Selector:     "app.corp.example.com",
		OriginalHost: OpenSSHNodePrefix + "bob@app-short:2222",
		User:         "ops",
		HasUser:      true,
	})
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if res.OpenSSHAlias != "app-short" || res.CanonicalHost != "app.corp.example.com" {
		t.Fatalf("symmetric backfill = (alias=%q, canon=%q), want (\"app-short\", \"app.corp.example.com\")", res.OpenSSHAlias, res.CanonicalHost)
	}
}

func TestRound4_P2_20_CanonicalSnakeCaseCLIOptionAndHostNameNone(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host myalias",
		"  HostName 10.50.0.9",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	provider := NewProviderWithOpenSSHParser(nil, parser)

	cands := CanonicalDomainCandidatesWithOptions(
		provider,
		"myalias",
		[]string{
			"HostName=none",
			"canonicalize_hostname=yes",
			"canonical_domains=corp.example.com",
			"proxy_jump=none,none",
		},
		"",
	)
	// Decision 2.A: OpenSSH treats HostName=none as literal host "none", not an empty reset.
	if len(cands) != 1 || cands[0] != "none.corp.example.com" {
		t.Fatalf("CanonicalDomainCandidatesWithOptions = %v, want [none.corp.example.com]", cands)
	}
}

func TestRound4_P3_8_ParseOpenSSHMatchHostSpacingVariantsAndStrictRejection(t *testing.T) {
	t.Parallel()

	for _, validHeader := range []string{
		"Match host a,b",
		"Match host=a,b",
		"Match host = a,b",
		"Match host= a,b",
		"Match host =a,b",
	} {
		raw := validHeader + "\n  ConnectTimeout 17\n"
		p, err := NewOpenSSHParserFromReader(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("%q unexpected error: %v", validHeader, err)
		}
		opts, err := p.GetSSHOptions("b")
		if err != nil || opts.Get("connect_timeout") != "17" {
			t.Fatalf("%q options for b = (%v, %v), want connect_timeout=17", validHeader, opts, err)
		}
	}

	for _, invalidHeader := range []string{
		"Match host =a=b",
		"Match host=a=b",
		"Match host = a=b",
		"Match host a b",
		"Match host a user bob",
	} {
		raw := invalidHeader + "\n  ConnectTimeout 17\n"
		if _, err := NewOpenSSHParserFromReader(strings.NewReader(raw)); err == nil {
			t.Fatalf("%q should fail closed under strict single-criterion Match host policy", invalidHeader)
		}
	}
}

var _ = net.IPv4len
