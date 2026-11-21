package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
)

type round5CanonResolver struct {
	hosts map[string][]string
}

func (r *round5CanonResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if ips, ok := r.hosts[host]; ok {
		return ips, nil
	}
	return nil, context.DeadlineExceeded
}

func (r *round5CanonResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	return host + ".", nil
}

func TestRound5_P1_3_VirtualCanonicalTargetZeroPendingAndZeroProviderMutation(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  User alice",
		"  Port 2201",
		"  ConnectTimeout 11",
		"",
		"Host other",
		"  User bob",
		"  Port 2202",
		"",
		"Host *.corp.example.com",
		"  User direct-user",
		"  HostName 10.50.0.10",
		"  ServerAliveInterval 31",
	}, "\n") + "\n"

	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(nil, &abortSaveStore{}, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	canonTarget := OpenSSHNodePrefix + "short.corp.example.com"
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     canonTarget,
			OriginalHost: "short",
		},
	}, func(lease PendingLease) error {
		if lease.NodeID() != canonTarget {
			t.Fatalf("WithPendingNode = %q, want %q", lease.NodeID(), canonTarget)
		}
		repo.pendingMu.RLock()
		pendingCount := len(repo.pending)
		repo.pendingMu.RUnlock()
		if pendingCount != 0 {
			t.Fatalf("ProvenanceOpenSSHVirtual entered r.pending (count=%d), want 0", pendingCount)
		}
		if gotAlias, gotCanon := repo.NodeOpenSSHAlias(canonTarget), repo.NodeCanonicalHost(canonTarget); gotAlias != "" || gotCanon != "" {
			t.Fatalf("r.provider polluted by virtual WithPendingNode: alias=%q canon=%q", gotAlias, gotCanon)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(openssh:canon) failed: %v", err)
	}

	// Subsequent resolution via different OriginalHost ("other") or bare ProxyJump must not be hijacked.
	resOther, err := ResolveTarget(repo, ConnectionTarget{
		Selector:     canonTarget,
		OriginalHost: "other",
	})
	if err != nil {
		t.Fatalf("ResolveTarget(other) failed: %v", err)
	}
	if resOther.User != "bob" || resOther.Port != 2202 || resOther.OpenSSHAlias != "other" {
		t.Fatalf("second session hijacked by first PrepareNodeContext: %+v", resOther)
	}

	resDirect, err := ResolveTarget(repo, ConnectionTarget{Selector: canonTarget})
	if err != nil {
		t.Fatalf("ResolveTarget(%q): %v", canonTarget, err)
	}
	if resDirect.Host != "10.50.0.10" || resDirect.User != "direct-user" || resDirect.OpenSSHAlias != "" || resDirect.CanonicalHost != "" {
		t.Fatalf("ResolveTarget(%q) hijacked by prior PrepareNodeContext: %+v", canonTarget, resDirect)
	}
}

func TestRound5_P1_4_DefaultStoreConfirmAndReplaceNodePrunesAndWithOverridePreservesSaved(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host edge",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  ConnectTimeout 19",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	var prepID string
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{
			Selector:     "edge.corp.example.com",
			OriginalHost: "edge",
		},
	}, func(lease PendingLease) error {
		prepID = lease.NodeID()
		if !repo.IsPendingNode(prepID) {
			t.Fatalf("expected pending node %q before Confirm", prepID)
		}
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode/Confirm failed: %v", err)
	}
	if gotAlias, gotCanon := repo.NodeOpenSSHAlias(prepID), repo.NodeCanonicalHost(prepID); gotAlias != "edge" || gotCanon != "edge.corp.example.com" {
		t.Fatalf("post-confirm metadata = (%q, %q), want (edge, edge.corp.example.com)", gotAlias, gotCanon)
	}

	// WithOpenSSHConfigOverride(-F) must preserve saved nodes' OpenSSHAlias/CanonicalHost.
	overrideFile := filepath.Join(dir, "override_ssh_config")
	if err := writeTestFile(overrideFile, "Host edge\n  ConnectTimeout 33\n"); err != nil {
		t.Fatal(err)
	}
	overrideProv, err := WithOpenSSHConfigOverride(repo, overrideFile)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	if n, ok := overrideProv.GetNode(prepID); !ok || n.OpenSSHAlias != "edge" || n.CanonicalHost != "edge.corp.example.com" {
		t.Fatalf("WithOpenSSHConfigOverride lost saved node metadata: ok=%v node=%+v", ok, n)
	}

	// ReplaceNodeAtRefContext changing Port/Address must clear stale OpenSSHAlias and CanonicalHost.
	snap := repo.Snapshot()
	ver, err := nodeEntityVersion(snap, prepID)
	if err != nil {
		t.Fatal(err)
	}
	node, _ := snap.Nodes.Get(prepID)
	ident, _ := snap.Identities.Get(node.IdentityRef)
	if err := repo.ReplaceNodeAtRefContext(t.Context(), NodeRef{ID: prepID, Version: ver}, prepID, node, models.Host{
		Address: "10.99.0.1",
		Port:    2222,
	}, ident); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(prepID) != "" || repo.NodeCanonicalHost(prepID) != "" {
		t.Fatalf("address change did not clear OpenSSH metadata: alias=%q canon=%q",
			repo.NodeOpenSSHAlias(prepID), repo.NodeCanonicalHost(prepID))
	}

	verifyCreateAndImportPrunesDirtyMetadata(t, repo)
}

func verifyCreateAndImportPrunesDirtyMetadata(t *testing.T, repo *Repository) {
	t.Helper()

	// CreateNodeContext and ImportOpenSSHHostsContext clear pre-existing dirty side-map entries.
	newID := "fresh-node"
	repo.SetNodeOpenSSHAlias(newID, "dirty-alias")
	repo.SetNodeCanonicalHost(newID, "dirty.example.com")
	if _, err := repo.CreateNodeContext(t.Context(), newID, models.Node{HostRef: "h-new", IdentityRef: "id-new"}, models.Host{Address: "10.0.0.5", Port: 22}, models.Identity{User: "ops"}); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(newID) != "" || repo.NodeCanonicalHost(newID) != "" {
		t.Fatalf("CreateNodeContext retained dirty side-map metadata: alias=%q canon=%q", repo.NodeOpenSSHAlias(newID), repo.NodeCanonicalHost(newID))
	}

	impID := "imported-r5"
	repo.SetNodeOpenSSHAlias(impID, "dirty-imp")
	repo.SetNodeCanonicalHost(impID, "dirty.imp.com")
	if _, err := repo.ImportOpenSSHHostsContext(t.Context(), []OpenSSHHost{{
		Name:     impID,
		Host:     models.Host{Address: "10.0.0.6", Port: 22},
		Identity: models.Identity{User: "ops"},
		Node:     models.Node{OpenSSHAlias: impID},
	}}); err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	if repo.NodeOpenSSHAlias(impID) != "" || repo.NodeCanonicalHost(impID) != "" {
		t.Fatalf("ImportOpenSSHHostsContext retained dirty metadata: alias=%q canon=%q", repo.NodeOpenSSHAlias(impID), repo.NodeCanonicalHost(impID))
	}
}

func TestRound5_P2_6_And_P2_8_PendingEvictionAndAtomicMetadataReplacement(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}

	// P2-6: Ensure CheckRefUnreferenced disk reload evicts stale pending entry,
	// and CreateNodeContext/ImportOpenSSHHostsContext/EnsureNodeContext evict stale pending.
	createID := "ops@10.1.0.5:22"
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "10.1.0.5", User: "ops", HasUser: true, Port: 22, HasPort: true},
	}, func(PendingLease) error {
		if _, err := repo.CreateNodeContext(t.Context(), createID, models.Node{HostRef: "h-create", IdentityRef: "id-create"}, models.Host{Address: "10.1.0.5", Port: 22}, models.Identity{User: "ops"}); err != nil {
			t.Fatalf("CreateNodeContext: %v", err)
		}
		repo.pendingMu.RLock()
		_, stillPendingCreate := repo.pending[createID]
		repo.pendingMu.RUnlock()
		if stillPendingCreate {
			t.Fatalf("CreateNodeContext left stale pending entry for %q", createID)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(createID): %v", err)
	}

	// ReplaceNodeAtRefContext evicts stale pending for both old and renamed nodeID.
	renamedID := "renamed@10.1.0.6:22"
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "10.1.0.6", User: "renamed", HasUser: true, Port: 22, HasPort: true},
	}, func(PendingLease) error {
		snap := repo.Snapshot()
		ver, err := nodeEntityVersion(snap, createID)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.ReplaceNodeAtRefContext(t.Context(), NodeRef{ID: createID, Version: ver}, renamedID, models.Node{HostRef: "h-create", IdentityRef: "id-create"}, models.Host{Address: "10.1.0.6", Port: 22}, models.Identity{User: "renamed"}); err != nil {
			t.Fatalf("ReplaceNodeAtRefContext: %v", err)
		}
		repo.pendingMu.RLock()
		_, stillPendingRename := repo.pending[renamedID]
		repo.pendingMu.RUnlock()
		if stillPendingRename {
			t.Fatalf("ReplaceNodeAtRefContext left stale pending entry for %q", renamedID)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(renamedID): %v", err)
	}

	// CheckRefUnreferenced disk reload evicts stale pending when stale memory snapshot refreshes from disk.
	staleRef := credential.Ref{StoreID: "system", ItemID: "disk-evicted-ref"}
	diskStore := &memoryPersistStore{cfg: cloneConfiguration(nil)}
	repoDisk, err := NewRepositoryWithoutOpenSSH(nil, diskStore)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(repoDisk): %v", err)
	}
	if _, err := repoDisk.CreateNodeContext(t.Context(), "stale-holder", models.Node{HostRef: "h-disk", IdentityRef: "id-disk"}, models.Host{Address: "10.2.0.1", Port: 22}, models.Identity{
		User:             "ops",
		LoginPasswordRef: &staleRef,
	}); err != nil {
		t.Fatalf("CreateNodeContext(stale-holder): %v", err)
	}
	if err := repoDisk.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "10.2.0.9", User: "ops", HasUser: true, Port: 22, HasPort: true},
	}, func(lease PendingLease) error {
		diskReplacement := cloneConfiguration(nil)
		diskReplacement.Nodes.Set(lease.NodeID(), models.Node{HostRef: "h-new", IdentityRef: "id-new"})
		diskReplacement.Hosts.Set("h-new", models.Host{Address: "10.2.0.9", Port: 22})
		diskReplacement.Identities.Set("id-new", models.Identity{User: "ops"})
		diskStore.mu.Lock()
		diskStore.cfg = diskReplacement
		diskStore.mu.Unlock()
		if _, err := repoDisk.CheckRefUnreferenced(t.Context(), staleRef); err != nil {
			t.Fatalf("CheckRefUnreferenced: %v", err)
		}
		repoDisk.pendingMu.RLock()
		_, stillPendingDisk := repoDisk.pending[lease.NodeID()]
		repoDisk.pendingMu.RUnlock()
		if stillPendingDisk {
			t.Fatal("CheckRefUnreferenced did not evict stale r.pending entry on disk refresh")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(pendingDiskRes): %v", err)
	}

	// P2-8: atomic replacement clears old CanonicalHost when a new session updates only OpenSSHAlias.
	repo.provider.setSavedNodeOpenSSHMetadataIfPresent(renamedID, "alias-one", "canon-one.example.com")
	if repo.NodeOpenSSHAlias(renamedID) != "alias-one" || repo.NodeCanonicalHost(renamedID) != "canon-one.example.com" {
		t.Fatalf("initial metadata mismatch: (%q, %q)", repo.NodeOpenSSHAlias(renamedID), repo.NodeCanonicalHost(renamedID))
	}
	repo.provider.setSavedNodeOpenSSHMetadataIfPresent(renamedID, "alias-two", "")
	if repo.NodeOpenSSHAlias(renamedID) != "alias-two" || repo.NodeCanonicalHost(renamedID) != "" {
		t.Fatalf("non-atomic chimera metadata left behind: (%q, %q)", repo.NodeOpenSSHAlias(renamedID), repo.NodeCanonicalHost(renamedID))
	}
}

func TestRound5_P2_11_P3_8_P3_9_HostNameNoneCanonicalKeyAndProxyJumpNormalize(t *testing.T) {
	t.Parallel()

	// P3-8: host_name is NOT a supported pseudo-alias of hostname.
	if got := ssh.CanonicalOptionKey("host_name"); got != "" {
		t.Fatalf("CanonicalOptionKey(\"host_name\") = %q, want \"\"", got)
	}
	if got := ssh.CanonicalOptionKey("proxy_jump"); got != ssh.OptionProxyJump {
		t.Fatalf("CanonicalOptionKey(\"proxy_jump\") = %q, want %q", got, ssh.OptionProxyJump)
	}

	// P2-11: -o HostName=none is treated literally ("none") so Host 10.0.0.1 does not suppress canonicalization.
	sshCfg := strings.Join([]string{
		"Host short",
		"  HostName 10.0.0.1",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  User ops",
		"  ProxyJump none,none",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := NewProviderWithOpenSSHParser(nil, parser)

	canonRes, err := CanonicalizeHost(t.Context(), CanonicalizeInput{
		Provider:      prov,
		Host:          "short",
		RawCLIOptions: []string{"HostName=none"},
		Resolver: &round5CanonResolver{
			hosts: map[string][]string{"none.corp.example.com": {"10.20.0.2"}},
		},
	})
	if err != nil {
		t.Fatalf("CanonicalizeHost failed: %v", err)
	}
	if !canonRes.Canonicalized || canonRes.CanonicalHost != "none.corp.example.com" {
		t.Fatalf("HostName=none did not behave literally: %+v", canonRes)
	}

	// P3-9: baseJump="none,none" or " , " normalizes resolved ProxyJump to "" across
	// both OpenSSH virtual targets and saved nodes (exercising normalizeTargetJump directly).
	res, err := ResolveTarget(prov, ConnectionTarget{Selector: OpenSSHNodePrefix + "app.corp.example.com"})
	if err != nil {
		t.Fatalf("ResolveTarget failed: %v", err)
	}
	if res.ProxyJump != "" {
		t.Fatalf("ResolveTarget ProxyJump = %q, want empty when baseJump is disabled", res.ProxyJump)
	}
	savedJumpCfg := cloneConfiguration(nil)
	savedJumpCfg.Hosts.Set("hj", models.Host{Address: "10.50.0.99", Port: 22})
	savedJumpCfg.Identities.Set("ij", models.Identity{User: "ops"})
	savedJumpCfg.Nodes.Set("saved-none-jump", models.Node{HostRef: "hj", IdentityRef: "ij", ProxyJump: "none, ,none"})
	savedJumpProv := NewProviderWithoutOpenSSH(savedJumpCfg)
	savedRes, err := ResolveTarget(savedJumpProv, ConnectionTarget{Selector: "saved-none-jump"})
	if err != nil {
		t.Fatalf("ResolveTarget(saved-none-jump) failed: %v", err)
	}
	if savedRes.ProxyJump != "" {
		t.Fatalf("saved-none-jump ProxyJump = %q, want empty", savedRes.ProxyJump)
	}
	if got := normalizeTargetJump(savedJumpProv, " , ", ConnectionTarget{}); got != "" {
		t.Fatalf("normalizeTargetJump(\" , \") = %q, want empty", got)
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
