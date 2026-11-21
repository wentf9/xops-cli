package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func setupProvenanceTestRepo(t *testing.T) *Repository {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	store := NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))

	sshCfg := strings.Join([]string{
		"Host jump-a",
		"  HostName 10.77.0.2",
		"  User base",
		"",
		"Host jump-b",
		"  HostName 10.77.0.3",
		"  User base",
		"",
		"Host edge-a",
		"  HostName 10.77.0.1",
		"  User base",
		"  ProxyJump jump-a",
		"",
		"Host edge-b",
		"  HostName 10.77.0.1",
		"  User base",
		"  ProxyJump jump-b",
		"",
		"Host * ",
		"  SetEnv FROM_STAR=1",
	}, "\n") + "\n"
	parser, err := NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := NewRepositoryWithOpenSSHParser(NewProviderWithoutOpenSSH(nil).Snapshot(), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return repo
}

func TestNodeProvenanceAcrossAllOrigins(t *testing.T) {
	repo := setupProvenanceTestRepo(t)
	assertSavedManagedProvenance(t, repo)
	assertOpenSSHVirtualProvenance(t, repo)
	assertOpenSSHDerivedProvenance(t, repo)
	assertAdHocPendingProvenance(t, repo)
}

func assertSavedManagedProvenance(t *testing.T, repo *Repository) {
	t.Helper()
	if _, err := repo.CreateNodeContext(
		t.Context(),
		"saved-node",
		models.Node{HostRef: "h-saved", IdentityRef: "id-saved", Alias: []string{"saved"}},
		models.Host{Address: "10.77.0.99", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	savedRes, err := repo.ResolveTarget(ConnectionTarget{Selector: "saved"})
	if err != nil {
		t.Fatalf("ResolveTarget(saved): %v", err)
	}
	if savedRes.Provenance != ProvenanceSavedManaged {
		t.Fatalf("ResolveTarget(saved).Provenance = %s, want saved_managed", savedRes.Provenance)
	}
	savedSnap, err := repo.ResolveConnection("saved-node")
	if err != nil {
		t.Fatalf("ResolveConnection(saved-node): %v", err)
	}
	if savedSnap.Provenance != ProvenanceSavedManaged || savedSnap.UpdateRef == nil {
		t.Fatalf("savedSnap = (%s, updateRef=%v), want saved_managed with non-nil UpdateRef", savedSnap.Provenance, savedSnap.UpdateRef != nil)
	}
}

func assertOpenSSHVirtualProvenance(t *testing.T, repo *Repository) {
	t.Helper()
	virtRes, err := repo.ResolveTarget(ConnectionTarget{Selector: "openssh:edge-a"})
	if err != nil {
		t.Fatalf("ResolveTarget(openssh:edge-a): %v", err)
	}
	if virtRes.Provenance != ProvenanceOpenSSHVirtual {
		t.Fatalf("ResolveTarget(openssh:edge-a).Provenance = %s, want openssh_virtual", virtRes.Provenance)
	}
	virtSnap, err := repo.ResolveConnection("openssh:edge-a")
	if err != nil {
		t.Fatalf("ResolveConnection(openssh:edge-a): %v", err)
	}
	if virtSnap.Provenance != ProvenanceOpenSSHVirtual || virtSnap.UpdateRef != nil {
		t.Fatalf("virtSnap = (%s, updateRef=%v), want openssh_virtual with nil UpdateRef", virtSnap.Provenance, virtSnap.UpdateRef != nil)
	}
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "openssh:edge-a"},
	}, func(lease PendingLease) error {
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode(openssh:edge-a): %v", err)
	}
	if _, persisted := repo.GetNode("openssh:edge-a"); persisted {
		t.Fatal("openssh:edge-a must never be persisted by Confirm")
	}
}

func assertOpenSSHDerivedProvenance(t *testing.T, repo *Repository) {
	t.Helper()
	derivedRes, err := repo.ResolveTarget(ConnectionTarget{Selector: "edge-a", User: "ops", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(ops@edge-a): %v", err)
	}
	if derivedRes.Provenance != ProvenanceOpenSSHDerived {
		t.Fatalf("ResolveTarget(ops@edge-a).Provenance = %s, want openssh_derived", derivedRes.Provenance)
	}
	var nodeIDA string
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "edge-a", User: "ops", HasUser: true},
	}, func(leaseA PendingLease) error {
		nodeIDA = leaseA.NodeID()
		snapA, err := repo.ResolveConnection(nodeIDA)
		if err != nil {
			t.Fatalf("ResolveConnection(%q): %v", nodeIDA, err)
		}
		if snapA.Provenance != ProvenanceOpenSSHDerived {
			t.Fatalf("pending snapA.Provenance = %s, want openssh_derived", snapA.Provenance)
		}

		if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
			Target: ConnectionTarget{Selector: "edge-b", User: "ops", HasUser: true},
		}, func(leaseB PendingLease) error {
			if !IsOpenSSHNodeID(leaseB.NodeID()) {
				t.Fatalf("expected collided alias to receive openssh: ID, got %q", leaseB.NodeID())
			}
			snapB, err := repo.ResolveConnection(leaseB.NodeID())
			if err != nil {
				t.Fatalf("ResolveConnection(%q): %v", leaseB.NodeID(), err)
			}
			if snapB.Provenance != ProvenanceOpenSSHDerived || snapB.UpdateRef != nil {
				t.Fatalf("collided pending snapB = (%s, updateRef=%v), want openssh_derived with nil UpdateRef", snapB.Provenance, snapB.UpdateRef != nil)
			}
			return nil
		}); err != nil {
			t.Fatalf("WithPendingNode(ops@edge-b): %v", err)
		}

		return leaseA.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode(ops@edge-a): %v", err)
	}
	afterConfirmA, err := repo.ResolveConnection(nodeIDA)
	if err != nil {
		t.Fatalf("ResolveConnection after confirm(%q): %v", nodeIDA, err)
	}
	if afterConfirmA.Provenance != ProvenanceSavedManaged {
		t.Fatalf("afterConfirmA.Provenance = %s, want saved_managed", afterConfirmA.Provenance)
	}
}

func assertAdHocPendingProvenance(t *testing.T, repo *Repository) {
	t.Helper()
	adhocRes, err := repo.ResolveTarget(ConnectionTarget{Selector: "10.88.0.5", User: "adhoc", HasUser: true})
	if err != nil {
		t.Fatalf("ResolveTarget(adhoc): %v", err)
	}
	if adhocRes.Provenance != ProvenanceAdHocPending {
		t.Fatalf("ResolveTarget(adhoc).Provenance = %s, want adhoc_pending", adhocRes.Provenance)
	}
	if err := repo.WithPendingNode(t.Context(), EnsureNodeOptions{
		Target: ConnectionTarget{Selector: "10.88.0.5", User: "adhoc", HasUser: true},
	}, func(lease PendingLease) error {
		adhocSnap, err := repo.ResolveConnection(lease.NodeID())
		if err != nil {
			t.Fatalf("ResolveConnection(%q): %v", lease.NodeID(), err)
		}
		if adhocSnap.Provenance != ProvenanceAdHocPending {
			t.Fatalf("adhocSnap.Provenance = %s, want adhoc_pending", adhocSnap.Provenance)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(adhoc): %v", err)
	}
}

func TestNodeProvenanceHelpers(t *testing.T) {
	if !ProvenanceSavedManaged.IsSaved() || ProvenanceOpenSSHVirtual.IsSaved() {
		t.Fatal("unexpected IsSaved result")
	}
	if !ProvenanceOpenSSHVirtual.IsOpenSSH() || !ProvenanceOpenSSHDerived.IsOpenSSH() || ProvenanceSavedManaged.IsOpenSSH() || ProvenanceAdHocPending.IsOpenSSH() {
		t.Fatal("unexpected IsOpenSSH result")
	}
	if !ProvenanceOpenSSHVirtual.IsUnpersistedOpenSSH() || !ProvenanceOpenSSHDerived.IsUnpersistedOpenSSH() || ProvenanceSavedManaged.IsUnpersistedOpenSSH() || ProvenanceAdHocPending.IsUnpersistedOpenSSH() {
		t.Fatal("unexpected IsUnpersistedOpenSSH result")
	}
	if ProvenanceUnknown.String() != "unknown" {
		t.Fatalf("ProvenanceUnknown.String() = %q", ProvenanceUnknown.String())
	}
}
