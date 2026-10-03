package ports

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/ssh"
)

func fixtureSnapshot() OperationSnapshot {
	return OperationSnapshot{DomainID: "domain", Revision: "display-1", PolicyRevision: "policy-1", Policy: policy.Config{Enabled: true, ApprovalThreshold: "dangerous"},
		Targets:   map[string]Target{"node": {Info: NodeInfo{ID: "node", Alias: []string{"alias"}}, Version: "execution-1", Plan: ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{{NodeID: "node", Address: "192.0.2.1", Port: 22, User: "fixture", AuthType: "key", KeyRef: "key", AuthUpdateToken: "key-1"}}}}},
		Selectors: map[string]string{"alias": "node"},
	}
}

func TestBindingIgnoresDisplayButIncludesExecutionDependencies(t *testing.T) {
	snapshot := fixtureSnapshot()
	binding, err := Bind(snapshot, "scope", "xops_ssh_run", map[string]string{"command": "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	view := snapshot.Clone()
	view.Revision = "display-2"
	node := view.Targets["node"]
	node.Info.Alias = []string{"renamed"}
	view.Targets["node"] = node
	view.Policy.AuditLog = "/explicit/new/audit"
	if err := binding.Validate(view); err != nil {
		t.Fatalf("display edit invalidated execution: %v", err)
	}
	for _, change := range []func(*OperationSnapshot){
		func(s *OperationSnapshot) {
			v := s.Targets["node"]
			v.Plan.Hops[0].AuthUpdateToken = "key-2"
			s.Targets["node"] = v
		},
		func(s *OperationSnapshot) { s.PolicyRevision = "policy-2" },
		func(s *OperationSnapshot) { s.Policy.ApprovalThreshold = "safe" },
		func(s *OperationSnapshot) { v := s.Targets["node"]; v.Disabled = true; s.Targets["node"] = v },
		func(s *OperationSnapshot) { s.Selectors["alias"] = "another" },
	} {
		changed := snapshot.Clone()
		change(&changed)
		if err := binding.Validate(changed); !errors.Is(err, ErrStaleBinding) {
			t.Fatalf("changed binding accepted: %v", err)
		}
	}
	if err := binding.Validate(snapshot); err != nil {
		t.Fatal("defensive clones changed the original snapshot")
	}
}

func TestPermitIsImmutableBoundedAndPurposeLimited(t *testing.T) {
	snapshot := fixtureSnapshot()
	binding, err := Bind(snapshot, "scope", "xops_prepare_upload", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	admission := Admission{OperationID: "operation", Phase: Inspect, Snapshot: snapshot, Binding: binding}
	if _, err := NewPermit(context.Background(), admission, nil); err == nil {
		t.Fatal("unbounded permit accepted")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var releases atomic.Int32
	permit, err := NewPermit(ctx, admission, func() error { releases.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := permit.Close(); err != nil {
			t.Error(err)
		}
	}()
	snapshot.Targets["node"] = Target{}
	if _, _, err := permit.Snapshot().Resolve("alias"); err != nil {
		t.Fatal("caller mutation changed a permit")
	}
	if _, _, err := WorkContext(ctx, permit, Execute); !errors.Is(err, ErrPurpose) {
		t.Fatal("inspection permit gained execution capability")
	}
	work, stop, err := WorkContext(context.Background(), permit, Inspect)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if _, ok := work.Deadline(); !ok {
		t.Fatal("caller bypassed the permit deadline")
	}
	if err := permit.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-work.Done():
	case <-time.After(time.Second):
		t.Fatal("permit close did not cancel I/O")
	}
	if releases.Load() != 1 {
		t.Fatal("permit release was not idempotent")
	}
}

func TestInvalidPlanCannotBeBound(t *testing.T) {
	snapshot := fixtureSnapshot()
	target := snapshot.Targets["node"]
	target.Info.ID = "other"
	snapshot.Targets["node"] = target
	if _, err := snapshot.Digest(); err == nil {
		t.Fatal("display identity differed from execution identity")
	}
}
