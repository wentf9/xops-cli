package state

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/ssh"
	"go.uber.org/goleak"
)

func fixtureView() ports.OperationSnapshot {
	view := ports.OperationSnapshot{DomainID: "domain", Revision: "1", PolicyRevision: "policy-1", Targets: make(map[string]ports.Target), Selectors: map[string]string{"alias": "a"}}
	for index, id := range []string{"a", "b"} {
		view.Targets[id] = ports.Target{Info: ports.NodeInfo{ID: id, Tags: []string{"fixture"}}, Version: "1", Plan: ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{{NodeID: id, Address: fmt.Sprintf("192.0.2.%d", index+1), Port: 22, User: "fixture", AuthType: "password", AuthUpdateToken: "auth-1", TrustVersion: "trust-1"}}}}
	}
	return view
}

func setup(t *testing.T) (*Coordinator, context.Context) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	c, err := New(fixtureView(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c, ctx
}

func admission(t *testing.T, c *Coordinator, ctx context.Context, node string, phase ports.Phase) ports.Admission {
	t.Helper()
	view, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{node}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "xops_ssh_run", map[string]string{"node": node, "command": "hostname"})
	if err != nil {
		t.Fatal(err)
	}
	return ports.Admission{OperationID: "operation", Phase: phase, Snapshot: view, Binding: binding}
}
func enter(t *testing.T, c *Coordinator, ctx context.Context, a ports.Admission) ports.Permit {
	t.Helper()
	p, err := c.Enter(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}
func noPools(ctx context.Context, _ []ssh.ConnectionPlan) error { return ctx.Err() }
func publish(t *testing.T, c *Coordinator, ctx context.Context, next ports.OperationSnapshot) {
	t.Helper()
	u, err := c.BeginUpdate(ctx, c.Snapshot().Revision, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateBarrierAndAdmissionVersionAreAtomic(t *testing.T) {
	c, ctx := setup(t)
	oldA, oldB := admission(t, c, ctx, "a", ports.Execute), admission(t, c, ctx, "b", ports.Execute)
	active := enter(t, c, ctx, oldA)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].Address = "192.0.2.20"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enter(ctx, oldA); !errors.Is(err, ErrUpdating) {
		t.Fatalf("affected operation crossed update barrier: %v", err)
	}
	enter(t, c, ctx, oldB)
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enter(ctx, oldA); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("approval survived retargeting: %v", err)
	}
	if active.Context().Err() != nil {
		t.Fatal("ordinary edit cancelled admitted work")
	}
	_, captured, err := active.Snapshot().Resolve("a")
	if err != nil || captured.Plan.Hops[0].Address != "192.0.2.1" {
		t.Fatal("admitted operation changed target")
	}
	enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
}

func TestAuthClassOptionChangesRevokeActivePermitsWhileTransportEditsDoNot(t *testing.T) {
	authOptionCases := []struct {
		name string
		key  string
		val  string
	}{
		{name: "IdentitiesOnly", key: ssh.OptionIdentitiesOnly, val: "yes"},
		{name: "PubkeyAuthentication", key: ssh.OptionPubkeyAuthentication, val: "no"},
		{name: "PasswordAuthentication", key: ssh.OptionPasswordAuthentication, val: "no"},
		{name: "KbdInteractiveAuthentication", key: ssh.OptionKbdInteractiveAuthentication, val: "no"},
		{name: "PreferredAuthentications", key: ssh.OptionPreferredAuthentications, val: "publickey"},
		{name: "BatchMode", key: ssh.OptionBatchMode, val: "yes"},
		{name: "IdentityAgent", key: ssh.OptionIdentityAgent, val: "none"},
		{name: "CertificateFile", key: ssh.OptionCertificateFile, val: "/etc/ssh/id_ed25519-cert.pub"},
		{name: "IdentityFile", key: ssh.OptionIdentityFile, val: "/etc/ssh/id_ed25519"},
		{name: "StrictHostKeyChecking", key: ssh.OptionStrictHostKeyChecking, val: "yes"},
		{name: "UserKnownHostsFile", key: ssh.OptionUserKnownHostsFile, val: "/etc/ssh/custom_known_hosts"},
		{name: "GlobalKnownHostsFile", key: ssh.OptionGlobalKnownHostsFile, val: "/etc/ssh/global_known_hosts"},
		{name: "VerifyHostKeyDNS", key: ssh.OptionVerifyHostKeyDNS, val: "yes"},
		{name: "HashKnownHosts", key: ssh.OptionHashKnownHosts, val: "yes"},
	}

	for _, tc := range authOptionCases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx := setup(t)
			active := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
			next := c.Snapshot()
			next.Revision = "2"
			target := next.Targets["a"]
			target.Plan.Hops[0].Options = ssh.MustOptions(tc.key, tc.val)
			next.Targets["a"] = target
			publish(t, c, ctx, next)
			if active.Context().Err() == nil {
				t.Fatalf("changing auth-class option %s did not revoke active permit", tc.name)
			}
		})
	}

	t.Run("TransportOnlyDoesNotRevoke", func(t *testing.T) {
		c, ctx := setup(t)
		active := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
		next := c.Snapshot()
		next.Revision = "2"
		target := next.Targets["a"]
		target.Plan.Hops[0].Options = ssh.MustOptions(ssh.OptionCiphers, "aes256-gcm@openssh.com")
		next.Targets["a"] = target
		publish(t, c, ctx, next)
		if active.Context().Err() != nil {
			t.Fatalf("changing transport-only option Ciphers unexpectedly revoked active permit: %v", active.Context().Err())
		}
	})
}

func TestCommittedPublicationFailureStaysBlocked(t *testing.T) {
	c, ctx := setup(t)
	a := admission(t, c, ctx, "a", ports.Execute)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].AuthUpdateToken = "auth-2"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.BeginPersistence(); err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	marker := errors.New("pool retirement failed")
	if err := u.Publish(ctx, func(context.Context, []ssh.ConnectionPlan) error { return marker }); !errors.Is(err, marker) {
		t.Fatalf("publication failure lost: %v", err)
	}
	if !c.Pending() || c.Snapshot().Revision != "2" {
		t.Fatal("committed publication was rolled back or unblocked")
	}
	if err := u.Abort(); !errors.Is(err, ErrPersistenceUnknown) {
		t.Fatal("aborted an already committed write")
	}
	if _, err := c.Enter(ctx, a); !errors.Is(err, ErrUpdating) {
		t.Fatalf("failed publication admitted work: %v", err)
	}
	if err := u.Publish(ctx, noPools); err != nil {
		t.Fatal(err)
	}
	if c.Pending() {
		t.Fatal("successful recovery left admission blocked")
	}
	if _, err := c.Enter(ctx, a); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatal("old approval survived recovery")
	}
}

func TestUnknownPersistenceRequiresAnExplicitConclusion(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Version = "2"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.BeginPersistence(); err != nil {
		t.Fatal(err)
	}
	if err := u.Abort(); !errors.Is(err, ErrPersistenceUnknown) {
		t.Fatal("ambiguous persistence released admission")
	}
	if _, err := c.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"a"}}); !errors.Is(err, ErrUpdating) {
		t.Fatal("ambiguous state remained usable")
	}
	if err := u.ConfirmRollback(); err != nil {
		t.Fatal(err)
	}
	if c.Pending() || c.Snapshot().Revision != "1" {
		t.Fatal("confirmed rollback did not restore admission")
	}
}

func TestRevocationCancelsWorkButPreservesReservedCommit(t *testing.T) {
	c, ctx := setup(t)
	ordinary := enter(t, c, ctx, admission(t, c, ctx, "a", ports.TransferStart))
	commit := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Commit))
	unrelated := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Disabled = true
	next.Targets["a"] = target
	publish(t, c, ctx, next)
	if ordinary.Context().Err() == nil {
		t.Fatal("disabled node retained cancellable work")
	}
	if commit.Context().Err() != nil {
		t.Fatal("revocation cancelled a reserved commit")
	}
	if unrelated.Context().Err() != nil {
		t.Fatal("node revocation cancelled unrelated work")
	}
}

func TestRetirementDoesNotHoldThePublicationMutex(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Plan.Hops[0].Address = "192.0.2.20"
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	// The publication worker is released below or by the bounded test context.
	go func() {
		finished <- u.Publish(ctx, func(ctx context.Context, _ []ssh.ConnectionPlan) error {
			close(started)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("retirement never started")
	}
	enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestDisplayOnlyEditDoesNotRetireConnectionsOrApprovals(t *testing.T) {
	c, ctx := setup(t)
	a := admission(t, c, ctx, "a", ports.Execute)
	next := c.Snapshot()
	next.Revision = "2"
	target := next.Targets["a"]
	target.Info.Tags = []string{"new-display-tag"}
	next.Targets["a"] = target
	u, err := c.BeginUpdate(ctx, "1", next)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	var retired atomic.Int32
	if err := u.Publish(ctx, func(_ context.Context, plans []ssh.ConnectionPlan) error { retired.Add(int32(len(plans))); return nil }); err != nil {
		t.Fatal(err)
	}
	if retired.Load() != 0 {
		t.Fatal("display-only edit retired execution connections")
	}
	enter(t, c, ctx, a)
}

func TestDeletedNodeIDCannotBeReused(t *testing.T) {
	c, ctx := setup(t)
	next := c.Snapshot()
	next.Revision = "2"
	delete(next.Targets, "a")
	delete(next.Selectors, "alias")
	publish(t, c, ctx, next)
	next = fixtureView()
	next.Revision = "3"
	if _, err := c.BeginUpdate(ctx, "2", next); !errors.Is(err, ErrIdentityReuse) {
		t.Fatalf("deleted ID reused: %v", err)
	}
}

func TestJumpTopologyAndHopPrincipalEditsRevokeActivePermits(t *testing.T) {
	jump1 := ssh.ConnectionConfig{
		NodeID:          "jump1",
		Address:         "192.0.2.101",
		Port:            22,
		User:            "jump-user",
		AuthType:        "key",
		KeyRef:          "jump1-key",
		AuthUpdateToken: "j1-auth-1",
		TrustVersion:    "j1-trust-1",
	}
	jump2 := ssh.ConnectionConfig{
		NodeID:          "jump2",
		Address:         "192.0.2.102",
		Port:            22,
		User:            "jump-user",
		AuthType:        "key",
		KeyRef:          "jump2-key",
		AuthUpdateToken: "j2-auth-1",
		TrustVersion:    "j2-trust-1",
	}

	newTwoBastionCoordinator := func(t *testing.T, withInitialJump1 bool) (*Coordinator, context.Context) {
		t.Helper()
		t.Cleanup(func() { goleak.VerifyNone(t) })
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		t.Cleanup(cancel)

		view := fixtureView()
		view.Targets["jump1"] = ports.Target{
			Info:    ports.NodeInfo{ID: "jump1"},
			Version: "1",
			Plan:    ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{jump1}},
		}
		view.Targets["jump2"] = ports.Target{
			Info:    ports.NodeInfo{ID: "jump2"},
			Version: "1",
			Plan:    ssh.ConnectionPlan{Scope: "scope", Hops: []ssh.ConnectionConfig{jump2}},
		}
		if withInitialJump1 {
			targetA := view.Targets["a"]
			targetA.Plan.Hops[0].ProxyJump = "jump1"
			targetA.Plan.Hops = []ssh.ConnectionConfig{jump1, targetA.Plan.Hops[0]}
			view.Targets["a"] = targetA
		}
		c, err := New(view, Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		})
		return c, ctx
	}

	t.Run("JumpChainRemoved", func(t *testing.T) {
		c, ctx := newTwoBastionCoordinator(t, true)
		activeA := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
		activeB := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))

		next := c.Snapshot()
		next.Revision = "2"
		targetA := next.Targets["a"]
		finalHop := targetA.Plan.Hops[1]
		finalHop.ProxyJump = ""
		targetA.Plan.Hops = []ssh.ConnectionConfig{finalHop}
		next.Targets["a"] = targetA
		publish(t, c, ctx, next)

		if activeA.Context().Err() == nil {
			t.Fatal("removing jump hop [jump1, a] -> [a] did not revoke active permit on a")
		}
		if activeB.Context().Err() != nil {
			t.Fatal("unrelated permit on b was unexpectedly revoked")
		}
	})

	t.Run("JumpChainAdded", func(t *testing.T) {
		c, ctx := newTwoBastionCoordinator(t, false)
		activeA := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))

		next := c.Snapshot()
		next.Revision = "2"
		targetA := next.Targets["a"]
		finalHop := targetA.Plan.Hops[0]
		finalHop.ProxyJump = "jump1"
		targetA.Plan.Hops = []ssh.ConnectionConfig{jump1, finalHop}
		next.Targets["a"] = targetA
		publish(t, c, ctx, next)

		if activeA.Context().Err() == nil {
			t.Fatal("adding jump hop [a] -> [jump1, a] did not revoke active permit on a")
		}
	})

	t.Run("JumpChainReplaced", func(t *testing.T) {
		c, ctx := newTwoBastionCoordinator(t, true)
		activeA := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
		activeB := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))

		next := c.Snapshot()
		next.Revision = "2"
		targetA := next.Targets["a"]
		finalHop := targetA.Plan.Hops[1]
		finalHop.ProxyJump = "jump2"
		targetA.Plan.Hops = []ssh.ConnectionConfig{jump2, finalHop}
		next.Targets["a"] = targetA
		publish(t, c, ctx, next)

		if activeA.Context().Err() == nil {
			t.Fatal("replacing jump hop [jump1, a] -> [jump2, a] did not revoke active permit on a")
		}
		if activeB.Context().Err() != nil {
			t.Fatal("unrelated permit on b was unexpectedly revoked")
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(hop *ssh.ConnectionConfig)
	}{
		{
			name:   "HopUserChanged",
			mutate: func(hop *ssh.ConnectionConfig) { hop.User = "readonly" },
		},
		{
			name:   "HopSudoModeChanged",
			mutate: func(hop *ssh.ConnectionConfig) { hop.SudoMode = "sudo" },
		},
		{
			name:   "HopOriginalHostChanged",
			mutate: func(hop *ssh.ConnectionConfig) { hop.OriginalHost = "web-alias" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx := setup(t)
			activeA := enter(t, c, ctx, admission(t, c, ctx, "a", ports.Execute))
			activeB := enter(t, c, ctx, admission(t, c, ctx, "b", ports.Execute))

			next := c.Snapshot()
			next.Revision = "2"
			targetA := next.Targets["a"]
			tc.mutate(&targetA.Plan.Hops[0])
			next.Targets["a"] = targetA
			publish(t, c, ctx, next)

			if activeA.Context().Err() == nil {
				t.Fatalf("%s did not revoke active permit on a", tc.name)
			}
			if activeB.Context().Err() != nil {
				t.Fatalf("%s unexpectedly revoked unrelated permit on b", tc.name)
			}
		})
	}
}
