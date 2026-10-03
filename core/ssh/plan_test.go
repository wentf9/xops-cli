package ssh

import (
	"context"
	"errors"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

type forbiddenPlanProvider struct{ calls atomic.Int32 }

func (p *forbiddenPlanProvider) GetConfig(string) (*ClientConfig, error) {
	p.calls.Add(1)
	return nil, errors.New("mutable provider must not be used by a captured plan")
}

type planSecrets struct{}

func (planSecrets) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.VersionToken != "v1" && req.VersionToken != "v2" {
		return nil, ErrSnapshotMismatch
	}
	return []byte("plan-password"), nil
}

func TestPlanConnectionsAreVersionedAndDrainLeases(t *testing.T) {
	defer goleak.VerifyNone(t)
	address, _, stop := startTestAutoSSHServer(t, "plan-password")
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	provider := &forbiddenPlanProvider{}
	connector := NewConnector(provider, WithSecretResolver(planSecrets{}), WithHostKeyVerifier(&fixtureTrust{}))
	defer closePlanConnector(t, connector)
	connector.EnableKeepAlive(t.Context(), time.Hour, time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	plan := ConnectionPlan{Scope: "runtime", Hops: []ConnectionConfig{{
		NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "v1",
	}}}
	first := connectPlanFixture(t, ctx, connector, plan)
	defer closePlanLease(t, first)
	key, err := ConnectionKey(plan)
	if err != nil {
		t.Fatal(err)
	}
	if connector.plans[key].connector.keepAliveCfg == nil {
		t.Fatal("plan lost the host keepalive policy")
	}
	second := connectPlanFixture(t, ctx, connector, plan)
	defer closePlanLease(t, second)
	if first.Client.sshClient != second.Client.sshClient {
		t.Fatal("identical plan did not reuse its generation")
	}
	if err := connector.RetirePlan(plan); err != nil {
		t.Fatal(err)
	}
	plan.Hops[0].AuthUpdateToken = "v2"
	third := connectPlanFixture(t, ctx, connector, plan)
	defer closePlanLease(t, third)
	if first.Client.sshClient == third.Client.sshClient {
		t.Fatal("rotated credential reused old transport")
	}
	if first.Client.ConnectionConfig().AuthUpdateToken != "v1" {
		t.Fatal("caller mutation changed an in-flight snapshot")
	}
	probePlanFixture(t, first)
	closePlanLease(t, first)
	probePlanFixture(t, second)
	closePlanLease(t, second)
	probePlanFixture(t, third)
	if provider.calls.Load() != 0 {
		t.Fatal("ConnectPlan re-read the mutable provider")
	}
}

func connectPlanFixture(t *testing.T, ctx context.Context, connector *Connector, plan ConnectionPlan) *PlanConnection {
	t.Helper()
	lease, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func closePlanLease(t *testing.T, lease *PlanConnection) {
	t.Helper()
	if err := lease.Close(); err != nil {
		t.Error(err)
	}
}

func closePlanConnector(t *testing.T, connector *Connector) {
	t.Helper()
	if err := connector.CloseAll(); err != nil {
		t.Error(err)
	}
}

func probePlanFixture(t *testing.T, lease *PlanConnection) {
	t.Helper()
	if err := lease.Client.rootConn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lease.Client.sshClient.SendRequest("plan-probe", true, nil); err != nil {
		t.Fatalf("live plan lease was interrupted: %v", err)
	}
}

func TestConnectionKeyIncludesEveryHopAndSourceVersion(t *testing.T) {
	original := ConnectionPlan{Scope: "scope", Hops: []ConnectionConfig{
		{NodeID: "jump", Address: "192.0.2.1", User: "fixture", AuthType: "key", KeyRef: "jump-key", AuthUpdateToken: "v1", TrustVersion: "t1"},
		{NodeID: "target", Address: "192.0.2.2", Port: 22, User: "fixture", AuthType: "password", AuthUpdateToken: "v1"},
	}}
	base, err := ConnectionKey(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ConnectionPlan){
		func(p *ConnectionPlan) { p.Scope = "other" },
		func(p *ConnectionPlan) { p.Hops[0].Address = "192.0.2.3" },
		func(p *ConnectionPlan) { p.Hops[0].AuthUpdateToken = "v2" },
		func(p *ConnectionPlan) { p.Hops[0].KeyRef = "other-key" },
		func(p *ConnectionPlan) { p.Hops[0].TrustVersion = "t2" },
		func(p *ConnectionPlan) { p.Hops[1].SudoUpdateToken = "sudo-v2" },
	} {
		plan := original
		plan.Hops = slices.Clone(plan.Hops)
		mutate(&plan)
		got, err := ConnectionKey(plan)
		if err != nil || got == base {
			t.Fatalf("connection generation ignored a dependency: key=%s error=%v", got, err)
		}
	}
	original.Hops[0].Port = 22
	got, err := ConnectionKey(original)
	if err != nil || got != base {
		t.Fatal("default port created a different connection identity")
	}
	original.Hops[1].ProxyJump = "uncaptured-host"
	if _, err := ConnectionKey(original); err == nil {
		t.Fatal("connection plan escaped its captured jump chain")
	}
}

func TestRetirementBeforeConnectionCannotResurrectPool(t *testing.T) {
	defer goleak.VerifyNone(t)
	address, _, stop := startTestAutoSSHServer(t, "plan-password")
	defer stop()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	connector := NewConnector(nil, WithSecretResolver(planSecrets{}), WithHostKeyVerifier(&fixtureTrust{}))
	defer closePlanConnector(t, connector)
	plan := ConnectionPlan{Scope: "scope", Hops: []ConnectionConfig{{NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "v1"}}}
	if err := connector.RetirePlan(plan); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	lease := connectPlanFixture(t, ctx, connector, plan)
	defer closePlanLease(t, lease)
	probePlanFixture(t, lease)
	if len(connector.plans) != 0 {
		t.Fatal("late admitted work resurrected a retired cache generation")
	}
	closePlanLease(t, lease)
	if len(connector.allPlans) != 0 {
		t.Fatal("uncached retired connection outlived its lease")
	}
}

type cancelledPlanDialer struct{ started chan struct{} }

func (d cancelledPlanDialer) Dial(string, string) (net.Conn, error) {
	return nil, errors.New("context-free dial is forbidden")
}
func (d cancelledPlanDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestCloseAllJoinsInFlightPlanHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)
	dialer := cancelledPlanDialer{started: make(chan struct{})}
	connector := NewConnector(nil, WithSecretResolver(planSecrets{}), WithHostKeyVerifier(&fixtureTrust{}), WithDialer(dialer))
	defer closePlanConnector(t, connector)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	// Parent CloseAll closes and joins the scoped connector and this call.
	go func() {
		lease, err := connector.ConnectPlan(ctx, ConnectionPlan{Scope: "scope", Hops: []ConnectionConfig{{
			NodeID: "node", Address: "192.0.2.1", User: "fixture", AuthType: "password", AuthUpdateToken: "v1",
		}}})
		if lease != nil {
			err = errors.Join(err, lease.Close())
		}
		finished <- err
	}()
	select {
	case <-dialer.started:
	case <-ctx.Done():
		t.Fatal("plan did not begin its handshake")
	}
	closePlanConnector(t, connector)
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("closed plan handshake succeeded")
		}
	case <-ctx.Done():
		t.Fatal("closing a connector left its plan worker running")
	}
}

func TestCapturedPlanClosesNestedBlackholedTransport(t *testing.T) {
	for _, hops := range []int{1, 2} {
		t.Run(strconv.Itoa(hops), func(t *testing.T) {
			t.Cleanup(func() { goleak.VerifyNone(t) })
			connector, _, dialer := newBlackholeProxyClient(t, hops, true)
			dialer.conn.drop.Store(true)
			done := make(chan error, 1)
			// CloseAll interrupts the captured physical root and joins nested workers.
			go func() { done <- connector.CloseAll() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				closeTestResource(t, dialer.conn)
				<-done
				t.Fatal("captured plan shutdown blocked on a nested SSH channel")
			}
		})
	}
}
