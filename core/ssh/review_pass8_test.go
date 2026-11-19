package ssh

import (
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPass8_H1_KnownHostsHostPortWildcards(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		port    string
		want    bool
	}{
		// Single-pattern wildcards matching full OpenSSH host[:port] token
		{"*:2222", "app.example.com", "2222", true},
		{"*:2222", "192.0.2.10", "2222", true},
		{"*:2222", "::1", "2222", true},
		{"*:2222", "app.example.com", "22", false},
		{"*:2222", "app.example.com", "", false},
		{"*:2222", "app.example.com", "2200", false},

		{"[*.corp.example.com]:2222", "db.corp.example.com", "2222", true},
		{"[*.corp.example.com]:2222", "db.corp.example.com", "22", false},
		{"[*.corp.example.com]:2222", "corp.example.com", "2222", false},

		{"[host?]:2*", "host1", "2222", true},
		{"[host?]:2*", "hosta", "2022", true},
		{"[host?]:2*", "host1", "22", false},
		{"[host?]:2*", "host12", "2222", false},
		{"[host?]:2*", "host1", "3222", false},

		{"!*.bad.corp,*", "ok.corp", "22", true},
		{"!*.bad.corp,*", "ok.corp", "2222", true},
		{"!*.bad.corp,*", "evil.bad.corp", "22", false},
		{"!*.bad.corp,*", "evil.bad.corp", "2222", true}, // Matches OpenSSH ssh-keygen -F: !*.bad.corp only excludes unbracketed port-22 token
		{"![*.bad.corp]:2222,*", "evil.bad.corp", "2222", false},
		{"![*.bad.corp]:2222,*", "evil.bad.corp", "22", true},

		{"[::1]:2222", "::1", "2222", true},
		{"[::1]:2222", "::1", "22", false},

		// Exact OpenSSH_10.6p2 ssh-keygen -F parity for port-containing patterns and ! negations
		{"*:*", "app.corp", "22", false},
		{"*:*", "app.corp", "2222", true},
		{"[*.corp]:*", "app.corp", "22", false},
		{"[*.corp]:*", "app.corp", "2222", true},
		{"app.corp:*", "app.corp", "2222", false},
		{"*:22", "app.corp", "22", false},
		{"[app.corp]:22", "app.corp", "22", false},
		{"app.corp:22", "app.corp", "22", false},
		{"127.0.0.1:2222", "127.0.0.1", "2222", false},
		{"*,!*:22", "app.corp", "22", true},
		{"*,!bad.corp:*", "bad.corp", "2222", true},
		{"*,![bad.corp]:*", "bad.corp", "22", true},
		{"*,![bad.corp]:*", "bad.corp", "2222", false},
		{"*,![app.corp]:22", "app.corp", "22", true},
	}

	for _, tc := range cases {
		m, err := newKHHostnameMatcher(tc.pattern)
		if err != nil {
			t.Fatalf("newKHHostnameMatcher(%q) error = %v", tc.pattern, err)
		}
		got := m.match(khAddr{host: tc.host, port: tc.port})
		if got != tc.want {
			t.Errorf("pattern %q on (%q, %q) = %v, want %v", tc.pattern, tc.host, tc.port, got, tc.want)
		}
	}

	for _, bad := range []string{"[unclosed:2222", "[host]"} {
		if _, err := newKHHostnameMatcher(bad); err == nil {
			t.Errorf("newKHHostnameMatcher(%q) expected syntax error, got nil", bad)
		}
	}
}

func TestPass8_H2_SetEnvSingleDirectiveFirstKeyWinsAndValidatesAll(t *testing.T) {
	vars, err := parseSetEnvDirective("FOO=first FOO=second BAR=ok")
	if err != nil {
		t.Fatalf("parseSetEnvDirective unexpected error: %v", err)
	}
	if len(vars) != 2 || vars[0].Name != "FOO" || vars[0].Value != "first" || vars[1].Name != "BAR" || vars[1].Value != "ok" {
		t.Fatalf("parseSetEnvDirective first-key-wins = %+v, want FOO=first & BAR=ok", vars)
	}

	if _, err := parseSetEnvDirective("FOO=first BADTOKEN"); err == nil {
		t.Fatal("parseSetEnvDirective must validate every token after duplicate keys")
	}

	opts, err := NewOptions()
	if err != nil {
		t.Fatalf("NewOptions: %v", err)
	}
	if err := opts.Set(OptionSetEnv, "FOO=first FOO=second BAR=ok"); err != nil {
		t.Fatalf("Set(OptionSetEnv): %v", err)
	}
	envVars, err := ResolveSessionEnv(opts, nil)
	if err != nil {
		t.Fatalf("ResolveSessionEnv: %v", err)
	}
	if len(envVars) != 2 || envVars[0].Name != "FOO" || envVars[0].Value != "first" {
		t.Fatalf("ResolveSessionEnv = %+v, want FOO=first & BAR=ok", envVars)
	}
}

func TestPass8_M1_AcquireReleaseMasterConcurrentRace(t *testing.T) {
	srv := &MuxServer{
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}
	srv.AddForegroundSession()
	conn := &Connector{
		masters: map[*MuxServer]*masterOwnership{
			srv: {nodeID: "node-1", foregroundSession: true},
		},
		masterOrder: []*MuxServer{srv},
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 200 {
				_ = conn.ReleaseMaster(srv)
				_ = conn.AcquireMaster(srv)
				_ = conn.OwnsMaster(srv)
			}
		})
	}
	wg.Wait()
}

type pass8BlockingCloser struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *pass8BlockingCloser) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func TestPass8_M2_WaitClosingEndpointAndRetireFallbackBarrier(t *testing.T) {
	setTestHome(t)
	t.Run("waitClosingEndpointLocked_waits_for_inFlight_closingWait", verifyPass8WaitClosingEndpointInFlight)
	t.Run("retireForward_sets_closingWait_on_inFlight_fallbackEntry", verifyPass8RetireFallbackBarrier)
}

func verifyPass8WaitClosingEndpointInFlight(t *testing.T) {
	srv := &MuxServer{
		idleNotify:   make(chan struct{}),
		shutdownChan: make(chan struct{}),
	}
	lk := forwardListenKey{
		fwdScope:   muxForwardScopeRemote,
		network:    "tcp",
		keyHost:    "127.0.0.1",
		listenPort: 45810,
	}
	waitCh := make(chan struct{})
	srv.forwardTable.endpoints = map[forwardListenKey]*muxForwardEndpointSlot{
		lk: {
			state:       forwardSlotOpening,
			closingWait: waitCh,
		},
	}

	done := make(chan bool, 1)
	go func() {
		srv.idleMu.Lock()
		waited, aborted := srv.waitClosingEndpointLocked(lk)
		if waited {
			srv.idleMu.Lock()
		}
		srv.idleMu.Unlock()
		done <- waited && !aborted
	}()

	select {
	case ok := <-done:
		t.Fatalf("waitClosingEndpointLocked returned prematurely (%v) while inFlight closingWait was open", ok)
	case <-time.After(40 * time.Millisecond):
	}

	close(waitCh)
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("waitClosingEndpointLocked did not report waited && !aborted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitClosingEndpointLocked after closingWait closed")
	}
}

func verifyPass8RetireFallbackBarrier(t *testing.T) {
	srv := &MuxServer{
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}
	lk := forwardListenKey{
		fwdScope:   muxForwardScopeRemote,
		network:    "tcp",
		keyHost:    "127.0.0.1",
		listenPort: 45811,
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	const fwdKey = "R:127.0.0.1:45811->127.0.0.1:9000"
	blocker := &pass8BlockingCloser{entered: entered, release: release}
	entry := &muxForwardEntry{
		fwdType:       MUX_FWD_REMOTE,
		forwardKey:    fwdKey,
		listenKey:     lk,
		hasListenKey:  true,
		dynamicAlloc:  true,
		remote:        true,
		shadowClosers: []io.Closer{blocker},
	}
	srv.forwardTable.putEntryLocked(fwdKey, entry)
	srv.forwardTable.endpoints = map[forwardListenKey]*muxForwardEndpointSlot{
		lk: {
			state:         forwardSlotOpening,
			fallbackEntry: entry,
		},
	}

	retireDone := make(chan struct{})
	go func() {
		srv.retireForward(fwdKey, entry)
		close(retireDone)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fallback shadowCloser")
	}

	srv.idleMu.Lock()
	ep := srv.forwardTable.endpoints[lk]
	inFlightBusy := srv.forwardTable.hasInFlightEndpointsLocked()
	srv.idleMu.Unlock()
	if ep == nil || ep.closingWait == nil || ep.fallbackEntry != nil || !inFlightBusy {
		t.Fatalf("expected active closingWait and cleared fallbackEntry on inFlight slot, got ep=%+v inFlightBusy=%v", ep, inFlightBusy)
	}

	waitDone := make(chan bool, 1)
	go func() {
		srv.idleMu.Lock()
		waited, aborted := srv.waitClosingEndpointLocked(lk)
		if waited {
			srv.idleMu.Lock()
		}
		srv.idleMu.Unlock()
		waitDone <- waited && !aborted
	}()

	select {
	case <-waitDone:
		t.Fatal("waitClosingEndpointLocked returned before fallback shadowCloser finished")
	case <-time.After(40 * time.Millisecond):
	}

	close(release)
	select {
	case ok := <-waitDone:
		if !ok {
			t.Fatal("waitClosingEndpointLocked failed after closingWait finished")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitClosingEndpointLocked")
	}
	<-retireDone

	srv.idleMu.Lock()
	epAfter := srv.forwardTable.endpoints[lk]
	srv.idleMu.Unlock()
	if epAfter == nil || epAfter.state != forwardSlotOpening || epAfter.closingWait != nil {
		t.Fatalf("expected original inFlight slot preserved with closingWait=nil, got %+v", epAfter)
	}
}

func TestPass8_M3_RetireForwardSchedulesShutdownAfterCloseBarrier(t *testing.T) {
	srv := &MuxServer{
		persistEnabled:   false,
		hadActiveSession: true,
		idleNotify:       make(chan struct{}),
		shutdownChan:     make(chan struct{}),
	}
	lk := forwardListenKey{
		fwdScope:   muxForwardScopeRemote,
		network:    "tcp",
		keyHost:    "127.0.0.1",
		listenPort: 45812,
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	const fwdKey = "R:127.0.0.1:45812->127.0.0.1:9001"
	entry := &muxForwardEntry{
		fwdType:       MUX_FWD_REMOTE,
		forwardKey:    fwdKey,
		listenKey:     lk,
		hasListenKey:  true,
		remote:        true,
		shadowClosers: []io.Closer{&pass8BlockingCloser{entered: entered, release: release}},
	}
	srv.forwardTable.putEntryLocked(fwdKey, entry)
	srv.forwardTable.endpoints = map[forwardListenKey]*muxForwardEndpointSlot{
		lk: {state: forwardSlotActive, entry: entry},
	}

	go srv.retireForward(fwdKey, entry)

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for shadowCloser in retireForward")
	}

	if srv.isShuttingDown() {
		t.Fatal("server entered shutdown before retireForward close barrier completed")
	}
	if srv.PrepareHandoff() {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoff succeeded while retireForward closingSlot was active")
	}

	close(release)
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("non-persistent MuxServer wedged open after retireForward finished close barrier")
	}
}

func TestPass8_M5_PrepareHandoffWithSessionsAtomicReservation(t *testing.T) {
	srv := &MuxServer{
		persistEnabled: false,
		idleNotify:     make(chan struct{}),
		shutdownChan:   make(chan struct{}),
	}

	if !srv.addActiveSession() {
		t.Fatal("first addActiveSession failed")
	}
	if srv.PrepareHandoff() {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoff() must fail while activeSessions == 1")
	}
	if !srv.PrepareHandoffWithSessions(1) {
		t.Fatal("PrepareHandoffWithSessions(1) expected true while activeSessions == 1")
	}
	if srv.addActiveSession() {
		t.Fatal("addActiveSession must be rejected while handoff is reserved")
	}
	if srv.addActiveForwardStream() {
		t.Fatal("addActiveForwardStream must be rejected while handoff is reserved")
	}
	if srv.PrepareHandoffWithSessions(1) {
		t.Fatal("duplicate PrepareHandoffWithSessions(1) must return false")
	}

	srv.CancelHandoff()
	if srv.isShuttingDown() {
		t.Fatal("CancelHandoff left shuttingDown=true")
	}
	select {
	case <-srv.Wait():
		t.Fatal("CancelHandoff unexpectedly shut down non-persistent master still holding foreground ref")
	default:
	}

	if !srv.addActiveSession() {
		t.Fatal("addActiveSession failed after CancelHandoff")
	}
	if srv.PrepareHandoffWithSessions(1) {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoffWithSessions(1) must fail when activeSessions == 2")
	}
}

func TestPass8_L1_RemoteForwardNilCtxOnMuxClient(t *testing.T) {
	cli := &Client{muxSocketPath: "/tmp/nonexistent-mux-pass8.sock"}
	var nilCtx context.Context
	fwd, err := cli.RemoteForward(nilCtx, "127.0.0.1:0", "127.0.0.1:8080")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "nil") {
		t.Fatalf("RemoteForward(nil, ...) = (%v, %v), want nil context error", fwd, err)
	}
	if fwd != nil {
		t.Fatalf("expected nil Forward on error, got %+v", fwd)
	}
}
