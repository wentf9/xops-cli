package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/testleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestPhase5_OptionRegistryAccessorsAndPlanIsolation(t *testing.T) {
	assertPhase5OptionSpecsAndAccessors(t)
	assertPhase5OptionRejection(t)
	assertPhase5PlanIsolation(t)
}

func assertPhase5OptionSpecsAndAccessors(t *testing.T) {
	t.Helper()
	specs := []struct {
		name string
		key  string
	}{
		{"ProxyCommand", OptionProxyCommand},
		{"LocalCommand", OptionLocalCommand},
		{"PermitLocalCommand", OptionPermitLocalCommand},
	}
	for _, s := range specs {
		spec, ok := LookupOptionSpec(s.name)
		if !ok || spec.CanonicalKey != s.key || spec.Class != OptionClassLocalExec || spec.MultiValue {
			t.Fatalf("unexpected spec for %s: ok=%v %+v", s.name, ok, spec)
		}
	}

	var nilOpts *Options
	if nilOpts.ProxyCommand() != "" || nilOpts.ActiveProxyCommand() != "" || nilOpts.LocalCommand() != "" || nilOpts.PermitLocalCommand() {
		t.Fatal("expected nil *Options Phase 5 accessors to return safe zero values")
	}

	opts := &Options{}
	if err := opts.Set("ProxyCommand", "  ssh -W %h:%p bastion  "); err != nil {
		t.Fatalf("Set ProxyCommand failed: %v", err)
	}
	if opts.ProxyCommand() != "ssh -W %h:%p bastion" || opts.ActiveProxyCommand() != "ssh -W %h:%p bastion" {
		t.Fatalf("unexpected ProxyCommand accessors: %q / %q", opts.ProxyCommand(), opts.ActiveProxyCommand())
	}
	if err := opts.Set("ProxyCommand", "NONE"); err != nil {
		t.Fatalf("Set ProxyCommand=NONE failed: %v", err)
	}
	if opts.ProxyCommand() != "none" || opts.ActiveProxyCommand() != "" {
		t.Fatalf("expected ProxyCommand=none to disable ActiveProxyCommand, got %q / %q", opts.ProxyCommand(), opts.ActiveProxyCommand())
	}

	if err := opts.Set("LocalCommand", " echo connected-%n "); err != nil {
		t.Fatalf("Set LocalCommand failed: %v", err)
	}
	if err := opts.Set("PermitLocalCommand", "YES"); err != nil {
		t.Fatalf("Set PermitLocalCommand=YES failed: %v", err)
	}
	if opts.LocalCommand() != "echo connected-%n" || !opts.PermitLocalCommand() {
		t.Fatalf("unexpected LocalCommand/PermitLocalCommand: %q / %v", opts.LocalCommand(), opts.PermitLocalCommand())
	}
}

func assertPhase5OptionRejection(t *testing.T) {
	t.Helper()
	proxySpec, _ := LookupOptionSpec(OptionProxyCommand)
	localSpec, _ := LookupOptionSpec(OptionLocalCommand)
	for _, bad := range []string{"   ", "echo hi\nid", "nc\x00evil", "cmd\r"} {
		if _, err := proxySpec.Normalize(bad); err == nil {
			t.Fatalf("expected ProxyCommand=%q to be rejected", bad)
		}
		if _, err := localSpec.Normalize(bad); err == nil {
			t.Fatalf("expected LocalCommand=%q to be rejected", bad)
		}
	}
}

func assertPhase5PlanIsolation(t *testing.T) {
	t.Helper()
	basePlan := ConnectionPlan{
		Scope: "phase5-mcp-test",
		Hops: []ConnectionConfig{{
			NodeID:   "web",
			Address:  "10.0.0.10",
			Port:     22,
			User:     "root",
			AuthType: "auto",
			Options:  MustOptions(OptionAddressFamily, "inet"),
		}},
	}
	baseKey, err := ConnectionKey(basePlan)
	if err != nil {
		t.Fatalf("ConnectionKey(basePlan) failed: %v", err)
	}

	withLocalExec := ConnectionPlan{
		Scope: "phase5-mcp-test",
		Hops: []ConnectionConfig{{
			NodeID:   "web",
			Address:  "10.0.0.10",
			Port:     22,
			User:     "root",
			AuthType: "auto",
			Options: MustOptions(
				OptionAddressFamily, "inet",
				OptionProxyCommand, "none",
				OptionLocalCommand, "touch /tmp/pwn",
				OptionPermitLocalCommand, "yes",
			),
		}},
	}
	localExecKey, err := ConnectionKey(withLocalExec)
	if err != nil || localExecKey != baseKey {
		t.Fatalf("OptionClassLocalExec leaked into ConnectionKey: err=%v", err)
	}

	plan, err := normalizePlan(withLocalExec)
	if err != nil {
		t.Fatalf("normalizePlan failed: %v", err)
	}
	hopOpts := plan.Hops[0].Options
	if hopOpts.ProxyCommand() != "" || hopOpts.LocalCommand() != "" || hopOpts.PermitLocalCommand() {
		t.Fatalf("OptionClassLocalExec leaked into normalized ConnectionPlan: %+v", hopOpts)
	}
	if hopOpts.AddressFamily() != "inet" {
		t.Fatalf("expected transport option AddressFamily=inet to remain, got %q", hopOpts.AddressFamily())
	}
	cfgFromPlan := clientConfigFromPlan(withLocalExec.Hops[0])
	if cfgFromPlan.Options.ActiveProxyCommand() != "" || cfgFromPlan.Options.PermitLocalCommand() {
		t.Fatal("OptionClassLocalExec leaked into clientConfigFromPlan")
	}

	// An active ProxyCommand defines routing; plans must fail closed rather
	// than silently dialing the endpoint directly (review M1).
	withProxy := withLocalExec
	withProxy.Hops = []ConnectionConfig{withLocalExec.Hops[0]}
	withProxy.Hops[0].Options = MustOptions(OptionAddressFamily, "inet", OptionProxyCommand, "nc %h %p")
	if _, err := normalizePlan(withProxy); !errors.Is(err, ErrProxyCommandUnavailable) {
		t.Fatalf("normalizePlan with active ProxyCommand: err=%v, want ErrProxyCommandUnavailable", err)
	}
	if _, err := ConnectionKey(withProxy); !errors.Is(err, ErrProxyCommandUnavailable) {
		t.Fatalf("ConnectionKey with active ProxyCommand: err=%v, want ErrProxyCommandUnavailable", err)
	}
	connector := NewConnector(&planProvider{configs: map[string]ClientConfig{}})
	defer func() { _ = connector.CloseAll() }()
	if _, err := connector.ConnectPlan(context.Background(), withProxy); !errors.Is(err, ErrProxyCommandUnavailable) {
		t.Fatalf("ConnectPlan with active ProxyCommand: err=%v, want ErrProxyCommandUnavailable", err)
	}
}

func TestPhase5_ValidateSafeExecTokenAndExpansion_CVE202351385(t *testing.T) {
	validTokens := []struct {
		kind string
		val  string
	}{
		{"%h", "app-01.prod.example.com"},
		{"%h", "192.168.1.10"},
		{"%h", "[2001:db8::1]"},
		{"%h", "[fe80::1%eth0]"},
		{"%n", "my_host-alias.local"},
		{"%r", "deploy.user_1-ops@corp.local"},
		{"%u", "alice"},
		{"%p", "22"},
		{"%p", "65535"},
		{"%i", "1000"},
		{"%i", "S-1-5-21-12345"},
		{"%C", "0123456789abcdefABCDEF"},
		{"%d", "/home/alice_1"},
		{"%d", `C:\Users\alice.dev`},
	}
	for _, tc := range validTokens {
		if err := ValidateSafeExecToken(tc.kind, tc.val); err != nil {
			t.Fatalf("expected ValidateSafeExecToken(%q, %q) to succeed, got %v", tc.kind, tc.val, err)
		}
	}

	unsafeTokens := []struct {
		kind string
		val  string
	}{
		{"%h", ""},
		{"%h", "-oProxyCommand=sh"},
		{"%h", "-J"},
		{"%h", "host;id"},
		{"%h", "host name"},
		{"%h", "host`id`"},
		{"%h", "host$(id)"},
		{"%h", "host|cat"},
		{"%h", "host&id"},
		{"%h", "host'quote"},
		{"%h", `host"quote`},
		{"%h", `host\slash`},
		{"%h", "host\nnewline"},
		{"%h", "host\x00null"},
		{"%h", strings.Repeat("a", 256)},
		{"%r", ""},
		{"%r", "-lroot"},
		{"%r", "user;id"},
		{"%r", "user name"},
		{"%r", `DOMAIN\user`},
		{"%r", "user$var"},
		{"%r", strings.Repeat("u", 129)},
		{"%p", ""},
		{"%p", "0"},
		{"%p", "65536"},
		{"%p", "-22"},
		{"%p", "22;id"},
	}
	for _, tc := range unsafeTokens {
		err := ValidateSafeExecToken(tc.kind, tc.val)
		if !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ValidateSafeExecToken(%q, %q) error = %v, want ErrUnsafeExecToken", tc.kind, tc.val, err)
		}
	}

	env := Environment{
		HomeDir:   "/home/localdev",
		LocalUser: "localdev",
		LocalHost: "workstation.corp.internal",
		LocalUID:  "1001",
	}
	target := TargetContext{
		Host:         "10.10.20.30",
		Port:         2222,
		User:         "deploy",
		OriginalHost: "web-prod",
	}

	gotProxy, err := ExpandProxyCommand("ssh -W %h:%p -l %r bastion-%%-%n", env, target)
	if err != nil {
		t.Fatalf("ExpandProxyCommand failed: %v", err)
	}
	if want := "ssh -W 10.10.20.30:2222 -l deploy bastion-%-web-prod"; gotProxy != want {
		t.Fatalf("ExpandProxyCommand = %q, want %q", gotProxy, want)
	}

	// Local-only tokens (%u, %d) are rejected in ProxyCommand per OpenSSH spec.
	if _, err := ExpandProxyCommand("nc %u %h %p", env, target); err == nil {
		t.Fatal("expected %u to be rejected in ExpandProxyCommand")
	}

	gotLocal, err := ExpandLocalCommand("logger %% %n %h:%p %r %u %i %L %l %d %C", env, target)
	if err != nil {
		t.Fatalf("ExpandLocalCommand failed: %v", err)
	}
	if !strings.HasPrefix(gotLocal, "logger % web-prod 10.10.20.30:2222 deploy localdev 1001 workstation workstation.corp.internal /home/localdev ") {
		t.Fatalf("unexpected ExpandLocalCommand output: %q", gotLocal)
	}

	// Even when the template omits %h, an unsafe TargetContext.Host must still fail closed.
	evilTarget := target
	evilTarget.Host = "-oProxyCommand=evil"
	if _, err := ExpandProxyCommand("nc fixed.example.com 22", env, evilTarget); !errors.Is(err, ErrUnsafeExecToken) {
		t.Fatalf("expected unsafe TargetContext.Host to fail closed, got %v", err)
	}
}

func TestPhase5_ConnectorProxyCommand_FailClosedAndInjectionBlocked(t *testing.T) {
	opts := MustOptions(
		OptionProxyCommand, "ssh -W %h:%p %n",
		OptionStrictHostKeyChecking, "no",
	)

	const secretPassword = "super-secret-phase5-password"
	store := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"prod": {
				NodeID:       "prod",
				OriginalHost: "prod",
				Address:      "10.0.0.50",
				Port:         22,
				User:         "ops",
				AuthType:     "password",
				Password:     secretPassword,
				Options:      opts,
			},
		},
	}

	// 1. Default Environment (DialProxyCommand == nil) fails closed with ErrProxyCommandUnavailable.
	headlessConn := NewConnector(store, WithHostKeyVerifier(trustAnyFixtureHostKey{}))
	t.Cleanup(func() { _ = headlessConn.CloseAll() })
	if _, err := headlessConn.Connect(t.Context(), "prod"); !errors.Is(err, ErrProxyCommandUnavailable) {
		t.Fatalf("Connect with nil DialProxyCommand error = %v, want ErrProxyCommandUnavailable", err)
	}

	// 2. CVE-2023-51385 leading-dash / shell-metacharacter host or user blocks BEFORE invoking DialProxyCommand.
	var dialCalls atomic.Int32
	bufLog := testleak.NewBufferLogger()
	sandboxedConn := NewConnector(
		store,
		WithLogger(bufLog),
		WithHostKeyVerifier(trustAnyFixtureHostKey{}),
		WithEnvironment(Environment{
			DialProxyCommand: func(context.Context, string) (net.Conn, error) {
				dialCalls.Add(1)
				return nil, errors.New("should never be called")
			},
		}),
	)
	t.Cleanup(func() { _ = sandboxedConn.CloseAll() })

	store.configs["prod"].OriginalHost = "-oProxyCommand=touch /tmp/pwn"
	_, err := sandboxedConn.Connect(t.Context(), "prod")
	if !errors.Is(err, ErrUnsafeExecToken) {
		t.Fatalf("Connect with unsafe OriginalHost error = %v, want ErrUnsafeExecToken", err)
	}
	if dialCalls.Load() != 0 {
		t.Fatalf("DialProxyCommand was invoked %d times on unsafe token!", dialCalls.Load())
	}
	testleak.AssertNoSecretInError(t, err, secretPassword)
	testleak.AssertNoSecretInLogs(t, bufLog, secretPassword)
}

func startInMemoryPipeSSHServer(t *testing.T, serverConn net.Conn, expectedPassword string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == expectedPassword {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
	}
	srvCfg.AddHostKey(signer)

	var srvWg sync.WaitGroup
	t.Cleanup(func() {
		_ = serverConn.Close()
		srvWg.Wait()
	})
	srvWg.Add(1)
	go func() {
		defer srvWg.Done()
		sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(serverConn, srvCfg)
		if hsErr != nil {
			_ = serverConn.Close()
			return
		}
		defer func() { _ = sConn.Close() }()
		srvWg.Add(1)
		go func() {
			defer srvWg.Done()
			cryptoSSH.DiscardRequests(reqs)
		}()
		for newChan := range chans {
			if newChan.ChannelType() != "session" {
				_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
				continue
			}
			ch, chReqs, chErr := newChan.Accept()
			if chErr != nil {
				continue
			}
			srvWg.Add(1)
			go func() {
				defer srvWg.Done()
				handleInMemoryExecRequests(ch, chReqs)
			}()
		}
	}()
}

func handleInMemoryExecRequests(ch cryptoSSH.Channel, reqs <-chan *cryptoSSH.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			_, _ = io.WriteString(ch, "proxy-exec-ok\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{Status: 0}))
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

type trackingPipeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackingPipeConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newLoopbackConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		s, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- s
		}
		close(accepted)
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		_ = c.Close()
		t.Fatal("failed to accept loopback connection")
	}
	return c, s
}

func TestPhase5_ConnectorProxyCommand_InMemoryEndToEndAndLifecycle(t *testing.T) {
	opts := MustOptions(
		OptionProxyCommand, "ssh -W %h:%p -l %r via-%n",
		OptionStrictHostKeyChecking, "no",
	)

	store := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"web": {
				NodeID:       "web",
				OriginalHost: "web-alias",
				Address:      "10.20.30.40",
				Port:         2222,
				User:         "alice",
				AuthType:     "password",
				Password:     "test-pw",
				Options:      opts,
			},
		},
	}

	var gotExpanded string
	var trackedClientSide *trackingPipeConn
	conn := NewConnector(
		store,
		WithHandshakeTimeout(120*time.Millisecond),
		WithHostKeyVerifier(trustAnyFixtureHostKey{}),
		WithEnvironment(Environment{
			DialProxyCommand: func(_ context.Context, command string) (net.Conn, error) {
				gotExpanded = command
				cSide, sSide := newLoopbackConnPair(t)
				startInMemoryPipeSSHServer(t, sSide, "test-pw")
				trackedClientSide = &trackingPipeConn{Conn: cSide}
				return trackedClientSide, nil
			},
		}),
	)

	client, err := conn.Connect(t.Context(), "web")
	if err != nil {
		t.Fatalf("Connect over ProxyCommand failed: %v", err)
	}
	if want := "ssh -W 10.20.30.40:2222 -l alice via-web-alias"; gotExpanded != want {
		t.Fatalf("expanded ProxyCommand = %q, want %q", gotExpanded, want)
	}

	out, err := client.Run(t.Context(), "uptime")
	if err != nil {
		t.Fatalf("client.Run over ProxyCommand failed: %v", err)
	}
	if strings.TrimSpace(out) != "proxy-exec-ok" {
		t.Fatalf("client.Run output = %q, want proxy-exec-ok", out)
	}

	// Target compatibility check: mutating ProxyCommand triggers ErrSnapshotMismatch.
	changedOpts := opts.Clone()
	_ = changedOpts.Set(OptionProxyCommand, "nc %h %p")
	changedCfg := *store.configs["web"]
	changedCfg.Options = changedOpts
	if compatErr := validateTargetCompatibility(client.ConnectionConfig(), &changedCfg); !errors.Is(compatErr, ErrSnapshotMismatch) {
		t.Fatalf("validateTargetCompatibility on changed ProxyCommand = %v, want ErrSnapshotMismatch", compatErr)
	}

	if err := conn.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	if trackedClientSide == nil || !trackedClientSide.closed.Load() {
		t.Fatal("expected CloseAll to close underlying ProxyCommand net.Conn")
	}
}

func TestPhase5_ConnectorProxyCommand_MidHandshakeCancelClosesConn(t *testing.T) {
	opts := MustOptions(
		OptionProxyCommand, "nc %h %p",
		OptionStrictHostKeyChecking, "no",
	)

	store := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"stalled": {
				NodeID:   "stalled",
				Address:  "10.0.0.99",
				Port:     22,
				User:     "root",
				AuthType: "password",
				Password: "pw",
				Options:  opts,
			},
		},
	}

	dialed := make(chan struct{})
	var tracked *trackingPipeConn
	conn := NewConnector(
		store,
		WithHandshakeTimeout(120*time.Millisecond),
		WithHostKeyVerifier(trustAnyFixtureHostKey{}),
		WithEnvironment(Environment{
			DialProxyCommand: func(_ context.Context, _ string) (net.Conn, error) {
				cSide, sSide := newLoopbackConnPair(t)
				t.Cleanup(func() { _ = sSide.Close() })
				tracked = &trackingPipeConn{Conn: cSide}
				close(dialed)
				return tracked, nil
			},
		}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-dialed
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := conn.Connect(ctx, "stalled")
	if err == nil {
		t.Fatal("expected stalled handshake canceled by ctx to fail")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for tracked == nil || !tracked.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("expected mid-handshake cancellation to close ProxyCommand net.Conn")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPhase5_ClientRunPostAuthLocalCommand(t *testing.T) {
	var executed []string
	baseClient := &Client{
		environment: Environment{
			LocalUser: "localuser",
			LocalHost: "laptop.local",
			LocalUID:  "501",
			HomeDir:   "/Users/localuser",
			RunLocalCommand: func(_ context.Context, cmd string) error {
				executed = append(executed, cmd)
				return nil
			},
		},
		connCfg: ConnectionConfig{
			NodeID:       "db",
			OriginalHost: "db-primary",
			Address:      "10.0.1.5",
			Port:         2200,
			User:         "postgres",
			Options:      &Options{},
		},
	}

	// 1. Default PermitLocalCommand=no -> never runs even if LocalCommand is set.
	_ = baseClient.connCfg.Options.Set(OptionLocalCommand, "echo %n %h:%p %r")
	if err := baseClient.RunPostAuthLocalCommand(t.Context()); err != nil {
		t.Fatalf("PermitLocalCommand=no returned error: %v", err)
	}
	if len(executed) != 0 {
		t.Fatalf("LocalCommand ran despite PermitLocalCommand=no: %v", executed)
	}

	// 2. PermitLocalCommand=yes + LocalCommand=none -> no-op.
	_ = baseClient.connCfg.Options.Set(OptionPermitLocalCommand, "yes")
	_ = baseClient.connCfg.Options.Set(OptionLocalCommand, "none")
	if err := baseClient.RunPostAuthLocalCommand(t.Context()); err != nil {
		t.Fatalf("LocalCommand=none returned error: %v", err)
	}
	if len(executed) != 0 {
		t.Fatalf("LocalCommand=none should not execute: %v", executed)
	}

	// 3. PermitLocalCommand=yes + valid LocalCommand -> expands and executes once.
	_ = baseClient.connCfg.Options.Set(OptionLocalCommand, "echo %n %h:%p %r %u")
	if err := baseClient.RunPostAuthLocalCommand(t.Context()); err != nil {
		t.Fatalf("RunPostAuthLocalCommand failed: %v", err)
	}
	if len(executed) != 1 || executed[0] != "echo db-primary 10.0.1.5:2200 postgres localuser" {
		t.Fatalf("unexpected executed LocalCommand: %v", executed)
	}

	// 4. Headless environment without RunLocalCommand fails closed with ErrLocalCommandUnavailable.
	baseClient.environment.RunLocalCommand = nil
	if err := baseClient.RunPostAuthLocalCommand(t.Context()); !errors.Is(err, ErrLocalCommandUnavailable) {
		t.Fatalf("expected ErrLocalCommandUnavailable, got %v", err)
	}
}

func TestPhase5_ConnectorProxyJumpPrecedenceAndBastionProxyCommand(t *testing.T) {
	// Target has both ProxyJump="bastion" and a fallback ProxyCommand; ProxyJump wins on target,
	// while bastion itself connects via ProxyCommand.
	var acceptWg sync.WaitGroup
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = targetLn.Close()
		acceptWg.Wait()
	})
	acceptWg.Add(1)
	go func() {
		defer acceptWg.Done()
		for {
			s, acceptErr := targetLn.Accept()
			if acceptErr != nil {
				return
			}
			startInMemoryPipeSSHServer(t, s, "target-pw")
		}
	}()
	targetHost, targetPortStr, _ := net.SplitHostPort(targetLn.Addr().String())
	var targetPort int
	for i := 0; i < len(targetPortStr); i++ {
		targetPort = targetPort*10 + int(targetPortStr[i]-'0')
	}

	bastionLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	startForwardingBastionSSHServer(t, bastionLn, "bastion-pw")

	var proxyCmdInvocations []string
	store := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  "10.1.1.1",
				Port:     22,
				User:     "jump",
				AuthType: "password",
				Password: "bastion-pw",
				Options: MustOptions(
					OptionProxyCommand, "dial-bastion %h:%p",
					OptionStrictHostKeyChecking, "no",
				),
			},
			"target": {
				NodeID:    "target",
				Address:   targetHost,
				Port:      targetPort,
				User:      "app",
				AuthType:  "password",
				Password:  "target-pw",
				ProxyJump: "bastion",
				Options: MustOptions(
					OptionProxyCommand, "should-not-run-for-target %h:%p",
					OptionStrictHostKeyChecking, "no",
				),
			},
		},
	}

	conn := NewConnector(
		store,
		WithHostKeyVerifier(trustAnyFixtureHostKey{}),
		WithEnvironment(Environment{
			DialProxyCommand: func(_ context.Context, cmd string) (net.Conn, error) {
				proxyCmdInvocations = append(proxyCmdInvocations, cmd)
				return net.Dial("tcp", bastionLn.Addr().String())
			},
		}),
	)
	t.Cleanup(func() { _ = conn.CloseAll() })

	client, err := conn.Connect(t.Context(), "target")
	if err != nil {
		t.Fatalf("Connect target via ProxyJump over ProxyCommand bastion failed: %v", err)
	}
	out, err := client.Run(t.Context(), "echo ok")
	if err != nil || strings.TrimSpace(out) != "proxy-exec-ok" {
		t.Fatalf("target Run = (%q, %v), want (proxy-exec-ok, nil)", out, err)
	}
	if len(proxyCmdInvocations) != 1 || proxyCmdInvocations[0] != "dial-bastion 10.1.1.1:22" {
		t.Fatalf("unexpected ProxyCommand invocations: %v", proxyCmdInvocations)
	}
}

func startForwardingBastionSSHServer(t *testing.T, ln net.Listener, expectedPassword string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == expectedPassword {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
	}
	srvCfg.AddHostKey(signer)

	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				serveBastionConn(c, srvCfg, &wg)
			}(raw)
		}
	}()
}

func serveBastionConn(raw net.Conn, srvCfg *cryptoSSH.ServerConfig, wg *sync.WaitGroup) {
	sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(raw, srvCfg)
	if hsErr != nil {
		_ = raw.Close()
		return
	}
	defer func() { _ = sConn.Close() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		cryptoSSH.DiscardRequests(reqs)
	}()
	for newChan := range chans {
		if newChan.ChannelType() != "direct-tcpip" {
			_ = newChan.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		var payload struct {
			Host       string
			Port       uint32
			OriginHost string
			OriginPort uint32
		}
		if err := cryptoSSH.Unmarshal(newChan.ExtraData(), &payload); err != nil {
			_ = newChan.Reject(cryptoSSH.ConnectionFailed, err.Error())
			continue
		}
		upstream, dialErr := net.Dial("tcp", net.JoinHostPort(payload.Host, itoaPort(int(payload.Port))))
		if dialErr != nil {
			_ = newChan.Reject(cryptoSSH.ConnectionFailed, dialErr.Error())
			continue
		}
		ch, chReqs, chErr := newChan.Accept()
		if chErr != nil {
			_ = upstream.Close()
			continue
		}
		wg.Add(2)
		go func() {
			defer wg.Done()
			cryptoSSH.DiscardRequests(chReqs)
		}()
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.Copy(ch, upstream)
				_ = ch.Close()
			}()
			_, _ = io.Copy(upstream, ch)
			_ = upstream.Close()
			_ = ch.Close()
			<-done
		}()
	}
}

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}

func TestPhase5_LocalExecNodeIDOriginalHostFallbackAndRejection(t *testing.T) {
	validCases := []struct {
		nodeID   string
		address  string
		port     int
		user     string
		wantOrig string
	}{
		{"root@10.0.0.5:22", "10.0.0.5", 22, "root", "10.0.0.5"},
		{"openssh:web-prod", "10.0.0.11", 22, "deploy", "web-prod"},
		{"openssh:ops@10.0.0.5:2222", "10.0.0.5", 2222, "ops", "10.0.0.5"},
		{"root@[fe80::1%eth0]:2222", "fe80::1%eth0", 2222, "root", "fe80::1%eth0"},
	}

	for _, tc := range validCases {
		opts := MustOptions(
			OptionProxyCommand, "proxy-to %n %h:%p %r",
			OptionPermitLocalCommand, "yes",
			OptionLocalCommand, "local-for %n %h:%p %r",
			OptionStrictHostKeyChecking, "no",
		)
		store := &mapTestProvider{
			configs: map[string]*ClientConfig{
				tc.nodeID: {
					NodeID:   tc.nodeID,
					Address:  tc.address,
					Port:     tc.port,
					User:     tc.user,
					AuthType: "password",
					Password: "pw",
					Options:  opts,
				},
			},
		}

		// Verify Connector.buildTargetContext remains untouched for ControlPath / mux handoff.
		rawConn := NewConnector(store)
		if gotMuxOrig := rawConn.buildTargetContext(connectionPlanNode{name: tc.nodeID, cfg: store.configs[tc.nodeID]}).OriginalHost; gotMuxOrig != tc.nodeID {
			_ = rawConn.CloseAll()
			t.Fatalf("buildTargetContext(%q).OriginalHost = %q, want %q", tc.nodeID, gotMuxOrig, tc.nodeID)
		}
		_ = rawConn.CloseAll()

		var gotProxyCmd, gotLocalCmd string
		conn := NewConnector(
			store,
			WithHostKeyVerifier(trustAnyFixtureHostKey{}),
			WithEnvironment(Environment{
				LocalUser: "localdev",
				DialProxyCommand: func(_ context.Context, cmd string) (net.Conn, error) {
					gotProxyCmd = cmd
					cSide, sSide := newLoopbackConnPair(t)
					startInMemoryPipeSSHServer(t, sSide, "pw")
					return cSide, nil
				},
				RunLocalCommand: func(_ context.Context, cmd string) error {
					gotLocalCmd = cmd
					return nil
				},
			}),
		)

		client, err := conn.Connect(t.Context(), tc.nodeID)
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("Connect(%q) failed: %v", tc.nodeID, err)
		}
		wantProxy := "proxy-to " + tc.wantOrig + " " + tc.address + ":" + itoaPort(tc.port) + " " + tc.user
		if gotProxyCmd != wantProxy {
			_ = conn.CloseAll()
			t.Fatalf("Connect(%q) ProxyCommand = %q, want %q", tc.nodeID, gotProxyCmd, wantProxy)
		}
		if err := client.RunPostAuthLocalCommand(t.Context()); err != nil {
			_ = conn.CloseAll()
			t.Fatalf("RunPostAuthLocalCommand(%q) failed: %v", tc.nodeID, err)
		}
		wantLocal := "local-for " + tc.wantOrig + " " + tc.address + ":" + itoaPort(tc.port) + " " + tc.user
		if gotLocalCmd != wantLocal {
			_ = conn.CloseAll()
			t.Fatalf("RunPostAuthLocalCommand(%q) = %q, want %q", tc.nodeID, gotLocalCmd, wantLocal)
		}
		_ = conn.CloseAll()
	}

	assertPhase5UnsafeNodeIDsFailClosed(t)
}

func assertPhase5UnsafeNodeIDsFailClosed(t *testing.T) {
	t.Helper()
	unsafeCases := []struct {
		nodeID       string
		originalHost string
	}{
		{nodeID: "root@-oProxyCommand=sh:22"},
		{nodeID: "bad;id@10.0.0.5:22"},
		{nodeID: "-lroot@10.0.0.5:22"},
		{nodeID: "openssh:-oProxyCommand=sh"},
		{nodeID: "openssh:"},
		{nodeID: "root@10.0.0.5:22;id"},
		{nodeID: "root@10.0.0.5:22", originalHost: "explicit@disallowed"},
		{nodeID: "root@10.0.0.5:22", originalHost: "-oProxyCommand=sh"},
	}

	for _, tc := range unsafeCases {
		var dialCalls, localCalls atomic.Int32
		opts := MustOptions(
			OptionProxyCommand, "nc %n %p -u %r",
			OptionPermitLocalCommand, "yes",
			OptionLocalCommand, "echo %n %r",
			OptionStrictHostKeyChecking, "no",
		)
		store := &mapTestProvider{
			configs: map[string]*ClientConfig{
				tc.nodeID: {
					NodeID:       tc.nodeID,
					OriginalHost: tc.originalHost,
					Address:      "10.0.0.5",
					Port:         22,
					User:         "root",
					AuthType:     "password",
					Password:     "pw",
					Options:      opts,
				},
			},
		}
		env := Environment{
			LocalUser: "localdev",
			DialProxyCommand: func(context.Context, string) (net.Conn, error) {
				dialCalls.Add(1)
				return nil, errors.New("unexpected dial")
			},
			RunLocalCommand: func(context.Context, string) error {
				localCalls.Add(1)
				return nil
			},
		}
		conn := NewConnector(store, WithHostKeyVerifier(trustAnyFixtureHostKey{}), WithEnvironment(env))
		_, err := conn.Connect(t.Context(), tc.nodeID)
		_ = conn.CloseAll()
		if !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("Connect(nodeID=%q, orig=%q) error = %v, want ErrUnsafeExecToken", tc.nodeID, tc.originalHost, err)
		}
		if dialCalls.Load() != 0 {
			t.Fatalf("DialProxyCommand called %d times on unsafe nodeID=%q orig=%q", dialCalls.Load(), tc.nodeID, tc.originalHost)
		}

		c := &Client{
			environment: env,
			connCfg:     store.configs[tc.nodeID].ToConnectionConfig(),
		}
		if err := c.RunPostAuthLocalCommand(t.Context()); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("RunPostAuthLocalCommand(nodeID=%q, orig=%q) error = %v, want ErrUnsafeExecToken", tc.nodeID, tc.originalHost, err)
		}
		if localCalls.Load() != 0 {
			t.Fatalf("RunLocalCommand called %d times on unsafe nodeID=%q orig=%q", localCalls.Load(), tc.nodeID, tc.originalHost)
		}
	}
}
