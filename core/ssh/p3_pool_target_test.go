package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP3_NormalizeAndBuildClientTargetContext(t *testing.T) {
	t.Parallel()

	env := Environment{LocalUser: "localops"}
	ctrl := &ControlConfig{Master: ControlMasterAuto, Path: "/tmp/p3-%C.sock"}

	t.Run("NormalizeTargetContext", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name string
			raw  TargetContext
			want TargetContext
		}{
			{
				name: "bracketed IPv6 and default port/user",
				raw: TargetContext{
					Host:          " [2001:db8::1] ",
					Port:          0,
					User:          "",
					OriginalHost:  "  v6-alias \t",
					CanonicalHost: "  v6.example.internal  ",
					JumpHost:      "none",
					KeyPath:       "/keys/id_ed25519",
					Control:       ctrl,
				},
				want: TargetContext{
					Host:          "2001:db8::1",
					Port:          22,
					User:          "localops",
					OriginalHost:  "v6-alias",
					CanonicalHost: "v6.example.internal",
					JumpHost:      "",
					KeyPath:       "/keys/id_ed25519",
					Control:       ctrl,
				},
			},
			{
				name: "bracketed IPv6 with zone ID and negative port",
				raw: TargetContext{
					Host:         "[fe80::1%eth0]",
					Port:         -10,
					User:         "deploy",
					OriginalHost: "   ",
					JumpHost:     "NONE, none",
				},
				want: TargetContext{
					Host:         "fe80::1%eth0",
					Port:         22,
					User:         "deploy",
					OriginalHost: "",
					JumpHost:     "",
				},
			},
			{
				name: "comma-only and spaced ProxyJump list",
				raw: TargetContext{
					Host:     "10.0.0.5",
					Port:     2222,
					User:     "ops",
					JumpHost: " , ",
				},
				want: TargetContext{
					Host:     "10.0.0.5",
					Port:     2222,
					User:     "ops",
					JumpHost: "",
				},
			},
			{
				name: "multi-hop ProxyJump strips whitespace and none entries",
				raw: TargetContext{
					Host:     "app.internal",
					Port:     2200,
					User:     "svc",
					JumpHost: " a , none , b ",
				},
				want: TargetContext{
					Host:     "app.internal",
					Port:     2200,
					User:     "svc",
					JumpHost: "a,b",
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := NormalizeTargetContext(tc.raw, env)
				if got != tc.want {
					t.Fatalf("NormalizeTargetContext(%+v) = %+v, want %+v", tc.raw, got, tc.want)
				}
			})
		}
	})

	t.Run("BuildClientTargetContext", func(t *testing.T) {
		t.Parallel()

		// Nil cfg must not panic and must fall back safely.
		gotNil := BuildClientTargetContext("  fallback-node  ", nil, env, ctrl)
		wantNil := TargetContext{
			Host:         "",
			Port:         22,
			User:         "localops",
			OriginalHost: "fallback-node",
			Control:      ctrl,
		}
		if gotNil != wantNil {
			t.Fatalf("BuildClientTargetContext(nil) = %+v, want %+v", gotNil, wantNil)
		}

		// Explicit OriginalHost wins over NodeID and nodeName.
		cfgExplicit := &ClientConfig{
			NodeID:        "node-id",
			OriginalHost:  "  cli-alias  ",
			CanonicalHost: "  web.prod.local ",
			Address:       " [fe80::2%en0] ",
			Port:          0,
			User:          "",
			ProxyJump:     "bastion1, bastion2",
			KeyPath:       "/tmp/key",
		}
		gotExplicit := BuildClientTargetContext("plan-name", cfgExplicit, env, ctrl)
		wantExplicit := TargetContext{
			Host:          "fe80::2%en0",
			Port:          22,
			User:          "localops",
			OriginalHost:  "cli-alias",
			CanonicalHost: "web.prod.local",
			JumpHost:      "bastion1,bastion2",
			KeyPath:       "/tmp/key",
			Control:       ctrl,
		}
		if gotExplicit != wantExplicit {
			t.Fatalf("BuildClientTargetContext(explicit) = %+v, want %+v", gotExplicit, wantExplicit)
		}

		// Empty OriginalHost falls back to NodeID; empty NodeID falls back to nodeName.
		cfgNodeID := &ClientConfig{
			NodeID:    "node-from-id",
			Address:   "10.1.2.3",
			Port:      2202,
			User:      "alice",
			ProxyJump: "none,none",
		}
		if got := BuildClientTargetContext("plan-name", cfgNodeID, env, nil); got.OriginalHost != "node-from-id" || got.JumpHost != "" {
			t.Fatalf("BuildClientTargetContext(NodeID fallback) = %+v", got)
		}

		cfgPlanFallback := &ClientConfig{
			OriginalHost: "   ",
			NodeID:       "   ",
			Address:      "[2001:db8::9]",
			ProxyJump:    ",",
		}
		gotFallback := BuildClientTargetContext("plan-node", cfgPlanFallback, env, ctrl)
		if gotFallback.OriginalHost != "plan-node" || gotFallback.Host != "2001:db8::9" || gotFallback.Port != 22 || gotFallback.User != "localops" || gotFallback.JumpHost != "" {
			t.Fatalf("BuildClientTargetContext(nodeName fallback) = %+v", gotFallback)
		}

		// Connector.buildTargetContext delegates directly to BuildClientTargetContext.
		conn := NewConnector(nil, WithEnvironment(env))
		defer func() { _ = conn.CloseAll() }()
		planNode := connectionPlanNode{name: "plan-name", cfg: cfgExplicit, control: ctrl}
		if got := conn.buildTargetContext(planNode); got != gotExplicit {
			t.Fatalf("Connector.buildTargetContext() = %+v, want %+v", got, gotExplicit)
		}
	})
}

type p3GatedFixture struct {
	srv     *sshfixture.Server
	host    string
	port    int
	label   string
	mu      sync.Mutex
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newP3GatedFixture(t *testing.T, ctx context.Context, label string, pubKeys ...cryptoSSH.PublicKey) *p3GatedFixture {
	t.Helper()
	f := &p3GatedFixture{
		label:   label,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	srv, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		PublicKeys: pubKeys,
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			if command == "hold" {
				f.once.Do(func() { close(f.started) })
				select {
				case <-f.release:
				case <-ctx.Done():
					return
				}
				_, _ = io.WriteString(channel, f.label+":held-ok")
			} else {
				_, _ = io.WriteString(channel, f.label+":"+command)
			}
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatalf("start %s sshfixture failed: %v", label, err)
	}
	t.Cleanup(func() {
		f.ReleaseHold()
		if err := srv.Close(); err != nil {
			t.Errorf("close %s sshfixture failed: %v", label, err)
		}
	})
	host, port := fixtureEndpoint(t, srv.Address)
	f.srv = srv
	f.host = host
	f.port = port
	return f
}

func (f *p3GatedFixture) ReleaseHold() {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.release:
	default:
		close(f.release)
	}
}

type p3RoutingDialer struct {
	mu       sync.Mutex
	aliases  map[string]string
	networks []string
}

func (d *p3RoutingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *p3RoutingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.networks = append(d.networks, network)
	target := addr
	if mapped, ok := d.aliases[addr]; ok {
		target = mapped
	}
	d.mu.Unlock()
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, target)
}

func (d *p3RoutingDialer) Networks() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.networks)
}

func writeP3Ed25519KeyFile(t *testing.T, dir, name string) (string, cryptoSSH.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("create ssh public key: %v", err)
	}
	block, err := cryptoSSH.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key file: %v", err)
	}
	return path, sshPub
}

func runP3Command(t *testing.T, ctx context.Context, client *Client, cmd string) string {
	t.Helper()
	plan, err := PlanCommand(cmd, CommandOptions{})
	if err != nil {
		t.Fatalf("PlanCommand(%q) failed: %v", cmd, err)
	}
	res := client.ExecuteCommand(ctx, plan)
	if err := res.Err(); err != nil {
		t.Fatalf("ExecuteCommand(%q) failed: %v", cmd, err)
	}
	return strings.TrimSpace(res.Output)
}

func startP3HeldCommand(t *testing.T, ctx context.Context, client *Client, started <-chan struct{}) <-chan struct {
	out string
	err error
} {
	t.Helper()
	plan, err := PlanCommand("hold", CommandOptions{})
	if err != nil {
		t.Fatalf("PlanCommand(hold) failed: %v", err)
	}
	done := make(chan struct {
		out string
		err error
	}, 1)
	go func() {
		res := client.ExecuteCommand(ctx, plan)
		done <- struct {
			out string
			err error
		}{out: strings.TrimSpace(res.Output), err: res.Err()}
	}()
	select {
	case <-started:
	case <-ctx.Done():
	}
	return done
}

func assertP3TransportClosed(t *testing.T, name string, client *Client) {
	t.Helper()
	if !isClientTransportClosed(client) {
		t.Errorf("%s physical transport was not marked closed after CloseAll", name)
	}
	if _, _, err := client.sshClient.SendRequest("p3-closed-check", true, nil); err == nil {
		t.Errorf("%s SSH transport unexpectedly remained open after CloseAll", name)
	}
}

type p3MutationCase struct {
	name          string
	initial       func(env *p3MutationEnv) *ClientConfig
	mutate        func(env *p3MutationEnv, cfg *ClientConfig)
	wantSecondOut string
	verify        func(t *testing.T, env *p3MutationEnv, c1, c2 *Client)
}

type p3MutationEnv struct {
	srv1     *p3GatedFixture
	srv2     *p3GatedFixture
	bastion  *p3GatedFixture
	dialer   *p3RoutingDialer
	recorder *diagnosticRecorder
	key1Path string
	key2Path string
}

func runP3MutationSubtest(t *testing.T, tc p3MutationCase) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	keyDir := t.TempDir()
	key1Path, pub1 := writeP3Ed25519KeyFile(t, keyDir, "id_ed25519_1")
	key2Path, pub2 := writeP3Ed25519KeyFile(t, keyDir, "id_ed25519_2")

	srv1 := newP3GatedFixture(t, ctx, "srv1", pub1, pub2)
	srv2 := newP3GatedFixture(t, ctx, "srv2", pub1, pub2)
	bastion := newP3GatedFixture(t, ctx, "bastion")

	dialer := &p3RoutingDialer{
		aliases: map[string]string{
			fmt.Sprintf("host-a.p3.test:%d", srv1.port): srv1.srv.Address,
			fmt.Sprintf("host-b.p3.test:%d", srv1.port): srv2.srv.Address,
		},
	}
	recorder := &diagnosticRecorder{}
	env := &p3MutationEnv{
		srv1:     srv1,
		srv2:     srv2,
		bastion:  bastion,
		dialer:   dialer,
		recorder: recorder,
		key1Path: key1Path,
		key2Path: key2Path,
	}

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  bastion.host,
				Port:     bastion.port,
				User:     "fixture",
				AuthType: "password",
				Password: sshfixture.Password,
			},
			"node": tc.initial(env),
		},
	}

	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithDiagnostics(recorder),
	)
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := connector.CloseAll(); err != nil {
				t.Errorf("cleanup CloseAll failed: %v", err)
			}
		}
	})

	client1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("first Connect(node) failed: %v", err)
	}
	if got := runP3Command(t, ctx, client1, "before"); got != "srv1:before" {
		t.Fatalf("client1 initial command = %q, want %q", got, "srv1:before")
	}

	// Keep an active exec session in flight on client1 across the mutation + second Connect.
	heldDone := startP3HeldCommand(t, ctx, client1, srv1.started)

	provider.mu.Lock()
	tc.mutate(env, provider.cfgs["node"])
	provider.mu.Unlock()

	client2, err := connector.Connect(ctx, "node")
	if err != nil {
		srv1.ReleaseHold()
		<-heldDone
		t.Fatalf("second Connect(node) after mutation failed: %v", err)
	}
	if client1.sshClient == client2.sshClient {
		srv1.ReleaseHold()
		<-heldDone
		t.Fatalf("second Connect(node) reused incompatible pooled transport for mutation %q", tc.name)
	}
	if got := runP3Command(t, ctx, client2, "after"); got != tc.wantSecondOut {
		srv1.ReleaseHold()
		<-heldDone
		t.Fatalf("client2 command = %q, want %q", got, tc.wantSecondOut)
	}

	// Release client1's active session and verify it finished uninterrupted AND can still open new sessions.
	srv1.ReleaseHold()
	heldRes := <-heldDone
	if heldRes.err != nil || heldRes.out != "srv1:held-ok" {
		t.Fatalf("client1 in-flight session disrupted: out=%q err=%v", heldRes.out, heldRes.err)
	}
	if got := runP3Command(t, ctx, client1, "still-alive"); got != "srv1:still-alive" {
		t.Fatalf("client1 follow-up command after retirement = %q, want %q", got, "srv1:still-alive")
	}

	if tc.verify != nil {
		tc.verify(t, env, client1, client2)
	}

	// CloseAll must close both client1's retired transport and client2's active transport cleanly.
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	closed = true
	if connector.pool.Count() != 0 {
		t.Fatalf("expected empty active pool after CloseAll, got %d", connector.pool.Count())
	}
	if remainingRetired := connector.pool.RetiredCount(); remainingRetired != 0 {
		t.Fatalf("expected empty retired pool after CloseAll, got %d", remainingRetired)
	}
	assertP3TransportClosed(t, "client1 (retired)", client1)
	assertP3TransportClosed(t, "client2 (active)", client2)
}

func p3BaseMutationConfig(env *p3MutationEnv) *ClientConfig {
	return &ClientConfig{
		NodeID:   "node",
		Address:  env.srv1.host,
		Port:     env.srv1.port,
		User:     "alice",
		AuthType: "password",
		Password: sshfixture.Password,
	}
}

func assertP3AuthCount(t *testing.T, label string, got, want int32) {
	t.Helper()
	if got != want {
		t.Fatalf("%s auth count = %d, want %d", label, got, want)
	}
}

func assertP3TwoServerAuth(t *testing.T, env *p3MutationEnv, _, _ *Client) {
	t.Helper()
	assertP3AuthCount(t, "srv1", env.srv1.srv.Authenticated.Load(), 1)
	assertP3AuthCount(t, "srv2", env.srv2.srv.Authenticated.Load(), 1)
}

func assertP3SingleServerReauth(t *testing.T, env *p3MutationEnv, _, _ *Client) {
	t.Helper()
	assertP3AuthCount(t, "srv1", env.srv1.srv.Authenticated.Load(), 2)
}

func assertP3NegotiatedCiphers(t *testing.T, env *p3MutationEnv, _, _ *Client) {
	t.Helper()
	var ciphers []string
	for _, ev := range env.recorder.snapshot() {
		if ev.Kind == corelog.Authenticated {
			ciphers = append(ciphers, ev.ReadCipher)
		}
	}
	want := []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"}
	if !slices.Equal(ciphers, want) {
		t.Fatalf("negotiated ciphers = %v, want %v", ciphers, want)
	}
}

func TestP3_ConnectorPool_SnapshotIsolationAcrossMutations(t *testing.T) {
	cases := []p3MutationCase{
		{
			name: "Address",
			initial: func(env *p3MutationEnv) *ClientConfig {
				cfg := p3BaseMutationConfig(env)
				cfg.Address = "host-a.p3.test"
				return cfg
			},
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.Address = "host-b.p3.test"
			},
			wantSecondOut: "srv2:after",
			verify:        assertP3TwoServerAuth,
		},
		{
			name:    "Port",
			initial: p3BaseMutationConfig,
			mutate: func(env *p3MutationEnv, cfg *ClientConfig) {
				cfg.Port = env.srv2.port
			},
			wantSecondOut: "srv2:after",
			verify:        assertP3TwoServerAuth,
		},
		{
			name:    "User",
			initial: p3BaseMutationConfig,
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.User = "bob"
			},
			wantSecondOut: "srv1:after",
			verify: func(t *testing.T, env *p3MutationEnv, c1, c2 *Client) {
				assertP3SingleServerReauth(t, env, c1, c2)
				if c1.Config().User != "alice" || c2.Config().User != "bob" {
					t.Fatalf("users = (%q, %q), want (alice, bob)", c1.Config().User, c2.Config().User)
				}
			},
		},
		{
			name: "AddressFamily",
			initial: func(env *p3MutationEnv) *ClientConfig {
				cfg := p3BaseMutationConfig(env)
				cfg.Options = MustOptions(OptionAddressFamily, "any")
				return cfg
			},
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.Options = MustOptions(OptionAddressFamily, "inet")
			},
			wantSecondOut: "srv1:after",
			verify: func(t *testing.T, env *p3MutationEnv, _, _ *Client) {
				if nets := env.dialer.Networks(); !slices.Equal(nets, []string{"tcp", "tcp4"}) {
					t.Fatalf("dial networks = %v, want [tcp tcp4]", nets)
				}
			},
		},
		{
			name: "KeyPath",
			initial: func(env *p3MutationEnv) *ClientConfig {
				return &ClientConfig{
					NodeID:   "node",
					Address:  env.srv1.host,
					Port:     env.srv1.port,
					User:     "alice",
					AuthType: "key",
					KeyPath:  env.key1Path,
				}
			},
			mutate: func(env *p3MutationEnv, cfg *ClientConfig) {
				cfg.KeyPath = env.key2Path
			},
			wantSecondOut: "srv1:after",
			verify: func(t *testing.T, env *p3MutationEnv, c1, c2 *Client) {
				assertP3SingleServerReauth(t, env, c1, c2)
				if c1.Config().KeyPath != env.key1Path || c2.Config().KeyPath != env.key2Path {
					t.Fatalf("key paths = (%q, %q), want (%q, %q)",
						c1.Config().KeyPath, c2.Config().KeyPath, env.key1Path, env.key2Path)
				}
			},
		},
		{
			name: "KeyPaths",
			initial: func(env *p3MutationEnv) *ClientConfig {
				return &ClientConfig{
					NodeID:   "node",
					Address:  env.srv1.host,
					Port:     env.srv1.port,
					User:     "alice",
					AuthType: "key",
					KeyPaths: []string{env.key1Path},
				}
			},
			mutate: func(env *p3MutationEnv, cfg *ClientConfig) {
				cfg.KeyPaths = []string{env.key2Path}
			},
			wantSecondOut: "srv1:after",
			verify:        assertP3SingleServerReauth,
		},
		{
			name: "StrictHostKeyChecking",
			initial: func(env *p3MutationEnv) *ClientConfig {
				cfg := p3BaseMutationConfig(env)
				cfg.Options = MustOptions(OptionStrictHostKeyChecking, "yes")
				return cfg
			},
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.Options = MustOptions(OptionStrictHostKeyChecking, "no")
			},
			wantSecondOut: "srv1:after",
			verify:        assertP3SingleServerReauth,
		},
		{
			name: "Ciphers",
			initial: func(env *p3MutationEnv) *ClientConfig {
				cfg := p3BaseMutationConfig(env)
				cfg.Options = MustOptions(OptionCiphers, "aes128-gcm@openssh.com")
				return cfg
			},
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.Options = MustOptions(OptionCiphers, "chacha20-poly1305@openssh.com")
			},
			wantSecondOut: "srv1:after",
			verify:        assertP3NegotiatedCiphers,
		},
		{
			name:    "ProxyJump_DisabledSnapshotDriftSameRouteKey",
			initial: p3BaseMutationConfig,
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.ProxyJump = "none"
			},
			wantSecondOut: "srv1:after",
			verify:        assertP3SingleServerReauth,
		},
		{
			name:    "ProxyJump_DirectToBastion",
			initial: p3BaseMutationConfig,
			mutate: func(_ *p3MutationEnv, cfg *ClientConfig) {
				cfg.ProxyJump = "bastion"
			},
			wantSecondOut: "srv1:after",
			verify: func(t *testing.T, env *p3MutationEnv, c1, c2 *Client) {
				assertP3AuthCount(t, "bastion", env.bastion.srv.Authenticated.Load(), 1)
				if env.bastion.srv.Forwards.Load() != 1 {
					t.Fatalf("bastion forwards = %d, want 1", env.bastion.srv.Forwards.Load())
				}
				assertP3SingleServerReauth(t, env, c1, c2)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runP3MutationSubtest(t, tc)
		})
	}
}

func runP3JumpMutationScenario(t *testing.T, connectJumpFirst bool) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastion1 := newP3GatedFixture(t, ctx, "bastion1")
	bastion2 := newP3GatedFixture(t, ctx, "bastion2")
	target := newP3GatedFixture(t, ctx, "target")

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID:   "jump",
				Address:  bastion1.host,
				Port:     bastion1.port,
				User:     "ops-old",
				AuthType: "password",
				Password: sshfixture.Password,
			},
			"target": {
				NodeID:    "target",
				Address:   target.host,
				Port:      target.port,
				User:      "fixture",
				AuthType:  "password",
				Password:  sshfixture.Password,
				ProxyJump: "jump",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	closed := false
	t.Cleanup(func() {
		if !closed {
			if err := connector.CloseAll(); err != nil {
				t.Errorf("cleanup CloseAll failed: %v", err)
			}
		}
	})

	client1, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("first Connect(target) failed: %v", err)
	}
	assertP3AuthCount(t, "initial bastion1", bastion1.srv.Authenticated.Load(), 1)
	assertP3AuthCount(t, "initial bastion2", bastion2.srv.Authenticated.Load(), 0)
	assertP3AuthCount(t, "initial target", target.srv.Authenticated.Load(), 1)

	// Hold an active exec session on client1 (old bastion1 -> target chain).
	heldDone := startP3HeldCommand(t, ctx, client1, target.started)
	heldConsumed := false
	defer func() {
		target.ReleaseHold()
		if !heldConsumed {
			<-heldDone
		}
	}()

	// Mutate jump's Address/Port and User to point at bastion2.
	provider.mu.Lock()
	provider.cfgs["jump"].Address = bastion2.host
	provider.cfgs["jump"].Port = bastion2.port
	provider.cfgs["jump"].User = "ops-new"
	provider.mu.Unlock()

	if connectJumpFirst {
		jump2, jumpErr := connector.Connect(ctx, "jump")
		if jumpErr != nil {
			t.Fatalf("Connect(jump) after mutation failed: %v", jumpErr)
		}
		if jump2.Config().User != "ops-new" {
			t.Fatalf("jump2.User = %q, want ops-new", jump2.Config().User)
		}
	}

	client2, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second Connect(target) after jump mutation failed: %v", err)
	}
	if client1.sshClient == client2.sshClient {
		t.Fatal("Connect(target) reused old jump->target transport after jump mutated")
	}
	assertP3AuthCount(t, "post-mutation bastion1", bastion1.srv.Authenticated.Load(), 1)
	assertP3AuthCount(t, "post-mutation bastion2", bastion2.srv.Authenticated.Load(), 1)
	assertP3AuthCount(t, "post-mutation target", target.srv.Authenticated.Load(), 2)
	if bastion2.srv.Forwards.Load() != 1 {
		t.Fatalf("bastion2 forwards = %d, want 1", bastion2.srv.Forwards.Load())
	}

	// Verify client2 works over the new bastion2 -> target chain.
	if got := runP3Command(t, ctx, client2, "via-b2"); got != "target:via-b2" {
		t.Fatalf("client2 command = %q, want target:via-b2", got)
	}

	// Verify client1's active session over old bastion1 -> target survived uninterrupted.
	target.ReleaseHold()
	heldRes := <-heldDone
	heldConsumed = true
	if heldRes.err != nil || heldRes.out != "target:held-ok" {
		t.Fatalf("client1 active session on old jump chain disrupted: out=%q err=%v", heldRes.out, heldRes.err)
	}
	if got := runP3Command(t, ctx, client1, "still-via-b1"); got != "target:still-via-b1" {
		t.Fatalf("client1 follow-up command on old jump chain = %q, want target:still-via-b1", got)
	}

	// CloseAll closes both generations cleanly.
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	closed = true
	assertP3TransportClosed(t, "client1 (old jump chain)", client1)
	assertP3TransportClosed(t, "client2 (new jump chain)", client2)
}

func TestP3_ConnectorPool_JumpHopMutationCascadesWithoutKillingLiveSession(t *testing.T) {
	t.Run("DirectTargetReconnect", func(t *testing.T) {
		runP3JumpMutationScenario(t, false)
	})
	t.Run("JumpReconnectedBeforeTarget", func(t *testing.T) {
		runP3JumpMutationScenario(t, true)
	})
}

func TestP3_CapturePlanAndConnectPlan_MultiHopReuseWithSnapshots(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	jump := newP3GatedFixture(t, ctx, "jump")
	target := newP3GatedFixture(t, ctx, "target")

	captureProvider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID:   "jump",
				Address:  jump.host,
				Port:     jump.port,
				User:     "fixture",
				AuthType: "password",
			},
			"target": {
				NodeID:    "target",
				Address:   target.host,
				Port:      target.port,
				User:      "fixture",
				AuthType:  "password",
				ProxyJump: "jump",
			},
		},
	}

	plan, err := CapturePlan(ctx, captureProvider, "target", "p3-multihop")
	if err != nil {
		t.Fatalf("CapturePlan failed: %v", err)
	}
	if len(plan.Hops) != 2 {
		t.Fatalf("len(plan.Hops) = %d, want 2", len(plan.Hops))
	}

	recorder := &diagnosticRecorder{}
	connector := NewConnector(
		&forbiddenPlanProvider{},
		WithSecretResolver(staticFixtureSecrets{}),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithDiagnostics(recorder),
	)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("CloseAll failed: %v", err)
		}
	})

	lease1, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatalf("first ConnectPlan failed: %v", err)
	}
	defer closePlanLease(t, lease1)

	if got := runP3Command(t, ctx, lease1.Client, "first"); got != "target:first" {
		t.Fatalf("lease1 command = %q, want target:first", got)
	}
	if jump.srv.Authenticated.Load() != 1 || target.srv.Authenticated.Load() != 1 {
		t.Fatalf("after first ConnectPlan auth counts = (%d, %d), want (1, 1)",
			jump.srv.Authenticated.Load(), target.srv.Authenticated.Load())
	}

	beforeSecond := len(recorder.snapshot())

	lease2, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatalf("second ConnectPlan failed: %v", err)
	}
	defer closePlanLease(t, lease2)

	if lease1.Client.sshClient != lease2.Client.sshClient {
		t.Fatal("second ConnectPlan did not reuse cached 2-hop PooledClient")
	}
	if jump.srv.Authenticated.Load() != 1 || target.srv.Authenticated.Load() != 1 {
		t.Fatalf("second ConnectPlan unexpectedly re-authenticated: jump=%d target=%d",
			jump.srv.Authenticated.Load(), target.srv.Authenticated.Load())
	}
	if got := runP3Command(t, ctx, lease2.Client, "second"); got != "target:second" {
		t.Fatalf("lease2 command = %q, want target:second", got)
	}

	events := recorder.snapshot()[beforeSecond:]
	var sawJumpReuse, sawTargetReuse bool
	for _, ev := range events {
		if ev.Kind == corelog.ConnectionReused {
			switch ev.NodeID {
			case "jump":
				sawJumpReuse = true
			case "target":
				sawTargetReuse = true
			}
		}
	}
	if !sawJumpReuse || !sawTargetReuse {
		t.Fatalf("expected ConnectionReused diagnostics for jump and target on second ConnectPlan, got %+v", events)
	}
}

type staticFixtureSecrets struct{}

func (staticFixtureSecrets) ResolveSecret(ctx context.Context, _ SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte(sshfixture.Password), nil
}
