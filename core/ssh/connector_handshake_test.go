package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type immutableProviderSpy struct {
	nopCredentialRecorder
	mu             sync.Mutex
	cfg            *ClientConfig
	updated        int
	committedToken string
	lastPwd        string
	lastKey        string
	lastPhr        string
}

func (p *immutableProviderSpy) GetConfig(string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.updated == 0 {
		return p.cfg, nil
	}
	cp := cloneClientConfigForAssertion(p.cfg)
	cp.AuthUpdateToken = p.committedToken
	if p.lastKey != "" {
		cp.KeyPath = p.lastKey
	}
	return cp, nil
}

func (p *immutableProviderSpy) UpdateAuth(_ context.Context, _, authUpdateToken, password, keyPath, passphrase string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updated++
	p.lastPwd = password
	p.lastKey = keyPath
	p.lastPhr = passphrase
	p.committedToken = authUpdateToken + "-committed"
	return p.committedToken, nil
}

func cloneClientConfigForAssertion(cfg *ClientConfig) *ClientConfig {
	cp := *cfg
	cp.KeyPaths = slices.Clone(cfg.KeyPaths)
	cp.Execution = cfg.Execution.Clone()
	cp.Options = cfg.Options.Clone()
	return &cp
}

func TestFreezeDialPolicyDoesNotMutateCallerConfig(t *testing.T) {
	cfg := &ClientConfig{
		NodeID:                "web-01",
		Address:               "[2001:db8::1]",
		Port:                  0,
		User:                  "ops",
		AuthType:              "auto",
		KeyPath:               "/tmp/k1",
		KeyPaths:              []string{"/tmp/k1", "/tmp/k2"},
		KeyRef:                "ref-1",
		AuthUpdateToken:       "auth-tok",
		SudoMode:              SudoModeSudo,
		SudoUpdateToken:       "sudo-tok",
		ProxyJump:             "bastion",
		OriginalHost:          "web-alias",
		TrustVersion:          "trust-1",
		PasswordPromptPattern: "Password:",
		Password:              "secret-pwd",
		Passphrase:            "secret-pass",
		SuPwd:                 "secret-su",
		Execution:             &ExecutionConfig{Interpreter: InterpreterSh},
		Options:               MustOptions(OptionConnectTimeout, "5s"),
	}
	snapshot := cloneClientConfigForAssertion(cfg)

	policy := freezeDialPolicy(cfg)
	if !reflect.DeepEqual(cfg, snapshot) {
		t.Fatalf("freezeDialPolicy mutated caller ClientConfig:\n got=%+v\nwant=%+v", cfg, snapshot)
	}

	// Mutating caller storage afterwards must not alias frozen dialPolicy.
	cfg.KeyPaths[0] = "/tmp/mutated"
	cfg.Execution.Interpreter = InterpreterFish
	_ = cfg.Options.Set(OptionConnectTimeout, "99s")
	cfg.Password = "mutated"

	if policy.port != 22 || policy.address != "2001:db8::1" {
		t.Fatalf("unexpected normalization in dialPolicy: address=%q port=%d", policy.address, policy.port)
	}
	if !slices.Equal(policy.keyPaths, []string{"/tmp/k1", "/tmp/k2"}) {
		t.Fatalf("dialPolicy aliased caller KeyPaths: %v", policy.keyPaths)
	}
	if policy.execution == nil || policy.execution.Interpreter != InterpreterSh {
		t.Fatalf("dialPolicy aliased caller Execution: %+v", policy.execution)
	}
	if policy.options.ConnectTimeout() != 5*time.Second {
		t.Fatalf("dialPolicy aliased caller Options: got %v, want 5s", policy.options.ConnectTimeout())
	}

	ro := policy.readOnlyConfig()
	if ro.Password != "" || ro.Passphrase != "" || ro.SuPwd != "" {
		t.Fatalf("readOnlyConfig leaked secrets: pwd=%q phr=%q su=%q", ro.Password, ro.Passphrase, ro.SuPwd)
	}
	ro.KeyPaths[0] = "/tmp/ro-mutated"
	if policy.readOnlyConfig().KeyPaths[0] != "/tmp/k1" {
		t.Fatal("mutating readOnlyConfig().KeyPaths leaked back into dialPolicy")
	}

	cc := policy.toConnectionConfig()
	if cc.Port != 22 || cc.Address != "2001:db8::1" {
		t.Fatalf("unexpected ConnectionConfig fields: address=%q port=%d", cc.Address, cc.Port)
	}
	cc.KeyPaths[0] = "/tmp/cc-mutated"
	if policy.readOnlyConfig().KeyPaths[0] != "/tmp/k1" {
		t.Fatal("mutating toConnectionConfig().KeyPaths leaked back into dialPolicy")
	}
}

func TestHandshakeAttemptTransitionsAndScrub(t *testing.T) {
	cfg := &ClientConfig{
		AuthType:   "auto",
		Password:   "init-pwd",
		Passphrase: "init-phr",
		SuPwd:      "init-su",
	}
	discoveredCalls := 0
	attempt := newHandshakeAttempt(cfg, func() { discoveredCalls++ })

	if got := attempt.consumeInitialPassword(); got != "init-pwd" {
		t.Fatalf("first consumeInitialPassword = %q, want init-pwd", got)
	}
	if got := attempt.consumeInitialPassword(); got != "" {
		t.Fatalf("second consumeInitialPassword = %q, want empty", got)
	}
	if got := string(attempt.consumeInitialPassphrase()); got != "init-phr" {
		t.Fatalf("first consumeInitialPassphrase = %q, want init-phr", got)
	}
	if got := attempt.consumeInitialPassphrase(); len(got) != 0 {
		t.Fatalf("second consumeInitialPassphrase = %q, want empty", got)
	}

	// Keep backing buffers to assert scrub zeros them in place.
	initPwdBuf := []byte("buf-init-pwd")
	initPhrBuf := []byte("buf-init-phr")
	initSuBuf := []byte("buf-init-su")
	compatBuf := []byte("buf-compat")
	attempt.initialPassword = initPwdBuf
	attempt.initialPassphrase = initPhrBuf
	attempt.initialSuPwd = initSuBuf
	attempt.compatPassword = compatBuf

	// Key passphrase recorded, then rejected -> returns to baseline AuthType.
	attempt.recordPassphrase("/tmp/id_a", "pass-a")
	out := attempt.outcome()
	if !out.discovered || out.keyPath != "/tmp/id_a" || out.passphrase != "pass-a" || out.authType != "key" {
		t.Fatalf("unexpected outcome after recordPassphrase: %+v", out)
	}
	attempt.rejectCandidate(autoAuthProtocolPublicKey)
	out = attempt.outcome()
	if out.passphrase != "" || out.keyPath != "" || out.authType != "auto" {
		t.Fatalf("unexpected outcome after key rejection: %+v", out)
	}

	// MFA partial-success retention: recordPassphrase followed by recordPassword(pwd, false) retains both.
	attempt.recordPassphrase("/tmp/id_mfa", "pass-mfa")
	attempt.recordPassword("otp-or-pwd", false)
	mfaOut := attempt.outcome()
	if mfaOut.passphrase != "pass-mfa" || mfaOut.keyPath != "/tmp/id_mfa" || mfaOut.password != "otp-or-pwd" {
		t.Fatalf("MFA recordPassword(clearPassphrase=false) lost key state: %+v", mfaOut)
	}
	attempt.rejectCandidate(autoAuthProtocolPassword)
	if out := attempt.outcome(); out.password != "" || out.passphrase != "pass-mfa" {
		t.Fatalf("expected password rejection to preserve passphrase in MFA, got %+v", out)
	}

	resPwdBuf := attempt.resolvedPassword
	resPhrBuf := attempt.resolvedPassphrase
	attempt.scrub()
	assertSliceAllZero(t, "initialPassword", initPwdBuf)
	assertSliceAllZero(t, "initialPassphrase", initPhrBuf)
	assertSliceAllZero(t, "initialSuPwd", initSuBuf)
	assertSliceAllZero(t, "compatPassword", compatBuf)
	assertSliceAllZero(t, "resolvedPassword", resPwdBuf)
	assertSliceAllZero(t, "resolvedPassphrase", resPhrBuf)

	if cleared := attempt.outcome(); cleared != (authOutcome{}) {
		t.Fatalf("expected zero authOutcome after scrub, got %+v", cleared)
	}
	if discoveredCalls == 0 {
		t.Fatal("expected onDiscovered callback to fire")
	}
}

func TestConnectAndInitializeLeaveProviderConfigUnmutated(t *testing.T) {
	t.Run("key_discovery_recording_and_reconnect_with_normalized_address", assertKeyDiscoveryAndReconnectUnmutated)
	t.Run("rejected_key_fallback_to_password_and_failed_handshake", assertRejectedKeyFallbackAndFailUnmutated)
	t.Run("port_zero_normalization_and_compat_secret_resolver", assertPortZeroAndCompatResolverUnmutated)
}

func assertKeyDiscoveryAndReconnectUnmutated(t *testing.T) {
	pemData, pub := generateTestEncryptedKey(t, "enc-pass")
	addr, stop := startTestMultiAuthSSHServer(t, pub, "unused-pwd")
	defer stop()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	keyPath := filepath.Join(t.TempDir(), "id_enc")
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		t.Fatalf("write encrypted key: %v", err)
	}

	sharedCfg := &ClientConfig{
		NodeID:          "immutable-key-node",
		Address:         "[" + host + "]",
		Port:            port,
		User:            "ops",
		AuthType:        "key",
		KeyPath:         "",
		KeyPaths:        []string{keyPath},
		AuthUpdateToken: "v1",
		Password:        "stale-password",
		Options:         MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none"),
	}
	origSnapshot := cloneClientConfigForAssertion(sharedCfg)
	spy := &immutableProviderSpy{cfg: sharedCfg}
	ui := &recoveryTestUI{values: []string{"enc-pass", "enc-pass"}}

	conn := NewConnector(spy, WithInteractionHandler(ui), WithCredentialRecorder(spy), WithHandshakeTimeout(3*time.Second))
	conn.AcceptNewHostKey.Store(true)
	defer func() { _ = conn.CloseAll() }()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	client, err := conn.Connect(ctx, "immutable-key-node")
	if err != nil {
		t.Fatalf("Connect(key): %v", err)
	}
	if !reflect.DeepEqual(sharedCfg, origSnapshot) {
		t.Fatalf("Connect mutated provider ClientConfig:\n got=%+v\nwant=%+v", sharedCfg, origSnapshot)
	}
	if spy.updated != 1 || spy.lastPhr != "enc-pass" || spy.lastKey != keyPath || spy.lastPwd != "" {
		t.Fatalf("unexpected recorded outcome: %+v", spy)
	}
	if cc := client.Config(); cc.Password != "" || cc.Passphrase != "" {
		t.Fatalf("client.Config() leaked secrets: %+v", cc)
	}

	// Evict and reconnect via second Connect to confirm repeated handshakes stay immutable.
	key := DigestClientConfig(NewClientConfig(*sharedCfg), ZeroHopDigest)
	if pooled, ok := conn.pool.Get(key); ok {
		conn.pool.Evict(key, pooled, true)
	}
	if _, err := conn.Connect(ctx, "immutable-key-node"); err != nil {
		t.Fatalf("reconnect failed: %v", err)
	}
	if !reflect.DeepEqual(sharedCfg, origSnapshot) {
		t.Fatalf("reconnect mutated provider ClientConfig")
	}
}

func assertRejectedKeyFallbackAndFailUnmutated(t *testing.T) {
	_, otherPub := generateTestEncryptedKey(t, "other")
	unacceptedPEM, _ := generateTestEncryptedKey(t, "wrong-or-unaccepted")
	addr, stop := startTestMultiAuthSSHServer(t, otherPub, "good-pwd")
	defer stop()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	badKeyPath := filepath.Join(t.TempDir(), "id_unaccepted")
	if err := os.WriteFile(badKeyPath, unacceptedPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	fallbackCfg := &ClientConfig{
		NodeID:   "immutable-fallback",
		Address:  host,
		Port:     port,
		User:     "ops",
		AuthType: "auto",
		KeyPath:  badKeyPath,
		Options:  MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none", OptionIdentitiesOnly, "yes"),
	}
	origFallback := cloneClientConfigForAssertion(fallbackCfg)
	ui := &recoveryTestUI{values: []string{"wrong-or-unaccepted", "good-pwd"}}
	conn := NewConnector(&immutableProviderSpy{cfg: fallbackCfg}, WithInteractionHandler(ui), WithHandshakeTimeout(3*time.Second))
	conn.AcceptNewHostKey.Store(true)
	defer func() { _ = conn.CloseAll() }()

	client, err := conn.Connect(t.Context(), "immutable-fallback")
	if err != nil {
		t.Fatalf("Connect(fallback): %v", err)
	}
	if client.ConnectionConfig().AuthType != "password" {
		t.Fatalf("expected ConnectionConfig.AuthType=password after fallback, got %q", client.ConnectionConfig().AuthType)
	}
	if !reflect.DeepEqual(fallbackCfg, origFallback) {
		t.Fatalf("fallback Connect mutated caller ClientConfig:\n got=%+v\nwant=%+v", fallbackCfg, origFallback)
	}

	// Failed handshake path must also leave caller ClientConfig untouched.
	failCfg := &ClientConfig{
		NodeID:     "fail-node",
		Address:    host,
		Port:       port,
		User:       "ops",
		AuthType:   "password",
		Password:   "bad-pwd",
		Passphrase: "unused-phr",
		SuPwd:      "unused-su",
		Options:    MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none"),
	}
	origFail := cloneClientConfigForAssertion(failCfg)
	failConn := NewConnector(nil, WithHostKeyVerifier(staticTestVerifier{}), WithHandshakeTimeout(2*time.Second))
	defer func() { _ = failConn.CloseAll() }()
	if _, failErr := failConn.initializeConnection(t.Context(), connectionPlanNode{name: "fail-node", cfg: failCfg}, nil, nil); failErr == nil {
		t.Fatal("expected initializeConnection failure with wrong password")
	}
	if !reflect.DeepEqual(failCfg, origFail) {
		t.Fatalf("failed handshake mutated caller ClientConfig:\n got=%+v\nwant=%+v", failCfg, origFail)
	}
}

func assertPortZeroAndCompatResolverUnmutated(t *testing.T) {
	addr, stop := startTestMultiAuthSSHServer(t, nil, "compat-login-pwd")
	defer stop()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	sharedCfg := &ClientConfig{
		NodeID:   "port-zero-compat",
		Address:  host,
		Port:     0,
		User:     "ops",
		AuthType: "password",
		Password: "compat-login-pwd",
		SuPwd:    "compat-su-pwd",
		Options:  MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none"),
	}
	origSnapshot := cloneClientConfigForAssertion(sharedCfg)
	fixedDialer := handshakeTestDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		wantDefault := net.JoinHostPort(sharedCfg.Address, "22")
		if address != wantDefault {
			return nil, errors.New("unexpected dial addr: " + address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	})

	conn := NewConnector(nil, WithHostKeyVerifier(staticTestVerifier{}), WithHandshakeTimeout(3*time.Second))
	defer func() { _ = conn.CloseAll() }()

	client, err := conn.initializeConnection(t.Context(), connectionPlanNode{name: "port-zero-compat", cfg: sharedCfg}, fixedDialer, nil)
	if err != nil {
		t.Fatalf("initializeConnection(Port:0): %v", err)
	}
	if !reflect.DeepEqual(sharedCfg, origSnapshot) {
		t.Fatalf("initializeConnection(Port:0) mutated caller ClientConfig:\n got=%+v\nwant=%+v", sharedCfg, origSnapshot)
	}
	if client.ConnectionConfig().Port != 22 {
		t.Fatalf("client.ConnectionConfig().Port = %d, want 22", client.ConnectionConfig().Port)
	}
	if cc := client.Config(); cc.Password != "" || cc.SuPwd != "" {
		t.Fatalf("client.Config() leaked secrets: %+v", cc)
	}
	if client.resolver == nil {
		t.Fatal("expected fail-closed secretResolver attached on NewConnector client")
	}
	if _, err := client.resolver.ResolveSecret(t.Context(), SecretRequest{Kind: SecretKindSuPassword}); !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired from NewConnector fail-closed resolver, got %v", err)
	}

	// Direct compat client construction (newClient with nil resolver) preserves compatSecretResolver
	// while keeping client.Config() and caller sharedCfg unmutated.
	compatClient := newClient(nil, nil, sharedCfg, nil, "")
	if !reflect.DeepEqual(sharedCfg, origSnapshot) {
		t.Fatalf("newClient mutated caller ClientConfig:\n got=%+v\nwant=%+v", sharedCfg, origSnapshot)
	}
	suSecret, err := compatClient.resolver.ResolveSecret(t.Context(), SecretRequest{Kind: SecretKindSuPassword})
	if err != nil || string(suSecret) != "compat-su-pwd" {
		t.Fatalf("compatSecretResolver SuPassword = (%q, %v), want compat-su-pwd", suSecret, err)
	}
	if cc := compatClient.Config(); cc.Password != "" || cc.SuPwd != "" {
		t.Fatalf("compatClient.Config() leaked secrets: %+v", cc)
	}
}

type handshakeTestDialer func(context.Context, string, string) (net.Conn, error)

func (d handshakeTestDialer) Dial(network, address string) (net.Conn, error) {
	return d(context.Background(), network, address)
}

func (d handshakeTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d(ctx, network, address)
}

type staticTestVerifier struct{}

func (staticTestVerifier) Verify(context.Context, HostKeyRequest, cryptoSSH.PublicKey) error {
	return nil
}

func TestKeyAuthWithKeyRefRequiresKeySourceFailClosedAndConfigSnapshotClonesKeyPaths(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ambient")
	pemData, _ := generateTestEncryptedKey(t, "pass")
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	cfg := &ClientConfig{
		NodeID:   "ref-node",
		Address:  "127.0.0.1",
		Port:     22,
		User:     "ops",
		AuthType: "key",
		KeyRef:   "opaque-key-ref",
		KeyPaths: []string{keyPath},
		Options:  MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none", OptionIdentityFile, keyPath),
	}
	conn := NewConnector(nil, WithHostKeyVerifier(staticTestVerifier{}))
	defer func() { _ = conn.CloseAll() }()

	if _, _, err := conn.buildSSHConfig(t.Context(), cfg, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "explicit key source") {
		t.Fatalf("expected AuthType=key with KeyRef and nil keySource to fail closed, got %v", err)
	}

	c := &Client{connCfg: cfg.ToConnectionConfig()}
	snap := c.Config()
	if !reflect.DeepEqual(snap.KeyPaths, []string{keyPath}) {
		t.Fatalf("Client.Config().KeyPaths = %v, want [%q]", snap.KeyPaths, keyPath)
	}
	snap.KeyPaths[0] = "mutated"
	if c.Config().KeyPaths[0] != keyPath {
		t.Fatalf("mutating Config().KeyPaths mutated live connCfg: %v", c.Config().KeyPaths)
	}
}

type funcSecretPrompterForTest func(ctx context.Context, req SecretRequest) (string, error)

func (f funcSecretPrompterForTest) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	return f(ctx, req)
}

func TestKeyAuthAndMultiKeyAuth_ShareSecProviderForMFA(t *testing.T) {
	key1Path := filepath.Join(t.TempDir(), "id_unused")
	_ = writeAuthTestPrivateKey(t, key1Path)
	key2Path := filepath.Join(t.TempDir(), "id_accepted")
	acceptedSigner := writeAuthTestPrivateKey(t, key2Path)
	acceptedRaw := string(acceptedSigner.PublicKey().Marshal())

	addr, stop := startTestMultiAuthSSHServer(t, nil, "", func(sc *cryptoSSH.ServerConfig) {
		sc.PublicKeyCallback = func(conn cryptoSSH.ConnMetadata, pub cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if string(pub.Marshal()) != acceptedRaw {
				return nil, errors.New("key rejected")
			}
			return nil, &cryptoSSH.PartialSuccessError{
				Next: cryptoSSH.ServerAuthCallbacks{
					KeyboardInteractiveCallback: func(_ cryptoSSH.ConnMetadata, client cryptoSSH.KeyboardInteractiveChallenge) (*cryptoSSH.Permissions, error) {
						answers, err := client("", "", []string{"OTP:"}, []bool{true})
						if err != nil {
							return nil, err
						}
						if len(answers) != 1 || answers[0] != "654321" {
							return nil, errors.New("bad OTP")
						}
						return &cryptoSSH.Permissions{}, nil
					},
				},
			}
		}
	})
	defer stop()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	baseOpts := MustOptions(OptionStrictHostKeyChecking, "no", OptionUserKnownHostsFile, "none")

	t.Run("single-key-mfa-propagates-terminal-error", func(t *testing.T) {
		wantErr := errors.New("single-key mfa prompter aborted")
		spy := &immutableProviderSpy{cfg: &ClientConfig{
			NodeID:   "single-key-mfa",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyPath:  key2Path,
			Options:  baseOpts.Clone(),
		}}
		conn := NewConnector(
			spy,
			WithHostKeyVerifier(staticTestVerifier{}),
			WithSecretPrompter(funcSecretPrompterForTest(func(_ context.Context, req SecretRequest) (string, error) {
				if req.Kind != SecretKindPrivateKeyPassphrase {
					return "", wantErr
				}
				return "", nil
			})),
			WithHandshakeTimeout(3*time.Second),
		)
		defer func() { _ = conn.CloseAll() }()

		_, err := conn.Connect(t.Context(), "single-key-mfa")
		if !errors.Is(err, wantErr) {
			t.Fatalf("Connect error = %v, want errors.Is(_, %v)", err, wantErr)
		}
	})

	t.Run("multi-key-mfa-succeeds-without-recorder-and-propagates-terminal-error", func(t *testing.T) {
		okSpy := &immutableProviderSpy{cfg: &ClientConfig{
			NodeID:   "multi-key-mfa-ok",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyPaths: []string{key1Path, key2Path},
			Options:  baseOpts.Clone(),
		}}
		okConn := NewConnector(
			okSpy,
			WithHostKeyVerifier(staticTestVerifier{}),
			WithSecretPrompter(funcSecretPrompterForTest(func(_ context.Context, req SecretRequest) (string, error) {
				if req.Kind != SecretKindPrivateKeyPassphrase {
					return "654321", nil
				}
				return "", ErrInteractionRequired
			})),
			WithHandshakeTimeout(3*time.Second),
		)
		defer func() { _ = okConn.CloseAll() }()

		cli, err := okConn.Connect(t.Context(), "multi-key-mfa-ok")
		if err != nil || cli == nil {
			t.Fatalf("multi-key MFA Connect failed: cli=%v err=%v", cli, err)
		}

		wantErr := errors.New("multi-key mfa prompter aborted")
		errSpy := &immutableProviderSpy{cfg: &ClientConfig{
			NodeID:   "multi-key-mfa-err",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyPaths: []string{key1Path, key2Path},
			Options:  baseOpts.Clone(),
		}}
		errConn := NewConnector(
			errSpy,
			WithHostKeyVerifier(staticTestVerifier{}),
			WithSecretPrompter(funcSecretPrompterForTest(func(_ context.Context, req SecretRequest) (string, error) {
				if req.Kind != SecretKindPrivateKeyPassphrase {
					return "", wantErr
				}
				return "", ErrInteractionRequired
			})),
			WithHandshakeTimeout(3*time.Second),
		)
		defer func() { _ = errConn.CloseAll() }()

		_, err = errConn.Connect(t.Context(), "multi-key-mfa-err")
		if !errors.Is(err, wantErr) {
			t.Fatalf("multi-key MFA Connect error = %v, want errors.Is(_, %v)", err, wantErr)
		}
	})
}

func TestKeyAuthWithKeySource_MultiKeyFallbackAndNodeIDKeyed(t *testing.T) {
	wrongPath := filepath.Join(t.TempDir(), "id_wrong")
	wrongSigner := writeAuthTestPrivateKey(t, wrongPath)
	goodPath := filepath.Join(t.TempDir(), "id_good")
	goodSigner := writeAuthTestPrivateKey(t, goodPath)

	var wrongAuthCount, goodAuthCount int
	var mu sync.Mutex
	addr, stop := startTestMultiAuthSSHServer(t, nil, "", func(sc *cryptoSSH.ServerConfig) {
		sc.PublicKeyCallback = func(conn cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			mu.Lock()
			defer mu.Unlock()
			if conn.User() != "ops" {
				return nil, errors.New("unexpected user")
			}
			if string(key.Marshal()) == string(wrongSigner.PublicKey().Marshal()) {
				wrongAuthCount++
				return nil, errors.New("wrong key rejected")
			}
			if string(key.Marshal()) == string(goodSigner.PublicKey().Marshal()) {
				goodAuthCount++
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("unknown key")
		}
	})
	defer stop()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	baseOpts := MustOptions(
		OptionStrictHostKeyChecking, "no",
		OptionUserKnownHostsFile, "none",
		OptionIdentitiesOnly, "yes",
	)

	t.Run("sourced-key-rejected-falls-back-to-remaining-KeyPaths-and-deduplicates", func(t *testing.T) {
		mu.Lock()
		wrongAuthCount, goodAuthCount = 0, 0
		mu.Unlock()

		lease := &fixtureKeyLease{signer: wrongSigner}
		ks := &fixtureKeySource{lease: lease}
		cfg := &ClientConfig{
			NodeID:   "multi-key-sourced",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			KeyRef:   "opaque-wrong-key",
			KeyPath:  wrongPath,
			KeyPaths: []string{wrongPath, goodPath},
			Options:  baseOpts.Clone(),
		}
		conn := NewConnector(&mockConfigStore{cfg: cfg}, WithKeySource(ks), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, conn)

		cli, err := conn.Connect(t.Context(), "multi-key-sourced")
		if err != nil || cli == nil {
			t.Fatalf("expected fallback to second key in KeyPaths, got cli=%v err=%v", cli, err)
		}
		mu.Lock()
		wCount, gCount := wrongAuthCount, goodAuthCount
		mu.Unlock()
		if wCount != 1 || gCount != 1 {
			t.Fatalf("unexpected publickey offer counts: wrong=%d (want 1 deduplicated), good=%d (want 1)", wCount, gCount)
		}
		if lease.closed.Load() != 1 {
			t.Fatalf("sourced lease closed %d times, want 1", lease.closed.Load())
		}
	})

	t.Run("NodeID-keyed-KeySource-works-with-empty-KeyRef-and-KeyPath", func(t *testing.T) {
		lease := &fixtureKeyLease{signer: goodSigner}
		ks := &fixtureKeySource{lease: lease}
		cfg := &ClientConfig{
			NodeID:   "nodeid-keyed",
			Address:  host,
			Port:     port,
			User:     "ops",
			AuthType: "key",
			Options:  baseOpts.Clone(),
		}
		conn := NewConnector(&mockConfigStore{cfg: cfg}, WithKeySource(ks), WithHostKeyVerifier(staticTestVerifier{}))
		defer closePlanConnector(t, conn)

		cli, err := conn.Connect(t.Context(), "nodeid-keyed")
		if err != nil || cli == nil {
			t.Fatalf("NodeID-keyed KeySource Connect failed: cli=%v err=%v", cli, err)
		}
		if ks.request.NodeID != "nodeid-keyed" {
			t.Fatalf("KeyRequest.NodeID = %q, want %q", ks.request.NodeID, "nodeid-keyed")
		}
		if lease.closed.Load() != 1 {
			t.Fatalf("NodeID-keyed lease closed %d times, want 1", lease.closed.Load())
		}
	})
}
