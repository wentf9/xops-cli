package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/testleak"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

func TestPhase3_OptionSpecsMergingSerializationAndPlanKeys(t *testing.T) {
	assertPhase3NilOptionAccessors(t)
	assertPhase3RegistrySpecs(t)
	assertPhase3OptionValidationErrors(t)
	assertPhase3MergingAndSerialization(t)
	assertPhase3PlanKeyIsolation(t)
}

func assertPhase3NilOptionAccessors(t *testing.T) {
	t.Helper()
	var nilOpts *Options
	if nilOpts.CertificateFiles() != nil {
		t.Fatal("expected nil CertificateFiles() on nil *Options")
	}
	if nilOpts.IdentityAgent() != "" || nilOpts.ForwardAgent() != "" {
		t.Fatal("expected empty IdentityAgent/ForwardAgent on nil *Options")
	}
}

func assertPhase3RegistrySpecs(t *testing.T) {
	t.Helper()
	checks := []struct {
		key         string
		openSSHName string
		class       OptionClass
		multi       bool
	}{
		{OptionCertificateFile, "CertificateFile", OptionClassAuth, true},
		{OptionIdentityAgent, "IdentityAgent", OptionClassAuth, false},
		{OptionForwardAgent, "ForwardAgent", OptionClassForward, false},
	}
	for _, tc := range checks {
		spec, ok := LookupOptionSpec(tc.openSSHName)
		if !ok || spec.CanonicalKey != tc.key || spec.OpenSSHName != tc.openSSHName || spec.Class != tc.class || spec.MultiValue != tc.multi {
			t.Fatalf("unexpected spec for %s: ok=%v spec=%+v", tc.openSSHName, ok, spec)
		}
	}
}

func assertPhase3OptionValidationErrors(t *testing.T) {
	t.Helper()
	for _, key := range []string{OptionCertificateFile, OptionIdentityAgent, OptionForwardAgent} {
		spec, ok := LookupOptionSpec(key)
		if !ok {
			t.Fatalf("missing spec for %q", key)
		}
		if _, err := spec.Normalize(""); err == nil {
			t.Fatalf("expected Normalize(\"\") error for %q", key)
		}
	}

	opts := &Options{}
	invalid := [][2]string{
		{OptionCertificateFile, "   "},
		{OptionCertificateFile, "a.pub\n\x07b.pub"},
		{OptionCertificateFile, "/bad/%z/cert.pub"},
		{OptionIdentityAgent, "   "},
		{OptionIdentityAgent, "$123BAD"},
		{OptionIdentityAgent, "/bad\x00sock"},
		{OptionForwardAgent, "   "},
		{OptionForwardAgent, "/bad/%z/agent.sock"},
	}
	for _, pair := range invalid {
		if err := opts.Set(pair[0], pair[1]); err == nil {
			t.Fatalf("expected error for Set(%q, %q)", pair[0], pair[1])
		}
	}
	var badJSON Options
	if err := json.Unmarshal([]byte(`{"certificate_file":["a.pub","   "]}`), &badJSON); err == nil {
		t.Fatal("expected JSON empty list element rejection for certificate_file")
	}
}

func assertPhase3MergingAndSerialization(t *testing.T) {
	t.Helper()
	high := &Options{}
	if err := high.Set("CertificateFile", "~/.ssh/id_ed25519-cert.pub"); err != nil {
		t.Fatal(err)
	}
	if err := high.Set("IdentityAgent", "$CUSTOM_AGENT"); err != nil {
		t.Fatal(err)
	}
	if err := high.Set("ForwardAgent", "YES"); err != nil {
		t.Fatal(err)
	}

	low := &Options{}
	if err := low.Set("CertificateFile", "~/.ssh/id_rsa-cert.pub"); err != nil {
		t.Fatal(err)
	}
	if err := low.Set("IdentityAgent", "none"); err != nil {
		t.Fatal(err)
	}
	if err := low.Set("ForwardAgent", "no"); err != nil {
		t.Fatal(err)
	}

	merged := MergeOptionLayers(high, low)
	if !slices.Equal(merged.CertificateFiles(), []string{"~/.ssh/id_ed25519-cert.pub", "~/.ssh/id_rsa-cert.pub"}) {
		t.Fatalf("merged CertificateFiles = %v", merged.CertificateFiles())
	}
	if merged.IdentityAgent() != "$CUSTOM_AGENT" {
		t.Fatalf("merged IdentityAgent = %q, want $CUSTOM_AGENT", merged.IdentityAgent())
	}
	if merged.ForwardAgent() != "yes" {
		t.Fatalf("merged ForwardAgent = %q, want yes", merged.ForwardAgent())
	}

	yamlBytes, err := yaml.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	var fromYAML Options
	if err := yaml.Unmarshal(yamlBytes, &fromYAML); err != nil {
		t.Fatal(err)
	}
	jsonBytes, err := json.Marshal(&fromYAML)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Options
	if err := json.Unmarshal(jsonBytes, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fromJSON.CertificateFiles(), merged.CertificateFiles()) ||
		fromJSON.IdentityAgent() != merged.IdentityAgent() ||
		fromJSON.ForwardAgent() != merged.ForwardAgent() {
		t.Fatalf("round-trip mismatch: got %+v", fromJSON)
	}
}

func assertPhase3PlanKeyIsolation(t *testing.T) {
	t.Helper()
	makePlan := func(mutate func(*Options)) ConnectionPlan {
		opts := &Options{}
		mutate(opts)
		return ConnectionPlan{
			Scope: "p3-scope",
			Hops: []ConnectionConfig{{
				NodeID:  "n1",
				Address: "127.0.0.1",
				Port:    22,
				User:    "alice",
				Options: opts,
			}},
		}
	}

	baseKey, err := ConnectionKey(makePlan(func(*Options) {}))
	if err != nil {
		t.Fatal(err)
	}
	fwdYesKey, err := ConnectionKey(makePlan(func(o *Options) { _ = o.Set(OptionForwardAgent, "yes") }))
	if err != nil {
		t.Fatal(err)
	}
	if fwdYesKey != baseKey {
		t.Fatal("ForwardAgent (OptionClassForward) must be stripped from ConnectionPlan and not alter ConnectionKey")
	}

	certKey, err := ConnectionKey(makePlan(func(o *Options) { _ = o.Set(OptionCertificateFile, "/certs/a-cert.pub") }))
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := ConnectionKey(makePlan(func(o *Options) { _ = o.Set(OptionIdentityAgent, "none") }))
	if err != nil {
		t.Fatal(err)
	}
	if certKey == baseKey || agentKey == baseKey || certKey == agentKey {
		t.Fatal("CertificateFile and IdentityAgent (OptionClassAuth) must be reflected in ConnectionKey")
	}
}

type phase3CertFixture struct {
	caSigner   cryptoSSH.Signer
	hostSigner cryptoSSH.Signer
}

func newPhase3CertFixture(t *testing.T) phase3CertFixture {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := cryptoSSH.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptoSSH.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	return phase3CertFixture{caSigner: caSigner, hostSigner: hostSigner}
}

func signTestCertificate(
	t *testing.T,
	ca cryptoSSH.Signer,
	pub cryptoSSH.PublicKey,
	principal string,
	certType uint32,
	serial uint64,
) *cryptoSSH.Certificate {
	t.Helper()
	now := uint64(time.Now().Unix())
	cert := &cryptoSSH.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        certType,
		KeyId:           fmt.Sprintf("test-cert-%d", serial),
		ValidPrincipals: []string{principal},
		ValidAfter:      now - 60,
		ValidBefore:     now + 3600,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeEd25519KeyFile(t *testing.T, path string, passphrase string) (ed25519.PrivateKey, cryptoSSH.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = cryptoSSH.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = cryptoSSH.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, sshPub
}

func writeRSAKeyFile(t *testing.T, path string, passphrase string) (*rsa.PrivateKey, cryptoSSH.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = cryptoSSH.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	} else {
		block, err = cryptoSSH.MarshalPrivateKey(priv, "")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := cryptoSSH.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, sshPub
}

func startPhase3CertSSHServer(
	t *testing.T,
	hostSigner cryptoSSH.Signer,
	trustedCA cryptoSSH.PublicKey,
	trustedPlain cryptoSSH.PublicKey,
	pubKeyAuthAlgos []string,
) (int, *atomic.Int32) {
	t.Helper()
	var certLogins atomic.Int32
	checker := &cryptoSSH.CertChecker{
		IsUserAuthority: func(auth cryptoSSH.PublicKey) bool {
			return trustedCA != nil && bytes.Equal(auth.Marshal(), trustedCA.Marshal())
		},
		UserKeyFallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if trustedPlain != nil && bytes.Equal(key.Marshal(), trustedPlain.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("unknown public key")
		},
	}

	serverCfg := &cryptoSSH.ServerConfig{
		PublicKeyAuthAlgorithms: pubKeyAuthAlgos,
		PublicKeyCallback: func(conn cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			perms, err := checker.Authenticate(conn, key)
			if err == nil {
				if _, isCert := key.(*cryptoSSH.Certificate); isCert {
					certLogins.Add(1)
				}
			}
			return perms, err
		},
	}
	serverCfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	wg.Go(func() {
		for {
			rawConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Go(func() {
				serveSimplePhase3ExecConn(rawConn, serverCfg)
			})
		}
	})
	return ln.Addr().(*net.TCPAddr).Port, &certLogins
}

func serveSimplePhase3ExecConn(rawConn net.Conn, serverCfg *cryptoSSH.ServerConfig) {
	defer func() { _ = rawConn.Close() }()
	sConn, chans, reqs, err := cryptoSSH.NewServerConn(rawConn, serverCfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	go cryptoSSH.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, acceptErr := newCh.Accept()
		if acceptErr != nil {
			continue
		}
		go func(c cryptoSSH.Channel, r <-chan *cryptoSSH.Request) {
			defer func() { _ = c.Close() }()
			for req := range r {
				switch req.Type {
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					_, _ = io.WriteString(c, "ok\n")
					_, _ = c.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				}
			}
		}(ch, chReqs)
	}
}

func newPhase3TrustAllOptions(t *testing.T, dir string) *Options {
	t.Helper()
	opts := &Options{}
	if err := opts.Set(OptionStrictHostKeyChecking, StrictHostKeyCheckingNo); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(OptionUserKnownHostsFile, filepath.Join(dir, "known_hosts")); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(OptionPasswordAuthentication, "no"); err != nil {
		t.Fatal(err)
	}
	if err := opts.Set(OptionKbdInteractiveAuthentication, "no"); err != nil {
		t.Fatal(err)
	}
	return opts
}

func TestPhase3_UserCertificatesEd25519RSASHA2AndKeySource(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()

	// 1. Ed25519 sidecar auto-discovery (<key>-cert.pub).
	edKeyPath := filepath.Join(dir, "id_ed25519")
	_, edPub := writeEd25519KeyFile(t, edKeyPath, "")
	edCert := signTestCertificate(t, fix.caSigner, edPub, "alice", cryptoSSH.UserCert, 101)
	if err := os.WriteFile(edKeyPath+"-cert.pub", cryptoSSH.MarshalAuthorizedKey(edCert), 0o600); err != nil {
		t.Fatal(err)
	}

	portEd, certLoginsEd := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)
	env := fixtureEnvironment()
	env.HomeDir = dir
	env.LookupEnv = func(k string) (string, bool) {
		if k == "CERT_SUBDIR" {
			return "certs", true
		}
		return "", false
	}

	optsEd := newPhase3TrustAllOptions(t, dir)
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"ed-sidecar": {
			NodeID:   "ed-sidecar",
			Address:  "127.0.0.1",
			Port:     portEd,
			User:     "alice",
			AuthType: "auto",
			KeyPath:  edKeyPath,
			Options:  optsEd,
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cli, err := conn.Connect(t.Context(), "ed-sidecar")
	if err != nil {
		t.Fatalf("sidecar user cert connect failed: %v", err)
	}
	out, err := cli.Run(t.Context(), "echo ok")
	if err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("Run output = %q, err = %v", out, err)
	}
	if certLoginsEd.Load() != 1 {
		t.Fatalf("certLogins = %d, want 1", certLoginsEd.Load())
	}

	// 2. RSA SHA-2 (rsa-sha2-512-cert-v01@openssh.com / rsa-sha2-256-cert-v01@openssh.com)
	// with explicit CertificateFile token expansion + skipping malformed and HostCert entries!
	certSubdir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certSubdir, 0o700); err != nil {
		t.Fatal(err)
	}
	rsaKeyPath := filepath.Join(dir, "id_rsa")
	rsaPriv, rsaPub := writeRSAKeyFile(t, rsaKeyPath, "")

	badCertPath := filepath.Join(certSubdir, "corrupt-cert.pub")
	if err := os.WriteFile(badCertPath, []byte("not-a-valid-openssh-cert\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostCert := signTestCertificate(t, fix.caSigner, rsaPub, "alice", cryptoSSH.HostCert, 102)
	hostCertPath := filepath.Join(certSubdir, "host-cert.pub")
	if err := os.WriteFile(hostCertPath, cryptoSSH.MarshalAuthorizedKey(hostCert), 0o600); err != nil {
		t.Fatal(err)
	}
	rsaUserCert := signTestCertificate(t, fix.caSigner, rsaPub, "alice", cryptoSSH.UserCert, 103)
	rsaCertPath := filepath.Join(certSubdir, "alice-rsa-cert.pub")
	if err := os.WriteFile(rsaCertPath, cryptoSSH.MarshalAuthorizedKey(rsaUserCert), 0o600); err != nil {
		t.Fatal(err)
	}

	portRSA, certLoginsRSA := startPhase3CertSSHServer(
		t,
		fix.hostSigner,
		fix.caSigner.PublicKey(),
		nil,
		[]string{cryptoSSH.KeyAlgoRSASHA512, cryptoSSH.KeyAlgoRSASHA256},
	)
	dbg := &testDebugLogger{}
	optsRSA := newPhase3TrustAllOptions(t, dir)
	if err := optsRSA.Set(OptionCertificateFile, strings.Join([]string{
		"~/${CERT_SUBDIR}/corrupt-cert.pub",
		"~/${CERT_SUBDIR}/host-cert.pub",
		"~/${CERT_SUBDIR}/%r-rsa-cert.pub",
	}, "\n")); err != nil {
		t.Fatal(err)
	}

	rsaSigner, err := cryptoSSH.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatal(err)
	}
	ks := &fixedPhase3KeySource{signer: rsaSigner}
	providerRSA := &mapConfigProvider{configs: map[string]*ClientConfig{
		"rsa-cert": {
			NodeID:   "rsa-cert",
			Address:  "127.0.0.1",
			Port:     portRSA,
			User:     "alice",
			AuthType: "key",
			KeyRef:   "managed-rsa",
			KeyPath:  rsaKeyPath,
			Options:  optsRSA,
		},
	}}
	connRSA := NewConnector(providerRSA, WithEnvironment(env), WithKeySource(ks), WithLogger(dbg))
	t.Cleanup(func() { _ = connRSA.CloseAll() })

	if _, err := connRSA.Connect(t.Context(), "rsa-cert"); err != nil {
		t.Fatalf("RSA SHA-2 user certificate connect failed: %v", err)
	}
	if certLoginsRSA.Load() != 1 {
		t.Fatalf("RSA certLogins = %d, want 1", certLoginsRSA.Load())
	}
	logs := strings.Join(dbg.snapshot(), "\n")
	if !strings.Contains(logs, "corrupt-cert.pub") || !strings.Contains(logs, "HostCert") && !strings.Contains(logs, "CertType=2") {
		t.Fatalf("expected diagnostic logs for corrupt and HostCert files, got:\n%s", logs)
	}
}

type fixedPhase3KeySource struct {
	signer cryptoSSH.Signer
}

func (s *fixedPhase3KeySource) OpenKey(context.Context, KeyRequest) (KeyLease, error) {
	return fixedPhase3KeyLease{signer: s.signer}, nil
}

type fixedPhase3KeyLease struct {
	signer cryptoSSH.Signer
}

func (l fixedPhase3KeyLease) Signer() cryptoSSH.Signer { return l.signer }
func (l fixedPhase3KeyLease) Close() error             { return nil }

type mapConfigProvider struct {
	configs map[string]*ClientConfig
}

func (p *mapConfigProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	cfg, ok := p.configs[nodeID]
	if !ok {
		return nil, fmt.Errorf("missing config %q", nodeID)
	}
	cloned := *cfg
	cloned.KeyPaths = slices.Clone(cfg.KeyPaths)
	cloned.Options = cfg.Options.Clone()
	return &cloned, nil
}

type countingPassphrasePrompter struct {
	passphrase string
	calls      atomic.Int32
}

func (p *countingPassphrasePrompter) PromptSecret(_ context.Context, req SecretRequest) (string, error) {
	if req.Kind != SecretKindPrivateKeyPassphrase {
		return "", ErrInteractionRequired
	}
	p.calls.Add(1)
	return p.passphrase, nil
}

func TestPhase3_CertLazySignerZeroRedundantPassphrasePrompts(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	const secretPassphrase = "correct-horse-battery-staple-p3-secret"

	encKeyPath := filepath.Join(dir, "id_enc_rsa")
	_, rsaPub := writeRSAKeyFile(t, encKeyPath, secretPassphrase)
	userCert := signTestCertificate(t, fix.caSigner, rsaPub, "alice", cryptoSSH.UserCert, 201)
	if err := os.WriteFile(encKeyPath+"-cert.pub", cryptoSSH.MarshalAuthorizedKey(userCert), 0o600); err != nil {
		t.Fatal(err)
	}

	_, untrustedCAPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	untrustedCA, err := cryptoSSH.NewSignerFromKey(untrustedCAPriv)
	if err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir

	// Case 1: Server rejects BOTH cert and plain key -> 0 passphrase prompts!
	t.Run("rejected cert and plain key prompts 0 times", func(t *testing.T) {
		port, _ := startPhase3CertSSHServer(t, fix.hostSigner, untrustedCA.PublicKey(), nil, nil)
		prompter := &countingPassphrasePrompter{passphrase: secretPassphrase}
		bufLog := testleak.NewBufferLogger()
		opts := newPhase3TrustAllOptions(t, dir)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", KeyPath: encKeyPath, Options: opts},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithSecretPrompter(prompter), WithLogger(bufLog))
		defer func() { _ = conn.CloseAll() }()

		_, connectErr := conn.Connect(t.Context(), "n")
		if connectErr == nil {
			t.Fatal("expected authentication failure when neither CA nor plain key is trusted")
		}
		if got := prompter.calls.Load(); got != 0 {
			t.Fatalf("passphrase prompt count = %d, want 0", got)
		}
		testleak.AssertNoSecretInError(t, connectErr, secretPassphrase)
		testleak.AssertNoSecretInLogs(t, bufLog, secretPassphrase)
	})

	// Case 2: Server trusts CA -> 1 passphrase prompt!
	t.Run("accepted cert prompts exactly once", func(t *testing.T) {
		port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, []string{cryptoSSH.KeyAlgoRSASHA256})
		prompter := &countingPassphrasePrompter{passphrase: secretPassphrase}
		bufLog := testleak.NewBufferLogger()
		opts := newPhase3TrustAllOptions(t, dir)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", KeyPath: encKeyPath, Options: opts},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithSecretPrompter(prompter), WithLogger(bufLog))
		defer func() { _ = conn.CloseAll() }()

		if _, connectErr := conn.Connect(t.Context(), "n"); connectErr != nil {
			t.Fatalf("expected user cert login to succeed: %v", connectErr)
		}
		if got := prompter.calls.Load(); got != 1 {
			t.Fatalf("passphrase prompt count = %d, want 1", got)
		}
		if certLogins.Load() != 1 {
			t.Fatalf("certLogins = %d, want 1", certLogins.Load())
		}
		testleak.AssertNoSecretInLogs(t, bufLog, secretPassphrase)
	})

	// Case 3: Server rejects cert (CA untrusted) and accepts plain key -> 1 passphrase prompt!
	t.Run("rejected cert then accepted plain key prompts once", func(t *testing.T) {
		port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, untrustedCA.PublicKey(), rsaPub, nil)
		prompter := &countingPassphrasePrompter{passphrase: secretPassphrase}
		bufLog := testleak.NewBufferLogger()
		opts := newPhase3TrustAllOptions(t, dir)
		provider := &mapConfigProvider{configs: map[string]*ClientConfig{
			"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", KeyPath: encKeyPath, Options: opts},
		}}
		conn := NewConnector(provider, WithEnvironment(env), WithSecretPrompter(prompter), WithLogger(bufLog))
		defer func() { _ = conn.CloseAll() }()

		if _, connectErr := conn.Connect(t.Context(), "n"); connectErr != nil {
			t.Fatalf("expected plain key fallback to succeed: %v", connectErr)
		}
		if got := prompter.calls.Load(); got != 1 {
			t.Fatalf("passphrase prompt count = %d, want 1", got)
		}
		if certLogins.Load() != 0 {
			t.Fatalf("certLogins = %d, want 0", certLogins.Load())
		}
		testleak.AssertNoSecretInLogs(t, bufLog, secretPassphrase)
	})
}

func startInMemoryAgentListener(t *testing.T, keys ...any) (string, *atomic.Int32) {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	sockPath := filepath.Join(t.TempDir(), "ag.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		shortSock := filepath.Join("/tmp", fmt.Sprintf("xops-p3-ag-%d.sock", time.Now().UnixNano()))
		ln, err = net.Listen("unix", shortSock)
		if err != nil {
			t.Skipf("cannot listen unix socket: %v", err)
		}
		sockPath = shortSock
		t.Cleanup(func() { _ = os.Remove(shortSock) })
	}
	var activeConns atomic.Int32
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			activeConns.Add(1)
			wg.Go(func() {
				defer activeConns.Add(-1)
				defer func() { _ = c.Close() }()
				_ = agent.ServeAgent(keyring, c)
			})
		}
	})
	return sockPath, &activeConns
}

func TestPhase3_ResolveIdentityAgentAndAgentCertPairing(t *testing.T) {
	assertPhase3ResolveIdentityAgentCases(t)
	assertPhase3AgentCertPairingAndFailClosed(t)
	assertPhase3IdentitiesOnlyDefaultKeyWithCertFile(t)
}

func assertPhase3ResolveIdentityAgentCases(t *testing.T) {
	t.Helper()
	env := fixtureEnvironment()
	env.HomeDir = "/home/tester"
	env.AgentSocket = "/env/default.sock"
	env.LookupEnv = func(k string) (string, bool) {
		if k == "MY_AGENT_SOCK" {
			return "/from/env/agent.sock", true
		}
		return "", false
	}
	target := TargetContext{Host: "db.internal", Port: 2222, User: "alice", OriginalHost: "db"}

	cases := []struct {
		spec         string
		wantSock     string
		wantSuffix   string
		wantDisabled bool
	}{
		{spec: "none", wantDisabled: true},
		{spec: "", wantSock: "/env/default.sock"},
		{spec: "SSH_AUTH_SOCK", wantSock: "/env/default.sock"},
		{spec: "$MY_AGENT_SOCK", wantSock: "/from/env/agent.sock"},
		{spec: "${MY_AGENT_SOCK}", wantSock: "/from/env/agent.sock"},
		{spec: "~/ag-%r@%h-%p.sock", wantSuffix: "ag-alice@db.internal-2222.sock"},
		{spec: `\\.\pipe\openssh-ssh-agent`, wantSock: `\\.\pipe\openssh-ssh-agent`},
	}
	for _, tc := range cases {
		sock, disabled, err := ResolveIdentityAgent(tc.spec, env, target)
		if err != nil || disabled != tc.wantDisabled {
			t.Fatalf("ResolveIdentityAgent(%q) = (%q, %v, %v)", tc.spec, sock, disabled, err)
		}
		if tc.wantSuffix != "" && !strings.HasSuffix(sock, tc.wantSuffix) {
			t.Fatalf("ResolveIdentityAgent(%q) = %q, want suffix %q", tc.spec, sock, tc.wantSuffix)
		}
		if tc.wantSuffix == "" && sock != tc.wantSock {
			t.Fatalf("ResolveIdentityAgent(%q) = %q, want %q", tc.spec, sock, tc.wantSock)
		}
	}
	if _, _, err := ResolveIdentityAgent("$UNSET_AGENT", env, target); err == nil {
		t.Fatal("expected unset $UNSET_AGENT to fail")
	}
}

func assertPhase3AgentCertPairingAndFailClosed(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}

	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	_, unrelatedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPubRaw, certPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPub, err := cryptoSSH.NewPublicKey(certPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	userCert := signTestCertificate(t, fix.caSigner, certPub, "alice", cryptoSSH.UserCert, 301)
	certFile := filepath.Join(dir, "agent-only-cert.pub")
	if err := os.WriteFile(certFile, cryptoSSH.MarshalAuthorizedKey(userCert), 0o600); err != nil {
		t.Fatal(err)
	}

	agentSock, _ := startInMemoryAgentListener(t, unrelatedPriv, certPriv)
	port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)

	// 1. IdentityAgent=none blocks agent completely even when AgentSocket is populated.
	agentEnv := fixtureEnvironment()
	agentEnv.HomeDir = dir
	agentEnv.AgentSocket = agentSock

	optsNone := newPhase3TrustAllOptions(t, dir)
	_ = optsNone.Set(OptionIdentityAgent, "none")
	_ = optsNone.Set(OptionCertificateFile, certFile)
	connNone := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", Options: optsNone},
	}}, WithEnvironment(agentEnv))
	t.Cleanup(func() { _ = connNone.CloseAll() })
	if _, err := connNone.Connect(t.Context(), "n"); err == nil {
		t.Fatal("expected IdentityAgent=none to disable agent auth")
	}

	// 2. IdentitiesOnly=yes + CertificateFile (without IdentityFile) pairs ONLY the matching agent key!
	optsIDOnly := newPhase3TrustAllOptions(t, dir)
	_ = optsIDOnly.Set(OptionIdentitiesOnly, "yes")
	_ = optsIDOnly.Set(OptionIdentityAgent, agentSock)
	_ = optsIDOnly.Set(OptionCertificateFile, certFile)
	connPair := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", Options: optsIDOnly},
	}}, WithEnvironment(agentEnv))
	t.Cleanup(func() { _ = connPair.CloseAll() })
	if _, err := connPair.Connect(t.Context(), "n"); err != nil {
		t.Fatalf("expected agent + CertificateFile under IdentitiesOnly=yes to succeed: %v", err)
	}
	if certLogins.Load() != 1 {
		t.Fatalf("certLogins = %d, want 1", certLogins.Load())
	}

	// 3. Nil DialAgent fails closed cleanly.
	noDialEnv := Environment{HomeDir: dir, AgentSocket: agentSock}
	connNoDial := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "agent", Options: newPhase3TrustAllOptions(t, dir)},
	}}, WithEnvironment(noDialEnv))
	t.Cleanup(func() { _ = connNoDial.CloseAll() })
	if _, err := connNoDial.Connect(t.Context(), "n"); err == nil {
		t.Fatal("expected nil DialAgent to fail closed")
	}
}

func assertPhase3IdentitiesOnlyDefaultKeyWithCertFile(t *testing.T) {
	t.Helper()
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	defaultKeyPath := filepath.Join(sshDir, "id_ed25519")
	_, defaultPub := writeEd25519KeyFile(t, defaultKeyPath, "")
	userCert := signTestCertificate(t, fix.caSigner, defaultPub, "alice", cryptoSSH.UserCert, 302)
	explicitCertPath := filepath.Join(dir, "explicit-default-key-cert.pub")
	if err := os.WriteFile(explicitCertPath, cryptoSSH.MarshalAuthorizedKey(userCert), 0o600); err != nil {
		t.Fatal(err)
	}

	port, certLogins := startPhase3CertSSHServer(t, fix.hostSigner, fix.caSigner.PublicKey(), nil, nil)

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.DefaultKeyPaths = []string{defaultKeyPath}

	opts := newPhase3TrustAllOptions(t, dir)
	_ = opts.Set(OptionIdentitiesOnly, "yes")
	_ = opts.Set(OptionIdentityAgent, "none")
	_ = opts.Set(OptionCertificateFile, explicitCertPath)

	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"n": {NodeID: "n", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "auto", Options: opts},
	}}, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	if _, err := conn.Connect(t.Context(), "n"); err != nil {
		t.Fatalf("expected IdentitiesOnly=yes + CertificateFile without IdentityFile to pair default on-disk key: %v", err)
	}
	if certLogins.Load() != 1 {
		t.Fatalf("certLogins = %d, want 1", certLogins.Load())
	}
}

type phase3AgentServerState struct {
	hostSigner     cryptoSSH.Signer
	clientPub      cryptoSSH.PublicKey
	rejectAgentReq atomic.Bool
	agentReqCount  atomic.Int32
	probeExecSeen  atomic.Int32
	mu             sync.Mutex
	lastServerConn cryptoSSH.Conn
}

func (s *phase3AgentServerState) getLastConn() cryptoSSH.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastServerConn
}

func startPhase3ForwardAgentServer(t *testing.T, state *phase3AgentServerState) int {
	t.Helper()
	serverCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if bytes.Equal(key.Marshal(), state.clientPub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("unauthorized")
		},
	}
	serverCfg.AddHostKey(state.hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Go(func() {
				servePhase3ForwardAgentConn(raw, serverCfg, state)
			})
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func servePhase3ForwardAgentConn(raw net.Conn, serverCfg *cryptoSSH.ServerConfig, state *phase3AgentServerState) {
	defer func() { _ = raw.Close() }()
	sConn, chans, reqs, err := cryptoSSH.NewServerConn(raw, serverCfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()
	state.mu.Lock()
	state.lastServerConn = sConn
	state.mu.Unlock()
	go cryptoSSH.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
			continue
		}
		ch, chReqs, acceptErr := newCh.Accept()
		if acceptErr != nil {
			continue
		}
		go handlePhase3AgentSession(sConn, ch, chReqs, state)
	}
}

func handlePhase3AgentSession(sConn cryptoSSH.Conn, ch cryptoSSH.Channel, chReqs <-chan *cryptoSSH.Request, state *phase3AgentServerState) {
	defer func() { _ = ch.Close() }()
	agentRequested := false
	for req := range chReqs {
		switch req.Type {
		case agentForwardRequestType:
			state.agentReqCount.Add(1)
			if state.rejectAgentReq.Load() {
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				continue
			}
			agentRequested = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var payload struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			runPhase3ExecAction(sConn, ch, payload.Command, agentRequested, state)
			return
		default:
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}
}

func runPhase3ExecAction(sConn cryptoSSH.Conn, ch cryptoSSH.Channel, cmd string, agentRequested bool, state *phase3AgentServerState) {
	switch {
	case strings.Contains(cmd, "query-agent"):
		if !agentRequested {
			_, _ = io.WriteString(ch, "no-agent-req\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		agCh, agReqs, err := sConn.OpenChannel(agentForwardChannelType, nil)
		if err != nil {
			_, _ = fmt.Fprintf(ch, "open-err:%v\n", err)
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		go cryptoSSH.DiscardRequests(agReqs)
		keys, listErr := agent.NewClient(agCh).List()
		_ = agCh.Close()
		if listErr != nil {
			_, _ = fmt.Fprintf(ch, "list-err:%v\n", listErr)
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		_, _ = fmt.Fprintf(ch, "keys=%d\n", len(keys))
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
	case strings.Contains(cmd, "hold-open"):
		_, _ = io.WriteString(ch, "ready\n")
		_, _ = io.Copy(io.Discard, ch)
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
	default:
		if agentRequested {
			_, _ = io.WriteString(ch, "unexpected-agent-on-probe\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		state.probeExecSeen.Add(1)
		_, _ = io.WriteString(ch, "0\n")
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
	}
}

func TestPhase3_ResolveForwardAgentMatrix(t *testing.T) {
	env := fixtureEnvironment()
	env.HomeDir = "/home/alice"
	env.AgentSocket = "/default/ssh_auth.sock"
	target := TargetContext{Host: "app", Port: 22, User: "alice", OriginalHost: "app"}

	if sock, ok, err := ResolveForwardAgent("", "", env, target); err != nil || ok || sock != "" {
		t.Fatalf("empty = (%q, %v, %v)", sock, ok, err)
	}
	if sock, ok, err := ResolveForwardAgent("no", "/custom.sock", env, target); err != nil || ok || sock != "" {
		t.Fatalf("no = (%q, %v, %v)", sock, ok, err)
	}
	if sock, ok, err := ResolveForwardAgent("yes", "none", env, target); err != nil || ok || sock != "" {
		t.Fatalf("yes + IdentityAgent=none = (%q, %v, %v)", sock, ok, err)
	}
	if sock, ok, err := ResolveForwardAgent("yes", "/id-agent.sock", env, target); err != nil || !ok || sock != "/id-agent.sock" {
		t.Fatalf("yes + IdentityAgent = (%q, %v, %v)", sock, ok, err)
	}
	if sock, ok, err := ResolveForwardAgent("SSH_AUTH_SOCK", "none", env, target); err != nil || !ok || sock != "/default/ssh_auth.sock" {
		t.Fatalf("SSH_AUTH_SOCK = (%q, %v, %v)", sock, ok, err)
	}
	if sock, ok, err := ResolveForwardAgent("~/fwd-%r.sock", "none", env, target); err != nil || !ok || !strings.HasSuffix(sock, "fwd-alice.sock") {
		t.Fatalf("override path = (%q, %v, %v)", sock, ok, err)
	}
}

func TestPhase3_ForwardAgentLifecycleProbesCapAndMux(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix agent listener and PROTOCOL.mux test runs on Unix")
	}

	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	loginPriv, loginPub := writeEd25519KeyFile(t, keyPath, "")
	agentSock, activeAgentConns := startInMemoryAgentListener(t, loginPriv)

	state := &phase3AgentServerState{hostSigner: fix.hostSigner, clientPub: loginPub}
	port := startPhase3ForwardAgentServer(t, state)

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.AgentSocket = agentSock

	opts := newPhase3TrustAllOptions(t, dir)
	if err := opts.Set(OptionForwardAgent, "yes"); err != nil {
		t.Fatal(err)
	}
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"node": {
			NodeID:   "node",
			Address:  "127.0.0.1",
			Port:     port,
			User:     "alice",
			AuthType: "key",
			KeyPath:  keyPath,
			Options:  opts,
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cli, err := conn.Connect(t.Context(), "node")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Internal probes (sendSessionEnv=false) MUST NEVER request auth-agent-req@openssh.com!
	probeOut, err := cli.runWithoutLoginWithConfig(t.Context(), "id -u", DefaultRunConfig(), false)
	if err != nil || strings.TrimSpace(probeOut) != "0" {
		t.Fatalf("internal probe failed: out=%q err=%v", probeOut, err)
	}
	probePlan, err := PlanCommand("id -u", CommandOptions{
		Interpreter:   InterpreterSh,
		LaunchDialect: LaunchPOSIX,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := cli.executeCommand(t.Context(), probePlan, false); res.ExecutionErr != nil {
		t.Fatalf("internal executeCommand probe failed: %v", res.ExecutionErr)
	}
	if state.agentReqCount.Load() != 0 {
		t.Fatalf("internal probes sent %d auth-agent-req requests, want 0", state.agentReqCount.Load())
	}

	// 2. User command forwards agent and lists 1 key; after exit, 0-lease rejects rogue open!
	out, err := cli.Run(t.Context(), "query-agent")
	if err != nil || !strings.Contains(out, "keys=1") {
		t.Fatalf("user Run query-agent = %q, err = %v", out, err)
	}
	if _, _, rogueErr := state.getLastConn().OpenChannel(agentForwardChannelType, nil); rogueErr == nil {
		t.Fatal("expected rogue auth-agent@openssh.com open with 0 active leases to be rejected")
	}

	// 3. Server rejecting auth-agent-req@openssh.com is non-fatal and releases lease immediately!
	state.rejectAgentReq.Store(true)
	if res := cli.ExecuteCommand(t.Context(), probePlan); res.ExecutionErr != nil {
		t.Fatalf("rejected auth-agent-req should not fail user command: %v", res.ExecutionErr)
	}
	if _, _, rogueErr := state.getLastConn().OpenChannel(agentForwardChannelType, nil); rogueErr == nil {
		t.Fatal("expected lease to be released immediately after server rejected auth-agent-req")
	}
	state.rejectAgentReq.Store(false)

	// 4. Multi-session ref-counting + MaxAgentForwardChannels=64 cap + 1s cancellation drain!
	assertPhase3ForwardAgentCapAndDrain(t, cli, state, activeAgentConns)

	// 5. Mux Master (AllowAgentForward=false): WantAgent gated on passenger, MUX_C_PROXY forwards cleanly!
	assertPhase3MuxAgentForwarding(t, dir, port, keyPath, agentSock, env, state)
}

func assertPhase3ForwardAgentCapAndDrain(
	t *testing.T,
	cli *Client,
	state *phase3AgentServerState,
	activeAgentConns *atomic.Int32,
) {
	t.Helper()
	baselineGoroutines := runtime.NumGoroutine()

	ctx1, cancel1 := context.WithCancel(t.Context())
	defer cancel1()
	stream1, err := cli.RunStream(ctx1, "hold-open")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := stream1.Read(buf); err != nil {
		t.Fatal(err)
	}

	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	stream2, err := cli.RunStream(ctx2, "hold-open")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream2.Read(buf); err != nil {
		t.Fatal(err)
	}

	// Close session 1 while session 2 stays open -> agent forwarding MUST still work!
	cancel1()
	_ = stream1.Close()

	sConn := state.getLastConn()
	held := make([]cryptoSSH.Channel, 0, MaxAgentForwardChannels)
	for i := 0; i < MaxAgentForwardChannels; i++ {
		ch, reqs, openErr := sConn.OpenChannel(agentForwardChannelType, nil)
		if openErr != nil {
			t.Fatalf("channel %d/%d open failed: %v", i+1, MaxAgentForwardChannels, openErr)
		}
		go cryptoSSH.DiscardRequests(reqs)
		held = append(held, ch)
	}

	// 65th concurrent channel MUST be rejected with ResourceShortage!
	if extraCh, _, extraErr := sConn.OpenChannel(agentForwardChannelType, nil); extraErr == nil {
		_ = extraCh.Close()
		t.Fatal("expected 65th concurrent auth-agent@openssh.com channel to be rejected")
	}

	// Cancel session 2 -> within 1s drain, all 64 local agent conns close and goroutines settle!
	startDrain := time.Now()
	cancel2()
	_ = stream2.Close()
	if elapsed := time.Since(startDrain); elapsed > 2*time.Second {
		t.Fatalf("session agent forward drain took %s, expected <= 1s bounded drain", elapsed)
	}
	for _, ch := range held {
		_ = ch.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if activeAgentConns.Load() == 0 && runtime.NumGoroutine() <= baselineGoroutines+4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := activeAgentConns.Load(); got != 0 {
		t.Fatalf("active local agent connections after drain = %d, want 0", got)
	}
}

func assertPhase3MuxAgentForwarding(
	t *testing.T,
	dir string,
	port int,
	keyPath string,
	agentSock string,
	env Environment,
	state *phase3AgentServerState,
) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	sockPath := filepath.Join(os.TempDir(), fmt.Sprintf("xops-p3-mux-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(sockPath) })

	// Master has ForwardAgent=no (AllowAgentForward=false).
	masterOpts := newPhase3TrustAllOptions(t, dir)
	_ = masterOpts.Set(OptionControlMaster, "yes")
	_ = masterOpts.Set(OptionControlPath, sockPath)
	_ = masterOpts.Set(OptionControlPersist, "yes")
	_ = masterOpts.Set(OptionForwardAgent, "no")

	masterConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: masterOpts},
	}}, WithEnvironment(env))
	t.Cleanup(func() { _ = masterConn.CloseAll() })

	if _, err := masterConn.Connect(t.Context(), "m"); err != nil {
		t.Fatalf("start mux master failed: %v", err)
	}

	// Passenger via MUX_C_PROXY (ControlMaster=no, ForwardAgent=yes) MUST forward agent to passenger's local agent!
	proxyOpts := newPhase3TrustAllOptions(t, dir)
	_ = proxyOpts.Set(OptionControlMaster, "no")
	_ = proxyOpts.Set(OptionControlPath, sockPath)
	_ = proxyOpts.Set(OptionForwardAgent, "yes")
	_ = proxyOpts.Set(OptionIdentityAgent, agentSock)

	proxyConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: proxyOpts},
	}}, WithEnvironment(env))
	t.Cleanup(func() { _ = proxyConn.CloseAll() })

	proxyCli, err := proxyConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect via mux proxy failed: %v", err)
	}
	out, err := proxyCli.Run(t.Context(), "query-agent")
	if err != nil || !strings.Contains(out, "keys=1") {
		t.Fatalf("MUX_C_PROXY ForwardAgent query-agent = %q, err = %v", out, err)
	}

	// After proxy session exits, Master has 0 active proxy leases -> rogue server open MUST be rejected!
	if _, _, rogueErr := state.getLastConn().OpenChannel(agentForwardChannelType, nil); rogueErr == nil {
		t.Fatal("expected Master to reject auth-agent@openssh.com once MUX_C_PROXY session ended")
	}

	assertPhase3MuxProxyWantReplyFalseAndCloseRace(t, sockPath, port, agentSock, env, state)
}

func assertPhase3MuxProxyWantReplyFalseAndCloseRace(
	t *testing.T,
	sockPath string,
	port int,
	agentSock string,
	env Environment,
	state *phase3AgentServerState,
) {
	t.Helper()
	// Direct channel-close race check: attachAgentProxyLease after releaseAgentProxyLease
	// must reject attachment and immediately close the late-arriving lease.
	racePC := &proxyChan{}
	racePC.releaseAgentProxyLease()
	lateLease := &agentForwardLease{}
	if racePC.attachAgentProxyLease(lateLease) {
		t.Fatal("expected attachAgentProxyLease after releaseAgentProxyLease to return false")
	}
	lateLease.mu.Lock()
	closedLate := lateLease.closed
	lateLease.mu.Unlock()
	if !closedLate {
		t.Fatal("expected late lease to be released immediately when proxyChan is already closed")
	}

	// Native OpenSSH MUX_C_PROXY behavior: auth-agent-req@openssh.com sent with wantReply=false!
	rawProxySSH, _, err := DialControlProxy(t.Context(), sockPath, TargetContext{
		Host: "127.0.0.1",
		Port: port,
		User: "alice",
	})
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	t.Cleanup(func() { _ = rawProxySSH.Close() })

	router, err := getOrCreateAgentRouter(rawProxySSH)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter on proxy SSH client failed: %v", err)
	}
	clientLease := router.acquireLocalLease(t.Context(), agentSock, env.DialAgent, nil)

	ch, chReqs, err := rawProxySSH.OpenChannel("session", nil)
	if err != nil {
		clientLease.Release()
		t.Fatalf("OpenChannel(session) over MUX_C_PROXY failed: %v", err)
	}
	go cryptoSSH.DiscardRequests(chReqs)

	if _, err := ch.SendRequest(agentForwardRequestType, false, nil); err != nil {
		_ = ch.Close()
		clientLease.Release()
		t.Fatalf("SendRequest(auth-agent-req, wantReply=false) failed: %v", err)
	}
	execPayload := cryptoSSH.Marshal(struct{ Command string }{Command: "query-agent"})
	if accepted, err := ch.SendRequest("exec", true, execPayload); err != nil || !accepted {
		_ = ch.Close()
		clientLease.Release()
		t.Fatalf("SendRequest(exec query-agent) accepted=%v err=%v", accepted, err)
	}
	data, err := io.ReadAll(ch)
	_ = ch.Close()
	clientLease.Release()
	if err != nil || !strings.Contains(string(data), "keys=1") {
		t.Fatalf("MUX_C_PROXY wantReply=false query-agent = %q, err = %v", string(data), err)
	}

	// Wait briefly for channel-close packet to propagate on MuxServer, then verify rogue open is rejected.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		rogueCh, _, rogueErr := state.getLastConn().OpenChannel(agentForwardChannelType, nil)
		if rogueErr != nil {
			return
		}
		_ = rogueCh.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected MuxServer proxy lease to be released after proxy session channel closed")
}
