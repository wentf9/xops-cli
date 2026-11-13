package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

func generateEd25519TestKeyFile(t *testing.T, path string, passphrase string) (cryptoSSH.Signer, cryptoSSH.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	var block *pem.Block
	if passphrase != "" {
		block, err = cryptoSSH.MarshalPrivateKeyWithPassphrase(priv, "test-key", []byte(passphrase))
	} else {
		block, err = cryptoSSH.MarshalPrivateKey(priv, "test-key")
	}
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
	return signer, signer.PublicKey()
}

type recordingDialer struct {
	mu       sync.Mutex
	networks []string
	inner    net.Dialer
}

func (d *recordingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.networks = append(d.networks, network)
	d.mu.Unlock()
	return d.inner.DialContext(ctx, network, addr)
}

func (d *recordingDialer) snapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.networks)
}

func TestPhase1_AddressFamily_OptionAndDialNetwork(t *testing.T) {
	var nilOpts *Options
	if got := nilOpts.AddressFamily(); got != "" {
		t.Fatalf("nil Options.AddressFamily() = %q, want empty", got)
	}
	if got := nilOpts.DialNetwork(); got != "tcp" {
		t.Fatalf("nil Options.DialNetwork() = %q, want tcp", got)
	}

	cases := []struct {
		raw     string
		wantFam string
		wantNet string
		wantErr bool
	}{
		{raw: "any", wantFam: "any", wantNet: "tcp"},
		{raw: "ANY", wantFam: "any", wantNet: "tcp"},
		{raw: "inet", wantFam: "inet", wantNet: "tcp4"},
		{raw: "  InEt  ", wantFam: "inet", wantNet: "tcp4"},
		{raw: "inet6", wantFam: "inet6", wantNet: "tcp6"},
		{raw: "INET6", wantFam: "inet6", wantNet: "tcp6"},
		{raw: "ipv4", wantErr: true},
		{raw: "unix", wantErr: true},
		{raw: "   ", wantErr: true},
	}

	for _, tc := range cases {
		opts := &Options{}
		err := opts.Set("AddressFamily", tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("Set(AddressFamily, %q) succeeded, want error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Set(AddressFamily, %q) failed: %v", tc.raw, err)
		}
		if got := opts.AddressFamily(); got != tc.wantFam {
			t.Fatalf("AddressFamily() after %q = %q, want %q", tc.raw, got, tc.wantFam)
		}
		if got := opts.DialNetwork(); got != tc.wantNet {
			t.Fatalf("DialNetwork() after %q = %q, want %q", tc.raw, got, tc.wantNet)
		}
	}

	def, ok := LookupOptionSpec("AddressFamily")
	if !ok || def.CanonicalKey != OptionAddressFamily || def.OpenSSHName != "AddressFamily" || def.Class != OptionClassTransport {
		t.Fatalf("unexpected AddressFamily OptionSpec: %+v (ok=%v)", def, ok)
	}
}

func TestPhase1_AddressFamily_DialAndProxyJumpAndForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionFix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bastionFix.Close() }()

	targetFix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = targetFix.Close() }()

	bHost, bPortStr, _ := net.SplitHostPort(bastionFix.Address)
	bPort, _ := strconv.Atoi(bPortStr)
	tHost, tPortStr, _ := net.SplitHostPort(targetFix.Address)
	tPort, _ := strconv.Atoi(tPortStr)

	recDialer := &recordingDialer{}
	provider := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  bHost,
				Port:     bPort,
				User:     "jumpuser",
				AuthType: "password",
				Password: sshfixture.Password,
				Options:  MustOptions(OptionAddressFamily, "inet"),
			},
			"target": {
				NodeID:    "target",
				Address:   tHost,
				Port:      tPort,
				User:      "appuser",
				AuthType:  "password",
				Password:  sshfixture.Password,
				ProxyJump: "bastion",
				Options:   MustOptions(OptionAddressFamily, "inet"),
			},
		},
	}

	connector := NewConnector(
		provider,
		WithDialer(recDialer),
		WithHostKeyVerifier(trustAnyFixtureHostKey{}),
	)
	defer func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Errorf("CloseAll: %v", closeErr)
		}
	}()

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect via ProxyJump with AddressFamily=inet failed: %v", err)
	}
	if got := recDialer.snapshot(); !slices.Equal(got, []string{"tcp4"}) {
		t.Fatalf("expected ProxyJump initial dial to use tcp4, got %v", got)
	}

	// Verify LocalForwardEndpoint uses tcp4 for TCP while keeping unix for streamlocal.
	_, echoAddr := startEchoServer(t, "tcp4", "127.0.0.1:0")
	echoHost, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)

	fwdCtx, cancelFwd := context.WithCancel(ctx)
	fwd, err := client.LocalForwardEndpoint(
		fwdCtx,
		ForwardEndpoint{Host: "127.0.0.1", Port: 0, HasHost: true},
		ForwardEndpoint{Host: echoHost, Port: uint16(echoPort), HasHost: true},
		false,
	)
	if err != nil {
		cancelFwd()
		t.Fatalf("LocalForwardEndpoint under AddressFamily=inet failed: %v", err)
	}
	localConn, err := net.Dial("tcp4", fwd.Addr().String())
	if err != nil {
		cancelFwd()
		_ = fwd.Wait()
		t.Fatalf("dial local tcp4 forward failed: %v", err)
	}
	verifyEchoRoundtrip(t, localConn, "dual-stack-tcp4")
	_ = localConn.Close()
	cancelFwd()
	_ = fwd.Wait()

	// StreamLocal endpoint network remains "unix" even when AddressFamily=inet6.
	unixEp := ForwardEndpoint{SocketPath: "/tmp/example.sock"}
	if netw, _ := unixEp.LocalListenAddressWithNetwork(false, "tcp6"); netw != "unix" {
		t.Fatalf("Unix LocalListenAddressWithNetwork network = %q, want unix", netw)
	}
	if netw, _ := unixEp.RemoteListenAddressForMode(GatewayPortsYes, "tcp6"); netw != "unix" {
		t.Fatalf("Unix RemoteListenAddressForMode network = %q, want unix", netw)
	}
	if netw, _ := unixEp.ConnectAddressWithNetwork("tcp6"); netw != "unix" {
		t.Fatalf("Unix ConnectAddressWithNetwork network = %q, want unix", netw)
	}
}

func TestPhase1_IdentityFile_MultiValue(t *testing.T) {
	var nilOpts *Options
	if got := nilOpts.IdentityFiles(); got != nil {
		t.Fatalf("nil Options.IdentityFiles() = %v, want nil", got)
	}
	if got := nilOpts.IdentityFile(); got != "" {
		t.Fatalf("nil Options.IdentityFile() = %q, want empty", got)
	}

	def, ok := LookupOptionSpec("IdentityFile")
	if !ok || def.CanonicalKey != OptionIdentityFile || def.OpenSSHName != "IdentityFile" || def.Class != OptionClassAuth || !def.MultiValue {
		t.Fatalf("unexpected IdentityFile OptionSpec: %+v (ok=%v)", def, ok)
	}

	opts := &Options{}
	if err := opts.Append("IdentityFile", "  ~/.ssh/id_ed25519  "); err != nil {
		t.Fatalf("Append 1 failed: %v", err)
	}
	if err := opts.Append(OptionIdentityFile, "~/.ssh/id_rsa"); err != nil {
		t.Fatalf("Append 2 failed: %v", err)
	}
	if got := opts.IdentityFiles(); !slices.Equal(got, []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"}) {
		t.Fatalf("IdentityFiles() = %v, want [~/.ssh/id_ed25519 ~/.ssh/id_rsa]", got)
	}
	if got := opts.IdentityFile(); got != "~/.ssh/id_ed25519" {
		t.Fatalf("IdentityFile() = %q, want ~/.ssh/id_ed25519", got)
	}

	// Reject whitespace-only or empty multi-value entries.
	if err := opts.Append(OptionIdentityFile, "   "); err == nil {
		t.Fatal("expected whitespace-only IdentityFile Append to fail")
	}
	if err := opts.Set(OptionIdentityFile, "\t "); err == nil {
		t.Fatal("expected whitespace-only IdentityFile Set to fail")
	}

	assertIdentityFilesCodecRoundTrip(t, opts, []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"})

	// Empty string Set clears the option cleanly.
	if err := opts.Set(OptionIdentityFile, ""); err != nil {
		t.Fatalf("Set empty failed: %v", err)
	}
	if len(opts.IdentityFiles()) != 0 || opts.IdentityFile() != "" {
		t.Fatalf("expected cleared IdentityFiles(), got %v", opts.IdentityFiles())
	}
}

func assertIdentityFilesCodecRoundTrip(t *testing.T, opts *Options, want []string) {
	t.Helper()
	yamlData, err := yaml.Marshal(opts)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	var fromYAML Options
	if err := yaml.Unmarshal(yamlData, &fromYAML); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if !slices.Equal(fromYAML.IdentityFiles(), want) {
		t.Fatalf("YAML round-trip IdentityFiles() = %v, want %v", fromYAML.IdentityFiles(), want)
	}

	jsonData, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var fromJSON Options
	if err := json.Unmarshal(jsonData, &fromJSON); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !slices.Equal(fromJSON.IdentityFiles(), want) {
		t.Fatalf("JSON round-trip IdentityFiles() = %v, want %v", fromJSON.IdentityFiles(), want)
	}

	var invalidJSON Options
	if err := json.Unmarshal([]byte(`{"identity_file":["/valid/key","   "]}`), &invalidJSON); err == nil {
		t.Fatal("expected whitespace-only element in identity_file JSON array to fail")
	}
}

func TestPhase1_ExpandHostName(t *testing.T) {
	validCases := []struct {
		pattern      string
		originalHost string
		want         string
	}{
		{pattern: "10.0.0.5", originalHost: "web", want: "10.0.0.5"},
		{pattern: "%h.internal.corp", originalHost: "web-01", want: "web-01.internal.corp"},
		{pattern: "%%literal-%h%%", originalHost: "db", want: "%literal-db%"},
		{pattern: "  bastion-%h.example.com  ", originalHost: "  app  ", want: "bastion-app.example.com"},
	}
	for _, tc := range validCases {
		got, err := ExpandHostName(tc.pattern, tc.originalHost)
		if err != nil || got != tc.want {
			t.Fatalf("ExpandHostName(%q, %q) = (%q, %v), want (%q, nil)", tc.pattern, tc.originalHost, got, err, tc.want)
		}
	}

	invalidCases := []struct {
		name         string
		pattern      string
		originalHost string
	}{
		{name: "empty pattern", pattern: "", originalHost: "host"},
		{name: "whitespace pattern", pattern: "   ", originalHost: "host"},
		{name: "empty originalHost with %h", pattern: "%h.example.com", originalHost: ""},
		{name: "unknown token %p", pattern: "%h:%p", originalHost: "host"},
		{name: "unknown token %u", pattern: "%u.example.com", originalHost: "host"},
		{name: "unknown token %n", pattern: "%n.example.com", originalHost: "host"},
		{name: "trailing percent", pattern: "host%", originalHost: "host"},
		{name: "control char NUL in pattern", pattern: "bad\x00host", originalHost: "host"},
		{name: "control char newline in pattern", pattern: "bad\nhost", originalHost: "host"},
		{name: "control char DEL 0x7f in pattern", pattern: "bad\x7fhost", originalHost: "host"},
		{name: "control char in originalHost", pattern: "%h.corp", originalHost: "bad\rhost"},
	}
	for _, tc := range invalidCases {
		if got, err := ExpandHostName(tc.pattern, tc.originalHost); err == nil {
			t.Fatalf("%s: ExpandHostName(%q, %q) = %q, want error", tc.name, tc.pattern, tc.originalHost, got)
		}
	}
}

func TestPhase1_EnvironmentContracts(t *testing.T) {
	globalKH := []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}
	var nilEnviron func() []string
	var nilDialAgent func(context.Context, string) (net.Conn, error)
	var nilDialProxy func(context.Context, string) (net.Conn, error)
	var nilRunLocal func(context.Context, string) error
	var nilLookupSSHFP func(context.Context, string) (SSHFPResult, error)

	c := NewConnector(nil, WithEnvironment(Environment{
		GlobalKnownHostsFiles: globalKH,
		Environ:               nilEnviron,
		DialAgent:             nilDialAgent,
		DialProxyCommand:      nilDialProxy,
		RunLocalCommand:       nilRunLocal,
		LookupSSHFP:           nilLookupSSHFP,
	}))
	defer func() { _ = c.CloseAll() }()

	globalKH[0] = "/mutated"
	if !slices.Equal(c.environment.GlobalKnownHostsFiles, []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}) {
		t.Fatalf("GlobalKnownHostsFiles was not cloned: %v", c.environment.GlobalKnownHostsFiles)
	}
	if c.environment.Environ != nil || c.environment.DialAgent != nil || c.environment.DialProxyCommand != nil || c.environment.RunLocalCommand != nil || c.environment.LookupSSHFP != nil {
		t.Fatal("expected nil func fields to remain nil after WithEnvironment sanitization")
	}

	rec := SSHFPRecord{Algorithm: 4, FingerprintType: 2, Fingerprint: []byte{1, 2, 3}}
	res := SSHFPResult{Records: []SSHFPRecord{rec}, Authenticated: true}
	if !res.Authenticated || len(res.Records) != 1 || res.Records[0].Algorithm != 4 || res.Records[0].FingerprintType != 2 {
		t.Fatalf("unexpected SSHFPResult: %+v", res)
	}
}

func TestPhase1_OptionClassLocalExec_And_PlanIsolation(t *testing.T) {
	if OptionClassLocalExec != "local_exec" {
		t.Fatalf("OptionClassLocalExec = %q, want local_exec", OptionClassLocalExec)
	}

	// Temporarily register a synthetic local_exec option in optionLookupMap to verify StripClasses,
	// normalizePlan, and clientConfigFromPlan hard-strip OptionClassLocalExec!
	const syntheticLocalExecKey = "__test_local_exec_option"
	optionLookupMap[syntheticLocalExecKey] = OptionSpec{
		CanonicalKey: syntheticLocalExecKey,
		OpenSSHName:  "TestLocalExecOption",
		Class:        OptionClassLocalExec,
		Normalize: func(raw string) (string, error) {
			return strings.TrimSpace(raw), nil
		},
	}
	t.Cleanup(func() {
		delete(optionLookupMap, syntheticLocalExecKey)
	})

	basePlan := ConnectionPlan{
		Scope: "mcp-test",
		Hops: []ConnectionConfig{
			{
				NodeID:   "app",
				Address:  "192.0.2.10",
				Port:     22,
				User:     "ops",
				AuthType: "auto",
				KeyPaths: []string{"/keys/a", "/keys/b"},
				Options: MustOptions(
					OptionAddressFamily, "inet",
					OptionIdentityFile, "/keys/opt1",
					OptionIdentityFile, "/keys/opt2",
				),
			},
		},
	}
	baseKey, err := ConnectionKey(basePlan)
	if err != nil {
		t.Fatalf("ConnectionKey(basePlan): %v", err)
	}

	withLocalExec := basePlan
	withLocalExec.Hops = slices.Clone(basePlan.Hops)
	withLocalExec.Hops[0] = basePlan.Hops[0].Clone()
	if err := withLocalExec.Hops[0].Options.Set(syntheticLocalExecKey, "nc %h %p"); err != nil {
		t.Fatalf("Set synthetic local_exec: %v", err)
	}
	localExecKey, err := ConnectionKey(withLocalExec)
	if err != nil {
		t.Fatalf("ConnectionKey(withLocalExec): %v", err)
	}
	if localExecKey != baseKey {
		t.Fatal("OptionClassLocalExec leaked into normalized ConnectionKey")
	}

	normalized, err := normalizePlan(withLocalExec)
	if err != nil {
		t.Fatalf("normalizePlan: %v", err)
	}
	if normalized.Hops[0].Options.Has(syntheticLocalExecKey) {
		t.Fatal("normalizePlan failed to strip OptionClassLocalExec")
	}
	clientCfg := clientConfigFromPlan(withLocalExec.Hops[0])
	if clientCfg.Options.Has(syntheticLocalExecKey) {
		t.Fatal("clientConfigFromPlan failed to strip OptionClassLocalExec")
	}

	// Reordering KeyPaths, OptionIdentityFile, or changing OptionAddressFamily MUST change ConnectionKey.
	reorderedKeyPaths := basePlan
	reorderedKeyPaths.Hops = []ConnectionConfig{basePlan.Hops[0].Clone()}
	reorderedKeyPaths.Hops[0].KeyPaths = []string{"/keys/b", "/keys/a"}
	if k, err := ConnectionKey(reorderedKeyPaths); err != nil || k == baseKey {
		t.Fatalf("reordering KeyPaths did not change ConnectionKey: err=%v", err)
	}

	reorderedOptKeys := basePlan
	reorderedOptKeys.Hops = []ConnectionConfig{basePlan.Hops[0].Clone()}
	reorderedOptKeys.Hops[0].Options = MustOptions(
		OptionAddressFamily, "inet",
		OptionIdentityFile, "/keys/opt2",
		OptionIdentityFile, "/keys/opt1",
	)
	if k, err := ConnectionKey(reorderedOptKeys); err != nil || k == baseKey {
		t.Fatalf("reordering OptionIdentityFile did not change ConnectionKey: err=%v", err)
	}

	changedFamily := basePlan
	changedFamily.Hops = []ConnectionConfig{basePlan.Hops[0].Clone()}
	if err := changedFamily.Hops[0].Options.Set(OptionAddressFamily, "inet6"); err != nil {
		t.Fatal(err)
	}
	if k, err := ConnectionKey(changedFamily); err != nil || k == baseKey {
		t.Fatalf("changing OptionAddressFamily did not change ConnectionKey: err=%v", err)
	}
}

func TestPhase1_MultiKeyAuth_OrderDedupTokensAndIdentitiesOnlyAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	tmpHome := t.TempDir()
	keyDir := filepath.Join(tmpHome, "keys")
	_, pub1 := generateEd25519TestKeyFile(t, filepath.Join(keyDir, "k1"), "")
	_, _ = generateEd25519TestKeyFile(t, filepath.Join(keyDir, "k2"), "")
	_, pub3 := generateEd25519TestKeyFile(t, filepath.Join(keyDir, "ops-127.0.0.1-key"), "")

	// Server 1 accepts ONLY pub3 (resolved via ~/keys/%r-%h-key in Options.IdentityFiles()).
	fix1, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		PublicKeys: []cryptoSSH.PublicKey{pub3},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fix1.Close() }()
	host1, port1Str, _ := net.SplitHostPort(fix1.Address)
	port1, _ := strconv.Atoi(port1Str)

	env := Environment{
		HomeDir:        tmpHome,
		LocalUser:      "localu",
		LocalHost:      "laptop.local",
		KnownHostsFile: filepath.Join(tmpHome, "known_hosts"),
		DefaultKeyPaths: []string{
			filepath.Join(keyDir, "k1"), // duplicate of KeyPaths[0]
		},
	}

	for _, authType := range []string{"auto", "key"} {
		t.Run("multi_key_"+authType, func(t *testing.T) {
			provider := &mapTestProvider{
				configs: map[string]*ClientConfig{
					"node": {
						NodeID:   "node",
						Address:  host1,
						Port:     port1,
						User:     "ops",
						AuthType: authType,
						KeyPaths: []string{filepath.Join(keyDir, "k1")},
						KeyPath:  filepath.Join(keyDir, "k2"),
						Options: MustOptions(
							OptionIdentityFile, filepath.Join(keyDir, "k1"), // duplicate
							OptionIdentityFile, "~/keys/%r-%h-key",
							OptionPasswordAuthentication, "no",
							OptionKbdInteractiveAuthentication, "no",
						),
					},
				},
			}
			c := NewConnector(provider, WithEnvironment(env), WithHostKeyVerifier(trustAnyFixtureHostKey{}))
			defer func() { _ = c.CloseAll() }()

			if _, err := c.Connect(ctx, "node"); err != nil {
				t.Fatalf("Connect(%s) with multi-key + token expansion failed: %v", authType, err)
			}
		})
	}

	keyring := agent.NewKeyring()
	_, rawUnrelatedPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedSigner, err := cryptoSSH.NewSignerFromKey(rawUnrelatedPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: rawUnrelatedPriv}); err != nil {
		t.Fatal(err)
	}

	_, rawMatchingPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	matchingSigner, err := cryptoSSH.NewSignerFromKey(rawMatchingPriv)
	if err != nil {
		t.Fatal(err)
	}
	encBlock, err := cryptoSSH.MarshalPrivateKeyWithPassphrase(rawMatchingPriv, "enc", []byte("do-not-prompt"))
	if err != nil {
		t.Fatal(err)
	}
	matchingEncPath := filepath.Join(keyDir, "matching_encrypted")
	if err := os.WriteFile(matchingEncPath, pem.EncodeToMemory(encBlock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: rawMatchingPriv}); err != nil {
		t.Fatal(err)
	}

	dialInMemAgent := func(dCtx context.Context, _ string) (net.Conn, error) {
		if err := dCtx.Err(); err != nil {
			return nil, err
		}
		clientConn, serverConn := net.Pipe()
		go func() {
			_ = agent.ServeAgent(keyring, serverConn)
			_ = serverConn.Close()
		}()
		return clientConn, nil
	}

	// Server 3 accepts ONLY unrelatedSigner (in agent, NOT in IdentityFiles).
	fixUnrelated, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		PublicKeys: []cryptoSSH.PublicKey{unrelatedSigner.PublicKey(), pub1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fixUnrelated.Close() }()
	uHost, uPortStr, _ := net.SplitHostPort(fixUnrelated.Address)
	uPort, _ := strconv.Atoi(uPortStr)

	// 1. With IdentitiesOnly=yes and IdentityFile=k2 (neither pub1 nor unrelatedSigner),
	// BOTH DefaultKeyPaths (k1/pub1) AND unrelated agent key MUST be filtered out -> auth fails!
	envWithAgent := env
	envWithAgent.AgentSocket = "in-memory-agent"
	envWithAgent.DialAgent = dialInMemAgent

	providerBlocked := &mapTestProvider{
		configs: map[string]*ClientConfig{
			"blocked": {
				NodeID:   "blocked",
				Address:  uHost,
				Port:     uPort,
				User:     "ops",
				AuthType: "auto",
				Options: MustOptions(
					OptionIdentitiesOnly, "yes",
					OptionIdentityFile, filepath.Join(keyDir, "k2"),
					OptionPasswordAuthentication, "no",
					OptionKbdInteractiveAuthentication, "no",
				),
			},
		},
	}
	cBlocked := NewConnector(providerBlocked, WithEnvironment(envWithAgent), WithHostKeyVerifier(trustAnyFixtureHostKey{}))
	defer func() { _ = cBlocked.CloseAll() }()
	if _, err := cBlocked.Connect(ctx, "blocked"); err == nil {
		t.Fatal("expected IdentitiesOnly=yes to block unrelated agent key and DefaultKeyPaths")
	}

	// 2. Server 4 accepts matchingSigner: encrypted file is in KeyPaths AND unlocked in ssh-agent.
	// With IdentitiesOnly=yes and NO passphrase prompter, it MUST succeed via filtered ssh-agent signer!
	fixMatching, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{
		PublicKeys: []cryptoSSH.PublicKey{matchingSigner.PublicKey()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fixMatching.Close() }()
	mHost, mPortStr, _ := net.SplitHostPort(fixMatching.Address)
	mPort, _ := strconv.Atoi(mPortStr)

	for _, authType := range []string{"auto", "agent"} {
		t.Run("identities_only_matching_agent_"+authType, func(t *testing.T) {
			providerMatch := &mapTestProvider{
				configs: map[string]*ClientConfig{
					"match": {
						NodeID:   "match",
						Address:  mHost,
						Port:     mPort,
						User:     "ops",
						AuthType: authType,
						KeyPaths: []string{matchingEncPath},
						Options: MustOptions(
							OptionIdentitiesOnly, "yes",
							OptionPasswordAuthentication, "no",
							OptionKbdInteractiveAuthentication, "no",
						),
					},
				},
			}
			cMatch := NewConnector(providerMatch, WithEnvironment(envWithAgent), WithHostKeyVerifier(trustAnyFixtureHostKey{}))
			defer func() { _ = cMatch.CloseAll() }()
			if _, err := cMatch.Connect(ctx, "match"); err != nil {
				t.Fatalf("expected IdentitiesOnly=yes with matching agent key to succeed (%s): %v", authType, err)
			}
		})
	}
}

func TestPhase1_GatewayPorts_Modes_EndToEndAndMux(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	_, locTCP := startEchoServer(t, "tcp", "127.0.0.1:0")
	_, locPortStr, _ := net.SplitHostPort(locTCP)
	locPort, _ := strconv.Atoi(locPortStr)

	cases := []struct {
		mode         string
		bind         ForwardEndpoint
		wantBindPref string
	}{
		// GatewayPorts=no forces "localhost" on bare port AND wildcard (:port / *:port), keeps explicit IP.
		{mode: GatewayPortsNo, bind: ForwardEndpoint{Port: 0, HasHost: false}, wantBindPref: "localhost:0"},
		{mode: GatewayPortsNo, bind: ForwardEndpoint{Port: 0, HasHost: true, Wildcard: true}, wantBindPref: "localhost:0"},
		{mode: GatewayPortsNo, bind: ForwardEndpoint{Host: "127.0.0.1", Port: 0, HasHost: true}, wantBindPref: "127.0.0.1:0"},

		// GatewayPorts=yes forces wildcard "" (":0") on bare port, wildcard, and explicit bind.
		{mode: GatewayPortsYes, bind: ForwardEndpoint{Port: 0, HasHost: false}, wantBindPref: ":0"},
		{mode: GatewayPortsYes, bind: ForwardEndpoint{Port: 0, HasHost: true, Wildcard: true}, wantBindPref: ":0"},
		{mode: GatewayPortsYes, bind: ForwardEndpoint{Host: "127.0.0.1", Port: 0, HasHost: true}, wantBindPref: ":0"},

		// GatewayPorts=clientspecified honors :port / *:port ("") and explicit IP, defaults bare port to "localhost".
		{mode: GatewayPortsClientSpecified, bind: ForwardEndpoint{Port: 0, HasHost: false}, wantBindPref: "localhost:0"},
		{mode: GatewayPortsClientSpecified, bind: ForwardEndpoint{Port: 0, HasHost: true, Wildcard: true}, wantBindPref: ":0"},
		{mode: GatewayPortsClientSpecified, bind: ForwardEndpoint{Host: "127.0.0.1", Port: 0, HasHost: true}, wantBindPref: "127.0.0.1:0"},
	}

	for i, tc := range cases {
		t.Run(tc.mode+"_"+strconv.Itoa(i), func(t *testing.T) {
			fix, err := sshfixture.New(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fix.Close() }()
			host, portStr, _ := net.SplitHostPort(fix.Address)
			port, _ := strconv.Atoi(portStr)

			provider := &mapTestProvider{
				configs: map[string]*ClientConfig{
					"node": {
						NodeID:   "node",
						Address:  host,
						Port:     port,
						User:     "ops",
						AuthType: "password",
						Password: sshfixture.Password,
						Options:  MustOptions(OptionGatewayPorts, tc.mode),
					},
				},
			}
			c := NewConnector(provider, WithHostKeyVerifier(trustAnyFixtureHostKey{}))
			defer func() { _ = c.CloseAll() }()

			client, err := c.Connect(ctx, "node")
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}

			fwdCtx, cancelFwd := context.WithCancel(ctx)
			fwd, err := client.RemoteForwardEndpoint(fwdCtx, ForwardSpec{
				Bind: tc.bind,
				Dest: ForwardEndpoint{Host: "127.0.0.1", Port: uint16(locPort), HasHost: true},
			})
			if err != nil {
				cancelFwd()
				t.Fatalf("RemoteForwardEndpoint: %v", err)
			}
			cancelFwd()
			_ = fwd.Wait()

			reqs := fix.RequestedForwards()
			if len(reqs) != 1 || reqs[0] != tc.wantBindPref {
				t.Fatalf("mode=%s bind=%+v: RequestedForwards() = %v, want [%s]", tc.mode, tc.bind, reqs, tc.wantBindPref)
			}

			// Also verify ParseForwardSpecs("-R ...") round-trip with RemoteListenAddressForMode!
			muxSrv := &MuxServer{gatewayPortsMode: tc.mode, dialNetwork: "tcp"}
			muxHost, muxPort := tc.bind.MuxListenEndpoint()
			_, muxListenAddr, _, err := muxSrv.resolveMuxForwardListen(MUX_FWD_REMOTE, muxHost, muxPort)
			if err != nil || muxListenAddr != tc.wantBindPref {
				t.Fatalf("MuxServer.resolveMuxForwardListen(mode=%s, host=%q) = (%q, %v), want %q", tc.mode, muxHost, muxListenAddr, err, tc.wantBindPref)
			}
		})
	}

	// Verify ParseRemoteForwardSpec preserves leading ":port:..." vs "*:port:..." vs bare "port:...".
	specLeadingColon, err := ParseRemoteForwardSpec(":8080:127.0.0.1:80")
	if err != nil {
		t.Fatalf("ParseRemoteForwardSpec(:8080:...): %v", err)
	}
	if _, addr := specLeadingColon.Bind.RemoteListenAddressForMode(GatewayPortsClientSpecified, "tcp"); addr != ":8080" {
		t.Fatalf("clientspecified leading colon addr = %q, want :8080", addr)
	}
	if _, addr := specLeadingColon.Bind.RemoteListenAddressForMode(GatewayPortsNo, "tcp"); addr != "localhost:8080" {
		t.Fatalf("GatewayPorts=no leading colon addr = %q, want localhost:8080", addr)
	}

	specBare, err := ParseRemoteForwardSpec("8080:127.0.0.1:80")
	if err != nil {
		t.Fatalf("ParseRemoteForwardSpec(8080:...): %v", err)
	}
	if _, addr := specBare.Bind.RemoteListenAddressForMode(GatewayPortsClientSpecified, "tcp"); addr != "localhost:8080" {
		t.Fatalf("clientspecified bare port addr = %q, want localhost:8080", addr)
	}
	if _, addr := specBare.Bind.RemoteListenAddressForMode(GatewayPortsYes, "tcp"); addr != ":8080" {
		t.Fatalf("GatewayPorts=yes bare port addr = %q, want :8080", addr)
	}
}

type mapTestProvider struct {
	configs map[string]*ClientConfig
}

func (p *mapTestProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	cfg, ok := p.configs[nodeID]
	if !ok || cfg == nil {
		return nil, errors.New("node not found")
	}
	cloned := *cfg
	cloned.KeyPaths = slices.Clone(cfg.KeyPaths)
	cloned.Options = cfg.Options.Clone()
	return &cloned, nil
}

type trustAnyFixtureHostKey struct{}

func (trustAnyFixtureHostKey) Verify(ctx context.Context, _ HostKeyRequest, _ cryptoSSH.PublicKey) error {
	return ctx.Err()
}
