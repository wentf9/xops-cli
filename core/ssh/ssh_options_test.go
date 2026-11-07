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
	"reflect"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func TestOptionRegistry_LookupAndNormalization(t *testing.T) {
	cases := []struct {
		key      string
		rawValue string
		wantKey  string
		wantVal  string
	}{
		{"control_master", "Auto", OptionControlMaster, "auto"},
		{"ControlMaster", "YES", OptionControlMaster, "yes"},
		{"control_path", "~/.ssh/cm-%C", OptionControlPath, "~/.ssh/cm-%C"},
		{"ControlPath", "NONE", OptionControlPath, "none"},
		{"control_persist", "10m", OptionControlPersist, "10m"},
		{"ControlPersist", "Yes", OptionControlPersist, "yes"},
		{"connect_timeout", "15", OptionConnectTimeout, "15"},
		{"ConnectTimeout", "10s", OptionConnectTimeout, "10s"},
		{"server_alive_interval", "30", OptionServerAliveInterval, "30"},
		{"ServerAliveInterval", "1m", OptionServerAliveInterval, "1m"},
		{"server_alive_count_max", "3", OptionServerAliveCountMax, "3"},
		{"ServerAliveCountMax", "5", OptionServerAliveCountMax, "5"},
		{"tcp_keep_alive", "yes", OptionTCPKeepAlive, "yes"},
		{"TCPKeepAlive", "false", OptionTCPKeepAlive, "no"},
		{"strict_host_key_checking", "accept-new", OptionStrictHostKeyChecking, "accept-new"},
		{"StrictHostKeyChecking", "off", OptionStrictHostKeyChecking, "no"},
		{"user_known_hosts_file", "/dev/null", OptionUserKnownHostsFile, "/dev/null"},
		{"UserKnownHostsFile", "none", OptionUserKnownHostsFile, "none"},
		{"pubkey_authentication", "no", OptionPubkeyAuthentication, "no"},
		{"PubkeyAuthentication", "true", OptionPubkeyAuthentication, "yes"},
		{"password_authentication", "no", OptionPasswordAuthentication, "no"},
		{"PasswordAuthentication", "yes", OptionPasswordAuthentication, "yes"},
		{"kbd_interactive_authentication", "no", OptionKbdInteractiveAuthentication, "no"},
		{"KbdInteractiveAuthentication", "yes", OptionKbdInteractiveAuthentication, "yes"},
		{"ChallengeResponseAuthentication", "no", OptionKbdInteractiveAuthentication, "no"},
		{"identities_only", "yes", OptionIdentitiesOnly, "yes"},
		{"IdentitiesOnly", "no", OptionIdentitiesOnly, "no"},
		{"preferred_authentications", "PublicKey, Password", OptionPreferredAuthentications, "publickey,password"},
		{"PreferredAuthentications", "keyboard-interactive", OptionPreferredAuthentications, "keyboard-interactive"},
		{"batch_mode", "yes", OptionBatchMode, "yes"},
		{"BatchMode", "no", OptionBatchMode, "no"},
		{"host_key_algorithms", "+ssh-rsa", OptionHostKeyAlgorithms, "+ssh-rsa"},
		{"HostKeyAlgorithms", "ssh-ed25519,ecdsa-sha2-nistp256", OptionHostKeyAlgorithms, "ssh-ed25519,ecdsa-sha2-nistp256"},
		{"ciphers", "^aes128-gcm@openssh.com", OptionCiphers, "^aes128-gcm@openssh.com"},
		{"Ciphers", "chacha20-poly1305@openssh.com", OptionCiphers, "chacha20-poly1305@openssh.com"},
		{"macs", "-hmac-sha1", OptionMACs, "-hmac-sha1"},
		{"MACs", "hmac-sha2-256", OptionMACs, "hmac-sha2-256"},
		{"kex_algorithms", "curve25519-sha256", OptionKexAlgorithms, "curve25519-sha256"},
		{"KexAlgorithms", "+diffie-hellman-group14-sha256", OptionKexAlgorithms, "+diffie-hellman-group14-sha256"},
	}

	opts := &Options{}
	for _, tc := range cases {
		spec, ok := LookupOptionSpec(tc.key)
		if !ok {
			t.Fatalf("expected LookupOptionSpec(%q) to succeed", tc.key)
		}
		if spec.CanonicalKey != tc.wantKey {
			t.Fatalf("LookupOptionSpec(%q).CanonicalKey = %q, want %q", tc.key, spec.CanonicalKey, tc.wantKey)
		}
		if err := opts.Set(tc.key, tc.rawValue); err != nil {
			t.Fatalf("opts.Set(%q, %q) unexpected error: %v", tc.key, tc.rawValue, err)
		}
		if got := opts.Get(tc.wantKey); got != tc.wantVal {
			t.Fatalf("opts.Get(%q) after Set(%q, %q) = %q, want %q", tc.wantKey, tc.key, tc.rawValue, got, tc.wantVal)
		}
	}

	for _, removed := range []string{"compression", "Compression", "forward_agent", "ForwardAgent"} {
		if _, ok := LookupOptionSpec(removed); ok {
			t.Fatalf("expected %q to be removed from optionRegistry", removed)
		}
	}
}

func TestOptions_YAMLAndJSONSerialization(t *testing.T) {
	// Input YAML uses mixed snake_case and OpenSSH PascalCase
	rawYAML := `
ControlMaster: auto
control_path: ~/.ssh/cm-%r@%h:%p
ControlPersist: 10m
StrictHostKeyChecking: accept-new
ConnectTimeout: 15s
PreferredAuthentications:
  - publickey
  - password
`
	var opts Options
	if err := yaml.Unmarshal([]byte(rawYAML), &opts); err != nil {
		t.Fatalf("Unmarshal YAML failed: %v", err)
	}
	if opts.ControlMaster() != ControlMasterAuto {
		t.Fatalf("ControlMaster = %q, want auto", opts.ControlMaster())
	}
	if opts.ControlPath() != "~/.ssh/cm-%r@%h:%p" {
		t.Fatalf("ControlPath = %q", opts.ControlPath())
	}
	if opts.ControlPersist() != "10m" {
		t.Fatalf("ControlPersist = %q", opts.ControlPersist())
	}
	if opts.StrictHostKeyChecking() != StrictHostKeyCheckingAcceptNew {
		t.Fatalf("StrictHostKeyChecking = %q", opts.StrictHostKeyChecking())
	}
	if opts.ConnectTimeout() != 15*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 15s", opts.ConnectTimeout())
	}
	if got := opts.PreferredAuthentications(); !reflect.DeepEqual(got, []string{"publickey", "password"}) {
		t.Fatalf("PreferredAuthentications = %v", got)
	}

	// Marshal back to YAML must always emit canonical snake_case keys
	marshaledYAML, err := yaml.Marshal(&opts)
	if err != nil {
		t.Fatalf("Marshal YAML failed: %v", err)
	}
	yamlStr := string(marshaledYAML)
	for _, wantKey := range []string{
		"control_master: auto",
		"control_path: ~/.ssh/cm-%r@%h:%p",
		"control_persist: 10m",
		"connect_timeout: 15s",
		"strict_host_key_checking: accept-new",
		"preferred_authentications: publickey,password",
	} {
		if !strings.Contains(yamlStr, wantKey) {
			t.Fatalf("expected marshaled YAML to contain %q, got:\n%s", wantKey, yamlStr)
		}
	}
	if strings.Contains(yamlStr, "ControlMaster") || strings.Contains(yamlStr, "StrictHostKeyChecking") {
		t.Fatalf("expected marshaled YAML to use snake_case only, got:\n%s", yamlStr)
	}

	// JSON round-trip with OpenSSH keys in input and snake_case in output
	rawJSON := `{"ControlMaster":"auto","ControlPath":"~/.ssh/cm-%C","BatchMode":true,"ConnectTimeout":20}`
	var jsonOpts Options
	if err := json.Unmarshal([]byte(rawJSON), &jsonOpts); err != nil {
		t.Fatalf("Unmarshal JSON failed: %v", err)
	}
	if !jsonOpts.BatchMode() || jsonOpts.ConnectTimeout() != 20*time.Second {
		t.Fatalf("unexpected jsonOpts: %+v", jsonOpts)
	}
	outJSON, err := json.Marshal(&jsonOpts)
	if err != nil {
		t.Fatalf("Marshal JSON failed: %v", err)
	}
	if !strings.Contains(string(outJSON), `"control_master":"auto"`) || !strings.Contains(string(outJSON), `"batch_mode":"yes"`) {
		t.Fatalf("unexpected marshaled JSON: %s", string(outJSON))
	}
}

func TestOptions_RejectsUnknownAndDuplicateKeys(t *testing.T) {
	var opts Options
	err := yaml.Unmarshal([]byte("unknown_ssh_option: foo\n"), &opts)
	if err == nil || !strings.Contains(err.Error(), "unknown ssh option") {
		t.Fatalf("expected unknown ssh option error, got: %v", err)
	}

	// Duplicate canonical key via snake_case + PascalCase in same YAML block
	dupYAML := "control_master: auto\nControlMaster: no\n"
	err = yaml.Unmarshal([]byte(dupYAML), &opts)
	if err == nil || !strings.Contains(err.Error(), "duplicate ssh option") {
		t.Fatalf("expected duplicate ssh option error, got: %v", err)
	}
}

func TestOptions_InheritanceAndControlBridge(t *testing.T) {
	global := MustOptions(
		OptionControlMaster, "auto",
		OptionControlPath, "~/.ssh/cm-%C",
		OptionControlPersist, "10m",
		OptionConnectTimeout, "20s",
		OptionStrictHostKeyChecking, "accept-new",
	)
	node := MustOptions(
		OptionControlPersist, "30m",
		OptionBatchMode, "yes",
	)
	cli := MustOptions(
		OptionConnectTimeout, "5s",
	)

	eff, err := EffectiveOptions(cli, node, global)
	if err != nil {
		t.Fatalf("EffectiveOptions failed: %v", err)
	}
	if err := eff.ValidateEffective(); err != nil {
		t.Fatalf("ValidateEffective failed: %v", err)
	}
	if eff.ControlMaster() != ControlMasterAuto {
		t.Fatalf("ControlMaster = %q", eff.ControlMaster())
	}
	if eff.ControlPersist() != "30m" {
		t.Fatalf("ControlPersist = %q, want 30m", eff.ControlPersist())
	}
	if eff.ConnectTimeout() != 5*time.Second {
		t.Fatalf("ConnectTimeout = %v, want 5s", eff.ConnectTimeout())
	}
	if !eff.BatchMode() {
		t.Fatal("expected BatchMode = true")
	}

	ctrl := eff.ControlConfig()
	if ctrl == nil || ctrl.Master != ControlMasterAuto || ctrl.Path != "~/.ssh/cm-%C" || ctrl.Persist != "30m" {
		t.Fatalf("unexpected ControlConfig: %+v", ctrl)
	}
}

func TestOptions_ControlPathNoneNormalization(t *testing.T) {
	global := MustOptions(
		OptionControlMaster, "auto",
		OptionControlPath, "~/.ssh/cm-%C",
		OptionControlPersist, "10m",
	)
	// ControlPath=none disables multiplexing even when parent has ControlMaster=auto
	disableMux := MustOptions(
		OptionControlPath, "none",
	)
	effDisabled, err := ResolveOptions(disableMux, global)
	if err != nil {
		t.Fatalf("ResolveOptions failed: %v", err)
	}
	if err := effDisabled.ValidateEffective(); err != nil {
		t.Fatalf("ValidateEffective with ControlPath=none failed: %v", err)
	}
	if effDisabled.ControlConfig().IsEnabled() {
		t.Fatalf("expected ControlPath=none to disable multiplexing, got: %+v", effDisabled.ControlConfig())
	}

	// M3: Child setting ControlMaster=yes over inherited ControlPath=none must normalize to disabled
	childMasterOnly := MustOptions(
		OptionControlMaster, "yes",
	)
	effInheritedNone, err := ResolveOptions(childMasterOnly, disableMux)
	if err != nil {
		t.Fatalf("ResolveOptions with inherited ControlPath=none failed: %v", err)
	}
	if err := effInheritedNone.ValidateEffective(); err != nil {
		t.Fatalf("ValidateEffective with inherited ControlPath=none failed: %v", err)
	}
	if effInheritedNone.ControlConfig().IsEnabled() {
		t.Fatalf("expected inherited ControlPath=none to disable multiplexing even with child ControlMaster=yes, got: %+v", effInheritedNone.ControlConfig())
	}

	// M4 (Root Cause 2): Higher tier overriding ControlPath over a middle tier's ControlPath=none
	// must preserve the lower tier's ControlMaster=auto instead of prematurely zeroing it out.
	tier1PathOverride := MustOptions(OptionControlPath, "/tmp/override.sock")
	effMultiLayer, err := EffectiveOptions(tier1PathOverride, disableMux, global)
	if err != nil {
		t.Fatalf("EffectiveOptions multi-layer failed: %v", err)
	}
	if effMultiLayer.ControlMaster() != ControlMasterAuto || effMultiLayer.ControlPath() != "/tmp/override.sock" || effMultiLayer.ControlPersist() != "10m" {
		t.Fatalf("expected Tier 1 path override to preserve Tier 3 ControlMaster=auto and ControlPersist=10m, got %+v", effMultiLayer.ControlConfig())
	}
}

func TestResolveAlgorithmList(t *testing.T) {
	defaults := []string{"alg-a", "alg-b", "alg-c"}

	// Explicit list
	got, err := ResolveAlgorithmList("alg-c,alg-a", defaults)
	if err != nil || !reflect.DeepEqual(got, []string{"alg-c", "alg-a"}) {
		t.Fatalf("explicit list got %v, err %v", got, err)
	}

	// +append
	got, err = ResolveAlgorithmList("+alg-d,alg-b", defaults)
	if err != nil || !reflect.DeepEqual(got, []string{"alg-a", "alg-b", "alg-c", "alg-d"}) {
		t.Fatalf("+append got %v, err %v", got, err)
	}

	// ^prepend
	got, err = ResolveAlgorithmList("^alg-d,alg-c", defaults)
	if err != nil || !reflect.DeepEqual(got, []string{"alg-d", "alg-c", "alg-a", "alg-b"}) {
		t.Fatalf("^prepend got %v, err %v", got, err)
	}

	// -remove
	got, err = ResolveAlgorithmList("-alg-b", defaults)
	if err != nil || !reflect.DeepEqual(got, []string{"alg-a", "alg-c"}) {
		t.Fatalf("-remove got %v, err %v", got, err)
	}

	// -remove all fails
	if _, err := ResolveAlgorithmList("-alg-a,alg-b,alg-c", defaults); err == nil {
		t.Fatal("expected error when removing all algorithms")
	}
}

func TestConnector_RuntimeOptions_HostKeyAndAlgorithmsAndAuth(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := signer.PublicKey()

	tmpDir := t.TempDir()
	khFile := filepath.Join(tmpDir, "known_hosts")
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	connector := NewConnector(nil, WithEnvironment(Environment{
		HomeDir:        tmpDir,
		KnownHostsFile: khFile,
	}))

	// 1. StrictHostKeyChecking=no + UserKnownHostsFile=none bypasses verification without creating known_hosts
	cfgNo := &ClientConfig{
		NodeID:  "node-no",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, "none",
			OptionBatchMode, "yes",
		),
	}
	cbNo, err := connector.getHostKeyCallback(ctx, nil, cfgNo)
	if err != nil {
		t.Fatalf("getHostKeyCallback(StrictHostKeyChecking=no) error: %v", err)
	}
	if err := cbNo("10.0.0.1:22", remoteAddr, pubKey); err != nil {
		t.Fatalf("expected StrictHostKeyChecking=no to accept unknown host key, got: %v", err)
	}
	if _, err := os.Stat(khFile); !os.IsNotExist(err) {
		t.Fatalf("expected UserKnownHostsFile=none not to create %s", khFile)
	}

	// 2. StrictHostKeyChecking=yes rejects unknown host key
	cfgYes := &ClientConfig{
		NodeID:  "node-yes",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "yes",
			OptionUserKnownHostsFile, khFile,
		),
	}
	cbYes, err := connector.getHostKeyCallback(ctx, nil, cfgYes)
	if err != nil {
		t.Fatalf("getHostKeyCallback(StrictHostKeyChecking=yes) error: %v", err)
	}
	if err := cbYes("10.0.0.1:22", remoteAddr, pubKey); err == nil {
		t.Fatal("expected StrictHostKeyChecking=yes to reject unknown host key")
	}

	// 3. StrictHostKeyChecking=ask with BatchMode=yes rejects unknown host key without prompting
	cfgBatchAsk := &ClientConfig{
		NodeID:  "node-batch-ask",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "ask",
			OptionBatchMode, "yes",
			OptionUserKnownHostsFile, khFile,
		),
	}
	cbBatchAsk, err := connector.getHostKeyCallback(ctx, nil, cfgBatchAsk)
	if err != nil {
		t.Fatalf("getHostKeyCallback(ask+BatchMode) error: %v", err)
	}
	if err := cbBatchAsk("10.0.0.1:22", remoteAddr, pubKey); err == nil {
		t.Fatal("expected StrictHostKeyChecking=ask with BatchMode=yes to reject unknown host key")
	}

	// 4. StrictHostKeyChecking=accept-new accepts and persists unknown host key to UserKnownHostsFile,
	//    after which StrictHostKeyChecking=yes succeeds!
	cfgAcceptNew := &ClientConfig{
		NodeID:  "node-accept-new",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, khFile,
		),
	}
	cbAcceptNew, err := connector.getHostKeyCallback(ctx, nil, cfgAcceptNew)
	if err != nil {
		t.Fatalf("getHostKeyCallback(accept-new) error: %v", err)
	}
	if err := cbAcceptNew("10.0.0.1:22", remoteAddr, pubKey); err != nil {
		t.Fatalf("expected StrictHostKeyChecking=accept-new to accept new host key, got: %v", err)
	}
	cbYesAfter, err := connector.getHostKeyCallback(ctx, nil, cfgYes)
	if err != nil {
		t.Fatalf("getHostKeyCallback(yes after accept-new) error: %v", err)
	}
	if err := cbYesAfter("10.0.0.1:22", remoteAddr, pubKey); err != nil {
		t.Fatalf("expected StrictHostKeyChecking=yes to accept persisted host key, got: %v", err)
	}

	verifyRuntimeSSHConfigAlgorithmsAndAuth(t, ctx, connector)
}

func verifyRuntimeSSHConfigAlgorithmsAndAuth(t *testing.T, ctx context.Context, connector *Connector) {
	t.Helper()
	// 5. buildSSHConfig applies Ciphers, MACs, KexAlgorithms, HostKeyAlgorithms, and auth filtering
	cfgAlgs := &ClientConfig{
		NodeID:   "node-algs",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "password",
		Password: "secret",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionCiphers, "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com",
			OptionMACs, "hmac-sha2-256-etm@openssh.com",
			OptionKexAlgorithms, "curve25519-sha256",
			OptionHostKeyAlgorithms, "ssh-ed25519",
		),
	}
	sshCfg, cleanup, err := connector.buildSSHConfig(ctx, cfgAlgs, nil, func() {}, nil)
	if err != nil {
		t.Fatalf("buildSSHConfig failed: %v", err)
	}
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if !reflect.DeepEqual(sshCfg.Ciphers, []string{"aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"}) {
		t.Fatalf("unexpected Ciphers: %v", sshCfg.Ciphers)
	}
	if !reflect.DeepEqual(sshCfg.MACs, []string{"hmac-sha2-256-etm@openssh.com"}) {
		t.Fatalf("unexpected MACs: %v", sshCfg.MACs)
	}
	if !reflect.DeepEqual(sshCfg.KeyExchanges, []string{"curve25519-sha256"}) {
		t.Fatalf("unexpected KeyExchanges: %v", sshCfg.KeyExchanges)
	}
	if !reflect.DeepEqual(sshCfg.HostKeyAlgorithms, []string{"ssh-ed25519"}) {
		t.Fatalf("unexpected HostKeyAlgorithms: %v", sshCfg.HostKeyAlgorithms)
	}

	// 6. PasswordAuthentication=no blocks password auth
	cfgNoPass := &ClientConfig{
		NodeID:   "node-nopass",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "password",
		Password: "secret",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionPasswordAuthentication, "no",
		),
	}
	if _, _, err := connector.buildSSHConfig(ctx, cfgNoPass, nil, func() {}, nil); err == nil {
		t.Fatal("expected PasswordAuthentication=no to reject password authentication")
	}
}

type stubAlgorithmVerifier struct {
	HostKeyVerifier
	algs []string
}

func (s stubAlgorithmVerifier) HostKeyAlgorithms(context.Context, HostKeyRequest) ([]string, error) {
	return s.algs, nil
}

func TestConnector_HostKeyMismatchWithStrictNo_DisablesPasswordAndKbdInteractive(t *testing.T) {
	ctx := context.Background()
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer1, err := cryptoSSH.NewSignerFromKey(priv1)
	if err != nil {
		t.Fatal(err)
	}
	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer2, err := cryptoSSH.NewSignerFromKey(priv2)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	kh1 := filepath.Join(tmpDir, "kh1")
	kh2 := filepath.Join(tmpDir, "kh-%h")
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 22}

	connector := NewConnector(nil, WithEnvironment(Environment{
		HomeDir:        tmpDir,
		KnownHostsFile: kh1,
	}))

	// Persist signer1 under kh-10.0.0.1 via space-separated UserKnownHostsFile with %h token
	cfgAccept := &ClientConfig{
		NodeID:  "node-1",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "accept-new",
			OptionUserKnownHostsFile, kh2+" "+kh1,
		),
	}
	cbAccept, err := connector.getHostKeyCallback(ctx, nil, cfgAccept)
	if err != nil {
		t.Fatalf("getHostKeyCallback(accept-new) error: %v", err)
	}
	if err := cbAccept("10.0.0.1:22", remoteAddr, signer1.PublicKey()); err != nil {
		t.Fatalf("cbAccept failed: %v", err)
	}
	expandedKH2 := filepath.Join(tmpDir, "kh-10.0.0.1")
	if _, err := os.Stat(expandedKH2); err != nil {
		t.Fatalf("expected %s to be created on write: %v", expandedKH2, err)
	}

	// Now present mismatched signer2 with StrictHostKeyChecking=no:
	// handshake callback accepts it, sets hostKeyChanged=true, and disables password/kbd-interactive auth.
	cfgMismatchNo := &ClientConfig{
		NodeID:   "node-1",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "password",
		Password: "secret",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, kh2+" "+kh1,
		),
	}
	sshCfg, cleanup, err := connector.buildSSHConfig(ctx, cfgMismatchNo, nil, func() {}, nil)
	if err != nil {
		t.Fatalf("buildSSHConfig failed: %v", err)
	}
	if cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if err := sshCfg.HostKeyCallback("10.0.0.1:22", remoteAddr, signer2.PublicKey()); err != nil {
		t.Fatalf("expected StrictHostKeyChecking=no to allow mismatched key at callback stage, got: %v", err)
	}
	// 1. Explicit password mode: AuthCallback must fail closed with ErrHostKeyMismatch
	if _, authErr := sshCfg.AuthCallback(&cryptoSSH.ClientAuthContext{AllowedMethods: []string{"password"}}); !errors.Is(authErr, ErrHostKeyMismatch) {
		t.Fatalf("expected password AuthCallback after host key mismatch to return ErrHostKeyMismatch, got: %v", authErr)
	}

	// 2. Explicit keyboard-interactive mode: AuthCallback must fail closed with ErrHostKeyMismatch
	cfgKbdMismatch := &ClientConfig{
		NodeID:   "node-1",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "keyboard-interactive",
		Password: "secret",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, kh2+" "+kh1,
		),
	}
	sshCfgKbd, cleanupKbd, err := connector.buildSSHConfig(ctx, cfgKbdMismatch, nil, func() {}, nil)
	if err != nil {
		t.Fatalf("buildSSHConfig(keyboard-interactive) failed: %v", err)
	}
	if cleanupKbd != nil {
		defer func() { _ = cleanupKbd() }()
	}
	if err := sshCfgKbd.HostKeyCallback("10.0.0.1:22", remoteAddr, signer2.PublicKey()); err != nil {
		t.Fatalf("HostKeyCallback(kbd) failed: %v", err)
	}
	if _, authErr := sshCfgKbd.AuthCallback(&cryptoSSH.ClientAuthContext{AllowedMethods: []string{"keyboard-interactive", "password"}}); !errors.Is(authErr, ErrHostKeyMismatch) {
		t.Fatalf("expected keyboard-interactive AuthCallback after host key mismatch to return ErrHostKeyMismatch, got: %v", authErr)
	}

	// 3. Auto mode: AuthCallback must skip password/kbd-interactive and return ErrHostKeyMismatch
	cfgAutoMismatch := &ClientConfig{
		NodeID:   "node-1",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "auto",
		Password: "secret",
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, kh2+" "+kh1,
		),
	}
	sshCfgAuto, cleanupAuto, err := connector.buildSSHConfig(ctx, cfgAutoMismatch, nil, func() {}, nil)
	if err != nil {
		t.Fatalf("buildSSHConfig(auto) failed: %v", err)
	}
	if cleanupAuto != nil {
		defer func() { _ = cleanupAuto() }()
	}
	if err := sshCfgAuto.HostKeyCallback("10.0.0.1:22", remoteAddr, signer2.PublicKey()); err != nil {
		t.Fatalf("HostKeyCallback(auto) failed: %v", err)
	}
	if _, authErr := sshCfgAuto.AuthCallback(&cryptoSSH.ClientAuthContext{AllowedMethods: []string{"password", "keyboard-interactive"}}); !errors.Is(authErr, ErrHostKeyMismatch) {
		t.Fatalf("expected auto AuthCallback after host key mismatch to return ErrHostKeyMismatch, got: %v", authErr)
	}

	// 4. Key mode with PartialSuccess MFA transition: stage 0 allows publickey, stage 1 blocks keyboard-interactive with ErrHostKeyMismatch
	verifyKeyPartialSuccessMismatch(t, ctx, connector, tmpDir, priv1, signer2.PublicKey(), remoteAddr, kh2+" "+kh1)
}

func verifyKeyPartialSuccessMismatch(
	t *testing.T,
	ctx context.Context,
	connector *Connector,
	tmpDir string,
	privKey ed25519.PrivateKey,
	mismatchedServerKey cryptoSSH.PublicKey,
	remoteAddr net.Addr,
	userKH string,
) {
	t.Helper()
	pemBlock, err := cryptoSSH.MarshalPrivateKey(privKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(tmpDir, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatal(err)
	}
	cfgKeyMismatch := &ClientConfig{
		NodeID:   "node-1",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "key",
		KeyPath:  keyFile,
		Options: MustOptions(
			OptionStrictHostKeyChecking, "no",
			OptionUserKnownHostsFile, userKH,
		),
	}
	sshCfgKey, cleanupKey, err := connector.buildSSHConfig(ctx, cfgKeyMismatch, nil, func() {}, nil)
	if err != nil {
		t.Fatalf("buildSSHConfig(key) failed: %v", err)
	}
	if cleanupKey != nil {
		defer func() { _ = cleanupKey() }()
	}
	if err := sshCfgKey.HostKeyCallback("10.0.0.1:22", remoteAddr, mismatchedServerKey); err != nil {
		t.Fatalf("HostKeyCallback(key) failed: %v", err)
	}
	// Stage 0 (publickey): allowed (returns nil, nil so ClientConfig.Auth[0] runs)
	if m, err := sshCfgKey.AuthCallback(&cryptoSSH.ClientAuthContext{AllowedMethods: []string{"publickey"}}); err != nil || m != nil {
		t.Fatalf("expected stage 0 publickey to proceed, got method=%v err=%v", m, err)
	}
	// Stage 1 (after publickey PartialSuccess, server asks for keyboard-interactive): must fail closed with ErrHostKeyMismatch
	if _, err := sshCfgKey.AuthCallback(&cryptoSSH.ClientAuthContext{
		PartialSuccessMethods: []string{"publickey"},
		AllowedMethods:        []string{"keyboard-interactive"},
	}); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("expected stage 1 MFA keyboard-interactive after host key mismatch to return ErrHostKeyMismatch, got: %v", err)
	}
}

func TestConnector_HostKeyAlgorithmsIntersectionWithVerifier(t *testing.T) {
	ctx := context.Background()
	connector := NewConnector(nil, WithHostKeyVerifier(stubAlgorithmVerifier{
		algs: []string{"ssh-ed25519", "ecdsa-sha2-nistp256"},
	}))

	cfgOverlap := &ClientConfig{
		Address: "10.0.0.1",
		Port:    22,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "rsa-sha2-512,ssh-ed25519",
		),
	}
	algs, err := connector.getHostKeyAlgorithms(ctx, nil, cfgOverlap)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms with overlap failed: %v", err)
	}
	if !reflect.DeepEqual(algs, []string{"ssh-ed25519"}) {
		t.Fatalf("expected intersection [ssh-ed25519], got %v", algs)
	}

	cfgDisjoint := &ClientConfig{
		Address: "10.0.0.1",
		Port:    22,
		Options: MustOptions(
			OptionHostKeyAlgorithms, "rsa-sha2-512",
		),
	}
	if _, err := connector.getHostKeyAlgorithms(ctx, nil, cfgDisjoint); err == nil {
		t.Fatal("expected error when HostKeyAlgorithms has no overlap with verifier algorithms")
	}
}

func TestPlanAndIdentitiesOnlyAndKnownHostsExpansion(t *testing.T) {
	// 1. Root Cause 3: clientConfigFromPlan strips OptionClassMux while retaining transport/auth options
	planCfg := ConnectionConfig{
		NodeID:  "node-plan",
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(
			OptionControlMaster, "auto",
			OptionControlPath, "~/.ssh/cm-%C",
			OptionControlPersist, "10m",
			OptionConnectTimeout, "12s",
		),
	}
	converted := clientConfigFromPlan(planCfg)
	if converted.Options == nil || converted.Options.ConnectTimeout() != 12*time.Second {
		t.Fatalf("expected non-mux option ConnectTimeout=12s to be preserved, got %+v", converted.Options)
	}
	if converted.Options.ControlConfig() != nil {
		t.Fatalf("expected clientConfigFromPlan to strip OptionClassMux, got %+v", converted.Options.ControlConfig())
	}

	// 2. Root Cause 1 (M2): IdentitiesOnly=yes keeps DefaultKeyPaths when no explicit KeyPath is set,
	// and skips DefaultKeyPaths when an explicit KeyPath is set.
	tmpDir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock, err := cryptoSSH.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	defaultKey := filepath.Join(tmpDir, "default_id")
	explicitKey := filepath.Join(tmpDir, "explicit_id")
	if err := os.WriteFile(defaultKey, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicitKey, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatal(err)
	}

	planDefault := buildAutoAuthPlan(context.Background(), AutoAuthOptions{
		DefaultKeyPaths: []string{defaultKey},
		SSHOptions: MustOptions(
			OptionIdentitiesOnly, "yes",
			OptionPasswordAuthentication, "no",
			OptionKbdInteractiveAuthentication, "no",
		),
	})
	if len(planDefault.candidates) != 1 || !strings.Contains(planDefault.candidates[0].label, "default key") {
		t.Fatalf("expected IdentitiesOnly=yes without explicit key to keep DefaultKeyPaths, got %+v", planDefault.candidates)
	}

	planExplicit := buildAutoAuthPlan(context.Background(), AutoAuthOptions{
		KeyPath:         explicitKey,
		DefaultKeyPaths: []string{defaultKey},
		SSHOptions: MustOptions(
			OptionIdentitiesOnly, "yes",
			OptionPasswordAuthentication, "no",
			OptionKbdInteractiveAuthentication, "no",
		),
	})
	if len(planExplicit.candidates) != 1 || !strings.Contains(planExplicit.candidates[0].label, "explicit key") {
		t.Fatalf("expected IdentitiesOnly=yes with explicit key to skip DefaultKeyPaths, got %+v", planExplicit.candidates)
	}

	// 3. Root Cause 5: expandKnownHostsPath expands ${VAR} without % and fails closed on invalid token %k
	envWithLookup := Environment{
		HomeDir: tmpDir,
		LookupEnv: func(key string) (string, bool) {
			if key == "XOPS_TEST_KH_DIR" {
				return tmpDir, true
			}
			return "", false
		},
	}
	expandedEnv, err := expandKnownHostsPath("${XOPS_TEST_KH_DIR}/known_hosts", envWithLookup, TargetContext{})
	if err != nil || expandedEnv != filepath.Join(tmpDir, "known_hosts") {
		t.Fatalf("expected ${XOPS_TEST_KH_DIR} to expand, got %q, err=%v", expandedEnv, err)
	}
	if _, err := expandKnownHostsPath(filepath.Join(tmpDir, "kh-%k"), envWithLookup, TargetContext{}); err == nil {
		t.Fatal("expected unsupported token %k in expandKnownHostsPath to return an error")
	}
}

func TestEdgeCases_KnownHostsDir_AgentIdentitiesOnly_AlgoDefaults_PlanNormalization(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	connector := NewConnector(nil, WithEnvironment(Environment{
		HomeDir:        tmpDir,
		KnownHostsFile: filepath.Join(tmpDir, "known_hosts"),
	}))

	// 1. UserKnownHostsFile pointing to a directory must fail closed
	dirCfg := &ClientConfig{
		Address: "10.0.0.1",
		Port:    22,
		User:    "root",
		Options: MustOptions(OptionUserKnownHostsFile, tmpDir),
	}
	if _, err := connector.getHostKeyCallback(ctx, nil, dirCfg); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("expected UserKnownHostsFile directory error, got: %v", err)
	}

	// 2. AuthType == "agent" must respect IdentitiesOnly=yes
	agentCfg := &ClientConfig{
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "agent",
		Options:  MustOptions(OptionIdentitiesOnly, "yes"),
	}
	if _, _, err := connector.buildSSHConfig(ctx, agentCfg, nil, func() {}, nil); err == nil || !strings.Contains(err.Error(), "IdentitiesOnly=yes") {
		t.Fatalf("expected AuthType=agent with IdentitiesOnly=yes to fail, got: %v", err)
	}

	// 3. Removing all default secure Ciphers via "-" must fail during option normalization
	allDefaultCiphers := strings.Join(cryptoSSH.SupportedAlgorithms().Ciphers, ",")
	opts := &Options{}
	if err := opts.Set(OptionCiphers, "-"+allDefaultCiphers); err == nil {
		t.Fatal("expected removing all default secure ciphers to fail normalization")
	}

	// 4. MergeOptionLayers keeps ImplicitTier4=false when a higher layer sets ControlPersist
	t2 := MustOptions(OptionControlPersist, "10m")
	t4 := MustOptions(OptionControlMaster, "auto", OptionControlPath, "/tmp/cm-%C")
	t4.ImplicitTier4 = true
	merged := MergeOptionLayers(t2, t4)
	if merged == nil || merged.ImplicitTier4 {
		t.Fatalf("expected ImplicitTier4=false when Tier 2 explicitly sets ControlPersist, got %+v", merged)
	}
	t2NoPersist := MustOptions(OptionConnectTimeout, "5s")
	mergedImplicit := MergeOptionLayers(t2NoPersist, t4)
	if mergedImplicit == nil || !mergedImplicit.ImplicitTier4 {
		t.Fatalf("expected ImplicitTier4=true when only Tier 4 provides mux options, got %+v", mergedImplicit)
	}

	// 5. normalizePlan clones Options and strips OptionClassMux before ConnectionKey hashing
	origOpts := MustOptions(
		OptionControlMaster, "auto",
		OptionControlPath, "/tmp/cm-%C",
		OptionConnectTimeout, "15s",
	)
	planWithMux := ConnectionPlan{
		Scope: "scope-1",
		Hops: []ConnectionConfig{{
			NodeID:  "n1",
			Address: "10.0.0.1",
			Port:    22,
			User:    "root",
			Options: origOpts,
		}},
	}
	planWithoutMux := ConnectionPlan{
		Scope: "scope-1",
		Hops: []ConnectionConfig{{
			NodeID:  "n1",
			Address: "10.0.0.1",
			Port:    22,
			User:    "root",
			Options: MustOptions(OptionConnectTimeout, "15s"),
		}},
	}
	key1, err := ConnectionKey(planWithMux)
	if err != nil {
		t.Fatalf("ConnectionKey(planWithMux) failed: %v", err)
	}
	key2, err := ConnectionKey(planWithoutMux)
	if err != nil {
		t.Fatalf("ConnectionKey(planWithoutMux) failed: %v", err)
	}
	if key1 != key2 {
		t.Fatalf("expected ConnectionKey to ignore stripped OptionClassMux options, got %q != %q", key1, key2)
	}
}

type testOptionsPrompter struct {
	promptCalled  bool
	confirmCalled bool
	reportCalled  bool
}

func (p *testOptionsPrompter) PromptSecret(context.Context, SecretRequest) (string, error) {
	p.promptCalled = true
	return "should-not-be-used", nil
}

func (p *testOptionsPrompter) ConfirmSession(context.Context, string) (bool, error) {
	p.confirmCalled = true
	return true, nil
}

func (p *testOptionsPrompter) CredentialRecoveryAllowed() bool {
	return true
}

func (p *testOptionsPrompter) ReportCredentialFailure(context.Context, string) error {
	p.reportCalled = true
	return nil
}

type failingCredentialRecorder struct{}

func (failingCredentialRecorder) UpdateAuth(context.Context, string, string, string, string, string) (string, error) {
	return "", errors.New("save failed")
}

func (failingCredentialRecorder) UpdateSudo(context.Context, string, string, SudoMode, string) (string, error) {
	return "", errors.New("save failed")
}

type timeoutCheckingSecretResolver struct {
	observedRemaining time.Duration
}

func (r *timeoutCheckingSecretResolver) ResolveSecret(ctx context.Context, _ SecretRequest) ([]byte, error) {
	if dl, ok := ctx.Deadline(); ok {
		r.observedRemaining = time.Until(dl)
	}
	return []byte("secret-pwd"), nil
}

func TestBatchModeBlocksCredentialRecoveryAndResolveSecretHonorsConnectTimeout(t *testing.T) {
	ctx := context.Background()
	prompter := &testOptionsPrompter{}
	resolver := &timeoutCheckingSecretResolver{}

	conn := NewConnector(
		nil,
		WithSecretPrompter(prompter),
		WithSecretResolver(resolver),
		WithCredentialRecorder(failingCredentialRecorder{}),
	)
	defer func() { _ = conn.CloseAll() }()

	// 1. Explicit AuthType: "key" with encrypted key and BatchMode=yes must not enter recoverableKeyAuth or prompt
	pemData, _ := generateTestEncryptedKey(t, "correct-passphrase")
	encKeyPath := filepath.Join(t.TempDir(), "id_enc")
	if err := os.WriteFile(encKeyPath, pemData, 0600); err != nil {
		t.Fatalf("write encrypted key failed: %v", err)
	}
	keyCfg := &ClientConfig{
		NodeID:   "n-key-batch",
		Address:  "127.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "key",
		KeyPath:  encKeyPath,
		Options:  MustOptions(OptionBatchMode, "yes"),
	}
	// Clear resolver temporarily so resolveKeyAuth gets ErrInteractionRequired
	conn.secretResolver = rejectSecretResolver{}
	if _, _, err := conn.keyAuth(ctx, keyCfg, conn.getNodeSecretPrompter(keyCfg), nil); err == nil {
		t.Fatal("expected keyAuth with encrypted key and BatchMode=yes to fail without passphrase")
	}
	if prompter.promptCalled || prompter.reportCalled {
		t.Fatalf("expected BatchMode=yes to block prompt and recovery report in keyAuth, got prompt=%v report=%v", prompter.promptCalled, prompter.reportCalled)
	}

	// 2. recordAuthUpdate with BatchMode=yes must not invoke ReportCredentialFailure
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	saveCfg := &ClientConfig{
		NodeID:          "n-save-batch",
		Password:        "discovered",
		AuthUpdateToken: "tok-1",
		Options:         MustOptions(OptionBatchMode, "yes"),
	}
	if _, err := conn.recordAuthUpdate(ctx, "n-save-batch", saveCfg, c1); err == nil || errors.Is(err, errCredentialNotSaved) {
		t.Fatalf("expected hard save error without interactive recovery under BatchMode=yes, got %v", err)
	}
	if prompter.reportCalled {
		t.Fatal("expected ReportCredentialFailure not to be called under BatchMode=yes")
	}

	// 3. resolvePasswordAuth honors node ConnectTimeout via resolveSecret
	conn.secretResolver = resolver
	pwdCfg := &ClientConfig{
		NodeID:   "n-pwd-timeout",
		Address:  "127.0.0.1",
		Port:     22,
		User:     "root",
		AuthType: "password",
		Options:  MustOptions(OptionConnectTimeout, "3s"),
	}
	if _, err := conn.resolvePasswordAuth(pwdCfg); err != nil {
		t.Fatalf("resolvePasswordAuth failed: %v", err)
	}
	if resolver.observedRemaining <= 0 || resolver.observedRemaining > 3*time.Second {
		t.Fatalf("expected resolveSecret deadline bounded by 3s ConnectTimeout, got %v", resolver.observedRemaining)
	}
}

func TestClientBatchModeAndSnapshotCloningAndTargetTrustValidation(t *testing.T) {
	ctx := context.Background()
	prompter := &testOptionsPrompter{}

	cfg := &ClientConfig{
		NodeID:   "n1",
		Address:  "10.0.0.1",
		Port:     22,
		User:     "root",
		SudoMode: SudoModeSudo,
		Options: MustOptions(
			OptionBatchMode, "yes",
			OptionConnectTimeout, "9s",
			OptionStrictHostKeyChecking, "yes",
		),
	}
	client := newClientWithComponents(nil, nil, cfg, nil, nil, prompter, nil, "", 0, 0, nil)
	if client.handshakeTimeout != 9*time.Second {
		t.Fatalf("expected client.handshakeTimeout=9s from ConnectTimeout option, got %v", client.handshakeTimeout)
	}
	if _, err := client.resolvePrivilegeMaterial(ctx, SecretKindSudoPassword); !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired in BatchMode=yes privilege resolution, got %v", err)
	}
	if prompter.promptCalled {
		t.Fatal("expected SecretPrompter not to be called when BatchMode=yes")
	}

	// Verify confirmSessionCallback returns nil when BatchMode=yes
	conn := NewConnector(nil, WithSessionConfirmer(prompter))
	if cb := conn.confirmSessionCallback("n1", cfg); cb != nil {
		t.Fatal("expected confirmSessionCallback to be nil when BatchMode=yes")
	}

	// Verify Client.Config() and Client.ConnectionConfig() deep-clone Options
	snapCfg := client.Config()
	if snapCfg == nil || snapCfg.Options == nil || !snapCfg.Options.BatchMode() {
		t.Fatalf("expected Client.Config() to include cloned Options, got %+v", snapCfg)
	}
	_ = snapCfg.Options.Set(OptionBatchMode, "no")
	connCfg := client.ConnectionConfig()
	if connCfg.Options == nil || !connCfg.Options.BatchMode() {
		t.Fatalf("expected mutating Client.Config().Options not to affect client, got %+v", connCfg.Options)
	}
	_ = connCfg.Options.Set(OptionBatchMode, "no")
	if !client.ConnectionConfig().Options.BatchMode() {
		t.Fatal("expected mutating Client.ConnectionConfig().Options not to affect live client")
	}

	// Verify validateTargetCompatibility detects trust option drift
	newCfg := *cfg
	newCfg.Options = MustOptions(OptionStrictHostKeyChecking, "no")
	if err := validateTargetCompatibility(client.ConnectionConfig(), &newCfg); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch when StrictHostKeyChecking changed, got %v", err)
	}
}
