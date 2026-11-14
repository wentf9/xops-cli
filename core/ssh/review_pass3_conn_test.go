package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestPass3Conn_H1_CertAuthorityNeverAcceptedAsRawPlainHostKey(t *testing.T) {
	fix := newPhase3CertFixture(t)
	caLine := "@cert-authority *.corp.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n"
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 22}

	t.Run("user_only_clean_known_hosts_rejects_raw_ca_pubkey_and_blocks_tofu", func(t *testing.T) {
		dir := t.TempDir()
		userKH := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(userKH, []byte(caLine), 0o600); err != nil {
			t.Fatal(err)
		}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = userKH
		env.GlobalKnownHostsFiles = nil

		cfg := &ClientConfig{
			NodeID:  "corp-plain-ca",
			Address: "app.corp.example",
			Port:    22,
			User:    "alice",
			Options: MustOptions(
				OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
				OptionUserKnownHostsFile, userKH,
				OptionGlobalKnownHostsFile, "none",
			),
		}
		conn := NewConnector(nil, WithEnvironment(env))
		conn.AcceptNewHostKey.Store(true)
		t.Cleanup(func() { _ = conn.CloseAll() })

		_, _, rawCB, err := conn.openKnownHostsCallback(userKH, cfg)
		if err != nil {
			t.Fatalf("openKnownHostsCallback failed: %v", err)
		}
		rawErr := rawCB("app.corp.example:22", remote, fix.caSigner.PublicKey())
		keyErr, ok := errors.AsType[*knownhosts.KeyError](rawErr)
		if !ok || len(keyErr.Want) == 0 {
			t.Fatalf("raw CA key against @cert-authority: err=%v, want *knownhosts.KeyError with non-empty Want", rawErr)
		}

		stateCB, err := conn.getHostKeyCallbackWithState(t.Context(), nil, cfg, nil, nil)
		if err != nil {
			t.Fatalf("getHostKeyCallbackWithState failed: %v", err)
		}
		if err := stateCB("app.corp.example:22", remote, fix.caSigner.PublicKey()); !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("accept-new callback with raw CA key = %v, want ErrHostKeyMismatch", err)
		}
		if err := stateCB("app.corp.example:22", remote, fix.hostSigner.PublicKey()); !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("accept-new callback with plain host key in @cert-authority domain = %v, want ErrHostKeyMismatch (no silent TOFU downgrade)", err)
		}
		afterKH, err := os.ReadFile(userKH)
		if err != nil {
			t.Fatal(err)
		}
		if string(afterKH) != caLine {
			t.Fatalf("known_hosts was unexpectedly modified:\n%s", string(afterKH))
		}

		validCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "app.corp.example", cryptoSSH.HostCert, 9101)
		if err := stateCB("app.corp.example:22", remote, validCert); err != nil {
			t.Fatalf("valid host certificate signed by @cert-authority rejected: %v", err)
		}
	})

	t.Run("global_known_hosts_and_e2e_handshake_reject_raw_ca_pubkey_but_accept_signed_cert", func(t *testing.T) {
		assertPass3H1GlobalAndEndToEnd(t, fix)
	})
}

func assertPass3H1GlobalAndEndToEnd(t *testing.T, fix phase3CertFixture) {
	t.Helper()
	dir := t.TempDir()
	userKH := filepath.Join(dir, "user_known_hosts")
	globalKH := filepath.Join(dir, "global_known_hosts")

	rawCAPort := startRekeySSHServer(t, fix.caSigner, "pw123")
	hostCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "127.0.0.1", cryptoSSH.HostCert, 9102)
	hostCertSigner, err := cryptoSSH.NewCertSigner(hostCert, fix.hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	certPort := startRekeySSHServer(t, hostCertSigner, "pw123")

	caPubStr := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey())))
	globalContent := "@cert-authority [127.0.0.1]:" + strconv.Itoa(rawCAPort) + ",[127.0.0.1]:" + strconv.Itoa(certPort) + " " + caPubStr + "\n"
	if err := os.WriteFile(globalKH, []byte(globalContent), 0o644); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = []string{globalKH}

	opts := MustOptions(
		OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
		OptionUserKnownHostsFile, userKH,
		OptionGlobalKnownHostsFile, globalKH,
	)
	provider := &mapConfigProvider{configs: map[string]*ClientConfig{
		"raw-ca-server": {
			NodeID:   "raw-ca-server",
			Address:  "127.0.0.1",
			Port:     rawCAPort,
			User:     "alice",
			AuthType: "password",
			Password: "pw123",
			Options:  opts.Clone(),
		},
		"valid-cert-server": {
			NodeID:   "valid-cert-server",
			Address:  "127.0.0.1",
			Port:     certPort,
			User:     "alice",
			AuthType: "password",
			Password: "pw123",
			Options:  opts.Clone(),
		},
	}}
	conn := NewConnector(provider, WithEnvironment(env))
	conn.AcceptNewHostKey.Store(true)
	t.Cleanup(func() { _ = conn.CloseAll() })

	if _, err := conn.Connect(t.Context(), "raw-ca-server"); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("Connect to server presenting raw CA key = %v, want ErrHostKeyMismatch", err)
	}
	if data, err := os.ReadFile(userKH); err == nil && strings.TrimSpace(string(data)) != "" {
		t.Fatalf("raw CA key must not be persisted to user known_hosts:\n%s", string(data))
	}
	if _, err := conn.Connect(t.Context(), "valid-cert-server"); err != nil {
		t.Fatalf("Connect to server presenting valid CA-signed HostCert failed: %v", err)
	}
}

func TestPass3Conn_H2_MidUserAuthRekeyEnforcesPinningBeforeHandshakeDone(t *testing.T) {
	key1 := newPhase4HostKey(t)
	key2 := newPhase4HostKey(t)
	remote := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 22}

	for _, nilFlag := range []bool{false, true} {
		modeName := "handshakeDone_false"
		if nilFlag {
			modeName = "handshakeDone_nil"
		}
		t.Run(modeName+"_accept_new_blocks_mid_auth_key_swap_and_dedupes_same_key", func(t *testing.T) {
			assertPass3MidAuthAcceptNewPinning(t, nilFlag, key1, key2, remote)
		})
		t.Run(modeName+"_sshfp_and_ask_block_mid_auth_key_swap_and_no_reprompt", func(t *testing.T) {
			assertPass3MidAuthSSHFPAndAskPinning(t, nilFlag, key1, key2, remote)
		})
		t.Run(modeName+"_rotated_ca_cert_allowed_while_untrusted_swap_rejected", func(t *testing.T) {
			assertPass3MidAuthCertRotation(t, nilFlag, key2, remote)
		})
	}
}

func assertPass3MidAuthCertRotation(t *testing.T, nilFlag bool, unpinnedPlain cryptoSSH.PublicKey, remote net.Addr) {
	t.Helper()
	fix := newPhase3CertFixture(t)
	untrustedFix := newPhase3CertFixture(t)
	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")
	caLine := "@cert-authority *.corp.example " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(khFile, []byte(caLine), 0o600); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khFile
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cfg := &ClientConfig{
		NodeID:  "mid-auth-cert",
		Address: "api.corp.example",
		Port:    22,
		User:    "alice",
		Options: MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
			OptionUserKnownHostsFile, khFile,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	var flag *atomic.Bool
	if !nilFlag {
		flag = &atomic.Bool{}
	}
	cb, err := conn.getHostKeyCallbackWithState(t.Context(), nil, cfg, nil, flag)
	if err != nil {
		t.Fatal(err)
	}

	cert1 := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "api.corp.example", cryptoSSH.HostCert, 9201)
	rotatedKey := newPhase4HostKey(t)
	cert2 := signTestCertificate(t, fix.caSigner, rotatedKey, "api.corp.example", cryptoSSH.HostCert, 9202)
	badCert := signTestCertificate(t, untrustedFix.caSigner, rotatedKey, "api.corp.example", cryptoSSH.HostCert, 9203)

	if err := cb("api.corp.example:22", remote, cert1); err != nil {
		t.Fatalf("initial KEX with cert1 failed: %v", err)
	}
	if err := cb("api.corp.example:22", remote, cert2); err != nil {
		t.Fatalf("mid-auth rekey with rotated CA-signed cert2 failed: %v", err)
	}
	if err := cb("api.corp.example:22", remote, badCert); err == nil {
		t.Fatal("expected mid-auth rekey with untrusted CA cert to fail")
	}
	if err := cb("api.corp.example:22", remote, unpinnedPlain); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mid-auth rekey downgrade to plain key = %v, want ErrHostKeyMismatch", err)
	}
}

func assertPass3MidAuthAcceptNewPinning(
	t *testing.T,
	nilFlag bool,
	key1, key2 cryptoSSH.PublicKey,
	remote net.Addr,
) {
	t.Helper()
	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khFile

	cfg := &ClientConfig{
		NodeID:  "mid-auth-accept-new",
		Address: "app.example.com",
		Port:    22,
		User:    "alice",
		Options: MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAcceptNew,
			OptionUserKnownHostsFile, khFile,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	var flag *atomic.Bool
	if !nilFlag {
		flag = &atomic.Bool{}
	}
	cb, err := conn.getHostKeyCallbackWithState(t.Context(), nil, cfg, nil, flag)
	if err != nil {
		t.Fatalf("getHostKeyCallbackWithState failed: %v", err)
	}

	// Initial KEX #1 accepts KEY_1 via accept-new while initialHandshakeDone is still false/nil.
	if err := cb("app.example.com:22", remote, key1); err != nil {
		t.Fatalf("initial KEX with KEY_1 failed: %v", err)
	}
	// Benign mid-userauth rekey with the SAME KEY_1 succeeds without duplicating known_hosts lines.
	if err := cb("app.example.com:22", remote, key1); err != nil {
		t.Fatalf("mid-userauth rekey with identical KEY_1 failed: %v", err)
	}
	// Hostile mid-userauth rekey swapping to KEY_2 before initialHandshakeDone.Store(true) MUST fail closed.
	if err := cb("app.example.com:22", remote, key2); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mid-userauth rekey with swapped KEY_2 = %v, want ErrHostKeyMismatch", err)
	}

	rawKH, err := os.ReadFile(khFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(rawKH)), "\n")
	if len(lines) != 1 {
		t.Fatalf("known_hosts line count = %d, want 1:\n%s", len(lines), string(rawKH))
	}
	key2Wire := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(key2)))
	if strings.Contains(string(rawKH), key2Wire) {
		t.Fatalf("swapped KEY_2 was written to known_hosts:\n%s", string(rawKH))
	}
}

func assertPass3MidAuthSSHFPAndAskPinning(
	t *testing.T,
	nilFlag bool,
	key1, key2 cryptoSSH.PublicKey,
	remote net.Addr,
) {
	t.Helper()
	dir := t.TempDir()
	khSSHFP := filepath.Join(dir, "kh_sshfp")
	sum := sha256.Sum256(key1.Marshal())

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khSSHFP
	env.LookupSSHFP = func(_ context.Context, _ string) (SSHFPResult, error) {
		return SSHFPResult{
			Authenticated: true,
			Records: []SSHFPRecord{{
				Algorithm:       4,
				FingerprintType: 2,
				Fingerprint:     sum[:],
			}},
		}, nil
	}

	cfgSSHFP := &ClientConfig{
		NodeID:  "mid-auth-sshfp",
		Address: "sshfp.example.com",
		Port:    22,
		User:    "alice",
		Options: MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAsk,
			OptionVerifyHostKeyDNS, VerifyHostKeyDNSYes,
			OptionUserKnownHostsFile, khSSHFP,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	prompter := &spyInteractionPrompter{}
	conn := NewConnector(nil, WithEnvironment(env), WithInteractionHandler(prompter))
	t.Cleanup(func() { _ = conn.CloseAll() })

	var flag *atomic.Bool
	if !nilFlag {
		flag = &atomic.Bool{}
	}
	cbSSHFP, err := conn.getHostKeyCallbackWithState(t.Context(), nil, cfgSSHFP, nil, flag)
	if err != nil {
		t.Fatal(err)
	}
	if err := cbSSHFP("sshfp.example.com:22", remote, key1); err != nil {
		t.Fatalf("initial SSHFP KEX failed: %v", err)
	}
	if err := cbSSHFP("sshfp.example.com:22", remote, key2); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mid-userauth rekey swap after SSHFP accept = %v, want ErrHostKeyMismatch", err)
	}
	if prompter.confirmCalls.Load() != 0 {
		t.Fatalf("unexpected interactive prompt during SSHFP mid-userauth rekey: %d", prompter.confirmCalls.Load())
	}

	// Also verify interactive ask mode prompts once on KEX #1, does not re-prompt on same KEY_1, and rejects KEY_2.
	khAsk := filepath.Join(dir, "kh_ask")
	envAsk := fixtureEnvironment()
	envAsk.HomeDir = dir
	envAsk.KnownHostsFile = khAsk
	connAsk := NewConnector(nil, WithEnvironment(envAsk), WithInteractionHandler(prompter))
	t.Cleanup(func() { _ = connAsk.CloseAll() })

	cfgAsk := &ClientConfig{
		NodeID:  "mid-auth-ask",
		Address: "ask.example.com",
		Port:    22,
		User:    "alice",
		Options: MustOptions(
			OptionStrictHostKeyChecking, StrictHostKeyCheckingAsk,
			OptionUserKnownHostsFile, khAsk,
			OptionGlobalKnownHostsFile, "none",
		),
	}
	var askFlag *atomic.Bool
	if !nilFlag {
		askFlag = &atomic.Bool{}
	}
	cbAsk, err := connAsk.getHostKeyCallbackWithState(t.Context(), nil, cfgAsk, nil, askFlag)
	if err != nil {
		t.Fatal(err)
	}
	if err := cbAsk("ask.example.com:22", remote, key1); err != nil {
		t.Fatalf("initial ask KEX failed: %v", err)
	}
	if err := cbAsk("ask.example.com:22", remote, key1); err != nil {
		t.Fatalf("mid-userauth rekey with same KEY_1 failed: %v", err)
	}
	if err := cbAsk("ask.example.com:22", remote, key2); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mid-userauth rekey with swapped KEY_2 = %v, want ErrHostKeyMismatch", err)
	}
	if prompter.confirmCalls.Load() != 1 {
		t.Fatalf("confirmCalls = %d, want 1", prompter.confirmCalls.Load())
	}
}

func TestPass3Conn_H3_KnownHostsGlobTrailingStarCaseInsensitivityAndLinearBound(t *testing.T) {
	fix := newPhase3CertFixture(t)
	remote := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 77), Port: 22}

	t.Run("trailing_star_and_negation_exclude_exact_prefix", func(t *testing.T) {
		dir := t.TempDir()
		khFile := filepath.Join(dir, "known_hosts")
		caPub := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey())))
		plainKey := newPhase4HostKey(t)
		plainLine := "*,!staging* " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(plainKey))) + "\n"
		caLine := "@cert-authority *,!staging* " + caPub + "\n"
		if err := os.WriteFile(khFile, []byte(caLine+plainLine), 0o600); err != nil {
			t.Fatal(err)
		}

		env := fixtureEnvironment()
		env.HomeDir = dir
		env.KnownHostsFile = khFile
		conn := NewConnector(nil, WithEnvironment(env))
		t.Cleanup(func() { _ = conn.CloseAll() })

		_, _, cb, err := conn.openKnownHostsCallback(khFile, &ClientConfig{Address: "prod", Port: 22})
		if err != nil {
			t.Fatal(err)
		}

		prodCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "prod", cryptoSSH.HostCert, 9301)
		if err := cb("prod:22", remote, prodCert); err != nil {
			t.Fatalf("expected prod:22 cert to match *,!staging*: %v", err)
		}
		if err := cb("prod:22", remote, plainKey); err != nil {
			t.Fatalf("expected prod:22 plain key to match *,!staging*: %v", err)
		}

		for _, excluded := range []string{"staging", "staging-01", "STAGING", "Staging-Blue"} {
			cert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), strings.ToLower(excluded), cryptoSSH.HostCert, 9302)
			if err := cb(excluded+":22", remote, cert); err == nil {
				t.Fatalf("expected @cert-authority *,!staging* to exclude %q", excluded)
			}
			if err := cb(excluded+":22", remote, plainKey); err == nil {
				t.Fatalf("expected *,!staging* plain entry to exclude %q", excluded)
			}
		}

		if !khWildcardMatch([]byte("*web*"), []byte("myweb")) || !khWildcardMatch([]byte("web***"), []byte("web")) {
			t.Fatal("expected trailing '*' globs to match zero trailing characters")
		}
	})

	t.Run("case_insensitive_patterns_negations_brackets_and_hashed_hosts", func(t *testing.T) {
		assertPass3CaseInsensitiveAndHashedHosts(t, fix)
	})

	t.Run("pathological_multi_star_pattern_completes_under_10ms", func(t *testing.T) {
		pat := []byte("*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b")
		input := []byte(strings.Repeat("a", 40) + "c")
		start := time.Now()
		matched := khWildcardMatch(pat, input)
		elapsed := time.Since(start)
		if matched {
			t.Fatal("expected pathological pattern not to match")
		}
		if elapsed >= 10*time.Millisecond {
			t.Fatalf("khWildcardMatch took %v, want < 10ms", elapsed)
		}
	})
}

func assertPass3CaseInsensitiveAndHashedHosts(t *testing.T, fix phase3CertFixture) {
	t.Helper()
	dir := t.TempDir()
	khFile := filepath.Join(dir, "known_hosts")
	caPub := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey())))
	sharedKey := newPhase4HostKey(t)
	sharedPub := strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(sharedKey)))
	hashedKey := newPhase4HostKey(t)

	var buf strings.Builder
	buf.WriteString("@cert-authority *.corp.example,!bad.corp.example " + caPub + "\n")
	buf.WriteString("@cert-authority [*.corp.example]:2222,![bad.corp.example]:2222 " + caPub + "\n")
	buf.WriteString("*.corp.example,!bad.corp.example " + sharedPub + "\n")
	buf.WriteString("[*.corp.example]:2222,![bad.corp.example]:2222 " + sharedPub + "\n")
	buf.WriteString(knownhosts.Line([]string{knownhosts.HashHostname("openssh-hashed.corp.example")}, hashedKey) + "\n")
	buf.WriteString(knownhosts.Line([]string{knownhosts.HashHostname("[openssh-hashed.corp.example]:2222")}, hashedKey) + "\n")
	if err := os.WriteFile(khFile, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(khFile, "MixedWrite.Corp.Example:22", hashedKey, true); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(khFile, "[MixedWrite.Corp.Example]:2222", hashedKey, true); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = khFile
	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	_, _, cb, err := conn.openKnownHostsCallback(khFile, &ClientConfig{Address: "good.corp.example", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	remote22 := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 88), Port: 22}
	remote2222 := &net.TCPAddr{IP: net.IPv4(192, 0, 2, 88), Port: 2222}

	// Mixed-case bad.corp.example and [Bad.corp.example]:2222 must hit the !bad.corp.example negation.
	emptyPrincipalCert := &cryptoSSH.Certificate{
		Key:         fix.hostSigner.PublicKey(),
		Serial:      9303,
		CertType:    cryptoSSH.HostCert,
		ValidAfter:  uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore: uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := emptyPrincipalCert.SignCert(rand.Reader, fix.caSigner); err != nil {
		t.Fatal(err)
	}

	if err := cb("Bad.corp.example:22", remote22, emptyPrincipalCert); err == nil {
		t.Fatal("expected Bad.corp.example:22 cert to be rejected by !bad.corp.example")
	}
	if err := cb("[Bad.corp.example]:2222", remote2222, emptyPrincipalCert); err == nil {
		t.Fatal("expected [Bad.corp.example]:2222 cert to be rejected by ![bad.corp.example]:2222")
	}
	if err := cb("Bad.corp.example:22", remote22, sharedKey); err == nil {
		t.Fatal("expected Bad.corp.example:22 plain key to be rejected by !bad.corp.example")
	}
	if err := cb("[Bad.corp.example]:2222", remote2222, sharedKey); err == nil {
		t.Fatal("expected [Bad.corp.example]:2222 plain key to be rejected by ![bad.corp.example]:2222")
	}

	// Non-excluded mixed-case hosts and hashed hosts succeed regardless of caller casing.
	goodCert := signTestCertificate(t, fix.caSigner, fix.hostSigner.PublicKey(), "good.corp.example", cryptoSSH.HostCert, 9304)
	if err := cb("Good.Corp.Example:22", remote22, goodCert); err != nil {
		t.Fatalf("Good.Corp.Example:22 cert failed: %v", err)
	}
	if err := cb("[Good.Corp.Example]:2222", remote2222, goodCert); err != nil {
		t.Fatalf("[Good.Corp.Example]:2222 cert failed: %v", err)
	}
	for _, h := range []string{
		"OpenSSH-Hashed.Corp.Example:22",
		"[OpenSSH-Hashed.Corp.Example]:2222",
		"mixedwrite.corp.example:22",
		"[MIXEDWRITE.CORP.EXAMPLE]:2222",
	} {
		r := remote22
		if strings.HasSuffix(h, ":2222") {
			r = remote2222
		}
		if err := cb(h, r, hashedKey); err != nil {
			t.Fatalf("hashed known_hosts case-insensitive check failed for %q: %v", h, err)
		}
	}
}

func TestPass3Conn_M1_CertAuthorityHostKeyAlgorithmsExcludeSHA1AndDSA(t *testing.T) {
	fix := newPhase3CertFixture(t)
	dir := t.TempDir()
	globalKH := filepath.Join(dir, "ssh_known_hosts")
	userKH := filepath.Join(dir, "known_hosts")

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := cryptoSSH.NewPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	caLine := "@cert-authority * " + strings.TrimSpace(string(cryptoSSH.MarshalAuthorizedKey(fix.caSigner.PublicKey()))) + "\n"
	if err := os.WriteFile(globalKH, []byte(caLine), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(userKH, "host.corp.example", rsaPub, false); err != nil {
		t.Fatal(err)
	}

	env := fixtureEnvironment()
	env.HomeDir = dir
	env.KnownHostsFile = userKH
	env.GlobalKnownHostsFiles = []string{globalKH}

	conn := NewConnector(nil, WithEnvironment(env))
	t.Cleanup(func() { _ = conn.CloseAll() })

	cfg := &ClientConfig{
		NodeID:  "corp-ca",
		Address: "host.corp.example",
		Port:    22,
		User:    "alice",
	}
	algs, err := conn.getHostKeyAlgorithms(t.Context(), nil, cfg)
	if err != nil {
		t.Fatalf("getHostKeyAlgorithms failed: %v", err)
	}
	if len(algs) == 0 {
		t.Fatal("defaultKnownHostsHostKeyAlgorithms returned empty/nil slice on @cert-authority")
	}

	forbidden := []string{
		cryptoSSH.KeyAlgoRSA,
		"ssh-dss",
		cryptoSSH.CertAlgoRSAv01,
		"ssh-dss-cert-v01@openssh.com",
	}
	for _, bad := range forbidden {
		if slices.Contains(algs, bad) {
			t.Fatalf("insecure algorithm %q leaked into HostKeyAlgorithms: %v", bad, algs)
		}
	}

	supported := cryptoSSH.SupportedAlgorithms().HostKeys
	var wantCerts []string
	for _, alg := range supported {
		if isCertAlgorithm(alg) {
			wantCerts = append(wantCerts, alg)
		}
	}
	if len(algs) < len(wantCerts)+2 || !slices.Equal(algs[:len(wantCerts)], wantCerts) {
		t.Fatalf("expected modern certificate algorithms first, got %v (want prefix %v)", algs, wantCerts)
	}
	// Pinned plain RSA key in user known_hosts must order rsa-sha2-512, rsa-sha2-256 right after certs.
	afterCerts := algs[len(wantCerts):]
	if afterCerts[0] != cryptoSSH.KeyAlgoRSASHA512 || afterCerts[1] != cryptoSSH.KeyAlgoRSASHA256 {
		t.Fatalf("expected pinned RSA SHA-2 plain algorithms immediately after certs, got %v", afterCerts)
	}
	if len(algs) != len(supported) {
		t.Fatalf("HostKeyAlgorithms length = %d, want %d (%v)", len(algs), len(supported), algs)
	}
}

func TestPass3Conn_L1_UnbracketedColonValidationAndPercentHBracketStripping(t *testing.T) {
	badHostTokens := []string{
		":not:ipv6",
		":not:ipv6:zzzz",
		":::",
		"example.com:2222",
		"127.0.0.1:2222",
		"2001:db8::1:zzzz",
		"[127.0.0.1]",
		"[[2001:db8::1]]",
	}
	for _, bad := range badHostTokens {
		if err := ValidateSafeExecToken("%h", bad); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ValidateSafeExecToken(%%h, %q) = %v, want ErrUnsafeExecToken", bad, err)
		}
		if err := ValidateSafeExecToken("%n", bad); !errors.Is(err, ErrUnsafeExecToken) {
			t.Fatalf("ValidateSafeExecToken(%%n, %q) = %v, want ErrUnsafeExecToken", bad, err)
		}
	}

	goodHostTokens := []string{
		"::1",
		"2001:db8::1",
		"fe80::1%eth0",
		"[2001:db8::1]",
		"[fe80::1%eth0]",
	}
	for _, good := range goodHostTokens {
		if err := ValidateSafeExecToken("%h", good); err != nil {
			t.Fatalf("ValidateSafeExecToken(%%h, %q) unexpected error: %v", good, err)
		}
	}

	env := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation",
		LocalUID:  "1000",
	}

	gotProxyW, err := ExpandProxyCommand("ssh -W [%h]:%p jump", env, TargetContext{
		Host: "[2001:db8::1]",
		Port: 22,
		User: "alice",
	})
	if err != nil || gotProxyW != "ssh -W [2001:db8::1]:22 jump" {
		t.Fatalf("ExpandProxyCommand([2001:db8::1]) = %q, %v; want %q", gotProxyW, err, "ssh -W [2001:db8::1]:22 jump")
	}

	gotZoneProxy, err := ExpandProxyCommand("ssh -W [%h]:%p jump", env, TargetContext{
		Host: "[fe80::1%eth0]",
		Port: 2222,
		User: "alice",
	})
	if err != nil || gotZoneProxy != "ssh -W [fe80::1%eth0]:2222 jump" {
		t.Fatalf("ExpandProxyCommand([fe80::1%%eth0]) = %q, %v; want %q", gotZoneProxy, err, "ssh -W [fe80::1%eth0]:2222 jump")
	}

	gotUnquoted, err := ExpandProxyCommand("nc %h %p", env, TargetContext{
		Host: "[2001:db8::1]",
		Port: 22,
		User: "alice",
	})
	if err != nil || gotUnquoted != "nc 2001:db8::1 22" || strings.ContainsAny(gotUnquoted, "[]") {
		t.Fatalf("ExpandProxyCommand unquoted %%h = %q, %v; want %q without brackets", gotUnquoted, err, "nc 2001:db8::1 22")
	}

	gotLocal, err := ExpandLocalCommand("echo [%h]:%p %n", env, TargetContext{
		Host:         "[2001:db8::1]",
		Port:         22,
		User:         "alice",
		OriginalHost: "[fe80::1%eth0]",
	})
	if err != nil || gotLocal != "echo [2001:db8::1]:22 fe80::1%eth0" {
		t.Fatalf("ExpandLocalCommand = %q, %v; want %q", gotLocal, err, "echo [2001:db8::1]:22 fe80::1%eth0")
	}

	// Ensure %C hash matches clean unbracketed host address.
	gotHashBracketed, err := ExpandLocalCommand("%C", env, TargetContext{Host: "[2001:db8::1]", Port: 22, User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	gotHashBare, err := ExpandLocalCommand("%C", env, TargetContext{Host: "2001:db8::1", Port: 22, User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if gotHashBracketed != gotHashBare {
		t.Fatalf("%%C hash mismatch between bracketed (%s) and bare (%s) IPv6 host", gotHashBracketed, gotHashBare)
	}
}
