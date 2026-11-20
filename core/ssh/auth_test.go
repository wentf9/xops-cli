package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestDialSSHAgent_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := dialAgentConn(ctx, fixtureEnvironment().DialAgent, "unused-agent-socket")
	if conn != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Fatalf("close unexpected ssh-agent connection failed: %v", closeErr)
		}
		t.Fatal("dialAgentConn() returned a connection for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialAgentConn() error = %v, want context.Canceled", err)
	}

	// Also verify fail-closed when DialAgent is nil.
	conn, err = dialAgentConn(context.Background(), nil, "unused-agent-socket")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("dialAgentConn() returned a connection when DialAgent is nil")
	}
	if err == nil {
		t.Fatal("dialAgentConn() expected error when DialAgent is nil")
	}
}

type mockUIForTest struct {
	passphrase string
	called     bool
	lastReq    SecretRequest
}

func setTestHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	return dir
}

func (m *mockUIForTest) PromptSecret(ctx context.Context, req SecretRequest) (string, error) {
	m.called = true
	m.lastReq = req
	return m.passphrase, nil
}

func (m *mockUIForTest) ConfirmHostKey(ctx context.Context, req HostKeyConfirmation) (bool, error) {
	return true, nil
}

// generateTestEncryptedKey 生成一个传统的 PEM 格式加密私钥及其公钥
func generateTestEncryptedKey(t *testing.T, passphrase string) ([]byte, ssh.PublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	// nolint:staticcheck // SA1019: EncryptPEMBlock is deprecated but useful for generating a test encrypted key
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privDER, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("failed to encrypt pem block: %v", err)
	}
	pemData := pem.EncodeToMemory(block)

	sshPub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to create ssh public key: %v", err)
	}

	return pemData, sshPub
}

// marshalOpenSSHPrivateKeyHeaderForTest 手动构造一个包含明文公钥的 OpenSSH 格式私钥 PEM 数据头部，用以测试免密公钥解析
func marshalOpenSSHPrivateKeyHeaderForTest(pubKey ssh.PublicKey) []byte {
	var buf []byte

	// 1. magic
	buf = append(buf, []byte("openssh-key-v1\x00")...)

	writeString := func(s string) {
		length := uint32(len(s))
		buf = append(buf, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
		buf = append(buf, []byte(s)...)
	}

	writeBytes := func(b []byte) {
		length := uint32(len(b))
		buf = append(buf, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
		buf = append(buf, b...)
	}

	// 2. ciphername
	writeString("aes256-ctr")
	// 3. kdfname
	writeString("bcrypt")
	// 4. kdfopts
	writeString("dummyopts")

	// 5. num keys (uint32)
	buf = append(buf, 0, 0, 0, 1)

	// 6. pubKey0
	writeBytes(pubKey.Marshal())
	// 7. encrypted private key section (required by golang.org/x/crypto/ssh PassphraseMissingError check)
	writeBytes([]byte("dummy-encrypted-privkey"))

	return buf
}

func TestLazySigner(t *testing.T) {
	passphrase := "secret123"
	pemData, sshPub := generateTestEncryptedKey(t, passphrase)

	// 使用临时文件模拟 keyPath 路径，以便测试自动保存公钥的功能
	tempDir := t.TempDir()

	keyPath := filepath.Join(tempDir, "id_rsa")

	ui := &mockUIForTest{passphrase: passphrase}
	lazy := &lazySigner{
		pubKey:   sshPub,
		keyPath:  keyPath,
		keyData:  pemData,
		prompter: ui,
		passphraseCallback: func(path, pass string) {
			if path != keyPath || pass != passphrase {
				t.Errorf("unexpected callback parameters: %s, %s", path, pass)
			}
		},
	}

	// 验证 PublicKey 方法没有触发密码输入，并且公钥正确
	if lazy.PublicKey().Type() != sshPub.Type() {
		t.Errorf("expected public key type %s, got %s", sshPub.Type(), lazy.PublicKey().Type())
	}
	if ui.called {
		t.Error("PromptSecret was unexpectedly called during PublicKey()")
	}

	// 验证 Sign 方法触发密码输入，且签名成功
	testData := []byte("hello world")
	sig, err := lazy.Sign(rand.Reader, testData)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if !ui.called {
		t.Error("expected PromptPassword to be called during Sign()")
	}

	if err = sshPub.Verify(testData, sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	// 验证解密成功后是否自动生成了公钥文件
	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err != nil {
		t.Errorf("expected public key file to be saved: %v", err)
	}

	// 第二次调用，应该不需要再提示密码输入 (利用缓存 signer)
	ui.called = false
	sig2, err := lazy.Sign(rand.Reader, testData)
	if err != nil {
		t.Fatalf("second Sign failed: %v", err)
	}
	if ui.called {
		t.Error("PromptPassword was unexpectedly called for the second Sign()")
	}
	if err = sshPub.Verify(testData, sig2); err != nil {
		t.Errorf("second signature verification failed: %v", err)
	}
}

func TestParseOpenSSHPublicKeyFromEncryptedPrivate(t *testing.T) {
	_, sshPub := generateTestEncryptedKey(t, "secret")
	headerData := marshalOpenSSHPrivateKeyHeaderForTest(sshPub)

	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: headerData,
	}
	pemData := pem.EncodeToMemory(block)

	parsedPub, err := parseOpenSSHPublicKeyFromEncryptedPrivate(pemData)
	if err != nil {
		t.Fatalf("failed to parse OpenSSH public key: %v", err)
	}

	if parsedPub.Type() != sshPub.Type() {
		t.Errorf("expected type %s, got %s", sshPub.Type(), parsedPub.Type())
	}
}

func TestBuildAutoAuthPlan_LazySigner_OpenSSH(t *testing.T) {
	tempDir := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	sshDir := filepath.Join(tempDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("failed to create .ssh dir: %v", err)
	}

	_, sshPub := generateTestEncryptedKey(t, "secret123")
	headerData := marshalOpenSSHPrivateKeyHeaderForTest(sshPub)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: headerData,
	}
	pemData := pem.EncodeToMemory(block)

	keyPath := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	ui := &mockUIForTest{passphrase: "secret123"}
	plan := buildTestAutoAuthPlan(t.Context(), AutoAuthOptions{
		LifecycleCtx: t.Context(),
		User:         "testuser",
		Host:         "127.0.0.1",
		Prompter:     ui,
	})
	if plan.cleanup != nil {
		t.Cleanup(plan.cleanup)
	}

	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err != nil {
		t.Errorf("expected public key file to be auto-extracted and saved: %v", err)
	}
	if ui.called {
		t.Error("PromptSecret was unexpectedly called during buildAutoAuthPlan")
	}
	if len(plan.candidates) != 3 {
		t.Fatalf("expected default key, password, and keyboard-interactive candidates, got %d", len(plan.candidates))
	}
	if plan.candidates[0].protocol != autoAuthProtocolPublicKey {
		t.Fatalf("first candidate protocol = %q, want %q", plan.candidates[0].protocol, autoAuthProtocolPublicKey)
	}
}

func TestBuildAutoAuthPlan_LazySigner_PEMFallback(t *testing.T) {
	tempDir := setTestHome(t)
	t.Setenv("SSH_AUTH_SOCK", "")

	sshDir := filepath.Join(tempDir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("failed to create .ssh dir: %v", err)
	}

	passphrase := "secret123"
	pemData, _ := generateTestEncryptedKey(t, passphrase)
	keyPath := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	ui := &mockUIForTest{passphrase: passphrase}
	plan := buildTestAutoAuthPlan(t.Context(), AutoAuthOptions{
		LifecycleCtx: t.Context(),
		User:         "testuser",
		Host:         "127.0.0.1",
		Prompter:     ui,
	})
	if plan.cleanup != nil {
		t.Cleanup(plan.cleanup)
	}

	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err == nil {
		t.Error("expected public key file not to be saved before the PEM candidate is attempted")
	}
	if ui.called {
		t.Error("PromptSecret was unexpectedly called during buildAutoAuthPlan")
	}
	if len(plan.candidates) != 3 {
		t.Fatalf("expected PEM key, password, and keyboard-interactive candidates, got %d", len(plan.candidates))
	}
	if plan.candidates[0].protocol != autoAuthProtocolPublicKey {
		t.Fatalf("first candidate protocol = %q, want %q", plan.candidates[0].protocol, autoAuthProtocolPublicKey)
	}
}

func TestResolveKeySigners_SkipsUnencryptedUnsupportedOpenSSHKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519_sk")
	_, sshPub := generateTestEncryptedKey(t, "secret123")
	if err := savePublicKey(keyPath, sshPub); err != nil {
		t.Fatalf("savePublicKey: %v", err)
	}

	var raw []byte
	raw = append(raw, []byte("openssh-key-v1\x00")...)
	writeStr := func(s string) {
		l := uint32(len(s))
		raw = append(raw, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
		raw = append(raw, s...)
	}
	writeBytes := func(b []byte) {
		l := uint32(len(b))
		raw = append(raw, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
		raw = append(raw, b...)
	}
	writeStr("none")
	writeStr("none")
	writeStr("")
	raw = append(raw, 0, 0, 0, 1)
	writeBytes(sshPub.Marshal())
	writeStr("stub-unencrypted-sk-payload")

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: raw})
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write stub sk key: %v", err)
	}

	ui := &mockUIForTest{passphrase: "should-not-prompt"}
	secProvider := &autoSecretProvider{
		lifecycleCtx: t.Context(),
		prompter:     ui,
	}
	_, method, err := resolveKeySigners(keyPath, nil, true, secProvider, nil, nil, false, nil)
	if err == nil || method != nil {
		t.Fatalf("expected unencrypted unsupported OpenSSH key to skip with error (method=nil), got method=%v err=%v", method, err)
	}
	if ui.called {
		t.Fatal("PromptSecret was called on unencrypted unsupported OpenSSH key")
	}
}

func TestResolveKeySigners_SkipsPKCS8AndEncryptedSKWithoutPrompting(t *testing.T) {
	appendSSHString := func(dst []byte, s string) []byte {
		n := uint32(len(s))
		dst = append(dst, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		return append(dst, s...)
	}

	t.Run("pkcs8-encrypted-private-key-skipped-without-prompt", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "pkcs8_enc")
		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: []byte("dummy-pkcs8-encrypted-payload"),
		})
		if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
			t.Fatal(err)
		}

		ui := &mockUIForTest{passphrase: "should-not-be-used"}
		secProvider := &autoSecretProvider{
			lifecycleCtx:       context.Background(),
			prompter:           ui,
			handshakeTimeout:   time.Second,
			interactionTimeout: time.Second,
		}
		_, method, err := resolveKeySigners(keyPath, nil, true, secProvider, nil, nil, false, nil)
		if err == nil || method != nil {
			t.Fatalf("expected PKCS#8 encrypted key to skip with error (method=nil), got method=%v err=%v", method, err)
		}
		if ui.called {
			t.Fatal("PromptSecret must not be called for unsupported PKCS#8 ENCRYPTED PRIVATE KEY")
		}
	})

	t.Run("encrypted-sk-ed25519-skipped-without-prompt", func(t *testing.T) {
		pubWire := appendSSHString(nil, ssh.KeyAlgoSKED25519)
		pubWire = appendSSHString(pubWire, string(make([]byte, 32)))
		pubWire = appendSSHString(pubWire, "ssh:")

		kdfOpts := appendSSHString(nil, "0123456789abcdef")
		kdfOpts = append(kdfOpts, 0, 0, 0, 16)

		raw := append([]byte(nil), "openssh-key-v1\x00"...)
		raw = appendSSHString(raw, "aes256-ctr")
		raw = appendSSHString(raw, "bcrypt")
		raw = appendSSHString(raw, string(kdfOpts))
		raw = append(raw, 0, 0, 0, 1) // numkeys = 1
		raw = appendSSHString(raw, string(pubWire))
		raw = appendSSHString(raw, string(make([]byte, 16))) // dummy encrypted privblock

		pemData := pem.EncodeToMemory(&pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: raw,
		})
		keyPath := filepath.Join(t.TempDir(), "id_ed25519_sk")
		if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
			t.Fatal(err)
		}

		ui := &mockUIForTest{passphrase: "should-not-be-used"}
		secProvider := &autoSecretProvider{
			lifecycleCtx:       context.Background(),
			prompter:           ui,
			handshakeTimeout:   time.Second,
			interactionTimeout: time.Second,
		}
		_, method, err := resolveKeySigners(keyPath, nil, true, secProvider, nil, nil, false, nil)
		if err == nil || method != nil {
			t.Fatalf("expected encrypted sk-* key to skip with error (method=nil), got method=%v err=%v", method, err)
		}
		if ui.called {
			t.Fatal("PromptSecret must not be called for encrypted sk-* key")
		}
	})
}
