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

	"golang.org/x/crypto/ssh"
)

func TestDialSSHAgent_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, err := dialSSHAgent(ctx, "unused-agent-socket")
	if conn != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Fatalf("close unexpected ssh-agent connection failed: %v", closeErr)
		}
		t.Fatal("dialSSHAgent() returned a connection for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dialSSHAgent() error = %v, want context.Canceled", err)
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
	plan := buildAutoAuthPlan(t.Context(), AutoAuthOptions{
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
	if len(plan.candidates) != 2 {
		t.Fatalf("expected default key and password candidates, got %d", len(plan.candidates))
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
	plan := buildAutoAuthPlan(t.Context(), AutoAuthOptions{
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
	if len(plan.candidates) != 2 {
		t.Fatalf("expected PEM key and password candidates, got %d", len(plan.candidates))
	}
	if plan.candidates[0].protocol != autoAuthProtocolPublicKey {
		t.Fatalf("first candidate protocol = %q, want %q", plan.candidates[0].protocol, autoAuthProtocolPublicKey)
	}
}
