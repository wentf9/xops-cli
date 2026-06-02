package ssh

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AuthMethod 定义获取 SSH 认证方法的接口
type AuthMethod interface {
	GetMethod() (ssh.AuthMethod, error)
}

var _ AuthMethod = (*PasswordAuth)(nil)

// PasswordAuth 实现密码认证
type PasswordAuth struct {
	Password string
}

func (p *PasswordAuth) GetMethod() (ssh.AuthMethod, error) {
	return ssh.Password(p.Password), nil
}

var _ AuthMethod = (*KeyAuth)(nil)

// KeyAuth 实现私钥认证
type KeyAuth struct {
	Path       string
	Passphrase string
}

func (k *KeyAuth) GetMethod() (ssh.AuthMethod, error) {
	keyData, err := os.ReadFile(k.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", k.Path, err)
	}
	var signer ssh.Signer
	if k.Passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyData, []byte(k.Passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(keyData)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return ssh.PublicKeys(signer), nil
}

var _ ssh.Signer = (*lazySigner)(nil)

type lazySigner struct {
	pubKey             ssh.PublicKey
	keyPath            string
	keyData            []byte
	ui                 InteractionHandler
	passphraseCallback func(string, string)
	decryptedSigner    ssh.Signer
	mu                 sync.RWMutex
}

func (s *lazySigner) PublicKey() ssh.PublicKey {
	return s.pubKey
}

func (s *lazySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signer, err := s.getDecryptedSigner()
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand, data)
}

func (s *lazySigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	signer, err := s.getDecryptedSigner()
	if err != nil {
		return nil, err
	}
	if algoSigner, ok := signer.(ssh.AlgorithmSigner); ok {
		return algoSigner.SignWithAlgorithm(rand, data, algorithm)
	}
	return signer.Sign(rand, data)
}

func (s *lazySigner) getDecryptedSigner() (ssh.Signer, error) {
	s.mu.RLock()
	if s.decryptedSigner != nil {
		signer := s.decryptedSigner
		s.mu.RUnlock()
		return signer, nil
	}
	s.mu.RUnlock()

	// 将交互式的 PromptPassword 移到锁的外部，防止阻塞其他协程
	prompt := fmt.Sprintf("Enter passphrase for key '%s': ", s.keyPath)
	passphrase, err := s.ui.PromptPassword(prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 双重检查，防止在等待用户输入期间其他协程已经解密成功
	if s.decryptedSigner != nil {
		return s.decryptedSigner, nil
	}

	decSigner, err := ssh.ParsePrivateKeyWithPassphrase(s.keyData, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
	}
	s.decryptedSigner = decSigner

	// 成功输入密码短语解密后，自动保存公钥到对应文件
	savePublicKey(s.keyPath, decSigner.PublicKey())

	s.passphraseCallback(s.keyPath, passphrase)
	return decSigner, nil
}

// savePublicKey 自动将公钥以 authorized_keys 格式保存到对应的 .pub 文件中
func savePublicKey(keyPath string, pubKey ssh.PublicKey) {
	pubKeyPath := keyPath + ".pub"
	if _, err := os.Stat(pubKeyPath); err == nil {
		// 如果公钥文件已经存在，不需要重复保存
		return
	}
	pubBytes := ssh.MarshalAuthorizedKey(pubKey)
	_ = os.WriteFile(pubKeyPath, pubBytes, 0644)
}

// parseOpenSSHPublicKeyFromEncryptedPrivate 从 OpenSSH 格式的加密私钥中直接提取明文存储的公钥数据
func parseOpenSSHPublicKeyFromEncryptedPrivate(keyData []byte) (ssh.PublicKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("not an openssh private key")
	}

	data := block.Bytes
	const magic = "openssh-key-v1\x00"
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		return nil, fmt.Errorf("invalid magic header")
	}
	data = data[len(magic):]

	readString := func() ([]byte, bool) {
		if len(data) < 4 {
			return nil, false
		}
		length := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		data = data[4:]
		if uint32(len(data)) < length {
			return nil, false
		}
		res := data[:length]
		data = data[length:]
		return res, true
	}

	// Read ciphername
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read ciphername")
	}
	// Read kdfname
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read kdfname")
	}
	// Read kdfopts
	if _, ok := readString(); !ok {
		return nil, fmt.Errorf("failed to read kdfopts")
	}

	// Read num keys (uint32)
	if len(data) < 4 {
		return nil, fmt.Errorf("failed to read num keys")
	}
	numKeys := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	data = data[4:]
	if numKeys < 1 {
		return nil, fmt.Errorf("no keys found")
	}

	// Read first public key
	pubKeyData, ok := readString()
	if !ok {
		return nil, fmt.Errorf("failed to read public key data")
	}

	return ssh.ParsePublicKey(pubKeyData)
}

// tryResolveKey 尝试解析特定路径的私钥
func tryResolveKey(keyPath string, ui InteractionHandler, passphraseCallback func(string, string)) (ssh.Signer, ssh.AuthMethod, error) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key data failed: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyData)
	if err == nil {
		return signer, nil, nil
	}

	// 私钥解析失败，可能是因为被密码保护了，也可能格式损坏
	// 无论何种错误，均优先尝试免密读取或从私钥提取公钥以开启延时加载 (lazySigner)
	var pubKey ssh.PublicKey
	pubKeyPath := keyPath + ".pub"
	if pubKeyData, readErr := os.ReadFile(pubKeyPath); readErr == nil {
		var parseErr error
		pubKey, _, _, _, parseErr = ssh.ParseAuthorizedKey(pubKeyData)
		if parseErr != nil {
			logger.Debugf("Failed to parse public key: %s, error: %v", pubKeyPath, parseErr)
			pubKey = nil
		}
	} else {
		// 尝试直接从 OpenSSH 格式的加密私钥中免密提取公钥数据
		if extractedPubKey, extractErr := parseOpenSSHPublicKeyFromEncryptedPrivate(keyData); extractErr == nil {
			pubKey = extractedPubKey
			logger.Debugf("Extracted public key from OpenSSH private key without passphrase: %s", keyPath)
			savePublicKey(keyPath, pubKey)
		} else {
			logger.Debugf("Failed to extract public key from OpenSSH key: %s, error: %v", keyPath, extractErr)
		}
	}

	if pubKey != nil {
		lazy := &lazySigner{
			pubKey:             pubKey,
			keyPath:            keyPath,
			keyData:            keyData,
			ui:                 ui,
			passphraseCallback: passphraseCallback,
		}
		return lazy, nil, nil
	}

	// 如果真的没有提取到公钥，且报错确是 PassphraseMissingError，则回退到原本的 PublicKeysCallback
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		keyDataCopy := keyData
		keyPathCopy := keyPath
		method := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			prompt := fmt.Sprintf("Enter passphrase for key '%s': ", keyPathCopy)
			passphrase, err := ui.PromptPassword(prompt)
			if err != nil {
				return nil, fmt.Errorf("failed to read passphrase: %w", err)
			}
			s, err := ssh.ParsePrivateKeyWithPassphrase(keyDataCopy, []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
			}
			savePublicKey(keyPathCopy, s.PublicKey())
			passphraseCallback(keyPathCopy, passphrase)
			return []ssh.Signer{s}, nil
		})
		return nil, method, nil
	}

	return nil, nil, err
}

// BuildAutoAuthMethods 生成一个包含多种回退机制的 AuthMethod 链
// passphraseCallback 在用户成功输入受密码保护的私钥密码后被调用，用于持久化
func BuildAutoAuthMethods(user, host string, ui InteractionHandler, passwordCallback func(string), passphraseCallback func(keyPath, passphrase string)) ([]ssh.AuthMethod, func()) {
	var methods []ssh.AuthMethod
	var cleanup func()

	// SSH Agent
	if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		if conn, err := net.Dial("unix", socket); err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
			cleanup = func() { _ = conn.Close() }
		}
	}

	// Default Keys
	defaultKeys := []string{"~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_dsa"}
	var signers []ssh.Signer
	for _, p := range defaultKeys {
		keyPath := expandHomeDir(p)
		logger.Debugf("Checking default key: %s", keyPath)
		if _, err := os.Stat(keyPath); err != nil {
			if os.IsNotExist(err) {
				logger.Debugf("Key file does not exist: %s", keyPath)
			} else {
				logger.Debugf("Failed to stat key: %s, error: %v", keyPath, err)
			}
			continue
		}
		logger.Debugf("Found default key: %s", keyPath)

		signer, method, err := tryResolveKey(keyPath, ui, passphraseCallback)
		if err != nil {
			logger.Debugf("Failed to resolve key: %s, error: %v", keyPath, err)
			continue
		}
		if signer != nil {
			signers = append(signers, signer)
		}
		if method != nil {
			methods = append(methods, method)
		}
	}

	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeys(signers...))
	}

	// Password Fallback
	methods = append(methods, ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		password, err := ui.PromptPassword(fmt.Sprintf("%s@%s's password: ", user, host))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		passwordCallback(password)
		return password, nil
	}), 3))

	return methods, cleanup
}
