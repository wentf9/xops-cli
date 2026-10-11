package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"os"

	"gopkg.in/yaml.v3"
)

func newEmptyV2Configuration() *Configuration {
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = 2
	cfg.Credential = DefaultCredentialConfig()
	return cfg
}

// Legacy fixture writers deliberately bypass Store: released binaries can no
// longer create or rewrite v1 files. Keep encryption out of production code.
func writeMigrationTestConfiguration(path, keyPath string, cfg *Configuration) error {
	if cfg.SchemaVersion == 2 {
		return NewDefaultStore(path, keyPath).Save(cfg)
	}
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	encode := func(value string) (string, error) {
		if value == "" {
			return "", nil
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		return "ENC:" + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(value), nil)), nil
	}
	copy := cfg.Snapshot()
	for _, name := range copy.Identities.Keys() {
		id, _ := copy.Identities.Get(name)
		id.Password, err = encode(id.Password)
		if err != nil {
			return err
		}
		id.Passphrase, err = encode(id.Passphrase)
		if err != nil {
			return err
		}
		copy.Identities.Set(name, id)
	}
	for _, name := range copy.Nodes.Keys() {
		node, _ := copy.Nodes.Get(name)
		node.SuPwd, err = encode(node.SuPwd)
		if err != nil {
			return err
		}
		copy.Nodes.Set(name, node)
	}
	raw, err := yaml.Marshal(copy)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}

func loadMigrationTestConfiguration(path, keyPath string) (*Configuration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	version, err := DetectSchemaVersion(raw)
	if err != nil {
		return nil, err
	}
	if version == 2 {
		return NewDefaultStore(path, keyPath).Load()
	}
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	for _, name := range cfg.Identities.Keys() {
		id, _ := cfg.Identities.Get(name)
		password, err := migrationPlaintext(id.Password, key)
		if err != nil {
			return nil, err
		}
		id.Password = string(password)
		clear(password)
		passphrase, err := migrationPlaintext(id.Passphrase, key)
		if err != nil {
			return nil, err
		}
		id.Passphrase = string(passphrase)
		clear(passphrase)
		cfg.Identities.Set(name, id)
	}
	for _, name := range cfg.Nodes.Keys() {
		node, _ := cfg.Nodes.Get(name)
		value, err := migrationPlaintext(node.SuPwd, key)
		if err != nil {
			return nil, err
		}
		node.SuPwd = string(value)
		clear(value)
		cfg.Nodes.Set(name, node)
	}
	return cfg, nil
}
