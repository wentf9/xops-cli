package config

import (
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestDetectSchemaVersion(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantVersion int
		wantErr     bool
	}{
		{
			name:        "empty content defaults to v1",
			yamlContent: "",
			wantVersion: 1,
			wantErr:     false,
		},
		{
			name: "legacy v1 config without schema_version",
			yamlContent: `
hosts:
  h1:
    address: 192.168.1.10
    port: 22
`,
			wantVersion: 1,
			wantErr:     false,
		},
		{
			name: "explicit schema_version 1",
			yamlContent: `
schema_version: 1
hosts:
  h1:
    address: 192.168.1.10
`,
			wantVersion: 1,
			wantErr:     false,
		},
		{
			name: "schema_version 2",
			yamlContent: `
schema_version: 2
credential:
  default_store: system
`,
			wantVersion: 2,
			wantErr:     false,
		},
		{
			name: "unsupported schema_version 3",
			yamlContent: `
schema_version: 3
`,
			wantVersion: 3,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ver, err := DetectSchemaVersion([]byte(tt.yamlContent))
			if (err != nil) != tt.wantErr {
				t.Fatalf("DetectSchemaVersion() err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrUnsupportedSchemaVersion) {
				t.Fatalf("expected ErrUnsupportedSchemaVersion, got: %v", err)
			}
			if ver != tt.wantVersion {
				t.Fatalf("expected version %d, got %d", tt.wantVersion, ver)
			}
		})
	}
}

func TestSchemaV2UnmarshalAndValidation(t *testing.T) {
	validV2YAML := `
schema_version: 2

credential:
  default_store: system
  remember_prompted: ask
  stores:
    system:
      type: system
      timeout: 5s
      cache_ttl: 0s
    ops-pass:
      type: pass
      timeout: 15s
      cache_ttl: 10m
      prefix: xops
    prod-vault:
      type: helper
      command: /usr/local/bin/xops-credential-vault
      args: ["--env", "prod"]
      timeout: 10s
      cache_ttl: 5m
      read_only: true

identities:
  admin-key:
    user: admin
    key_path: /home/user/.ssh/id_ed25519
    key_fingerprint: SHA256:abc1234567890
    passphrase_ref:
      store_id: system
      item_id: admin-passphrase-001
    auth_type: key

  operator:
    user: ops
    login_password_ref:
      store_id: ops-pass
      item_id: ops-login-001
    auth_type: password

hosts:
  srv1:
    address: 10.0.0.1
    port: 22

nodes:
  prod-node:
    host_ref: srv1
    identity_ref: admin-key
    sudo_mode: sudo
    privilege_password_ref:
      store_id: system
      item_id: prod-sudo-001
`

	cfg, err := UnmarshalV2([]byte(validV2YAML))
	if err != nil {
		t.Fatalf("UnmarshalV2 failed on valid YAML: %v", err)
	}

	if cfg.SchemaVersion != 2 {
		t.Fatalf("expected SchemaVersion 2, got %d", cfg.SchemaVersion)
	}
	if cfg.Credential.DefaultStore != "system" {
		t.Fatalf("expected default_store 'system', got %q", cfg.Credential.DefaultStore)
	}
	if cfg.Credential.RememberPrompted != "ask" {
		t.Fatalf("expected remember_prompted 'ask', got %q", cfg.Credential.RememberPrompted)
	}

	// 校验 StoreConfig 的 Duration 解析
	sysStore := cfg.Credential.Stores["system"]
	if sysStore.Timeout != 5*time.Second {
		t.Fatalf("expected system timeout 5s, got %v", sysStore.Timeout)
	}
	opsPass := cfg.Credential.Stores["ops-pass"]
	if opsPass.CacheTTL != 10*time.Minute {
		t.Fatalf("expected ops-pass cache_ttl 10m, got %v", opsPass.CacheTTL)
	}
	vaultStore := cfg.Credential.Stores["prod-vault"]
	if !vaultStore.ReadOnly || len(vaultStore.Args) != 2 {
		t.Fatalf("prod-vault store properties mismatch: %+v", vaultStore)
	}

	// 测试 To / From Configuration 转换
	internalCfg, err := FromV2(cfg)
	if err != nil {
		t.Fatalf("FromV2 failed: %v", err)
	}
	if internalCfg.SchemaVersion != 2 {
		t.Fatalf("expected internalCfg.SchemaVersion 2, got %d", internalCfg.SchemaVersion)
	}

	convertedV2, err := internalCfg.ToV2()
	if err != nil {
		t.Fatalf("ToV2 failed: %v", err)
	}
	if len(convertedV2.Nodes) != 1 || convertedV2.Nodes["prod-node"].PrivilegePasswordRef.ItemID != "prod-sudo-001" {
		t.Fatalf("roundtrip v2 nodes mismatch")
	}
}

func TestSchemaV2RejectsPlaintextSecrets(t *testing.T) {
	yamlWithPassword := `
schema_version: 2
credential:
  default_store: system
  stores:
    system:
      type: system
identities:
  bad-user:
    user: root
    password: myplaintextpassword
    auth_type: password
`

	_, err := UnmarshalV2([]byte(yamlWithPassword))
	if err == nil {
		t.Fatalf("expected error when YAML contains plaintext password, got nil")
	}
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation, got: %v", err)
	}

	yamlWithSuPwd := `
schema_version: 2
credential:
  default_store: system
  stores:
    system:
      type: system
hosts:
  h1:
    address: 1.2.3.4
    port: 22
identities:
  u1:
    user: test
    auth_type: password
nodes:
  n1:
    host_ref: h1
    identity_ref: u1
    sudo_mode: su
    su_pwd: plaintextsudopwd
`
	_, err = UnmarshalV2([]byte(yamlWithSuPwd))
	if err == nil {
		t.Fatalf("expected error when YAML contains plaintext su_pwd, got nil")
	}
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation, got: %v", err)
	}
}

func TestSchemaV2ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(cfg *ConfigurationV2)
		wantErr string
	}{
		{
			name: "wrong schema version",
			mutate: func(cfg *ConfigurationV2) {
				cfg.SchemaVersion = 1
			},
			wantErr: "expected schema_version 2",
		},
		{
			name: "default store not configured",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Credential.DefaultStore = "nonexistent"
			},
			wantErr: "default_store \"nonexistent\" not found",
		},
		{
			name: "invalid remember prompted",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Credential.RememberPrompted = "invalid-value"
			},
			wantErr: "invalid remember_prompted",
		},
		{
			name: "helper store without command",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Credential.Stores["h"] = StoreConfig{
					Type: StoreTypeHelper,
				}
			},
			wantErr: "requires non-empty command",
		},
		{
			name: "helper store with shell injection",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Credential.Stores["h"] = StoreConfig{
					Type:    StoreTypeHelper,
					Command: "/bin/helper | grep something",
				}
			},
			wantErr: "contains forbidden shell characters",
		},
		{
			name: "identity references unconfigured store",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Identities["u"] = IdentityV2{
					User: "u",
					LoginPasswordRef: &credential.Ref{
						StoreID: "unknown_store",
						ItemID:  "item_1",
					},
				}
			},
			wantErr: "store \"unknown_store\" not configured",
		},
		{
			name: "node references unconfigured host",
			mutate: func(cfg *ConfigurationV2) {
				cfg.Nodes["n"] = NodeV2{
					HostRef: "missing_host",
				}
			},
			wantErr: "references non-existent host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseCfg := &ConfigurationV2{
				SchemaVersion: 2,
				Credential: CredentialConfig{
					DefaultStore: "sys",
					Stores: map[string]StoreConfig{
						"sys": {Type: StoreTypeSystem},
					},
				},
				Identities: make(map[string]IdentityV2),
				Hosts:      make(map[string]models.Host),
				Nodes:      make(map[string]NodeV2),
			}
			tt.mutate(baseCfg)
			err := ValidateV2(baseCfg)
			if err == nil {
				t.Fatalf("expected validation error containing %q, got nil", tt.wantErr)
			}
			if !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("expected ErrSchemaValidation, got %v", err)
			}
		})
	}
}

func TestVersionHashingWithRefs(t *testing.T) {
	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)

	id1 := models.Identity{
		User:     "root",
		AuthType: "password",
		LoginPasswordRef: &credential.Ref{
			StoreID: "system",
			ItemID:  "item-001",
		},
	}
	identities.Set("id-root", id1)

	n1 := models.Node{
		HostRef:     "h1",
		IdentityRef: "id-root",
		SudoMode:    models.SudoModeSudo,
		PrivilegePasswordRef: &credential.Ref{
			StoreID: "system",
			ItemID:  "sudo-001",
		},
	}
	nodes.Set("node-1", n1)

	cfg := &Configuration{
		SchemaVersion: 2,
		Identities:    identities,
		Nodes:         nodes,
	}

	authVer1, err := nodeAuthVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeAuthVersion failed: %v", err)
	}

	sudoVer1, err := nodeSudoVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeSudoVersion failed: %v", err)
	}

	// 1. 改变 LoginPasswordRef.ItemID，认证版本哈希必须变化
	idRotated := id1
	idRotated.LoginPasswordRef = &credential.Ref{
		StoreID: "system",
		ItemID:  "item-002-new",
	}
	identities.Set("id-root", idRotated)

	authVer2, err := nodeAuthVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeAuthVersion after rotation failed: %v", err)
	}
	if authVer1 == authVer2 {
		t.Fatalf("expected auth version to change after credential rotation")
	}

	// 2. 改变 PassphraseRef，认证版本哈希必须变化
	idWithPassphrase := idRotated
	idWithPassphrase.PassphraseRef = &credential.Ref{
		StoreID: "system",
		ItemID:  "passphrase-001",
	}
	identities.Set("id-root", idWithPassphrase)

	authVer3, err := nodeAuthVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeAuthVersion after passphrase failed: %v", err)
	}
	if authVer2 == authVer3 {
		t.Fatalf("expected auth version to change after adding passphrase ref")
	}

	// 3. 改变 KeyFingerprint，认证版本哈希必须变化
	idWithFingerprint := idWithPassphrase
	idWithFingerprint.KeyFingerprint = "SHA256:fingerprint-abc"
	identities.Set("id-root", idWithFingerprint)

	authVer4, err := nodeAuthVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeAuthVersion after fingerprint failed: %v", err)
	}
	if authVer3 == authVer4 {
		t.Fatalf("expected auth version to change after updating fingerprint")
	}

	// 4. 改变 PrivilegePasswordRef.ItemID，提权版本哈希必须变化
	nodeRotated := n1
	nodeRotated.PrivilegePasswordRef = &credential.Ref{
		StoreID: "system",
		ItemID:  "sudo-002-new",
	}
	nodes.Set("node-1", nodeRotated)

	sudoVer2, err := nodeSudoVersion(cfg, "node-1")
	if err != nil {
		t.Fatalf("nodeSudoVersion after rotation failed: %v", err)
	}
	if sudoVer1 == sudoVer2 {
		t.Fatalf("expected sudo version to change after privilege credential rotation")
	}
}

func TestSnapshotNoPlaintextSecrets(t *testing.T) {
	v2YAML := `
schema_version: 2
credential:
  default_store: system
  stores:
    system:
      type: system
identities:
  u1:
    user: admin
    login_password_ref:
      store_id: system
      item_id: item-admin
    auth_type: password
hosts:
  h1:
    address: 1.1.1.1
    port: 22
nodes:
  n1:
    host_ref: h1
    identity_ref: u1
    sudo_mode: sudo
    privilege_password_ref:
      store_id: system
      item_id: item-sudo
`
	v2DTO, err := UnmarshalV2([]byte(v2YAML))
	if err != nil {
		t.Fatalf("UnmarshalV2 failed: %v", err)
	}

	cfg, err := FromV2(v2DTO)
	if err != nil {
		t.Fatalf("FromV2 failed: %v", err)
	}

	// 检查内部 Configuration 快照
	cloned := cfg.Snapshot()
	for _, k := range cloned.Identities.Keys() {
		id, _ := cloned.Identities.Get(k)
		if id.Password != "" || id.Passphrase != "" {
			t.Fatalf("cloned identity %q contains plaintext secret: pwd=%q, pass=%q", k, id.Password, id.Passphrase)
		}
	}
	for _, k := range cloned.Nodes.Keys() {
		n, _ := cloned.Nodes.Get(k)
		if n.SuPwd != "" {
			t.Fatalf("cloned node %q contains plaintext su_pwd: %q", k, n.SuPwd)
		}
	}
}

func TestStrictStoreFields(t *testing.T) {
	const baseYAML = `schema_version: 2
credential:
  default_store: s
  stores:
    s:
      type: system
      timeout: 5s
      cache_ttl: 0s
      read_ony: true
identities:
  u:
    user: root
    auth_type: password
hosts:
  h: {address: 192.0.2.1, port: 22}
nodes:
  n: {host_ref: h, identity_ref: u}
`
	_, err := UnmarshalV2([]byte(baseYAML))
	if err == nil {
		t.Fatal("unknown store field silently accepted")
	}
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation, got: %v", err)
	}
}

func TestPassphraseNeedsFingerprint(t *testing.T) {
	// 缺失 key_fingerprint
	missingFP := `schema_version: 2
credential:
  default_store: s
  stores:
    s:
      type: system
      timeout: 5s
      cache_ttl: 0s
identities:
  u:
    user: root
    auth_type: key
    key_path: /synthetic/key
    passphrase_ref: {store_id: s, item_id: original}
hosts:
  h: {address: 192.0.2.1, port: 22}
nodes:
  n: {host_ref: h, identity_ref: u}
`
	_, err := UnmarshalV2([]byte(missingFP))
	if err == nil {
		t.Fatal("passphrase reference accepted without key fingerprint")
	}
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation, got: %v", err)
	}

	// 带有非法空格的 key_fingerprint
	badFP := `schema_version: 2
credential:
  default_store: s
  stores:
    s:
      type: system
      timeout: 5s
      cache_ttl: 0s
identities:
  u:
    user: root
    auth_type: key
    key_path: /synthetic/key
    key_fingerprint: "SHA256: bad fingerprint"
    passphrase_ref: {store_id: s, item_id: original}
hosts:
  h: {address: 192.0.2.1, port: 22}
nodes:
  n: {host_ref: h, identity_ref: u}
`
	_, err = UnmarshalV2([]byte(badFP))
	if err == nil {
		t.Fatal("passphrase reference accepted with bad key fingerprint")
	}
	if !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("expected ErrSchemaValidation, got: %v", err)
	}

	// 合法 key_fingerprint
	validFP := `schema_version: 2
credential:
  default_store: s
  stores:
    s:
      type: system
      timeout: 5s
      cache_ttl: 0s
identities:
  u:
    user: root
    auth_type: key
    key_path: /synthetic/key
    key_fingerprint: "SHA256:validFingerprintString12345"
    passphrase_ref: {store_id: s, item_id: original}
hosts:
  h: {address: 192.0.2.1, port: 22}
nodes:
  n: {host_ref: h, identity_ref: u}
`
	cfg, err := UnmarshalV2([]byte(validFP))
	if err != nil {
		t.Fatalf("valid passphrase config rejected: %v", err)
	}
	if cfg.Identities["u"].KeyFingerprint != "SHA256:validFingerprintString12345" {
		t.Fatalf("unexpected key_fingerprint: %q", cfg.Identities["u"].KeyFingerprint)
	}
}
