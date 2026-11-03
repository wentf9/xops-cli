package config

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
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

func TestSchemaV2RejectsTrailingDocument(t *testing.T) {
	data := []byte("schema_version: 2\ncredential: {stores: {}}\nidentities: {}\nhosts: {}\nnodes: {}\n---\npassword: must-not-be-ignored\n")
	if _, err := UnmarshalV2(data); !errors.Is(err, ErrSchemaValidation) {
		t.Fatalf("trailing document accepted: %v", err)
	}
}

const schemaV2ExecutionYAML = `schema_version: 2
credential:
  default_store: s
  stores:
    s: {type: system}
identities:
  u: {user: root, auth_type: key}
hosts:
  h: {address: 127.0.0.1, port: 22}
execution:
  interpreter: bash
  launch_dialect: posix
  login: false
nodes:
  n1:
    host_ref: h
    identity_ref: u
  n2:
    host_ref: h
    identity_ref: u
    execution:
      interpreter: server
  n3:
    host_ref: h
    identity_ref: u
    execution:
      login: true
`

func parseSchemaV2Execution(t *testing.T) *ConfigurationV2 {
	t.Helper()
	cfgV2, err := UnmarshalV2([]byte(schemaV2ExecutionYAML))
	if err != nil {
		t.Fatalf("UnmarshalV2() unexpected error: %v", err)
	}
	return cfgV2
}

func TestSchemaV2Execution_ParseAndInheritance(t *testing.T) {
	cfgV2 := parseSchemaV2Execution(t)

	if cfgV2.Execution == nil || cfgV2.Execution.Interpreter != "bash" || cfgV2.Execution.LaunchDialect != "posix" || cfgV2.Execution.Login == nil || *cfgV2.Execution.Login != false {
		t.Fatalf("global execution mismatch: %+v", cfgV2.Execution)
	}

	// n1 inherits global
	effN1, err := ssh.ResolveExecution(cfgV2.Nodes["n1"].Execution, cfgV2.Execution)
	if err != nil || effN1.Interpreter != "bash" || *effN1.Login != false {
		t.Fatalf("n1 effective = %+v, want bash with login false (err: %v)", effN1, err)
	}

	// n2 overrides interpreter to server; login is reset to nil
	effN2, err := ssh.ResolveExecution(cfgV2.Nodes["n2"].Execution, cfgV2.Execution)
	if err != nil || effN2.Interpreter != "server" || effN2.Login != nil {
		t.Fatalf("n2 effective = %+v, want server with login nil (err: %v)", effN2, err)
	}

	// n3 overrides login to true
	effN3, err := ssh.ResolveExecution(cfgV2.Nodes["n3"].Execution, cfgV2.Execution)
	if err != nil || effN3.Interpreter != "bash" || effN3.Login == nil || *effN3.Login != true {
		t.Fatalf("n3 effective = %+v, want bash with login true (err: %v)", effN3, err)
	}
}

func TestSchemaV2Execution_FromV2AndSnapshot(t *testing.T) {
	cfgV2 := parseSchemaV2Execution(t)
	cfg, err := FromV2(cfgV2)
	if err != nil {
		t.Fatalf("FromV2() error: %v", err)
	}
	if cfg.Execution == nil || cfg.Execution.Interpreter != "bash" || cfg.Execution.Login == nil || *cfg.Execution.Login != false {
		t.Fatalf("FromV2 global execution lost or mutated: %+v", cfg.Execution)
	}

	n2Node, ok := cfg.Nodes.Get("n2")
	if !ok || n2Node.Execution == nil || n2Node.Execution.Interpreter != "server" {
		t.Fatalf("FromV2 n2 execution lost: %+v", n2Node.Execution)
	}

	// Test snapshot isolation
	snapshot := cfg.Snapshot()
	f := true
	snapshot.Execution.Login = &f
	if *cfg.Execution.Login != false {
		t.Fatal("mutating snapshot mutated original cfg.Execution")
	}

	// Test ToV2 roundtrip
	cfgV2Roundtrip, err := cfg.ToV2()
	if err != nil {
		t.Fatalf("ToV2() error: %v", err)
	}
	if cfgV2Roundtrip.Execution == nil || *cfgV2Roundtrip.Execution.Login != false {
		t.Fatalf("ToV2 roundtrip lost login: false")
	}
	if cfgV2Roundtrip.Nodes["n2"].Execution == nil || cfgV2Roundtrip.Nodes["n2"].Execution.Interpreter != "server" {
		t.Fatalf("ToV2 roundtrip lost node execution")
	}
}

func TestSchemaV2Execution_InvalidCombinationFails(t *testing.T) {
	badYAML := `schema_version: 2
credential:
  default_store: s
  stores: {s: {type: system}}
identities: {u: {user: root, auth_type: key}}
hosts: {h: {address: 127.0.0.1, port: 22}}
execution:
  interpreter: server
  login: true
nodes:
  n: {host_ref: h, identity_ref: u}
`
	if _, err := UnmarshalV2([]byte(badYAML)); err == nil {
		t.Fatal("expected error for server interpreter with login: true")
	}

	// Test unknown field rejection in execution
	unknownFieldYAML := `schema_version: 2
credential:
  default_store: s
  stores: {s: {type: system}}
identities: {u: {user: root, auth_type: key}}
hosts: {h: {address: 127.0.0.1, port: 22}}
execution:
  interpreter: server
  unknown_opt: true
nodes:
  n: {host_ref: h, identity_ref: u}
`
	if _, err := UnmarshalV2([]byte(unknownFieldYAML)); err == nil {
		t.Fatal("expected error for unknown field in execution block")
	}

	// Test node execution incompatible with global
	incompatibleNodeYAML := `schema_version: 2
credential:
  default_store: s
  stores: {s: {type: system}}
identities: {u: {user: root, auth_type: key}}
hosts: {h: {address: 127.0.0.1, port: 22}}
execution:
  interpreter: bash
  launch_dialect: windows-cmd
nodes:
  n: {host_ref: h, identity_ref: u}
`
	if _, err := UnmarshalV2([]byte(incompatibleNodeYAML)); err == nil {
		t.Fatal("expected error for bash interpreter with windows-cmd dialect")
	}
}

func TestSchemaV2_ForbiddenPlaintextSecrets(t *testing.T) {
	tests := []struct {
		name        string
		yamlSnippet string
		errContains string
	}{
		{
			name: "totp_secret under identity",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    totp_secret: "JBSWY3DPEHPK3PXP"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "totp_secret",
		},
		{
			name: "otp_secret under identity",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    otp_secret: "JBSWY3DPEHPK3PXP"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "otp_secret",
		},
		{
			name: "answer under identity",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    answer: "plain_answer"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "answer",
		},
		{
			name: "secret under identity",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    secret: "plain_secret"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "secret",
		},
		{
			name: "totp_secret in otp block",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    otp:
      totp_secret: "JBSWY3DPEHPK3PXP"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "totp_secret",
		},
		{
			name: "otp_secret in otp block",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    otp:
      otp_secret: "JBSWY3DPEHPK3PXP"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "otp_secret",
		},
		{
			name: "secret in otp block",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    otp:
      secret: "JBSWY3DPEHPK3PXP"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "secret",
		},
		{
			name: "answer in keyboard_interactive rule",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: "Code:"
          answer: "secret_answer"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "answer",
		},
		{
			name: "secret in keyboard_interactive rule",
			yamlSnippet: `schema_version: 2
credential: {default_store: s, stores: {s: {type: system}}}
hosts: {h: {address: 1.1.1.1, port: 22}}
identities:
  dev:
    user: admin
    auth_type: key
    keyboard_interactive:
      rules:
        - name: r1
          prompt_pattern: "Code:"
          secret: "secret_val"
nodes: {n: {host_ref: h, identity_ref: dev}}`,
			errContains: "secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalV2([]byte(tt.yamlSnippet))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.errContains)
			}
			if !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("expected ErrSchemaValidation, got: %v", err)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.errContains)
			}
		})
	}
}

func TestSchemaV2_OTPValidation(t *testing.T) {
	baseYAML := `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts: {h: {address: 10.0.0.1, port: 22}}
nodes: {n: {host_ref: h, identity_ref: dev}}
`

	// 1. Mutual exclusion: both totp_secret_ref and command
	t.Run("mutual exclusion both ref and command", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      totp_secret_ref: {store_id: pass, item_id: "totp-key"}
      command: "oathtool --totp"
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("expected mutually exclusive error, got: %v", err)
		}
	})

	// 2. Missing source: neither totp_secret_ref nor command
	t.Run("missing both ref and command", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      prompt_pattern: "Code:"
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "must specify either") {
			t.Fatalf("expected must specify either error, got: %v", err)
		}
	})

	// 3. Unconfigured store in totp_secret_ref
	t.Run("unconfigured store", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      totp_secret_ref: {store_id: nonexistent_store, item_id: "totp-key"}
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("expected store not configured error, got: %v", err)
		}
	})

	// 4. Shell metacharacters in command
	t.Run("shell metacharacters", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      command: "oathtool; rm -rf /"
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "forbidden shell characters") {
			t.Fatalf("expected forbidden shell characters error, got: %v", err)
		}
	})

	// 5. Invalid regex in prompt_pattern
	t.Run("invalid prompt_pattern regex", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      totp_secret_ref: {store_id: pass, item_id: "totp-key"}
      prompt_pattern: "(unclosed_regex"
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "invalid regex") {
			t.Fatalf("expected invalid regex error, got: %v", err)
		}
	})

	// 6. Valid OTP config with totp_secret_ref
	t.Run("valid totp_secret_ref", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      totp_secret_ref: {store_id: pass, item_id: "totp-key"}
      prompt_pattern: "Verification Code:"
`
		cfg, err := UnmarshalV2([]byte(y))
		if err != nil {
			t.Fatalf("unexpected error for valid totp_secret_ref: %v", err)
		}
		if cfg.Identities["dev"].OTP == nil || cfg.Identities["dev"].OTP.TOTPSecretRef.ItemID != "totp-key" {
			t.Fatalf("parsed OTP config mismatch")
		}
	})

	// 7. Valid OTP config with command
	t.Run("valid command", func(t *testing.T) {
		y := baseYAML + `identities:
  dev:
    user: dev
    auth_type: otp
    otp:
      command: "/usr/local/bin/get-totp"
      args: ["--account", "dev"]
      timeout: 10s
`
		cfg, err := UnmarshalV2([]byte(y))
		if err != nil {
			t.Fatalf("unexpected error for valid command: %v", err)
		}
		if cfg.Identities["dev"].OTP.Command != "/usr/local/bin/get-totp" {
			t.Fatalf("parsed OTP command mismatch")
		}
		if cfg.Identities["dev"].OTP.Timeout != 10*time.Second {
			t.Fatalf("parsed OTP timeout mismatch: got %v", cfg.Identities["dev"].OTP.Timeout)
		}
	})
}

const testKIYAMLBase = `schema_version: 2
credential:
  default_store: pass
  stores:
    pass: {type: pass}
hosts: {h: {address: 10.0.0.1, port: 22}}
nodes: {n: {host_ref: h, identity_ref: dev}}
`

func TestSchemaV2_KeyboardInteractiveValidation_InvalidRules(t *testing.T) {
	// 1. Duplicate rule names
	t.Run("duplicate rule names", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: dup
          prompt_pattern: "Prompt1:"
          source: otp
        - name: dup
          prompt_pattern: "Prompt2:"
          source: otp
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "duplicate rule name") {
			t.Fatalf("expected duplicate rule name error, got: %v", err)
		}
	})

	// 2. Empty prompt_pattern
	t.Run("empty prompt_pattern", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: ""
          source: otp
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "prompt_pattern cannot be empty") {
			t.Fatalf("expected empty prompt_pattern error, got: %v", err)
		}
	})

	// 3. Invalid instruction regex
	t.Run("invalid instruction regex", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Password:"
          instruction_pattern: "[invalid_regex"
          source: login_password
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "invalid regex") {
			t.Fatalf("expected invalid regex error, got: %v", err)
		}
	})

	// 4. source: otp with secret_ref
	t.Run("source otp with secret_ref", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "Code:"
          source: otp
          secret_ref: {store_id: pass, item_id: "sec1"}
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "cannot specify secret_ref") {
			t.Fatalf("expected cannot specify secret_ref error, got: %v", err)
		}
	})

	// 5. source: secret without name
	t.Run("source secret without name", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - prompt_pattern: "PIN:"
          source: secret
          secret_ref: {store_id: pass, item_id: "pin1"}
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "must specify non-empty name") {
			t.Fatalf("expected must specify non-empty name error, got: %v", err)
		}
	})

	// 6. source: secret without secret_ref
	t.Run("source secret without secret_ref", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: pin-rule
          prompt_pattern: "PIN:"
          source: secret
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "must specify secret_ref") {
			t.Fatalf("expected must specify secret_ref error, got: %v", err)
		}
	})

	// 7. source: command with forbidden shell character
	t.Run("source command with shell char", func(t *testing.T) {
		y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: cmd-rule
          prompt_pattern: "Token:"
          source: command
          command: "cat token | tr -d '\n'"
`
		_, err := UnmarshalV2([]byte(y))
		if err == nil || !strings.Contains(err.Error(), "forbidden shell characters") {
			t.Fatalf("expected forbidden shell characters error, got: %v", err)
		}
	})
}

func TestSchemaV2_KeyboardInteractiveValidation_ValidRules(t *testing.T) {
	y := testKIYAMLBase + `identities:
  dev:
    user: dev
    auth_type: keyboard-interactive
    keyboard_interactive:
      rules:
        - name: pwd-rule
          prompt_pattern: "Password:"
          source: login_password
        - name: otp-rule
          prompt_pattern: "Verification Code:"
          instruction_pattern: "Enter MFA"
          source: otp
        - name: sec-rule
          prompt_pattern: "Static PIN:"
          source: secret
          secret_ref: {store_id: pass, item_id: "static-pin"}
        - name: cmd-rule
          prompt_pattern: "Dynamic Token:"
          source: command
          command: "/usr/bin/token-gen"
          args: ["--env", "prod"]
          timeout: 5s
`
	cfg, err := UnmarshalV2([]byte(y))
	if err != nil {
		t.Fatalf("unexpected error for valid rules: %v", err)
	}
	rules := cfg.Identities["dev"].KeyboardInteractive.Rules
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	if rules[0].Source != models.ChallengeSourceLoginPassword ||
		rules[1].Source != models.ChallengeSourceOTP ||
		rules[2].Source != models.ChallengeSourceSecret ||
		rules[3].Source != models.ChallengeSourceCommand {
		t.Fatalf("parsed rules sources mismatch")
	}
}

func TestToV2AndFromV2_OTPAndKeyboardInteractive(t *testing.T) {
	orig := &Configuration{
		SchemaVersion: 2,
		Credential: &CredentialConfig{
			DefaultStore: "pass",
			Stores: map[string]StoreConfig{
				"pass": {Type: StoreTypePass},
			},
		},
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
	}

	orig.Hosts.Set("h1", models.Host{Address: "127.0.0.1", Port: 22})

	idModel := models.Identity{
		User:     "ops",
		AuthType: "keyboard-interactive",
		OTP: &models.OTPConfig{
			TOTPSecretRef: &credential.Ref{StoreID: "pass", ItemID: "totp-key"},
			PromptPattern: "OTP:",
		},
		KeyboardInteractive: &models.KeyboardInteractiveConfig{
			Rules: []models.ChallengeRule{
				{
					Name:          "r1",
					PromptPattern: "Password:",
					Source:        models.ChallengeSourceLoginPassword,
				},
				{
					Name:          "r2",
					PromptPattern: "OTP:",
					Source:        models.ChallengeSourceOTP,
				},
			},
		},
	}
	orig.Identities.Set("id1", idModel)
	orig.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	// Convert to V2 DTO
	v2, err := orig.ToV2()
	if err != nil {
		t.Fatalf("ToV2 failed: %v", err)
	}

	v2ID := v2.Identities["id1"]
	if v2ID.OTP == nil || v2ID.OTP.TOTPSecretRef.ItemID != "totp-key" {
		t.Fatalf("v2 OTP mismatch")
	}
	if v2ID.KeyboardInteractive == nil || len(v2ID.KeyboardInteractive.Rules) != 2 {
		t.Fatalf("v2 KeyboardInteractive mismatch")
	}

	// Verify deep clone isolation
	v2ID.OTP.TOTPSecretRef.ItemID = "mutated"
	if idModel.OTP.TOTPSecretRef.ItemID != "totp-key" {
		t.Fatalf("mutating v2 affected orig model")
	}

	// Convert back FromV2
	reloaded, err := FromV2(v2)
	if err != nil {
		t.Fatalf("FromV2 failed: %v", err)
	}

	reloadedID, ok := reloaded.Identities.Get("id1")
	if !ok {
		t.Fatalf("identity id1 missing in reloaded config")
	}
	if reloadedID.OTP == nil || reloadedID.OTP.TOTPSecretRef.ItemID != "mutated" {
		t.Fatalf("reloaded OTP mismatch")
	}
	if reloadedID.KeyboardInteractive == nil || len(reloadedID.KeyboardInteractive.Rules) != 2 {
		t.Fatalf("reloaded KeyboardInteractive mismatch")
	}
}
