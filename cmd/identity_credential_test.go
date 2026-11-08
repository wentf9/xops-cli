package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func init() {
	if os.Getenv("TEST_IDENTITY_HELPER") == "1" {
		runTestIdentityHelper()
		os.Exit(0)
	}
}

func runTestIdentityHelper() {
	if path := os.Getenv("TEST_HELPER_CALL_FILE"); path != "" {
		if err := os.WriteFile(path, []byte("called"), 0600); err != nil {
			fmt.Fprintln(os.Stderr, "record test helper invocation failed")
			os.Exit(1)
		}
	}
	action := os.Args[len(os.Args)-1]
	if code := os.Getenv("TEST_HELPER_ERROR_CODE"); code != "" {
		fmt.Printf("{\"code\":%q}\n", code)
		os.Exit(1)
	}
	dataFile := os.Getenv("TEST_HELPER_DATA_FILE")
	if dataFile == "" {
		_, _ = fmt.Fprintf(os.Stderr, "missing TEST_HELPER_DATA_FILE")
		os.Exit(1)
	}

	dataMap := make(map[string]string)
	if raw, err := os.ReadFile(dataFile); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &dataMap)
	}

	type reqT struct {
		ItemID string `json:"itemID"`
		Secret string `json:"secret"`
	}
	var req reqT
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil && err != io.EOF {
		_, _ = fmt.Fprintf(os.Stderr, "decode json failed: %v", err)
		os.Exit(1)
	}

	switch action {
	case "get":
		sec, ok := dataMap[req.ItemID]
		if !ok {
			fmt.Println(`{"code":"not-found","message":"item not found"}`)
			os.Exit(1)
		}
		fmt.Printf("{\"secret\":%q}\n", sec)
	case "store":
		dataMap[req.ItemID] = req.Secret
		b, _ := json.Marshal(dataMap)
		_ = os.WriteFile(dataFile, b, 0o600)
		fmt.Println("{}")
	case "erase":
		delete(dataMap, req.ItemID)
		b, _ := json.Marshal(dataMap)
		_ = os.WriteFile(dataFile, b, 0o600)
		fmt.Println("{}")
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown action %s", action)
		os.Exit(1)
	}
}

func TestIdentityCredentialCommandTree(t *testing.T) {
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)

	credCmd, _, err := root.Find([]string{"identity", "credential"})
	if err != nil {
		t.Fatalf("find identity credential command: %v", err)
	}
	if credCmd.Name() != "credential" {
		t.Errorf("identity credential command name = %q, want credential", credCmd.Name())
	}
	if !slices.Contains(credCmd.Aliases, "cred") {
		t.Errorf("identity credential aliases = %v, want 'cred'", credCmd.Aliases)
	}

	setCmd, _, err := root.Find([]string{"identity", "credential", "set"})
	if err != nil {
		t.Fatalf("find identity credential set command: %v", err)
	}
	if setCmd.Flags().Lookup("kind") == nil {
		t.Errorf("expected --kind flag on set command")
	}
	if setCmd.Flags().Lookup("store") == nil {
		t.Errorf("expected --store flag on set command")
	}
	if setCmd.Flags().Lookup("password-stdin") == nil {
		t.Errorf("expected --password-stdin flag on set command")
	}

	delCmd, _, err := root.Find([]string{"identity", "credential", "delete"})
	if err != nil {
		t.Fatalf("find identity credential delete command: %v", err)
	}
	if delCmd.Flags().Lookup("kind") == nil {
		t.Errorf("expected --kind flag on delete command")
	}
}

func TestIdentityCredentialSetAndDelete_Stdin(t *testing.T) {
	tempDir := setupTestEnvironment(t)
	helperDataFile := filepath.Join(tempDir, "helper_data.json")
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", helperDataFile)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{SchemaVersion: 2,
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "helper-store",
			Stores: map[string]config.StoreConfig{
				"helper-store": {
					Type:    config.StoreTypeHelper,
					Command: os.Args[0],
				},
			},
		},
	}
	cfg.Identities.Set("admin", models.Identity{
		User:     "root",
		AuthType: "password",
	})
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}

	// 1. 测试 set 操作
	setBuf := new(bytes.Buffer)
	cmd := NewCmdIdentity()
	cmd.SetOut(setBuf)
	cmd.SetIn(strings.NewReader("new_secure_secret_456\n"))
	cmd.SetArgs([]string{"credential", "set", "admin", "--kind", "login_password", "--password-stdin"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute identity credential set failed: %v", err)
	}

	// 验证配置已更新：明文已清除，且设置了 LoginPasswordRef
	updatedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load updated config: %v", err)
	}
	adminIdentity, ok := updatedCfg.Identities.Get("admin")
	if !ok {
		t.Fatalf("identity 'admin' not found after set")
	}
	if adminIdentity.Password != "" {
		t.Errorf("expected identity.Password to be cleared, got %q", adminIdentity.Password)
	}
	if adminIdentity.LoginPasswordRef == nil || adminIdentity.LoginPasswordRef.IsEmpty() {
		t.Fatalf("expected identity.LoginPasswordRef to be set, got nil/empty")
	}
	if adminIdentity.LoginPasswordRef.StoreID != "helper-store" {
		t.Errorf("expected StoreID = helper-store, got %q", adminIdentity.LoginPasswordRef.StoreID)
	}

	// 2. 测试 delete 操作
	delBuf := new(bytes.Buffer)
	delCmd := NewCmdIdentity()
	delCmd.SetOut(delBuf)
	delCmd.SetArgs([]string{"credential", "delete", "admin", "--kind", "login_password"})

	if err := delCmd.Execute(); err != nil {
		t.Fatalf("execute identity credential delete failed: %v", err)
	}

	// 验证配置中的引用已删除
	deletedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load config after delete: %v", err)
	}
	adminAfterDel, ok := deletedCfg.Identities.Get("admin")
	if !ok {
		t.Fatalf("identity 'admin' not found after delete")
	}
	if adminAfterDel.LoginPasswordRef != nil && !adminAfterDel.LoginPasswordRef.IsEmpty() {
		t.Errorf("expected LoginPasswordRef to be empty after delete, got %v", adminAfterDel.LoginPasswordRef)
	}
}

func TestIdentityCredentialSet_NotFound(t *testing.T) {
	_ = setupTestEnvironment(t)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)

	cfg := &config.Configuration{SchemaVersion: 2,
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	cmd := NewCmdIdentity()
	cmd.SetArgs([]string{"credential", "set", "non_existent_id", "--kind", "login_password", "--password-stdin"})
	cmd.SetIn(strings.NewReader("secret\n"))

	if err := cmd.Execute(); err == nil {
		t.Errorf("expected error when setting credential for non-existent identity, got nil")
	}
}

func TestUnifiedCredentialAndSimplifiedWorkflows(t *testing.T) {
	store := setupWorkflowTestStore(t)

	// 1. Positional `id add <name> <user>`
	mustExecRoot(t, "id-secret-1\n", "id", "add", "prod-id", "deploy", "--password-stdin")
	mustExecRoot(t, "id-secret-2\n", "id", "add", "temp-id", "ops", "--password-stdin")
	mustExecRoot(t, "id-secret-3\n", "id", "add", "temp-id-2", "audit", "--password-stdin")

	// 2. Positional `h add <alias> <user>@<host>:<port> --skip-verify`
	mustExecRoot(t, "", "h", "add", "web-01", "root@192.0.2.10:2222", "--skip-verify")
	mustExecRoot(t, "", "h", "add", "ops@192.0.2.11", "--skip-verify")

	// 3. Direct credential set on node via `cred set <alias> --password` and `--sudo`
	mustExecRoot(t, "node-login-pwd\n", "cred", "set", "web-01", "--password", "--password-stdin")
	mustExecRoot(t, "node-sudo-pwd\n", "cred", "set", "web-01", "--sudo", "--password-stdin")

	// 4. Direct credential set on identity via `id set <name> --totp`
	mustExecRoot(t, "JBSWY3DPEHPK3PXP\n", "id", "set", "prod-id", "--totp", "--password-stdin")
	assertSavedNodeAndIdentityCredentials(t, store)

	// 5. Direct `h tag <tag> <node1> <node2>` and `h tag -d <tag> <node2>`
	mustExecRoot(t, "", "h", "tag", "cluster", "web-01", "ops@192.0.2.11:22")
	mustExecRoot(t, "", "h", "tag", "-d", "cluster", "ops@192.0.2.11:22")

	// 6. `h ed` with `--add-tag`, `--rm-tag`, and `-I` (rebind identity template)
	mustExecRoot(t, "", "h", "ed", "web-01", "--add-tag", "frontend,canary", "--rm-tag", "cluster", "-I", "prod-id")
	assertEditedNodeState(t, store)

	// 7. Delete sudo secret via `h rm-secret <node> --sudo` and multi-delete
	mustExecRoot(t, "", "h", "rm-secret", "web-01", "--sudo")
	mustExecRoot(t, "", "h", "rm", "web-01", "ops@192.0.2.11:22")
	mustExecRoot(t, "", "id", "rm", "temp-id", "temp-id-2")
	assertAllDeleted(t, store)
}

func setupWorkflowTestStore(t *testing.T) config.Store {
	t.Helper()
	tempDir := setupTestEnvironment(t)
	helperDataFile := filepath.Join(tempDir, "helper_data.json")
	t.Setenv("TEST_IDENTITY_HELPER", "1")
	t.Setenv("TEST_HELPER_DATA_FILE", helperDataFile)

	cfgPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatalf("GetConfigFilePath failed: %v", err)
	}
	store := config.NewDefaultStore(cfgPath, keyPath)
	cfg := &config.Configuration{
		SchemaVersion: 2,
		Nodes:         concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:         concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities:    concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Credential: &config.CredentialConfig{
			DefaultStore: "helper-store",
			Stores: map[string]config.StoreConfig{
				"helper-store": {
					Type:    config.StoreTypeHelper,
					Command: os.Args[0],
				},
			},
		},
	}
	if err := store.Save(cfg); err != nil {
		t.Fatalf("failed to save initial config: %v", err)
	}
	return store
}

func mustExecRoot(t *testing.T, stdin string, args ...string) {
	t.Helper()
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)
	root.PersistentPreRunE = nil
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	if stdin != "" {
		root.SetIn(strings.NewReader(stdin))
	}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("execute %v failed: %v", args, err)
	}
}

func assertSavedNodeAndIdentityCredentials(t *testing.T, store config.Store) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	webNode, ok := loaded.Nodes.Get("root@192.0.2.10:2222")
	if !ok {
		t.Fatalf("expected node root@192.0.2.10:2222 to exist")
	}
	if webNode.PrivilegePasswordRef == nil || webNode.PrivilegePasswordRef.IsEmpty() {
		t.Fatalf("expected PrivilegePasswordRef on web-01 to be set")
	}
	webIdent, ok := loaded.Identities.Get(webNode.IdentityRef)
	if !ok || webIdent.LoginPasswordRef == nil || webIdent.LoginPasswordRef.IsEmpty() {
		t.Fatalf("expected LoginPasswordRef on web-01 identity to be set, got %+v", webIdent)
	}
	prodIdent, ok := loaded.Identities.Get("prod-id")
	if !ok || prodIdent.OTP == nil || prodIdent.OTP.TOTPSecretRef == nil {
		t.Fatalf("expected TOTPSecretRef on prod-id to be set, got %+v", prodIdent)
	}
}

func assertEditedNodeState(t *testing.T, store config.Store) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load config after edit failed: %v", err)
	}
	renamedNode, ok := loaded.Nodes.Get("deploy@192.0.2.10:2222")
	if !ok {
		t.Fatalf("expected node to be renamed to deploy@192.0.2.10:2222 after switching to prod-id")
	}
	if renamedNode.IdentityRef != "prod-id" {
		t.Errorf("expected IdentityRef = prod-id, got %q", renamedNode.IdentityRef)
	}
	if !slices.Equal(renamedNode.Tags, []string{"frontend", "canary"}) {
		t.Errorf("expected tags [frontend canary], got %v", renamedNode.Tags)
	}
}

func assertAllDeleted(t *testing.T, store config.Store) {
	t.Helper()
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load config after multi-delete failed: %v", err)
	}
	if loaded.Nodes.Count() != 0 {
		t.Errorf("expected 0 nodes after h rm, got %d", loaded.Nodes.Count())
	}
	if loaded.Identities.Count() != 0 {
		t.Errorf("expected 0 identities after id rm, got %d", loaded.Identities.Count())
	}
	raw, err := os.ReadFile(os.Getenv("TEST_HELPER_DATA_FILE"))
	if err != nil {
		t.Fatalf("read helper store file failed: %v", err)
	}
	var remaining map[string]string
	if err := json.Unmarshal(raw, &remaining); err != nil {
		t.Fatalf("unmarshal helper store file failed: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("expected 0 credentials remaining in helper store after cleanup, got %v", remaining)
	}
}
