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
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func init() {
	if os.Getenv("TEST_IDENTITY_HELPER") == "1" {
		runTestIdentityHelper()
		os.Exit(0)
	}
}

func runTestIdentityHelper() {
	action := os.Args[len(os.Args)-1]
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
		ItemID string `json:"item_id"`
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

	cfg := &config.Configuration{
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
		Password: "legacy_plain_password",
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

	cfg := &config.Configuration{
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
