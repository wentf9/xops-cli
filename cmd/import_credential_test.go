package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	hostcmd "github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestV2ImportPersistsCredentialReferences(t *testing.T) {
	for _, kind := range []string{"password", "passphrase"} {
		t.Run(kind, func(t *testing.T) {
			setupFirewallCredential(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := uint16(listener.Addr().(*net.TCPAddr).Port)
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			addr := utils.HostInfo{Host: "127.0.0.1", Port: port, User: "imported"}
			if kind == "password" {
				addr.Password = "csv-secret"
			} else {
				addr.Host = "127.0.0.2"
				addr.KeyPath = inventoryTestPrivateKey(t, true)
				addr.Passphrase = "key-password"
			}
			// Verify fails on the closed loopback port, after the import commit.
			// Race-instrumented helper processes each incur an exit delay;
			// allow the complete Put/Get/cleanup/verification sequence.
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			err = hostcmd.ExecuteLoadHostContext(ctx, []utils.HostInfo{addr})
			if err == nil || !strings.Contains(err.Error(), "verify failed") {
				t.Fatalf("import did not reach connection verification: %v", err)
			}
			_, repo, cfg, err := utils.GetConfigStore()
			if err != nil {
				t.Fatal(err)
			}
			nodeID := "node"
			if kind == "passphrase" {
				nodeID = fmt.Sprintf("imported@%s:%d", addr.Host, port)
			}
			snapshot, err := repo.ResolveConnection(nodeID)
			if err != nil {
				t.Fatal(err)
			}
			ref := snapshot.Identity.LoginPasswordRef
			if kind == "passphrase" {
				ref = snapshot.Identity.PassphraseRef
			}
			if ref == nil || snapshot.Identity.Password != "" || snapshot.Identity.Passphrase != "" {
				t.Fatal("import retained legacy secret fields")
			}
			reg, err := utils.GetCredentialRegistry(cfg)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := reg.Resolve(t.Context(), *ref)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Zero()
			want := addr.Password
			if kind == "passphrase" {
				want = addr.Passphrase
			}
			if string(secret.Value) != want {
				t.Fatal("imported credential value mismatch")
			}
		})
	}
}

func TestV2ImportFailuresPreserveConfiguration(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.0.0.2"} {
		t.Run(host, func(t *testing.T) {
			setupFirewallCredential(t)
			path, _, err := utils.GetConfigFilePath()
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
			err = hostcmd.ExecuteLoadHostContext(t.Context(), []utils.HostInfo{{Host: host, User: "imported", Password: "csv-secret", Alias: "new-alias"}})
			if !errors.Is(err, credential.ErrCredentialStoreLocked) {
				t.Fatalf("import lost backend error: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) {
				t.Fatalf("failed import modified configuration: %v", err)
			}
		})
	}
}

func TestImportVerificationResolvesExistingRef(t *testing.T) {
	setupFirewallCredential(t)
	t.Setenv("TEST_HELPER_ERROR_CODE", "locked")
	err := hostcmd.ExecuteLoadHostContext(t.Context(), []utils.HostInfo{{Host: "127.0.0.1", User: "admin"}})
	if !errors.Is(err, credential.ErrCredentialStoreLocked) {
		t.Fatalf("verification omitted resolver: %v", err)
	}
}

func TestV2ImportNoneRejectsSecretBeforeCreation(t *testing.T) {
	setupTestEnvironment(t)
	configureSessionOnlyCredential(t)
	err := hostcmd.ExecuteLoadHostContext(t.Context(), []utils.HostInfo{{Host: "127.0.0.2", User: "imported", Password: "csv-secret"}})
	if !errors.Is(err, credential.ErrCredentialStoreReadOnly) {
		t.Fatalf("none import: %v", err)
	}
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.NewDefaultStore(path, key).Load()
	if err != nil || cfg.Nodes.Count() != 0 {
		t.Fatalf("failed import left metadata: %v", err)
	}
}
