package adapter

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestPreparedNodeSSHAuthenticationPersistence(t *testing.T) {
	setTestHome(t)
	host, port, stopServer := startAdapterPrivilegeSSHServer(t, "valid-password", "")
	t.Cleanup(stopServer)
	for _, tc := range []struct {
		name     string
		password string
		remember bool
		success  bool
	}{
		{name: "authenticated_session_only", password: "valid-password", success: true},
		{name: "authenticated_remember", password: "valid-password", remember: true, success: true},
		{name: "authentication_failed", password: "wrong-password", remember: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, diskStore, path, original := pendingAdapterRepository(t)
			prepared, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{Target: config.ConnectionTarget{
				Selector: host, User: "root", HasUser: true, Port: uint16(port), HasPort: true,
			}})
			if err != nil {
				t.Fatal(err)
			}
			service, secrets := pendingCredentialService(t, repo)
			connector := NewConnectorWithAdapterOptions(repo, []Option{
				WithCredentialService(service),
				WithNonInteractive(!tc.remember),
				WithSessionAuthOverride(prepared.NodeID, SessionAuth{Password: tc.password, Remember: tc.remember}),
			}, ssh.WithHandshakeTimeout(time.Second))
			connector.AcceptNewHostKey.Store(true)
			defer func() {
				if err := connector.CloseAll(); err != nil {
					t.Errorf("close connector: %v", err)
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			client, connectErr := connector.Connect(ctx, prepared.NodeID)
			if (connectErr == nil) != tc.success {
				t.Fatalf("connect success = %v, error = %v", tc.success, connectErr)
			}
			if client != nil {
				defer func() {
					if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						t.Errorf("close SSH client: %v", err)
					}
				}()
			}
			disk, err := diskStore.Load()
			if err != nil {
				t.Fatal(err)
			}
			node, saved := disk.Nodes.Get(prepared.NodeID)
			if saved != tc.success {
				t.Fatalf("saved node = %v, expected %v", saved, tc.success)
			}
			if !tc.success {
				current, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(current) != string(original) || len(secrets.data) != 0 {
					t.Fatal("failed authentication modified configuration or credentials")
				}
				return
			}
			identity, ok := disk.Identities.Get(node.IdentityRef)
			if !ok || identity.Password != "" || (identity.LoginPasswordRef != nil) != tc.remember {
				t.Fatal("node was not saved before credential recording, or remember policy was bypassed")
			}
			if tc.remember {
				secret, err := secrets.Get(ctx, *identity.LoginPasswordRef)
				if err != nil {
					t.Fatal(err)
				}
				defer secret.Zero()
				if string(secret.Value) != tc.password {
					t.Fatal("remembered credential does not match authenticated password")
				}
			}
			assertCommandFailureKeepsNode(t, client, diskStore, prepared.NodeID)
		})
	}
}

func pendingAdapterRepository(t *testing.T) (*config.Repository, config.Store, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	diskStore := config.NewDefaultStore(path, filepath.Join(dir, "config.key"))
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Credential = &config.CredentialConfig{DefaultStore: "memory"}
	if err := diskStore.Save(cfg); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, diskStore)
	if err != nil {
		t.Fatal(err)
	}
	return repo, diskStore, path, original
}

func pendingCredentialService(t *testing.T, repo *config.Repository) (*credential.Service, *adapterCredentialStore) {
	t.Helper()
	secrets := &adapterCredentialStore{data: make(map[string]credential.Secret)}
	registry := credential.NewRegistry()
	if err := registry.Register("memory", secrets); err != nil {
		t.Fatal(err)
	}
	journal, err := credential.NewJournalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := credential.NewService(registry, journal, repo.AsConfigUpdater(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return service, secrets
}

func assertCommandFailureKeepsNode(t *testing.T, client *ssh.Client, diskStore config.Store, nodeID string) {
	t.Helper()
	// Persistence is complete before a shell or command is opened. A
	// later execution failure must not undo the authenticated node.
	commandCtx, cancelCommand := context.WithCancel(t.Context())
	cancelCommand()
	if _, err := client.Run(commandCtx, "false"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled remote command, got %v", err)
	}
	disk, err := diskStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := disk.Nodes.Get(nodeID); !ok {
		t.Fatal("command failure removed the authenticated node")
	}
}

func TestSavedNodeSurvivesFailedAuthentication(t *testing.T) {
	setTestHome(t)
	host, port, stop := startAdapterPrivilegeSSHServer(t, "valid-password", "")
	t.Cleanup(stop)
	repo, _, path, _ := pendingAdapterRepository(t)
	// Explicit creation is still durable without first authenticating.
	saved, err := repo.EnsureNodeContext(t.Context(), config.EnsureNodeOptions{Target: config.ConnectionTarget{
		Selector: host, User: "root", HasUser: true, Port: uint16(port), HasPort: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	connector := NewConnectorWithAdapterOptions(repo, []Option{
		WithNonInteractive(true),
		WithSessionAuthOverride(saved.NodeID, SessionAuth{Password: "invalid-password"}),
	}, ssh.WithHandshakeTimeout(time.Second))
	connector.AcceptNewHostKey.Store(true)
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close connector: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := connector.Connect(ctx, saved.NodeID); err == nil {
		t.Fatal("invalid authentication succeeded")
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("failed authentication changed the explicitly saved node")
	}
	if _, exists := repo.GetNode(saved.NodeID); !exists {
		t.Fatal("failed authentication removed the existing node")
	}
}
